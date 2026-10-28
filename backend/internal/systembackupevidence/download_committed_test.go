package systembackupevidence

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The real admission and post-commit SQL authority run against scripted SQL.
// This owner policy witnesses lock order only, not production owner authority.
type committedTestPolicy struct {
	*downloadTestPolicy
	db          *admissionTxDB
	onAuthorize func()
	legacy      bool
}

func (p *committedTestPolicy) Authorize(ctx context.Context, tx *sql.Tx, actor Actor, record Record, required []string) error {
	if err := p.downloadTestPolicy.Authorize(ctx, tx, actor, record, required); err != nil {
		return err
	}
	if p.onAuthorize != nil {
		p.onAuthorize()
	}
	return nil
}

func (p *committedTestPolicy) LockScope(ctx context.Context, tx *sql.Tx, installation string, id Identity) error {
	if !p.legacy && !p.db.opKeyLocked {
		p.db.t.Fatal("post-commit owner lock before original operation/receipt")
	}
	p.db.ownerLocked = true
	p.db.calls = append(p.db.calls, "committed-owner")
	return p.downloadTestPolicy.LockScope(ctx, tx, installation, id)
}

func committedFixture(t *testing.T) (*admissionTxFixture, *SQLDownloadAuthority, *CommittedDownloadAdmission) {
	return committedConfiguredFixture(t, nil)
}

func committedConfiguredFixture(t *testing.T, configure func(*admissionTxFixture)) (*admissionTxFixture, *SQLDownloadAuthority, *CommittedDownloadAdmission) {
	f, a := uncommittedConfiguredFixture(t, configure)
	c, err := f.service.Admit(f.request)
	if err != nil || c == nil {
		t.Fatal("admission", err, f.db.calls)
	}
	return f, a, c
}

func uncommittedConfiguredFixture(t *testing.T, configure func(*admissionTxFixture)) (*admissionTxFixture, *SQLDownloadAuthority) {
	t.Helper()
	f := newAdmissionTxFixture(t)
	if configure != nil {
		configure(f)
	}
	r := f.initial
	r.Ref.Identity = f.db.configCells["evidence_store_identity_hash"].(string)
	r.Ref.Version = f.db.configCells["evidence_store_ref_version"].(string)
	var err error
	r.Ref.RelativeKey, err = keyFor("evidence", r.Manifest.Identity)
	if err != nil {
		t.Fatal(err)
	}
	f.initial, f.db.record, f.env.hint, f.db.m.f.Record = r, r, r, r
	if configure != nil && oneOf(r.Manifest.Identity.Classification, "confidential", "sensitive") {
		f.sign(t, f.request.Header.Get("Idempotency-Key"), f.db.now.Add(-time.Minute), f.db.now.Add(time.Minute))
	}
	// Allow enough time for a loaded test host, without extending any returned
	// deadline; all authority/claim limits remain the original admission limits.
	f.env.reservationUntil = f.db.now.Add(20 * time.Second)
	p := &committedTestPolicy{downloadTestPolicy: &downloadTestPolicy{deadline: r.OwnerDeadline}, db: f.db}
	f.service.registry.Policy = p
	dir := t.TempDir()
	writeAdmissionPinnedFile(t, filepath.Join(dir, "rbac_bindings", "v1", f.env.rbacHash+".json"), f.env.rbac)
	a, err := NewSQLDownloadAuthority(DownloadAuthorityConfig{Registry: f.service.registry, JWTSecret: f.secret,
		ConfigVersion: 1, ConfigSHA256: f.db.config.SHA256(), RBACVersion: "v1", RBACSHA256: f.env.rbacHash, RegistryDirectory: dir,
		Root: "evidence", Store: KeyRef{r.Ref.Identity, r.Ref.Version},
		Read:   KeyRef{f.db.configCells["evidence_read_identity_hash"].(string), f.db.configCells["evidence_read_ref_version"].(string)},
		Issuer: "https://issuer.local", Audience: "download-provider", Subject: "system:download", TokenFile: filepath.Join(dir, "token"), ExpiresAt: f.db.now.Add(2 * time.Minute)})
	if err != nil {
		t.Fatal("authority", err)
	}
	return f, a
}

// Provider transport is synthetic; the actual committed S3 authorization and
// envelope/range/DEK code execute. No real STS or KMS network claim is made.
type committedScopedReadStore struct {
	*testStore
	authority *SQLDownloadAuthority
	scopes    []S3Scope
}

func (s *committedScopedReadStore) check(ctx context.Context, scope S3Scope) error {
	g, err := s.authority.AuthorizeS3(ctx, scope)
	defer wipe(g.Token)
	if err != nil {
		return err
	}
	if g.Authorization.Scope != scope || g.Authorization.AccessKind != "download" || len(g.Token) == 0 {
		return ErrDenied
	}
	s.scopes = append(s.scopes, scope)
	return nil
}
func (s *committedScopedReadStore) Stat(ctx context.Context, ref Ref) (ObjectInfo, error) {
	if err := s.check(ctx, S3Scope{Operation: S3Stat, Ref: ref}); err != nil {
		return ObjectInfo{}, err
	}
	return s.testStore.Stat(ctx, ref)
}
func (s *committedScopedReadStore) Range(ctx context.Context, ref Ref, offset, length int64) (io.ReadCloser, error) {
	if err := s.check(ctx, S3Scope{Operation: S3Range, Ref: ref, Offset: offset, Length: length}); err != nil {
		return nil, err
	}
	return s.testStore.Range(ctx, ref, offset, length)
}

func writeCommittedProviderToken(t *testing.T, a *SQLDownloadAuthority) {
	t.Helper()
	projected, err := json.Marshal(map[string]any{"iss": a.c.Issuer, "aud": a.c.Audience, "sub": a.c.Subject, "exp": time.Now().Add(10 * time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	writeAdmissionPinnedFile(t, a.c.TokenFile, []byte("header."+base64.RawURLEncoding.EncodeToString(projected)+".signature"))
}

func TestCommittedDownloadProviderGrantsAndRealEnvelopeOpenRange(t *testing.T) {
	p, plain, object, keys := fixture(t, int(ChunkSize)+131)
	f, a, c := committedConfiguredFixture(t, func(f *admissionTxFixture) {
		f.initial.Manifest = p.Manifest()
		f.request.Header.Set("Range", "bytes="+strconv.FormatInt(ChunkSize, 10)+"-"+strconv.FormatInt(ChunkSize+63, 10))
	})
	ctx := bindCommittedFixture(t, a, c)
	writeCommittedProviderToken(t, a)
	store := &committedScopedReadStore{testStore: &testStore{data: object, present: true, info: ObjectInfo{Version: c.record.Ref.ImmutableVersion, SHA256: hash(object), Size: int64(len(object))}}, authority: a}
	if err := a.CheckCommittedDownload(ctx, c); err != nil {
		t.Fatal("provider precheck", err)
	}
	info, err := store.Stat(ctx, c.record.Ref)
	if err != nil || !matchObject(c.Record(), info) {
		t.Fatal("stat", err)
	}
	start, end, partial := c.Range()
	if !partial || start != ChunkSize || end != ChunkSize+63 {
		t.Fatal("signed normalized range")
	}
	data, err := OpenRange(ctx, c.Record().Manifest, c.record.Ref, store, DownloadKeys{Authority: a, Keys: keys}, start, end)
	defer wipe(data)
	if err != nil || !bytes.Equal(data, plain[start:end+1]) {
		t.Fatal("committed range/envelope unwrap", err)
	}
	if err = a.CheckCommittedDownload(ctx, c); err != nil {
		t.Fatal("final pre-header check", err)
	}
	if len(store.scopes) != 3 || store.scopes[0].Operation != S3Stat || store.scopes[1].Offset != 0 || store.scopes[1].Length != c.record.Manifest.HeaderSize || store.scopes[2].Offset != c.record.Manifest.Chunks[1].FrameOffset || store.scopes[2].Length != c.record.Manifest.Chunks[1].FrameLength {
		t.Fatal("provider read unsigned frames", store.scopes)
	}
	if f.db.inserts != 1 || f.env.prepares != 1 || f.db.reserved != 65536 {
		t.Fatal("provider repeated admission")
	}
}

func bindCommittedFixture(t *testing.T, a *SQLDownloadAuthority, c *CommittedDownloadAdmission) context.Context {
	t.Helper()
	ctx, cancel, err := a.BindCommittedDownload(context.Background(), c)
	if err != nil || ctx == nil || cancel == nil {
		t.Fatal("bind", err)
	}
	t.Cleanup(cancel)
	return ctx
}

func TestCommittedDownloadReadsOriginalGroupWithoutRepeatingAdmission(t *testing.T) {
	f, a, c := committedFixture(t)
	ctx := bindCommittedFixture(t, a, c)
	before := f.db.saved
	group := admissionTxSnapshot{record: f.db.record, op: append([]driver.Value(nil), f.db.m.op...), receipt: append([]driver.Value(nil), f.db.m.receipt...), nonce: append([]driver.Value(nil), f.db.nonce...), body: append([]byte(nil), f.db.body...)}
	start, end, present := c.Range()
	f.request.Header.Set("Range", "bytes=1-2")
	f.request.Header.Set("Idempotency-Key", "mutated-after-commit")
	if s, e, p := c.Range(); s != start || e != end || p != present {
		t.Fatal("mutable HTTP headers changed committed range")
	}
	for i := 0; i < 2; i++ {
		queryStart, callStart := len(f.db.queries), len(f.db.calls)
		if err := a.CheckCommittedDownload(ctx, c); err != nil {
			t.Fatal("known committed check", err, f.db.queries[queryStart:])
		}
		calls := strings.Join(f.db.calls[callStart:], ",")
		if !strings.Contains(calls, "operation-read,receipt-read,committed-owner") || !strings.HasSuffix(calls, "commit") {
			t.Fatal("post-commit lock sequence", calls)
		}
		queries := strings.Join(f.db.queries[queryStart:], "\n")
		for _, want := range []string{downloadAdmissionNonceCandidateReadSQL, downloadAdmissionNonceReadSQL, downloadIntentReadSQL, downloadCommittedOwnerSQL, "SELECT revoked_before", "canonical_config_json"} {
			if !strings.Contains(queries, want) {
				t.Fatal("guard omitted original/current fact", want)
			}
		}
	}
	if !reflect.DeepEqual(group.op, f.db.m.op) || !reflect.DeepEqual(group.receipt, f.db.m.receipt) || !reflect.DeepEqual(group.nonce, f.db.nonce) || !reflect.DeepEqual(group.record, f.db.record) || !reflect.DeepEqual(group.body, f.db.body) || f.db.inserts != 1 || f.env.prepares != 1 || f.db.reserved != 65536 || f.db.commits != 3 || before.record.RowVersion != f.initial.RowVersion {
		t.Fatal("post-commit check repeated/mutated admission")
	}
	if c.rows.audit.tx != nil {
		t.Fatal("committed object retained pending SQL transaction")
	}
}

func TestCommittedDownloadBindingIsSingleAttemptAcrossCopies(t *testing.T) {
	for _, mode := range []string{"copy_second", "wrong_authority_after_bind", "wrong_database", "wrong_secret", "wrong_config", "nil_context", "canceled", "expired", "empty_rows"} {
		t.Run(mode, func(t *testing.T) {
			f, a, c := committedFixture(t)
			copyCap := *c
			other := *a
			other.c.JWTSecret = append([]byte(nil), a.c.JWTSecret...)
			var live context.Context
			ctx := context.Background()
			switch mode {
			case "copy_second", "wrong_authority_after_bind":
				live = bindCommittedFixture(t, a, c)
			case "wrong_database":
				other.c.Registry.Database += "_other"
			case "wrong_secret":
				other.c.JWTSecret[0] ^= 1
			case "wrong_config":
				other.c.ConfigVersion++
			case "nil_context":
				ctx = nil
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "expired":
				copyCap.localDeadline = time.Now().Add(-time.Second)
			case "empty_rows":
				copyCap.rows.nonceID = 0
			}
			begins := f.db.begins
			bound, cancel, err := other.BindCommittedDownload(ctx, &copyCap)
			if cancel != nil {
				cancel()
			}
			if err == nil || bound != nil || f.db.begins != begins {
				t.Fatal("invalid/repeated binding escaped or accessed SQL")
			}
			if live != nil && a.CheckCommittedDownload(live, c) == nil {
				t.Fatal("failed copy did not poison original")
			}
			if _, cancel, err = a.BindCommittedDownload(context.Background(), c); err == nil || cancel != nil {
				t.Fatal("failed attempt was reusable")
			}
		})
	}
}

func TestCommittedDownloadRejectsChangedSQLAndLatchesFailure(t *testing.T) {
	type attack struct {
		name, witness string
		change        func(*admissionTxFixture, *SQLDownloadAuthority)
	}
	attacks := []attack{
		{"session_revoked", "FROM system_backup_v2_admin_sessions", func(f *admissionTxFixture, _ *SQLDownloadAuthority) { f.db.sessionRevoked = true }},
		{"password", "FROM system_backup_v2_admin_sessions", func(f *admissionTxFixture, _ *SQLDownloadAuthority) { f.db.password = "changed" }},
		{"role", "FROM users", func(f *admissionTxFixture, _ *SQLDownloadAuthority) { f.db.role = "user" }},
		{"user_disabled", "FROM users", func(f *admissionTxFixture, _ *SQLDownloadAuthority) { f.db.userActive = false }},
		{"account_revoked", "FROM system_backup_v2_admin_revocations", func(f *admissionTxFixture, _ *SQLDownloadAuthority) { f.db.revokedBefore = f.db.now }},
		{"session_shortened", "FROM system_backup_v2_admin_sessions", func(f *admissionTxFixture, _ *SQLDownloadAuthority) { f.db.sessionUntil = f.db.now.Add(time.Minute) }},
		{"active_config", "SELECT active_config_version", func(f *admissionTxFixture, _ *SQLDownloadAuthority) { f.db.activeConfig++ }},
		{"materialized_config", "canonical_config_json", func(f *admissionTxFixture, _ *SQLDownloadAuthority) { f.db.fault = "materialized_drift" }},
		{"legacy_config", "canonical_config_json", func(f *admissionTxFixture, _ *SQLDownloadAuthority) { f.db.fault = "canonical_missing" }},
		{"operation", downloadAdmissionOperationReadSQL, func(f *admissionTxFixture, _ *SQLDownloadAuthority) { f.db.m.fault = "operation_drift" }},
		{"receipt_rehashed", downloadAdmissionReceiptReadSQL, func(f *admissionTxFixture, _ *SQLDownloadAuthority) { f.db.m.fault = "receipt_rehashed" }},
		{"public_rehashed", downloadAdmissionReceiptReadSQL, func(f *admissionTxFixture, _ *SQLDownloadAuthority) { f.db.m.fault = "public_rehashed" }},
		{"nonce_issuer", downloadAdmissionNonceReadSQL, func(f *admissionTxFixture, _ *SQLDownloadAuthority) { f.db.nonce[1] = strings.Repeat("f", 64) }},
		{"nonce_subject", downloadAdmissionNonceReadSQL, func(f *admissionTxFixture, _ *SQLDownloadAuthority) { f.db.nonce[2] = strings.Repeat("f", 64) }},
		{"nonce_accepted", downloadAdmissionNonceReadSQL, func(f *admissionTxFixture, _ *SQLDownloadAuthority) { f.db.nonce[8] = f.db.now.Add(time.Microsecond) }},
		{"nonce_consumed", downloadAdmissionNonceReadSQL, func(f *admissionTxFixture, _ *SQLDownloadAuthority) {
			f.db.consumed = f.db.consumed.Add(time.Microsecond)
		}},
		{"nonce_other_history", downloadAdmissionNonceCandidateReadSQL, func(f *admissionTxFixture, _ *SQLDownloadAuthority) { f.db.preConsumed = "v1" }},
		{"history_added", "UNION SELECT nonce_hmac_key_version", func(f *admissionTxFixture, _ *SQLDownloadAuthority) {
			f.db.retainedVersions = []string{"v1", "v2", "v3"}
		}},
		{"history_removed", "UNION SELECT nonce_hmac_key_version", func(f *admissionTxFixture, _ *SQLDownloadAuthority) { f.db.retainedVersions = []string{"v2"} }},
		{"intent_body", downloadIntentReadSQL, func(f *admissionTxFixture, _ *SQLDownloadAuthority) { f.db.body = []byte(`{"changed":true}`) }},
		{"intent_time", downloadIntentReadSQL, func(f *admissionTxFixture, _ *SQLDownloadAuthority) {
			f.db.created = f.db.created.Add(time.Microsecond)
		}},
		{"null_origin", downloadCommittedOwnerSQL, func(f *admissionTxFixture, _ *SQLDownloadAuthority) { s := ""; f.db.committedOrigin = &s }},
		{"foreign_origin", downloadCommittedOwnerSQL, func(f *admissionTxFixture, _ *SQLDownloadAuthority) {
			s := "installation_other"
			f.db.committedOrigin = &s
		}},
		{"owner", downloadCommittedOwnerSQL, func(f *admissionTxFixture, _ *SQLDownloadAuthority) {
			f.db.record.Manifest.Identity.OwnerID = "sbk_22222222-2222-4333-8444-555555555555"
		}},
		{"claim", "SELECT id,owner_target_type", func(f *admissionTxFixture, _ *SQLDownloadAuthority) {
			f.db.record.Claim = "aev_" + strings.Repeat("f", 32)
		}},
		{"version", "SELECT id,owner_target_type", func(f *admissionTxFixture, _ *SQLDownloadAuthority) { f.db.record.RowVersion++ }},
		{"claim_deadline", "SELECT id,owner_target_type", func(f *admissionTxFixture, _ *SQLDownloadAuthority) {
			f.db.record.ClaimUntil = f.db.record.ClaimUntil.Add(time.Microsecond)
		}},
		{"ref", "SELECT id,owner_target_type", func(f *admissionTxFixture, _ *SQLDownloadAuthority) { f.db.record.Ref.ImmutableVersion = "v2" }},
		{"clock_backwards", "canonical_config_json", func(f *admissionTxFixture, _ *SQLDownloadAuthority) { f.db.now = f.db.now.Add(-time.Microsecond) }},
		{"expired_sql", "FROM system_backup_v2_admin_sessions", func(f *admissionTxFixture, _ *SQLDownloadAuthority) { f.db.now = f.db.now.Add(time.Hour) }},
		{"unknown_read_commit", "SELECT UTC_TIMESTAMP(6)", func(f *admissionTxFixture, _ *SQLDownloadAuthority) { f.db.commitUnknown = true }},
		{"rbac_file", "", func(_ *admissionTxFixture, a *SQLDownloadAuthority) {
			if err := os.WriteFile(filepath.Join(a.c.RegistryDirectory, "rbac_bindings", "v1", a.c.RBACSHA256+".json"), []byte("changed"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, v := range attacks {
		t.Run(v.name, func(t *testing.T) {
			f, a, c := committedFixture(t)
			ctx := bindCommittedFixture(t, a, c)
			// Validate this exact fixture reaches a successful SQL guard first.
			if err := a.CheckCommittedDownload(ctx, c); err != nil {
				t.Fatal("baseline", err, f.db.queries)
			}
			f.db.record = c.Record()
			queryStart, commits := len(f.db.queries), f.db.commits
			v.change(f, a)
			if a.CheckCommittedDownload(ctx, c) == nil {
				t.Fatal("changed committed/current fact accepted")
			}
			if v.witness != "" && !strings.Contains(strings.Join(f.db.queries[queryStart:], "\n"), v.witness) {
				t.Fatal("negative did not reach intended stage", v.witness, f.db.queries[queryStart:])
			}
			if v.name != "unknown_read_commit" && f.db.commits != commits {
				t.Fatal("failed read committed")
			}
			if len(f.db.m.op) != 14 || len(f.db.m.receipt) != 16 || len(f.db.nonce) != 16 || f.db.inserts != 1 {
				t.Fatal("failed read erased/repeated original admission")
			}
			// Reset the injected state. The shared failure must still prevent SQL.
			f.db.record = c.Record()
			f.db.fault = ""
			f.db.m.fault = ""
			f.db.sessionRevoked = false
			f.db.userActive = true
			f.db.role = "admin"
			f.db.password = "synthetic-current-password"
			f.db.revokedBefore = time.Time{}
			f.db.activeConfig = 1
			f.db.commitUnknown = false
			queryStart = len(f.db.queries)
			copyCap := *c
			if a.CheckCommittedDownload(ctx, &copyCap) == nil || a.CheckCommittedDownload(ctx, c) == nil || len(f.db.queries) != queryStart {
				t.Fatal("failed capability reusable")
			}
		})
	}
}

func TestCommittedDownloadProviderRangeAndCallerMismatchFailClosed(t *testing.T) {
	for _, mode := range []string{"partial_header", "partial_frame", "other_ref", "write", "actor", "manifest", "key", "transit_wrap", "download_wrap"} {
		t.Run(mode, func(t *testing.T) {
			f, a, c := committedFixture(t)
			ctx := bindCommittedFixture(t, a, c)
			writeCommittedProviderToken(t, a)
			if a.CheckCommittedDownload(ctx, c) != nil {
				t.Fatal("baseline")
			}
			scope := S3Scope{Operation: S3Range, Ref: c.record.Ref, Offset: 0, Length: c.record.Manifest.HeaderSize}
			switch mode {
			case "partial_header":
				scope.Length--
			case "partial_frame":
				scope.Offset = c.record.Manifest.Chunks[0].FrameOffset
				scope.Length = c.record.Manifest.Chunks[0].FrameLength - 1
			case "other_ref":
				scope.Ref.ImmutableVersion = "v2"
			case "write":
				scope.Operation = S3Put
			case "actor":
				if a.AuthorizeDownload(ctx, Actor{ID: "43"}, c.Record()) == nil {
					t.Fatal("actor")
				}
			case "manifest":
				r := c.Record()
				r.Manifest.Identity.Media = "application/json"
				if a.AuthorizeDownload(ctx, downloadActor(c.actor), r) == nil {
					t.Fatal("manifest")
				}
			case "key":
				if _, err := (DownloadKeys{Authority: a}).Unwrap(ctx, c.record.Manifest.Key, []byte("wrong")); err == nil {
					t.Fatal("key")
				}
			case "transit_wrap":
				if _, err := (&downloadTransitCredentials{}).Resolve(ctx, c.record.Manifest.Key, TransitWrap); err == nil {
					t.Fatal("wrap")
				}
			case "download_wrap":
				if _, err := (&DownloadTransit{}).Wrap(ctx, c.record.Manifest.Key, []byte("denied")); err == nil {
					t.Fatal("wrap")
				}
			}
			if mode == "partial_header" || mode == "partial_frame" || mode == "other_ref" || mode == "write" {
				if _, err := a.AuthorizeS3(ctx, scope); err == nil {
					t.Fatal("provider scope accepted")
				}
			}
			queries := len(f.db.queries)
			if a.CheckCommittedDownload(ctx, c) == nil || len(f.db.queries) != queries {
				t.Fatal("provider/caller failure did not poison admission")
			}
		})
	}
}

func TestCommittedDownloadFinalReadFollowsOwnerAuthorizationCallback(t *testing.T) {
	for _, mode := range []string{"session", "account_revocation", "nonce", "operation", "receipt", "intent", "evidence", "origin", "config", "clock"} {
		t.Run(mode, func(t *testing.T) {
			f, a, c := committedFixture(t)
			ctx := bindCommittedFixture(t, a, c)
			if err := a.CheckCommittedDownload(ctx, c); err != nil {
				t.Fatal("baseline", err)
			}
			p := a.c.Registry.Policy.(*committedTestPolicy)
			called, afterCallback := 0, 0
			witness := ""
			p.onAuthorize = func() {
				called++
				afterCallback = len(f.db.queries)
				switch mode {
				case "session":
					f.db.sessionRevoked = true
					witness = "FROM system_backup_v2_admin_sessions"
				case "account_revocation":
					f.db.revokedBefore = f.db.now
					witness = "FROM system_backup_v2_admin_revocations"
				case "nonce":
					f.db.nonce[2] = strings.Repeat("f", 64)
					witness = downloadAdmissionNonceReadSQL
				case "operation":
					f.db.m.op[6] = strings.Repeat("f", 64)
					witness = downloadAdmissionOperationReadSQL
				case "receipt":
					f.db.m.receipt[8] = strings.Repeat("f", 64)
					witness = downloadAdmissionReceiptReadSQL
				case "intent":
					f.db.created = f.db.created.Add(time.Second)
					witness = downloadIntentReadSQL
				case "evidence":
					f.db.record.Claim = "aev_" + strings.Repeat("f", 32)
					witness = "SELECT id,owner_target_type"
				case "origin":
					origin := ""
					f.db.committedOrigin = &origin
					witness = downloadCommittedOwnerSQL
				case "config":
					f.db.configCells["enabled"] = true
					witness = "canonical_config_json"
				case "clock":
					f.db.now = f.db.now.Add(-time.Microsecond)
					witness = downloadIntentClockSQL
				}
			}
			commits := f.db.commits
			if a.CheckCommittedDownload(ctx, c) == nil || called != 1 || f.db.commits != commits {
				t.Fatal("callback changed original facts without final rejection", called)
			}
			if !strings.Contains(strings.Join(f.db.queries[afterCallback:], "\n"), witness) {
				t.Fatal("final guard did not independently read changed fact", witness)
			}
			if f.db.record.Claim != c.record.Claim || f.db.m.op[6] != c.request.RequestHash() {
				t.Fatal("failed read did not roll back callback changes")
			}
		})
	}
}

func TestCommittedDownloadCanceledOrExpiredBindingStopsBeforeSQL(t *testing.T) {
	for _, mode := range []string{"canceled", "expired", "unbound_context", "other_authority"} {
		t.Run(mode, func(t *testing.T) {
			f, a, c := committedFixture(t)
			ctx, cancel, err := a.BindCommittedDownload(context.Background(), c)
			if err != nil {
				t.Fatal(err)
			}
			defer cancel()
			target := a
			switch mode {
			case "canceled":
				cancel()
			case "expired":
				c.localDeadline = time.Now().Add(-time.Second)
			case "unbound_context":
				ctx = context.Background()
			case "other_authority":
				other := *a
				target = &other
			}
			queries := len(f.db.queries)
			if target.CheckCommittedDownload(ctx, c) == nil || len(f.db.queries) != queries {
				t.Fatal("invalid bound authority reached SQL")
			}
		})
	}
}

func TestCommittedDownloadCipherFramesAreLimitedToSignedPlaintextRange(t *testing.T) {
	_, _, c := committedFixture(t)
	var err error
	c.request, err = BindSensitiveDownloadRequest(c.actor, c.record.Manifest, http.Header{"Idempotency-Key": {"range_scope_test_012345"}, "Range": {"bytes=4096-8191"}})
	if err != nil {
		t.Fatal(err)
	}
	// Scope selection only: this artificial three-frame layout is not submitted
	// to SQL/provider or represented as a valid encrypted object.
	c.record.Manifest.Chunks = []Chunk{{PlainOffset: 0, PlainLength: 4096, FrameOffset: 256, FrameLength: 4124}, {PlainOffset: 4096, PlainLength: 4096, FrameOffset: 4380, FrameLength: 4124}, {PlainOffset: 8192, PlainLength: 1, FrameOffset: 8504, FrameLength: 29}}
	for _, v := range []struct {
		offset, length int64
		want           bool
	}{{0, 256, true}, {0, 255, false}, {256, 4124, false}, {4380, 4124, true}, {8504, 29, false}, {257, 4123, false}, {256, 8248, false}, {9999, 1, false}} {
		if got := c.allowsS3(S3Scope{Operation: S3Range, Offset: v.offset, Length: v.length}); got != v.want {
			t.Fatalf("scope %d/%d got %v", v.offset, v.length, got)
		}
	}
}
