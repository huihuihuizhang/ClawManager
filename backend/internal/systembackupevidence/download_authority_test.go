package systembackupevidence

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackupsecurity"
	"github.com/golang-jwt/jwt/v5"
)

// This synthetic owner policy tests that the production authority invokes the
// D-owned boundary. It is never supplied by the runtime constructor itself.
type downloadTestPolicy struct {
	deadline              time.Time
	denyOwner             bool
	locks, authorizations int
	actor                 Actor
	required              []string
}

type downloadTestStepUp struct {
	calls int
	fail  bool
}

// This wrapper exercises the handler's in-transaction call with its synthetic
// memory registry. The SQL authority's transaction requirement is tested above.
type downloadTestAuthenticator struct {
	*SQLDownloadAuthority
	stepUp *downloadTestStepUp
}

func (a downloadTestAuthenticator) AuthorizeSensitiveDownload(ctx context.Context, request *http.Request, actor Actor, record Record, start, end int64, _ Locked) error {
	return a.stepUp.VerifyAndConsume(ctx, nil, request, actor, record, start, end)
}

func (s *downloadTestStepUp) VerifyAndConsume(_ context.Context, _ *sql.Tx, _ *http.Request, _ Actor, _ Record, start, end int64) error {
	s.calls++
	if s.fail || start < 0 || end < start {
		return ErrDenied
	}
	return nil
}

func (p *downloadTestPolicy) LockScope(_ context.Context, _ *sql.Tx, _ string, _ Identity) error {
	p.locks++
	if p.denyOwner {
		return ErrDenied
	}
	return nil
}
func (p *downloadTestPolicy) Admit(context.Context, *sql.Tx, Record, time.Time) error {
	return ErrDenied
}
func (p *downloadTestPolicy) Authorize(_ context.Context, _ *sql.Tx, a Actor, _ Record, required []string) error {
	p.authorizations++
	p.actor = a
	p.required = append([]string(nil), required...)
	if p.denyOwner {
		return ErrDenied
	}
	return nil
}
func (p *downloadTestPolicy) Deletable(context.Context, *sql.Tx, Record, time.Time) error {
	return ErrDenied
}
func (p *downloadTestPolicy) Audit(context.Context, *sql.Tx, Audit) error { return ErrDenied }
func (p *downloadTestPolicy) OwnerDeadline(context.Context, *sql.Tx, Identity) (time.Time, error) {
	return p.deadline, nil
}

type downloadFixture struct {
	a                      *SQLDownloadAuthority
	c                      DownloadAuthorityConfig
	db                     *authorityDB
	policy                 *downloadTestPolicy
	record                 Record
	actor                  Actor
	ctx                    context.Context
	request                *http.Request
	keys                   testKeys
	plain, object, wrapped []byte
	rbacFile               string
	stepUp                 *downloadTestStepUp
}

func newDownloadFixture(t *testing.T, role string) *downloadFixture {
	t.Helper()
	p, plain, object, keys := fixture(t, 9000)
	now := time.Now().UTC().Truncate(time.Microsecond)
	policy := &downloadTestPolicy{deadline: now.Add(time.Minute)}
	d := &authorityDB{t: t}
	db := sql.OpenDB(d)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	root := t.TempDir()
	rbac := []byte(fmt.Sprintf(`{"schema_version":"system-backup-registration-rbac.draft.v1","version":"v1","installation_id":"installation_test","bindings":[{"actor_id":"42","subject":"user:42","role":"%s"}]}`, role))
	stepUp := &downloadTestStepUp{}
	c := DownloadAuthorityConfig{Registry: SQLRegistry{DB: db, Installation: "installation_test", ServerUUID: "server", Database: "evidence-test", Policy: policy}, JWTSecret: bytes.Repeat([]byte{7}, 32), ConfigVersion: 3, ConfigSHA256: hash([]byte(`{}`)), RBACVersion: "v1", RBACSHA256: hash(rbac), RegistryDirectory: root, Root: "evidence", Store: KeyRef{strings.Repeat("a", 64), "v1"}, Read: KeyRef{strings.Repeat("c", 64), "read-v1"}, Issuer: "https://issuer.example", Audience: "download-sts", Subject: "system:serviceaccount:backup:evidence-reader", TokenFile: filepath.Join(root, "oidc-token"), ExpiresAt: now.Add(time.Hour), SensitiveStepUp: stepUp}
	dir := filepath.Join(root, "rbac_bindings", c.RBACVersion)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	rbacFile := filepath.Join(dir, c.RBACSHA256+".json")
	if err := os.WriteFile(rbacFile, rbac, 0600); err != nil {
		t.Fatal(err)
	}
	claims := jwt.MapClaims{"user_id": 42, "token_type": "access", "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(5 * time.Minute).Unix()}
	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(c.JWTSecret)
	if err != nil {
		t.Fatal(err)
	}
	projected, _ := json.Marshal(map[string]any{"iss": c.Issuer, "aud": c.Audience, "sub": c.Subject, "exp": now.Add(10 * time.Minute).Unix()})
	if err := os.WriteFile(c.TokenFile, []byte("header."+base64.RawURLEncoding.EncodeToString(projected)+".signature"), 0600); err != nil {
		t.Fatal(err)
	}
	key, _ := keyFor(c.Root, p.manifest.Identity)
	r := Record{Manifest: p.Manifest(), Ref: Ref{c.Store.Identity, c.Store.Version, key, "object-v1"}, State: "ready", Failure: "none", RowVersion: 2, CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), ProtectedUntil: now.Add(2 * time.Hour), OwnerDeadline: policy.deadline, Claim: "aev_0123456789abcdef0123456789abcdef", ClaimUntil: now.Add(25 * time.Second)}
	f := &downloadFixture{c: c, db: d, policy: policy, record: r, keys: keys, plain: plain, object: object, rbacFile: rbacFile, stepUp: stepUp}
	m, i, ch := r.Manifest, r.Manifest.Identity, r.Manifest.Chunks[0]
	nonce, _ := base64.RawURLEncoding.DecodeString(ch.Nonce)
	tag, _ := base64.RawURLEncoding.DecodeString(ch.Tag)
	password := "synthetic-password-hash"
	d.plan = []authorityQuery{
		{"SELECT @@server_uuid", nil, []driver.Value{c.Registry.ServerUUID, c.Registry.Database, now, int64(0)}},
		{"ORDER BY origin_installation_id FOR UPDATE", nil, []driver.Value{c.Registry.Installation}},
		{"SELECT active_config_version FROM", []driver.Value{c.Registry.Installation}, []driver.Value{c.ConfigVersion}},
		{"FROM system_backup_v2_configs", []driver.Value{c.Registry.Installation, c.ConfigVersion}, []driver.Value{c.ConfigSHA256, c.RBACVersion, c.RBACSHA256, c.Store.Identity, c.Store.Version, c.Read.Identity, c.Read.Version}},
		{"SELECT password_hash FROM users", []driver.Value{int64(42)}, []driver.Value{password}},
		{"FROM system_backup_v2_admin_sessions", []driver.Value{c.Registry.Installation, hash([]byte(accessToken))}, []driver.Value{int64(42), "user:42", hash([]byte(password)), now.Add(3 * time.Minute), false, now}},
		{"SELECT owner_target_type,owner_target_public_id", []driver.Value{i.ID}, []driver.Value{i.OwnerType, i.OwnerID}},
		{"FROM system_backup_v2_evidence WHERE public_id=? FOR UPDATE", []driver.Value{i.ID}, []driver.Value{int64(10), i.OwnerType, i.OwnerID, i.Type, r.State, r.Failure, r.Ref.Identity, r.Ref.Version, r.Ref.RelativeKey, r.Ref.ImmutableVersion, i.ContentHash, i.ContentSize, m.ObjectHash, m.ObjectSize, ChunkSize, int64(len(m.Chunks)), m.ChunkRoot, i.Media, "envelope_v1", m.Key.Identity, m.Key.Version, m.EnvelopeHash, i.Classification, r.Claim, r.ClaimUntil, r.ExpiresAt, r.ProtectedUntil, r.RowVersion, r.CreatedAt, "evidence", hash([]byte(key)), Framing}},
		{"FROM system_backup_v2_evidence_chunks", []driver.Value{int64(10)}, []driver.Value{ch.Index, ch.PlainOffset, ch.PlainLength, ch.PlainHash, ch.FrameOffset, ch.FrameLength, ch.CipherHash, nonce, tag}},
		{"SELECT UTC_TIMESTAMP(6)", nil, []driver.Value{now}},
	}
	f.a, err = NewSQLDownloadAuthority(c)
	if err != nil {
		t.Fatal(err)
	}
	f.request = httptest.NewRequest("GET", "https://local"+Path+i.ID, nil)
	f.request.TLS = &tls.ConnectionState{}
	f.request.Header.Set("Authorization", "Bearer "+accessToken)
	f.ctx, f.actor, err = f.a.AuthenticateContext(f.request)
	if err != nil {
		t.Fatal(err)
	}
	f.ctx = withEvidenceAccess(f.ctx, "download", r)
	var env envelope
	if err := json.Unmarshal(object[12:m.HeaderSize], &env); err != nil {
		t.Fatal(err)
	}
	f.wrapped, err = base64.StdEncoding.DecodeString(env.Wrapped)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestDownloadAuthoritySessionAndProviderScopes(t *testing.T) {
	f := newDownloadFixture(t, "security_admin")
	if err := f.a.AuthorizeDownload(f.ctx, f.actor, f.record); err != nil {
		t.Fatal(err)
	}
	if f.policy.actor != f.actor || !reflect.DeepEqual(f.policy.required, permissions("sensitive")) {
		t.Fatal("owner policy bypassed")
	}
	for _, scope := range []S3Scope{{Ref: f.record.Ref, Operation: S3Stat}, {Ref: f.record.Ref, Operation: S3Range, Length: f.record.Manifest.HeaderSize}} {
		g, err := f.a.AuthorizeS3(f.ctx, scope)
		defer wipe(g.Token)
		if err != nil || g.Authorization.AccessKind != "download" || g.Authorization.AttemptNumber != 0 || g.Authorization.Evidence != f.record.Manifest.Identity || !g.Authorization.ExpiresAt.Equal(f.record.ClaimUntil) {
			t.Fatal("download grant", err)
		}
	}
	// Password, session and frozen JWT secret are checked independently.
	for i := range f.c.JWTSecret {
		f.c.JWTSecret[i] = 0
	}
	if _, _, err := f.a.AuthenticateContext(f.request); err != nil {
		t.Fatal("secret alias", err)
	}
	for _, op := range []S3Operation{S3Put, S3Delete} {
		if g, err := f.a.AuthorizeS3(f.ctx, S3Scope{Ref: f.record.Ref, Operation: op}); err != ErrDenied || len(g.Token) != 0 {
			t.Fatal("write permission inherited")
		}
	}
	for _, scope := range []S3Scope{
		{Ref: Ref{f.record.Ref.Identity, f.record.Ref.Version, f.record.Ref.RelativeKey, "wrong-version"}, Operation: S3Stat},
		{Ref: f.record.Ref, Operation: S3Range, Offset: f.record.Manifest.ObjectSize, Length: 1},
		{Ref: f.record.Ref, Operation: S3Range, Length: ChunkSize + 29},
	} {
		if g, err := f.a.AuthorizeS3(f.ctx, scope); err != ErrDenied || len(g.Token) != 0 {
			t.Fatal("invalid scope admitted")
		}
	}
}

func TestDownloadAuthorityRequiresSensitiveStepUp(t *testing.T) {
	f := newDownloadFixture(t, "security_admin")
	tx, err := f.c.Registry.DB.BeginTx(f.ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	locked := &sqlLocked{registry: f.c.Registry, tx: tx, record: f.record}
	f.a.c.SensitiveStepUp = nil
	if err := f.a.AuthorizeSensitiveDownload(f.ctx, f.request, f.actor, f.record, 0, 20, locked); err != ErrDenied {
		t.Fatal("missing second factor accepted", err)
	}
	f.a.c.SensitiveStepUp = f.stepUp
	f.stepUp.fail = true
	if err := f.a.AuthorizeSensitiveDownload(f.ctx, f.request, f.actor, f.record, 0, 20, locked); err != ErrDenied || f.stepUp.calls != 1 {
		t.Fatal("failed second factor accepted", err)
	}
}

func TestDownloadAuthorityRejectsRevocationAndDrift(t *testing.T) {
	t.Run("commit_cancellation", func(t *testing.T) {
		f := newDownloadFixture(t, "security_admin")
		ctx, cancel := context.WithCancel(f.ctx)
		defer cancel()
		f.db.onCommit = cancel
		if err := f.a.AuthorizeDownload(ctx, f.actor, f.record); err != ErrDenied || f.db.commits != 1 {
			t.Fatal("cancellation during commit escaped", err)
		}
	})
	t.Run("session_ends_during_commit", func(t *testing.T) {
		f := newDownloadFixture(t, "security_admin")
		until := time.Now().Add(2 * time.Second)
		f.db.plan[5].values[3] = until
		f.db.onCommit = func() { time.Sleep(time.Until(until.Add(20 * time.Millisecond))) }
		if err := f.a.AuthorizeDownload(f.ctx, f.actor, f.record); err != ErrDenied || f.db.commits != 1 {
			t.Fatal("expired session escaped commit", err)
		}
	})
	for _, test := range []struct {
		name          string
		query, column int
		value         driver.Value
	}{
		{"database", 0, 1, "other"}, {"installation", 1, 0, "installation_other"}, {"active_config", 2, 0, int64(4)},
		{"config_hash", 3, 0, strings.Repeat("e", 64)}, {"rbac_hash", 3, 2, strings.Repeat("e", 64)}, {"store", 3, 3, strings.Repeat("e", 64)}, {"reader", 3, 6, "revoked"},
		{"password_changed", 4, 0, "new-hash"}, {"session_user", 5, 0, int64(43)}, {"session_subject", 5, 1, "user:43"}, {"credential_changed", 5, 2, strings.Repeat("e", 64)}, {"session_expired", 5, 3, time.Now().Add(-time.Minute)}, {"session_revoked", 5, 4, true},
		{"owner_changed", 6, 1, "sbk_aaaaaaaa-2222-4333-8444-555555555555"}, {"state", 7, 4, "deleting"}, {"version", 7, 9, ""}, {"claim_taken", 7, 23, "other"}, {"claim_expired", 7, 24, time.Now().Add(-time.Minute)}, {"row_version", 7, 27, int64(3)},
		{"clock_after_lock", 9, 0, time.Now().Add(time.Minute)},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newDownloadFixture(t, "security_admin")
			f.db.plan[test.query].values[test.column] = test.value
			if err := f.a.AuthorizeDownload(f.ctx, f.actor, f.record); err != ErrDenied || f.db.commits != 0 {
				t.Fatal("unsafe download", err)
			}
		})
	}
	for _, name := range []string{"bare_context", "other_authority", "task_claim", "gc_claim", "actor_mismatch", "manifest_mismatch", "owner_denied", "registry_removed", "registry_modified", "commit_failure"} {
		t.Run(name, func(t *testing.T) {
			f := newDownloadFixture(t, "security_admin")
			switch name {
			case "bare_context":
				f.ctx = context.Background()
			case "other_authority":
				other, err := NewSQLDownloadAuthority(f.c)
				if err != nil {
					t.Fatal(err)
				}
				f.a = other
			case "task_claim":
				f.ctx = withEvidenceAccess(f.ctx, "task", f.record)
			case "gc_claim":
				f.ctx = withEvidenceAccess(f.ctx, "gc", f.record)
			case "actor_mismatch":
				f.actor.ID = "43"
			case "manifest_mismatch":
				f.record.Manifest.Identity.ContentHash = strings.Repeat("e", 64)
			case "owner_denied":
				f.policy.denyOwner = true
			case "registry_removed":
				os.Remove(f.rbacFile)
			case "registry_modified":
				os.WriteFile(f.rbacFile, []byte(`{}`), 0600)
			case "commit_failure":
				f.db.commitErr = true
			}
			if err := f.a.AuthorizeDownload(f.ctx, f.actor, f.record); err != ErrDenied {
				t.Fatal(err)
			}
		})
	}
	for _, name := range []string{"no_tls", "no_bearer", "wrong_signature", "refresh_token"} {
		t.Run(name, func(t *testing.T) {
			f := newDownloadFixture(t, "security_admin")
			switch name {
			case "no_tls":
				f.request.TLS = nil
			case "no_bearer":
				f.request.Header.Del("Authorization")
			case "wrong_signature":
				f.request.Header.Set("Authorization", f.request.Header.Get("Authorization")+"x")
			case "refresh_token":
				token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"user_id": 42, "token_type": "refresh", "iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix()}).SignedString(f.c.JWTSecret)
				f.request.Header.Set("Authorization", "Bearer "+token)
			}
			if _, _, err := f.a.AuthenticateContext(f.request); err != ErrAuth {
				t.Fatal(err)
			}
		})
	}
}

func TestDownloadRBACClassificationMatrix(t *testing.T) {
	for _, role := range []string{"viewer", "operator", "config_admin", "security_admin"} {
		for _, classification := range []string{"public", "internal", "confidential", "sensitive"} {
			t.Run(role+"/"+classification, func(t *testing.T) {
				f := newDownloadFixture(t, role)
				raw, err := os.ReadFile(f.rbacFile)
				if err != nil {
					t.Fatal(err)
				}
				actor := systembackupsecurity.RegistrationActor{UserID: 42, Subject: "user:42"}
				err = systembackupsecurity.AuthorizeEvidencePermissions(raw, f.c.RBACSHA256, f.c.RBACVersion, f.c.Registry.Installation, actor, permissions(classification))
				want := classification == "public" || classification == "internal" || role == "security_admin" || classification == "confidential" && role == "operator"
				if (err == nil) != want {
					t.Fatal("wrong role/classification decision", err)
				}
			})
		}
	}
	for _, name := range []string{"duplicate", "case_alias", "missing", "null", "unknown_role", "unknown_permission"} {
		t.Run(name, func(t *testing.T) {
			f := newDownloadFixture(t, "security_admin")
			raw, _ := os.ReadFile(f.rbacFile)
			bad := string(raw)
			required := permissions("sensitive")
			switch name {
			case "duplicate":
				bad = strings.Replace(bad, `"role":"security_admin"`, `"role":"viewer","role":"security_admin"`, 1)
			case "case_alias":
				bad = strings.Replace(bad, `"role":"security_admin"`, `"role":"viewer","Role":"security_admin"`, 1)
			case "missing":
				bad = strings.Replace(bad, `,"role":"security_admin"`, "", 1)
			case "null":
				bad = strings.Replace(bad, `"role":"security_admin"`, `"role":null`, 1)
			case "unknown_role":
				bad = strings.Replace(bad, `"security_admin"`, `"superadmin"`, 1)
			case "unknown_permission":
				required = []string{"system_backup.everything"}
			}
			if err := systembackupsecurity.AuthorizeEvidencePermissions([]byte(bad), hash([]byte(bad)), f.c.RBACVersion, f.c.Registry.Installation, systembackupsecurity.RegistrationActor{UserID: 42, Subject: "user:42"}, required); err == nil {
				t.Fatal("unsafe RBAC accepted")
			}
		})
	}
}

type downloadUnwrapKeys struct {
	testKeys
	calls    int
	onUnwrap func()
	returned []byte
}

func (k *downloadUnwrapKeys) Unwrap(ctx context.Context, key KeyRef, wrapped []byte) ([]byte, error) {
	k.calls++
	dek, err := k.testKeys.Unwrap(ctx, key, wrapped)
	k.returned = dek
	if k.onUnwrap != nil {
		k.onUnwrap()
	}
	return dek, err
}

func TestDownloadUnwrapBindsEnvelopeAndRevocation(t *testing.T) {
	for _, name := range []string{"success", "different_wrapped_dek", "wrong_key", "revoke_during_unwrap", "wrap_denied"} {
		t.Run(name, func(t *testing.T) {
			f := newDownloadFixture(t, "security_admin")
			inner := &downloadUnwrapKeys{testKeys: f.keys}
			keys := DownloadKeys{Authority: f.a, Keys: inner}
			key := f.record.Manifest.Key
			wrapped := append([]byte(nil), f.wrapped...)
			switch name {
			case "different_wrapped_dek":
				wrapped[0] ^= 1
			case "wrong_key":
				key.Version = "other"
			case "revoke_during_unwrap":
				inner.onUnwrap = func() { f.db.plan[5].values[4] = true }
			case "wrap_denied":
				if dek, err := keys.Wrap(f.ctx, key, bytes.Repeat([]byte{1}, 32)); err != ErrKey || dek != nil {
					t.Fatal("wrap allowed")
				}
				return
			}
			dek, err := keys.Unwrap(f.ctx, key, wrapped)
			defer wipe(dek)
			if name == "success" {
				if err != nil || len(dek) != 32 || f.db.commits != 2 {
					t.Fatal(err)
				}
			} else {
				if err != ErrKey || dek != nil {
					t.Fatal("unwrap escaped", err)
				}
				if name == "revoke_during_unwrap" {
					if inner.calls != 1 || !bytes.Equal(inner.returned, make([]byte, 32)) {
						t.Fatal("revoked DEK not wiped")
					}
				} else if inner.calls != 0 {
					t.Fatal("wrong envelope reached KEK")
				}
			}
		})
	}
}

type downloadMemoryRegistry struct {
	*memoryRegistry
	actor Actor
}
type downloadMemoryLocked struct {
	Locked
	actor Actor
}

func (m downloadMemoryRegistry) WithLocked(ctx context.Context, id string, fn func(Locked) error) error {
	return m.memoryRegistry.WithLocked(ctx, id, func(tx Locked) error { return fn(downloadMemoryLocked{Locked: tx, actor: m.actor}) })
}
func (l downloadMemoryLocked) Authorize(_ context.Context, actor Actor, required []string) error {
	if actor != l.actor || !reflect.DeepEqual(required, permissions(l.Record().Manifest.Identity.Classification)) {
		return ErrDenied
	}
	return nil
}

func TestDownloadHandlerCarriesSessionAndRechecks(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		t.Run(fmt.Sprint(revoked), func(t *testing.T) {
			f := newDownloadFixture(t, "security_admin")
			// The synthetic registry owns claim/audit mechanics; the new authority
			// separately exercises real JWT, session/RBAC SQL and envelope binding.
			m := &memoryRegistry{r: f.record, now: time.Now().UTC()}
			m.r.Claim = ""
			m.r.ClaimUntil = time.Time{}
			m.r.RowVersion = 1
			f.db.onBegin = func(_ int) {
				f.db.plan[7].values[23] = m.r.Claim
				f.db.plan[7].values[24] = m.r.ClaimUntil
				f.db.plan[7].values[27] = m.r.RowVersion
			}
			store := &testStore{present: true, data: f.object, info: ObjectInfo{Version: f.record.Ref.ImmutableVersion, SHA256: f.record.Manifest.ObjectHash, Size: f.record.Manifest.ObjectSize}}
			if revoked {
				store.onRead = func() { f.db.plan[5].values[4] = true }
			}
			h := Handler{Auth: downloadTestAuthenticator{SQLDownloadAuthority: f.a, stepUp: f.stepUp}, Service: Service{Registry: downloadMemoryRegistry{memoryRegistry: m, actor: f.actor}, Store: store, Keys: DownloadKeys{Authority: f.a, Keys: f.keys}, Failure: func(context.Context, string, string) {}}}
			server := httptest.NewTLSServer(h)
			defer server.Close()
			r, _ := http.NewRequest("GET", server.URL+Path+f.record.Manifest.Identity.ID, nil)
			r.Header = f.request.Header.Clone()
			r.Header.Set("Range", "bytes=0-20")
			response, err := server.Client().Do(r)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(io.LimitReader(response.Body, 1024))
			if err != nil {
				t.Fatal(err)
			}
			if store.reads < 1 || f.db.begins < 2 {
				t.Fatal("test did not reach authorized object read")
			}
			if f.stepUp.calls != 1 {
				t.Fatal("sensitive read skipped second-factor boundary", f.stepUp.calls)
			}
			if revoked {
				if response.StatusCode != 503 || bytes.Contains(body, f.plain[:21]) {
					t.Fatal("revoked response leaked plaintext")
				}
			} else if response.StatusCode != 206 || !bytes.Equal(body, f.plain[:21]) {
				t.Fatal("valid download failed", response.StatusCode, string(body))
			}
			if m.r.Claim != "" {
				t.Fatal("claim not released")
			}
		})
	}
}
