package systembackupevidence

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"strings"
	"testing"
	"time"
)

type gcTestPolicy struct {
	*downloadTestPolicy
	denyDelete      bool
	deletableChecks int
	afterCheck      func()
}

func (p *gcTestPolicy) Deletable(context.Context, *sql.Tx, Record, time.Time) error {
	p.deletableChecks++
	if p.afterCheck != nil {
		p.afterCheck()
	}
	if p.denyDelete {
		return ErrConflict
	}
	return nil
}

type gcFixture struct {
	a      *SQLGCAuthority
	c      GCAuthorityConfig
	base   *downloadFixture
	peer   *taskFixture
	policy *gcTestPolicy
	ctx    context.Context
	record Record
}

func newGCFixture(t *testing.T) *gcFixture {
	t.Helper()
	base := newDownloadFixture(t, "security_admin")
	peer := newTaskFixture(t, false)
	now := time.Now().UTC().Truncate(time.Microsecond)
	policy := &gcTestPolicy{downloadTestPolicy: &downloadTestPolicy{deadline: now.Add(-10 * time.Minute)}}
	c := GCAuthorityConfig{Registry: base.c.Registry, ConfigVersion: base.c.ConfigVersion, ConfigSHA256: base.c.ConfigSHA256, Root: base.c.Root, Store: base.c.Store, Delete: KeyRef{strings.Repeat("d", 64), "delete-v1"}, OperationID: "sop_11111111-2222-4333-8444-555555555555", OperationClaim: "gc-worker-one", OperationRowVersion: 7, ClientCAPEM: peer.c.ClientCAPEM, ClientCASHA256: peer.c.ClientCASHA256, CertificateSHA256: peer.c.CertificateSHA256, Issuer: peer.c.Issuer, Audience: peer.c.Audience, Subject: peer.c.Subject, TokenFile: peer.c.TokenFile, ExpiresAt: peer.c.ExpiresAt}
	c.Registry.Policy = policy
	r := base.record
	r.State = "deleting"
	r.ExpiresAt = now.Add(-time.Minute)
	r.ProtectedUntil = now.Add(-time.Minute)
	r.OwnerDeadline = policy.deadline
	old := base.db.plan
	row := old[7]
	row.values[4] = r.State
	row.values[25] = r.ExpiresAt
	row.values[26] = r.ProtectedUntil
	base.db.plan = []authorityQuery{old[0], old[1], old[2],
		{"FROM system_backup_v2_configs", []driver.Value{c.Registry.Installation, c.ConfigVersion}, []driver.Value{c.ConfigSHA256, c.Store.Identity, c.Store.Version, c.Delete.Identity, c.Delete.Version, int64(60)}}, old[6],
		{"FROM system_backup_v2_operations", []driver.Value{c.Registry.Installation, c.OperationID}, []driver.Value{"evidence_gc", "system", c.Registry.Installation, "system", "system:controller", "running", c.OperationClaim, now.Add(time.Minute), c.OperationRowVersion, now.Add(2 * time.Minute)}}, row, old[8],
		{"SELECT UTC_TIMESTAMP(6)", nil, []driver.Value{now}}, {"SELECT UTC_TIMESTAMP(6)", nil, []driver.Value{now}},
	}
	a, err := NewSQLGCAuthority(c)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := a.AuthenticateRequest(peer.request)
	if err != nil {
		t.Fatal(err)
	}
	return &gcFixture{a: a, c: c, base: base, peer: peer, policy: policy, ctx: withEvidenceAccess(ctx, "gc", r), record: r}
}
func (f *gcFixture) scope(op S3Operation) S3Scope {
	s := S3Scope{Ref: f.record.Ref, Operation: op}
	if op == S3Delete {
		s.Object = ObjectInfo{Version: f.record.Ref.ImmutableVersion, SHA256: f.record.Manifest.ObjectHash, Size: f.record.Manifest.ObjectSize}
	}
	return s
}

func TestGCAuthorityExactVersionAndSeparateContext(t *testing.T) {
	f := newGCFixture(t)
	for _, op := range []S3Operation{S3Stat, S3Delete} {
		g, err := f.a.AuthorizeS3(f.ctx, f.scope(op))
		defer wipe(g.Token)
		if err != nil || g.Authorization.AccessKind != "gc" || g.Authorization.AttemptNumber != 0 || g.Authorization.Evidence != f.record.Manifest.Identity || !g.Authorization.ExpiresAt.Equal(f.record.ClaimUntil) {
			t.Fatalf("GC grant: %v", err)
		}
	}
	if f.policy.deletableChecks != 2 || f.policy.locks != 2 {
		t.Fatal("policy not checked for each provider access")
	}
	for _, ctx := range []context.Context{context.Background(), withEvidenceAccess(f.peer.ctx, "gc", f.record), withEvidenceAccess(f.base.ctx, "gc", f.record), withEvidenceAccess(f.ctx, "task", f.record), withEvidenceAccess(f.ctx, "download", f.record)} {
		g, err := f.a.AuthorizeS3(ctx, f.scope(S3Delete))
		wipe(g.Token)
		if err != ErrDenied {
			t.Fatal("GC borrowed a task/download identity or claim")
		}
	}
	other, err := NewSQLGCAuthority(f.c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = other.AuthorizeS3(f.ctx, f.scope(S3Stat)); err != ErrDenied {
		t.Fatal("context crossed authority instance")
	}
}

func TestGCAuthorityScopeAndRetentionFailures(t *testing.T) {
	for _, kind := range []string{"put", "range", "unversioned", "other version", "checksum", "length", "offset", "deadline", "protected", "unexpired", "references", "owner", "wrong state", "claim", "row version", "object key"} {
		t.Run(kind, func(t *testing.T) {
			f := newGCFixture(t)
			scope := f.scope(S3Delete)
			row := f.base.db.plan[6].values
			switch kind {
			case "put":
				scope.Operation = S3Put
			case "range":
				scope.Operation = S3Range
			case "unversioned":
				scope.Ref.ImmutableVersion = ""
			case "other version":
				scope.Ref.ImmutableVersion = "other"
				scope.Object.Version = "other"
			case "checksum":
				scope.Object.SHA256 = strings.Repeat("e", 64)
			case "length":
				scope.Object.Size++
			case "offset":
				scope.Offset = 1
			case "deadline":
				scope.Deadline = time.Now().Add(time.Minute)
			case "protected":
				row[26] = time.Now().Add(time.Hour)
			case "unexpired":
				row[25] = time.Now().Add(time.Hour)
			case "references":
				f.policy.denyDelete = true
			case "owner":
				f.policy.denyOwner = true
			case "wrong state":
				row[4] = "ready"
			case "claim":
				row[23] = "aev_other"
			case "row version":
				row[27] = int64(8)
			case "object key":
				scope.Ref.RelativeKey += "other"
			}
			g, err := f.a.AuthorizeS3(f.ctx, scope)
			if err != ErrDenied || len(g.Token) != 0 || f.base.db.commits != 0 {
				t.Fatalf("accepted %s: %v", kind, err)
			}
		})
	}
}

func TestGCAuthorityOperationAndConfigurationFailures(t *testing.T) {
	for _, kind := range []string{"operation type", "target type", "target", "actor type", "actor", "status", "worker", "lease", "operation version", "deadline", "active config", "config hash", "delete identity", "store identity", "database", "clock", "certificate expired", "commit error", "cancel on commit", "expire after policy"} {
		t.Run(kind, func(t *testing.T) {
			f := newGCFixture(t)
			op := f.base.db.plan[5].values
			config := f.base.db.plan[3].values
			switch kind {
			case "operation type":
				op[0] = "cleanup"
			case "target type":
				op[1] = "backup"
			case "target":
				op[2] = "installation_other"
			case "actor type":
				op[3] = "admin"
			case "actor":
				op[4] = "42"
			case "status":
				op[5] = "succeeded"
			case "worker":
				op[6] = "other"
			case "lease":
				op[7] = time.Now().Add(-time.Second)
			case "operation version":
				op[8] = int64(8)
			case "deadline":
				op[9] = time.Now().Add(-time.Second)
			case "active config":
				f.base.db.plan[2].values[0] = int64(4)
			case "config hash":
				config[0] = strings.Repeat("e", 64)
			case "delete identity":
				config[3] = strings.Repeat("e", 64)
			case "store identity":
				config[1] = strings.Repeat("e", 64)
			case "database":
				f.base.db.plan[0].values[0] = "other"
			case "clock":
				f.base.db.plan[9].values[0] = time.Now().Add(-time.Minute)
			case "certificate expired":
				f.a.c.ExpiresAt = time.Now().Add(-time.Second)
			case "commit error":
				f.base.db.commitErr = true
			case "cancel on commit":
				ctx, cancel := context.WithCancel(f.ctx)
				defer cancel()
				f.ctx = ctx
				f.base.db.onCommit = cancel
			case "expire after policy":
				f.policy.afterCheck = func() { f.base.db.plan[9].values[0] = time.Now().Add(time.Minute) }
			}
			g, err := f.a.AuthorizeS3(f.ctx, f.scope(S3Delete))
			if err != ErrDenied || len(g.Token) != 0 {
				t.Fatalf("accepted %s: %v", kind, err)
			}
		})
	}
}

func TestGCAbsenceAuthorizationBeforeAndAfterProvider(t *testing.T) {
	for _, kind := range []string{"success", "before", "during", "changed claim", "wrong request"} {
		t.Run(kind, func(t *testing.T) {
			f := newGCFixture(t)
			calls := 0
			request := S3AbsenceRequest{Ref: f.record.Ref, Challenge: strings.Repeat("f", 64)}
			if kind == "before" {
				f.policy.denyDelete = true
			}
			v := GCAbsenceVerifier{Authority: f.a, Verifier: s3AbsenceFunc(func(_ context.Context, r S3AbsenceRequest) (S3AbsenceProof, error) {
				calls++
				if kind == "during" {
					f.policy.denyDelete = true
				}
				if kind == "changed claim" {
					f.base.db.plan[5].values[8] = int64(8)
				}
				if kind == "wrong request" {
					r.Challenge = "other"
				}
				return S3AbsenceProof{Request: r, ObservedAt: time.Now(), ExpiresAt: time.Now().Add(time.Second)}, nil
			})}
			_, err := v.VerifyAbsent(f.ctx, request)
			if kind == "success" {
				if err != nil || calls != 1 {
					t.Fatal("proof denied", err)
				}
			} else {
				if err != ErrDenied {
					t.Fatal("unauthorized proof accepted")
				}
				if kind == "before" && calls != 0 {
					t.Fatal("provider called before authorization")
				}
			}
		})
	}
}

type gcResultMutationStore struct {
	Store
	afterAbsence func()
}

func (s gcResultMutationStore) Absent(ctx context.Context, r Ref) (Absence, error) {
	a, err := s.Store.Absent(ctx, r)
	s.afterAbsence()
	return a, err
}
func TestGCRechecksReferencesBeforeDroppingMetadata(t *testing.T) {
	for _, kind := range []string{"reference", "hold"} {
		t.Run(kind, func(t *testing.T) {
			s, m, _, _, _ := serviceFixture(t)
			m.now = m.now.Add(3 * time.Hour)
			s.Store = gcResultMutationStore{Store: s.Store, afterAbsence: func() {
				if kind == "reference" {
					m.referenced = true
				} else {
					m.r.ProtectedUntil = m.now.Add(time.Hour)
				}
			}}
			if err := s.GC(context.Background(), []string{m.r.Manifest.Identity.ID})[0]; err != ErrConflict {
				t.Fatalf("late %s not rejected: %v", kind, err)
			}
			if m.r.State == "deleted" || m.r.Ref.ImmutableVersion == "" || len(m.r.Manifest.Chunks) == 0 {
				t.Fatal("protected metadata discarded")
			}
		})
	}
}

func TestTaskContentRejectsCancellationAtCommit(t *testing.T) {
	f := newTaskFixture(t, false)
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	f.db.onCommit = cancel
	if _, err := f.a.AuthorizeContent(ctx, f.identity); err != ErrDenied {
		t.Fatal("content grant survived canceled commit", err)
	}
}

func TestGCAuthorityAdmissionAndPeer(t *testing.T) {
	f := newGCFixture(t)
	for _, kind := range []string{"database", "policy", "installation", "config", "store", "delete", "operation", "claim", "row", "CA", "certificate", "token path", "issuer", "audience", "subject", "expiry"} {
		t.Run(kind, func(t *testing.T) {
			c := f.c
			switch kind {
			case "database":
				c.Registry.DB = nil
			case "policy":
				c.Registry.Policy = nil
			case "installation":
				c.Registry.Installation = "other"
			case "config":
				c.ConfigSHA256 = "invalid"
			case "store":
				c.Store = KeyRef{}
			case "delete":
				c.Delete = KeyRef{}
			case "operation":
				c.OperationID = "other"
			case "claim":
				c.OperationClaim = ""
			case "row":
				c.OperationRowVersion = 0
			case "CA":
				c.ClientCASHA256 = strings.Repeat("e", 64)
			case "certificate":
				c.CertificateSHA256 = "invalid"
			case "token path":
				c.TokenFile = "relative-token"
			case "issuer":
				c.Issuer = "http://issuer.example"
			case "audience":
				c.Audience = ""
			case "subject":
				c.Subject = ""
			case "expiry":
				c.ExpiresAt = time.Now().Add(-time.Second)
			}
			if a, err := NewSQLGCAuthority(c); a != nil || err != ErrInvalid {
				t.Fatal("invalid admission accepted")
			}
		})
	}
	r := f.peer.request.Clone(context.Background())
	r.TLS = nil
	r.Header.Set("X-Client-Certificate", f.c.CertificateSHA256)
	if _, err := f.a.AuthenticateRequest(r); err != ErrAuth {
		t.Fatal("header accepted as mTLS")
	}
	other := newTaskFixture(t, false)
	if _, err := f.a.AuthenticateRequest(other.request); err != ErrAuth {
		t.Fatal("different peer certificate accepted")
	}
}
