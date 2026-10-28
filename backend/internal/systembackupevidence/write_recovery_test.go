package systembackupevidence

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This driver executes the real SQLRegistry scan/CAS boundary against a
// transactional fixture. It is not evidence of MySQL concurrency behavior.
type recoveryDB struct {
	*authorityDB
	record, pending                 Record
	audits, pendingAudits           []Audit
	writes, failWrite, failAudit    int
	unknownCommit                   bool
	observation, pendingObservation recoveryTestObservation
}

type recoveryTestObservation struct {
	health        string
	checked, next time.Time
}

func (d *recoveryDB) Connect(context.Context) (driver.Conn, error) { return d, nil }
func (d *recoveryDB) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if strings.HasPrefix(q, "SELECT next_reconcile_at FROM system_backup_v2_evidence") {
		if !strings.HasSuffix(q, "FOR UPDATE") || len(args) != 1 || args[0].Value != d.record.Manifest.Identity.ID {
			d.t.Fatal("scheduling check not locked to candidate")
		}
		return &authorityRows{values: []driver.Value{nullTime(d.observation.next)}}, nil
	}
	return d.authorityDB.QueryContext(ctx, q, args)
}
func (d *recoveryDB) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	d.pending = d.record
	d.pendingObservation = d.observation
	d.pendingAudits = nil
	r := d.record
	m, i := r.Manifest, r.Manifest.Identity
	row := d.plan[5].values
	row[1] = i.OwnerType
	row[2] = i.OwnerID
	row[3] = i.Type
	row[4] = r.State
	row[5] = r.Failure
	row[6] = r.Ref.Identity
	row[7] = r.Ref.Version
	row[8] = r.Ref.RelativeKey
	row[9] = nullString(r.Ref.ImmutableVersion)
	row[10] = i.ContentHash
	row[11] = i.ContentSize
	row[12] = m.ObjectHash
	row[13] = m.ObjectSize
	row[16] = m.ChunkRoot
	row[19] = m.Key.Identity
	row[20] = m.Key.Version
	row[21] = m.EnvelopeHash
	row[23] = nullString(r.Claim)
	row[24] = nullTime(r.ClaimUntil)
	row[25] = r.ExpiresAt
	row[26] = nullTime(r.ProtectedUntil)
	row[27] = r.RowVersion
	row[30] = hash([]byte(r.Ref.RelativeKey))
	if _, err := d.authorityDB.BeginTx(ctx, opts); err != nil {
		return nil, err
	}
	return d, nil
}
func (d *recoveryDB) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if !strings.HasPrefix(q, "UPDATE system_backup_v2_evidence SET storage_state=?") || (len(args) != 9 && len(args) != 12) {
		d.t.Fatal("recovery wrote outside evidence CAS")
	}
	d.writes++
	if d.failWrite == d.writes {
		return nil, errors.New("PRIVATE_SQL_ERROR")
	}
	if args[len(args)-2].Value != d.pending.Manifest.Identity.ID || args[len(args)-1].Value != d.pending.RowVersion {
		return driver.RowsAffected(0), nil
	}
	d.pending.State = args[0].Value.(string)
	d.pending.Failure = args[1].Value.(string)
	d.pending.Ref.ImmutableVersion = ""
	if args[2].Value != nil {
		d.pending.Ref.ImmutableVersion = args[2].Value.(string)
	}
	d.pending.Claim = ""
	if args[3].Value != nil {
		d.pending.Claim = args[3].Value.(string)
	}
	d.pending.ClaimUntil = time.Time{}
	if args[4].Value != nil {
		d.pending.ClaimUntil = args[4].Value.(time.Time)
	}
	d.pending.ExpiresAt = args[5].Value.(time.Time)
	d.pending.ProtectedUntil = time.Time{}
	if args[6].Value != nil {
		d.pending.ProtectedUntil = args[6].Value.(time.Time)
	}
	if len(args) == 12 {
		if !strings.Contains(q, ",observed_health=?,last_checked_at=?,next_reconcile_at=?") {
			d.t.Fatal("observation did not share state CAS")
		}
		d.pendingObservation = recoveryTestObservation{health: args[7].Value.(string), checked: args[8].Value.(time.Time)}
		if args[9].Value != nil {
			d.pendingObservation.next = args[9].Value.(time.Time)
		}
	} else if strings.Contains(q, "observed_health") || strings.Contains(q, "last_checked_at") || strings.Contains(q, "next_reconcile_at") {
		d.t.Fatal("claim-only save overwrote provider observation")
	}
	d.pending.RowVersion++
	return driver.RowsAffected(1), nil
}
func (d *recoveryDB) Commit() error {
	err := d.authorityDB.Commit()
	if err == nil || d.unknownCommit {
		d.record = d.pending
		d.observation = d.pendingObservation
		d.audits = append(d.audits, d.pendingAudits...)
	}
	return err
}
func (d *recoveryDB) Rollback() error { d.pendingAudits = nil; return nil }

type recoveryPolicy struct {
	*downloadTestPolicy
	db         *recoveryDB
	auditCalls int
}

func (p *recoveryPolicy) Audit(_ context.Context, _ *sql.Tx, a Audit) error {
	p.auditCalls++
	if p.db.failAudit == p.auditCalls {
		return ErrAudit
	}
	p.db.pendingAudits = append(p.db.pendingAudits, a)
	return nil
}

type recoveryFixture struct {
	a       *SQLWriteRecovery
	c       WriteRecoveryConfig
	db      *recoveryDB
	peer    *taskFixture
	policy  *recoveryPolicy
	ctx     context.Context
	signals []string
}

func newRecoveryFixture(t *testing.T) *recoveryFixture {
	t.Helper()
	base := newDownloadFixture(t, "security_admin")
	peer := newTaskFixture(t, false)
	now := time.Now().UTC().Truncate(time.Microsecond)
	r := base.record
	r.State = "write_unknown"
	r.Failure = "provider_unavailable"
	r.Ref.ImmutableVersion = ""
	r.Claim = ""
	r.ClaimUntil = time.Time{}
	r.RowVersion = 5
	r.OwnerDeadline = now.Add(-time.Minute)
	d := &recoveryDB{authorityDB: &authorityDB{t: t}, record: r}
	db := sql.OpenDB(d)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	policy := &recoveryPolicy{downloadTestPolicy: &downloadTestPolicy{deadline: r.OwnerDeadline}, db: d}
	c := WriteRecoveryConfig{Registry: SQLRegistry{DB: db, Installation: base.c.Registry.Installation, ServerUUID: base.c.Registry.ServerUUID, Database: base.c.Registry.Database, Policy: policy}, ConfigVersion: base.c.ConfigVersion, ConfigSHA256: base.c.ConfigSHA256, Root: base.c.Root, Store: base.c.Store, Read: base.c.Read, ClientCAPEM: peer.c.ClientCAPEM, ClientCASHA256: peer.c.ClientCASHA256, CertificateSHA256: peer.c.CertificateSHA256, Issuer: peer.c.Issuer, Audience: peer.c.Audience, Subject: peer.c.Subject, TokenFile: peer.c.TokenFile, ExpiresAt: peer.c.ExpiresAt}
	f := &recoveryFixture{c: c, db: d, peer: peer, policy: policy}
	c.Failure = func(_ context.Context, id, code string) {
		if id != r.Manifest.Identity.ID {
			t.Error("wrong signal evidence")
		}
		f.signals = append(f.signals, code)
	}
	f.c = c
	old := base.db.plan
	d.plan = []authorityQuery{old[0], old[1], old[2], {"FROM system_backup_v2_configs", []driver.Value{c.Registry.Installation, c.ConfigVersion}, []driver.Value{c.ConfigSHA256, c.Store.Identity, c.Store.Version, c.Read.Identity, c.Read.Version, int64(60)}}, old[6], old[7], old[8], {"SELECT UTC_TIMESTAMP(6)", nil, []driver.Value{now}}, {"SELECT UTC_TIMESTAMP(6)", nil, []driver.Value{now}}}
	var err error
	f.a, err = NewSQLWriteRecovery(c)
	if err != nil {
		t.Fatal(err)
	}
	f.ctx, err = f.a.AuthenticateRequest(peer.request)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

type recoveryStatFunc func(context.Context, Ref) (ObjectInfo, error)

func (f recoveryStatFunc) Stat(ctx context.Context, r Ref) (ObjectInfo, error) { return f(ctx, r) }
func (f *recoveryFixture) info() ObjectInfo {
	return ObjectInfo{Version: "recovered-v1", SHA256: f.db.record.Manifest.ObjectHash, Size: f.db.record.Manifest.ObjectSize}
}

func TestWriteRecoveryConvergesWithoutTaskOrWritePrivileges(t *testing.T) {
	for _, initial := range []string{"pending", "write_unknown"} {
		t.Run(initial, func(t *testing.T) {
			f := newRecoveryFixture(t)
			f.db.record.State = initial
			if initial == "pending" {
				f.db.record.Failure = "none"
			}
			want := f.info()
			calls := 0
			err := f.a.Reconcile(f.ctx, f.db.record.Manifest.Identity.ID, recoveryStatFunc(func(ctx context.Context, ref Ref) (ObjectInfo, error) {
				calls++
				if len(f.db.audits) != 1 || f.db.record.Claim == "" {
					t.Fatal("provider called before claim and intent commit")
				}
				g, err := f.a.AuthorizeS3(ctx, S3Scope{Ref: ref, Operation: S3Stat})
				defer wipe(g.Token)
				if err != nil || g.Authorization.AccessKind != "recovery" || g.Authorization.AttemptNumber != 0 || g.Authorization.Evidence != f.db.record.Manifest.Identity {
					t.Fatal("invalid recovery grant", err)
				}
				if _, err = f.peer.a.AuthorizeS3(ctx, S3Scope{Ref: ref, Operation: S3Stat}); err != ErrDenied {
					t.Fatal("recovery borrowed task authority")
				}
				for _, op := range []S3Operation{S3Put, S3Delete, S3Range} {
					if _, err = f.a.AuthorizeS3(ctx, S3Scope{Ref: ref, Operation: op}); err != ErrDenied {
						t.Fatal("recovery exposed other operation")
					}
				}
				return want, nil
			}))
			if err != nil || calls != 1 || f.db.record.State != "ready" || f.db.record.Ref.ImmutableVersion != want.Version || f.db.record.RowVersion != 7 || f.db.record.Claim != "" || len(f.db.audits) != 2 || len(f.signals) != 0 {
				t.Fatal("recovery did not converge", err)
			}
			if f.db.audits[0].Action != "evidence.recovery.intent" || f.db.audits[1].Action != "evidence.recovery.result" || f.db.audits[1].Outcome != "ready" {
				t.Fatal("wrong audit pair")
			}
		})
	}
}

func TestWriteRecoveryUnknownAndConflictingObjectsRetainEvidence(t *testing.T) {
	for _, kind := range []string{"404", "unavailable", "denied", "checksum", "length", "null version"} {
		t.Run(kind, func(t *testing.T) {
			f := newRecoveryFixture(t)
			info := f.info()
			var observed error
			expectedState := "write_unknown"
			expectedCode := "evidence_incomplete"
			switch kind {
			case "404":
				observed = ErrNotFound
			case "unavailable":
				observed = errors.New("PRIVATE_PROVIDER_ERROR")
			case "denied":
				observed = ErrDenied
			case "checksum":
				info.SHA256 = strings.Repeat("e", 64)
			case "length":
				info.Size++
			case "null version":
				info.Version = "null"
			}
			if observed == nil {
				expectedState = "write_failed"
				expectedCode = "checksum_mismatch"
			}
			err := f.a.Reconcile(f.ctx, f.db.record.Manifest.Identity.ID, recoveryStatFunc(func(context.Context, Ref) (ObjectInfo, error) { return info, observed }))
			if err == nil || strings.Contains(err.Error(), "PRIVATE") || f.db.record.State != expectedState || f.db.record.Ref.ImmutableVersion != "" || len(f.db.record.Manifest.Chunks) == 0 || f.db.record.Ref.RelativeKey == "" || len(f.signals) != 1 || f.signals[0] != expectedCode {
				t.Fatal("failure lost or misclassified evidence", err)
			}
		})
	}
}

func TestWriteRecoveryDeniesInvalidAdmissionAndCandidate(t *testing.T) {
	for _, kind := range []string{"no peer", "task peer", "before deadline", "active claim", "ready", "deleted", "known version", "owner", "config", "read ref", "store ref", "database", "clock", "expired admission", "intent audit", "claim CAS", "claim commit"} {
		t.Run(kind, func(t *testing.T) {
			f := newRecoveryFixture(t)
			calls := 0
			switch kind {
			case "no peer":
				f.ctx = context.Background()
			case "task peer":
				f.ctx = f.peer.ctx
			case "before deadline":
				f.policy.deadline = time.Now().Add(time.Hour)
			case "active claim":
				f.db.record.Claim = "other"
				f.db.record.ClaimUntil = time.Now().Add(time.Minute)
			case "ready":
				f.db.record.State = "ready"
			case "deleted":
				f.db.record.State = "deleted"
			case "known version":
				f.db.record.Ref.ImmutableVersion = "old"
			case "owner":
				f.policy.denyOwner = true
			case "config":
				f.db.plan[2].values[0] = int64(9)
			case "read ref":
				f.db.plan[3].values[3] = strings.Repeat("e", 64)
			case "store ref":
				f.db.plan[3].values[1] = strings.Repeat("e", 64)
			case "database":
				f.db.plan[0].values[0] = "other"
			case "clock":
				f.db.plan[7].values[0] = time.Now().Add(-time.Minute)
			case "expired admission":
				f.a.c.ExpiresAt = time.Now().Add(-time.Second)
			case "intent audit":
				f.db.failAudit = 1
			case "claim CAS":
				f.db.failWrite = 1
			case "claim commit":
				f.db.commitErr = true
			}
			err := f.a.Reconcile(f.ctx, f.db.record.Manifest.Identity.ID, recoveryStatFunc(func(context.Context, Ref) (ObjectInfo, error) { calls++; return f.info(), nil }))
			if err == nil || calls != 0 || f.db.record.RowVersion != 5 || len(f.db.audits) != 0 {
				t.Fatalf("invalid %s reached provider: %v", kind, err)
			}
		})
	}
}

func TestLegacyWriteRecoveryCannotClaimSystemProducerEvidence(t *testing.T) {
	f := newRecoveryFixture(t)
	i := &f.db.record.Manifest.Identity
	i.OwnerType, i.OwnerID, i.Type = "system", f.c.Registry.Installation, "capability_snapshot"
	key, err := keyFor(f.c.Root, *i)
	if err != nil {
		t.Fatal(err)
	}
	f.db.record.Ref.RelativeKey = key
	f.db.plan[4].values = []driver.Value{i.OwnerType, i.OwnerID}
	stats := 0
	err = f.a.Reconcile(f.ctx, i.ID, recoveryStatFunc(func(context.Context, Ref) (ObjectInfo, error) {
		stats++
		return f.info(), nil
	}))
	if err != ErrDenied || stats != 0 || f.db.index != 7 || f.db.record.RowVersion != 5 || f.db.writes != 0 || len(f.db.audits) != 0 {
		t.Fatalf("legacy recovery reached system evidence: err=%v stats=%d reads=%d writes=%d", err, stats, f.db.index, f.db.writes)
	}
}

func TestLegacyWriteRecoveryKeepsOrdinarySystemEvidence(t *testing.T) {
	f := newRecoveryFixture(t)
	i := &f.db.record.Manifest.Identity
	i.OwnerType, i.OwnerID, i.Type = "system", f.c.Registry.Installation, "diagnostic"
	key, err := keyFor(f.c.Root, *i)
	if err != nil {
		t.Fatal(err)
	}
	f.db.record.Ref.RelativeKey = key
	f.db.plan[4].values = []driver.Value{i.OwnerType, i.OwnerID}
	stats := 0
	err = f.a.Reconcile(f.ctx, i.ID, recoveryStatFunc(func(context.Context, Ref) (ObjectInfo, error) {
		stats++
		return f.info(), nil
	}))
	if err != nil || stats != 1 || f.db.record.State != "ready" || f.db.record.RowVersion != 7 || len(f.db.audits) != 2 {
		t.Fatalf("ordinary system evidence recovery regressed: err=%v stats=%d state=%s", err, stats, f.db.record.State)
	}
}

func TestWriteRecoveryRechecksBeforeResultCommit(t *testing.T) {
	for _, kind := range []string{"claim takeover", "config rotation", "manifest drift", "expired claim", "cancel", "result audit", "result CAS", "unknown result commit"} {
		t.Run(kind, func(t *testing.T) {
			f := newRecoveryFixture(t)
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			want := f.info()
			err := f.a.Reconcile(ctx, f.db.record.Manifest.Identity.ID, recoveryStatFunc(func(context.Context, Ref) (ObjectInfo, error) {
				switch kind {
				case "claim takeover":
					f.db.record.Claim = "other"
				case "config rotation":
					f.db.plan[2].values[0] = int64(9)
				case "manifest drift":
					f.db.record.Manifest.Key.Version = "rotated"
				case "expired claim":
					f.db.record.ClaimUntil = time.Now().Add(-time.Second)
				case "cancel":
					cancel()
				case "result audit":
					f.db.failAudit = 2
				case "result CAS":
					f.db.failWrite = 2
				case "unknown result commit":
					f.db.commitErr = true
					f.db.unknownCommit = true
				}
				return want, nil
			}))
			if err == nil || len(f.signals) != 1 || f.signals[0] != "evidence_incomplete" {
				t.Fatal("result failure unreported", err)
			}
			if kind != "unknown result commit" && (f.db.record.State == "ready" || f.db.record.Ref.ImmutableVersion != "" || len(f.db.audits) != 1) {
				t.Fatal("uncommitted result exposed")
			}
		})
	}
}

func TestWriteRecoverySTSRestrictsRecoveryKind(t *testing.T) {
	f := newSTSFixture(t, "ok")
	scope := f.scope
	scope.Operation = S3Stat
	scope.Offset = 0
	scope.Length = 0
	scope.Ref.ImmutableVersion = ""
	g := f.grant(scope)
	g.Authorization.AccessKind = "recovery"
	g.Authorization.AttemptNumber = 0
	defer wipe(g.Token)
	if !f.resolver.validGrant(g, scope) {
		t.Fatal("read-only recovery grant denied")
	}
	for _, op := range []S3Operation{S3Put, S3Delete, S3Range} {
		bad := g
		bad.Authorization.Scope.Operation = op
		if f.resolver.validGrant(bad, bad.Authorization.Scope) {
			t.Fatal("recovery grant permitted non-Stat")
		}
	}
	bad := g
	bad.Authorization.AttemptNumber = 1
	if f.resolver.validGrant(bad, scope) {
		t.Fatal("task attempt on recovery grant")
	}
}

func TestWriteRecoveryConstructorRequiresSignalAndPeer(t *testing.T) {
	f := newRecoveryFixture(t)
	for _, kind := range []string{"policy", "signal", "CA", "certificate", "token", "read", "expiry"} {
		t.Run(kind, func(t *testing.T) {
			c := f.c
			switch kind {
			case "policy":
				c.Registry.Policy = nil
			case "signal":
				c.Failure = nil
			case "CA":
				c.ClientCASHA256 = strings.Repeat("e", 64)
			case "certificate":
				c.CertificateSHA256 = "invalid"
			case "token":
				c.TokenFile = "relative"
			case "read":
				c.Read = KeyRef{}
			case "expiry":
				c.ExpiresAt = time.Now().Add(-time.Second)
			}
			if a, err := NewSQLWriteRecovery(c); err != ErrInvalid || a != nil {
				t.Fatal("invalid constructor accepted")
			}
		})
	}
	r := f.peer.request.Clone(context.Background())
	r.TLS = nil
	if _, err := f.a.AuthenticateRequest(r); err != ErrAuth {
		t.Fatal("non-mTLS request accepted")
	}
}

func TestWriteRecoveryPersistsObservationWithResult(t *testing.T) {
	for _, result := range []string{"ready", "unknown", "conflict"} {
		t.Run(result, func(t *testing.T) {
			f := newRecoveryFixture(t)
			now := f.db.plan[7].values[0].(time.Time)
			before := recoveryTestObservation{"degraded", now.Add(-time.Hour), now.Add(-time.Minute)}
			f.db.observation = before
			f.db.plan[3].values[5] = int64(123)
			info := f.info()
			var providerErr error
			want := recoveryTestObservation{health: "healthy", checked: now}
			switch result {
			case "unknown":
				providerErr = ErrNotFound
				want.health, want.next = "unknown", now.Add(123*time.Second)
			case "conflict":
				info.Size++
				want.health = "degraded"
			}
			err := f.a.Reconcile(f.ctx, f.db.record.Manifest.Identity.ID, recoveryStatFunc(func(ctx context.Context, ref Ref) (ObjectInfo, error) {
				if f.db.observation != before {
					t.Fatal("claim acquisition manufactured a check")
				}
				grant, err := f.a.AuthorizeS3(ctx, S3Scope{Ref: ref, Operation: S3Stat})
				wipe(grant.Token)
				if err != nil || f.db.observation != before {
					t.Fatal("authorization changed observation", err)
				}
				return info, providerErr
			}))
			if (err == nil) != (result == "ready") || f.db.observation != want || f.db.record.RowVersion != 7 || len(f.db.audits) != 2 {
				t.Fatalf("non-atomic or incorrect observation: %v %+v", err, f.db.observation)
			}
		})
	}
}

func TestWriteRecoveryObservationRollsBackWithResult(t *testing.T) {
	for _, failure := range []string{"audit", "CAS", "commit"} {
		t.Run(failure, func(t *testing.T) {
			f := newRecoveryFixture(t)
			now := f.db.plan[7].values[0].(time.Time)
			before := recoveryTestObservation{"unknown", now.Add(-time.Hour), now.Add(-time.Minute)}
			f.db.observation = before
			err := f.a.Reconcile(f.ctx, f.db.record.Manifest.Identity.ID, recoveryStatFunc(func(context.Context, Ref) (ObjectInfo, error) {
				switch failure {
				case "audit":
					f.db.failAudit = 2
				case "CAS":
					f.db.failWrite = 2
				case "commit":
					f.db.commitErr = true
				}
				return f.info(), nil
			}))
			if err == nil || f.db.observation != before || f.db.record.State != "write_unknown" || len(f.db.audits) != 1 {
				t.Fatal("failed result exposed new observation", err)
			}
		})
	}
}

func TestWriteRecoveryRequiresBoundedDatabaseRetryPolicy(t *testing.T) {
	for _, seconds := range []int64{-1, 0, 4, 5, 600, 601, 1 << 62} {
		t.Run(strconv.FormatInt(seconds, 10)+"s", func(t *testing.T) {
			f := newRecoveryFixture(t)
			f.db.plan[3].values[5] = seconds
			calls := 0
			err := f.a.Reconcile(f.ctx, f.db.record.Manifest.Identity.ID, recoveryStatFunc(func(context.Context, Ref) (ObjectInfo, error) {
				calls++
				return ObjectInfo{}, ErrNotFound
			}))
			if seconds >= 5 && seconds <= 600 {
				now := f.db.plan[7].values[0].(time.Time)
				if err != ErrNotFound || calls != 1 || !f.db.observation.next.Equal(now.Add(time.Duration(seconds)*time.Second)) {
					t.Fatal("valid retry bound lost", err)
				}
			} else if err != ErrDenied || calls != 0 || f.db.writes != 0 || len(f.db.audits) != 0 {
				t.Fatal("invalid retry policy reached provider", err)
			}
		})
	}
}
