package systembackupproducer

import (
	"context"
	"database/sql/driver"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Independent proof acceptance is synthetic here. These tests validate D's
// composition and CAS, not C signatures/provider authenticity or real A SQL.
type finishTestEnvironment struct {
	base           *claimTestEnvironment
	expected       FinishRequest
	fail           string
	alterAdmission func(*FinishAdmission)
	alterRefs      func(*ReferenceApproval)
	alterEvidence  func(*FinishEvidence)
}

func (e *finishTestEnvironment) phase(n string) error {
	e.base.m.events = append(e.base.m.events, "finish:"+n)
	if e.fail == n {
		return ErrUnavailable
	}
	return nil
}
func (e *finishTestEnvironment) PrepareFinish(_ context.Context, _ FinishBinding) (PreparedFinish, error) {
	if err := e.phase("prepare"); err != nil {
		return PreparedFinish{}, err
	}
	v := PreparedFinish{Session: e}
	if !e.base.noReport {
		s := e.base.db.now
		v.CapacityObservedAt = &s
	}
	return v, nil
}
func (e *finishTestEnvironment) LockInstallation(context.Context, SQL, FinishBinding) error {
	e.base.db.now = e.base.db.now.Add(e.base.wait)
	return e.phase("installation")
}
func (e *finishTestEnvironment) Authenticate(_ context.Context, _ SQL, b FinishBinding, _ DomainRecord) (FinishAdmission, error) {
	if err := e.phase("authenticate"); err != nil {
		return FinishAdmission{}, err
	}
	if !reflect.DeepEqual(e.expected, b.Request) {
		return FinishAdmission{}, ErrGuardRequired
	}
	h, _ := FinishBindingHash(b)
	a := FinishAdmission{RequestHash: h, IdentityHash: b.Subject, VerifiedProofHash: e.expected.ProofHash, IdentityExpiresAt: Timestamp(e.base.db.now.Add(time.Minute).Format(timeLayout)), ProofExpiresAt: Timestamp(e.base.db.now.Add(5 * time.Second).Format(timeLayout)), AdditionalCost: "65536"}
	if e.alterAdmission != nil {
		e.alterAdmission(&a)
	}
	return a, nil
}
func (e *finishTestEnvironment) LockHost(context.Context, SQL, FinishBinding, GrantRecord) error {
	return e.phase("host")
}
func (e *finishTestEnvironment) LockReferences(_ context.Context, _ SQL, b FinishBinding, _ FinishFacts) (ReferenceApproval, error) {
	if err := e.phase("refs"); err != nil {
		return ReferenceApproval{}, err
	}
	h, _ := FinishBindingHash(b)
	r := ReferenceApproval{RequestHash: h, PolicyHash: e.base.policy, VersionHash: e.base.refs, DependencyExpiresAt: Timestamp(e.base.db.now.Add(time.Minute).Format(timeLayout))}
	if e.alterRefs != nil {
		e.alterRefs(&r)
	}
	return r, nil
}
func (e *finishTestEnvironment) Reserve(_ context.Context, _ SQL, _ FinishBinding, c uint64) error {
	e.base.reserves++
	e.base.cost = c
	return e.phase("reserve")
}
func (e *finishTestEnvironment) Audit(_ context.Context, _ SQL, _ FinishBinding, stage string) error {
	return e.phase("audit:" + stage)
}
func (e *finishTestEnvironment) current() FinishEvidence {
	row := e.base.m.rows[claimTestTable][0].Columns
	v := FinishEvidence{ClaimEvidence: e.base.current(), Failure: row["failure"].(string)}
	if row["immutable"] != nil {
		version := Text(row["immutable"].(string))
		v.ImmutableVersion = &version
	}
	return v
}
func (e *finishTestEnvironment) LockEvidence(context.Context, SQL, FinishBinding, FinishFacts) (FinishEvidence, error) {
	e.base.db.now = e.base.db.now.Add(e.base.evidenceWait)
	if err := e.phase("evidence"); err != nil {
		return FinishEvidence{}, err
	}
	v := e.current()
	if e.alterEvidence != nil {
		e.alterEvidence(&v)
	}
	return v, nil
}
func (e *finishTestEnvironment) Recheck(_ context.Context, _ ReadSQL, _ FinishBinding, f FinishFacts, _ time.Time) error {
	if err := e.phase("recheck"); err != nil {
		return err
	}
	if !reflect.DeepEqual(f.Evidence, e.current()) {
		return ErrConflict
	}
	return nil
}
func setupFinish(t *testing.T) (*Finalizer, *PublicationClaim, FinishRequest, *fakeDB, *finishTestEnvironment, *commandMemory) {
	t.Helper()
	pub, h, request, db, base, m := setupClaim(t)
	claim, err := pub.ClaimPublication(context.Background(), h, request)
	if err != nil {
		t.Fatal(err)
	}
	db.now = db.now.Add(time.Second)
	version := Text("object-v1")
	r := FinishRequest{State: "ready", ProofHash: Hash(strings.Repeat("c", 64)), ObjectHash: base.history.Evidence.ObjectHash, ObjectBytes: base.history.Evidence.ObjectBytes, ImmutableVersion: &version, ObservedAt: Timestamp(db.now.Format(timeLayout)), BudgetUntil: Timestamp(db.now.Add(4 * time.Second).Format(timeLayout))}
	env := &finishTestEnvironment{base: base, expected: detached(r)}
	row := m.rows[claimTestTable][0].Columns
	row["failure"] = "none"
	row["immutable"] = nil
	row["health"] = "unknown"
	previous := db.execRecord
	db.execRecord = func(q string, a []driver.NamedValue) (driver.Result, error) {
		if q != finishPublicationCAS {
			return previous(q, a)
		}
		if len(a) != 9 {
			return nil, ErrInvalid
		}
		c := m.rows[claimTestTable][0].Columns
		v := Counter(c["version"].(string))
		n, err := v.SQLInt64()
		if err != nil {
			return nil, err
		}
		if a[3].Value != c["id"] || a[4].Value != n || a[5].Value != string(h.scope.Installation) || a[6].Value != c["state"] || a[7].Value != c["owner"] || !reflect.DeepEqual(a[8].Value, c["until"]) || c["immutable"] != nil {
			return driver.RowsAffected(0), nil
		}
		next, _ := nextCounter(v)
		c["state"] = a[0].Value
		c["failure"] = a[1].Value
		c["immutable"] = a[2].Value
		c["owner"] = nil
		c["until"] = nil
		c["version"] = string(next)
		m.events = append(m.events, "cas:finish")
		return driver.RowsAffected(1), nil
	}
	finalizer, err := NewFinalizer(pub.execution, env)
	if err != nil {
		t.Fatal(err)
	}
	base.reserves = 0
	m.events = nil
	return finalizer, claim, r, db, env, m
}
func TestFinishReadyAndUnknownAreAtomicAndConsumeClaim(t *testing.T) {
	for _, state := range []string{"ready", "write_unknown"} {
		t.Run(state, func(t *testing.T) {
			p, c, r, db, env, m := setupFinish(t)
			r.State = state
			if state == "write_unknown" {
				r.ImmutableVersion = nil
			}
			env.expected = detached(r)
			before := cloneMemory(m.rows)
			commits := db.commits
			out, err := p.FinishPublication(context.Background(), c, r)
			if err != nil || out.State != state || out.EvidenceVersion != "3" || !reflect.DeepEqual(out.ImmutableVersion, r.ImmutableVersion) || db.commits != commits+1 || env.base.reserves != 1 || env.base.cost != 131072 {
				t.Fatal(out, err)
			}
			for table, rows := range before {
				if table != claimTestTable && !(state == "ready" && table == "system_backup_producer_runs") && !reflect.DeepEqual(rows, m.rows[table]) {
					t.Fatal("changed D history/result", table)
				}
			}
			row := m.rows[claimTestTable][0].Columns
			if row["owner"] != nil || row["until"] != nil || row["health"] != "unknown" {
				t.Fatal("claim/health", row)
			}
			if state == "write_unknown" && (row["immutable"] != nil || row["failure"] != "provider_unavailable") {
				t.Fatal("unknown fabricated ready", row)
			}
			want := []string{"finish:prepare", "finish:installation", "lock:system_backup_producer_domains", "finish:authenticate", "lock:system_backup_producer_grants", "lock:system_backup_producer_runs", "lock:system_backup_producer_evidence_bindings", "finish:host", "lock:system_backup_producer_targets", "lock:system_backup_producer_evidence_refs", "finish:refs", "finish:reserve", "finish:audit:intent", "finish:evidence", "cas:finish", "finish:audit:result", "finish:recheck"}
			var run RunRecord
			loadMemoryRecord(t, m, &run, 0)
			if state == "ready" {
				want = append(want[:15], append([]string{"update:system_backup_producer_runs"}, want[15:]...)...)
				if run.State != "published" || run.RowVersion != "4" {
					t.Fatal("ready must atomically publish run", run)
				}
			} else if run.State != "pending" || run.RowVersion != "3" {
				t.Fatal("unknown must preserve pending run", run)
			}
			if !reflect.DeepEqual(want, m.events) {
				t.Fatal("order", m.events)
			}
			executionEnv := p.execution.environment.(*executionTestEnvironment)
			executionEnv.policy = c.binding.PolicyHash
			executionEnv.refVersion = c.binding.RefsVersionHash
			current := env.current().ClaimEvidence.Evidence
			executionEnv.evidence = &current
			call := CallRequest{Purpose: "publish", EvidenceID: c.binding.EvidenceID, RefIdentityHash: env.base.history.Evidence.StoreIdentityHash, RefVersion: ProviderVersion(env.base.history.Evidence.StoreRefVersion), PolicyHash: c.binding.PolicyHash, BudgetUntil: r.BudgetUntil}
			if snapshot, err := p.execution.BeginCall(context.Background(), &c.handle, call, c); err == nil || snapshot != nil {
				t.Fatal("consumed claim usable")
			}
			before = cloneMemory(m.rows)
			if out, err = p.FinishPublication(context.Background(), c, r); err == nil || !reflect.DeepEqual(out, FinishResult{}) || !reflect.DeepEqual(before, m.rows) {
				t.Fatal("duplicate finish", out, err)
			}
		})
	}
}
func TestFinishFailureRollbacks(t *testing.T) {
	for _, name := range []string{"prepare", "installation", "authenticate", "host", "refs", "reserve", "audit:intent", "evidence", "audit:result", "recheck", "no_report", "stale_report", "evidence_wait", "proof_hash", "request_hash", "identity", "identity_expired", "proof_expired", "refs_version", "policy", "dependency_expired", "cost_overflow", "manifest", "history", "owner", "type", "evidence_id", "claim_owner", "claim_expiry", "claim_version", "immutable_present", "invalid_failure", "retention", "protection", "cas_zero", "cas_multiple", "cas_error", "revoked", "renewed", "domain_closed", "missing_history", "missing_hold", "superseded", "expired_claim"} {
		t.Run(name, func(t *testing.T) {
			p, c, r, db, env, m := setupFinish(t)
			env.fail = name
			switch name {
			case "no_report":
				env.base.noReport = true
			case "stale_report":
				env.base.wait = 6 * time.Second
			case "evidence_wait":
				env.base.evidenceWait = 6 * time.Second
			case "proof_hash":
				env.alterAdmission = func(a *FinishAdmission) { a.VerifiedProofHash = Hash(strings.Repeat("f", 64)) }
			case "request_hash":
				env.alterAdmission = func(a *FinishAdmission) { a.RequestHash = Hash(strings.Repeat("f", 64)) }
			case "identity":
				env.alterAdmission = func(a *FinishAdmission) { a.IdentityHash = Hash(strings.Repeat("f", 64)) }
			case "identity_expired":
				env.alterAdmission = func(a *FinishAdmission) { a.IdentityExpiresAt = Timestamp(db.now.Format(timeLayout)) }
			case "proof_expired":
				env.alterAdmission = func(a *FinishAdmission) { a.ProofExpiresAt = Timestamp(db.now.Format(timeLayout)) }
			case "refs_version":
				env.alterRefs = func(a *ReferenceApproval) { a.VersionHash = Hash(strings.Repeat("f", 64)) }
			case "policy":
				env.alterRefs = func(a *ReferenceApproval) { a.PolicyHash = Hash(strings.Repeat("f", 64)) }
			case "dependency_expired":
				env.alterRefs = func(a *ReferenceApproval) { a.DependencyExpiresAt = Timestamp(db.now.Format(timeLayout)) }
			case "cost_overflow":
				env.alterAdmission = func(a *FinishAdmission) { a.AdditionalCost = "18446744073709551615" }
			case "manifest":
				env.alterEvidence = func(v *FinishEvidence) { v.ClaimEvidence.Evidence.ManifestHash = nil }
			case "history":
				env.alterEvidence = func(v *FinishEvidence) { v.ClaimEvidence.HistoryHash = Hash(strings.Repeat("f", 64)) }
			case "owner":
				env.alterEvidence = func(v *FinishEvidence) { v.ClaimEvidence.Evidence.OwnerID = "installation_other" }
			case "type":
				env.alterEvidence = func(v *FinishEvidence) { v.ClaimEvidence.Evidence.EvidenceType = "log" }
			case "evidence_id":
				env.alterEvidence = func(v *FinishEvidence) {
					v.ClaimEvidence.Evidence.EvidenceID = "sev_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
				}
			case "claim_owner":
				m.rows[claimTestTable][0].Columns["owner"] = "other"
			case "claim_expiry":
				m.rows[claimTestTable][0].Columns["until"] = db.now.Add(20 * time.Second)
			case "claim_version":
				m.rows[claimTestTable][0].Columns["version"] = "3"
			case "immutable_present":
				m.rows[claimTestTable][0].Columns["immutable"] = "other"
			case "invalid_failure":
				m.rows[claimTestTable][0].Columns["failure"] = "permission_denied"
			case "retention":
				env.alterEvidence = func(v *FinishEvidence) { v.ClaimEvidence.RetentionExpiresAt = r.BudgetUntil }
			case "protection":
				env.alterEvidence = func(v *FinishEvidence) { v.ClaimEvidence.ProtectedUntil = r.BudgetUntil }
			case "cas_zero", "cas_multiple", "cas_error":
				previous := db.execRecord
				db.execRecord = func(q string, a []driver.NamedValue) (driver.Result, error) {
					if q != finishPublicationCAS {
						return previous(q, a)
					}
					if name == "cas_error" {
						return nil, ErrUnavailable
					}
					if name == "cas_multiple" {
						return driver.RowsAffected(2), nil
					}
					return driver.RowsAffected(0), nil
				}
			case "revoked", "renewed":
				var g GrantRecord
				loadMemoryRecord(t, m, &g, 0)
				if name == "revoked" {
					g.State = "revoked"
				} else {
					g.RowVersion = "2"
				}
				replaceMemory(t, m, &g)
			case "domain_closed":
				var d DomainRecord
				loadMemoryRecord(t, m, &d, 0)
				d.State = "closed"
				replaceMemory(t, m, &d)
			case "missing_history":
				delete(m.rows, "system_backup_producer_evidence_bindings")
			case "missing_hold":
				delete(m.rows, "system_backup_producer_evidence_refs")
			case "superseded":
				var run RunRecord
				loadMemoryRecord(t, m, &run, 0)
				run.State = "superseded"
				replaceMemory(t, m, &run)
			case "expired_claim":
				db.now = db.now.Add(10 * time.Second)
			}
			before := cloneMemory(m.rows)
			out, err := p.FinishPublication(context.Background(), c, r)
			if err == nil || !reflect.DeepEqual(out, FinishResult{}) || !reflect.DeepEqual(before, m.rows) {
				t.Fatal("failure leaked result/write", out, err)
			}
		})
	}
}
func TestFinishProofTupleAndVersionRejections(t *testing.T) {
	for _, name := range []string{"changed_hash", "changed_size", "future_observation", "old_observation", "bad_state", "ready_without_version", "null_version", "unicode_version", "control_version", "long_version", "unknown_with_version", "unverified_proof", "budget_expired", "zero_claim", "foreign_claim"} {
		t.Run(name, func(t *testing.T) {
			p, c, r, db, env, m := setupFinish(t)
			switch name {
			case "changed_hash":
				r.ObjectHash = Hash(strings.Repeat("f", 64))
			case "changed_size":
				r.ObjectBytes = "1"
			case "future_observation":
				r.ObservedAt = Timestamp(db.now.Add(time.Second).Format(timeLayout))
			case "old_observation":
				r.ObservedAt = Timestamp(db.now.Add(-2 * time.Second).Format(timeLayout))
			case "bad_state":
				r.State = "write_failed"
			case "ready_without_version":
				r.ImmutableVersion = nil
			case "null_version":
				v := Text("null")
				r.ImmutableVersion = &v
			case "unicode_version":
				v := Text("版本")
				r.ImmutableVersion = &v
			case "control_version":
				v := Text("v1\n")
				r.ImmutableVersion = &v
			case "long_version":
				v := Text(strings.Repeat("x", 257))
				r.ImmutableVersion = &v
			case "unknown_with_version":
				r.State = "write_unknown"
			case "unverified_proof":
				r.ProofHash = Hash(strings.Repeat("f", 64))
			case "budget_expired":
				r.BudgetUntil = Timestamp(db.now.Format(timeLayout))
			case "zero_claim":
				c = &PublicationClaim{}
			case "foreign_claim":
				_, c, _, _, _, _ = setupFinish(t)
			}
			if name != "unverified_proof" {
				env.expected = detached(r)
			}
			before := cloneMemory(m.rows)
			if out, err := p.FinishPublication(context.Background(), c, r); err == nil || !reflect.DeepEqual(out, FinishResult{}) || !reflect.DeepEqual(before, m.rows) {
				t.Fatal("invalid proof", out, err)
			}
		})
	}
}
func TestFinishCommitOutcomes(t *testing.T) {
	for _, name := range []string{"unknown", "late"} {
		t.Run(name, func(t *testing.T) {
			p, c, r, db, _, m := setupFinish(t)
			if name == "unknown" {
				db.commitError = true
			} else {
				db.commitWait = 6 * time.Second
			}
			out, err := p.FinishPublication(context.Background(), c, r)
			if name == "unknown" {
				if !errors.Is(err, ErrCommitUnknown) || !reflect.DeepEqual(out, FinishResult{}) {
					t.Fatal(out, err)
				}
			} else if !errors.Is(err, ErrCommittedExpired) || out.State != "ready" || m.rows[claimTestTable][0].Columns["state"] != "ready" {
				t.Fatal(out, err)
			}
		})
	}
	p, c, r, _, _, _ := setupFinish(t)
	var nilEnv *finishTestEnvironment
	if _, err := NewFinalizer(p.execution, nilEnv); err == nil {
		t.Fatal("typed nil")
	}
	if out, err := p.FinishPublication(nil, c, r); err == nil || !reflect.DeepEqual(out, FinishResult{}) {
		t.Fatal("nil context")
	}
}

func TestFinishUnknownToReadyAndDetachedResult(t *testing.T) {
	p, c, r, _, _, m := setupFinish(t)
	m.rows[claimTestTable][0].Columns["state"] = "write_unknown"
	m.rows[claimTestTable][0].Columns["failure"] = "deadline_exceeded"
	out, err := p.FinishPublication(context.Background(), c, r)
	if err != nil || out.State != "ready" || out.ImmutableVersion == nil {
		t.Fatal(out, err)
	}
	*out.ImmutableVersion = "caller-change"
	if *r.ImmutableVersion != "object-v1" || m.rows[claimTestTable][0].Columns["immutable"] != "object-v1" {
		t.Fatal("returned version aliases immutable input")
	}
}

func TestFinishRunCASFailureRollsBackReady(t *testing.T) {
	p, c, r, db, _, m := setupFinish(t)
	before := cloneMemory(m.rows)
	previous := db.execRecord
	db.execRecord = func(q string, args []driver.NamedValue) (driver.Result, error) {
		if strings.HasPrefix(q, "UPDATE system_backup_producer_runs") {
			return driver.RowsAffected(0), nil
		}
		return previous(q, args)
	}
	out, err := p.FinishPublication(context.Background(), c, r)
	if err == nil || !reflect.DeepEqual(out, FinishResult{}) || !reflect.DeepEqual(before, m.rows) {
		t.Fatal("run CAS failure left ready evidence", out, err)
	}
}
