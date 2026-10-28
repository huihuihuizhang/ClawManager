package systembackupproducer

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The claim CAS below runs against a synthetic participant in commandMemory's
// transactional snapshot. No actual A SQL loader/MySQL/provider is exercised.
const claimTestTable = "system_backup_v2_evidence"

type claimTestEnvironment struct {
	db                 *fakeDB
	m                  *commandMemory
	history            HistoricalBindingRecord
	policy, refs       Hash
	fail               string
	noReport           bool
	wait, evidenceWait time.Duration
	reserves           int
	cost               uint64
	alterAdmission     func(*ClaimAdmission)
	alterRefs          func(*ReferenceApproval)
	alterEvidence      func(*ClaimEvidence)
}

func (e *claimTestEnvironment) phase(n string) error {
	e.m.events = append(e.m.events, "claim:"+n)
	if e.fail == n {
		return ErrUnavailable
	}
	return nil
}
func (e *claimTestEnvironment) PrepareClaim(_ context.Context, _ ClaimRequestBinding, _ bool) (PreparedClaim, error) {
	if err := e.phase("prepare"); err != nil {
		return PreparedClaim{}, err
	}
	p := PreparedClaim{Session: e}
	if !e.noReport {
		s := e.db.now
		p.CapacityObservedAt = &s
	}
	return p, nil
}
func (e *claimTestEnvironment) LockInstallation(context.Context, SQL, ClaimRequestBinding) error {
	e.db.now = e.db.now.Add(e.wait)
	return e.phase("installation")
}
func (e *claimTestEnvironment) Authenticate(_ context.Context, _ SQL, b ClaimRequestBinding, _ DomainRecord, _ bool) (ClaimAdmission, error) {
	if err := e.phase("authenticate"); err != nil {
		return ClaimAdmission{}, err
	}
	hash, _ := ClaimRequestHash(b)
	a := ClaimAdmission{RequestHash: hash, IdentityHash: b.Subject, IdentityExpiresAt: Timestamp(e.db.now.Add(time.Minute).Format(timeLayout)), ExpiresNotAfter: Timestamp(e.db.now.Add(30 * time.Second).Format(timeLayout)), AdditionalCost: "65536", ReadbackAllowed: true}
	if e.alterAdmission != nil {
		e.alterAdmission(&a)
	}
	return a, nil
}
func (e *claimTestEnvironment) LockHost(context.Context, SQL, ClaimRequestBinding, GrantRecord) error {
	return e.phase("host")
}
func (e *claimTestEnvironment) LockReferences(_ context.Context, _ SQL, b ClaimRequestBinding, _ ClaimFacts) (ReferenceApproval, error) {
	if err := e.phase("refs"); err != nil {
		return ReferenceApproval{}, err
	}
	h, _ := ClaimRequestHash(b)
	r := ReferenceApproval{RequestHash: h, PolicyHash: e.policy, VersionHash: e.refs, DependencyExpiresAt: Timestamp(e.db.now.Add(time.Minute).Format(timeLayout))}
	if e.alterRefs != nil {
		e.alterRefs(&r)
	}
	return r, nil
}
func (e *claimTestEnvironment) Reserve(_ context.Context, _ SQL, _ ClaimRequestBinding, c uint64) error {
	e.reserves++
	e.cost = c
	return e.phase("reserve")
}
func (e *claimTestEnvironment) Audit(_ context.Context, _ SQL, _ ClaimRequestBinding, stage string) error {
	return e.phase("audit:" + stage)
}
func (e *claimTestEnvironment) current() ClaimEvidence {
	c := e.m.rows[claimTestTable][0].Columns
	h, _ := PendingHistoryHash(e.history)
	manifest := e.history.Evidence.ManifestHash
	v := ClaimEvidence{Evidence: CallEvidence{EvidenceID: e.history.Evidence.EvidenceID, OwnerType: "system", OwnerID: e.history.Scope.Installation, EvidenceType: "capability_snapshot", State: c["state"].(string), RowVersion: ZeroCounter(c["version"].(string)), ManifestHash: &manifest}, HistoryHash: h, RetentionExpiresAt: e.history.RetentionExpiresAt, ProtectedUntil: e.history.RetentionExpiresAt}
	if c["owner"] != nil {
		o := ID(c["owner"].(string))
		u := Timestamp(c["until"].(time.Time).Format(timeLayout))
		v.Evidence.ClaimOwner = &o
		v.Evidence.ClaimExpiresAt = &u
	}
	return v
}
func (e *claimTestEnvironment) LockEvidence(context.Context, SQL, ClaimRequestBinding, ClaimFacts) (ClaimEvidence, error) {
	e.db.now = e.db.now.Add(e.evidenceWait)
	if err := e.phase("evidence"); err != nil {
		return ClaimEvidence{}, err
	}
	v := e.current()
	if e.alterEvidence != nil {
		e.alterEvidence(&v)
	}
	return v, nil
}
func (e *claimTestEnvironment) Recheck(_ context.Context, _ ReadSQL, _ ClaimRequestBinding, f ClaimFacts, _ time.Time) error {
	if err := e.phase("recheck"); err != nil {
		return err
	}
	if !reflect.DeepEqual(f.Evidence, e.current()) {
		return ErrConflict
	}
	return nil
}
func setupClaim(t *testing.T) (*Publication, *ExecutionHandle, ClaimRequest, *fakeDB, *claimTestEnvironment, *commandMemory) {
	t.Helper()
	pending, h, r, db, _, m := setupPending(t)
	if _, err := pending.AdmitPending(context.Background(), h, r); err != nil {
		t.Fatal(err)
	}
	env := &claimTestEnvironment{db: db, m: m, history: r.History, policy: Hash(strings.Repeat("a", 64)), refs: Hash(strings.Repeat("b", 64))}
	m.rows[claimTestTable] = []StoredRecord{{Table: claimTestTable, Columns: map[string]any{"id": string(r.History.Evidence.EvidenceID), "version": "1", "state": "pending", "owner": nil, "until": nil}}}
	previous := db.execRecord
	db.execRecord = func(q string, a []driver.NamedValue) (driver.Result, error) {
		if q != publicationClaimCAS {
			return previous(q, a)
		}
		if len(a) != 8 {
			return nil, ErrInvalid
		}
		row := m.rows[claimTestTable][0].Columns
		currentVersion := Counter(row["version"].(string))
		version, err := currentVersion.SQLInt64()
		if err != nil {
			return nil, err
		}
		if a[2].Value != row["id"] || a[3].Value != version || a[4].Value != string(h.scope.Installation) || a[5].Value != row["state"] || !reflect.DeepEqual(a[6].Value, row["owner"]) || !reflect.DeepEqual(a[7].Value, row["until"]) {
			return driver.RowsAffected(0), nil
		}
		next, _ := nextCounter(currentVersion)
		row["version"] = string(next)
		row["owner"] = a[0].Value
		row["until"] = a[1].Value
		m.events = append(m.events, "cas:claim")
		return driver.RowsAffected(1), nil
	}
	pub, err := NewPublication(pending.execution, env)
	if err != nil {
		t.Fatal(err)
	}
	request := ClaimRequest{EvidenceID: r.History.Evidence.EvidenceID, ExpectedEvidenceVersion: "1", Nonce: "publication-attempt-1", ExpiresAt: Timestamp(db.now.Add(10 * time.Second).Format(timeLayout)), PolicyHash: env.policy, RefsVersionHash: env.refs, BudgetUntil: Timestamp(db.now.Add(20 * time.Second).Format(timeLayout))}
	m.events = nil
	return pub, h, request, db, env, m
}
func TestClaimCommitReadbackAndExecution(t *testing.T) {
	p, h, r, db, env, m := setupClaim(t)
	before := cloneMemory(m.rows)
	commits := db.commits
	claim, err := p.ClaimPublication(context.Background(), h, r)
	if err != nil || claim == nil || claim.binding.EvidenceVersion != "2" || claim.binding.ExpiresAt != r.ExpiresAt || db.commits != commits+1 || env.reserves != 1 || env.cost != 131072 {
		t.Fatal("claim", claim, err, env.cost)
	}
	for table, rows := range before {
		if table != claimTestTable && !reflect.DeepEqual(rows, m.rows[table]) {
			t.Fatal("claim changed immutable state", table)
		}
	}
	want := []string{"claim:prepare", "claim:installation", "lock:system_backup_producer_domains", "claim:authenticate", "lock:system_backup_producer_grants", "lock:system_backup_producer_runs", "lock:system_backup_producer_evidence_bindings", "claim:host", "lock:system_backup_producer_targets", "lock:system_backup_producer_evidence_refs", "claim:refs", "claim:reserve", "claim:audit:intent", "claim:evidence", "cas:claim", "claim:audit:result", "claim:recheck"}
	if !reflect.DeepEqual(m.events, want) {
		t.Fatal("order", m.events)
	}
	if _, err = json.Marshal(claim); err == nil {
		t.Fatal("serializable claim")
	}
	before = cloneMemory(m.rows)
	env.noReport = true
	db.now = db.now.Add(time.Second)
	read, err := p.ReadPublicationClaim(context.Background(), h, r)
	if err != nil || read == nil || read.binding != claim.binding || env.reserves != 1 || !reflect.DeepEqual(before, m.rows) {
		t.Fatal("readback", read, err)
	}
	executionEnv := p.execution.environment.(*executionTestEnvironment)
	executionEnv.policy = r.PolicyHash
	executionEnv.refVersion = r.RefsVersionHash
	row := env.current().Evidence
	executionEnv.evidence = &row
	for _, purpose := range []string{"sts", "publish"} {
		call := CallRequest{Purpose: purpose, EvidenceID: r.EvidenceID, RefIdentityHash: env.history.Evidence.StoreIdentityHash, RefVersion: ProviderVersion(env.history.Evidence.StoreRefVersion), PolicyHash: r.PolicyHash, BudgetUntil: r.BudgetUntil}
		snapshot, err := p.execution.BeginCall(context.Background(), h, call, read)
		if err != nil || snapshot == nil || snapshot.Deadline().Format(timeLayout) != string(r.ExpiresAt) {
			t.Fatal("committed claim call", purpose, err)
		}
		if err = p.execution.RecheckCall(context.Background(), snapshot); err != nil {
			t.Fatal(err)
		}
	}
}
func TestClaimFailuresRollbackAndReturnNoAuthority(t *testing.T) {
	for _, name := range []string{"prepare", "installation", "authenticate", "host", "refs", "reserve", "audit:intent", "evidence", "audit:result", "recheck", "no_report", "stale_report", "evidence_wait", "identity", "request", "policy", "refs_version", "identity_expiry", "dependency_expiry", "max_expiry", "budget", "observation", "cost_overflow", "history_hash", "owner", "type", "evidence_id", "manifest", "retention", "protection", "ready", "version", "active_claim", "half_claim", "cas_zero", "cas_multiple", "cas_error", "revoked", "missing_history", "missing_hold", "run_not_pending", "write_cutoff", "signed_overflow"} {
		t.Run(name, func(t *testing.T) {
			p, h, r, db, env, m := setupClaim(t)
			env.fail = name
			switch name {
			case "no_report":
				env.noReport = true
			case "stale_report":
				env.wait = 6 * time.Second
			case "evidence_wait":
				env.evidenceWait = 6 * time.Second
			case "identity":
				env.alterAdmission = func(a *ClaimAdmission) { a.IdentityHash = Hash(strings.Repeat("f", 64)) }
			case "request":
				env.alterAdmission = func(a *ClaimAdmission) { a.RequestHash = Hash(strings.Repeat("f", 64)) }
			case "policy":
				env.alterRefs = func(a *ReferenceApproval) { a.PolicyHash = Hash(strings.Repeat("f", 64)) }
			case "refs_version":
				env.alterRefs = func(a *ReferenceApproval) { a.VersionHash = Hash(strings.Repeat("f", 64)) }
			case "identity_expiry":
				env.alterAdmission = func(a *ClaimAdmission) {
					a.IdentityExpiresAt = Timestamp(db.now.Add(5 * time.Second).Format(timeLayout))
				}
			case "dependency_expiry":
				env.alterRefs = func(a *ReferenceApproval) {
					a.DependencyExpiresAt = Timestamp(db.now.Add(5 * time.Second).Format(timeLayout))
				}
			case "max_expiry":
				env.alterAdmission = func(a *ClaimAdmission) { a.ExpiresNotAfter = Timestamp(db.now.Add(5 * time.Second).Format(timeLayout)) }
			case "budget":
				r.BudgetUntil = Timestamp(db.now.Add(5 * time.Second).Format(timeLayout))
			case "observation":
				db.now = db.now.Add(31 * time.Second)
			case "cost_overflow":
				env.alterAdmission = func(a *ClaimAdmission) { a.AdditionalCost = "18446744073709551615" }
			case "history_hash":
				env.alterEvidence = func(v *ClaimEvidence) { v.HistoryHash = Hash(strings.Repeat("f", 64)) }
			case "owner":
				env.alterEvidence = func(v *ClaimEvidence) { v.Evidence.OwnerID = "installation_other" }
			case "type":
				env.alterEvidence = func(v *ClaimEvidence) { v.Evidence.EvidenceType = "log" }
			case "evidence_id":
				env.alterEvidence = func(v *ClaimEvidence) { v.Evidence.EvidenceID = "sev_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" }
			case "manifest":
				env.alterEvidence = func(v *ClaimEvidence) { v.Evidence.ManifestHash = nil }
			case "retention":
				env.alterEvidence = func(v *ClaimEvidence) { v.RetentionExpiresAt = r.ExpiresAt }
			case "protection":
				env.alterEvidence = func(v *ClaimEvidence) { v.ProtectedUntil = r.ExpiresAt }
			case "ready":
				m.rows[claimTestTable][0].Columns["state"] = "ready"
			case "version":
				r.ExpectedEvidenceVersion = "2"
			case "active_claim":
				m.rows[claimTestTable][0].Columns["owner"] = "other"
				m.rows[claimTestTable][0].Columns["until"] = db.now.Add(time.Second)
			case "half_claim":
				env.alterEvidence = func(v *ClaimEvidence) { o := ID("other"); v.Evidence.ClaimOwner = &o }
			case "cas_zero", "cas_multiple", "cas_error":
				previous := db.execRecord
				db.execRecord = func(q string, a []driver.NamedValue) (driver.Result, error) {
					if q != publicationClaimCAS {
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
			case "revoked":
				var grant GrantRecord
				loadMemoryRecord(t, m, &grant, 0)
				grant.State = "revoked"
				replaceMemory(t, m, &grant)
			case "missing_history":
				delete(m.rows, "system_backup_producer_evidence_bindings")
			case "missing_hold":
				delete(m.rows, "system_backup_producer_evidence_refs")
			case "run_not_pending":
				var run RunRecord
				loadMemoryRecord(t, m, &run, 0)
				run.State = "acquired"
				replaceMemory(t, m, &run)
			case "write_cutoff":
				var run RunRecord
				loadMemoryRecord(t, m, &run, 0)
				run.OwnerWriteExpiresAt = Timestamp(db.now.Format(timeLayout))
				replaceMemory(t, m, &run)
			case "signed_overflow":
				r.ExpectedEvidenceVersion = "9223372036854775807"
			}
			before := cloneMemory(m.rows)
			claim, err := p.ClaimPublication(context.Background(), h, r)
			if err == nil || claim != nil || !reflect.DeepEqual(before, m.rows) {
				t.Fatal("failed claim leaked", claim, err)
			}
		})
	}
}
func TestClaimExactReadbackAndExpiredReplacement(t *testing.T) {
	for _, name := range []string{"nonce", "deadline", "budget", "policy", "refs", "expected_version", "no_read_permission", "expiry", "same_write", "version_drift", "renewed_handle", "foreign_service"} {
		t.Run(name, func(t *testing.T) {
			p, h, r, db, env, m := setupClaim(t)
			claim, err := p.ClaimPublication(context.Background(), h, r)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "nonce":
				r.Nonce = "changed"
			case "deadline":
				r.ExpiresAt = Timestamp(db.now.Add(11 * time.Second).Format(timeLayout))
			case "budget":
				r.BudgetUntil = Timestamp(db.now.Add(21 * time.Second).Format(timeLayout))
			case "policy":
				r.PolicyHash = Hash(strings.Repeat("f", 64))
				env.policy = r.PolicyHash
			case "refs":
				r.RefsVersionHash = Hash(strings.Repeat("f", 64))
				env.refs = r.RefsVersionHash
			case "expected_version":
				r.ExpectedEvidenceVersion = "2"
			case "no_read_permission":
				env.alterAdmission = func(a *ClaimAdmission) { a.ReadbackAllowed = false }
			case "expiry":
				db.now = db.now.Add(10 * time.Second)
			case "version_drift":
				m.rows[claimTestTable][0].Columns["version"] = "3"
			case "renewed_handle":
				var grant GrantRecord
				loadMemoryRecord(t, m, &grant, 0)
				grant.RowVersion = "2"
				replaceMemory(t, m, &grant)
			case "foreign_service":
				foreign, _, _, _, _, _ := setupClaim(t)
				p = foreign
			}
			before := cloneMemory(m.rows)
			if name == "same_write" {
				claim, err = p.ClaimPublication(context.Background(), h, r)
			} else {
				claim, err = p.ReadPublicationClaim(context.Background(), h, r)
			}
			if err == nil || claim != nil || !reflect.DeepEqual(before, m.rows) {
				t.Fatal("changed readback accepted", claim, err)
			}
		})
	}
	p, h, r, db, env, m := setupClaim(t)
	if _, err := p.ClaimPublication(context.Background(), h, r); err != nil {
		t.Fatal(err)
	}
	db.now = db.now.Add(11 * time.Second)
	r.ExpectedEvidenceVersion = "2"
	r.Nonce = "publication-attempt-2"
	r.ExpiresAt = Timestamp(db.now.Add(5 * time.Second).Format(timeLayout))
	claim, err := p.ClaimPublication(context.Background(), h, r)
	if err != nil || claim == nil || claim.binding.EvidenceVersion != "3" || env.reserves != 2 {
		t.Fatal("expired replacement", claim, err)
	}
	if m.rows[claimTestTable][0].Columns["state"] != "pending" {
		t.Fatal("claim changed publication state")
	}
}
func TestClaimUnknownCommitRequiresReadback(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "not_committed", true: "committed"}[committed], func(t *testing.T) {
			p, h, r, db, env, m := setupClaim(t)
			before := cloneMemory(m.rows)
			db.commitError = true
			if c, err := p.ClaimPublication(context.Background(), h, r); !errors.Is(err, ErrCommitUnknown) || c != nil {
				t.Fatal(c, err)
			}
			// The driver reports lost acknowledgement. Model BOTH possible durable
			// outcomes, then use a fresh transaction for the exact fixed request.
			if !committed {
				m.rows = before
			}
			db.commitError = false
			env.noReport = true
			c, err := p.ReadPublicationClaim(context.Background(), h, r)
			if committed {
				if err != nil || c == nil {
					t.Fatal("committed readback", err)
				}
			} else if err == nil || c != nil {
				t.Fatal("uncommitted readback", c, err)
			}
		})
	}
	p, h, r, db, _, _ := setupClaim(t)
	db.commitWait = 6 * time.Second
	if c, err := p.ClaimPublication(context.Background(), h, r); !errors.Is(err, ErrCommittedExpired) || c != nil {
		t.Fatal("late commit", c, err)
	}
	var nilEnv *claimTestEnvironment
	if _, err := NewPublication(p.execution, nilEnv); err == nil {
		t.Fatal("typed nil")
	}
	if c, err := p.ClaimPublication(nil, h, r); err == nil || c != nil {
		t.Fatal("nil context")
	}
}
