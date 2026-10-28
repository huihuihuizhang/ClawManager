package systembackupproducer

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

type recoveryTestEnvironment struct {
	db              *fakeDB
	m               *commandMemory
	history         HistoricalBindingRecord
	deny, failAudit bool
	revoked         bool
	order           []string
}

func (e *recoveryTestEnvironment) PrepareRecovery(_ context.Context, _ RecoveryRequest, op string, _ *RecoveryFinishRequest) (PreparedRecovery, error) {
	p := PreparedRecovery{Session: e}
	if op != "load" {
		now := e.db.now
		p.CapacityObservedAt = &now
	}
	return p, nil
}
func (e *recoveryTestEnvironment) LockInstallation(context.Context, SQL, RecoveryRequest) error {
	e.order = append(e.order, "installation")
	return nil
}
func (e *recoveryTestEnvironment) Authorize(_ context.Context, _ SQL, _ RecoveryRequest, hash Hash, _ string) (RecoveryAdmission, error) {
	e.order = append(e.order, "authority")
	return RecoveryAdmission{VerifiedRequestHash: hash, IdentityHash: Hash(strings.Repeat("a", 64)), RevocationEpoch: "1", IdentityExpiresAt: Timestamp(e.db.now.Add(time.Minute).Format(timeLayout)), DeploymentExpiresAt: Timestamp(e.db.now.Add(time.Minute).Format(timeLayout)), StatAllowed: !e.deny, AdditionalCost: "0"}, nil
}
func (e *recoveryTestEnvironment) LockReferences(context.Context, SQL, RecoveryRequest, HistoricalBindingRecord) error {
	e.order = append(e.order, "references")
	return nil
}
func (e *recoveryTestEnvironment) Reserve(context.Context, SQL, RecoveryRequest, uint64) error {
	e.order = append(e.order, "reserve")
	return nil
}
func (e *recoveryTestEnvironment) Audit(_ context.Context, _ SQL, _ RecoveryRequest, stage string) error {
	e.order = append(e.order, "audit:"+stage)
	if e.failAudit && stage == "result" {
		return ErrUnavailable
	}
	return nil
}
func (e *recoveryTestEnvironment) LockEvidence(context.Context, SQL, RecoveryRequest, HistoricalBindingRecord) (FinishEvidence, error) {
	e.order = append(e.order, "evidence")
	c := e.m.rows[claimTestTable][0].Columns
	h, _ := PendingHistoryHash(e.history)
	manifest := e.history.Evidence.ManifestHash
	v := FinishEvidence{ClaimEvidence: ClaimEvidence{Evidence: CallEvidence{EvidenceID: e.history.Evidence.EvidenceID, OwnerType: "system", OwnerID: e.history.Scope.Installation, EvidenceType: "capability_snapshot", State: c["state"].(string), RowVersion: ZeroCounter(c["version"].(string)), ManifestHash: &manifest}, HistoryHash: h, RetentionExpiresAt: e.history.RetentionExpiresAt, ProtectedUntil: e.history.RetentionExpiresAt}}
	if c["owner"] != nil {
		owner := ID(c["owner"].(string))
		until := Timestamp(c["until"].(time.Time).Format(timeLayout))
		v.ClaimEvidence.Evidence.ClaimOwner = &owner
		v.ClaimEvidence.Evidence.ClaimExpiresAt = &until
	}
	return v, nil
}
func (e *recoveryTestEnvironment) VerifyStat(_ context.Context, _ SQL, _ RecoveryRequest, _ HistoricalBindingRecord, r RecoveryFinishRequest) (RecoveryStatAdmission, error) {
	e.order = append(e.order, "stat-proof")
	return RecoveryStatAdmission{VerifiedProofHash: r.ProofHash, ProofExpiresAt: Timestamp(e.db.now.Add(time.Minute).Format(timeLayout)), Matched: true}, nil
}
func (e *recoveryTestEnvironment) Recheck(context.Context, ReadSQL, RecoveryRequest, HistoricalBindingRecord, time.Time) error {
	e.order = append(e.order, "recheck")
	if e.deny {
		return ErrGuardRequired
	}
	return nil
}

func TestHistoricalRecoveryIndependentAuthorityAndRollback(t *testing.T) {
	_, _, claimRequest, db, claimEnv, m := setupClaim(t)
	ownerCutoff, _ := claimEnv.history.OwnerWriteExpiresAt.Time()
	db.now = ownerCutoff.Add(time.Second)
	e := &recoveryTestEnvironment{db: db, m: m, history: claimEnv.history}
	previousQuery := db.queryRecord
	db.queryRecord = func(q string, a []driver.NamedValue) (driver.Rows, error) {
		if q != recoveryRevocationLockSQL {
			return previousQuery(q, a)
		}
		if len(a) != 2 {
			return nil, ErrInvalid
		}
		var revoked driver.Value
		if e.revoked {
			revoked = db.now
		}
		return &fakeRows{values: []driver.Value{int64(1), revoked, int64(1)}}, nil
	}
	previous := db.execRecord
	db.execRecord = func(q string, a []driver.NamedValue) (driver.Result, error) {
		if q != recoveryClaimCAS && q != recoveryFinishCAS {
			return previous(q, a)
		}
		row := m.rows[claimTestTable][0].Columns
		current, _ := Counter(row["version"].(string)).SQLInt64()
		if q == recoveryClaimCAS {
			if a[3].Value != current || a[2].Value != row["id"] {
				return driver.RowsAffected(0), nil
			}
			row["owner"], row["until"] = a[0].Value, a[1].Value
		} else {
			if a[4].Value != current || a[3].Value != row["id"] || a[7].Value != row["owner"] {
				return driver.RowsAffected(0), nil
			}
			row["state"], row["owner"], row["until"] = a[0].Value, nil, nil
		}
		row["version"] = strconv.FormatInt(current+1, 10)
		return driver.RowsAffected(1), nil
	}
	conn := sql.OpenDB(fakeConnector{db})
	t.Cleanup(func() { conn.Close() })
	s, err := NewHistoricalRecovery(conn, claimEnv.history.Scope, e)
	if err != nil {
		t.Fatal(err)
	}
	s.clock = func() time.Time { return db.now }
	r := RecoveryRequest{Scope: claimEnv.history.Scope, EvidenceID: claimRequest.EvidenceID, ExpectedEvidenceVersion: "1", Nonce: "recovery-attempt-1", ClaimExpiresAt: Timestamp(db.now.Add(10 * time.Second).Format(timeLayout)), BudgetUntil: Timestamp(db.now.Add(20 * time.Second).Format(timeLayout))}
	// A closed domain and revoked old grant cannot stand in for current A
	// workload authority; the dedicated authority itself is mandatory.
	var domain DomainRecord
	loadMemoryRecord(t, m, &domain, 0)
	domain.State = "closed"
	replaceMemory(t, m, &domain)
	e.deny = true
	before := cloneMemory(m.rows)
	if _, err = s.ClaimRecovery(context.Background(), r); err == nil || !reflect.DeepEqual(before, m.rows) {
		t.Fatal("denied recovery changed state", err)
	}
	e.deny = false
	e.revoked = true
	if _, err = s.ClaimRecovery(context.Background(), r); err == nil || !reflect.DeepEqual(before, m.rows) {
		t.Fatal("revoked workload claimed", err)
	}
	e.revoked = false
	claim, err := s.ClaimRecovery(context.Background(), r)
	if err != nil || claim == nil {
		t.Fatal("claim", err)
	}
	if _, err = json.Marshal(claim); err == nil {
		t.Fatal("serializable recovery claim")
	}
	if len(e.order) < 8 || !reflect.DeepEqual(e.order[len(e.order)-8:len(e.order)-5], []string{"installation", "authority", "references"}) {
		t.Fatal("authority order", e.order)
	}
	before = cloneMemory(m.rows)
	if _, err = s.ClaimRecovery(context.Background(), r); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(before, m.rows) {
		t.Fatal("duplicate claim changed state", err)
	}
	e.revoked = true
	result := RecoveryFinishRequest{State: "write_unknown", ProofHash: Hash(strings.Repeat("b", 64)), ObjectHash: e.history.Evidence.ObjectHash, ObjectBytes: e.history.Evidence.ObjectBytes, ObservedAt: Timestamp(db.now.Format(timeLayout)), BudgetUntil: Timestamp(db.now.Add(20 * time.Second).Format(timeLayout))}
	if _, err = s.FinishRecovery(context.Background(), claim, result); !errors.Is(err, ErrGuardRequired) || !reflect.DeepEqual(before, m.rows) {
		t.Fatal("revocation after claim did not fence finish", err)
	}
	e.revoked = false
	future := result
	future.ObservedAt = Timestamp(db.now.Add(time.Second).Format(timeLayout))
	if _, err = s.FinishRecovery(context.Background(), claim, future); !errors.Is(err, ErrExpired) || !reflect.DeepEqual(before, m.rows) {
		t.Fatal("future Stat timestamp accepted", err)
	}
	// Result-audit failure must roll back evidence CAS and consumed claim.
	e.failAudit = true
	before = cloneMemory(m.rows)
	if _, err = s.FinishRecovery(context.Background(), claim, result); err == nil || !reflect.DeepEqual(before, m.rows) {
		t.Fatal("audit failure committed", err)
	}
	e.failAudit = false
	finished, err := s.FinishRecovery(context.Background(), claim, result)
	if err != nil || finished.State != "write_unknown" || m.rows[claimTestTable][0].Columns["state"] != "write_unknown" {
		t.Fatal("finish", finished, err)
	}
	finishedRows := cloneMemory(m.rows)
	if _, err = s.FinishRecovery(context.Background(), claim, result); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(finishedRows, m.rows) {
		t.Fatal("consumed claim reused", err)
	}
	for table, rows := range before {
		if table != claimTestTable && !reflect.DeepEqual(rows, m.rows[table]) {
			t.Fatal("recovery changed non-evidence state", table)
		}
	}
	loaded, stat, err := s.LoadHistoricalBinding(context.Background(), r)
	if err != nil || !reflect.DeepEqual(loaded, e.history) || stat.EvidenceID != r.EvidenceID {
		t.Fatal("historical load", err)
	}
}
