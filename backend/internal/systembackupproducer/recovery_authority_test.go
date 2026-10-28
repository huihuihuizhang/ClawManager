package systembackupproducer

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type recoveryAuthorityFixture struct {
	db       *fakeDB
	next     RecoveryDeploymentProposal
	allowed  bool
	fail     string
	checks   int
	row      *recoveryDeploymentRow
	previous *recoveryDeploymentRow
}

func (e *recoveryAuthorityFixture) PrepareRecoveryAuthority(context.Context, RecoveryAuthorityRequest) (RecoveryAuthoritySession, error) {
	if e.fail == "prepare" {
		return nil, ErrUnavailable
	}
	return e, nil
}
func (e *recoveryAuthorityFixture) LockManager(_ context.Context, _ SQL, r RecoveryAuthorityRequest, current *RecoveryDeploymentProposal) (RecoveryAuthorityAdmission, error) {
	e.db.events = append(e.db.events, "manager-lock")
	if e.fail == "manager" || (e.row == nil) != (current == nil) {
		return RecoveryAuthorityAdmission{}, ErrGuardRequired
	}
	if e.row != nil && *current != recoveryDeploymentProposal(*e.row) {
		return RecoveryAuthorityAdmission{}, ErrGuardRequired
	}
	h, _ := RecoveryAuthorityHash(r)
	return RecoveryAuthorityAdmission{VerifiedRequestHash: h, ManagerExpiresAt: Timestamp(e.db.now.Add(time.Minute).Format(timeLayout)),
		WriteFenceAllowed: e.allowed, ManageAllowed: e.allowed, NextDeployment: e.next}, nil
}
func (e *recoveryAuthorityFixture) Audit(_ context.Context, _ SQL, _ RecoveryAuthorityRequest, stage string) error {
	e.db.events = append(e.db.events, "audit:"+stage)
	if e.fail == "audit:"+stage {
		return ErrUnavailable
	}
	return nil
}
func (e *recoveryAuthorityFixture) RecheckManager(_ context.Context, _ ReadSQL, _ RecoveryAuthorityRequest, _ time.Time) error {
	e.checks++
	e.db.events = append(e.db.events, "manager-recheck")
	if e.fail == "recheck" || !e.allowed {
		return ErrGuardRequired
	}
	return nil
}

func setupRecoveryAuthority(t *testing.T) (*RecoveryAuthorityManager, RecoveryAuthorityRequest, *recoveryAuthorityFixture, *fenceTestEnvironment, *fakeDB) {
	t.Helper()
	fenceManager, fenceRequest, fenceState, db := setupRecoveryFence(t)
	e := &recoveryAuthorityFixture{db: db, allowed: true}
	oldBegin, oldRollback := db.beginRecord, db.rollbackRecord
	oldQuery, oldExec := db.queryRecord, db.execRecord
	db.beginRecord = func() {
		oldBegin()
		if e.row != nil {
			copy := *e.row
			e.previous = &copy
		} else {
			e.previous = nil
		}
	}
	db.rollbackRecord = func() { oldRollback(); e.row = e.previous }
	db.queryRecord = func(q string, args []driver.NamedValue) (driver.Rows, error) {
		switch q {
		case "SELECT origin_installation_id FROM system_backup_v2_installation_state ORDER BY origin_installation_id FOR UPDATE":
			return &fakeRows{values: []driver.Value{string(fenceRequest.Scope.Installation)}}, nil
		case "SELECT origin_installation_id FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR UPDATE":
			if len(args) != 1 || args[0].Value != string(fenceRequest.Scope.Installation) {
				return &emptyFenceRows{}, nil
			}
			return &fakeRows{values: []driver.Value{string(fenceRequest.Scope.Installation)}}, nil
		case recoveryDeploymentLockSQL, recoveryDeploymentReadSQL:
			if e.row == nil {
				return &emptyFenceRows{}, nil
			}
			r := *e.row
			return &fakeRows{values: []driver.Value{r.installation, r.workload, r.issuer, r.subject,
				r.managerIssuer, r.actor, r.admission, r.clientCA, r.certificate, r.statProfile,
				r.enabled, r.epoch, r.authorizedUntil, r.version}}, nil
		}
		return oldQuery(q, args)
	}
	db.execRecord = func(q string, args []driver.NamedValue) (driver.Result, error) {
		switch q {
		case recoveryDeploymentInsertSQL:
			if e.row != nil || len(args) != 15 || args[12].Value != int64(1) || args[14].Value != int64(1) {
				return driver.RowsAffected(0), nil
			}
			next, err := e.next.row(fenceRequest.Scope)
			if err != nil || !bytes.Equal(next.workload, args[2].Value.([]byte)) {
				return driver.RowsAffected(0), nil
			}
			e.row = &next
			return driver.RowsAffected(1), nil
		case recoveryDeploymentUpdateSQL:
			if e.row == nil || len(args) != 18 || e.row.installation != args[14].Value.(string) ||
				!bytes.Equal(e.row.workload, args[15].Value.([]byte)) || e.row.epoch != args[16].Value.(int64) || e.row.version != args[17].Value.(int64) {
				return driver.RowsAffected(0), nil
			}
			next, err := e.next.row(fenceRequest.Scope)
			if err != nil || !bytes.Equal(next.workload, args[0].Value.([]byte)) || next.epoch != args[10].Value.(int64) || next.version != args[12].Value.(int64) {
				return driver.RowsAffected(0), nil
			}
			e.row = &next
			return driver.RowsAffected(1), nil
		}
		return oldExec(q, args)
	}
	manager, err := NewRecoveryAuthorityManager(fenceManager.db, fenceRequest.Scope, e)
	if err != nil {
		t.Fatal(err)
	}
	manager.clock = func() time.Time { return db.now }
	initial := RecoveryDeploymentProposal{
		WorkloadIdentityHash: fenceRequest.IdentityHash, IssuerIdentityHash: Hash(strings.Repeat("1", 64)),
		SubjectHash: Hash(strings.Repeat("2", 64)), ManagementIssuerHash: Hash(strings.Repeat("3", 64)),
		ActorIdentityHash: Hash(strings.Repeat("4", 64)), AdmissionHash: Hash(strings.Repeat("5", 64)),
		ClientCASHA256: Hash(strings.Repeat("6", 64)), CertificateSHA256: Hash(strings.Repeat("7", 64)),
		StatProfileHash: Hash(strings.Repeat("8", 64)), Enabled: true, Epoch: "1", RowVersion: "1",
		AuthorizedUntil: Timestamp(db.now.Add(time.Minute).Format(timeLayout)),
	}
	e.next = initial
	r := RecoveryAuthorityRequest{Fence: fenceRequest, ExpectedDeploymentVersion: "0", Nonce: "recovery-authority-1",
		BudgetUntil: Timestamp(db.now.Add(time.Minute).Format(timeLayout))}
	return manager, r, e, fenceState, db
}

func TestRecoveryAuthorityAtomicLifecycle(t *testing.T) {
	m, r, e, fence, db := setupRecoveryAuthority(t)
	ctx := context.Background()
	got, err := m.Change(ctx, r)
	if err != nil || got.DeploymentEpoch != "1" || got.DeploymentVersion != "1" || !got.Enabled || e.row == nil || e.checks != 1 {
		t.Fatal("register", got, err)
	}
	parent, deployment, manager, fenceLock := -1, -1, -1, -1
	for i, event := range db.events {
		switch event {
		case "SELECT origin_installation_id FROM system_backup_v2_installation_state ORDER BY origin_installation_id FOR UPDATE":
			parent = i
		case recoveryDeploymentLockSQL:
			deployment = i
		case "manager-lock":
			manager = i
		case recoveryFenceSelect:
			fenceLock = i
		}
	}
	if parent < 0 || deployment <= parent || manager <= deployment || fenceLock <= manager {
		t.Fatal("wrong L0/L1a/L1b/L2 order", db.events)
	}
	r.Fence.Operation, r.Fence.ExpectedEpoch, r.Fence.ExpectedRowVersion = "rotate", "1", "1"
	r.ExpectedDeploymentVersion = "1"
	e.next.Epoch, e.next.RowVersion = "2", "2"
	e.next.CertificateSHA256 = Hash(strings.Repeat("9", 64))
	got, err = m.Change(ctx, r)
	if err != nil || got.DeploymentEpoch != "2" || e.row.epoch != 2 || fence.rows[string(mustDigest(r.Fence.IdentityHash))].epoch != 2 {
		t.Fatal("same identity rotate", got, err)
	}
	r.Fence.ExpectedEpoch, r.Fence.ExpectedRowVersion, r.ExpectedDeploymentVersion = "2", "2", "2"
	nextIdentity := Hash(strings.Repeat("c", 64))
	r.Fence.NextIdentityHash = &nextIdentity
	e.next.Epoch, e.next.RowVersion, e.next.WorkloadIdentityHash = "3", "3", nextIdentity
	got, err = m.Change(ctx, r)
	oldKey, _ := hex.DecodeString(string(r.Fence.IdentityHash))
	newKey, _ := hex.DecodeString(string(nextIdentity))
	if err != nil || got.WorkloadIdentityHash != nextIdentity || !fence.rows[string(oldKey)].revoked || fence.rows[string(newKey)].epoch != 3 {
		t.Fatal("identity rotate", got, err)
	}
	r.Fence.IdentityHash, r.Fence.NextIdentityHash = nextIdentity, nil
	r.Fence.Operation, r.Fence.ExpectedEpoch, r.Fence.ExpectedRowVersion, r.ExpectedDeploymentVersion = "revoke", "3", "1", "3"
	e.next.Epoch, e.next.RowVersion, e.next.Enabled = "4", "4", false
	got, err = m.Change(ctx, r)
	if err != nil || got.Enabled || e.row.enabled || !fence.rows[string(newKey)].revoked || fence.rows[string(newKey)].epoch != 4 {
		t.Fatal("revoke", got, err)
	}
	if e.checks != 4 {
		t.Fatal("missing manager final checks", e.checks)
	}
}

func TestRecoveryAuthorityRollsBackBothRows(t *testing.T) {
	for _, fail := range []string{"manager", "audit:intent", "audit:result", "recheck", "fence-cas", "commit"} {
		t.Run(fail, func(t *testing.T) {
			m, r, e, fence, db := setupRecoveryAuthority(t)
			switch fail {
			case "fence-cas":
				fence.fail = "cas"
			case "commit":
				db.commitError = true
			default:
				e.fail = fail
			}
			got, err := m.Change(context.Background(), r)
			if err == nil || !reflect.DeepEqual(got, RecoveryAuthorityResult{}) {
				t.Fatal("unconfirmed authority escaped", got, err)
			}
			// A lost COMMIT reply leaves the database outcome unknowable. The
			// service must return no authority; it cannot promise rollback.
			if fail != "commit" && (e.row != nil || len(fence.rows) != 0) {
				t.Fatal("partial authority escaped", got, err, e.row, fence.rows)
			}
		})
	}
}

func TestRecoveryAuthorityRejectsStaleAndUntrustedTransition(t *testing.T) {
	m, r, e, fence, _ := setupRecoveryAuthority(t)
	r.ExpectedDeploymentVersion = "1"
	if got, err := m.Change(context.Background(), r); !errors.Is(err, ErrInvalid) || !reflect.DeepEqual(got, RecoveryAuthorityResult{}) {
		t.Fatal("register version", got, err)
	}
	r.ExpectedDeploymentVersion = "0"
	e.next.WorkloadIdentityHash = Hash(strings.Repeat("d", 64))
	if got, err := m.Change(context.Background(), r); !errors.Is(err, ErrGuardRequired) || !reflect.DeepEqual(got, RecoveryAuthorityResult{}) || e.row != nil || len(fence.rows) != 0 {
		t.Fatal("proposal identity mismatch", got, err)
	}
	e.next.WorkloadIdentityHash = r.Fence.IdentityHash
	e.allowed = false
	if got, err := m.Change(context.Background(), r); !errors.Is(err, ErrGuardRequired) || !reflect.DeepEqual(got, RecoveryAuthorityResult{}) {
		t.Fatal("manager permission", got, err)
	}
}

func TestRecoveryAuthorityDoesNotReviveRevokedDeployment(t *testing.T) {
	m, r, e, fence, _ := setupRecoveryAuthority(t)
	ctx := context.Background()
	if _, err := m.Change(ctx, r); err != nil {
		t.Fatal("register", err)
	}
	r.Fence.Operation, r.Fence.ExpectedEpoch, r.Fence.ExpectedRowVersion = "revoke", "1", "1"
	r.ExpectedDeploymentVersion = "1"
	e.next.Epoch, e.next.RowVersion, e.next.Enabled = "2", "2", false
	if _, err := m.Change(ctx, r); err != nil {
		t.Fatal("revoke", err)
	}
	r.Fence.Operation, r.Fence.ExpectedEpoch, r.Fence.ExpectedRowVersion = "rotate", "2", "2"
	r.ExpectedDeploymentVersion = "2"
	e.next.Epoch, e.next.RowVersion, e.next.Enabled = "3", "3", true
	if got, err := m.Change(ctx, r); !errors.Is(err, ErrConflict) || got != (RecoveryAuthorityResult{}) {
		t.Fatal("revoked deployment was revived", got, err)
	}
	key := string(mustDigest(r.Fence.IdentityHash))
	if e.row == nil || e.row.epoch != 2 || e.row.enabled || fence.rows[key].epoch != 2 || !fence.rows[key].revoked {
		t.Fatal("rejected rotation changed authority rows")
	}
}

func TestRecoveryAuthorityRetriesOnlyAsNewTransaction(t *testing.T) {
	m, r, e, fence, _ := setupRecoveryAuthority(t)
	e.fail = "audit:result"
	if got, err := m.Change(context.Background(), r); !errors.Is(err, ErrUnavailable) || got != (RecoveryAuthorityResult{}) {
		t.Fatal("failed transaction returned authority", got, err)
	}
	if e.row != nil || len(fence.rows) != 0 {
		t.Fatal("failed transaction left partial rows")
	}
	e.fail = ""
	got, err := m.Change(context.Background(), r)
	if err != nil || got.DeploymentEpoch != "1" || got.DeploymentVersion != "1" || e.row == nil || len(fence.rows) != 1 {
		t.Fatal("fresh transaction did not register", got, err)
	}
}

func TestRecoveryAuthoritySQLFailureRequiresFreshTransaction(t *testing.T) {
	m, r, e, fence, db := setupRecoveryAuthority(t)
	previous := db.execRecord
	failOnce := true
	db.execRecord = func(q string, args []driver.NamedValue) (driver.Result, error) {
		if q == recoveryFenceInsert && failOnce {
			failOnce = false
			return nil, errors.New("synthetic deadlock victim")
		}
		return previous(q, args)
	}
	got, err := m.Change(context.Background(), r)
	if !errors.Is(err, ErrUnavailable) || got != (RecoveryAuthorityResult{}) || failOnce {
		t.Fatal("failed SQL write returned authority", got, err)
	}
	if e.row != nil || len(fence.rows) != 0 || db.rollbacks != 1 || db.commits != 0 {
		t.Fatal("failed SQL write left partial authority", e.row, fence.rows, db.rollbacks, db.commits)
	}
	got, err = m.Change(context.Background(), r)
	if err != nil || got.DeploymentEpoch != "1" || got.DeploymentVersion != "1" ||
		e.row == nil || len(fence.rows) != 1 || db.commits != 1 {
		t.Fatal("fresh transaction did not register after SQL failure", got, err)
	}
}

func mustDigest(h Hash) []byte {
	b, _ := hex.DecodeString(string(h))
	return b
}
