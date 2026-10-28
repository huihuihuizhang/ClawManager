//go:build systembackup_mysql

package systembackupevidence

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

type dRecoveryAuthorityMySQLEnvironment struct {
	scope      pd.Scope
	facts      RecoveryManagerPeerFacts
	proposal   pd.RecoveryDeploymentProposal
	fail       string
	intentHook func()
}

func (e *dRecoveryAuthorityMySQLEnvironment) PrepareRecoveryAuthority(_ context.Context, _ pd.RecoveryAuthorityRequest) (pd.RecoveryAuthoritySession, error) {
	guard, err := NewRecoveryManagerRowGuard(e.scope, e.facts)
	if err != nil {
		return nil, err
	}
	return &dRecoveryAuthorityMySQLSession{env: e, guard: guard}, nil
}

func (e *dRecoveryAuthorityMySQLEnvironment) PrepareRecoveryAuthorityRead(_ context.Context, _ pd.RecoveryAuthorityReadRequest) (pd.RecoveryAuthorityReadSession, error) {
	guard, err := NewRecoveryManagerRowGuard(e.scope, e.facts)
	if err != nil {
		return nil, err
	}
	return &dRecoveryAuthorityMySQLSession{env: e, guard: guard}, nil
}

type dRecoveryAuthorityMySQLSession struct {
	env   *dRecoveryAuthorityMySQLEnvironment
	guard *RecoveryManagerRowGuard
}

func (s *dRecoveryAuthorityMySQLSession) LockManager(ctx context.Context, tx pd.SQL, r pd.RecoveryAuthorityRequest, _ *pd.RecoveryDeploymentProposal) (pd.RecoveryAuthorityAdmission, error) {
	if err := s.guard.Lock(ctx, tx); err != nil {
		return pd.RecoveryAuthorityAdmission{}, err
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil {
		return pd.RecoveryAuthorityAdmission{}, err
	}
	if err := s.guard.Admit(s.env.facts, RecoveryManagerWriteFence, now); err != nil {
		return pd.RecoveryAuthorityAdmission{}, err
	}
	if err := s.guard.Admit(s.env.facts, RecoveryManagerManageDeployment, now); err != nil {
		return pd.RecoveryAuthorityAdmission{}, err
	}
	h, err := pd.RecoveryAuthorityHash(r)
	if err != nil {
		return pd.RecoveryAuthorityAdmission{}, err
	}
	return pd.RecoveryAuthorityAdmission{VerifiedRequestHash: h, ManagerExpiresAt: systemExecutionStamp(s.env.facts.ExpiresAt),
		WriteFenceAllowed: true, ManageAllowed: true, NextDeployment: s.env.proposal}, nil
}

func (s *dRecoveryAuthorityMySQLSession) Audit(_ context.Context, _ pd.SQL, _ pd.RecoveryAuthorityRequest, stage string) error {
	if s.env.fail == stage {
		return pd.ErrUnavailable
	}
	if stage == "intent" && s.env.intentHook != nil {
		s.env.intentHook()
	}
	return nil
}

func (s *dRecoveryAuthorityMySQLSession) RecheckManager(ctx context.Context, tx pd.ReadSQL, _ pd.RecoveryAuthorityRequest, now time.Time) error {
	if err := s.guard.Recheck(ctx, tx, s.env.facts, RecoveryManagerWriteFence, now); err != nil {
		return err
	}
	return s.guard.Recheck(ctx, tx, s.env.facts, RecoveryManagerManageDeployment, now)
}

func (s *dRecoveryAuthorityMySQLSession) LockManagerRead(ctx context.Context, tx pd.SQL, r pd.RecoveryAuthorityReadRequest, _ *pd.RecoveryDeploymentProposal, _ pd.Hash) (pd.RecoveryAuthorityReadAdmission, error) {
	if err := s.guard.Lock(ctx, tx); err != nil {
		return pd.RecoveryAuthorityReadAdmission{}, err
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil {
		return pd.RecoveryAuthorityReadAdmission{}, err
	}
	if err := s.guard.Admit(s.env.facts, RecoveryManagerReadFence, now); err != nil {
		return pd.RecoveryAuthorityReadAdmission{}, err
	}
	h, err := pd.RecoveryAuthorityReadHash(r)
	if err != nil {
		return pd.RecoveryAuthorityReadAdmission{}, err
	}
	return pd.RecoveryAuthorityReadAdmission{VerifiedRequestHash: h,
		ManagerExpiresAt: systemExecutionStamp(s.env.facts.ExpiresAt), ReadAllowed: true}, nil
}

func (s *dRecoveryAuthorityMySQLSession) RecheckManagerRead(ctx context.Context, tx pd.ReadSQL, _ pd.RecoveryAuthorityReadRequest, now time.Time) error {
	return s.guard.Recheck(ctx, tx, s.env.facts, RecoveryManagerReadFence, now)
}

func TestDRecoveryAuthorityFixtureSeed(t *testing.T) {
	scope := pd.Scope{ServerUUID: "11111111-2222-4333-8444-555555555555", Database: "synthetic", Installation: "installation_recovery_authority_test"}
	if _, err := pd.RecoveryScopeKey(scope); err != nil {
		t.Fatal(err)
	}
}

// TestDRecoveryAuthorityMySQL exercises D's L0/L1a/L2 atomic transition with
// the real candidate tables and A's L1b row guard. The authenticated manager
// facts and audit capacity are fixtures; this is not production admission.
func TestDRecoveryAuthorityMySQL(t *testing.T) {
	db, lost := dProducerMySQLDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var database, server string
	mustSQL(t, db.QueryRowContext(ctx, "SELECT DATABASE(),@@server_uuid").Scan(&database, &server))
	scope := pd.Scope{ServerUUID: pd.ServerUUID(server), Database: pd.Database(database), Installation: "installation_recovery_authority_test"}
	key, err := pd.RecoveryScopeKey(scope)
	mustSQL(t, err)
	digest := func(c string) string { return strings.Repeat(c, 64) }
	decode := func(s string) []byte { b, err := hex.DecodeString(s); mustSQL(t, err); return b }
	var now time.Time
	mustSQL(t, db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now))
	until := now.Add(3 * time.Minute)
	facts := RecoveryManagerPeerFacts{Scope: scope, IdentityHash: digest("a"), IssuerIdentityHash: digest("b"),
		CredentialBindingHash: digest("c"), ExpiresAt: until}
	_, err = db.ExecContext(ctx, `INSERT INTO system_backup_v2_installation_state
(origin_installation_id,active_config_version,last_effective_enabled_transition_at,matrix_key)
VALUES (?,1,UTC_TIMESTAMP(6),'k8s-cluster')`, string(scope.Installation))
	mustSQL(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO system_backup_v2_recovery_managers
(scope_key,management_identity_hash,origin_installation_id,issuer_identity_hash,credential_binding_hash,can_read_fence,can_write_fence,can_manage_deployment,enabled,authorized_until,row_version)
VALUES (?,?,?,?,?,TRUE,TRUE,TRUE,TRUE,?,1)`, key, decode(facts.IdentityHash), string(scope.Installation),
		decode(facts.IssuerIdentityHash), decode(facts.CredentialBindingHash), until)
	mustSQL(t, err)
	firstIdentity := pd.Hash(digest("d"))
	proposal := pd.RecoveryDeploymentProposal{
		WorkloadIdentityHash: firstIdentity, IssuerIdentityHash: pd.Hash(digest("1")), SubjectHash: pd.Hash(digest("2")),
		ManagementIssuerHash: pd.Hash(facts.IssuerIdentityHash), ActorIdentityHash: pd.Hash(digest("3")),
		AdmissionHash: pd.Hash(digest("4")), ClientCASHA256: pd.Hash(digest("5")), CertificateSHA256: pd.Hash(digest("6")),
		StatProfileHash: pd.Hash(digest("7")), Enabled: true, Epoch: "1", RowVersion: "1",
		AuthorizedUntil: systemExecutionStamp(until),
	}
	env := &dRecoveryAuthorityMySQLEnvironment{scope: scope, facts: facts, proposal: proposal}
	manager, err := pd.NewRecoveryAuthorityManager(db, scope, env)
	mustSQL(t, err)
	reader, err := pd.NewRecoveryAuthorityReader(db, scope, env)
	mustSQL(t, err)
	readRequest := pd.RecoveryAuthorityReadRequest{Scope: scope, Nonce: "d-recovery-authority-read-mysql", BudgetUntil: systemExecutionStamp(until)}
	r := pd.RecoveryAuthorityRequest{Fence: pd.RecoveryFenceRequest{Scope: scope, Operation: "register", IdentityHash: firstIdentity,
		ExpectedEpoch: "0", ExpectedRowVersion: "0", ReasonHash: pd.Hash(digest("8"))},
		ExpectedDeploymentVersion: "0", Nonce: "d-recovery-authority-mysql", BudgetUntil: systemExecutionStamp(until)}
	read := func(identity pd.Hash) (bool, int64, int64, string, int64, bool) {
		t.Helper()
		var enabled bool
		var deploymentEpoch, deploymentVersion int64
		var workload []byte
		mustSQL(t, db.QueryRowContext(ctx, `SELECT enabled,deployment_epoch,row_version,workload_identity_hash FROM system_backup_v2_recovery_deployments WHERE scope_key=?`, key).
			Scan(&enabled, &deploymentEpoch, &deploymentVersion, &workload))
		var fenceEpoch, fenceVersion int64
		var revoked sql.NullTime
		mustSQL(t, db.QueryRowContext(ctx, `SELECT revocation_epoch,row_version,revoked_at FROM system_backup_v2_producer_recovery_revocations WHERE scope_key=? AND workload_identity_hash=?`, key, decode(string(identity))).
			Scan(&fenceEpoch, &fenceVersion, &revoked))
		return enabled, deploymentEpoch, deploymentVersion, hex.EncodeToString(workload), fenceEpoch, revoked.Valid
	}
	// The result audit fails after both writes; InnoDB must roll back both.
	env.fail = "result"
	if got, err := manager.Change(ctx, r); !errors.Is(err, pd.ErrUnavailable) || got != (pd.RecoveryAuthorityResult{}) {
		t.Fatalf("audit rollback result: %v %v", got, err)
	}
	var count int
	mustSQL(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_recovery_deployments WHERE scope_key=?", key).Scan(&count))
	if count != 0 {
		t.Fatal("deployment survived failed audit")
	}
	mustSQL(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_producer_recovery_revocations WHERE scope_key=?", key).Scan(&count))
	if count != 0 {
		t.Fatal("fence survived failed audit")
	}
	env.fail = ""
	// Two first registrations contend on the same L0 parent. Only one wins.
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := manager.Change(ctx, r); results <- err }()
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		switch {
		case err == nil:
			success++
		case errors.Is(err, pd.ErrConflict):
			conflict++
		default:
			t.Fatal("unexpected registration result", err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal("missing-row registration was not serialized", success, conflict)
	}
	if enabled, epoch, version, workload, fenceEpoch, revoked := read(firstIdentity); !enabled || epoch != 1 || version != 1 || workload != string(firstIdentity) || fenceEpoch != 1 || revoked {
		t.Fatal("registered rows disagree")
	}
	if observed, err := reader.Read(ctx, readRequest); err != nil || !observed.DeploymentFound || !observed.FenceFound || observed.Deployment.Epoch != "1" || observed.Fence.Epoch != "1" {
		t.Fatal("fresh manager-authorized read after registration", observed, err)
	}
	// Same identity certificate rotation must advance both epochs atomically.
	r.Fence.Operation, r.Fence.ExpectedEpoch, r.Fence.ExpectedRowVersion, r.ExpectedDeploymentVersion = "rotate", "1", "1", "1"
	env.proposal.Epoch, env.proposal.RowVersion, env.proposal.CertificateSHA256 = "2", "2", pd.Hash(digest("9"))
	if _, err := manager.Change(ctx, r); err != nil {
		t.Fatal("same identity rotate", err)
	}
	if enabled, epoch, version, workload, fenceEpoch, revoked := read(firstIdentity); !enabled || epoch != 2 || version != 2 || workload != string(firstIdentity) || fenceEpoch != 2 || revoked {
		t.Fatal("same identity rotation rows disagree")
	}
	// Lost COMMIT acknowledgement must return no authority, even if both rows
	// committed. The test then independently observes the exact current state.
	r.Fence.ExpectedEpoch, r.Fence.ExpectedRowVersion, r.ExpectedDeploymentVersion = "2", "2", "2"
	env.proposal.Epoch, env.proposal.RowVersion = "3", "3"
	lost.Store(true)
	if got, err := manager.Change(ctx, r); !errors.Is(err, pd.ErrCommitUnknown) || got != (pd.RecoveryAuthorityResult{}) {
		t.Fatalf("lost commit leaked authority: %v %v", got, err)
	}
	if enabled, epoch, version, workload, fenceEpoch, revoked := read(firstIdentity); !enabled || epoch != 3 || version != 3 || workload != string(firstIdentity) || fenceEpoch != 3 || revoked {
		t.Fatal("lost acknowledgement left inconsistent rows")
	}
	if observed, err := reader.Read(ctx, readRequest); err != nil || !observed.DeploymentFound || !observed.FenceFound || observed.Deployment.Epoch != "3" || observed.Fence.Epoch != "3" {
		t.Fatal("fresh manager-authorized read after lost acknowledgement", observed, err)
	}
	// The independent manager read must wait for the L0/L1a/L2 transition and
	// then observe the committed pair, never a half-rotated deployment.
	locked, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unlock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unlock)
	env.intentHook = func() { close(locked); <-release }
	r.Fence.ExpectedEpoch, r.Fence.ExpectedRowVersion, r.ExpectedDeploymentVersion = "3", "3", "3"
	env.proposal.Epoch, env.proposal.RowVersion = "4", "4"
	changeResult := make(chan error, 1)
	go func() { _, changeErr := manager.Change(ctx, r); changeResult <- changeErr }()
	select {
	case <-locked:
	case <-time.After(8 * time.Second):
		t.Fatal("manager did not hold the transition locks")
	}
	type observedResult struct {
		value pd.RecoveryAuthorityObservation
		err   error
	}
	readResult := make(chan observedResult, 1)
	go func() { value, readErr := reader.Read(ctx, readRequest); readResult <- observedResult{value, readErr} }()
	select {
	case result := <-readResult:
		t.Fatal("read passed the uncommitted transition", result)
	case <-time.After(150 * time.Millisecond):
	}
	unlock()
	select {
	case changeErr := <-changeResult:
		if changeErr != nil {
			t.Fatal("held transition", changeErr)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("held transition did not commit")
	}
	env.intentHook = nil
	select {
	case result := <-readResult:
		if result.err != nil || !result.value.DeploymentFound || !result.value.FenceFound ||
			result.value.Deployment.Epoch != "4" || result.value.Fence.Epoch != "4" {
			t.Fatal("read did not observe the committed pair", result)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("read did not resolve after transition")
	}
	// A separate connection holds L2 after the previous transition. The next
	// change reaches L2 only after locking L0/L1a/L1b; cancellation must roll
	// back the whole transaction, including any earlier deployment work.
	blocker, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	mustSQL(t, err)
	var blockedEpoch int64
	mustSQL(t, blocker.QueryRowContext(ctx, `SELECT revocation_epoch FROM system_backup_v2_producer_recovery_revocations
WHERE scope_key=? AND workload_identity_hash=? FOR UPDATE`, key, decode(string(firstIdentity))).Scan(&blockedEpoch))
	if blockedEpoch != 4 {
		blocker.Rollback()
		t.Fatal("unexpected blocked fence epoch", blockedEpoch)
	}
	r.Fence.ExpectedEpoch, r.Fence.ExpectedRowVersion, r.ExpectedDeploymentVersion = "4", "4", "4"
	env.proposal.Epoch, env.proposal.RowVersion = "5", "5"
	blockedCtx, cancelBlocked := context.WithTimeout(ctx, time.Second)
	blockedAt := time.Now()
	got, blockedErr := manager.Change(blockedCtx, r)
	cancelBlocked()
	if blockedErr == nil || got != (pd.RecoveryAuthorityResult{}) || time.Since(blockedAt) < 200*time.Millisecond {
		blocker.Rollback()
		t.Fatalf("blocked transition returned authority: %v %v", got, blockedErr)
	}
	mustSQL(t, blocker.Rollback())
	if enabled, epoch, version, workload, fenceEpoch, revoked := read(firstIdentity); !enabled || epoch != 4 || version != 4 || workload != string(firstIdentity) || fenceEpoch != 4 || revoked {
		t.Fatal("lock cancellation changed authority rows")
	}
	// A disabled manager loses both write and deployment authority on the next
	// transaction; no L1a/L2 version changes are permitted.
	_, err = db.ExecContext(ctx, `UPDATE system_backup_v2_recovery_managers SET enabled=FALSE,row_version=2 WHERE scope_key=? AND management_identity_hash=?`, key, decode(facts.IdentityHash))
	mustSQL(t, err)
	if got, err := manager.Change(ctx, r); err == nil || got != (pd.RecoveryAuthorityResult{}) {
		t.Fatalf("disabled manager changed authority: %v %v", got, err)
	}
	if _, epoch, _, _, fenceEpoch, _ := read(firstIdentity); epoch != 4 || fenceEpoch != 4 {
		t.Fatal("disabled manager advanced rows")
	}
	if observed, err := reader.Read(ctx, readRequest); err == nil || observed != (pd.RecoveryAuthorityObservation{}) {
		t.Fatalf("disabled manager read authority: %v %v", observed, err)
	}
	// Once an emergency revoke commits, a later rotate cannot silently turn
	// the same revoked identity back into an enabled deployment.
	_, err = db.ExecContext(ctx, `UPDATE system_backup_v2_recovery_managers SET enabled=TRUE,row_version=3 WHERE scope_key=? AND management_identity_hash=?`, key, decode(facts.IdentityHash))
	mustSQL(t, err)
	r.Fence.Operation = "revoke"
	env.proposal.Enabled = false
	if _, err := manager.Change(ctx, r); err != nil {
		t.Fatal("emergency revoke", err)
	}
	r.Fence.Operation, r.Fence.ExpectedEpoch, r.Fence.ExpectedRowVersion, r.ExpectedDeploymentVersion = "rotate", "5", "5", "5"
	env.proposal.Enabled, env.proposal.Epoch, env.proposal.RowVersion = true, "6", "6"
	if got, err := manager.Change(ctx, r); !errors.Is(err, pd.ErrConflict) || got != (pd.RecoveryAuthorityResult{}) {
		t.Fatalf("revoked identity revived: %v %v", got, err)
	}
	if enabled, epoch, version, _, fenceEpoch, revoked := read(firstIdentity); enabled || epoch != 5 || version != 5 || fenceEpoch != 5 || !revoked {
		t.Fatal("rejected rotate changed revoked rows")
	}
}
