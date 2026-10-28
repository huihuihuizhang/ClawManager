//go:build systembackup_mysql

package systembackupevidence

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// This race covers the combined L1a/L2 manager. The recovery workload and
// audit decision remain fixtures; production admission is a separate gate.
func TestDRecoveryAuthorityRaceMySQL(t *testing.T) {
	for _, operation := range []string{"rotate", "revoke"} {
		t.Run(operation, func(t *testing.T) {
			db, _ := dProducerMySQLDB(t)
			f := newDIntegrationFixtureWithDB(t, db, false, true)
			f.advance("pending")
			ctx := context.Background()
			identity := pd.Hash(strings.Repeat("7", 64))
			if operation == "revoke" {
				identity = pd.Hash(strings.Repeat("8", 64))
			}
			scope := f.history.Scope
			key, err := pd.RecoveryScopeKey(scope)
			mustSQL(t, err)
			var now time.Time
			mustSQL(t, db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now))
			until := now.Add(3 * time.Minute)
			digest := func(c string) string { return strings.Repeat(c, 64) }
			decode := func(s string) []byte { b, err := hex.DecodeString(s); mustSQL(t, err); return b }
			_, err = db.ExecContext(ctx, `INSERT INTO system_backup_v2_installation_state
(origin_installation_id,active_config_version,last_effective_enabled_transition_at,matrix_key)
VALUES (?,1,UTC_TIMESTAMP(6),'k8s-cluster')`, string(scope.Installation))
			mustSQL(t, err)
			facts := RecoveryManagerPeerFacts{Scope: scope, IdentityHash: digest("a"), IssuerIdentityHash: digest("b"),
				CredentialBindingHash: digest("c"), ExpiresAt: until}
			_, err = db.ExecContext(ctx, `INSERT INTO system_backup_v2_recovery_managers
(scope_key,management_identity_hash,origin_installation_id,issuer_identity_hash,credential_binding_hash,can_read_fence,can_write_fence,can_manage_deployment,enabled,authorized_until,row_version)
VALUES (?,?,?,?,?,TRUE,TRUE,TRUE,TRUE,?,1)`, key, decode(facts.IdentityHash), string(scope.Installation),
				decode(facts.IssuerIdentityHash), decode(facts.CredentialBindingHash), until)
			mustSQL(t, err)
			proposal := pd.RecoveryDeploymentProposal{
				WorkloadIdentityHash: identity, IssuerIdentityHash: pd.Hash(digest("1")), SubjectHash: pd.Hash(digest("2")),
				ManagementIssuerHash: pd.Hash(facts.IssuerIdentityHash), ActorIdentityHash: pd.Hash(digest("3")),
				AdmissionHash: pd.Hash(digest("4")), ClientCASHA256: pd.Hash(digest("5")), CertificateSHA256: pd.Hash(digest("6")),
				StatProfileHash: pd.Hash(digest("9")), Enabled: true, Epoch: "1", RowVersion: "1",
				AuthorizedUntil: systemExecutionStamp(until),
			}
			env := &dRecoveryAuthorityMySQLEnvironment{scope: scope, facts: facts, proposal: proposal}
			manager, err := pd.NewRecoveryAuthorityManager(db, scope, env)
			mustSQL(t, err)
			change := pd.RecoveryAuthorityRequest{Fence: pd.RecoveryFenceRequest{Scope: scope, Operation: "register",
				IdentityHash: identity, ExpectedEpoch: "0", ExpectedRowVersion: "0", ReasonHash: pd.Hash(digest("d"))},
				ExpectedDeploymentVersion: "0", Nonce: "authority-race", BudgetUntil: systemExecutionStamp(until)}
			_, err = manager.Change(ctx, change)
			mustSQL(t, err)
			if epoch, version, revoked, found := dRecoveryFenceStored(t, db, f.history, identity); !found || epoch != 1 || version != 1 || revoked {
				t.Fatal("combined manager registration failed", epoch, version, revoked, found)
			}
			recovery := &dRecoveryMySQLAuthority{f: f, identity: identity, epoch: "1"}
			service, err := pd.NewHistoricalRecovery(db, scope, recovery)
			mustSQL(t, err)
			dRecoveryMySQLWaitCutoff(t, db, f.history.OwnerWriteExpiresAt)
			mustSQL(t, db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now))
			request := pd.RecoveryRequest{Scope: scope, EvidenceID: f.history.Evidence.EvidenceID,
				ExpectedEvidenceVersion: "1", Nonce: "authority-race-recovery",
				ClaimExpiresAt: systemExecutionStamp(now.Add(90 * time.Second)), BudgetUntil: systemExecutionStamp(now.Add(120 * time.Second))}
			var work func() error
			if operation == "rotate" {
				work = func() error { _, err := service.ClaimRecovery(ctx, request); return err }
			} else {
				claim, err := service.ClaimRecovery(ctx, request)
				mustSQL(t, err)
				mustSQL(t, db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now))
				finish := pd.RecoveryFinishRequest{State: "write_unknown", ProofHash: pd.Hash(digest("e")),
					ObjectHash: f.history.Evidence.ObjectHash, ObjectBytes: f.history.Evidence.ObjectBytes,
					ObservedAt: systemExecutionStamp(now), BudgetUntil: systemExecutionStamp(now.Add(30 * time.Second))}
				work = func() error { _, err := service.FinishRecovery(ctx, claim, finish); return err }
			}
			beforeState, beforeVersion, beforeOwner := dRecoveryEvidenceState(t, db, request.EvidenceID)
			change.Fence.Operation, change.Fence.ExpectedEpoch, change.Fence.ExpectedRowVersion = operation, "1", "1"
			change.ExpectedDeploymentVersion = "1"
			env.proposal.Epoch, env.proposal.RowVersion = "2", "2"
			if operation == "revoke" {
				env.proposal.Enabled = false
			} else {
				env.proposal.CertificateSHA256 = pd.Hash(digest("f"))
			}
			locked, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unlock := func() { releaseOnce.Do(func() { close(release) }) }
			t.Cleanup(unlock)
			env.intentHook = func() { close(locked); <-release }
			managerResult := make(chan error, 1)
			go func() { _, changeErr := manager.Change(ctx, change); managerResult <- changeErr }()
			select {
			case <-locked:
			case <-time.After(8 * time.Second):
				t.Fatal("combined manager did not hold authority locks")
			}
			reached := make(chan struct{}, 1)
			recovery.authorized = reached
			recoveryResult := make(chan error, 1)
			go func() { recoveryResult <- work() }()
			select {
			case <-reached:
			case <-time.After(8 * time.Second):
				t.Fatal("recovery did not reach L2")
			}
			select {
			case workErr := <-recoveryResult:
				t.Fatal("recovery passed locked authority before management committed", workErr)
			case <-time.After(150 * time.Millisecond):
			}
			unlock()
			select {
			case changeErr := <-managerResult:
				mustSQL(t, changeErr)
			case <-time.After(8 * time.Second):
				t.Fatal("combined manager did not commit")
			}
			select {
			case workErr := <-recoveryResult:
				if !errors.Is(workErr, pd.ErrGuardRequired) {
					t.Fatal("old-epoch recovery was not fenced", workErr)
				}
			case <-time.After(8 * time.Second):
				t.Fatal("recovery did not resolve after management commit")
			}
			state, version, owner := dRecoveryEvidenceState(t, db, request.EvidenceID)
			if state != beforeState || version != beforeVersion || owner != beforeOwner {
				t.Fatal("fenced recovery changed evidence", state, version, owner)
			}
			var deploymentEpoch, deploymentVersion int64
			var enabled bool
			mustSQL(t, db.QueryRowContext(ctx, `SELECT deployment_epoch,row_version,enabled FROM system_backup_v2_recovery_deployments WHERE scope_key=?`, key).
				Scan(&deploymentEpoch, &deploymentVersion, &enabled))
			fenceEpoch, fenceVersion, revoked, found := dRecoveryFenceStored(t, db, f.history, identity)
			if !found || deploymentEpoch != 2 || deploymentVersion != 2 || fenceEpoch != 2 || fenceVersion != 2 || enabled == revoked {
				t.Fatal("combined manager left inconsistent authority", deploymentEpoch, deploymentVersion, enabled, fenceEpoch, fenceVersion, revoked)
			}
		})
	}
}
