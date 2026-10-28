//go:build systembackup_mysql

package systembackupevidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

type combinedRecoveryDecision struct {
	next       pd.RecoveryDeploymentProposal
	failResult bool
}

func TestSystemRecoveryAuthorityPinnedDecisionMySQL(t *testing.T) {
	db, _ := dProducerMySQLDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, peerFixture, c := systemPeerFixture(t)
	var server, database string
	mustSQL(t, db.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE()").Scan(&server, &database))
	scope := c.Scope
	scope.ServerUUID, scope.Database = pd.ServerUUID(server), pd.Database(database)
	mapping := RecoveryManagerPeerConfig{Scope: scope, IssuerIdentityHash: strings.Repeat("d", 64), Subject: "recovery-manager",
		ClientCAPEM: c.ClientCAPEM, ClientCASHA256: c.ClientCASHA256,
		CertificateSHA256: c.CertificateSHA256, ExpiresAt: c.ExpiresAt}
	auth, err := NewRecoveryManagerPeerAuthenticator(mapping)
	mustSQL(t, err)
	t.Cleanup(auth.Close)
	peer, err := auth.AuthenticateRequest(peerFixture.request)
	mustSQL(t, err)
	var now time.Time
	mustSQL(t, db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now))
	facts, err := auth.Check(ctx, peer, scope, now)
	mustSQL(t, err)
	key, err := pd.RecoveryScopeKey(scope)
	mustSQL(t, err)
	decode := func(s string) []byte { b, err := hex.DecodeString(s); mustSQL(t, err); return b }
	_, err = db.ExecContext(ctx, `INSERT INTO system_backup_v2_installation_state
(origin_installation_id,active_config_version,last_effective_enabled_transition_at,matrix_key)
VALUES (?,1,UTC_TIMESTAMP(6),'k8s-cluster')`, string(scope.Installation))
	mustSQL(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO system_backup_v2_recovery_managers
(scope_key,management_identity_hash,origin_installation_id,issuer_identity_hash,credential_binding_hash,can_read_fence,can_write_fence,can_manage_deployment,enabled,authorized_until,row_version)
VALUES (?,?,?,?,?,TRUE,TRUE,TRUE,TRUE,?,1)`, key, decode(facts.IdentityHash), string(scope.Installation),
		decode(facts.IssuerIdentityHash), decode(facts.CredentialBindingHash), now.Add(time.Minute))
	mustSQL(t, err)
	digest := func(s string) pd.Hash { return pd.Hash(strings.Repeat(s, 64)) }
	identity := digest("a")
	r := pd.RecoveryAuthorityRequest{Fence: pd.RecoveryFenceRequest{Scope: scope, Operation: "register",
		IdentityHash: identity, ExpectedEpoch: "0", ExpectedRowVersion: "0", ReasonHash: digest("b")},
		ExpectedDeploymentVersion: "0", Nonce: "a-manager-pinned-1", BudgetUntil: systemPublicationTimestamp(now.Add(time.Minute))}
	requestHash, err := pd.RecoveryAuthorityHash(r)
	mustSQL(t, err)
	doc := recoveryAuthorityDecisionDocument{SchemaVersion: recoveryAuthorityDecisionVersion, Scope: scope,
		RequestHash: string(requestHash), ManagerIdentityHash: facts.IdentityHash, ManagerIssuerHash: facts.IssuerIdentityHash,
		Next: pd.RecoveryDeploymentProposal{WorkloadIdentityHash: identity, IssuerIdentityHash: digest("1"),
			SubjectHash: digest("2"), ManagementIssuerHash: pd.Hash(facts.IssuerIdentityHash),
			ActorIdentityHash: digest("3"), AdmissionHash: digest("4"), ClientCASHA256: digest("5"),
			CertificateSHA256: digest("6"), StatProfileHash: digest("7"), Enabled: true,
			Epoch: "1", RowVersion: "1", AuthorizedUntil: systemPublicationTimestamp(now.Add(time.Minute))},
		NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}
	raw, err := json.Marshal(doc)
	mustSQL(t, err)
	path := filepath.Join(t.TempDir(), "deployment-decision.json")
	mustSQL(t, os.WriteFile(path, raw, 0600))
	sum := sha256.Sum256(raw)
	auditPath := filepath.Join(t.TempDir(), "independent-audit.jsonl")
	mustSQL(t, os.WriteFile(auditPath, nil, 0600))
	audit, err := NewRecoveryAuditJournal(auditPath, 4096)
	mustSQL(t, err)
	t.Cleanup(func() { audit.Close() })
	decision, err := NewPinnedRecoveryAuthorityDecision(scope, path, hex.EncodeToString(sum[:]), audit)
	mustSQL(t, err)
	env, err := NewSystemRecoveryAuthorityEnvironment(auth, peer, decision)
	mustSQL(t, err)
	manager, err := pd.NewRecoveryAuthorityManager(db, scope, env)
	mustSQL(t, err)
	result, err := manager.Change(ctx, r)
	mustSQL(t, err)
	if result.WorkloadIdentityHash != identity || result.DeploymentEpoch != "1" || result.DeploymentVersion != "1" || !result.Enabled {
		t.Fatal("pinned decision did not commit exact deployment")
	}
	var count int
	mustSQL(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_recovery_deployments WHERE scope_key=? AND enabled=TRUE AND deployment_epoch=1", key).Scan(&count))
	if count != 1 {
		t.Fatal("pinned decision did not write current deployment")
	}
	mustSQL(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_producer_recovery_revocations WHERE scope_key=? AND workload_identity_hash=? AND revocation_epoch=1", key, decode(string(identity))).Scan(&count))
	if count != 1 {
		t.Fatal("pinned decision did not write matching fence")
	}
	mustSQL(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_logs WHERE action LIKE 'system_backup.recovery_authority.%'").Scan(&count))
	lines, err := os.ReadFile(auditPath)
	mustSQL(t, err)
	parts := bytes.Split(bytes.TrimSuffix(lines, []byte{'\n'}), []byte{'\n'})
	if count != 2 || len(parts) != 2 || !bytes.Contains(parts[0], []byte(`"stage":"intent"`)) ||
		!bytes.Contains(parts[1], []byte(`"stage":"result_prepared"`)) {
		t.Fatal("pinned decision did not write both audits")
	}
}

func (d *combinedRecoveryDecision) NextDeployment(_ context.Context, _ pd.SQL, _ pd.RecoveryAuthorityRequest, _ *pd.RecoveryDeploymentProposal, _ RecoveryManagerPeerFacts) (pd.RecoveryDeploymentProposal, error) {
	return d.next, nil
}

func (d *combinedRecoveryDecision) Audit(ctx context.Context, tx pd.SQL, r pd.RecoveryAuthorityRequest, stage string) error {
	if d.failResult && stage == "result" {
		return errors.New("injected result audit failure")
	}
	hash, err := pd.RecoveryAuthorityHash(r)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_logs(action,resource_type,details) VALUES (?,'system_backup',JSON_OBJECT('request_hash',?))`,
		"system_backup.recovery_authority."+stage, string(hash))
	return err
}

// This probe verifies A's request-bound management mTLS adapter with the real
// L1b MySQL row. D's complete L1a/L2 manager transaction is tested separately.
func TestSystemRecoveryAuthorityMySQL(t *testing.T) {
	db, _ := dProducerMySQLDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, peerFixture, c := systemPeerFixture(t)
	mapping := RecoveryManagerPeerConfig{Scope: c.Scope, IssuerIdentityHash: strings.Repeat("d", 64), Subject: "recovery-manager",
		ClientCAPEM: c.ClientCAPEM, ClientCASHA256: c.ClientCASHA256, CertificateSHA256: c.CertificateSHA256, ExpiresAt: c.ExpiresAt}
	auth, err := NewRecoveryManagerPeerAuthenticator(mapping)
	mustSQL(t, err)
	t.Cleanup(auth.Close)
	peer, err := auth.AuthenticateRequest(peerFixture.request)
	mustSQL(t, err)
	var now time.Time
	mustSQL(t, db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now))
	facts, err := auth.Check(ctx, peer, c.Scope, now)
	mustSQL(t, err)
	decode := func(s string) []byte { b, err := hex.DecodeString(s); mustSQL(t, err); return b }
	key, err := pd.RecoveryScopeKey(c.Scope)
	mustSQL(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO system_backup_v2_installation_state
(origin_installation_id,active_config_version,last_effective_enabled_transition_at,matrix_key)
VALUES (?,1,UTC_TIMESTAMP(6),'k8s-cluster')`, string(c.Scope.Installation))
	mustSQL(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO system_backup_v2_recovery_managers
(scope_key,management_identity_hash,origin_installation_id,issuer_identity_hash,credential_binding_hash,can_read_fence,can_write_fence,can_manage_deployment,enabled,authorized_until,row_version)
VALUES (?,?,?,?,?,TRUE,TRUE,TRUE,TRUE,?,1)`, key, decode(facts.IdentityHash), string(c.Scope.Installation), decode(facts.IssuerIdentityHash), decode(facts.CredentialBindingHash), now.Add(time.Minute))
	mustSQL(t, err)
	decision := &recoveryAuthorityDecisionFixture{next: pd.RecoveryDeploymentProposal{ManagementIssuerHash: pd.Hash(facts.IssuerIdentityHash)}}
	env, err := NewSystemRecoveryAuthorityEnvironment(auth, peer, decision)
	mustSQL(t, err)
	r := pd.RecoveryAuthorityRequest{Fence: pd.RecoveryFenceRequest{
		Scope: c.Scope, Operation: "register", IdentityHash: pd.Hash(strings.Repeat("a", 64)),
		ExpectedEpoch: "0", ExpectedRowVersion: "0", ReasonHash: pd.Hash(strings.Repeat("b", 64)),
	}, ExpectedDeploymentVersion: "0", Nonce: "manager-mysql-register", BudgetUntil: systemPublicationTimestamp(now.Add(time.Minute))}
	s, err := env.PrepareRecoveryAuthority(ctx, r)
	mustSQL(t, err)
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	mustSQL(t, err)
	defer tx.Rollback()
	var parent string
	mustSQL(t, tx.QueryRowContext(ctx, "SELECT origin_installation_id FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR UPDATE", string(c.Scope.Installation)).Scan(&parent))
	if parent != string(c.Scope.Installation) {
		t.Fatal("wrong L0 parent")
	}
	admission, err := s.LockManager(ctx, recoveryManagerProbeTx{tx}, r, nil)
	if err != nil || !admission.WriteFenceAllowed || !admission.ManageAllowed || decision.calls != 1 {
		t.Fatal("current management authority rejected", err)
	}
	if err := s.RecheckManager(ctx, recoveryManagerProbeTx{tx}, r, now); err != nil {
		t.Fatal("unchanged manager final guard rejected", err)
	}
	_, err = tx.ExecContext(ctx, "UPDATE system_backup_v2_recovery_managers SET can_manage_deployment=FALSE,row_version=2 WHERE scope_key=? AND management_identity_hash=?", key, decode(facts.IdentityHash))
	mustSQL(t, err)
	if err := s.RecheckManager(ctx, recoveryManagerProbeTx{tx}, r, now); err != ErrDenied {
		t.Fatalf("revoked management permission accepted: %v", err)
	}
	mustSQL(t, tx.Rollback())
}

// The prior AManager probe exercised A's L1b adapter in a caller-owned SQL
// transaction. This probe runs the same authenticated adapter through D's
// complete L0/L1a/L1b/L2 transaction and checks audit rollback with real rows.
func TestSystemRecoveryAuthorityCombinedMySQL(t *testing.T) {
	db, _ := dProducerMySQLDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, peerFixture, c := systemPeerFixture(t)
	var server, database string
	mustSQL(t, db.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE()").Scan(&server, &database))
	scope := c.Scope
	scope.ServerUUID, scope.Database = pd.ServerUUID(server), pd.Database(database)
	mapping := RecoveryManagerPeerConfig{Scope: scope, IssuerIdentityHash: strings.Repeat("d", 64), Subject: "recovery-manager",
		ClientCAPEM: c.ClientCAPEM, ClientCASHA256: c.ClientCASHA256, CertificateSHA256: c.CertificateSHA256, ExpiresAt: c.ExpiresAt}
	auth, err := NewRecoveryManagerPeerAuthenticator(mapping)
	mustSQL(t, err)
	t.Cleanup(auth.Close)
	peer, err := auth.AuthenticateRequest(peerFixture.request)
	mustSQL(t, err)
	var now time.Time
	mustSQL(t, db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now))
	facts, err := auth.Check(ctx, peer, scope, now)
	mustSQL(t, err)
	decode := func(s string) []byte { b, err := hex.DecodeString(s); mustSQL(t, err); return b }
	key, err := pd.RecoveryScopeKey(scope)
	mustSQL(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO system_backup_v2_installation_state
(origin_installation_id,active_config_version,last_effective_enabled_transition_at,matrix_key)
VALUES (?,1,UTC_TIMESTAMP(6),'k8s-cluster')`, string(scope.Installation))
	mustSQL(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO system_backup_v2_recovery_managers
(scope_key,management_identity_hash,origin_installation_id,issuer_identity_hash,credential_binding_hash,can_read_fence,can_write_fence,can_manage_deployment,enabled,authorized_until,row_version)
VALUES (?,?,?,?,?,TRUE,TRUE,TRUE,TRUE,?,1)`, key, decode(facts.IdentityHash), string(scope.Installation),
		decode(facts.IssuerIdentityHash), decode(facts.CredentialBindingHash), now.Add(time.Minute))
	mustSQL(t, err)
	digest := func(s string) pd.Hash { return pd.Hash(strings.Repeat(s, 64)) }
	identity := digest("a")
	decision := &combinedRecoveryDecision{next: pd.RecoveryDeploymentProposal{
		WorkloadIdentityHash: identity, IssuerIdentityHash: digest("1"), SubjectHash: digest("2"),
		ManagementIssuerHash: pd.Hash(facts.IssuerIdentityHash), ActorIdentityHash: digest("3"),
		AdmissionHash: digest("4"), ClientCASHA256: digest("5"), CertificateSHA256: digest("6"),
		StatProfileHash: digest("7"), Enabled: true, Epoch: "1", RowVersion: "1",
		AuthorizedUntil: systemPublicationTimestamp(now.Add(time.Minute)),
	}}
	env, err := NewSystemRecoveryAuthorityEnvironment(auth, peer, decision)
	mustSQL(t, err)
	manager, err := pd.NewRecoveryAuthorityManager(db, scope, env)
	mustSQL(t, err)
	r := pd.RecoveryAuthorityRequest{Fence: pd.RecoveryFenceRequest{Scope: scope, Operation: "register",
		IdentityHash: identity, ExpectedEpoch: "0", ExpectedRowVersion: "0", ReasonHash: digest("b")},
		ExpectedDeploymentVersion: "0", Nonce: "a-manager-combined-1", BudgetUntil: systemPublicationTimestamp(now.Add(time.Minute))}
	decision.failResult = true
	if _, err := manager.Change(ctx, r); err == nil {
		t.Fatal("result audit failure committed recovery authority")
	}
	var count int
	mustSQL(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_recovery_deployments WHERE scope_key=?", key).Scan(&count))
	if count != 0 {
		t.Fatal("failed transaction left deployment")
	}
	mustSQL(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_producer_recovery_revocations WHERE scope_key=?", key).Scan(&count))
	if count != 0 {
		t.Fatal("failed transaction left revocation")
	}
	mustSQL(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_logs WHERE action LIKE 'system_backup.recovery_authority.%'").Scan(&count))
	if count != 0 {
		t.Fatal("failed transaction left audit")
	}
	decision.failResult = false
	r.Nonce = "a-manager-combined-2"
	result, err := manager.Change(ctx, r)
	mustSQL(t, err)
	if result.WorkloadIdentityHash != identity || result.DeploymentEpoch != "1" || result.DeploymentVersion != "1" || !result.Enabled {
		t.Fatal("combined result does not match current deployment")
	}
	mustSQL(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_recovery_deployments WHERE scope_key=? AND enabled=TRUE AND deployment_epoch=1", key).Scan(&count))
	if count != 1 {
		t.Fatal("combined transaction did not commit deployment")
	}
	mustSQL(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_producer_recovery_revocations WHERE scope_key=? AND workload_identity_hash=? AND revocation_epoch=1 AND revoked_at IS NULL", key, decode(string(identity))).Scan(&count))
	if count != 1 {
		t.Fatal("combined transaction did not commit matching fence")
	}
	mustSQL(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_logs WHERE action LIKE 'system_backup.recovery_authority.%'").Scan(&count))
	if count != 2 {
		t.Fatal("combined transaction did not commit intent and result audits")
	}
	_, err = db.ExecContext(ctx, "UPDATE system_backup_v2_recovery_managers SET can_write_fence=FALSE,row_version=2 WHERE scope_key=? AND management_identity_hash=?", key, decode(facts.IdentityHash))
	mustSQL(t, err)
	r.Fence.Operation, r.Fence.ExpectedEpoch, r.Fence.ExpectedRowVersion = "rotate", "1", "1"
	r.ExpectedDeploymentVersion, r.Nonce = "1", "a-manager-combined-3"
	decision.next.Epoch, decision.next.RowVersion, decision.next.CertificateSHA256 = "2", "2", digest("8")
	if _, err := manager.Change(ctx, r); err == nil {
		t.Fatal("revoked manager write permission changed recovery authority")
	}
	var epoch, version int64
	mustSQL(t, db.QueryRowContext(ctx, "SELECT deployment_epoch,row_version FROM system_backup_v2_recovery_deployments WHERE scope_key=?", key).Scan(&epoch, &version))
	if epoch != 1 || version != 1 {
		t.Fatal("denied manager request changed deployment")
	}
	mustSQL(t, db.QueryRowContext(ctx, "SELECT revocation_epoch,row_version FROM system_backup_v2_producer_recovery_revocations WHERE scope_key=? AND workload_identity_hash=?", key, decode(string(identity))).Scan(&epoch, &version))
	if epoch != 1 || version != 1 {
		t.Fatal("denied manager request changed revocation fence")
	}
	mustSQL(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_logs WHERE action LIKE 'system_backup.recovery_authority.%'").Scan(&count))
	if count != 2 {
		t.Fatal("denied manager request appended an audit result")
	}
}
