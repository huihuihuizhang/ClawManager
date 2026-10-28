//go:build systembackup_mysql

package systembackupevidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

func TestRecoveryManagerRevocationMySQL(t *testing.T) {
	db, _ := dProducerMySQLDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, peerFixture, config := systemPeerFixture(t)
	var server, database string
	mustSQL(t, db.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE()").Scan(&server, &database))
	scope := config.Scope
	scope.ServerUUID, scope.Database = pd.ServerUUID(server), pd.Database(database)
	mapping := RecoveryManagerPeerConfig{Scope: scope, IssuerIdentityHash: strings.Repeat("d", 64), Subject: "recovery-manager",
		ClientCAPEM: config.ClientCAPEM, ClientCASHA256: config.ClientCASHA256,
		CertificateSHA256: config.CertificateSHA256, ExpiresAt: config.ExpiresAt}
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
	identity, err := hex.DecodeString(facts.IdentityHash)
	mustSQL(t, err)
	issuer, err := hex.DecodeString(facts.IssuerIdentityHash)
	mustSQL(t, err)
	credential, err := hex.DecodeString(facts.CredentialBindingHash)
	mustSQL(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO system_backup_v2_installation_state
(origin_installation_id,active_config_version,last_effective_enabled_transition_at,matrix_key)
VALUES (?,1,UTC_TIMESTAMP(6),'k8s-cluster')`, string(scope.Installation))
	mustSQL(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO system_backup_v2_recovery_managers
(scope_key,management_identity_hash,origin_installation_id,issuer_identity_hash,credential_binding_hash,
can_read_fence,can_write_fence,can_manage_deployment,enabled,authorized_until,row_version)
VALUES (?,?,?,?,?,TRUE,TRUE,TRUE,TRUE,?,1)`, key, identity, string(scope.Installation), issuer, credential, now.Add(time.Minute))
	mustSQL(t, err)
	doc := recoveryManagerRevocationDocument{SchemaVersion: recoveryManagerRevocationVersion,
		GrantID: "superior-revoke-mysql-20261012", Scope: scope, SuperiorIdentityHash: strings.Repeat("a", 64),
		ManagerIdentityHash: facts.IdentityHash, ReasonHash: strings.Repeat("b", 64), ExpectedRowVersion: 1,
		NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}
	raw, err := json.Marshal(doc)
	mustSQL(t, err)
	path := filepath.Join(t.TempDir(), "revocation-grant.json")
	mustSQL(t, os.WriteFile(path, raw, 0600))
	sum := sha256.Sum256(raw)
	pin := hex.EncodeToString(sum[:])
	grant, err := ReadRecoveryManagerRevocationGrant(path, pin)
	mustSQL(t, err)
	auditPath := filepath.Join(t.TempDir(), "independent-audit.jsonl")
	mustSQL(t, os.WriteFile(auditPath, nil, 0600))
	audit, err := NewRecoveryAuditJournal(auditPath, 4096)
	mustSQL(t, err)
	t.Cleanup(func() { audit.Close() })
	service := RecoveryManagerRevocationService{DB: db, Scope: scope, SuperiorIdentityHash: doc.SuperiorIdentityHash,
		GrantPath: path, GrantSHA256: pin, ExternalAudit: audit}
	mustSQL(t, service.Revoke(ctx, grant))
	var version int64
	var enabled, read, write, manage bool
	var revoked time.Time
	mustSQL(t, db.QueryRowContext(ctx, `SELECT row_version,enabled,can_read_fence,can_write_fence,can_manage_deployment,revoked_at
FROM system_backup_v2_recovery_managers WHERE scope_key=? AND management_identity_hash=?`, key, identity).
		Scan(&version, &enabled, &read, &write, &manage, &revoked))
	if version != 2 || enabled || read || write || manage || revoked.IsZero() {
		t.Fatal("L1b revocation did not commit")
	}
	var count int
	mustSQL(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_logs WHERE action LIKE 'system_backup.recovery_manager_revocation.%'").Scan(&count))
	lines, err := os.ReadFile(auditPath)
	mustSQL(t, err)
	parts := bytes.Split(bytes.TrimSuffix(lines, []byte{'\n'}), []byte{'\n'})
	if count != 2 || len(parts) != 2 || !bytes.Contains(parts[0], []byte(`"stage":"intent"`)) ||
		!bytes.Contains(parts[1], []byte(`"stage":"result"`)) {
		t.Fatal("revocation audits did not commit")
	}
	readEnv, err := NewSystemRecoveryAuthorityReadEnvironment(auth, peer)
	mustSQL(t, err)
	reader, err := pd.NewRecoveryAuthorityReader(db, scope, readEnv)
	mustSQL(t, err)
	readRequest := pd.RecoveryAuthorityReadRequest{Scope: scope, Nonce: "revoked-manager-read-1",
		BudgetUntil: systemPublicationTimestamp(now.Add(time.Minute))}
	if _, err := reader.Read(ctx, readRequest); err == nil {
		t.Fatal("revoked manager read current authority")
	}
}
