//go:build systembackup_mysql

package systembackupevidence

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// D's current-state reader uses A's live mTLS and L1b read permission. The
// absent deployment is a valid observation before first registration.
func TestSystemRecoveryAuthorityReadMySQL(t *testing.T) {
	db, _ := dProducerMySQLDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, peerFixture, c := systemPeerFixture(t)
	// D's guarded transaction checks the actual MySQL server/database identity.
	// A direct L1b probe can use a synthetic scope, but the full reader cannot.
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
VALUES (?,?,?,?,?,TRUE,FALSE,FALSE,TRUE,?,1)`, key, decode(facts.IdentityHash), string(scope.Installation), decode(facts.IssuerIdentityHash), decode(facts.CredentialBindingHash), now.Add(time.Minute))
	mustSQL(t, err)
	env, err := NewSystemRecoveryAuthorityReadEnvironment(auth, peer)
	mustSQL(t, err)
	reader, err := pd.NewRecoveryAuthorityReader(db, scope, env)
	mustSQL(t, err)
	r := pd.RecoveryAuthorityReadRequest{Scope: scope, Nonce: "a-manager-read-mysql-1", BudgetUntil: systemPublicationTimestamp(now.Add(time.Minute))}
	observed, err := reader.Read(ctx, r)
	if err != nil || observed.DeploymentFound || observed.FenceFound {
		t.Fatal("authorized empty current-state observation rejected", err)
	}
	_, err = db.ExecContext(ctx, "UPDATE system_backup_v2_recovery_managers SET can_read_fence=FALSE,row_version=2 WHERE scope_key=? AND management_identity_hash=?", key, decode(facts.IdentityHash))
	mustSQL(t, err)
	r.Nonce = "a-manager-read-mysql-2"
	if _, err := reader.Read(ctx, r); err == nil {
		t.Fatal("revoked management read permission accepted")
	}
}
