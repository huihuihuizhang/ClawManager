//go:build systembackup_mysql

package systembackupevidence

import (
	"context"
	"database/sql"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

type recoveryManagerProbeTx struct{ *sql.Tx }

func (recoveryManagerProbeTx) LockRecord(context.Context, pd.RecordKey, any) (*pd.LockedRecord, error) {
	return nil, ErrDenied
}

func dRecoveryManagerProbeScope() pd.Scope {
	return pd.Scope{ServerUUID: "11111111-2222-4333-8444-555555555555", Database: "synthetic", Installation: "installation_recovery_manager_row_test"}
}

// Run locally before building or uploading the remote probe.
func TestDRecoveryManagerFixtureSeed(t *testing.T) {
	if _, err := pd.RecoveryScopeKey(dRecoveryManagerProbeScope()); err != nil {
		t.Fatalf("invalid remote fixture scope: %v", err)
	}
}

// TestDRecoveryManagerRowMySQL validates the L1b row check against the
// candidate MySQL table. It does not provision management authority.
func TestDRecoveryManagerRowMySQL(t *testing.T) {
	db, _ := dProducerMySQLDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	scope := dRecoveryManagerProbeScope()
	digest := func(c string) string { return strings.Repeat(c, 64) }
	decode := func(s string) []byte { b, err := hex.DecodeString(s); mustSQL(t, err); return b }
	var now time.Time
	mustSQL(t, db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now))
	until := now.Add(time.Minute)
	facts := RecoveryManagerPeerFacts{Scope: scope, IdentityHash: digest("a"), IssuerIdentityHash: digest("b"), CredentialBindingHash: digest("c"), ExpiresAt: until}
	key, err := pd.RecoveryScopeKey(scope)
	mustSQL(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO system_backup_v2_installation_state
(origin_installation_id,active_config_version,last_effective_enabled_transition_at,matrix_key)
VALUES (?,1,UTC_TIMESTAMP(6),'k8s-cluster')`, string(scope.Installation))
	mustSQL(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO system_backup_v2_recovery_managers
(scope_key,management_identity_hash,origin_installation_id,issuer_identity_hash,credential_binding_hash,can_read_fence,can_write_fence,can_manage_deployment,enabled,authorized_until,row_version)
VALUES (?,?,?,?,?,TRUE,TRUE,FALSE,TRUE,?,1)`, key, decode(facts.IdentityHash), string(scope.Installation), decode(facts.IssuerIdentityHash), decode(facts.CredentialBindingHash), until)
	mustSQL(t, err)
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	mustSQL(t, err)
	defer tx.Rollback()
	var parent string
	mustSQL(t, tx.QueryRowContext(ctx, "SELECT origin_installation_id FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR UPDATE", string(scope.Installation)).Scan(&parent))
	if parent != string(scope.Installation) {
		t.Fatal("wrong L0 parent")
	}
	g, err := NewRecoveryManagerRowGuard(scope, facts)
	mustSQL(t, err)
	if err := g.Lock(ctx, recoveryManagerProbeTx{tx}); err != nil {
		t.Fatal("L1b lock:", err)
	}
	if err := g.Admit(facts, RecoveryManagerWriteFence, now); err != nil {
		t.Fatal("write permission:", err)
	}
	if err := g.Admit(facts, RecoveryManagerManageDeployment, now); err != ErrDenied {
		t.Fatalf("manage permission granted: %v", err)
	}
	wrong := facts
	wrong.CredentialBindingHash = digest("d")
	if err := g.Admit(wrong, RecoveryManagerWriteFence, now); err != ErrDenied {
		t.Fatalf("wrong credential granted: %v", err)
	}
	if err := g.Recheck(ctx, recoveryManagerProbeTx{tx}, facts, RecoveryManagerWriteFence, now); err != nil {
		t.Fatal("same-row recheck:", err)
	}
	_, err = tx.ExecContext(ctx, "UPDATE system_backup_v2_recovery_managers SET can_write_fence=FALSE,row_version=2 WHERE scope_key=? AND management_identity_hash=?", key, decode(facts.IdentityHash))
	mustSQL(t, err)
	if err := g.Recheck(ctx, recoveryManagerProbeTx{tx}, facts, RecoveryManagerWriteFence, now); err != ErrDenied {
		t.Fatalf("permission drift granted: %v", err)
	}
	mustSQL(t, tx.Rollback())
	var version int64
	mustSQL(t, db.QueryRowContext(ctx, "SELECT row_version FROM system_backup_v2_recovery_managers WHERE scope_key=? AND management_identity_hash=?", key, decode(facts.IdentityHash)).Scan(&version))
	if version != 1 {
		t.Fatalf("failed guard committed drift: version=%d", version)
	}
}
