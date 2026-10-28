//go:build systembackup_mysql

package systembackupevidence

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// TestDRecoveryAuthoritySchemaMySQL validates only the proposed physical
// authority tables. It does not authenticate a manager or enable recovery.
func TestDRecoveryAuthoritySchemaMySQL(t *testing.T) {
	db, _ := dProducerMySQLDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	key := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
	until := time.Now().UTC().Add(time.Minute)
	const installation = "recovery-schema-test-installation"
	const insertDeployment = `INSERT INTO system_backup_v2_recovery_deployments
(scope_key,origin_installation_id,workload_identity_hash,issuer_identity_hash,subject_hash,management_issuer_identity_hash,actor_identity_hash,admission_hash,client_ca_sha256,certificate_sha256,stat_profile_hash,enabled,deployment_epoch,authorized_until,row_version)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
	deployment := func(origin string, scope []byte, epoch, version int64) error {
		_, err := db.ExecContext(ctx, insertDeployment, scope, origin, key(1), key(2), key(16), key(3), key(4), key(5), key(6), key(7), key(8), true, epoch, until, version)
		return err
	}
	if err := deployment("missing-installation", key(9), 1, 1); err == nil {
		t.Fatal("deployment accepted without L0 installation parent")
	}
	_, err := db.ExecContext(ctx, `INSERT INTO system_backup_v2_installation_state
(origin_installation_id,active_config_version,last_effective_enabled_transition_at,matrix_key)
VALUES (?,1,UTC_TIMESTAMP(6),'k8s-cluster')`, installation)
	mustSQL(t, err)
	if err = deployment(installation, key(9), 1, 1); err != nil {
		t.Fatal("valid deployment rejected", err)
	}
	if err = deployment(installation, key(9), 1, 1); err == nil {
		t.Fatal("duplicate deployment scope accepted")
	}
	if err = deployment(installation, key(10), 0, 1); err == nil {
		t.Fatal("zero deployment epoch accepted")
	}
	if err = deployment(installation, key(10), 1, 0); err == nil {
		t.Fatal("zero deployment row version accepted")
	}
	const insertManager = `INSERT INTO system_backup_v2_recovery_managers
(scope_key,management_identity_hash,origin_installation_id,issuer_identity_hash,credential_binding_hash,can_read_fence,can_write_fence,can_manage_deployment,enabled,authorized_until,revoked_at,row_version)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`
	manager := func(origin string, identity byte, revoked any, version int64) error {
		_, err := db.ExecContext(ctx, insertManager, key(9), key(identity), origin, key(12), key(13), true, true, true, true, until, revoked, version)
		return err
	}
	if err = manager("missing-installation", 11, nil, 1); err == nil {
		t.Fatal("manager accepted without L0 installation parent")
	}
	if err = manager(installation, 11, nil, 1); err != nil {
		t.Fatal("valid manager rejected", err)
	}
	if err = manager(installation, 11, nil, 1); err == nil {
		t.Fatal("duplicate manager identity accepted")
	}
	if err = manager(installation, 14, time.Now().UTC().Truncate(time.Microsecond), 1); err == nil {
		t.Fatal("enabled revoked manager accepted")
	}
	if err = manager(installation, 15, nil, 0); err == nil {
		t.Fatal("zero manager row version accepted")
	}
	for _, table := range []string{"system_backup_v2_recovery_deployments", "system_backup_v2_recovery_managers"} {
		var count int
		mustSQL(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&count))
		if count != 1 {
			t.Fatalf("%s committed rows=%d, want 1", table, count)
		}
	}
}
