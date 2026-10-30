package systembackupapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	shared "clawreef/internal/systembackup"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	read "clawreef/internal/systembackupread"
	"github.com/go-sql-driver/mysql"
)

// Real MySQL and signed, independently scoped recovery identity. This test
// exercises untouched settlement, not a Runtime stop/resume or publication.
func sourceWaitFixture(t *testing.T) (*sql.DB, c.SQLCaptureGate, d.Authority) {
	t.Helper()
	db, writer := submissionMySQL(t)
	ctx := context.Background()
	p, err := writer.Prepare(ctx, read.BackupTask, "createSystemBackup", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	_, err = p.Stage(realSubmissionSQL{ctx, tx, false}, TaskSubmissionIdentity{"installation_admission", "1", "createSystemBackup", "source-wait-original-001"})
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = (shared.Gate{DB: db}).EnsureScope(ctx, "installation"); err != nil {
		t.Fatal(err)
	}
	if err = (c.SQLGateInitializer{DB: db}).Ensure(ctx, "installation_admission", c.GatePolicy{LockTTL: 900 * time.Second, AcquisitionTimeout: 60 * time.Second, MaxHold: 600 * time.Second}); err != nil {
		t.Fatal(err)
	}
	q := c.SQLExecutionQueue{DB: db, InstallationID: "installation_admission", Owner: "wait-controller", Policy: c.LeasePolicy{TTL: 300 * time.Second, HeartbeatInterval: 10 * time.Second, ReconcileInterval: time.Second}}
	claimed, err := q.TakeBackup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("INSERT INTO system_backup_v2_attempts(target_type,target_public_id,attempt_no,phase,status) VALUES('backup',?,1,'capture','preparing')", claimed.Claim.Target.PublicID); err != nil {
		t.Fatal(err)
	}
	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	in, err := claimed.ExecutionInput(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	tx.Rollback()
	var account, server, database string
	if err = db.QueryRow("SELECT CURRENT_USER(),@@server_uuid,DATABASE()").Scan(&account, &server, &database); err != nil {
		t.Fatal(err)
	}
	user := "wait_" + strings.ReplaceAll(in.Authority.TaskPublicID[4:16], "-", "")
	if _, err = db.Exec("CREATE USER '" + user + "'@'%' IDENTIFIED BY 'local-wait-test-only'"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Exec("DROP USER '" + user + "'@'%'") })
	// Test-schema isolation, not evidence of production least-privilege grants.
	if _, err = db.Exec("GRANT ALL ON `" + database + "`.* TO '" + user + "'@'%'"); err != nil {
		t.Fatal(err)
	}
	config := mysql.Config{User: user, Passwd: "local-wait-test-only", Net: "tcp", Addr: "127.0.0.1:" + os.Getenv("TEST_SYSTEM_BACKUP_MYSQL_PORT"), DBName: database, ParseTime: true, AllowNativePasswords: true}
	controlDB, err := sql.Open("mysql", config.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { controlDB.Close() })
	account = user + "@%"
	dir := t.TempDir()
	key := make([]byte, 32)
	rand.Read(key)
	if err = os.WriteFile(filepath.Join(dir, "record-v1"), key, 0600); err != nil {
		t.Fatal(err)
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	grant := c.ExecutionGrant{Version: "system-backup-execution-grant.v1", InstallationID: in.Authority.InstallationID, ControllerOwner: in.Authority.ClaimOwner, DatabaseAccount: account, ServerUUID: server, Database: database, ConfigVersion: in.Authority.ConfigVersion, ConfigSHA256: in.Authority.ConfigSHA256, ProfileSHA256: writer.hash, NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Actions: []string{"recover"}, RecordKeys: []c.ExecutionRecordKey{{Ref: "record-v1", SHA256: digestJSON(key)}}}
	payload, _ := json.Marshal(grant)
	envelope, _ := json.Marshal(map[string]string{"payload_base64": base64.StdEncoding.EncodeToString(payload), "signature_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload))})
	path := filepath.Join(dir, "recovery.json")
	if err = os.WriteFile(path, envelope, 0600); err != nil {
		t.Fatal(err)
	}
	identity, err := c.NewPinnedExecutionIdentity(path, digestJSON(envelope), dir, pub)
	if err != nil {
		t.Fatal(err)
	}
	g := c.SQLCaptureGate{Authority: c.SQLExecutionAuthority{DB: controlDB, InstallationID: in.Authority.InstallationID, ApplicationScope: "installation"}, Recovery: c.SQLRecoveryAuthority{DB: controlDB, InstallationID: in.Authority.InstallationID, ApplicationScope: "installation", Identity: identity}, AcquisitionTimeout: 10 * time.Second, HoldTimeout: time.Minute}
	return db, g, in.Authority
}

func TestUntouchedSettlementPreservesForeignSourceGate(t *testing.T) {
	db, g, a := sourceWaitFixture(t)
	ctx := context.Background()
	// A different task's persisted physical protection; do not acquire/release it
	// using the current task or infer exit from its elapsed deadlines.
	if _, err := db.Exec("UPDATE system_backup_gate SET phase='releasing',owner='foreign-original',generation=7,fencing_token=9 WHERE scope='installation'"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE system_backup_gate_admissions SET owner='foreign-original',close_until=TIMESTAMPADD(SECOND,60,UTC_TIMESTAMP(6)) WHERE scope='installation'"); err != nil {
		t.Fatal(err)
	}
	waiting, err := g.WaitForSource(ctx, a)
	if err != nil || !waiting {
		t.Fatal("foreign gate not observed", waiting, err)
	}
	var start, repeat time.Time
	if err = db.QueryRow("SELECT source_gate_wait_started_at FROM system_backup_v2_backups WHERE public_id=?", a.TaskPublicID).Scan(&start); err != nil {
		t.Fatal(err)
	}
	if _, err = g.WaitForSource(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow("SELECT source_gate_wait_started_at FROM system_backup_v2_backups WHERE public_id=?", a.TaskPublicID).Scan(&repeat); err != nil || !start.Equal(repeat) {
		t.Fatal("wait restarted", start, repeat, err)
	}
	stale := a
	stale.ClaimRowVersion++
	if _, err = g.WaitForSource(ctx, stale); err == nil {
		t.Fatal("stale controller changed wait")
	}
	// A dispatched resource defeats untouched settlement even while a foreign
	// gate is held. The synthetic row is test-owned and is removed only here.
	if _, err = db.Exec(`INSERT INTO system_backup_v2_runtime_resources(task_public_id,resource_kind,namespace_name,resource_name,resource_owner,request_sha256,request_json,row_version,create_dispatched) VALUES(?,'Job','test','original','wait-controller',?,'{}',1,TRUE)`, a.TaskPublicID, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err = g.FailUntouched(ctx, a); !errors.Is(err, c.ErrExecutionRecoveryRequired) {
		t.Fatal("dispatched work ignored", err)
	}
	if _, err = g.WaitForSource(ctx, a); !errors.Is(err, c.ErrExecutionRecoveryRequired) {
		t.Fatal("wait accepted dispatched work", err)
	}
	if _, err = db.Exec("DELETE FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_name='original'", a.TaskPublicID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("UPDATE system_backup_gate SET owner=? WHERE scope='installation'", a.TaskPublicID); err != nil {
		t.Fatal(err)
	}
	if err = g.FailUntouched(ctx, a); !errors.Is(err, c.ErrExecutionRecoveryRequired) {
		t.Fatal("own unresolved gate settled", err)
	}
	if _, err = db.Exec("UPDATE system_backup_gate SET owner='foreign-original' WHERE scope='installation'"); err != nil {
		t.Fatal(err)
	}
	// Use SQL time to advance the task-owned wait only; a foreign lease expiring
	// is never exit evidence and its protection must remain exactly unchanged.
	if _, err = db.Exec("UPDATE system_backup_v2_backups SET source_gate_wait_started_at=TIMESTAMPADD(SECOND,-601,UTC_TIMESTAMP(6)) WHERE public_id=?", a.TaskPublicID); err != nil {
		t.Fatal(err)
	}
	if _, err = g.WaitForSource(ctx, a); !errors.Is(err, c.ErrSourceGateWaitExpired) {
		t.Fatal("bounded wait did not settle", err)
	}
	var phase, owner, admission, status string
	if err := db.QueryRow("SELECT phase,owner FROM system_backup_gate WHERE scope='installation'").Scan(&phase, &owner); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT owner FROM system_backup_gate_admissions WHERE scope='installation'").Scan(&admission); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT status FROM system_backup_v2_backups WHERE public_id=?", a.TaskPublicID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if phase != "releasing" || owner != "foreign-original" || admission != "foreign-original" || status != "failed" {
		t.Fatalf("foreign gate changed: %s %s %s; own %s", phase, owner, admission, status)
	}
	var category string
	if err = db.QueryRow("SELECT failure_category FROM system_backup_v2_backups WHERE public_id=?", a.TaskPublicID).Scan(&category); err != nil || category != "quiesce_timeout" {
		t.Fatal("timeout category", category, err)
	}
}
