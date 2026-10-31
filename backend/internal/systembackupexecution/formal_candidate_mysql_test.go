package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	security "clawreef/internal/systembackupsecurity"
	"github.com/go-sql-driver/mysql"
)

// Opt-in, disposable LOCAL MySQL only. The private credential file/DSN is never
// logged. All schema work stays in a fresh ad_d_ database, removed on return.
func TestFormalCandidateMySQLMigrationAndTransactionalReplay(t *testing.T) {
	file := os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS")
	if file == "" {
		t.Skip("requires disposable local MySQL credential file")
	}
	var credentials struct {
		Host           string
		Port           int
		User, Password string
	}
	raw, err := os.ReadFile(file)
	if err != nil || json.Unmarshal(raw, &credentials) != nil || credentials.Host != "127.0.0.1" || credentials.Port < 1024 || credentials.User == "" || credentials.Password == "" {
		t.Fatal("local fixture credentials unavailable")
	}
	clear(raw)
	cfg := mysql.NewConfig()
	cfg.User = credentials.User
	cfg.Passwd = credentials.Password
	cfg.Net = "tcp"
	cfg.Addr = credentials.Host + ":" + fmtPort(credentials.Port)
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 10 * time.Second
	cfg.WriteTimeout = 10 * time.Second
	cfg.Params = map[string]string{"time_zone": "'+00:00'"}
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal("local fixture connection unavailable")
	}
	defer admin.Close()
	var suffix [8]byte
	if _, err = rand.Read(suffix[:]); err != nil {
		t.Fatal("fixture identity unavailable")
	}
	database := "ad_d_candidate_" + hex.EncodeToString(suffix[:])
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err = admin.ExecContext(ctx, "CREATE DATABASE `"+database+"` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"); err != nil {
		t.Fatal("local fixture schema creation failed")
	}
	defer func() {
		if !strings.HasPrefix(database, "ad_d_candidate_") {
			t.Fatal("fixture cleanup escaped D schema")
		}
		if _, err := admin.ExecContext(context.Background(), "DROP DATABASE `"+database+"`"); err != nil {
			t.Error("D fixture schema cleanup failed")
		}
	}()
	cfg.DBName = database
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal("local fixture database unavailable")
	}
	defer db.Close()
	db.SetMaxOpenConns(4)
	for _, statement := range []string{
		"CREATE TABLE system_backup_v2_backups(public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY) ENGINE=InnoDB",
		"CREATE TABLE system_backup_v2_attempts(target_type ENUM('backup') NOT NULL,target_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,attempt_no INT UNSIGNED NOT NULL,phase ENUM('capture') NOT NULL,PRIMARY KEY(target_type,target_public_id,attempt_no,phase)) ENGINE=InnoDB",
		"CREATE TABLE system_backup_v2_configs(origin_installation_id VARCHAR(128) PRIMARY KEY,version BIGINT UNSIGNED NOT NULL,control_metadata_capacity_bytes BIGINT NOT NULL) ENGINE=InnoDB",
		"CREATE TABLE system_backup_v2_metadata_reservations(id BIGINT PRIMARY KEY,sample_at DATETIME(6) NOT NULL,reserved_bytes BIGINT NOT NULL) ENGINE=InnoDB",
	} {
		if _, err = db.ExecContext(ctx, statement); err != nil {
			t.Fatal("local fixture base table failed", err)
		}
	}
	base, err := os.ReadFile(filepath.Join("..", "db", "migrations", "123_backup_v2_runtime_execution_journal.sql"))
	if err != nil {
		t.Fatal(err)
	}
	// Execute the actual original resource-table DDL with its FKs/CHECKs.
	resourceDDL := strings.Split(string(base), "CREATE TABLE IF NOT EXISTS system_backup_v2_runtime_captures")[0]
	if _, err = db.ExecContext(ctx, resourceDDL); err != nil {
		t.Fatal("original runtime resource migration failed", err)
	}
	for _, name := range []string{"125_backup_v2_job_key_use.sql", "131_backup_v2_formal_job_candidates.sql"} {
		ddl, err := os.ReadFile(filepath.Join("..", "db", "migrations", name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.ExecContext(ctx, string(ddl)); err != nil {
			t.Fatal("candidate additive migration failed", name, err)
		}
	}
	a, j, _ := resultEvidenceFixture()
	if _, err = db.ExecContext(ctx, "INSERT INTO system_backup_v2_backups(public_id) VALUES(?)", a.TaskPublicID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, "INSERT INTO system_backup_v2_attempts VALUES('backup',?,?,'capture')", a.TaskPublicID, a.AttemptNo); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, "INSERT INTO system_backup_v2_configs VALUES(?,?,?)", a.InstallationID, a.ConfigVersion, 1<<30); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO system_backup_v2_runtime_resources(task_public_id,resource_kind,namespace_name,resource_name,resource_owner,request_sha256,request_json,row_version,create_dispatched,observed_uid,resource_version,lifecycle,attempt_no,phase,key_use_json) VALUES(?,'Job',?,?,'fixture',?,'{}',1,TRUE,?,'1','ready',?,'capture','{"State":"finished"}')`, a.TaskPublicID, j.Namespace, j.Name, strings.Repeat("a", 64), j.UID, a.AttemptNo); err != nil {
		t.Fatal("original Job fixture failed", err)
	}
	owner := &PublicJobOwner{}
	owner.Gate.Records.CapacityReportFile = filepath.Join(t.TempDir(), "capacity.json")
	var server string
	var now time.Time
	if db.QueryRowContext(ctx, "SELECT @@server_uuid,UTC_TIMESTAMP(6)").Scan(&server, &now) != nil {
		t.Fatal("local DB identity unavailable")
	}
	report := security.CapacityReport{ServerUUID: server, Database: database, ObservedAt: now, AvailableBytes: 4 << 30}
	encoded, _ := json.Marshal(report)
	if err = os.WriteFile(owner.Gate.Records.CapacityReportFile, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("d", 64)
	// Two actual InnoDB transactions race with distinct random sealing bytes.
	// Both represent the SAME immutable report; only the original winner stays.
	start := make(chan struct{})
	failures := make(chan error, 2)
	var wg sync.WaitGroup
	for _, cipher := range [][]byte{bytes.Repeat([]byte{7}, 9000), bytes.Repeat([]byte{8}, 9000)} {
		wg.Add(1)
		go func(cipher []byte) {
			defer wg.Done()
			<-start
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				failures <- err
				return
			}
			defer tx.Rollback()
			if err = owner.saveFormalCandidateTx(ctx, tx, a, j, "key-original", digest, cipher); err != nil {
				failures <- err
				return
			}
			failures <- tx.Commit()
		}(cipher)
	}
	close(start)
	wg.Wait()
	close(failures)
	for err = range failures {
		if err != nil {
			t.Fatal("transactional candidate replay failed", err)
		}
	}
	var stored []byte
	var count int64
	if db.QueryRowContext(ctx, "SELECT candidate_cipher FROM system_backup_v2_runtime_resources WHERE task_public_id=?", a.TaskPublicID).Scan(&stored) != nil || len(stored) != 9000 {
		t.Fatal("candidate ciphertext not retained")
	}
	if db.QueryRowContext(ctx, "SELECT reserved_bytes FROM system_backup_v2_metadata_reservations WHERE id=1").Scan(&count) != nil || count != 9000*2+65536 {
		t.Fatal("candidate reservation repeated or underbudgeted", count)
	}
	// An ACK can be lost after COMMIT; another transaction must read/replay,
	// preserve the old random ciphertext and reserve no extra capacity.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = owner.saveFormalCandidateTx(ctx, tx, a, j, "key-new-randomness", digest, bytes.Repeat([]byte{9}, 10000)); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var after []byte
	var afterCount int64
	if db.QueryRowContext(ctx, "SELECT candidate_cipher FROM system_backup_v2_runtime_resources WHERE task_public_id=?", a.TaskPublicID).Scan(&after) != nil || !bytes.Equal(stored, after) {
		t.Fatal("ACK retry overwrote original candidate")
	}
	if db.QueryRowContext(ctx, "SELECT reserved_bytes FROM system_backup_v2_metadata_reservations WHERE id=1").Scan(&afterCount) != nil || afterCount != count {
		t.Fatal("ACK retry reserved again")
	}
	for _, fault := range []string{"different-report", "wrong-attempt", "revoked"} {
		changed := a
		value := digest
		if fault == "different-report" {
			value = strings.Repeat("e", 64)
		}
		if fault == "wrong-attempt" {
			changed.AttemptNo++
		}
		if fault == "revoked" {
			if _, err = db.ExecContext(ctx, "UPDATE system_backup_v2_runtime_resources SET revoked=TRUE WHERE task_public_id=?", a.TaskPublicID); err != nil {
				t.Fatal(err)
			}
		}
		tx, err = db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		err = owner.saveFormalCandidateTx(ctx, tx, changed, j, "key-original", value, []byte("new-cipher"))
		tx.Rollback()
		if err == nil {
			t.Fatal("unsafe replay accepted", fault)
		}
	}
	for _, update := range []string{"candidate_key_ref=''", "candidate_cipher=NULL", "candidate_sha256='bad'", "candidate_cipher=REPEAT('x',32769)", "resource_kind='ConfigMap'"} {
		if _, err = db.ExecContext(ctx, "UPDATE system_backup_v2_runtime_resources SET "+update+" WHERE task_public_id=?", a.TaskPublicID); err == nil {
			t.Fatal("MySQL candidate CHECK accepted inconsistent row", update)
		}
	}
}

func fmtPort(port int) string { return strconv.Itoa(port) }
