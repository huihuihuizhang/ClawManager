package systembackupexecution

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	"github.com/go-sql-driver/mysql"
)

// This owner is deliberately inert DATA. The test proves real InnoDB lock
// mechanics and actual Bind SQL, not real deployment/A source authorization.
type originalLockDataAuthorization struct{ until time.Time }

func (v originalLockDataAuthorization) AuthorizeExecution(context.Context, *sql.Tx, d.Authority, time.Time) (c.ExecutionAuthorizationGuard, error) {
	return v, nil
}
func (v originalLockDataAuthorization) RecheckExecution(context.Context, *sql.Tx, d.Authority, time.Time) error {
	return nil
}
func (v originalLockDataAuthorization) ValidUntil() time.Time { return v.until }

func originalLockMySQLData(t *testing.T) (*sql.DB, *sql.DB, string, c.SQLExecutionAuthority, d.Authority) {
	t.Helper()
	file, pin := os.Getenv("D_GATE_TASK_MYSQL_CREDENTIALS"), os.Getenv("D_GATE_TASK_MYSQL_SERVER_UUID")
	if file == "" {
		t.Skip("requires separately owned UUID-pinned loopback lock-order MySQL")
	}
	var credentials struct {
		Host, User, Password string
		Port                 int
	}
	raw, err := os.ReadFile(file)
	if err != nil || len(raw) > 4096 || json.Unmarshal(raw, &credentials) != nil || credentials.Host != "127.0.0.1" || pin == "" {
		clear(raw)
		t.Fatal("invalid local lock-order fixture inputs")
	}
	clear(raw)
	cfg := mysql.NewConfig()
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(credentials.Host, strconv.Itoa(credentials.Port))
	cfg.User = credentials.User
	cfg.Passwd = credentials.Password
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.MultiStatements = true
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 10 * time.Second
	cfg.WriteTimeout = 10 * time.Second
	cfg.Params = map[string]string{"time_zone": "'+00:00'", "innodb_lock_wait_timeout": "5"}
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal("local fixture open failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var uuid string
	var detects int
	if admin.QueryRowContext(ctx, "SELECT @@server_uuid,@@innodb_deadlock_detect").Scan(&uuid, &detects) != nil || uuid != pin || detects != 1 {
		admin.Close()
		t.Fatal("local fixture UUID or deadlock-detection precondition failed")
	}
	var entropy [12]byte
	if _, err = rand.Read(entropy[:]); err != nil {
		t.Fatal("fixture entropy failed")
	}
	schema := "ad_d_lock_" + hex.EncodeToString(entropy[:])
	if _, err = admin.ExecContext(ctx, "CREATE DATABASE `"+schema+"`"); err != nil {
		admin.Close()
		t.Fatal("fresh lock DATA schema creation failed")
	}
	cfg.DBName = schema
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal("fresh fixture connection failed")
	}
	db.SetMaxOpenConns(6)
	t.Cleanup(func() {
		db.Close()
		clean, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := admin.ExecContext(clean, "DROP DATABASE `"+schema+"`"); err != nil {
			t.Error("fresh lock DATA cleanup failed")
		}
		admin.Close()
	})
	ddl := `CREATE TABLE system_backup_v2_maintenance_locks(origin_installation_id VARCHAR(128),scope VARCHAR(128),lock_name VARCHAR(128),gate_state VARCHAR(32),lock_owner VARCHAR(128),fencing_token BIGINT UNSIGNED,row_version BIGINT UNSIGNED,lease_expires_at DATETIME(6),absolute_hold_deadline_at DATETIME(6),PRIMARY KEY(origin_installation_id,scope,lock_name)) ENGINE=InnoDB;
CREATE TABLE system_backup_v2_installation_state(origin_installation_id VARCHAR(128) PRIMARY KEY,schema_version VARCHAR(128),row_version BIGINT UNSIGNED,active_config_version BIGINT UNSIGNED) ENGINE=InnoDB;
CREATE TABLE system_backup_v2_configs(origin_installation_id VARCHAR(128),version BIGINT UNSIGNED,schema_version VARCHAR(128),enabled BOOLEAN,canonical_config_json LONGTEXT,config_sha256 CHAR(64),config_size_bytes BIGINT UNSIGNED,PRIMARY KEY(origin_installation_id,version)) ENGINE=InnoDB;
CREATE TABLE system_backup_v2_backups(public_id VARCHAR(128) PRIMARY KEY,schema_version VARCHAR(128),origin_installation_id VARCHAR(128),task_type VARCHAR(32),request_id VARCHAR(128),status VARCHAR(32),controller_owner VARCHAR(128),row_version BIGINT UNSIGNED,controller_lease_expires_at DATETIME(6),deadline_at DATETIME(6),config_version BIGINT UNSIGNED,config_snapshot_json LONGTEXT,config_snapshot_size_bytes BIGINT UNSIGNED,config_snapshot_sha256 CHAR(64),maintenance_lock_owner VARCHAR(128),maintenance_fencing_token BIGINT UNSIGNED) ENGINE=InnoDB;
CREATE TABLE system_backup_v2_attempts(target_type VARCHAR(32),target_public_id VARCHAR(128),attempt_no BIGINT UNSIGNED,phase VARCHAR(32),status VARCHAR(32),row_version BIGINT UNSIGNED,PRIMARY KEY(target_type,target_public_id,phase,attempt_no)) ENGINE=InnoDB;`
	if _, err = db.ExecContext(ctx, ddl); err != nil {
		t.Fatal("fresh lock DATA tables failed")
	}
	var now time.Time
	if db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil {
		t.Fatal("SQL clock unavailable")
	}
	config := []byte(`{"fixture":"original lock metadata DATA"}`)
	a := d.Authority{InstallationID: "installation_lock_data", TaskPublicID: "sbk_01234567-89ab-cdef-0123-456789abcdef", TaskType: "backup", Phase: "capture", RequestID: "lock-data-request", ClaimOwner: "lock-data-controller", ClaimRowVersion: 1, ConfigVersion: 1, ConfigSHA256: hash(config), AttemptNo: 1, DeadlineAt: now.Add(time.Minute), MaintenanceOwner: "lock-data-capture", MaintenanceFencingToken: 1}
	statements := []struct {
		q    string
		args []any
	}{
		{"INSERT INTO system_backup_v2_maintenance_locks VALUES(?,?,?,?,?,?,?,?,?)", []any{a.InstallationID, c.CaptureGateScope, "system_backup_capture_gate", "held", a.MaintenanceOwner, 1, 1, now.Add(time.Minute), now.Add(time.Minute)}},
		{"INSERT INTO system_backup_v2_installation_state VALUES(?,?,?,?)", []any{a.InstallationID, "system-backup-installation-state.v1", 1, 1}},
		{"INSERT INTO system_backup_v2_configs VALUES(?,?,?,?,?,?,?)", []any{a.InstallationID, 1, "system-backup-config.v1", true, config, a.ConfigSHA256, len(config)}},
		{"INSERT INTO system_backup_v2_backups VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", []any{a.TaskPublicID, "system-backup-task.v1", a.InstallationID, "backup", a.RequestID, "capturing", a.ClaimOwner, 1, now.Add(time.Minute), a.DeadlineAt, 1, config, len(config), a.ConfigSHA256, a.MaintenanceOwner, 1}},
		{"INSERT INTO system_backup_v2_attempts VALUES(?,?,?,?,?,?)", []any{"backup", a.TaskPublicID, 1, "capture", "running", 1}},
	}
	for _, statement := range statements {
		if _, err = db.ExecContext(ctx, statement.q, statement.args...); err != nil {
			t.Fatal("fresh lock DATA rows failed")
		}
	}
	store := c.SQLExecutionAuthority{DB: db, InstallationID: a.InstallationID, DeploymentEnabled: true, Authorization: originalLockDataAuthorization{now.Add(time.Minute)}}
	return admin, db, schema, store, a
}

func originalWaitForNativeLock(t *testing.T, ctx context.Context, admin *sql.DB, schema, table string, connection uint64) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var count int
		err := admin.QueryRowContext(ctx, `SELECT COUNT(*) FROM performance_schema.data_lock_waits w JOIN performance_schema.data_locks l ON l.ENGINE_LOCK_ID=w.REQUESTING_ENGINE_LOCK_ID AND l.ENGINE=w.ENGINE JOIN performance_schema.threads t ON t.THREAD_ID=w.REQUESTING_THREAD_ID WHERE l.OBJECT_SCHEMA=? AND l.OBJECT_NAME=? AND t.PROCESSLIST_ID=?`, schema, table, connection).Scan(&count)
		if err != nil {
			t.Fatal("real lock barrier introspection unavailable")
		}
		if count > 0 {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal("expected actual native lock wait not observed")
		}
	}
}

func TestOriginalCaptureAuthorityLookupNativeLockOrderMySQL(t *testing.T) {
	admin, db, schema, store, a := originalLockMySQLData(t)
	for _, inverted := range []bool{true, false} {
		name := "unified-gate-before-task"
		if inverted {
			name = "old-task-before-gate-deadlock"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			source, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if err != nil {
				t.Fatal("source TX unavailable")
			}
			defer source.Rollback()
			heartbeat, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if err != nil {
				t.Fatal("heartbeat TX unavailable")
			}
			defer heartbeat.Rollback()
			var sourceID, heartbeatID uint64
			if source.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&sourceID) != nil || heartbeat.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&heartbeatID) != nil {
				t.Fatal("actual connection IDs unavailable")
			}
			located := a
			if inverted {
				err = source.QueryRowContext(ctx, originalCaptureAuthorityLookupSQL+" FOR SHARE", a.InstallationID, a.TaskPublicID).Scan(&located.ClaimOwner, &located.ClaimRowVersion, &located.RequestID, &located.ConfigVersion, &located.ConfigSHA256, &located.DeadlineAt, &located.MaintenanceFencingToken)
			} else {
				err = readOriginalCaptureAuthorityLookup(ctx, source, &located)
			}
			if err != nil || located.ClaimOwner != a.ClaimOwner || located.ClaimRowVersion != a.ClaimRowVersion || located.ConfigSHA256 != a.ConfigSHA256 {
				t.Fatal("original locator DATA read failed")
			}
			var ignored uint64
			if heartbeat.QueryRowContext(ctx, "SELECT row_version FROM system_backup_v2_maintenance_locks WHERE origin_installation_id=? AND scope=? AND lock_name='system_backup_capture_gate' FOR UPDATE", a.InstallationID, c.CaptureGateScope).Scan(&ignored) != nil {
				t.Fatal("heartbeat gate lock unavailable")
			}
			type bindResult struct {
				err         error
				diagnostics []c.ExecutionBindDiagnostic
			}
			bind := func() bindResult {
				var observed []c.ExecutionBindDiagnostic
				guard, err := store.BindObserved(ctx, source, located, func(v c.ExecutionBindDiagnostic) { observed = append(observed, v) })
				if err == nil {
					err = guard.Recheck(ctx, source)
				}
				source.Rollback()
				return bindResult{err, observed}
			}
			if inverted {
				taskResult := make(chan error, 1)
				go func() {
					var v uint64
					err := heartbeat.QueryRowContext(ctx, "SELECT row_version FROM system_backup_v2_backups WHERE public_id=? FOR UPDATE", a.TaskPublicID).Scan(&v)
					heartbeat.Rollback()
					taskResult <- err
				}()
				originalWaitForNativeLock(t, ctx, admin, schema, "system_backup_v2_backups", heartbeatID)
				result := bind()
				other := <-taskResult
				deadlock := false
				for _, v := range result.diagnostics {
					if v.Class() == "sql_deadlock" && v.SQLNumber() == 1213 {
						deadlock = true
						t.Log("actual Bind deadlock boundary", v.Stage(), "SQLSTATE", v.SQLState())
					}
				}
				var driver *mysql.MySQLError
				if errors.As(other, &driver) && driver.Number == 1213 {
					deadlock = true
					t.Log("actual heartbeat deadlock code", driver.Number)
				}
				if !deadlock {
					t.Fatal("old lock inversion did not produce actual 1213")
				}
			} else {
				if heartbeat.QueryRowContext(ctx, "SELECT row_version FROM system_backup_v2_backups WHERE public_id=? FOR UPDATE", a.TaskPublicID).Scan(&ignored) != nil {
					t.Fatal("plain source locator still locked task")
				}
				resultChannel := make(chan bindResult, 1)
				go func() { resultChannel <- bind() }()
				originalWaitForNativeLock(t, ctx, admin, schema, "system_backup_v2_maintenance_locks", sourceID)
				if err := heartbeat.Rollback(); err != nil {
					t.Fatal("heartbeat release failed")
				}
				result := <-resultChannel
				if result.err != nil || len(result.diagnostics) != 0 {
					t.Fatal("unified actual Bind/Recheck failed", result.diagnostics)
				}
				t.Log("real gate wait serialized; complete Bind and tail Recheck succeeded; no retries")
			}
		})
	}
	t.Run("plain-locator-cannot-adopt-new-current-task-version", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		source, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
		if err != nil {
			t.Fatal("source TX unavailable")
		}
		defer source.Rollback()
		located := a
		if readOriginalCaptureAuthorityLookup(ctx, source, &located) != nil {
			t.Fatal("plain original locator unavailable")
		}
		other, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
		if err != nil {
			t.Fatal("independent DATA mutation TX unavailable")
		}
		defer other.Rollback()
		result, err := other.ExecContext(ctx, "UPDATE system_backup_v2_backups SET row_version=row_version+1 WHERE public_id=? AND row_version=?", located.TaskPublicID, located.ClaimRowVersion)
		if err != nil {
			t.Fatal("independent DATA row version change blocked by locator")
		}
		changed, err := result.RowsAffected()
		if err != nil || changed != 1 {
			t.Fatal("independent DATA version change missing")
		}
		if other.Commit() != nil {
			t.Fatal("independent DATA version commit failed")
		}
		var observed []c.ExecutionBindDiagnostic
		guard, err := store.BindObserved(ctx, source, located, func(v c.ExecutionBindDiagnostic) { observed = append(observed, v) })
		if guard != nil || err != c.ErrExecutionAuthority || len(observed) != 1 || observed[0].Stage() != "bind-snapshot-task" || observed[0].Class() != "predicate" {
			t.Fatal("locking Bind adopted stale repeatable-read locator DATA", observed)
		}
		t.Log("actual current locking read rejected new task version after plain RR locator; DATA only, no claim authorization proof")
	})
}
