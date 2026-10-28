//go:build systembackup_mysql

package systembackupsecurity

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// Uses exact production config/state/operation CREATE TABLE statements in the
// pinned bundle. Admission is synthetic; this is not production activation.
func testConfigBootstrapMySQL(t *testing.T, ctx context.Context, admin *sql.DB, parent *mysql.Config, serverUUID string, ddl []byte) {
	var entropy [16]byte
	_, err := rand.Read(entropy[:])
	mysqlMust(t, err)
	database := "dbo_" + hex.EncodeToString(entropy[:])
	_, err = admin.ExecContext(ctx, "CREATE DATABASE "+database+" CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
	mysqlMust(t, err)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		var actual string
		if admin.QueryRowContext(cleanup, "SELECT @@server_uuid").Scan(&actual) != nil || actual != serverUUID {
			t.Error("CLEANUP_PENDING bootstrap server identity")
			return
		}
		if _, e := admin.ExecContext(cleanup, "DROP DATABASE "+database); e != nil {
			t.Error("CLEANUP_PENDING bootstrap run-owned database")
			return
		}
		var count int
		if admin.QueryRowContext(cleanup, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=?", database).Scan(&count) != nil || count != 0 {
			t.Error("CLEANUP_PENDING bootstrap database absence")
			return
		}
		t.Log("CLEANED bootstrap run-owned database")
	}()
	cfg := parent.Clone()
	cfg.DBName = database
	db, err := sql.Open("mysql", cfg.FormatDSN())
	mysqlMust(t, err)
	defer db.Close()
	_, err = db.ExecContext(ctx, `CREATE TABLE users(id INT PRIMARY KEY,username VARCHAR(128),role VARCHAR(16),is_active BOOLEAN,auth_provider VARCHAR(16)) ENGINE=InnoDB;
		CREATE TABLE audit_logs(id INT AUTO_INCREMENT PRIMARY KEY,user_id INT,action VARCHAR(100),resource_type VARCHAR(50),details JSON,FOREIGN KEY(user_id) REFERENCES users(id)) ENGINE=InnoDB;
		CREATE TABLE d_capacity_reservations(id BIGINT AUTO_INCREMENT PRIMARY KEY,bytes BIGINT) ENGINE=InnoDB;
		INSERT INTO users VALUES(42,'admin','admin',TRUE,'local');`)
	mysqlMust(t, err)
	_, err = db.ExecContext(ctx, string(ddl))
	mysqlMust(t, err)
	raw := bootstrapFixture(t)
	config, err := DecodeBootstrapConfig(raw)
	mysqlMust(t, err)
	g := OfflineBootstrapGrant{InstallationID: "installation_synthetic_bootstrap", ServerUUID: serverUUID, Database: database, Username: "admin", UserID: 42, MatrixKey: "k8s-cluster", ConfigSHA256: config.SHA256(), IdempotencyKey: "synthetic-bootstrap-mysql-001", ChangeReason: "isolated MySQL acceptance"}
	svc := ConfigBootstrapService{DB: db, Admission: mysqlBootstrapAdmission{}}
	counts := func(want int) {
		t.Helper()
		for _, table := range []string{"system_backup_v2_configs", "system_backup_v2_installation_state", "system_backup_v2_operations", "d_capacity_reservations", "audit_logs"} {
			var actual int
			mysqlMust(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&actual))
			expected := want
			if table == "audit_logs" {
				expected *= 2
			}
			if actual != expected {
				t.Fatalf("%s rows=%d expected=%d", table, actual, expected)
			}
		}
	}
	t.Run("result_audit_failure_rolls_back_config_state_and_reservation", func(t *testing.T) {
		_, e := db.ExecContext(ctx, `CREATE TRIGGER d_bootstrap_reject BEFORE INSERT ON audit_logs FOR EACH ROW BEGIN IF NEW.action='system_backup.config_bootstrap.result' THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic failure'; END IF; END`)
		mysqlMust(t, e)
		_, e = svc.Bootstrap(ctx, g, raw)
		if e != ErrProviderEvidenceStorage {
			t.Fatal("expected audit failure", e)
		}
		counts(0)
		_, e = db.ExecContext(ctx, "DROP TRIGGER d_bootstrap_reject")
		mysqlMust(t, e)
	})
	if t.Failed() {
		return
	}
	t.Run("concurrent_first_requests_commit_once", func(t *testing.T) {
		var wg sync.WaitGroup
		results := make(chan ConfigBootstrapResult, 4)
		failures := make(chan error, 4)
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for attempt := 0; attempt < 5; attempt++ {
					result, e := svc.Bootstrap(ctx, g, raw)
					if e == nil {
						results <- result
						return
					}
					if e != ErrProviderEvidenceStorage {
						failures <- e
						return
					}
					time.Sleep(20 * time.Millisecond)
				}
				failures <- ErrProviderEvidenceStorage
			}()
		}
		wg.Wait()
		close(results)
		close(failures)
		for e := range failures {
			t.Error(e)
		}
		created := 0
		op := ""
		received := 0
		for result := range results {
			received++
			if !result.Replayed {
				created++
			}
			if op == "" {
				op = result.OperationPublicID
			}
			if op != result.OperationPublicID {
				t.Error("duplicate operation")
			}
		}
		if created != 1 || received != 4 {
			t.Fatalf("created=%d received=%d", created, received)
		}
		counts(1)
	})
	if t.Failed() {
		return
	}
	var enabled bool
	var factor, hash string
	var size, version int64
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT enabled,source_size_safety_factor,config_sha256,config_size_bytes,version FROM system_backup_v2_configs").Scan(&enabled, &factor, &hash, &size, &version))
	if enabled || factor != "1.25" || hash != config.SHA256() || size != int64(len(config.CanonicalJSON())) || version != 1 {
		t.Fatal("persisted snapshot mismatch")
	}
	t.Run("wrong_database_conflict_reinitialization_and_revocation", func(t *testing.T) {
		wrong := g
		wrong.ServerUUID = "11111111-2222-3333-4444-555555555555"
		if _, e := svc.Bootstrap(ctx, wrong, raw); e != ErrRegistrationUnavailable {
			t.Fatal("wrong DB", e)
		}
		changed := g
		changed.ChangeReason = "changed reason"
		if _, e := svc.Bootstrap(ctx, changed, raw); e != ErrRegistrationConflict {
			t.Fatal("conflict", e)
		}
		changed = g
		changed.IdempotencyKey = "synthetic-bootstrap-mysql-002"
		if _, e := svc.Bootstrap(ctx, changed, raw); e != ErrBootstrapExists {
			t.Fatal("reinitialization", e)
		}
		_, e := db.ExecContext(ctx, "UPDATE users SET is_active=FALSE WHERE id=42")
		mysqlMust(t, e)
		if _, e = svc.Bootstrap(ctx, g, raw); e != ErrRegistrationPermission {
			t.Fatal("revocation", e)
		}
		counts(1)
	})
}

type mysqlBootstrapAdmission struct{}

func (mysqlBootstrapAdmission) Authorize(context.Context, *sql.Tx, OfflineBootstrapGrant, BootstrapConfig, time.Time) error {
	return nil
}
func (mysqlBootstrapAdmission) ValidateAndReserve(ctx context.Context, tx *sql.Tx, _ OfflineBootstrapGrant, c BootstrapConfig, _ time.Time) error {
	// Explicitly synthetic resolution; never used by the runtime constructor.
	if !strings.Contains(string(c.CanonicalJSON()), "synthetic-v1") {
		return ErrRegistrationUnavailable
	}
	_, err := tx.ExecContext(ctx, "INSERT INTO d_capacity_reservations(bytes) VALUES(?)", len(c.CanonicalJSON()))
	return err
}
