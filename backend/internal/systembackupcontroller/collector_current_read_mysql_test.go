package systembackupcontroller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	app "clawreef/internal/systembackup"
	d "clawreef/internal/systembackupdispatch"
	"github.com/go-sql-driver/mysql"
)

// DATA-only comparison of the three existing reads and their single-statement
// replacement. Temporary tables and this privileged fixture cannot authorize a
// collector. Production still calls the complete Authority.Check first.
func TestCollectorCurrentReadMatchesOriginalSQL(t *testing.T) {
	path := os.Getenv("TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS")
	if path == "" {
		t.Skip("requires original A's task-owned SAN/TLS MySQL")
	}
	var credential struct {
		Host, User, Password, CAFile, TLSServerName, ServerUUID string
		Port                                                    int
	}
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &credential) != nil || credential.Host != "127.0.0.1" || credential.Port != 63507 || credential.ServerUUID != "f3756194-d52b-11f1-b8cc-745d22085e06" {
		t.Fatal("wrong owned SQL fixture identity")
	}
	clear(raw)
	pem, err := os.ReadFile(credential.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("owned CA")
	}
	tlsName := fmt.Sprintf("collector-read-%d", time.Now().UnixNano())
	if err := mysql.RegisterTLSConfig(tlsName, &tls.Config{RootCAs: roots, ServerName: credential.TLSServerName, MinVersion: tls.VersionTLS13}); err != nil {
		t.Fatal(err)
	}
	defer mysql.DeregisterTLSConfig(tlsName)
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd, cfg.Net, cfg.Addr, cfg.DBName = credential.User, credential.Password, "tcp", "127.0.0.1:63507", "mysql"
	cfg.TLSConfig, cfg.InterpolateParams = tlsName, true
	cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = 5*time.Second, 10*time.Second, 10*time.Second
	credential.Password = ""
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var server string
	if db.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&server) != nil || server != credential.ServerUUID {
		t.Fatal("owned server UUID")
	}
	for _, query := range []string{
		`CREATE TEMPORARY TABLE system_backup_v2_runtime_captures(task_public_id VARCHAR(80) PRIMARY KEY,application_scope VARCHAR(80),gate_generation BIGINT UNSIGNED,acquire_token BIGINT UNSIGNED,held_token BIGINT NULL) ENGINE=InnoDB`,
		`CREATE TEMPORARY TABLE system_backup_gate(scope VARCHAR(80) PRIMARY KEY,owner VARCHAR(80),phase VARCHAR(20),generation BIGINT UNSIGNED,fencing_token BIGINT UNSIGNED,hold_deadline DATETIME(6) NULL) ENGINE=InnoDB`,
		`CREATE TEMPORARY TABLE system_backup_participants(scope VARCHAR(80),generation BIGINT UNSIGNED,state VARCHAR(20),resume_result VARCHAR(20)) ENGINE=InnoDB`,
	} {
		if _, err := db.ExecContext(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	g := SQLCaptureGate{Authority: SQLExecutionAuthority{DB: db, ApplicationScope: "original-scope"}}
	a := d.Authority{TaskPublicID: "original-task", MaintenanceFencingToken: 7}
	reset := func() {
		t.Helper()
		for _, query := range []string{
			`DELETE FROM system_backup_participants`, `DELETE FROM system_backup_gate`, `DELETE FROM system_backup_v2_runtime_captures`,
			`INSERT INTO system_backup_v2_runtime_captures VALUES ('original-task','original-scope',7,20,21)`,
			`INSERT INTO system_backup_gate VALUES ('original-scope','original-task','held',7,21,UTC_TIMESTAMP(6)+INTERVAL 1 MINUTE)`,
			`INSERT INTO system_backup_participants VALUES ('original-scope',7,'paused','none')`,
		} {
			if _, err := db.ExecContext(ctx, query); err != nil {
				t.Fatal(err)
			}
		}
	}
	legacy := func() error {
		o, err := g.ownership(ctx, a)
		if err != nil {
			return err
		}
		return (app.Gate{DB: db}).ValidateCapture(ctx, o)
	}
	for _, tc := range []struct {
		name, mutation string
		allowed        bool
	}{
		{"held", "", true},
		{"lost-held-ack", `UPDATE system_backup_v2_runtime_captures SET held_token=NULL`, true},
		{"unadvanced-token", `UPDATE system_backup_v2_runtime_captures SET held_token=NULL,acquire_token=21`, true},
		{"foreign-scope", `UPDATE system_backup_v2_runtime_captures SET application_scope='foreign'`, false},
		{"missing-capture", `DELETE FROM system_backup_v2_runtime_captures`, false},
		{"missing-gate", `DELETE FROM system_backup_gate`, false},
		{"foreign-owner", `UPDATE system_backup_gate SET owner='foreign-task'`, false},
		{"null-owner", `UPDATE system_backup_gate SET owner=NULL`, false},
		{"capture-generation", `UPDATE system_backup_v2_runtime_captures SET gate_generation=8`, false},
		{"actual-generation", `UPDATE system_backup_gate SET generation=8`, false},
		{"token-advanced-twice", `UPDATE system_backup_gate SET fencing_token=22`, false},
		{"held-token-mismatch", `UPDATE system_backup_v2_runtime_captures SET held_token=20`, false},
		{"acquiring", `UPDATE system_backup_gate SET phase='acquiring'`, false},
		{"releasing", `UPDATE system_backup_gate SET phase='releasing'`, false},
		{"idle", `UPDATE system_backup_gate SET phase='idle'`, false},
		{"expired", `UPDATE system_backup_gate SET hold_deadline=UTC_TIMESTAMP(6)-INTERVAL 1 MICROSECOND`, false},
		{"null-deadline", `UPDATE system_backup_gate SET hold_deadline=NULL`, false},
		{"participant-generation", `UPDATE system_backup_participants SET generation=8`, false},
		{"participant-running", `UPDATE system_backup_participants SET state='running'`, false},
		{"participant-resumed", `UPDATE system_backup_participants SET resume_result='succeeded'`, false},
		{"additional-running-participant", `INSERT INTO system_backup_participants VALUES ('original-scope',7,'running','none')`, false},
		{"foreign-participant", `INSERT INTO system_backup_participants VALUES ('foreign',1,'running','succeeded')`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reset()
			if tc.mutation != "" {
				if _, err := db.ExecContext(ctx, tc.mutation); err != nil {
					t.Fatal(err)
				}
			}
			old, current := legacy(), g.validateCurrentCollectors(ctx, a)
			if (old == nil) != tc.allowed || (current == nil) != tc.allowed {
				t.Fatalf("legacy/new allowed=%v/%v want=%v", old == nil, current == nil, tc.allowed)
			}
		})
	}
	reset()
	// Alternate the order to reduce warm-up/order bias. These are read-path
	// costs only, excluding the unchanged Authority.Check and HTTP handling.
	for round := 0; round < 2; round++ {
		reads := []struct {
			name string
			run  func() error
		}{{"three-original-reads", legacy}, {"one-current-read", func() error { return g.validateCurrentCollectors(ctx, a) }}}
		if round == 1 {
			reads[0], reads[1] = reads[1], reads[0]
		}
		for _, read := range reads {
			started := time.Now()
			for i := 0; i < 409; i++ {
				if err := read.run(); err != nil {
					t.Fatal(err)
				}
			}
			t.Log("collector read-only transport DATA", read.name, "round", round, "calls", 409, "elapsed", time.Since(started))
		}
	}
}
