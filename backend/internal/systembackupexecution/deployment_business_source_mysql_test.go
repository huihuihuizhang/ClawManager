package systembackupexecution

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"clawreef/internal/systembackup/domain"
	"github.com/go-sql-driver/mysql"
)

// Actual local MySQL table ACL/session/RR/export checks. The deliberately
// minimal empty business schemas exercise scope admission, not original DDL,
// full business constraints, physical source consistency or TLS deployment.
func TestDeploymentFiniteBusinessSourceAndActualCaptureMySQL(t *testing.T) {
	path := os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS")
	if path == "" {
		t.Skip("requires disposable local MySQL")
	}
	var cred struct {
		Host           string
		Port           int
		User, Password string
	}
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &cred) != nil || cred.Host != "127.0.0.1" {
		t.Fatal("local source fixture credentials unavailable")
	}
	clear(raw)
	config := mysql.NewConfig()
	config.User, config.Passwd = cred.User, cred.Password
	cred.Password = ""
	config.Net = "tcp"
	config.Addr = cred.Host + ":" + strconv.Itoa(cred.Port)
	config.ParseTime = true
	admin, err := sql.Open("mysql", config.FormatDSN())
	config.Passwd = ""
	if err != nil {
		t.Fatal("local fixture admin unavailable")
	}
	defer admin.Close()
	var id [8]byte
	rand.Read(id[:])
	name := "ad_d_src_" + hex.EncodeToString(id[:])
	user := name
	var password [24]byte
	rand.Read(password[:])
	pass := hex.EncodeToString(password[:])
	clear(password[:])
	if _, err = admin.Exec("CREATE DATABASE `" + name + "`"); err != nil {
		t.Fatal("local source schema create failed")
	}
	defer admin.Exec("DROP DATABASE `" + name + "`")
	if _, err = admin.Exec("CREATE USER '" + user + "'@'127.0.0.1' IDENTIFIED BY '" + pass + "'"); err != nil {
		t.Fatal("local source account create failed")
	}
	defer admin.Exec("DROP USER '" + user + "'@'127.0.0.1'")
	for _, table := range domain.BusinessCaptureTables() {
		if _, err = admin.Exec("CREATE TABLE `" + name + "`.`" + table + "` (id BIGINT NOT NULL PRIMARY KEY) ENGINE=InnoDB"); err != nil {
			t.Fatal("local business scope table fixture failed")
		}
		if _, err = admin.Exec("GRANT SELECT ON `" + name + "`.`" + table + "` TO '" + user + "'@'127.0.0.1'"); err != nil {
			t.Fatal("local finite source grant failed")
		}
	}
	if _, err = admin.Exec("INSERT INTO `" + name + "`.users VALUES(1)"); err != nil {
		t.Fatal(err)
	}
	config.User, config.Passwd, config.DBName = user, pass, name
	pass = ""
	reader, err := sql.Open("mysql", config.FormatDSN())
	config.Passwd = ""
	if err != nil {
		t.Fatal("local source reader unavailable")
	}
	defer reader.Close()
	reader.SetMaxOpenConns(1)
	var uuid string
	if admin.QueryRow("SELECT @@server_uuid").Scan(&uuid) != nil {
		t.Fatal("source server identity unavailable")
	}
	s := DeploymentService{Config: DeploymentConfig{CaptureScope: "six-part", SourceUser: user, SourceDatabase: name, SourceServerUUID: uuid}, Source: reader}
	ctx := context.Background()
	check := func() error { return s.checkSourceIdentity(ctx, reader) }
	if err = check(); err != nil {
		t.Fatal("service finite source admission", err)
	}
	tx, err := reader.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.checkSourceIdentity(ctx, tx); err != nil {
		t.Fatal("same authenticated source RR", err)
	}
	tx.Rollback()
	checks := 0
	snapshot, err := domain.CaptureBusinessSourceGuarded(ctx, reader, domain.Limits{MaxRows: 1000, MaxBytes: 32 << 20}, name, uuid, func(context.Context) error { checks++; return nil })
	if err != nil || len(snapshot.Tables) != len(domain.BusinessCaptureTables()) || checks < 10 {
		t.Fatal("actual finite-source original shared export", err, len(snapshot.Tables), checks)
	}
	if _, err = reader.Exec("UPDATE users SET id=2 WHERE id=1"); err == nil {
		t.Fatal("source role could write business data")
	}
	for _, mode := range []string{"missing", "control", "write", "database-wildcard"} {
		t.Run(mode, func(t *testing.T) {
			var undo string
			switch mode {
			case "missing":
				_, err = admin.Exec("REVOKE SELECT ON `" + name + "`.skill_blobs FROM '" + user + "'@'127.0.0.1'")
				undo = "GRANT SELECT ON `" + name + "`.skill_blobs TO '" + user + "'@'127.0.0.1'"
			case "control":
				_, err = admin.Exec("CREATE TABLE `" + name + "`.system_backup_v2_configs (id BIGINT PRIMARY KEY)")
				if err == nil {
					_, err = admin.Exec("GRANT SELECT ON `" + name + "`.system_backup_v2_configs TO '" + user + "'@'127.0.0.1'")
				}
				undo = "REVOKE SELECT ON `" + name + "`.system_backup_v2_configs FROM '" + user + "'@'127.0.0.1'"
			case "write":
				_, err = admin.Exec("GRANT UPDATE ON `" + name + "`.users TO '" + user + "'@'127.0.0.1'")
				undo = "REVOKE UPDATE ON `" + name + "`.users FROM '" + user + "'@'127.0.0.1'"
			case "database-wildcard":
				_, err = admin.Exec("GRANT SELECT ON `" + name + "`.* TO '" + user + "'@'127.0.0.1'")
				undo = "REVOKE SELECT ON `" + name + "`.* FROM '" + user + "'@'127.0.0.1'"
			}
			if err != nil {
				t.Fatal("local ACL fault setup failed")
			}
			defer admin.Exec(undo)
			if check() == nil {
				t.Fatal("service accepted non-finite source authority")
			}
			bad, err := domain.CaptureBusinessSourceGuarded(ctx, reader, domain.Limits{MaxRows: 1000, MaxBytes: 32 << 20}, name, uuid, func(context.Context) error { return nil })
			if err == nil || len(bad.Tables) != 0 {
				t.Fatal("worker accepted non-finite source authority", err)
			}
		})
	}
	checks = 0
	bad, err := domain.CaptureBusinessSourceGuarded(ctx, reader, domain.Limits{MaxRows: 1000, MaxBytes: 32 << 20}, name, uuid, func(context.Context) error {
		checks++
		if checks == 10 {
			_, e := admin.Exec("REVOKE SELECT ON `" + name + "`.users FROM '" + user + "'@'127.0.0.1'")
			if e != nil {
				t.Fatal("mid-RR source revocation failed")
			}
		}
		return nil
	})
	if err == nil || len(bad.Tables) != 0 || checks < 10 {
		t.Fatal("revoked original role returned usable source rows", err)
	}
}
