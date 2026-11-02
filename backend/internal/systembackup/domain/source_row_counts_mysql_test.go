package domain

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"testing"
	"time"

	mysql "github.com/go-sql-driver/mysql"
)

// Reuses only the reviewer's explicitly supplied disposable TLS instance.
// Own random schema/account are always cleaned, including on test failure.
// This proves query/RR/MDL semantics, not full public task authorization.
func TestSourceRowCountsMySQL(t *testing.T) {
	file := os.Getenv("TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS")
	if file == "" {
		t.Skip("requires reviewer-owned disposable SAN/TLS MySQL")
	}
	pin := os.Getenv("A_PERMIT_NATIVE_DISPOSABLE_SERVER_UUID")
	if !regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`).MatchString(pin) {
		t.Fatal("independent disposable server UUID pin required")
	}
	var credential struct {
		Host, User, Password, CAFile, TLSServerName, ServerUUID string
		Port                                                    int
	}
	input, err := os.Open(file)
	if err != nil {
		t.Fatal("disposable TLS credentials unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(input, 16385))
	closeErr := input.Close()
	defer clear(raw)
	if err != nil || closeErr != nil || len(raw) > 16384 || json.Unmarshal(raw, &credential) != nil || credential.Host != "127.0.0.1" || credential.Port < 1024 || credential.Port > 65535 || credential.Port == 3306 || credential.ServerUUID != pin || credential.User == "" || credential.Password == "" || credential.TLSServerName == "" || !filepath.IsAbs(credential.CAFile) {
		t.Fatal("disposable TLS credentials unavailable")
	}
	clear(raw)
	ca, err := os.ReadFile(credential.CAFile)
	if err != nil {
		t.Fatal("fixture CA unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("fixture CA invalid")
	}
	var entropy [16]byte
	if _, err = rand.Read(entropy[:]); err != nil {
		t.Fatal(err)
	}
	nonce := hex.EncodeToString(entropy[:])
	tlsName := "b-row-counts-" + nonce
	if err = mysql.RegisterTLSConfig(tlsName, &tls.Config{RootCAs: roots, ServerName: credential.TLSServerName, MinVersion: tls.VersionTLS13}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mysql.DeregisterTLSConfig(tlsName) })
	cfg := mysql.NewConfig()
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(credential.Host, strconv.Itoa(credential.Port))
	cfg.User = credential.User
	cfg.Passwd = credential.Password
	cfg.TLSConfig = tlsName
	cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = 5*time.Second, 15*time.Second, 15*time.Second
	cfg.Params = map[string]string{"time_zone": "'+00:00'"}
	cfg.Logger = &mysql.NopLogger{}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	open := func(c *mysql.Config) *sql.DB {
		t.Helper()
		db, e := sql.Open("mysql", c.FormatDSN())
		if e != nil {
			t.Fatal("fixture open failed")
		}
		t.Cleanup(func() { db.Close() })
		return db
	}
	admin := open(cfg)
	var uuid string
	if admin.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&uuid) != nil || uuid != credential.ServerUUID || uuid != pin {
		t.Fatal("fixture UUID mismatch")
	}
	name, user := "b_counts_"+nonce[:16], "b_counts_"+nonce[:16]
	exec := func(t *testing.T, db *sql.DB, q string) {
		t.Helper()
		if _, e := db.ExecContext(ctx, q); e != nil {
			t.Fatalf("owned fixture SQL failed: %T", e)
		}
	}
	exec(t, admin, "CREATE DATABASE `"+name+"`")
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, e := admin.ExecContext(c, "DROP DATABASE `"+name+"`"); e != nil {
			t.Error("owned count schema cleanup failed")
		}
	})
	adminCfg := cfg.Clone()
	adminCfg.DBName = name
	writer := open(adminCfg)
	for _, table := range []string{"users", "user_quotas", "instances"} {
		exec(t, writer, "CREATE TABLE `"+table+"`(id BIGINT UNSIGNED PRIMARY KEY,payload VARBINARY(100) NULL) ENGINE=InnoDB")
	}
	exec(t, writer, "INSERT INTO users VALUES(9007199254740993,0x00ff01)")
	exec(t, writer, "INSERT INTO user_quotas VALUES(2,NULL)")
	var passwordEntropy [24]byte
	if _, err = rand.Read(passwordEntropy[:]); err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(passwordEntropy[:])
	clear(passwordEntropy[:])
	exec(t, admin, "CREATE USER '"+user+"'@'127.0.0.1' IDENTIFIED BY '"+password+"'")
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, e := admin.ExecContext(c, "DROP USER '"+user+"'@'127.0.0.1'"); e != nil {
			t.Error("owned count user cleanup failed")
		}
	})
	for _, table := range []string{"users", "user_quotas", "instances"} {
		exec(t, admin, "GRANT SELECT ON `"+name+"`.`"+table+"` TO '"+user+"'@'127.0.0.1'")
	}
	readerCfg := adminCfg.Clone()
	readerCfg.User = user
	readerCfg.Passwd = password
	reader := open(readerCfg)
	if _, e := reader.ExecContext(ctx, "INSERT INTO instances VALUES(7,NULL)"); e == nil {
		t.Fatal("read identity could write")
	}
	limits := Limits{MaxRows: 100, MaxBytes: 1 << 20}
	t.Run("full-differential", func(t *testing.T) {
		old, e := captureWithCatalog(ctx, reader, limits, nil, catalogBusinessGuarded)
		if e != nil {
			t.Fatal(e)
		}
		got, e := captureWithCatalogMode(ctx, reader, limits, nil, catalogBusinessGuarded, true)
		if e != nil || !reflect.DeepEqual(old, got) {
			t.Fatal("native zero table/schema/raw values changed", e)
		}
	})
	t.Run("same-RR-exact-counts", func(t *testing.T) {
		tx, e := reader.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback()
		tables, e := catalogBusinessGuarded(ctx, tx, nil)
		if e != nil {
			t.Fatal(e)
		}
		counts, e := captureSourceRowCounts(ctx, tx, tables, nil)
		if e != nil || counts["instances"] != 0 || counts["users"] != 1 || counts["user_quotas"] != 1 {
			t.Fatal("native exact counts", e)
		}
		exec(t, writer, "INSERT INTO instances VALUES(3,0x00)")
		exec(t, writer, "UPDATE users SET payload=0x77")
		exec(t, writer, "DELETE FROM user_quotas")
		again, e := captureSourceRowCounts(ctx, tx, tables, nil)
		if e != nil || !reflect.DeepEqual(counts, again) {
			t.Fatal("count escaped RR", e)
		}
		var id string
		var payload []byte
		if tx.QueryRowContext(ctx, "SELECT id,payload FROM users").Scan(&id, &payload) != nil || id != "9007199254740993" || !reflect.DeepEqual(payload, []byte{0, 255, 1}) {
			t.Fatal("raw original RR row lost")
		}
		var fresh int
		if writer.QueryRowContext(ctx, "SELECT COUNT(*) FROM instances").Scan(&fresh) != nil || fresh != 1 {
			t.Fatal("writer commit invisible to fresh observer")
		}
		if e = tx.Rollback(); e != nil {
			t.Fatal(e)
		}
		exec(t, writer, "DELETE FROM instances")
		exec(t, writer, "UPDATE users SET payload=0x00ff01")
		exec(t, writer, "INSERT INTO user_quotas VALUES(2,NULL)")
	})
	t.Run("count-holds-MDL", func(t *testing.T) {
		tx, e := reader.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback()
		tables, e := catalogBusinessGuarded(ctx, tx, nil)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = captureSourceRowCounts(ctx, tx, tables, nil); e != nil {
			t.Fatal(e)
		}
		ddl, e := writer.Conn(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer ddl.Close()
		if _, e = ddl.ExecContext(ctx, "SET SESSION lock_wait_timeout=1"); e != nil {
			t.Fatal(e)
		}
		_, e = ddl.ExecContext(ctx, "ALTER TABLE instances ADD COLUMN blocked_by_count INT NULL")
		var sqlErr *mysql.MySQLError
		if !errors.As(e, &sqlErr) || sqlErr.Number != 1205 {
			t.Fatal("COUNT did not retain table MDL", e)
		}
		if e = tx.Rollback(); e != nil {
			t.Fatal(e)
		}
		if _, e = ddl.ExecContext(ctx, "ALTER TABLE instances ADD COLUMN blocked_by_count INT NULL"); e != nil {
			t.Fatal("DDL did not release after original tx", e)
		}
		exec(t, writer, "ALTER TABLE instances DROP COLUMN blocked_by_count")
	})
	t.Run("DDL-before-count-refused", func(t *testing.T) {
		reads := 0
		catalog := func(c context.Context, q queryer, check func() error) ([]Table, error) {
			shape, e := catalogBusinessGuarded(c, q, check)
			reads++
			if e == nil && reads == 1 {
				exec(t, writer, "ALTER TABLE instances ADD COLUMN changed_before_count INT NULL")
			}
			return shape, e
		}
		got, e := captureWithCatalogMode(ctx, reader, limits, nil, catalog, true)
		if e == nil || len(got.Tables) != 0 {
			t.Fatal("empty table schema change certified")
		}
		exec(t, writer, "ALTER TABLE instances DROP COLUMN changed_before_count")
	})
	t.Run("SELECT-revoked", func(t *testing.T) {
		tables, e := catalogBusinessGuarded(ctx, reader, nil)
		if e != nil {
			t.Fatal(e)
		}
		exec(t, admin, "REVOKE SELECT ON `"+name+"`.`instances` FROM '"+user+"'@'127.0.0.1'")
		got, e := captureSourceRowCounts(ctx, reader, tables, nil)
		if e == nil || got != nil {
			t.Fatal("revoked table became empty")
		}
	})
}
