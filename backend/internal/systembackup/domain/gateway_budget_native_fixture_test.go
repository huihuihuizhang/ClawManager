package domain_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/domain"
	mysql "github.com/go-sql-driver/mysql"
	upper "github.com/upper/db/v4"
	uppermysql "github.com/upper/db/v4/adapter/mysql"
)

type gatewayNative struct {
	t                           *testing.T
	ctx                         context.Context
	admin                       *sql.DB
	cfg                         *mysql.Config
	uuid, nonce, owners, source string
	ca                          []byte
	seed                        domain.Snapshot
	policy                      domain.Policy
	dbs, users                  []string
}

func newGatewayNative(t *testing.T) *gatewayNative {
	t.Helper()
	file := os.Getenv("CLAWMANAGER_GATEWAY_RESTORE_MYSQL_META")
	if file == "" {
		t.Skip("requires D owned UUID/marker/CA-pinned disposable TLS MySQL")
	}
	var meta struct {
		Root       string
		Port       int
		ServerUUID string `json:"server_uuid"`
		Nonce      string `json:"owner_nonce"`
		CAHash     string `json:"ca_sha256"`
	}
	raw, err := os.ReadFile(file)
	if err != nil || json.Unmarshal(raw, &meta) != nil || !filepath.IsAbs(meta.Root) || !strings.HasPrefix(filepath.Base(meta.Root), "cm-gateway-restore-") || meta.Port <= 0 || meta.Port == 63507 || meta.Port == 65298 || meta.Port == 59355 || len(meta.Nonce) != 32 {
		t.Fatal("owned TLS metadata unavailable")
	}
	marker, err := os.ReadFile(filepath.Join(meta.Root, "owner-nonce.txt"))
	if err != nil || strings.TrimSpace(string(marker)) != meta.Nonce {
		t.Fatal("owned local marker mismatch")
	}
	ca, err := os.ReadFile(filepath.Join(meta.Root, "ca.pem"))
	if err != nil {
		t.Fatal("owned CA unavailable")
	}
	hash := sha256.Sum256(ca)
	if hex.EncodeToString(hash[:]) != meta.CAHash {
		t.Fatal("owned CA pin mismatch")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		t.Fatal("owned CA invalid")
	}
	tlsName := "gatewaynative_" + meta.Nonce[:12]
	if mysql.RegisterTLSConfig(tlsName, &tls.Config{RootCAs: pool, ServerName: "gateway-restore-native.local", MinVersion: tls.VersionTLS12}) != nil {
		t.Fatal("owned TLS config")
	}
	t.Cleanup(func() { mysql.DeregisterTLSConfig(tlsName) })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	cfg := mysql.NewConfig()
	cfg.User = "root"
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(meta.Port))
	cfg.TLSConfig = tlsName
	cfg.ParseTime = false
	cfg.Params = map[string]string{"time_zone": "'+00:00'"}
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 15 * time.Second
	cfg.WriteTimeout = 15 * time.Second
	cfg.Logger = &mysql.NopLogger{}
	f := &gatewayNative{t: t, ctx: ctx, cfg: cfg, uuid: meta.ServerUUID, nonce: meta.Nonce, ca: ca}
	f.admin = f.open(cfg)
	f.admin.SetMaxIdleConns(0)
	var uuid string
	if f.admin.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&uuid) != nil || uuid != f.uuid {
		t.Fatal("owned TLS server UUID mismatch")
	}
	plainCfg := cfg.Clone()
	plainCfg.TLSConfig = ""
	plain, err := sql.Open("mysql", plainCfg.FormatDSN())
	if err != nil {
		t.Fatal("owned plaintext negative probe")
	}
	plainErr := plain.PingContext(ctx)
	plain.Close()
	if denied, ok := plainErr.(*mysql.MySQLError); !ok || denied.Number != 3159 {
		t.Fatal("server did not really reject plaintext transport with3159")
	}
	t.Log("private CA + DNS-verified TLS and actual plaintext login denial3159 PASS")
	f.owners = "gw_owner_" + meta.Nonce[:16]
	f.exec(f.admin, "CREATE DATABASE `"+f.owners+"`")
	f.exec(f.admin, "CREATE TABLE `"+f.owners+"`.owned(database_name VARCHAR(64) PRIMARY KEY,nonce CHAR(32) NOT NULL)")
	f.exec(f.admin, "INSERT INTO `"+f.owners+"`.owned VALUES(?,?)", f.owners, f.nonce)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		var uuid, nonce string
		if f.admin.QueryRowContext(cleanup, "SELECT @@server_uuid,(SELECT nonce FROM `"+f.owners+"`.owned WHERE database_name=?)", f.owners).Scan(&uuid, &nonce) != nil || uuid != f.uuid || nonce != f.nonce {
			t.Error("owned gateway cleanup identity mismatch")
			return
		}
		for _, user := range f.users {
			if _, err := f.admin.ExecContext(cleanup, "DROP USER IF EXISTS '"+user+"'@'127.0.0.1'"); err != nil {
				t.Error("owned gateway account cleanup")
			}
		}
		for _, name := range f.dbs {
			if _, err := f.admin.ExecContext(cleanup, "DROP DATABASE `"+name+"`"); err != nil {
				t.Error("owned gateway schema cleanup")
			}
		}
		if _, err := f.admin.ExecContext(cleanup, "DROP DATABASE `"+f.owners+"`"); err != nil {
			t.Error("owned marker cleanup")
		}
	})
	f.seed, f.policy = domain.GatewayBudgetNativeSeedForTest()
	return f
}

func (f *gatewayNative) open(cfg *mysql.Config) *sql.DB {
	f.t.Helper()
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		f.t.Fatal("owned SQL open")
	}
	if db.PingContext(f.ctx) != nil {
		f.t.Fatal("owned TLS SQL ping")
	}
	f.t.Cleanup(func() { db.Close() })
	return db
}
func (f *gatewayNative) exec(db *sql.DB, q string, args ...any) {
	f.t.Helper()
	if _, err := db.ExecContext(f.ctx, q, args...); err != nil {
		var number uint16
		if m, ok := err.(*mysql.MySQLError); ok {
			number = m.Number
		}
		f.t.Fatalf("owned fixture SQL failed (%T mysql=%d)", err, number)
	}
}

func (f *gatewayNative) schema(name string) *sql.DB {
	f.t.Helper()
	f.exec(f.admin, "CREATE DATABASE `"+name+"` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
	f.dbs = append(f.dbs, name)
	f.exec(f.admin, "INSERT INTO `"+f.owners+"`.owned VALUES(?,?)", name, f.nonce)
	c := f.cfg.Clone()
	c.DBName = name
	c.MultiStatements = true
	db := f.open(c)
	// Core rows are explicitly small named fixtures, not a production core
	// schema. The gateway three-table schema below is actual migration SQL.
	for _, table := range f.seed.Tables {
		if strings.HasPrefix(table.Name, "gateway_") {
			continue
		}
		var columns []string
		for _, column := range table.Columns {
			kind := "VARCHAR(255) NULL"
			if column.Name == "id" {
				kind = "INT NOT NULL PRIMARY KEY"
			}
			columns = append(columns, "`"+column.Name+"` "+kind)
		}
		f.exec(db, "CREATE TABLE `"+table.Name+"` ("+strings.Join(columns, ",")+") ENGINE=InnoDB")
	}
	f.exec(db, "CREATE TABLE model_invocations(id INT PRIMARY KEY,status VARCHAR(24),prompt_tokens INT,completion_tokens INT,total_tokens INT,created_at TIMESTAMP NULL) ENGINE=InnoDB")
	f.exec(db, "CREATE TABLE audit_events(id INT PRIMARY KEY) ENGINE=InnoDB")
	f.exec(db, "CREATE TABLE cost_records(id INT PRIMARY KEY,currency VARCHAR(3),estimated_cost DECIMAL(18,8)) ENGINE=InnoDB")
	for _, file := range []string{"038_add_instance_gateway_token_aliases.sql", "050_add_gateway_keys.sql", "051_add_gateway_key_rate_limits.sql", "052_add_gateway_key_budget_and_attribution.sql", "055_gateway_budget_currency_review.sql"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "db", "migrations", file))
		if err != nil {
			f.t.Fatal("trusted gateway migration unavailable")
		}
		f.exec(db, string(raw))
	}
	return db
}

func (f *gatewayNative) principal(user, name, grants string) *sql.DB {
	f.t.Helper()
	f.exec(f.admin, "CREATE USER '"+user+"'@'127.0.0.1' IDENTIFIED BY '"+f.nonce+"' REQUIRE SSL")
	f.users = append(f.users, user)
	conn, err := f.admin.Conn(f.ctx)
	if err != nil {
		f.t.Fatal("owned grant connection")
	}
	quoted, err := domain.QuotedGrantDatabase(f.ctx, conn, name)
	conn.Close()
	if err != nil {
		f.t.Fatal("literal owned schema grant")
	}
	f.exec(f.admin, "GRANT "+grants+" ON "+quoted+".* TO '"+user+"'@'127.0.0.1'")
	c := f.cfg.Clone()
	c.User, c.Passwd, c.DBName = user, f.nonce, name
	return f.open(c)
}

func (f *gatewayNative) upper(name, user, password string) upper.Session {
	f.t.Helper()
	s, err := uppermysql.Open(uppermysql.ConnectionURL{Host: f.cfg.Addr, Database: name, User: user, Password: password, Options: map[string]string{"charset": "utf8mb4", "parseTime": "true", "loc": "UTC", "time_zone": "'+00:00'", "tls": f.cfg.TLSConfig}})
	if err != nil {
		f.t.Fatal("owned repository TLS session")
	}
	f.t.Cleanup(func() { s.Close() })
	return s
}

// observe checks only fixture identity and this one account. It intentionally
// makes no claim about all consumer accounts or already authenticated writers;
// production target proof must independently inventory and reject those.
func (f *gatewayNative) observe(ctx context.Context, name, user string) error {
	var uuid, nonce, locked string
	err := f.admin.QueryRowContext(ctx, "SELECT @@server_uuid,(SELECT nonce FROM `"+f.owners+"`.owned WHERE database_name=?),(SELECT account_locked FROM mysql.user WHERE User=? AND Host='127.0.0.1')", name, user).Scan(&uuid, &nonce, &locked)
	if err != nil || uuid != f.uuid || nonce != f.nonce || locked != "N" {
		return fmt.Errorf("owned native identity/credential observation rejected")
	}
	return ctx.Err()
}

func (f *gatewayNative) revoke(writer *sql.DB, user string) {
	f.t.Helper()
	writer.Close()
	f.exec(f.admin, "ALTER USER '"+user+"'@'127.0.0.1' ACCOUNT LOCK")
	deadline := time.Now().Add(3 * time.Second)
	for {
		var count int
		if f.admin.QueryRowContext(f.ctx, "SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE USER=?", user).Scan(&count) != nil {
			f.t.Fatal("writer session observation failed")
		}
		if count == 0 {
			break
		}
		if time.Now().After(deadline) {
			f.t.Fatal("writer connections did not actually exit")
		}
		time.Sleep(10 * time.Millisecond)
	}
	c := f.cfg.Clone()
	c.User, c.Passwd = user, f.nonce
	probe, err := sql.Open("mysql", c.FormatDSN())
	if err != nil {
		f.t.Fatal("owned writer reauth probe")
	}
	defer probe.Close()
	err = probe.PingContext(f.ctx)
	m, ok := err.(*mysql.MySQLError)
	if !ok || m.Number != 3118 {
		f.t.Fatal("revoked writer reauthentication was not actual3118")
	}
}
