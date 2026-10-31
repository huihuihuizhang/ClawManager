package db

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"clawreef/internal/config"
	"clawreef/internal/systembackup/staging"
	"github.com/go-sql-driver/mysql"
)

func TestPublicMetadataDriverParametersActualMySQL(t *testing.T) {
	path := os.Getenv("TEST_D_METADATA_MYSQL_CREDENTIALS")
	if path == "" {
		t.Skip("requires disposable local metadata transport MySQL")
	}
	var credential struct {
		Host, User, Password, ServerUUID string
		Port                             int
	}
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &credential) != nil || credential.Host != "127.0.0.1" || credential.ServerUUID == "" {
		t.Fatal("local metadata credentials unavailable")
	}
	clear(raw)
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd, cfg.Net, cfg.Addr = credential.User, credential.Password, "tcp", net.JoinHostPort(credential.Host, strconv.Itoa(credential.Port))
	cfg.ParseTime, cfg.Loc = true, time.UTC
	cfg.Timeout = 5 * time.Second
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	credential.Password = ""
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })
	var server string
	if admin.QueryRow("SELECT @@server_uuid").Scan(&server) != nil || server != credential.ServerUUID {
		t.Fatal("owned metadata server identity")
	}
	var nonce [8]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	suffix := hex.EncodeToString(nonce[:])
	database, user, password := "ad_d_meta_"+suffix, "sbk_mt_"+suffix, hex.EncodeToString(nonce[:])+hex.EncodeToString(nonce[:])
	if _, err = admin.Exec("CREATE DATABASE `" + database + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec("DROP DATABASE `" + database + "`"); err != nil {
			t.Error(err)
		}
	})
	if _, err = admin.Exec("CREATE TABLE `" + database + "`.parameter_roundtrip(id BIGINT PRIMARY KEY,label LONGTEXT CHARACTER SET utf8mb4,body LONGBLOB,observed DATETIME(6),amount DECIMAL(16,6),flag BOOLEAN) ENGINE=InnoDB"); err != nil {
		t.Fatal(err)
	}
	if _, err = admin.Exec("CREATE USER '" + user + "'@'127.0.0.1' IDENTIFIED BY '" + password + "'"); err != nil {
		t.Fatal("create dedicated metadata test role")
	}
	t.Cleanup(func() {
		if _, err := admin.Exec("DROP USER '" + user + "'@'127.0.0.1'"); err != nil {
			t.Error(err)
		}
	})
	if _, err = admin.Exec("GRANT SELECT,INSERT,UPDATE ON `" + database + "`.`parameter_roundtrip` TO '" + user + "'@'127.0.0.1'"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	session, err := ConnectPublicBackupMetadata(config.DatabaseConfig{Host: credential.Host, Port: credential.Port, User: user, Password: password, Database: database}, func(ctx context.Context, pool *sql.DB) error {
		pool.SetMaxOpenConns(1)
		var account, actualDatabase string
		if err := pool.QueryRowContext(ctx, "SELECT CURRENT_USER(),DATABASE()").Scan(&account, &actualDatabase); err != nil {
			return err
		}
		if account != user+"@127.0.0.1" || actualDatabase != database {
			return io.ErrUnexpectedEOF
		}
		return nil
	})
	password = ""
	if err != nil {
		t.Fatal("actual public metadata constructor", err)
	}
	t.Cleanup(func() { session.Close() })
	pool := session.Driver().(*sql.DB)
	var charset, collation, zone string
	if pool.QueryRowContext(ctx, "SELECT @@character_set_client,@@collation_connection,@@session.time_zone").Scan(&charset, &collation, &zone) != nil || charset != "utf8mb4" || collation != "utf8mb4_unicode_ci" || zone != "+00:00" {
		t.Fatal("metadata constructor changed charset/collation/UTC policy", charset, collation, zone)
	}
	if _, err := pool.ExecContext(ctx, "SELECT 1; SELECT 2"); err == nil {
		t.Fatal("metadata constructor enabled multiple statements")
	}
	label := "quote' double\" backslash\\ NUL\x00 SUB\x1a 中文😀 ?; DROP TABLE parameter_roundtrip;--"
	plain := make([]byte, 256*256)
	for i := range plain {
		plain[i] = byte(i)
	}
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	sum := sha256.Sum256(plain)
	binding := staging.Binding{BackupID: "sbk_11111111-1111-4111-8111-111111111111", Attempt: "1", Path: "installation_parameter/capture/plan", CaptureContextHash: strings.Repeat("a", 64), EnvelopeID: hex.EncodeToString(sum[:])}
	var sealed bytes.Buffer
	if err = staging.Seal(ctx, &sealed, key, binding, func(w io.Writer) error { _, e := w.Write(plain); return e }); err != nil {
		t.Fatal(err)
	}
	for index, mode := range []string{"STRICT_ALL_TABLES", "STRICT_ALL_TABLES,NO_BACKSLASH_ESCAPES"} {
		t.Run(mode, func(t *testing.T) {
			if _, err := pool.ExecContext(ctx, "SET SESSION sql_mode=?", mode); err != nil {
				t.Fatal(err)
			}
			tx, err := pool.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			var isolation string
			if tx.QueryRowContext(ctx, "SELECT @@transaction_isolation").Scan(&isolation) != nil || isolation != "REPEATABLE-READ" {
				t.Fatal("metadata transaction isolation changed", isolation)
			}
			var counterName string
			var preparedBefore, preparedAfter, preparedFallback uint64
			if tx.QueryRowContext(ctx, "SHOW SESSION STATUS LIKE 'Com_stmt_prepare'").Scan(&counterName, &preparedBefore) != nil {
				t.Fatal("actual driver protocol counter")
			}
			observed := time.Now().UTC().Truncate(time.Microsecond)
			if _, err = tx.ExecContext(ctx, "INSERT INTO parameter_roundtrip(id,label,body,observed,amount,flag) VALUES(?,?,?,?,?,?)", index+1, label, sealed.Bytes(), observed, "-12345.678901", true); err != nil {
				t.Fatal(err)
			}
			var actualLabel, amount string
			var actual []byte
			var at time.Time
			var flag bool
			if err = tx.QueryRowContext(ctx, "SELECT label,body,observed,amount,flag FROM parameter_roundtrip WHERE id=?", index+1).Scan(&actualLabel, &actual, &at, &amount, &flag); err != nil {
				t.Fatal(err)
			}
			if actualLabel != label || !bytes.Equal(actual, sealed.Bytes()) || !at.Equal(observed) || at.Location() != time.UTC || amount != "-12345.678901" || !flag {
				t.Fatal("actual interpolated parameters changed bytes/time/types")
			}
			if tx.QueryRowContext(ctx, "SHOW SESSION STATUS LIKE 'Com_stmt_prepare'").Scan(&counterName, &preparedAfter) != nil || preparedAfter != preparedBefore {
				t.Fatal("actual metadata constructor did not enable native parameter interpolation", preparedBefore, preparedAfter)
			}
			var opened bytes.Buffer
			if staging.Open(ctx, bytes.NewReader(actual), &opened, key, binding, int64(len(plain))) != nil || !bytes.Equal(opened.Bytes(), plain) {
				t.Fatal("actual sealed payload was not byte-exact")
			}
			var literal, value string
			var binary []byte
			if err = tx.QueryRowContext(ctx, "SELECT '?' AS literal,? AS value,? AS body", label, plain).Scan(&literal, &value, &binary); err != nil || literal != "?" || value != label || !bytes.Equal(binary, plain) {
				t.Fatal("literal question mark/prepared fallback changed parameters", err)
			}
			if tx.QueryRowContext(ctx, "SHOW SESSION STATUS LIKE 'Com_stmt_prepare'").Scan(&counterName, &preparedFallback) != nil || preparedFallback <= preparedAfter {
				t.Fatal("driver's original prepared fallback was not observed")
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			var persisted []byte
			if pool.QueryRowContext(ctx, "SELECT body FROM parameter_roundtrip WHERE id=?", index+1).Scan(&persisted) != nil || !bytes.Equal(persisted, sealed.Bytes()) {
				t.Fatal("committed metadata bytes changed")
			}
		})
	}
}
