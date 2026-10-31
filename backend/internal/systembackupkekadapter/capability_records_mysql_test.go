//go:build systembackup_mysql

package systembackupkekadapter

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
	kms "clawreef/internal/systembackupkms"
	mysql "github.com/go-sql-driver/mysql"
)

func capabilityLocalMySQL(t *testing.T, ctx context.Context) (*sql.DB, *sql.DB, reg.DatabaseIdentity) {
	t.Helper()
	path, uuid := os.Getenv("A_SIGNING_MYSQL_CREDENTIALS_FILE"), os.Getenv("A_SIGNING_MYSQL_SERVER_UUID")
	if path == "" || uuid == "" {
		t.Fatal("independently pinned local MySQL credentials file/UUID required")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 4096 {
		t.Fatal("local credentials unavailable")
	}
	var credentials struct {
		Host, User, Password string
		Port                 int
	}
	if json.Unmarshal(raw, &credentials) != nil || credentials.Host != "127.0.0.1" {
		clear(raw)
		t.Fatal("local TCP credentials invalid")
	}
	clear(raw)
	cfg := mysql.NewConfig()
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(credentials.Host, strconv.Itoa(credentials.Port))
	cfg.User = credentials.User
	cfg.Passwd = credentials.Password
	cfg.ParseTime = true
	cfg.MultiStatements = true
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 10 * time.Second
	cfg.WriteTimeout = 10 * time.Second
	root, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal("local MySQL open failed")
	}
	t.Cleanup(func() { root.Close() })
	var actual string
	if root.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&actual) != nil || actual != uuid {
		t.Fatal("local MySQL UUID mismatch")
	}
	var random [12]byte
	if _, err = rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	run := hex.EncodeToString(random[:])
	database, user := "ad_a_kek_"+run, "ad_a_cap_"+run[:16]
	if _, err = root.ExecContext(ctx, "CREATE DATABASE `"+database+"`"); err != nil {
		t.Fatal(err)
	}
	cfg.DBName = database
	owner, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Close() })
	if _, err = owner.ExecContext(ctx, "CREATE TABLE _ad_a_capability_marker(run_id VARCHAR(64) PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	if _, err = owner.ExecContext(ctx, "INSERT INTO _ad_a_capability_marker VALUES (?)", run); err != nil {
		t.Fatal(err)
	}
	userCreated := false
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var server, marker string
		if root.QueryRowContext(cleanup, "SELECT @@server_uuid").Scan(&server) != nil || server != uuid || owner.QueryRowContext(cleanup, "SELECT run_id FROM _ad_a_capability_marker").Scan(&marker) != nil || marker != run {
			t.Error("capability fixture cleanup ownership mismatch; retained")
			return
		}
		if userCreated {
			if _, e := root.ExecContext(cleanup, "DROP USER '"+user+"'@'127.0.0.1'"); e != nil {
				t.Error("owned capability user cleanup failed")
			}
		}
		if _, e := root.ExecContext(cleanup, "DROP DATABASE `"+database+"`"); e != nil {
			t.Error("owned capability database cleanup failed")
		}
	})
	for _, name := range []string{"127_backup_v2_kek_registry.sql", "128_backup_installation_kek_authority.sql"} {
		ddl, e := os.ReadFile("../db/migrations/" + name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = owner.ExecContext(ctx, string(ddl)); e != nil {
			t.Fatal("exact original migration failed", name, e)
		}
	}
	if _, err = owner.ExecContext(ctx, `CREATE TABLE system_backup_v2_evidence(public_id VARCHAR(128) PRIMARY KEY,owner_target_type VARCHAR(32),owner_target_public_id VARCHAR(128),evidence_type VARCHAR(32),storage_state VARCHAR(32),observed_health VARCHAR(32),encryption VARCHAR(32),inline_payload VARBINARY(8192),content_checksum CHAR(64),content_size_bytes BIGINT UNSIGNED,expires_at DATETIME(6),CHECK(content_checksum=SHA2(inline_payload,256)),CHECK(content_size_bytes=OCTET_LENGTH(inline_payload))) ENGINE=InnoDB`); err != nil {
		t.Fatal(err)
	}
	var passwordRaw [24]byte
	if _, err = rand.Read(passwordRaw[:]); err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(passwordRaw[:])
	clear(passwordRaw[:])
	if _, err = root.ExecContext(ctx, "CREATE USER '"+user+"'@'127.0.0.1' IDENTIFIED BY '"+password+"'"); err != nil {
		t.Fatal("local read-only capability user creation failed")
	}
	userCreated = true
	for _, table := range []string{"system_backup_v2_evidence", "system_backup_installation_kek_authority"} {
		if _, err = root.ExecContext(ctx, "GRANT SELECT ON `"+database+"`.`"+table+"` TO '"+user+"'@'127.0.0.1'"); err != nil {
			t.Fatal(err)
		}
	}
	readerCfg := cfg.Clone()
	readerCfg.User = user
	readerCfg.Passwd = password
	password = ""
	readerCfg.MultiStatements = false
	reader, err := sql.Open("mysql", readerCfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reader.Close() })
	return owner, reader, reg.DatabaseIdentity{ServerUUID: uuid, Database: database}
}

func TestSQLOriginalKEKCapabilityMySQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	owner, reader, database := capabilityLocalMySQL(t, ctx)
	r, issuer, key := ownerRecordFixture(t)
	writer, err := NewInstallationAuthorityWriter(owner, r.Binding.InstallationID, database, issuer)
	if err != nil {
		t.Fatal(err)
	}
	raw, sig := signOwner(r, key)
	if version, e := writer.Put(ctx, raw, sig, 0); e != nil || version != 1 {
		t.Fatal("original signed mapping import failed", e)
	}
	g, gpin, gkey := providerCapabilityFixture(t, r.Binding, kms.Generate)
	u, upin, ukey := providerCapabilityFixture(t, r.Binding, kms.Unwrap)
	put := func(id string, e capabilityEvidence) {
		t.Helper()
		h := sha256.Sum256(e.raw)
		if _, err = owner.ExecContext(ctx, `INSERT INTO system_backup_v2_evidence VALUES (?,'system',?,'capability_snapshot','inline','healthy','none',?,?,?,?)`, id, r.Binding.InstallationID, e.raw, hex.EncodeToString(h[:]), len(e.raw), e.until); err != nil {
			t.Fatal(err)
		}
	}
	put(gpin.Source.RecordID, signCapabilityFixture(t, g, gkey))
	put(upin.Source.RecordID, signCapabilityFixture(t, u, ukey))
	preparation, err := NewSQLInstallationPreparation(reader, database, r.Binding.InstallationID, issuer, gpin, upin)
	if err != nil {
		t.Fatal(err)
	}
	readRaw, readSig, err := preparation.Reader.ReadOriginal(ctx, r.Binding.InstallationID, r.Binding.ConfigRef)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = authenticate(readRaw, readSig, issuer, time.Now()); err != nil {
		t.Fatal("original SQL authority signature failed", err)
	}
	caps, err := preparation.Capabilities.PrepareCapabilities(ctx, r.Binding)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := owner.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	bound, locked, err := (reg.SQLStore{}).Bind(ctx, tx, r.Binding.InstallationID)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	var now time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil {
		tx.Rollback()
		t.Fatal("SQL clock unavailable")
	}
	if caps.Generate.Recheck(ctx, tx, locked, now) != nil || caps.Unwrap.Recheck(ctx, tx, locked, now) != nil {
		tx.Rollback()
		t.Fatal("real same-transaction purpose capability recheck failed")
	}
	mapping := &originalMapping{reader: preparation.Reader, key: issuer, record: r}
	if mapping.Recheck(ctx, tx, locked, now) != nil {
		tx.Rollback()
		t.Fatal("original mapping same-transaction recheck failed")
	}
	if _, err = bound.CompleteScan(ctx); err == nil {
		tx.Rollback()
		t.Fatal("empty fresh registry fabricated coverage")
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err = reader.ExecContext(ctx, "UPDATE system_backup_v2_evidence SET observed_health='degraded'"); err == nil {
		t.Fatal("capability reader can mutate original evidence")
	}
	if _, err = reader.ExecContext(ctx, "DELETE FROM system_backup_installation_kek_authority"); err == nil {
		t.Fatal("original mapping reader can delete history source")
	}
	// Independently signed revocation is imported through the existing fenced
	// writer. The current source is disabled while history remains immutable.
	r.Revision = "r2"
	r.GenerateRevoked = true
	raw, sig = signOwner(r, key)
	if version, e := writer.Put(ctx, raw, sig, 1); e != nil || version != 2 {
		t.Fatal("fenced purpose revocation failed", e)
	}
	raw, sig, err = preparation.Reader.ReadOriginal(ctx, r.Binding.InstallationID, r.Binding.ConfigRef)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = authenticate(raw, sig, issuer, time.Now()); err == nil {
		t.Fatal("revoked mapping admitted")
	}
	var count int
	if owner.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_installation_kek_authority_history").Scan(&count) != nil || count != 2 {
		t.Fatal("original history was lost")
	}
	r.Revision = "r3"
	r.GenerateRevoked = false
	raw, sig = signOwner(r, key)
	if _, err = writer.Put(ctx, raw, sig, 2); err == nil {
		t.Fatal("revocation resurrected historical mapping")
	}
	g.Revoked = true
	e := signCapabilityFixture(t, g, gkey)
	h := sha256.Sum256(e.raw)
	if _, err = owner.ExecContext(ctx, `UPDATE system_backup_v2_evidence SET inline_payload=?,content_checksum=?,content_size_bytes=? WHERE public_id=?`, e.raw, hex.EncodeToString(h[:]), len(e.raw), gpin.Source.RecordID); err != nil {
		t.Fatal(err)
	}
	if _, err = preparation.Capabilities.PrepareCapabilities(ctx, r.Binding); err == nil {
		t.Fatal("revoked provider capability prepared")
	}
}
