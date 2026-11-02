package systembackupkekadapter

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	reg "clawreef/internal/systembackupkekregistry"
	kms "clawreef/internal/systembackupkms"
	"github.com/go-sql-driver/mysql"
)

func TestHeldProviderPermitRowsRejectsForeignScopeBeforeSQL(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tx, guard := new(sql.Tx), new(c.ExecutionAuthorityGuard)
	issue := &PreparedProviderPermitIssue{issuer: &ProviderPermitIssuer{}, capability: &sqlPreparedCapability{}}
	proof := &heldProviderPermitRows{ctx: ctx, tx: tx, issue: issue, guard: guard, capability: issue.capability}
	// Invalid cases must fail BEFORE reaching a SQL call on the zero tx.
	for _, tc := range []struct {
		name string
		edit func(*heldProviderPermitRows)
	}{
		{"context", func(p *heldProviderPermitRows) { p.ctx = context.Background() }},
		{"transaction", func(p *heldProviderPermitRows) { p.tx = new(sql.Tx) }},
		{"issue", func(p *heldProviderPermitRows) { p.issue = new(PreparedProviderPermitIssue) }},
		{"guard", func(p *heldProviderPermitRows) { p.guard = new(c.ExecutionAuthorityGuard) }},
		{"authority", func(p *heldProviderPermitRows) { p.authority.AttemptNo++ }},
		{"capability", func(p *heldProviderPermitRows) { p.capability = new(sqlPreparedCapability) }},
		{"source", func(p *heldProviderPermitRows) { p.source.RecordID = "foreign" }},
		{"mapping", func(p *heldProviderPermitRows) { p.mapping.Version = "foreign" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := *proof
			tc.edit(&copy)
			if _, _, _, err := copy.read(ctx, tx, issue, guard); err == nil {
				t.Fatal("foreign scope reached current data")
			}
		})
	}
	if _, _, _, err := (*heldProviderPermitRows)(nil).read(ctx, tx, issue, guard); err == nil {
		t.Fatal("nil lock proof accepted")
	}
	cancel()
	if _, _, _, err := proof.read(ctx, tx, issue, guard); err == nil {
		t.Fatal("canceled original context accepted")
	}
}

// Actual SQL DATA differential only. This does not construct a live execution
// guard or authorize any provider. Full StageOriginal native tests remain the
// authority/revocation/window proof. Only a separately pinned disposable TLS
// server may host this exact, privately named two-table schema.
func TestHeldProviderPermitRowsCurrentMySQL(t *testing.T) {
	pin := os.Getenv("A_PERMIT_NATIVE_DISPOSABLE_SERVER_UUID")
	if pin == "" {
		t.Skip("requires owner-pinned disposable TLS MySQL")
	}
	var credentials struct {
		Host, User, Password, CAFile, TLSServerName, ServerUUID string
		Port                                                    int
	}
	raw, err := os.ReadFile(os.Getenv("TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS"))
	if err != nil || len(raw) > 16384 || json.Unmarshal(raw, &credentials) != nil || credentials.Host != "127.0.0.1" || credentials.Port < 1024 || credentials.Port == 3306 || credentials.ServerUUID != pin {
		t.Fatal("disposable TLS credentials/pin unavailable")
	}
	clear(raw)
	ca, err := os.ReadFile(credentials.CAFile)
	roots := x509.NewCertPool()
	if err != nil || !roots.AppendCertsFromPEM(ca) {
		t.Fatal("disposable CA unavailable")
	}
	var nonce [8]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	run := hex.EncodeToString(nonce[:])
	tlsName := "a-permit-rows-" + run
	if mysql.RegisterTLSConfig(tlsName, &tls.Config{RootCAs: roots, ServerName: credentials.TLSServerName, MinVersion: tls.VersionTLS13}) != nil {
		t.Fatal("TLS registration unavailable")
	}
	t.Cleanup(func() { mysql.DeregisterTLSConfig(tlsName) })
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd = credentials.User, credentials.Password
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(credentials.Host, strconv.Itoa(credentials.Port))
	cfg.TLSConfig = tlsName
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout, cfg.WriteTimeout = 10*time.Second, 10*time.Second
	cfg.Params = map[string]string{"time_zone": "'+00:00'"}
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal("disposable connection unavailable")
	}
	t.Cleanup(func() { admin.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var observed string
	if admin.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&observed) != nil || observed != pin {
		t.Fatal("disposable UUID mismatch before schema creation")
	}
	schema := "ad_a_permit_rows_" + run
	if _, err = admin.ExecContext(ctx, "CREATE DATABASE `"+schema+"`"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if _, err := admin.ExecContext(cleanup, "DROP DATABASE `"+schema+"`"); err != nil {
			t.Error("exact owned data schema cleanup failed", err)
		}
	})
	cfg.DBName = schema
	db, err := sql.Open("mysql", cfg.FormatDSN())
	cfg.Passwd = ""
	credentials.Password = ""
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, ddl := range []string{
		`CREATE TABLE system_backup_v2_evidence(public_id VARCHAR(128) PRIMARY KEY,owner_target_type VARCHAR(32),owner_target_public_id VARCHAR(128),evidence_type VARCHAR(64),storage_state VARCHAR(32),observed_health VARCHAR(32),encryption VARCHAR(32),inline_payload BLOB,content_checksum CHAR(64),content_size_bytes BIGINT UNSIGNED,expires_at DATETIME(6)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_installation_kek_authority(installation_id VARCHAR(128),identity_hash VARCHAR(128),registry_version VARCHAR(128),signed_record BLOB,signature BLOB,PRIMARY KEY(installation_id,identity_hash,registry_version)) ENGINE=InnoDB`,
	} {
		if _, err = db.ExecContext(ctx, ddl); err != nil {
			t.Fatal(err)
		}
	}
	mapping, issuer, key := ownerRecordFixture(t)
	defer clear(key)
	mappingRaw, mappingSig := signOwner(mapping, key)
	capRecord, capPin, capKey := providerCapabilityFixture(t, mapping.Binding, kms.Generate)
	defer clear(capKey)
	evidence := signCapabilityFixture(t, capRecord, capKey)
	evidence.until = evidence.until.UTC().Truncate(time.Microsecond)
	now := time.Now().UTC()
	facts := reg.Snapshot{InstallationID: mapping.Binding.InstallationID, Database: reg.DatabaseIdentity{ServerUUID: pin, Database: schema}}
	capUntil := capRecord.Until
	if evidence.until.Before(capUntil) {
		capUntil = evidence.until
	}
	capability := &sqlPreparedCapability{database: facts.Database, record: capRecord, pin: capPin, evidence: evidence, until: capUntil}
	issue := &PreparedProviderPermitIssue{issuer: &ProviderPermitIssuer{cfg: ProviderPermitIssuerConfig{Binding: mapping.Binding, InstallationIssuer: issuer}}, capability: capability, mapping: mapping, mappingRaw: mappingRaw, mappingSignature: mappingSig, mappingIssuer: issuer, until: now.Add(10 * time.Second)}
	issue.scope.Input.Authority = d.Authority{InstallationID: facts.InstallationID}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	reset := func() {
		t.Helper()
		sum := sha256.Sum256(evidence.raw)
		if _, err := tx.ExecContext(ctx, `REPLACE INTO system_backup_v2_evidence VALUES(?,'system',?,'capability_snapshot','inline','healthy','none',?,?,?,?)`, capPin.Source.RecordID, facts.InstallationID, evidence.raw, hex.EncodeToString(sum[:]), len(evidence.raw), evidence.until); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `REPLACE INTO system_backup_installation_kek_authority VALUES(?,?,?,?,?)`, facts.InstallationID, mapping.Binding.ConfigRef.IdentityHash, mapping.Binding.ConfigRef.Version, mappingRaw, mappingSig); err != nil {
			t.Fatal(err)
		}
	}
	reset()
	// Original FIRST ordered reads establish the exact row locks before a batch.
	if capability.recheck(ctx, tx, facts, now) != nil {
		t.Fatal("first capability read")
	}
	if _, _, err = (SQLOriginalReader{}).RecheckOriginal(ctx, tx, facts.InstallationID, mapping.Binding.ConfigRef); err != nil {
		t.Fatal(err)
	}
	guard := new(c.ExecutionAuthorityGuard)
	proof := &heldProviderPermitRows{ctx: ctx, tx: tx, issue: issue, guard: guard, authority: issue.scope.Input.Authority, capability: capability, source: capPin.Source, mapping: mapping.Binding.ConfigRef}
	revoked := mapping
	revoked.GenerateRevoked = true
	revokedRaw, revokedSig := signOwner(revoked, key)
	renewed := mapping
	renewed.Revision = "current-renewal"
	renewed.Source.RecordVersion = "current-renewal"
	renewed.Until = renewed.Until.Add(time.Minute)
	renewedRaw, renewedSig := signOwner(renewed, key)
	changedEvidence := append(append([]byte(nil), evidence.raw...), ' ')
	changedSum := sha256.Sum256(changedEvidence)
	for _, tc := range []struct {
		name, query string
		args        []any
		allowed     bool
	}{
		{name: "unchanged", allowed: true},
		{name: "health", query: `UPDATE system_backup_v2_evidence SET observed_health='unhealthy'`},
		{name: "owner", query: `UPDATE system_backup_v2_evidence SET owner_target_public_id='foreign'`},
		{name: "type", query: `UPDATE system_backup_v2_evidence SET evidence_type='diagnostic'`},
		{name: "encryption", query: `UPDATE system_backup_v2_evidence SET encryption='encrypted'`},
		{name: "checksum", query: `UPDATE system_backup_v2_evidence SET content_checksum=REPEAT('0',64)`},
		{name: "size", query: `UPDATE system_backup_v2_evidence SET content_size_bytes=content_size_bytes+1`},
		{name: "expiry", query: `UPDATE system_backup_v2_evidence SET expires_at=TIMESTAMPADD(SECOND,-1,expires_at)`},
		{name: "different_current_bytes", query: `UPDATE system_backup_v2_evidence SET inline_payload=?,content_checksum=?,content_size_bytes=?`, args: []any{changedEvidence, hex.EncodeToString(changedSum[:]), len(changedEvidence)}},
		{name: "current_mapping_revocation", query: `UPDATE system_backup_installation_kek_authority SET signed_record=?,signature=?`, args: []any{revokedRaw, revokedSig}},
		{name: "current_mapping_renewal", query: `UPDATE system_backup_installation_kek_authority SET signed_record=?,signature=?`, args: []any{renewedRaw, renewedSig}, allowed: true},
		{name: "signature", query: `UPDATE system_backup_installation_kek_authority SET signature='broken'`},
		{name: "missing_mapping", query: `DELETE FROM system_backup_installation_kek_authority`},
		{name: "missing_capability", query: `DELETE FROM system_backup_v2_evidence`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reset()
			if tc.query != "" {
				if _, err := tx.ExecContext(ctx, tc.query, tc.args...); err != nil {
					t.Fatal(err)
				}
			}
			oldE, oldErr := readCapabilityEvidence(ctx, tx, facts.InstallationID, capPin, true)
			oldRaw, oldSig, mapErr := (SQLOriginalReader{}).RecheckOriginal(ctx, tx, facts.InstallationID, mapping.Binding.ConfigRef)
			oldAllowed := oldErr == nil && mapErr == nil && capability.recheckEvidence(ctx, facts, now, oldE) == nil && issue.recheckMapping(oldRaw, oldSig, now) == nil
			newE, newRaw, newSig, newErr := proof.read(ctx, tx, issue, guard)
			newAllowed := newErr == nil && capability.recheckEvidence(ctx, facts, now, newE) == nil && issue.recheckMapping(newRaw, newSig, now) == nil
			if oldAllowed != tc.allowed || newAllowed != oldAllowed {
				t.Fatalf("current old=%v batch=%v want=%v", oldAllowed, newAllowed, tc.allowed)
			}
		})
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = proof.read(ctx, tx, issue, guard); err == nil {
		t.Fatal("completed original transaction reused")
	}
}
