package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

type downloadPinsModel struct {
	config                          downloadDeployment
	grants                          []string
	account, role, server, database string
	queries                         int
	connections                     int
	db                              *sql.DB
	base                            *downloadPinsModel
}
type downloadPinsConnector struct{ model *downloadPinsModel }
type downloadPinsDriver struct{}

func (downloadPinsDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }
func (c downloadPinsConnector) Driver() driver.Driver       { return downloadPinsDriver{} }
func (c downloadPinsConnector) Connect(context.Context) (driver.Conn, error) {
	c.model.connections++
	return &downloadPinsConn{c.model}, nil
}

type downloadPinsConn struct{ model *downloadPinsModel }

func (*downloadPinsConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (*downloadPinsConn) Begin() (driver.Tx, error) {
	return nil, errors.New("unexpected business transaction")
}
func (*downloadPinsConn) Close() error { return nil }
func (c *downloadPinsConn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	c.model.queries++
	if q == "SELECT @@server_uuid,DATABASE(),CURRENT_USER(),CURRENT_ROLE()" {
		return &downloadPinsRows{width: 4, data: [][]driver.Value{{c.model.server, c.model.database, c.model.account, c.model.role}}}, nil
	}
	if q == "SHOW GRANTS" {
		rows := &downloadPinsRows{width: 1}
		for _, s := range c.model.grants {
			rows.data = append(rows.data, []driver.Value{s})
		}
		return rows, nil
	}
	return nil, errors.New("PRIVATE unexpected SQL")
}

type downloadPinsRows struct {
	width int
	data  [][]driver.Value
}

func (r *downloadPinsRows) Columns() []string {
	out := make([]string, r.width)
	for n := range out {
		out[n] = "column"
	}
	return out
}
func (*downloadPinsRows) Close() error { return nil }
func (r *downloadPinsRows) Next(out []driver.Value) error {
	if len(r.data) == 0 {
		return io.EOF
	}
	copy(out, r.data[0])
	r.data = r.data[1:]
	return nil
}

func writeDownloadFixtureFile(t *testing.T, path string, raw []byte) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func downloadFixtureGrants(c downloadDeployment) []string {
	grantee := "'" + c.DatabaseUser + "'@'%'"
	out := []string{"GRANT USAGE ON *.* TO " + grantee, "GRANT LOCK TABLES ON `" + c.Database + "`.* TO " + grantee}
	tables := map[string][]string{
		"users": {"SELECT"}, "audit_logs": {"SELECT", "INSERT"}, "system_backup_v2_installation_state": {"SELECT"}, "system_backup_v2_configs": {"SELECT"},
		"system_backup_v2_operations": {"SELECT", "INSERT"}, "system_backup_v2_evidence": {"SELECT", "INSERT", "UPDATE"}, "system_backup_v2_evidence_chunks": {"SELECT"},
		"system_backup_v2_download_admission_receipts": {"SELECT", "INSERT"}, "system_backup_v2_download_result_receipts": {"SELECT", "INSERT"}, "system_backup_v2_strong_auth_nonces": {"SELECT", "INSERT"},
		"system_backup_v2_metadata_reservations": {"SELECT", "INSERT", "UPDATE"}, "system_backup_v2_admin_sessions": {"SELECT", "INSERT", "UPDATE"}, "system_backup_v2_admin_revocations": {"SELECT"}, "system_backup_v2_totp_credentials": {"SELECT", "INSERT", "UPDATE"},
		"system_backup_v2_backups": {"SELECT"}, "system_backup_v2_restore_drills": {"SELECT"}, "system_backup_v2_preflights": {"SELECT"}, "system_backup_v2_artifact_verifications": {"SELECT"},
	}
	var names []string
	for name := range tables {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		out = append(out, "GRANT "+strings.Join(tables[name], ", ")+" ON `"+c.Database+"`.`"+name+"` TO "+grantee)
	}
	return out
}

func downloadDeploymentFixture(t *testing.T) (downloadDeployment, *sec.RegistrationApplication, *downloadPinsModel, string) {
	t.Helper()
	dir := t.TempDir()
	cert := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(cert.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate().Raw})
	caPath := filepath.Join(dir, "ca.pem")
	caSHA := writeDownloadFixtureFile(t, caPath, ca)
	secret := bytes.Repeat([]byte{9}, 32)
	secretPath := filepath.Join(dir, "jwt")
	writeDownloadFixtureFile(t, secretPath, secret)
	baseHash := strings.Repeat("a", 64)
	now := time.Now().UTC().Truncate(time.Microsecond)
	c := downloadDeployment{SchemaVersion: "system-backup-download-deployment.v1", RegistrationRuntimeSHA256: baseHash, ServerUUID: "11111111-2222-4333-8444-555555555555", Database: "download_test", Installation: "installation_test", DatabaseUser: "download_reader", ConfigVersion: 1, ConfigSHA256: strings.Repeat("b", 64), Root: "evidence",
		Store: downloadReferencePins{Identity: strings.Repeat("c", 64), Version: "store-v1"}, Read: downloadReferencePins{Identity: strings.Repeat("d", 64), Version: "read-v1"}, AuthorityUntil: now.Add(time.Hour), MaterialsUntil: now.Add(time.Minute), AuditMinimumRetainUntil: now.Add(24 * time.Hour), LargeSmokeBytes: 1, AdmissionReservationBytes: 65536, ResultReservationBytes: 65536, JournalPath: filepath.Join(dir, "failure.jsonl"), JournalMaxBytes: 4096,
		S3: downloadS3Pins{Endpoint: cert.URL, Region: "us-east-1", Bucket: "evidence-test", CAFile: caPath, CASHA256: caSHA}, STS: downloadSTSPins{Endpoint: cert.URL, RoleARN: "arn:aws:iam::123456789012:role/evidence-reader", Issuer: "https://issuer.example", Audience: "download-sts", Subject: "system:serviceaccount:backup:evidence-reader", TokenFile: filepath.Join(dir, "s3-token"), CAFile: caPath, CASHA256: caSHA},
		Transit: []downloadTransitPins{{Endpoint: cert.URL, Key: downloadReferencePins{Identity: strings.Repeat("e", 64), Version: "kek-v1"}, KeyName: "evidence", KeyVersion: 1, Mount: "jwt", Role: "download-reader", Policy: "download-decrypt", Audience: "download-unwrap", TokenFile: filepath.Join(dir, "transit-token"), CAFile: caPath, CASHA256: caSHA}}}
	writeDownloadFixtureFile(t, c.JournalPath, nil)
	model := &downloadPinsModel{config: c, account: c.DatabaseUser + "@%", role: "NONE", server: c.ServerUUID, database: c.Database}
	model.grants = downloadFixtureGrants(c)
	c.GrantsFile = filepath.Join(dir, "grants.json")
	raw, _ := json.Marshal(downloadGrantPins{SchemaVersion: "system-backup-download-sql-pins.v1", ServerUUID: c.ServerUUID, Database: c.Database, User: c.DatabaseUser, Statements: model.grants})
	c.GrantsSHA256 = writeDownloadFixtureFile(t, c.GrantsFile, raw)
	db := sql.OpenDB(downloadPinsConnector{model})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	model.db = db
	model.base = &downloadPinsModel{account: "registration_writer@%", role: "NONE", server: c.ServerUUID, database: c.Database}
	registrationDB := sql.OpenDB(downloadPinsConnector{model.base})
	t.Cleanup(func() { registrationDB.Close() })
	base := &sec.RegistrationApplication{DB: registrationDB, Config: sec.RegistrationRuntimeConfig{ExpectedServerUUID: c.ServerUUID, ExpectedDatabase: c.Database, InstallationID: c.Installation, ConfigVersion: c.ConfigVersion, RBACRegistryVersion: "v1", RBACRegistrySHA256: strings.Repeat("f", 64), RegistryDirectory: filepath.Join(dir, "registries"), NonceDirectory: filepath.Join(dir, "nonce"), CapacityReportFile: filepath.Join(dir, "capacity.json"), JWTSecretFile: secretPath}}
	base.API.Registration.Auth = sec.JWTRegistrationAuthenticator{Secret: append([]byte(nil), secret...)}
	base.API.TOTP.Issuer.Key.Issuer = "strong-proof"
	return c, base, model, filepath.Join(dir, "deployment.json")
}

func TestDownloadDeploymentLoadsConcreteRuntimeAndMountsTLS(t *testing.T) {
	c, base, model, path := downloadDeploymentFixture(t)
	raw, _ := json.Marshal(c)
	pin := writeDownloadFixtureFile(t, path, raw)
	d, err := loadDownloadDeployment(context.Background(), base, model.db, path, pin, c.RegistrationRuntimeSHA256, c.DatabaseUser)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	if model.connections != 1 || model.queries != 2 || model.base.connections != 0 || model.base.queries != 0 || d.application.ProofTargets == nil || d.application.Runtime.CheckFailurePersistence() != nil {
		t.Fatal("composition or single-connection pins missing")
	}
	h, err := mountDownloadHTTP(base.API, d)
	if err != nil {
		t.Fatal(err)
	}
	plain := httptest.NewRequest("GET", "https://example.invalid/unknown", nil)
	plain.TLS = nil
	plain.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, plain)
	if w.Code != 426 {
		t.Fatal("forwarded header bypassed TLS", w.Code)
	}
	server := httptest.NewTLSServer(h)
	defer server.Close()
	for _, test := range []struct {
		path   string
		status int
	}{{"/unknown", 404}, {"/api/v1/admin/system-backup-evidence/sev_11111111-2222-4333-8444-555555555555", 401}} {
		res, err := server.Client().Get(server.URL + test.path)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		if res.StatusCode != test.status {
			t.Fatal("route/status", test.path, res.StatusCode)
		}
	}
	d.application.Runtime.Close()
	res, err := server.Client().Get(server.URL + "/unknown")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 503 {
		t.Fatal("closed journal did not block control plane", res.StatusCode)
	}
	if model.queries != 2 {
		t.Fatal("unauthenticated traffic reached SQL")
	}
}

func TestDownloadDeploymentRejectsWrongPinsAndSources(t *testing.T) {
	for _, mode := range []string{"file_pin", "base_pin", "installation", "database_user", "root", "config_version", "grants_pin", "grant_drift", "role", "server", "missing_journal", "ca_pin", "mixed_jwt"} {
		t.Run(mode, func(t *testing.T) {
			c, base, model, path := downloadDeploymentFixture(t)
			sqlUser := c.DatabaseUser
			switch mode {
			case "base_pin":
				c.RegistrationRuntimeSHA256 = strings.Repeat("0", 64)
			case "installation":
				c.Installation = "installation_other"
			case "database_user":
				c.DatabaseUser = "someone_else"
			case "root":
				c.DatabaseUser = "root"
			case "config_version":
				c.ConfigVersion++
			case "grants_pin":
				c.GrantsSHA256 = strings.Repeat("0", 64)
			case "grant_drift":
				model.grants = append(model.grants, "GRANT SELECT ON `download_test`.`system_backup_other` TO 'download_reader'@'%'")
			case "role":
				model.role = "`elevated`@`%`"
			case "server":
				model.server = "wrong"
			case "missing_journal":
				os.Remove(c.JournalPath)
			case "ca_pin":
				c.S3.CASHA256 = strings.Repeat("0", 64)
			case "mixed_jwt":
				writeDownloadFixtureFile(t, base.Config.JWTSecretFile, bytes.Repeat([]byte{8}, 32))
			}
			raw, _ := json.Marshal(c)
			pin := writeDownloadFixtureFile(t, path, raw)
			if mode == "file_pin" {
				pin = strings.Repeat("0", 64)
			}
			if d, err := loadDownloadDeployment(context.Background(), base, model.db, path, pin, strings.Repeat("a", 64), sqlUser); err == nil {
				d.Close()
				t.Fatal("untrusted deployment accepted")
			}
		})
	}
}

func TestDownloadDeploymentStrictJSON(t *testing.T) {
	for _, raw := range []string{`{"schema_version":"a","schema_version":"b"}`, `{"Schema_Version":"a"}`, `{"schema_version":"a","extra":1}`, `{"schema_version":"\ud800"}`, `{"schema_version":"a"} {}`, `null`} {
		var c downloadDeployment
		err := strictDeploymentJSON([]byte(raw), &c)
		if err == nil {
			t.Fatal("ambiguous deployment JSON", raw)
		}
	}
}

func TestDownloadGrantShapeRejectsEscalation(t *testing.T) {
	c, _, _, _ := downloadDeploymentFixture(t)
	good := downloadFixtureGrants(c)
	if downloadGrantShape(c, good) != nil {
		t.Fatal("fixture grants rejected")
	}
	for _, extra := range []string{"GRANT ALL PRIVILEGES ON `download_test`.* TO 'download_reader'@'%'", "GRANT SELECT ON *.* TO 'download_reader'@'%'", "GRANT UPDATE ON `download_test`.`audit_logs` TO 'download_reader'@'%'", "GRANT UPDATE ON `download_test`.`users` TO 'download_reader'@'%'", "GRANT DELETE ON `download_test`.`system_backup_v2_evidence` TO 'download_reader'@'%'", "GRANT 'role'@'%' TO 'download_reader'@'%'", good[2] + " WITH GRANT OPTION", "GRANT SELECT ON `other`.`system_backup_v2_backups` TO 'download_reader'@'%'"} {
		if downloadGrantShape(c, append(append([]string(nil), good...), extra)) == nil {
			t.Fatal("overbroad grant accepted", extra)
		}
	}
	if downloadGrantShape(c, append(append([]string(nil), good[:1]...), good[2:]...)) == nil {
		t.Fatal("missing locking privilege accepted")
	}
	if downloadGrantShape(c, good[:len(good)-1]) == nil {
		t.Fatal("missing required table privilege accepted")
	}
}
