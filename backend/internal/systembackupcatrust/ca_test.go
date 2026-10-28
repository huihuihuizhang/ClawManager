package systembackupcatrust

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

func sum(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

type fixture struct {
	v          *Validator
	grant      sec.OfflineBootstrapGrant
	config     sec.BootstrapConfig
	server     *httptest.Server
	clock      *time.Time
	handshakes *atomic.Int64
}

func newFixture(t *testing.T, leafExpired bool) fixture {
	t.Helper()
	now := time.Now().UTC()
	clock := now
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"trust-test.invalid"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if leafExpired {
		leaf.NotAfter = now.Add(-time.Minute)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	var handshakes atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("admission issued an HTTP provider request")
		w.WriteHeader(204)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: leafKey}}, GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { handshakes.Add(1); return nil, nil }}
	server.StartTLS()
	t.Cleanup(server.Close)
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	caFile := filepath.Join(dir, "ca.pem")
	if err = os.WriteFile(caFile, ca, 0600); err != nil {
		t.Fatal(err)
	}
	seed, err := os.ReadFile(filepath.Join("..", "systembackupevidence", "testdata", "download_mfa_probe_inputs.json"))
	if err != nil {
		t.Fatal(err)
	}
	var capsule struct {
		Effective json.RawMessage `json:"effective_config"`
	}
	if json.Unmarshal(seed, &capsule) != nil {
		t.Fatal("effective config missing")
	}
	config, err := sec.DecodeBootstrapConfig(capsule.Effective)
	if err != nil {
		t.Fatal(err)
	}
	var pin sec.BootstrapSecretRef
	for _, p := range config.References() {
		if p.Purpose == "evidence_ca" {
			pin = p
		}
	}
	descriptor, err := json.Marshal(map[string]string{"ref_kind": "ca_bundle", "purpose": "evidence_ca", "identity_hash": pin.IdentityHash, "identity_version": pin.Version, "provider_identity_hash": strings.Repeat("b", 64), "scope_hash": strings.Repeat("c", 64), "description_redacted": "synthetic public trust"})
	if err != nil {
		t.Fatal(err)
	}
	descriptorFile := filepath.Join(dir, "reference.json")
	if err = os.WriteFile(descriptorFile, descriptor, 0600); err != nil {
		t.Fatal(err)
	}
	b := Binding{InstallationID: "installation_test", ServerUUID: "00000000-0000-0000-0000-000000000001", Database: "synthetic_test", ConfigSHA256: config.SHA256(), Purpose: "evidence_ca", ProviderIdentityHash: strings.Repeat("b", 64), ScopeHash: strings.Repeat("c", 64), DescriptorFile: descriptorFile, DescriptorSHA256: sum(descriptor), CAFile: caFile, CASHA256: sum(ca), Endpoint: "https://trust-test.invalid:" + endpoint.Port(), TargetIP: netip.MustParseAddr("127.0.0.1"), NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(2 * time.Minute)}
	v, err := New(b)
	if err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return clock }
	g := sec.OfflineBootstrapGrant{InstallationID: b.InstallationID, ServerUUID: b.ServerUUID, Database: b.Database, ConfigSHA256: b.ConfigSHA256}
	return fixture{v, g, config, server, &clock, &handshakes}
}

func TestCAAdmissionUsesActualTLSAndRechecksWithoutNetworkOrCommit(t *testing.T) {
	f := newFixture(t, false)
	prepared, err := f.v.Prepare(context.Background(), f.grant, f.config)
	if err != nil {
		t.Fatal("real TLS admission failed", err)
	}
	if f.handshakes.Load() != 1 {
		t.Fatal("exact TLS target not contacted once")
	}
	f.server.Close()
	tx, state := transaction(t, f.grant.ServerUUID, f.grant.Database)
	if err = prepared.Recheck(context.Background(), tx, *f.clock); err != nil {
		t.Fatal("local recheck failed", err)
	}
	if f.handshakes.Load() != 1 || state.queries != 1 || state.commits != 0 || state.rollbacks != 0 {
		t.Fatal("recheck contacted provider, changed SQL state or skipped identity")
	}
	*f.clock = f.clock.Add(31 * time.Second)
	if prepared.Recheck(context.Background(), tx, *f.clock) == nil {
		t.Fatal("stale TLS observation accepted")
	}
}

func TestCAAdmissionRejectsUntrustedTLSAndChangedLocalInputs(t *testing.T) {
	for _, name := range []string{"expired_leaf", "wrong_hostname", "wrong_CA", "junk_CA", "private_key_block", "changed_descriptor", "wrong_scope", "wrong_installation", "canceled"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, name == "expired_leaf")
			ctx := context.Background()
			g := f.grant
			switch name {
			case "wrong_hostname":
				f.v.host = "wrong.invalid"
			case "wrong_CA":
				other := newFixture(t, false)
				raw, err := os.ReadFile(other.v.binding.CAFile)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(f.v.binding.CAFile, raw, 0600); err != nil {
					t.Fatal(err)
				}
				f.v.binding.CASHA256 = sum(raw)
			case "junk_CA", "private_key_block":
				raw, err := os.ReadFile(f.v.binding.CAFile)
				if err != nil {
					t.Fatal(err)
				}
				if name == "junk_CA" {
					raw = append([]byte("not a certificate\n"), raw...)
				} else {
					raw = append(raw, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("synthetic")})...)
				}
				if err = os.WriteFile(f.v.binding.CAFile, raw, 0600); err != nil {
					t.Fatal(err)
				}
				f.v.binding.CASHA256 = sum(raw)
			case "changed_descriptor":
				if err := os.WriteFile(f.v.binding.DescriptorFile, []byte(`{}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong_scope":
				f.v.binding.ScopeHash = strings.Repeat("d", 64)
			case "wrong_installation":
				g.InstallationID = "installation_other"
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if check, err := f.v.Prepare(ctx, g, f.config); err != sec.ErrRegistrationUnavailable || check != nil {
				t.Fatal("untrusted admission did not fail closed")
			}
		})
	}
}

func TestCARecheckRejectsRevokedBytesWrongDatabaseAndCanceledRead(t *testing.T) {
	for _, name := range []string{"removed_CA", "changed_CA", "changed_descriptor", "database", "server", "canceled_during_SQL", "expiry_during_SQL", "expired_mapping", "old_SQL_clock"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, false)
			prepared, err := f.v.Prepare(context.Background(), f.grant, f.config)
			if err != nil {
				t.Fatal(err)
			}
			f.server.Close()
			server, database := f.grant.ServerUUID, f.grant.Database
			now := *f.clock
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch name {
			case "removed_CA":
				if err = os.Remove(f.v.binding.CAFile); err != nil {
					t.Fatal(err)
				}
			case "changed_CA":
				if err = os.WriteFile(f.v.binding.CAFile, []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "changed_descriptor":
				if err = os.WriteFile(f.v.binding.DescriptorFile, []byte(`{}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "database":
				database = "other"
			case "server":
				server = "00000000-0000-0000-0000-000000000002"
			case "expired_mapping":
				*f.clock = f.clock.Add(3 * time.Minute)
			case "old_SQL_clock":
				now = now.Add(-time.Second)
			}
			tx, state := transaction(t, server, database)
			if name == "canceled_during_SQL" {
				state.cancel = cancel
			}
			if name == "expiry_during_SQL" {
				state.cancel = func() { *f.clock = f.clock.Add(31 * time.Second) }
			}
			if prepared.Recheck(ctx, tx, now) != sec.ErrRegistrationUnavailable {
				t.Fatal("invalid recheck accepted")
			}
			if f.handshakes.Load() != 1 || state.commits != 0 || state.rollbacks != 0 {
				t.Fatal("failure performed external work or ended caller transaction")
			}
		})
	}
}

func TestCATrustBindingRejectsUncontrolledEndpointsAndFormatting(t *testing.T) {
	f := newFixture(t, false)
	for _, endpoint := range []string{"http://trust-test.invalid", "https://u:p@trust-test.invalid", "https://trust-test.invalid/path", "https://trust-test.invalid?", "https://trust-test.invalid?q=x", "https://trust-test.invalid#x", "https://trust-test.invalid:0"} {
		b := f.v.binding
		b.Endpoint = endpoint
		if v, err := New(b); v != nil || err != sec.ErrRegistrationUnavailable {
			t.Fatal("uncontrolled endpoint accepted")
		}
	}
	if fmt.Sprintf("%v %#v", f.v, f.v) != "BootstrapCATrustValidator BootstrapCATrustValidator" {
		t.Fatal("formatting exposed deployment binding")
	}
	if _, err := json.Marshal(f.v); err == nil {
		t.Fatal("JSON exposed endpoint or file names")
	}
	if _, err := (*Validator)(nil).Prepare(context.Background(), f.grant, f.config); err == nil {
		t.Fatal("nil validator accepted")
	}
}

func TestCATrustBindingNeverFormatsOrSerializesDeploymentPins(t *testing.T) {
	b := Binding{
		InstallationID: "PRIVATE_INSTALLATION_SENTINEL", ServerUUID: "PRIVATE_SERVER_SENTINEL", Database: "PRIVATE_DATABASE_SENTINEL", ConfigSHA256: "PRIVATE_CONFIG_SENTINEL",
		Purpose: "evidence_ca", ProviderIdentityHash: "PRIVATE_PROVIDER_SENTINEL", ScopeHash: "PRIVATE_SCOPE_SENTINEL",
		DescriptorFile: "PRIVATE_DESCRIPTOR_SENTINEL", DescriptorSHA256: "PRIVATE_DESCRIPTOR_PIN_SENTINEL", CAFile: "PRIVATE_CA_SENTINEL", CASHA256: "PRIVATE_CA_PIN_SENTINEL",
		Endpoint: "https://PRIVATE_ENDPOINT_SENTINEL.invalid", TargetIP: netip.MustParseAddr("192.0.2.42"), NotBefore: time.Unix(1000, 0), ExpiresAt: time.Unix(2000, 0),
	}
	for _, item := range []struct {
		name  string
		value any
	}{{"value", b}, {"pointer", &b}} {
		for _, format := range []struct{ name, verb string }{{"default", "%v"}, {"detailed", "%+v"}, {"Go", "%#v"}} {
			t.Run(item.name+"/"+format.name, func(t *testing.T) {
				if fmt.Sprintf(format.verb, item.value) != "BootstrapCATrustBinding" {
					t.Fatal("deployment Binding escaped constant formatting boundary")
				}
			})
		}
		t.Run(item.name+"/json", func(t *testing.T) {
			raw, err := json.Marshal(item.value)
			if err == nil || len(raw) != 0 || strings.Contains(err.Error(), "PRIVATE_") {
				t.Fatal("deployment Binding escaped JSON rejection boundary")
			}
		})
	}
}

type sqlState struct {
	server, database            string
	queries, commits, rollbacks int
	cancel                      context.CancelFunc
}
type testDriver struct{ s *sqlState }
type testConn struct{ s *sqlState }
type testTx struct{ s *sqlState }
type testRows struct {
	values []driver.Value
	done   bool
}

func (d testDriver) Open(string) (driver.Conn, error)   { return &testConn{d.s}, nil }
func (c *testConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unexpected prepare") }
func (c *testConn) Close() error                        { return nil }
func (c *testConn) Begin() (driver.Tx, error)           { return &testTx{c.s}, nil }
func (c *testConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if query != "SELECT @@server_uuid,DATABASE()" || len(args) != 0 {
		return nil, errors.New("unexpected SQL")
	}
	c.s.queries++
	if c.s.cancel != nil {
		c.s.cancel()
	}
	return &testRows{values: []driver.Value{c.s.server, c.s.database}}, nil
}
func (t *testTx) Commit() error       { t.s.commits++; return nil }
func (t *testTx) Rollback() error     { t.s.rollbacks++; return nil }
func (r *testRows) Columns() []string { return []string{"server", "database"} }
func (r *testRows) Close() error      { return nil }
func (r *testRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	copy(dest, r.values)
	r.done = true
	return nil
}

var driverID atomic.Int64

func transaction(t *testing.T, server, database string) (*sql.Tx, *sqlState) {
	t.Helper()
	state := &sqlState{server: server, database: database}
	name := fmt.Sprintf("ca-trust-%d", driverID.Add(1))
	sql.Register(name, testDriver{state})
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	return tx, state
}
