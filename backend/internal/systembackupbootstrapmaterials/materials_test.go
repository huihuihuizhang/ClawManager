package systembackupbootstrapmaterials

// Real temporary nonce files and loopback TLS, synthetic authority/SQL only.
// These tests do not authenticate a deployment or prove InnoDB range locking.
import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
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

	ca "clawreef/internal/systembackupcatrust"
	nonce "clawreef/internal/systembackupnoncebootstrap"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

func digest(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func stamp(t time.Time) pd.Timestamp {
	return pd.Timestamp(t.UTC().Format("2006-01-02T15:04:05.000000Z"))
}

type materialFixture struct {
	m          *Materials
	n          nonce.Binding
	a, e       ca.Binding
	g          sec.OfflineBootstrapGrant
	c          sec.BootstrapConfig
	r          pd.BootstrapConsumptionRequest
	ctx        context.Context
	inner      *syntheticAuthority
	server     *httptest.Server
	handshakes *atomic.Int64
}
type syntheticAuthority struct {
	phases   []string
	deny     string
	capacity time.Time
}

func (a *syntheticAuthority) visit(stage string) error {
	a.phases = append(a.phases, stage)
	if a.deny == stage {
		return sec.ErrRegistrationPermission
	}
	return nil
}
func (a *syntheticAuthority) PrepareBootstrapCandidates(ctx context.Context, g sec.OfflineBootstrapGrant, c sec.BootstrapConfig, r pd.BootstrapConsumptionRequest) (sec.PreparedBootstrapCandidateAuthority, error) {
	if err := a.visit("prepare"); err != nil {
		return sec.PreparedBootstrapCandidateAuthority{}, err
	}
	return sec.PreparedBootstrapCandidateAuthority{Session: a, CapacityObservedAt: &a.capacity}, nil
}
func (a *syntheticAuthority) Authorize(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, d pd.DomainRecord, now time.Time) (pd.BootstrapConsumptionAdmission, error) {
	if err := a.visit("authorize"); err != nil {
		return pd.BootstrapConsumptionAdmission{}, err
	}
	h, err := pd.BootstrapConsumptionHash(r)
	return pd.BootstrapConsumptionAdmission{BindingHash: h, IdentityExpiresAt: stamp(now.Add(time.Hour)), DependencyExpiresAt: stamp(now.Add(time.Hour))}, err
}
func (a *syntheticAuthority) LockHosts(context.Context, pd.BootstrapSQL, pd.BootstrapConsumptionRequest, pd.BootstrapConsumptionFacts) error {
	return a.visit("hosts")
}
func (a *syntheticAuthority) LockReferences(context.Context, pd.BootstrapSQL, pd.BootstrapConsumptionRequest, pd.BootstrapConsumptionFacts) error {
	return a.visit("references")
}
func (a *syntheticAuthority) Reserve(context.Context, pd.BootstrapSQL, pd.BootstrapConsumptionRequest, pd.BootstrapConsumptionFacts) error {
	return a.visit("reserve")
}
func (a *syntheticAuthority) LockEvidence(context.Context, pd.BootstrapSQL, pd.BootstrapConsumptionRequest, pd.BootstrapConsumptionFacts) ([]pd.ResultEvidence, error) {
	return nil, a.visit("evidence")
}
func (a *syntheticAuthority) Recheck(context.Context, pd.BootstrapReadSQL, pd.BootstrapConsumptionRequest, pd.BootstrapConsumptionFacts, time.Time) error {
	return a.visit("recheck")
}

func setupMaterials(t *testing.T) materialFixture {
	t.Helper()
	root := t.TempDir()
	now := time.Now().UTC()
	raw, err := os.ReadFile("../systembackupevidence/testdata/download_mfa_probe_inputs.json")
	if err != nil {
		t.Fatal(err)
	}
	var input struct {
		Effective json.RawMessage `json:"effective_config"`
	}
	if json.Unmarshal(raw, &input) != nil {
		t.Fatal("config capsule")
	}
	c, err := sec.DecodeBootstrapConfig(input.Effective)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, b []byte) string {
		p := filepath.Join(root, name)
		if err := os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"materials.invalid"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	var handshakes atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unexpected HTTP provider call") }))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { handshakes.Add(1); return nil, nil }}
	server.StartTLS()
	t.Cleanup(server.Close)
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	public := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	caFile := write("ca.pem", public)
	n := nonce.Binding{InstallationID: "installation_test", ServerUUID: "00000000-0000-0000-0000-000000000001", Database: "synthetic_test", ConfigSHA256: c.SHA256(), NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(2 * time.Minute)}
	var artifact, evidence ca.Binding
	for _, pin := range c.References() {
		if pin.Purpose != "nonce_hmac" && pin.Purpose != "artifact_ca" && pin.Purpose != "evidence_ca" {
			continue
		}
		purpose, kind := pin.Purpose, "ca_bundle"
		if purpose == "nonce_hmac" {
			purpose = "strong_auth_nonce_hmac"
			kind = "external_secret"
		}
		descriptor := map[string]string{"ref_kind": kind, "purpose": purpose, "identity_hash": pin.IdentityHash, "identity_version": pin.Version, "provider_identity_hash": strings.Repeat("b", 64), "scope_hash": strings.Repeat("c", 64), "description_redacted": "synthetic material"}
		if pin.Purpose == "nonce_hmac" {
			descriptor["read_mode"] = "exact_version_only"
		}
		data, err := json.Marshal(descriptor)
		if err != nil {
			t.Fatal(err)
		}
		file := write(pin.Purpose+".json", data)
		if pin.Purpose == "nonce_hmac" {
			material := bytes.Repeat([]byte{7}, 32)
			n.Keys = []nonce.Key{{IdentityHash: pin.IdentityHash, Version: pin.Version, ProviderIdentityHash: strings.Repeat("b", 64), ScopeHash: strings.Repeat("c", 64), DescriptorFile: file, DescriptorSHA256: digest(data), MaterialFile: write("nonce.key", material), MaterialSHA256: digest(material), ProtectedUntil: now.Add(24 * time.Hour)}}
			continue
		}
		binding := ca.Binding{InstallationID: n.InstallationID, ServerUUID: n.ServerUUID, Database: n.Database, ConfigSHA256: n.ConfigSHA256, Purpose: pin.Purpose, ProviderIdentityHash: strings.Repeat("b", 64), ScopeHash: strings.Repeat("c", 64), DescriptorFile: file, DescriptorSHA256: digest(data), CAFile: caFile, CASHA256: digest(public), Endpoint: "https://materials.invalid:" + endpoint.Port(), TargetIP: netip.MustParseAddr("127.0.0.1"), NotBefore: n.NotBefore, ExpiresAt: n.ExpiresAt}
		if pin.Purpose == "artifact_ca" {
			artifact = binding
		} else {
			evidence = binding
		}
	}
	g := sec.OfflineBootstrapGrant{InstallationID: n.InstallationID, ServerUUID: n.ServerUUID, Database: n.Database, ConfigSHA256: c.SHA256()}
	inner := &syntheticAuthority{capacity: now.Truncate(time.Microsecond)}
	m, err := New(inner, n, artifact, evidence)
	if err != nil {
		t.Fatal(err)
	}
	vectors, err := os.ReadFile("../../../contracts/system-backup/v12/producer-authority-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Positive []struct {
			ID    string          `json:"id"`
			Value json.RawMessage `json:"value"`
		} `json:"positive"`
	}
	if json.Unmarshal(vectors, &doc) != nil {
		t.Fatal("vectors")
	}
	var result pd.ResultRequest
	for _, v := range doc.Positive {
		if v.ID == "unconfigured_signing" {
			result, err = pd.DecodeResult(v.Value)
		}
	}
	if err != nil || result.RunID == "" {
		t.Fatal("vector", err)
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(c.CanonicalJSON(), &fields)
	scope := pd.Scope{ServerUUID: pd.ServerUUID(n.ServerUUID), Database: pd.Database(n.Database), Installation: pd.Installation(n.InstallationID)}
	result.Scope = scope
	result.Evidence.OwnerID = scope.Installation
	result.Admission.Unconfigured.CandidateHash = pd.Hash(c.SHA256())
	result.Admission.Unconfigured.RegistrySetHash = pd.Hash(digest(fields["registries"]))
	result.Admission.Unconfigured.RefSetHash = pd.Hash(digest(fields["references"]))
	r := pd.BootstrapConsumptionRequest{Scope: scope, OfflineGrantHash: pd.Hash(strings.Repeat("d", 64)), ConfigHash: pd.Hash(c.SHA256()), RegistrySetHash: result.Admission.Unconfigured.RegistrySetHash, RefSetHash: result.Admission.Unconfigured.RefSetHash, ActorID: "42", Username: "synthetic", MatrixKey: "k8s-cluster", Endpoint: sec.BootstrapConfigEndpoint, IdempotencyKey: "synthetic-bootstrap-materials", Candidates: []pd.BootstrapCandidateSelection{{Purpose: "capture_signing", ReferenceIdentityHash: pd.Hash(strings.Repeat("e", 64)), ReferenceVersion: "v1", MappingHash: pd.Hash(strings.Repeat("f", 64)), Request: result, ResultVersion: "1"}}}
	if _, err = pd.BootstrapConsumptionHash(r); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return materialFixture{m, n, artifact, evidence, g, c, r, ctx, inner, server, &handshakes}
}

type sqlState struct {
	f                  materialFixture
	now                time.Time
	final              bool
	queries            []string
	commits, rollbacks int
	badRetained        bool
}
type connector struct{ s *sqlState }
type drv struct{}
type conn struct{ s *sqlState }
type txn struct{ s *sqlState }

func (connector) Driver() driver.Driver                                      { return drv{} }
func (c connector) Connect(context.Context) (driver.Conn, error)             { return &conn{c.s}, nil }
func (drv) Open(string) (driver.Conn, error)                                 { return nil, errors.New("connector only") }
func (*conn) Prepare(string) (driver.Stmt, error)                            { return nil, errors.New("unexpected statement") }
func (*conn) Close() error                                                   { return nil }
func (c *conn) Begin() (driver.Tx, error)                                    { return &txn{c.s}, nil }
func (c *conn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) { return c.Begin() }
func (t *txn) Commit() error                                                 { t.s.commits++; return nil }
func (t *txn) Rollback() error                                               { t.s.rollbacks++; return nil }

type rows struct {
	data  [][]driver.Value
	width int
}

func (r *rows) Columns() []string {
	out := make([]string, r.width)
	for i := range out {
		out[i] = fmt.Sprint(i)
	}
	return out
}
func (*rows) Close() error { return nil }
func (r *rows) Next(dest []driver.Value) error {
	if len(r.data) == 0 {
		return io.EOF
	}
	copy(dest, r.data[0])
	r.data = r.data[1:]
	return nil
}
func (c *conn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	s := c.s
	s.queries = append(s.queries, q)
	switch {
	case strings.HasPrefix(q, "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6)"):
		return &rows{[][]driver.Value{{s.f.g.ServerUUID, s.f.g.Database, s.now, int64(0)}}, 4}, nil
	case q == "SELECT @@server_uuid,DATABASE()":
		return &rows{[][]driver.Value{{s.f.g.ServerUUID, s.f.g.Database}}, 2}, nil
	case q == "SELECT UTC_TIMESTAMP(6)":
		return &rows{[][]driver.Value{{s.now}}, 1}, nil
	case strings.HasPrefix(q, "SELECT id,origin_installation_id,version,config_sha256,enabled,nonce_hmac_ref_version,nonce_hmac_identity_hash FROM system_backup_v2_configs FORCE INDEX(uk_sb_config_version) ORDER BY origin_installation_id,version FOR UPDATE"):
		if len(args) != 0 {
			return nil, errors.New("global config scope narrowed")
		}
		r := &rows{width: 7}
		if s.final {
			key := s.f.n.Keys[0]
			r.data = [][]driver.Value{{"1", s.f.g.InstallationID, "1", s.f.c.SHA256(), false, key.Version, key.IdentityHash}}
		}
		return r, nil
	case strings.HasPrefix(q, "SELECT id,nonce_hmac_key_version,retain_until FROM system_backup_v2_strong_auth_nonces"):
		if len(args) != 1 {
			return nil, errors.New("missing fixed retention cutoff")
		}
		version := s.f.n.Keys[0].Version
		if s.badRetained {
			version = "unknown"
		}
		return &rows{[][]driver.Value{{"1", version, s.f.n.ExpiresAt}}, 3}, nil
	default:
		return nil, errors.New("unexpected material SQL")
	}
}

type materialPolicy struct {
	f         materialFixture
	session   sec.BootstrapCandidateAuthoritySession
	replay    bool
	admission pd.BootstrapConsumptionAdmission
}

func (p *materialPolicy) LockAndAuthorize(ctx context.Context, raw pd.SQL, _ pd.Scope) (pd.GuardPlan, error) {
	tx := raw.(pd.BootstrapSQL)
	now, err := tx.SampleTime(ctx)
	if err != nil {
		return pd.GuardPlan{}, err
	}
	p.admission, err = p.session.Authorize(ctx, tx, p.f.r, pd.DomainRecord{}, now)
	if err != nil {
		return pd.GuardPlan{}, err
	}
	deadline, err := p.admission.IdentityExpiresAt.Time()
	if err != nil {
		return pd.GuardPlan{}, err
	}
	if !p.replay {
		facts := pd.BootstrapConsumptionFacts{}
		if err = p.session.LockHosts(ctx, tx, p.f.r, facts); err != nil {
			return pd.GuardPlan{}, err
		}
		if err = p.session.LockReferences(ctx, tx, p.f.r, facts); err != nil {
			return pd.GuardPlan{}, err
		}
		if err = p.session.Reserve(ctx, tx, p.f.r, facts); err != nil {
			return pd.GuardPlan{}, err
		}
		dependency, e := p.admission.DependencyExpiresAt.Time()
		if e != nil {
			return pd.GuardPlan{}, e
		}
		if dependency.Before(deadline) {
			deadline = dependency
		}
	}
	return pd.GuardPlan{BindingHash: p.admission.BindingHash, Deadlines: []time.Time{deadline}}, nil
}
func (*materialPolicy) Recheck(context.Context, pd.ReadSQL, pd.Scope, pd.GuardPlan, time.Time) error {
	return nil
}

func TestMaterialsPreserveOriginalAuthorityAndFinalChecks(t *testing.T) {
	for _, mode := range []string{"normal", "removed_nonce", "removed_CA", "changed_descriptor", "late_expiry", "unknown_retained", "original_deny", "replay_missing", "replay_denied", "wrong_context", "repeat_authorize_copy"} {
		t.Run(mode, func(t *testing.T) {
			f := setupMaterials(t)
			if mode == "replay_missing" || mode == "replay_denied" {
				if err := os.Remove(f.n.Keys[0].MaterialFile); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(f.a.CAFile); err != nil {
					t.Fatal(err)
				}
			}
			prepared, err := f.m.PrepareBootstrapCandidates(f.ctx, f.g, f.c, f.r)
			if err != nil {
				t.Fatal(err)
			}
			f.server.Close() // Any under-lock TLS attempt would fail.
			if mode != "replay_missing" && mode != "replay_denied" && f.handshakes.Load() != 2 {
				t.Fatal("expected real two-purpose TLS", f.handshakes.Load())
			}
			if mode == "original_deny" || mode == "replay_denied" {
				f.inner.deny = "recheck"
			}
			if mode == "wrong_context" {
				f.inner.deny = ""
			}
			state := &sqlState{f: f, now: time.Now().UTC().Truncate(time.Microsecond)}
			if mode == "unknown_retained" {
				state.badRetained = true
			}
			db := sql.OpenDB(connector{state})
			defer db.Close()
			policy := &materialPolicy{f: f, session: prepared.Session, replay: strings.HasPrefix(mode, "replay_")}
			runner, err := pd.NewTransactions(db, f.r.Scope, policy)
			if err != nil {
				t.Fatal(err)
			}
			tx, err := db.BeginTx(f.ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			err = runner.GuardInTx(f.ctx, tx, func(ctx context.Context, guard *pd.Transaction) error {
				if policy.replay {
					return prepared.Session.Recheck(ctx, guard, f.r, pd.BootstrapConsumptionFacts{Replayed: true}, state.now)
				}
				state.final = true
				if _, err := prepared.Session.LockEvidence(ctx, guard, f.r, pd.BootstrapConsumptionFacts{}); err != nil {
					return err
				}
				switch mode {
				case "removed_nonce":
					if err := os.Remove(f.n.Keys[0].MaterialFile); err != nil {
						t.Fatal(err)
					}
				case "removed_CA":
					if err := os.Remove(f.a.CAFile); err != nil {
						t.Fatal(err)
					}
				case "changed_descriptor":
					if err := os.WriteFile(f.e.DescriptorFile, []byte("PRIVATE changed descriptor"), 0600); err != nil {
						t.Fatal(err)
					}
				case "late_expiry":
					state.now = state.now.Add(time.Minute)
				case "wrong_context":
					ctx = context.Background()
				case "repeat_authorize_copy":
					copy := *prepared.Session.(*materialSession)
					_, _ = copy.Authorize(ctx, guard, f.r, pd.DomainRecord{}, state.now)
				}
				return prepared.Session.Recheck(ctx, guard, f.r, pd.BootstrapConsumptionFacts{}, state.now)
			})
			if mode == "normal" || mode == "replay_missing" {
				if err != nil {
					t.Fatal("valid composition rejected", err, f.inner.phases)
				}
				if err = tx.Commit(); err != nil {
					t.Fatal(err)
				}
				if mode == "normal" && strings.Join(f.inner.phases, ",") != "prepare,authorize,hosts,references,reserve,evidence,recheck" {
					t.Fatal("original authority bypassed", f.inner.phases)
				}
				if mode == "replay_missing" && strings.Join(f.inner.phases, ",") != "prepare,authorize,recheck" {
					t.Fatal("history performed resource work", f.inner.phases)
				}
			} else {
				if err == nil {
					t.Fatal("unsafe composition succeeded")
				}
				_ = tx.Rollback()
				if state.commits != 0 {
					t.Fatal("failed composition committed")
				}
			}
		})
	}
}

func TestMaterialsCompositionAndInputInspectionClosed(t *testing.T) {
	f := setupMaterials(t)
	if _, err := New(nil, f.n, f.a, f.e); err == nil {
		t.Fatal("missing authority accepted")
	}
	var missing *syntheticAuthority
	if _, err := New(missing, f.n, f.a, f.e); err == nil {
		t.Fatal("typed nil authority accepted")
	}
	bad := f.a
	bad.InstallationID = "installation_other"
	if _, err := New(f.inner, f.n, bad, f.e); err == nil {
		t.Fatal("cross installation binding accepted")
	}
	if _, err := New(f.inner, f.n, f.e, f.a); err == nil {
		t.Fatal("CA purposes swapped")
	}
	owners, err := f.m.Owners(sec.BootstrapOwnerAdapters{})
	if err != nil {
		t.Fatal(err)
	}
	if len(sec.MissingBootstrapOwnerAdapters(owners)) != 27 {
		t.Fatal("other requirements removed")
	}
	if _, err := f.m.Owners(owners); err == nil {
		t.Fatal("silent replacement accepted")
	}
	if _, err := f.m.PrepareBootstrapCandidates(context.Background(), f.g, f.c, f.r); err == nil {
		t.Fatal("unbounded context accepted")
	}
	statuses := f.m.InspectInputs(f.ctx, f.g, f.c)
	for _, s := range statuses {
		if s.Status != "inputs_checked" {
			t.Fatal(statuses)
		}
	}
	if f.handshakes.Load() != 0 {
		t.Fatal("inspection dialed TLS")
	}
	if err = os.Remove(f.n.Keys[0].MaterialFile); err != nil {
		t.Fatal(err)
	}
	statuses = f.m.InspectInputs(f.ctx, f.g, f.c)
	if statuses[0].Status != "not_ready" || statuses[1].Status != "inputs_checked" || statuses[2].Status != "inputs_checked" {
		t.Fatal(statuses)
	}
	encoded, err := json.Marshal(statuses)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), f.n.Keys[0].MaterialFile) || strings.Contains(string(encoded), f.n.Keys[0].MaterialSHA256) {
		t.Fatal("input diagnostics leaked")
	}
	if _, err = json.Marshal(f.m); err == nil {
		t.Fatal("authority serialized")
	}
}
