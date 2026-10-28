//go:build systembackup_mysql

package systembackupevidence

// Actual original file/nonce/CA/capacity APIs composed with real A/D. The
// deployment/purpose/provider mapping and physical report remain explicitly
// synthetic. No HTTP route, production permission or arbitrary DSN is added.
import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ca "clawreef/internal/systembackupcatrust"
	nonce "clawreef/internal/systembackupnoncebootstrap"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

type bootstrapOriginalProfile struct {
	config             sec.BootstrapConfig
	deployment         sec.BootstrapDeploymentConfig
	paths              map[string]string
	nonceBinding       nonce.Binding
	caBindings         []ca.Binding
	handshakes         *atomic.Int64
	notBefore, expires time.Time
}

func bootstrapOriginalProfileFiles(t *testing.T, raw json.RawMessage, scope pd.Scope) *bootstrapOriginalProfile {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	p := &bootstrapOriginalProfile{paths: map[string]string{}, handshakes: &atomic.Int64{}, notBefore: now.Add(-time.Minute), expires: now.Add(4 * time.Minute)}
	dir := t.TempDir()
	var fields map[string]json.RawMessage
	mustSQL(t, json.Unmarshal(raw, &fields))
	var regs []sec.BootstrapRegistryRef
	mustSQL(t, json.Unmarshal(fields["registries"], &regs))
	registryBytes := map[string][]byte{}
	for i, r := range regs {
		b := []byte(`{"synthetic":true}`)
		if r.Kind == "rbac_bindings" {
			b, _ = json.Marshal(map[string]any{"schema_version": "system-backup-registration-rbac.draft.v1", "version": r.Version, "installation_id": scope.Installation, "bindings": []map[string]string{{"actor_id": "42", "subject": "user:42", "role": "security_admin"}}})
		}
		regs[i].SHA256 = hash(b)
		registryBytes[r.Kind] = b
	}
	fields["registries"], _ = json.Marshal(regs)
	encoded, err := json.Marshal(fields)
	mustSQL(t, err)
	p.config, err = sec.DecodeBootstrapConfig(encoded)
	mustSQL(t, err)
	p.deployment = sec.BootstrapDeploymentConfig{SchemaVersion: "system-backup-bootstrap-deployment.v1", InstallationID: string(scope.Installation), ExpectedServerUUID: string(scope.ServerUUID), ExpectedDatabase: string(scope.Database), ConfigSHA256: p.config.SHA256(), GrantFile: filepath.Join(dir, "original-grant.json"), RegistryDirectory: filepath.Join(dir, "registries")}
	p.paths["grant"] = p.deployment.GrantFile
	for _, r := range regs {
		path := filepath.Join(p.deployment.RegistryDirectory, r.Kind, r.Version, r.SHA256+".json")
		mustSQL(t, os.MkdirAll(filepath.Dir(path), 0700))
		mustSQL(t, os.WriteFile(path, registryBytes[r.Kind], 0600))
		p.paths[r.Kind] = path
	}
	p.nonceBinding = nonce.Binding{InstallationID: string(scope.Installation), ServerUUID: string(scope.ServerUUID), Database: string(scope.Database), ConfigSHA256: p.config.SHA256(), NotBefore: p.notBefore, ExpiresAt: p.expires}
	var active sec.BootstrapSecretRef
	for _, r := range p.config.References() {
		if r.Purpose == "nonce_hmac" {
			active = r
		}
	}
	old := sec.BootstrapSecretRef{Purpose: "nonce_hmac", IdentityHash: hash([]byte("original synthetic retained nonce identity")), Version: "retained-original-v0"}
	for i, r := range []sec.BootstrapSecretRef{active, old} {
		desc, e := json.Marshal(map[string]string{"ref_kind": "external_secret", "purpose": "strong_auth_nonce_hmac", "identity_hash": r.IdentityHash, "identity_version": r.Version, "provider_identity_hash": strings.Repeat("b", 64), "scope_hash": strings.Repeat("c", 64), "description_redacted": "synthetic original nonce reference", "read_mode": "exact_version_only"})
		mustSQL(t, e)
		key := make([]byte, 32)
		_, e = rand.Read(key)
		mustSQL(t, e)
		descPath, keyPath := filepath.Join(dir, "nonce-"+strconv.Itoa(i)+".json"), filepath.Join(dir, "nonce-"+strconv.Itoa(i)+".key")
		mustSQL(t, os.WriteFile(descPath, desc, 0600))
		mustSQL(t, os.WriteFile(keyPath, key, 0600))
		p.nonceBinding.Keys = append(p.nonceBinding.Keys, nonce.Key{IdentityHash: r.IdentityHash, Version: r.Version, ProviderIdentityHash: strings.Repeat("b", 64), ScopeHash: strings.Repeat("c", 64), DescriptorFile: descPath, DescriptorSHA256: hash(desc), MaterialFile: keyPath, MaterialSHA256: hash(key), ProtectedUntil: now.Add(48 * time.Hour)})
		for j := range key {
			key[j] = 0
		}
		if i == 0 {
			p.paths["nonce_material"], p.paths["nonce_descriptor"] = keyPath, descPath
		} else {
			p.paths["retained_material"] = keyPath
		}
	}
	// A real loopback TLS handshake, with a synthetic CA and no HTTP request.
	rootKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mustSQL(t, e)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic original material CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, e := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	mustSQL(t, e)
	leafKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mustSQL(t, e)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"original-materials.invalid"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, e := x509.CreateCertificate(rand.Reader, leaf, root, &leafKey.PublicKey, rootKey)
	mustSQL(t, e)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("material validation issued an HTTP request") }))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: leafKey}}, GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { p.handshakes.Add(1); return nil, nil }}
	server.StartTLS()
	t.Cleanup(server.Close)
	endpoint, e := url.Parse(server.URL)
	mustSQL(t, e)
	caBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	for _, r := range p.config.References() {
		if r.Purpose != "artifact_ca" && r.Purpose != "evidence_ca" {
			continue
		}
		desc, e := json.Marshal(map[string]string{"ref_kind": "ca_bundle", "purpose": r.Purpose, "identity_hash": r.IdentityHash, "identity_version": r.Version, "provider_identity_hash": strings.Repeat("b", 64), "scope_hash": strings.Repeat("c", 64), "description_redacted": "synthetic original public trust"})
		mustSQL(t, e)
		descPath, caPath := filepath.Join(dir, r.Purpose+".json"), filepath.Join(dir, r.Purpose+".pem")
		mustSQL(t, os.WriteFile(descPath, desc, 0600))
		mustSQL(t, os.WriteFile(caPath, caBytes, 0600))
		p.paths[r.Purpose+"_descriptor"], p.paths[r.Purpose+"_pem"] = descPath, caPath
		p.caBindings = append(p.caBindings, ca.Binding{InstallationID: string(scope.Installation), ServerUUID: string(scope.ServerUUID), Database: string(scope.Database), ConfigSHA256: p.config.SHA256(), Purpose: r.Purpose, ProviderIdentityHash: strings.Repeat("b", 64), ScopeHash: strings.Repeat("c", 64), DescriptorFile: descPath, DescriptorSHA256: hash(desc), CAFile: caPath, CASHA256: hash(caBytes), Endpoint: "https://original-materials.invalid:" + endpoint.Port(), TargetIP: netip.MustParseAddr("127.0.0.1"), NotBefore: p.notBefore, ExpiresAt: p.expires})
	}
	if len(p.caBindings) != 2 || active.IdentityHash == "" {
		t.Fatal("complete nonce/CA profile missing")
	}
	return p
}

func (p *bootstrapOriginalProfile) grantFile(t *testing.T, g sec.OfflineBootstrapGrant) {
	b, e := json.Marshal(sec.BootstrapGrantFile{SchemaVersion: "system-backup-offline-bootstrap-grant.v1", NotBefore: p.notBefore, ExpiresAt: p.expires, Grant: g})
	mustSQL(t, e)
	mustSQL(t, os.WriteFile(p.deployment.GrantFile, b, 0600))
	p.deployment.GrantSHA256 = hash(b)
}

type bootstrapOriginalAuthority struct {
	base          *bootstrapMySQLAuthority
	profile       *bootstrapOriginalProfile
	nonce         *nonce.Validator
	cas           []*ca.Validator
	mode          string
	preparedTLS   int64
	preparedReady bool
}
type bootstrapOriginalSession struct {
	sec.BootstrapCandidateAuthoritySession
	owner              *bootstrapOriginalAuthority
	nonce              *nonce.PreparedCandidateNonce
	cas                []*ca.PreparedCandidateCA
	lockedNonce        *nonce.CandidateNonceCheck
	lockedCAs          []*ca.CandidateCACheck
	preparedHandshakes int64
}

func (a *bootstrapOriginalAuthority) PrepareBootstrapCandidates(ctx context.Context, g sec.OfflineBootstrapGrant, c sec.BootstrapConfig, r pd.BootstrapConsumptionRequest) (sec.PreparedBootstrapCandidateAuthority, error) {
	base, err := a.base.PrepareBootstrapCandidates(ctx, g, c, r)
	if err != nil {
		return base, err
	}
	s := &bootstrapOriginalSession{BootstrapCandidateAuthoritySession: base.Session, owner: a}
	// Every attempt really calls the original material APIs before BEGIN.
	// Their closed prepared result on physical failure must not preempt L3
	// exact history. Only new-use LockReferences requires successful material.
	s.nonce, err = a.nonce.PrepareCandidateAttempt(ctx, g, c)
	if err != nil {
		return sec.PreparedBootstrapCandidateAuthority{}, err
	}
	for _, v := range a.cas {
		p, e := v.PrepareCandidateAttempt(ctx, g, c)
		if e != nil {
			return sec.PreparedBootstrapCandidateAuthority{}, e
		}
		s.cas = append(s.cas, p)
	}
	s.preparedHandshakes = a.profile.handshakes.Load()
	a.preparedTLS = s.preparedHandshakes
	a.preparedReady = s.nonce != nil && s.nonce.DependencyDeadline() != nil && len(s.cas) == 2
	for _, c := range s.cas {
		a.preparedReady = a.preparedReady && c.DependencyDeadline() != nil
	}
	a.base.f.t.Logf("ORIGINAL_PREPARE branch=physical tls_total=%d material_apis=real", s.preparedHandshakes)
	base.Session = s
	return base, nil
}
func (s *bootstrapOriginalSession) Authorize(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, d pd.DomainRecord, now time.Time) (pd.BootstrapConsumptionAdmission, error) {
	a, err := s.BootstrapCandidateAuthoritySession.Authorize(ctx, tx, r, d, now)
	if err != nil {
		return a, err
	}
	add := func(v *pd.Timestamp) {
		if v != nil && *v < a.DependencyExpiresAt {
			a.DependencyExpiresAt = *v
		}
	}
	if s.nonce != nil {
		add(s.nonce.DependencyDeadline())
	}
	for _, v := range s.cas {
		add(v.DependencyDeadline())
	}
	return a, nil
}
func (s *bootstrapOriginalSession) LockReferences(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts) error {
	if s.nonce == nil || len(s.cas) != 2 {
		return pd.ErrGuardRequired
	}
	if err := s.BootstrapCandidateAuthoritySession.LockReferences(ctx, tx, r, f); err != nil {
		return err
	}
	var err error
	s.lockedNonce, err = s.nonce.LockReferences(ctx, tx)
	if err != nil {
		return err
	}
	for _, v := range s.cas {
		c, e := v.CheckCandidate(ctx, tx)
		if e != nil {
			return e
		}
		s.lockedCAs = append(s.lockedCAs, c)
	}
	if s.owner.profile.handshakes.Load() != s.preparedHandshakes {
		return pd.ErrGuardRequired
	}
	return nil
}
func (s *bootstrapOriginalSession) Recheck(ctx context.Context, tx pd.BootstrapReadSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts, now time.Time) error {
	if f.Replayed {
		return s.BootstrapCandidateAuthoritySession.Recheck(ctx, tx, r, f, now)
	}
	if s.owner.mode == "resource_wait" {
		var waited int
		if err := tx.QueryRowContext(ctx, "SELECT SLEEP(3.2)").Scan(&waited); err != nil {
			return err
		}
		if waited != 0 {
			return pd.ErrGuardRequired
		}
		s.owner.base.f.t.Log("ORIGINAL_RESOURCE_WAIT original_bound_preserved=yes duration_ms=3200")
	}
	if s.owner.mode == "late_retained_ledger" {
		var changed int
		if err := tx.QueryRowContext(ctx, "SELECT original_retained_mutate()").Scan(&changed); err != nil || changed != 1 {
			s.owner.base.f.t.Fatal("retained ledger mutation not stored", changed, err)
		}
		s.owner.base.f.t.Log("ORIGINAL_MATERIAL_CHANGED kind=retained_ledger stage=work_end")
	} else if strings.HasPrefix(s.owner.mode, "late_") {
		key := strings.TrimPrefix(s.owner.mode, "late_")
		if key == "grant_replace" {
			key = "grant"
		}
		path := s.owner.profile.paths[key]
		if path == "" {
			return pd.ErrGuardRequired
		}
		if key == "grant" && s.owner.mode != "late_grant_replace" {
			if err := os.Remove(path); err != nil {
				return err
			}
		} else {
			b, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			if e = os.WriteFile(path, append(b, '\n'), 0600); e != nil {
				return e
			}
		}
		s.owner.base.f.t.Log("ORIGINAL_MATERIAL_CHANGED kind=" + key + " stage=work_end")
	}
	if s.lockedNonce == nil || len(s.lockedCAs) != 2 {
		return pd.ErrGuardRequired
	}
	if err := s.lockedNonce.Recheck(ctx, tx); err != nil {
		return err
	}
	for _, c := range s.lockedCAs {
		if err := c.Recheck(ctx, tx); err != nil {
			return err
		}
	}
	if s.owner.profile.handshakes.Load() != s.preparedHandshakes {
		return pd.ErrGuardRequired
	}
	return s.BootstrapCandidateAuthoritySession.Recheck(ctx, tx, r, f, now)
}

// New database/new lifecycle: this fixture NEVER alters committed dummy-hash
// records to impersonate an original file profile. The small preliminary
// manifest only obtains the fixed synthetic installation identity.
func bootstrapOriginalFixture(t *testing.T, actual bool) (sec.ConfigBootstrapService, *bootstrapMySQLAuthority, *bootstrapOriginalProfile, *atomic.Bool) {
	capsule := bootstrapMySQLInput(t)
	var db *sql.DB
	var lost *atomic.Bool
	if actual {
		raw, e := os.ReadFile(os.Getenv("D_PROVIDER_REGISTRATION_DDL"))
		mustSQL(t, e)
		if !reflect.DeepEqual(raw, bootstrapConsumerMySQLInputs) || hash(raw) != os.Getenv("D_PROVIDER_REGISTRATION_DDL_SHA256") {
			t.Fatal("compiled capsule mismatch")
		}
		path := filepath.Join(t.TempDir(), "candidate.sql")
		mustSQL(t, os.WriteFile(path, []byte(capsule.DDL), 0600))
		t.Setenv("D_PROVIDER_REGISTRATION_DDL", path)
		t.Setenv("D_PROVIDER_REGISTRATION_DDL_SHA256", capsule.DDLSHA)
		db, lost = dProducerMySQLDB(t)
		var checks int
		mustSQL(t, db.QueryRow("SELECT @@session.foreign_key_checks").Scan(&checks))
		if checks != 1 {
			t.Fatal("actual FK checks required")
		}
		rows, e := db.Query("SELECT filename FROM clawmanager.schema_migrations ORDER BY filename")
		mustSQL(t, e)
		var names []string
		for rows.Next() {
			var n string
			mustSQL(t, rows.Scan(&n))
			names = append(names, n)
		}
		mustSQL(t, rows.Err())
		mustSQL(t, rows.Close())
		if !reflect.DeepEqual(names, capsule.Migrations) {
			t.Fatal("formal migration ledger differs")
		}
		for _, table := range []string{"users", "audit_logs", "system_backup_v2_evidence", "system_backup_v2_evidence_chunks", "system_backup_v2_configs", "system_backup_v2_installation_state", "system_backup_v2_operations", "system_backup_v2_metadata_reservations", "system_backup_v2_strong_auth_nonces"} {
			var name, ddl string
			mustSQL(t, db.QueryRow("SHOW CREATE TABLE clawmanager."+table).Scan(&name, &ddl))
			if name != table || !strings.HasPrefix(ddl, "CREATE TABLE `"+table+"`") {
				t.Fatal("canonical table differs")
			}
			_, e = db.Exec(ddl)
			mustSQL(t, e)
		}
		_, e = db.Exec("INSERT INTO users(id,username,email,password_hash,role,is_active,auth_provider) VALUES(42,'bootstrap-probe','original-materials@example.invalid','synthetic-noncredential','admin',TRUE,'local')")
		mustSQL(t, e)
		t.Log("ORIGINAL_FIXTURE migrations=96 candidate_tables=8 full_canonical_A_tables=9 foreign_key_checks=1 authority=synthetic_original_mapping material_APIs=real")
	}
	bootstrapMySQLProfile(t, capsule)
	_, _, _, binding := producerBindingFixture(t)
	command, e := pd.DecodeCommand(dIntegrationVector(t, "commands", "acquire"))
	mustSQL(t, e)
	scope := command.Scope
	scope.Installation = binding.OwnerID
	if actual {
		scope, e = dIntegrationDatabaseScope(context.Background(), db, scope)
		mustSQL(t, e)
	}
	p := bootstrapOriginalProfileFiles(t, capsule.Config, scope)
	capsule.Config = p.config.CanonicalJSON()
	c := bootstrapMySQLProfile(t, capsule)
	f := newDIntegrationFixtureWithDB(t, db)
	f.advance("pending", "claim", "finish", "result")
	if actual {
		dMySQLReceipt(t, f)
	}
	_, base := bootstrapMySQLPlan(t, f, c)
	p.grantFile(t, base.g)
	n, e := nonce.New(p.nonceBinding)
	mustSQL(t, e)
	inner := &bootstrapOriginalAuthority{base: base, profile: p, nonce: n}
	for _, b := range p.caBindings {
		v, e := ca.New(b)
		mustSQL(t, e)
		inner.cas = append(inner.cas, v)
	}
	authority, e := sec.NewBootstrapCandidateFileAuthority(p.deployment, inner)
	mustSQL(t, e)
	plan, e := sec.NewConfigBootstrapCandidates(f.db, base.g, c.CanonicalJSON(), base.selection, authority)
	mustSQL(t, e)
	return sec.ConfigBootstrapService{DB: f.db, Candidates: plan}, base, p, lost
}

func bootstrapOriginalRequest(a *bootstrapMySQLAuthority) pd.BootstrapConsumptionRequest {
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(a.c.CanonicalJSON(), &fields)
	g, _ := json.Marshal(a.g)
	return pd.BootstrapConsumptionRequest{Scope: a.f.command.Scope, OfflineGrantHash: pd.Hash(hash(g)), ConfigHash: pd.Hash(a.c.SHA256()), RegistrySetHash: pd.Hash(hash(fields["registries"])), RefSetHash: pd.Hash(hash(fields["references"])), ActorID: "42", Username: a.g.Username, MatrixKey: a.g.MatrixKey, Endpoint: sec.BootstrapConfigEndpoint, IdempotencyKey: a.g.IdempotencyKey, Candidates: a.selection}
}

func TestDBootstrapOriginalMaterialsMySQLSeed(t *testing.T) {
	_, a, p, _ := bootstrapOriginalFixture(t, false)
	n, e := nonce.New(p.nonceBinding)
	mustSQL(t, e)
	inner := &bootstrapOriginalAuthority{base: a, profile: p, nonce: n}
	for _, b := range p.caBindings {
		v, e := ca.New(b)
		mustSQL(t, e)
		inner.cas = append(inner.cas, v)
	}
	authority, e := sec.NewBootstrapCandidateFileAuthority(p.deployment, inner)
	mustSQL(t, e)
	prepared, e := authority.PrepareBootstrapCandidates(context.Background(), a.g, a.c, bootstrapOriginalRequest(a))
	mustSQL(t, e)
	if prepared.Session == nil || prepared.CapacityObservedAt == nil || p.handshakes.Load() != 2 || !inner.preparedReady {
		t.Fatal("original file/nonce/CA preparation incomplete")
	}
	t.Log("PASS bootstrap-original-materials-seed new_compatible_lifecycle=yes original_files=yes nonce_material=actual_owned_bytes ca_tls=actual_loopback handshakes=2 actual_mysql=not_run production=no")
}

func TestDBootstrapOriginalMaterialsMySQL(t *testing.T) {
	for _, mode := range []string{"commit_replay", "commit_lost", "replay_missing_nonce", "replay_missing_ca", "replay_missing_nonrbac", "replay_grant_removed", "replay_rbac_changed", "missing_nonce_new", "missing_ca_new", "late_grant", "late_grant_replace", "late_rbac_bindings", "late_nonce_material", "late_retained_material", "late_nonce_descriptor", "late_evidence_ca_descriptor", "late_evidence_ca_pem", "late_parts", "retained_nonce_commit", "retained_unknown_rejected", "late_retained_ledger", "resource_wait"} {
		t.Run(mode, func(t *testing.T) {
			svc, a, p, lost := bootstrapOriginalFixture(t, true)
			// Retrieve only the test-owned composite; production wrappers remain
			// opaque. Set the hook through the fixed original object, not reflection.
			n, e := nonce.New(p.nonceBinding)
			mustSQL(t, e)
			inner := &bootstrapOriginalAuthority{base: a, profile: p, nonce: n, mode: mode}
			if mode == "resource_wait" {
				// Fix shorter ORIGINAL resource bounds before Prepare; never edit
				// a prepared observation or extend it after the controlled SQL wait.
				until := time.Now().UTC().Add(3 * time.Second)
				binding := p.nonceBinding
				binding.ExpiresAt = until
				inner.nonce, e = nonce.New(binding)
				mustSQL(t, e)
			}
			for _, b := range p.caBindings {
				v, e := ca.New(b)
				mustSQL(t, e)
				inner.cas = append(inner.cas, v)
			}
			authority, e := sec.NewBootstrapCandidateFileAuthority(p.deployment, inner)
			mustSQL(t, e)
			plan, e := sec.NewConfigBootstrapCandidates(a.f.db, a.g, a.c.CanonicalJSON(), a.selection, authority)
			mustSQL(t, e)
			svc.Candidates = plan
			if mode == "retained_nonce_commit" || mode == "retained_unknown_rejected" || mode == "late_retained_ledger" {
				version := p.nonceBinding.Keys[1].Version
				if mode == "retained_unknown_rejected" {
					version = "unknown-retained-v0"
				}
				bootstrapOriginalRetained(t, a, version)
				if mode == "late_retained_ledger" {
					_, e = a.f.db.Exec("CREATE FUNCTION original_retained_mutate() RETURNS INT DETERMINISTIC MODIFIES SQL DATA BEGIN UPDATE system_backup_v2_strong_auth_nonces SET nonce_hmac_key_version='unknown-late-v0'; RETURN ROW_COUNT(); END")
					mustSQL(t, e)
				}
			}
			if strings.HasPrefix(mode, "replay_") {
				first, e := bootstrapMySQLCall(svc, a)
				mustSQL(t, e)
				bootstrapMySQLCommitted(t, a)
				path := p.paths["nonce_material"]
				switch mode {
				case "replay_missing_ca":
					path = p.paths["evidence_ca_pem"]
				case "replay_missing_nonrbac":
					path = p.paths["parts"]
				case "replay_grant_removed":
					path = p.paths["grant"]
				case "replay_rbac_changed":
					path = p.paths["rbac_bindings"]
				}
				if mode == "replay_rbac_changed" {
					b, e := os.ReadFile(path)
					mustSQL(t, e)
					mustSQL(t, os.WriteFile(path, append(b, '\n'), 0600))
				} else {
					mustSQL(t, os.Remove(path))
				}
				before := dMySQLSnapshot(t, a.f.db)
				dialed := p.handshakes.Load()
				r, e := bootstrapMySQLCall(svc, a)
				if p.handshakes.Load() != inner.preparedTLS {
					t.Fatal("TLS occurred after preparation boundary")
				}
				if mode == "replay_grant_removed" || mode == "replay_rbac_changed" {
					if e == nil || r != (sec.ConfigBootstrapResult{}) {
						t.Fatal("revoked original file authority replayed", r, e)
					}
				} else {
					mustSQL(t, e)
					if !r.Replayed || r.OperationPublicID != first.OperationPublicID {
						t.Fatal("physical resource failure prevented exact history", r)
					}
				}
				delta := int64(2)
				if mode == "replay_missing_ca" {
					delta = 1
				}
				if mode == "replay_grant_removed" || mode == "replay_rbac_changed" {
					delta = 0
				}
				if p.handshakes.Load()-dialed != delta {
					t.Fatal("historical attempt did not retain actual original preparation")
				}
				dMySQLUnchanged(t, a.f.db, before)
				if mode == "replay_grant_removed" || mode == "replay_rbac_changed" {
					t.Logf("ORIGINAL_HISTORY result=denied_current_authority capacity_charge=unchanged preparation_tls_delta=%d work_end_tls=none", delta)
				} else {
					t.Logf("ORIGINAL_HISTORY result=locked_exact_read capacity_charge=unchanged preparation_tls_delta=%d work_end_tls=none", delta)
				}
				return
			}
			if mode == "missing_nonce_new" {
				mustSQL(t, os.Remove(p.paths["nonce_material"]))
			}
			if mode == "missing_ca_new" {
				mustSQL(t, os.Remove(p.paths["evidence_ca_pem"]))
			}
			before := dMySQLSnapshot(t, a.f.db)
			if mode == "commit_lost" {
				lost.Store(true)
			}
			r, e := bootstrapMySQLCall(svc, a)
			if p.handshakes.Load() != inner.preparedTLS {
				t.Fatal("TLS occurred after preparation boundary")
			}
			if strings.HasPrefix(mode, "late_") || strings.HasPrefix(mode, "missing_") || mode == "retained_unknown_rejected" || mode == "resource_wait" {
				if e == nil || r != (sec.ConfigBootstrapResult{}) {
					t.Fatal("material mutation exposed success", r, e)
				}
				dMySQLUnchanged(t, a.f.db, before)
				return
			}
			if mode == "commit_lost" {
				if !errors.Is(e, sec.ErrRegistrationCommitUnknown) || r != (sec.ConfigBootstrapResult{}) {
					t.Fatal("commit loss not uncertain", r, e)
				}
			} else {
				mustSQL(t, e)
				if r.Replayed {
					t.Fatal("first material consumption replayed")
				}
			}
			bootstrapMySQLCommitted(t, a)
			committed := dMySQLSnapshot(t, a.f.db)
			dialed := p.handshakes.Load()
			replay, e := bootstrapMySQLCall(svc, a)
			mustSQL(t, e)
			if !replay.Replayed {
				t.Fatal("exact original-materials history not recovered")
			}
			if p.handshakes.Load()-dialed != 2 || p.handshakes.Load() != inner.preparedTLS {
				t.Fatal("retry must prepare original TLS before locks and never redial in Work")
			}
			t.Log("ORIGINAL_HISTORY result=locked_exact_read capacity_charge=unchanged preparation_tls_delta=2 work_end_tls=none")
			dMySQLUnchanged(t, a.f.db, committed)
		})
	}
}

func bootstrapOriginalRetained(t *testing.T, a *bootstrapMySQLAuthority, version string) {
	t.Helper()
	r, e := a.f.db.Exec("INSERT INTO audit_logs(user_id,action,resource_type,details) VALUES(42,'original_materials.retention_fixture','system_backup','{}')")
	mustSQL(t, e)
	id, e := r.LastInsertId()
	mustSQL(t, e)
	var now time.Time
	mustSQL(t, a.f.db.QueryRow("SELECT UTC_TIMESTAMP(6)").Scan(&now))
	h := strings.Repeat("a", 64)
	_, e = a.f.db.Exec(`INSERT INTO system_backup_v2_strong_auth_nonces
(origin_installation_id,issuer_sha256,subject_sha256,session_sha256,nonce_hmac,nonce_hmac_key_version,endpoint,request_hash,idempotency_key,authenticated_at,expires_at,consumed_at,response_sha256,audit_log_id,retain_until)
VALUES ('installation_retained_fixture',?,?,?,?,?,'bootstrapOriginalRetention',?,'original-retained-fixture-0001',?,?,?,?,?,?)`, h, h, h, h, version, h, now, now.Add(time.Minute), now, h, id, now.Add(time.Hour))
	mustSQL(t, e)
	t.Log("ORIGINAL_RETAINED_FIXTURE rows=1 key_relation=global_exact physical_authority=synthetic")
}
