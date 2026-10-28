package systembackupsecurity

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

type mutationMaterialDB struct {
	identity   DatabaseIdentity
	versions   []string
	identities map[string]string
	failAt     int
	queries    int
	commits    int
}
type mutationMaterialConnector struct{ s *mutationMaterialDB }

func (c mutationMaterialConnector) Driver() driver.Driver { return registrationTestDriver{} }
func (c mutationMaterialConnector) Connect(context.Context) (driver.Conn, error) {
	return &mutationMaterialConn{c.s}, nil
}

type mutationMaterialConn struct{ s *mutationMaterialDB }

func (*mutationMaterialConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (*mutationMaterialConn) Close() error                        { return nil }
func (c *mutationMaterialConn) Begin() (driver.Tx, error)         { return &mutationMaterialTx{c.s}, nil }
func (c *mutationMaterialConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return c.Begin()
}
func (c *mutationMaterialConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	c.s.queries++
	if c.s.queries == c.s.failAt {
		return nil, errors.New("PRIVATE nonce storage failure")
	}
	switch {
	case q == "SELECT @@server_uuid,DATABASE()":
		return registrationRow(c.s.identity.ServerUUID, c.s.identity.Database), nil
	case strings.HasPrefix(q, "SELECT nonce_hmac_ref_version FROM system_backup_v2_configs"):
		if len(args) != 1 {
			return nil, errors.New("missing retention time")
		}
		rows := &registrationTestRows{width: 1}
		for _, v := range c.s.versions {
			rows.data = append(rows.data, []driver.Value{v})
		}
		return rows, nil
	case q == "SELECT DISTINCT nonce_hmac_ref_version,nonce_hmac_identity_hash FROM system_backup_v2_configs ORDER BY nonce_hmac_ref_version,nonce_hmac_identity_hash":
		versions := make([]string, 0, len(c.s.identities))
		for version := range c.s.identities {
			versions = append(versions, version)
		}
		sort.Strings(versions)
		rows := &registrationTestRows{width: 2}
		for _, v := range versions {
			rows.data = append(rows.data, []driver.Value{v, c.s.identities[v]})
		}
		return rows, nil
	}
	return nil, errors.New("unexpected material SQL")
}

type mutationMaterialTx struct{ s *mutationMaterialDB }

func (t *mutationMaterialTx) Commit() error { t.s.commits++; return nil }
func (*mutationMaterialTx) Rollback() error { return nil }

type mutationMaterialFixture struct {
	source   *ConfigMutationSecurityFiles
	model    *mutationMaterialDB
	tx       *sql.Tx
	current  ConfigValues
	actor    RegistrationActor
	now      time.Time
	provider ProviderIssuerRegistry
	strong   StrongAuthIssuerRegistry
	key      ed25519.PrivateKey
}

func newMutationMaterialFixture(t *testing.T) *mutationMaterialFixture {
	t.Helper()
	now := time.Date(2026, 10, 15, 2, 0, 0, 0, time.UTC)
	identity := DatabaseIdentity{"11111111-2222-3333-4444-555555555555", "synthetic"}
	current, err := DecodeConfigValues(bootstrapFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	m := &mutationMaterialDB{identity: identity, versions: []string{"old", "synthetic-v1"}, identities: map[string]string{"old": registrationHash("synthetic-old-nonce-identity")}}
	for _, ref := range current.References() {
		if ref.Purpose == "nonce_hmac" {
			m.identities[ref.Version] = ref.IdentityHash
		}
	}
	db := sql.OpenDB(mutationMaterialConnector{m})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback() })
	dir := t.TempDir()
	source, err := NewConfigMutationSecurityFiles("installation_synthetic", identity, filepath.Join(dir, "registry"), filepath.Join(dir, "nonce"))
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("s", 32)))
	providerKey := ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))
	provider := ProviderIssuerRegistry{"system-backup-provider-issuers.draft.v1", "provider-v1", ProviderProofScope{"installation_synthetic", "provider-proof"}, []ProviderIssuerRegistryKey{{"provider", "provider-key", "v1", "provider_proof_issuer", providerKey.Public().(ed25519.PublicKey), now.Add(-time.Hour), now.Add(time.Hour), false, []string{"external_action"}, []string{"provider_presence"}}}}
	strong := StrongAuthIssuerRegistry{"system-backup-strong-auth-issuers.draft.v1", "strong-v1", "admin-mfa", []StrongAuthRegistryKey{{"issuer-admin-mfa-v1", "strong-key", "v1", "strong_auth_issuer", key.Public().(ed25519.PublicKey), now.Add(-time.Hour), now.Add(time.Hour), false, IssuerPolicy{[]string{"webauthn"}, []string{}, []string{"webauthn"}}}}}
	f := &mutationMaterialFixture{source, m, tx, current, RegistrationActor{42, "user:42", strings.Repeat("a", 64), now.Add(time.Hour), now.Add(-time.Hour)}, now, provider, strong, key}
	f.persist(t)
	for _, version := range m.versions {
		material := strings.Repeat("n", 32)
		if version == "old" {
			material = strings.Repeat("o", 32)
		}
		f.writeNonce(t, version, []byte(material))
	}
	return f
}
func (f *mutationMaterialFixture) writeNonce(t *testing.T, version string, material []byte) {
	t.Helper()
	path := filepath.Join(f.source.files.NonceDirectory, f.model.identities[version], version)
	if os.MkdirAll(filepath.Dir(path), 0700) != nil || os.WriteFile(path, material, 0600) != nil {
		t.Fatal("nonce fixture write")
	}
}
func (f *mutationMaterialFixture) persist(t *testing.T) {
	t.Helper()
	v := f.current.snapshot.values
	v.Registries = f.current.Registries()
	for i, pin := range v.Registries {
		var value any
		switch pin.Kind {
		case "provider_proof_issuers":
			value, pin.Version = f.provider, f.provider.Version
		case "strong_auth_issuers":
			value, pin.Version = f.strong, f.strong.Version
		default:
			continue
		}
		raw, _ := json.Marshal(value)
		pin.SHA256 = registrationHash(string(raw))
		path := filepath.Join(f.source.files.RegistryDirectory, pin.Kind, pin.Version, pin.SHA256+".json")
		if os.MkdirAll(filepath.Dir(path), 0700) != nil || os.WriteFile(path, raw, 0600) != nil {
			t.Fatal("registry fixture write")
		}
		v.Registries[i] = pin
	}
	raw, _ := json.Marshal(v)
	var err error
	f.current, err = DecodeConfigValues(raw)
	if err != nil {
		t.Fatal(err)
	}
}
func (f *mutationMaterialFixture) load(versions []string) (VerifyConfig, error) {
	return f.source.StrongAuth(context.Background(), f.tx, f.actor, "installation_synthetic", f.current, versions, f.now)
}
func (f *mutationMaterialFixture) proof(t *testing.T, endpoint string) (Proof, RequestBinding) {
	t.Helper()
	p := testProof()
	p.Payload.Audience, p.Payload.Subject, p.Payload.Session = f.strong.Audience, f.actor.Subject, f.actor.Session
	p.Payload.Endpoint, p.Payload.AuthTime, p.Payload.ExpiresAt = endpoint, f.now.Add(-time.Minute).Format(time.RFC3339Nano), f.now.Add(3*time.Minute).Format(time.RFC3339Nano)
	p.Signature.KeyID, p.Signature.KeyVersion = "strong-key", "v1"
	p.Signature.Algorithm = "EdDSA"
	p.Signature.ProtectedHeader = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","key_version":"v1","kid":"strong-key","purpose":"strong_auth_issuer","typ":"` + DomainSeparator + `"}`))
	raw, err := CanonicalPayload(p.Payload)
	if err != nil {
		t.Fatal(err)
	}
	p.Signature.Value = base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.key, []byte(p.Signature.ProtectedHeader+"."+base64.RawURLEncoding.EncodeToString(raw))))
	return p, RequestBinding{p.Payload.Issuer, p.Payload.Audience, p.Payload.Subject, p.Payload.Session, endpoint, p.Payload.RequestHash, p.Payload.IdempotencyKey}
}

func TestConfigMutationMaterialVerifiesRealSignatureAndAllNonceKeys(t *testing.T) {
	f := newMutationMaterialFixture(t)
	for _, endpoint := range []string{ConfigUpdateEndpoint, ConfigRollbackEndpoint} {
		sc, err := f.load(f.model.versions)
		if err != nil {
			t.Fatal(err)
		}
		p, binding := f.proof(t, endpoint)
		v, err := Verify(p, binding, sc)
		if err != nil || v.NonceHMACKeyVersion != "synthetic-v1" || len(v.NonceHMACCandidates) != 2 || f.model.commits != 0 {
			t.Fatal("real crypto/history verification failed", err)
		}
		p.Signature.Value = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		if _, err = Verify(p, binding, sc); err == nil {
			t.Fatal("invalid signature accepted")
		}
	}
	sc, err := f.load(f.model.versions)
	if err != nil {
		t.Fatal(err)
	}
	sc.NonceHMACKeys["old"][0] = 0
	sc.RequiredNonceHMACKeyVersions[0] = "mutated"
	sc2, err := f.load(f.model.versions)
	if err != nil || sc2.NonceHMACKeys["old"][0] != 'o' || sc2.RequiredNonceHMACKeyVersions[0] != "old" {
		t.Fatal("returned material aliases source or caller versions", err)
	}
}

func TestConfigMutationMaterialRejectsPurposeDriftAndHistoricalGaps(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*mutationMaterialFixture)
	}{
		{"cross-purpose-same-public-key", func(f *mutationMaterialFixture) { f.provider.Keys[0].PublicKey = f.strong.Keys[0].PublicKey }},
		{"revoked-provider-key-reuse", func(f *mutationMaterialFixture) {
			f.provider.Keys[0].PublicKey = f.strong.Keys[0].PublicKey
			f.provider.Keys[0].Revoked = true
		}},
		{"foreign-installation", func(f *mutationMaterialFixture) { f.provider.Scope.InstallationID = "installation_foreign" }},
		{"strong-purpose", func(f *mutationMaterialFixture) { f.strong.Keys[0].Purpose = "provider_proof_issuer" }},
		{"strong-key-revoked", func(f *mutationMaterialFixture) { f.strong.Keys[0].Revoked = true }},
		{"strong-key-expired", func(f *mutationMaterialFixture) { f.strong.Keys[0].NotAfter = f.now }},
		{"strong-key-future", func(f *mutationMaterialFixture) { f.strong.Keys[0].NotBefore = f.now.Add(time.Second) }},
		{"duplicate-key-version", func(f *mutationMaterialFixture) { f.strong.Keys = append(f.strong.Keys, f.strong.Keys[0]) }},
		{"issuer-policy-drift", func(f *mutationMaterialFixture) {
			k := f.strong.Keys[0]
			k.KeyVersion = "v2"
			k.Policy.Methods = []string{"totp"}
			f.strong.Keys = append(f.strong.Keys, k)
		}},
		{"missing-policy", func(f *mutationMaterialFixture) { f.strong.Keys[0].Policy.Methods = []string{} }},
		{"missing-old-nonce-file", func(f *mutationMaterialFixture) {
			if os.Remove(filepath.Join(f.source.files.NonceDirectory, f.model.identities["old"], "old")) != nil {
				t.Fatal("remove")
			}
		}},
		{"old-nonce-wrong-length", func(f *mutationMaterialFixture) { f.writeNonce(t, "old", []byte(strings.Repeat("o", 31))) }},
		{"active-identity-drift", func(f *mutationMaterialFixture) { f.model.identities["synthetic-v1"] = strings.Repeat("f", 64) }},
		{"retained-ledger-key-without-config-identity", func(f *mutationMaterialFixture) { f.model.versions = append(f.model.versions, "ledger-only") }},
		{"foreign-database", func(f *mutationMaterialFixture) { f.model.identity.Database = "foreign" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMutationMaterialFixture(t)
			tc.edit(f)
			f.persist(t)
			if sc, err := f.load(f.model.versions); err != ErrRegistrationUnavailable || sc.NonceHMACKeys != nil {
				t.Fatal("invalid material admitted or error exposed", err)
			}
		})
	}
}

func TestConfigMutationMaterialRequiresExactRetainedSetAndFileBytes(t *testing.T) {
	for _, versions := range [][]string{nil, {"synthetic-v1"}, {"old", "old"}, {"old", "../bad"}} {
		f := newMutationMaterialFixture(t)
		if _, err := f.load(versions); err != ErrRegistrationUnavailable {
			t.Fatal("incomplete or duplicate retained set accepted", err)
		}
	}
	f := newMutationMaterialFixture(t)
	for _, pin := range f.current.Registries() {
		if pin.Kind == "strong_auth_issuers" {
			if os.WriteFile(filepath.Join(f.source.files.RegistryDirectory, pin.Kind, pin.Version, pin.SHA256+".json"), []byte(`{}`), 0600) != nil {
				t.Fatal("write")
			}
		}
	}
	if _, err := f.load(f.model.versions); err != ErrRegistrationUnavailable {
		t.Fatal("changed bytes at pinned path accepted", err)
	}
	for phase := 1; phase <= 3; phase++ {
		f := newMutationMaterialFixture(t)
		f.model.failAt = phase
		if _, err := f.load(f.model.versions); err != ErrRegistrationUnavailable {
			t.Fatal("storage error leaked or admitted", phase, err)
		}
	}
	if source, err := NewConfigMutationSecurityFiles("installation_synthetic", f.model.identity, "relative", f.source.files.NonceDirectory); source != nil || err != ErrRegistrationUnavailable {
		t.Fatal("relative registry accepted", err)
	}
}
