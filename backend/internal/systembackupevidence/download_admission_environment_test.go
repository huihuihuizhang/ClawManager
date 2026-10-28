package systembackupevidence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

// Files contain synthetic keys/registries/reports, and SQL/owner transport is
// modeled. The real A session, material, RBAC and capacity implementations and
// the complete D transaction execute. This is not physical/MySQL acceptance.
type admissionPinnedOwners struct {
	f                       *admissionTxFixture
	previews, locks, guards int
	onGuard                 func()
}

func (o *admissionPinnedOwners) Preview(ctx context.Context, tx *sql.Tx, installation string, actor sec.RegistrationActor, id string) (Record, error) {
	o.previews++
	if !o.f.db.installationLocked || o.f.db.opKeyLocked || tx == nil || ctx.Err() != nil || installation != o.f.initial.Manifest.Identity.Installation || id != o.f.initial.Manifest.Identity.ID || actor.UserID != 42 {
		return Record{}, ErrDenied
	}
	return o.f.db.record, nil
}
func (o *admissionPinnedOwners) LockOwnerReferences(ctx context.Context, tx *sql.Tx, record Record) error {
	o.locks++
	if !o.f.db.opKeyLocked || ctx.Err() != nil || tx == nil || !sameDownloadAdmissionImmutable(record, o.f.initial) {
		return ErrDenied
	}
	o.f.db.ownerLocked = true
	o.f.db.calls = append(o.f.db.calls, "L4")
	return nil
}
func (o *admissionPinnedOwners) Recheck(ctx context.Context, tx *sql.Tx, actor sec.RegistrationActor, record Record) error {
	o.guards++
	if !o.f.db.ownerLocked || tx == nil || ctx.Err() != nil || actor.UserID != 42 || !sameDownloadAdmissionImmutable(record, o.f.initial) {
		return ErrDenied
	}
	if o.onGuard != nil {
		o.onGuard()
	}
	return nil
}

type admissionPinnedFixture struct {
	*admissionTxFixture
	environment          *PinnedDownloadAdmissionEnvironment
	owners               *admissionPinnedOwners
	configuration        PinnedDownloadAdmissionConfig
	noncePaths           map[string]string
	rbacPath, reportPath string
	report               sec.CapacityReport
}

func writeAdmissionPinnedFile(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
func newAdmissionPinnedFixture(t *testing.T) *admissionPinnedFixture {
	t.Helper()
	return newAdmissionPinnedFixtureFromBase(t, newAdmissionTxFixture(t))
}

func newAdmissionPinnedFixtureFromBase(t *testing.T, f *admissionTxFixture) *admissionPinnedFixture {
	t.Helper()
	dir := t.TempDir()
	registryDir, nonceDir := filepath.Join(dir, "registries"), filepath.Join(dir, "nonce")
	now := f.db.now
	providerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	strongKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	provider := sec.ProviderIssuerRegistry{SchemaVersion: "system-backup-provider-issuers.draft.v1", Version: "provider-v1",
		Scope: sec.ProviderProofScope{InstallationID: f.initial.Manifest.Identity.Installation, Audience: "provider-proof"},
		Keys:  []sec.ProviderIssuerRegistryKey{{Issuer: "provider", KeyID: "provider-key", KeyVersion: "v1", Purpose: "provider_proof_issuer", PublicKey: providerKey.Public().(ed25519.PublicKey), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), TargetTypes: []string{"external_action"}, ProofTypes: []string{"provider_presence"}}}}
	strong := sec.StrongAuthIssuerRegistry{SchemaVersion: "system-backup-strong-auth-issuers.draft.v1", Version: "strong-v1", Audience: f.env.cfg.ExpectedAudience,
		Keys: []sec.StrongAuthRegistryKey{{Issuer: "issuer-transaction", KeyID: "admission-key", KeyVersion: "v1", Purpose: "strong_auth_issuer", PublicKey: strongKey.Public().(ed25519.PublicKey), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), Policy: sec.IssuerPolicy{Methods: []string{"totp"}, ACR: []string{}, AMR: []string{"pwd", "otp"}}}}}
	var doc map[string]any
	decoder := json.NewDecoder(bytes.NewReader(f.db.config.CanonicalJSON()))
	decoder.UseNumber()
	if err := decoder.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	p := &admissionPinnedFixture{admissionTxFixture: f, noncePaths: map[string]string{}}
	for _, value := range doc["registries"].([]any) {
		pin := value.(map[string]any)
		var raw []byte
		switch pin["registry_kind"] {
		case "rbac_bindings":
			raw = append([]byte(nil), f.env.rbac...)
		case "provider_proof_issuers":
			raw, _ = json.Marshal(provider)
			pin["version"] = provider.Version
		case "strong_auth_issuers":
			raw, _ = json.Marshal(strong)
			pin["version"] = strong.Version
		default:
			continue
		}
		pin["sha256"] = hash(raw)
		path := filepath.Join(registryDir, pin["registry_kind"].(string), pin["version"].(string), hash(raw)+".json")
		writeAdmissionPinnedFile(t, path, raw)
		if pin["registry_kind"] == "rbac_bindings" {
			p.rbacPath = path
		}
	}
	f.db.config, f.db.configCells = admissionConfigDocument(t, doc)
	for version, material := range f.env.cfg.NonceHMACKeys {
		identity := hash([]byte("old-nonce-identity"))
		if version == "v2" {
			identity = f.db.configCells["nonce_hmac_identity_hash"].(string)
		}
		p.noncePaths[version] = filepath.Join(nonceDir, identity, version)
		writeAdmissionPinnedFile(t, p.noncePaths[version], material)
	}
	materials, err := sec.NewConfigMutationSecurityFiles(f.initial.Manifest.Identity.Installation, f.db.identity, registryDir, nonceDir)
	if err != nil {
		t.Fatal(err)
	}
	p.reportPath = filepath.Join(dir, "synthetic-capacity-report.json")
	p.report = sec.CapacityReport{ServerUUID: f.db.identity.ServerUUID, Database: f.db.identity.Database, ObservedAt: now, AllocatedBytes: 1048576, AvailableBytes: 1099511627776}
	p.writeReport(t)
	capacity, err := sec.NewConfigMutationCapacity(f.db.identity, p.reportPath, 1)
	if err != nil {
		t.Fatal(err)
	}
	p.owners = &admissionPinnedOwners{f: f}
	p.configuration = PinnedDownloadAdmissionConfig{Installation: f.initial.Manifest.Identity.Installation, Sessions: f.env.sessions, Materials: materials, RegistryDirectory: registryDir, Issuer: "issuer-transaction", Owners: p.owners, Capacity: capacity,
		MeasuredReservationBytes: 65536, MaterialsUntil: now.Add(2 * time.Minute), AuditMinimumRetainUntil: now.Add(3 * time.Hour)}
	p.environment, err = NewPinnedDownloadAdmissionEnvironment(p.configuration)
	if err != nil {
		t.Fatal(err)
	}
	f.service, err = NewDownloadAdmissionService(f.service.registry, f.secret, p.environment)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func (p *admissionPinnedFixture) writeReport(t *testing.T) {
	t.Helper()
	raw, err := json.Marshal(p.report)
	if err != nil {
		t.Fatal(err)
	}
	writeAdmissionPinnedFile(t, p.reportPath, raw)
}

func TestDownloadAdmissionPinnedPublicClassificationDoesNotLoadMFA(t *testing.T) {
	for _, damagedRBAC := range []bool{false, true} {
		t.Run(fmt.Sprint(damagedRBAC), func(t *testing.T) {
			p := newAdmissionPinnedFixture(t)
			r := p.initial
			r.Manifest.Identity.Classification = "public"
			p.initial, p.db.record, p.env.hint, p.db.m.f.Record = r, r, r, r
			p.request.Header.Del(sec.StrongAuthProofHeader)
			p.request.Header.Del("Idempotency-Key")
			p.environment.config.MaterialsUntil = p.db.now.Add(-time.Minute)
			for _, file := range p.noncePaths {
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
			}
			if damagedRBAC {
				writeAdmissionPinnedFile(t, p.rbacPath, []byte("invalid RBAC"))
			}
			cap, err := p.service.admit(p.request, true)
			if cap != nil || err == nil {
				t.Fatal("classification returned admission capability")
			}
			if damagedRBAC {
				if err == errDownloadAdmissionPublic {
					t.Fatal("RBAC failure fell back to public reader")
				}
			} else if err != errDownloadAdmissionPublic {
				t.Fatal("public hint depended on expired/missing MFA material", err)
			}
			if p.db.inserts != 0 || len(p.db.nonce) != 0 || p.owners.locks != 0 || p.db.reserved != 0 || p.db.rollbacks != 1 {
				t.Fatal("classification had private admission effects")
			}
		})
	}
}

func TestDownloadAdmissionPinnedEnvironmentCombinesRealModules(t *testing.T) {
	p := newAdmissionPinnedFixture(t)
	out, err := p.service.Admit(p.request)
	if err != nil || out == nil {
		t.Fatal("pinned admission", err, p.db.calls, p.db.queries)
	}
	if p.owners.previews != 1 || p.owners.locks != 1 || p.owners.guards != 2 || p.db.commitAttempts != 1 || p.db.rollbacks != 0 || p.db.reserved != 65536 || !p.db.sample.Equal(p.report.ObservedAt) || len(p.db.nonce) != 16 || len(p.db.m.receipt) != 16 || len(p.db.m.op) != 14 {
		t.Fatal("real modules were bypassed", p.db.calls, p.owners)
	}
	if raw, err := json.Marshal(p.service); err == nil || raw != nil || fmt.Sprintf("%v %#v", p.service, p.service) != "DownloadAdmissionService DownloadAdmissionService" {
		t.Fatal("service exposed secret state")
	}
	for _, version := range []string{"v1", "v2"} {
		raw, err := os.ReadFile(p.noncePaths[version])
		if err != nil || !bytes.Equal(raw, p.env.cfg.NonceHMACKeys[version]) {
			t.Fatal("Close changed mounted source keys")
		}
	}
}

func TestDownloadAdmissionPinnedEnvironmentRejectsChangedSourcesAtomically(t *testing.T) {
	for _, mode := range []string{"missing_historical_key", "missing_active_key", "corrupt_rbac", "stale_capacity", "foreign_capacity", "physical_capacity", "late_historical_key", "late_active_key", "late_rbac", "late_password", "late_revocation", "late_capacity_sample", "late_capacity_expiry", "late_capacity_floor"} {
		t.Run(mode, func(t *testing.T) {
			p := newAdmissionPinnedFixture(t)
			late := strings.HasPrefix(mode, "late_")
			hit := false
			attack := func() {
				hit = true
				switch mode {
				case "missing_historical_key":
					if err := os.Remove(p.noncePaths["v1"]); err != nil {
						t.Fatal(err)
					}
				case "missing_active_key":
					if err := os.Remove(p.noncePaths["v2"]); err != nil {
						t.Fatal(err)
					}
				case "corrupt_rbac", "late_rbac":
					writeAdmissionPinnedFile(t, p.rbacPath, []byte("{}"))
				case "stale_capacity":
					p.report.ObservedAt = p.report.ObservedAt.Add(-5 * time.Second)
					p.writeReport(t)
				case "foreign_capacity":
					p.report.Database = "another_database"
					p.writeReport(t)
				case "physical_capacity":
					p.report.AvailableBytes = 1
					p.writeReport(t)
				case "late_historical_key":
					writeAdmissionPinnedFile(t, p.noncePaths["v1"], bytes.Repeat([]byte{0x44}, 32))
				case "late_active_key":
					writeAdmissionPinnedFile(t, p.noncePaths["v2"], bytes.Repeat([]byte{0x55}, 32))
				case "late_password":
					p.db.password = "changed-password"
				case "late_revocation":
					p.db.sessionRevoked = true
				case "late_capacity_sample":
					p.db.sample = p.db.sample.Add(time.Microsecond)
				case "late_capacity_expiry":
					p.db.now = p.db.now.Add(5 * time.Second)
				case "late_capacity_floor":
					p.db.reserved = 0
				}
			}
			if late {
				p.owners.onGuard = func() {
					if p.owners.guards != 1 {
						return
					}
					if len(p.db.nonce) != 16 || len(p.db.m.op) != 14 || len(p.db.m.receipt) != 16 || len(p.db.body) == 0 || p.db.reserved != 65536 || p.db.record.Claim == "" {
						t.Fatal("attack never reached fully staged original transaction")
					}
					attack()
				}
			} else {
				attack()
			}
			out, err := p.service.Admit(p.request)
			if !hit || err == nil || out != nil {
				t.Fatal("source change accepted", mode, err, p.db.calls)
			}
			if late && p.owners.guards == 0 || !late && p.owners.previews != 1 {
				t.Fatal("requested adapter stage not reached")
			}
			if !late && (mode == "stale_capacity" || mode == "foreign_capacity" || mode == "physical_capacity") && p.owners.locks != 1 {
				t.Fatal("capacity fault failed before owner/nonce locks")
			}
			assertAdmissionRolledBack(t, p.admissionTxFixture)
			if !p.db.sample.IsZero() {
				t.Fatal("capacity sample survived rollback")
			}
		})
	}
}

func TestDownloadAdmissionPinnedEnvironmentRequiresDeploymentInputs(t *testing.T) {
	p := newAdmissionPinnedFixture(t)
	for _, mode := range []string{"sessions", "materials", "owners", "typed_nil_owners", "capacity", "relative_registry", "issuer", "physical_cost_missing", "physical_cost_small", "physical_cost_large", "materials_time", "audit_time"} {
		t.Run(mode, func(t *testing.T) {
			c := p.configuration
			switch mode {
			case "sessions":
				c.Sessions = nil
			case "materials":
				c.Materials = nil
			case "owners":
				c.Owners = nil
			case "typed_nil_owners":
				c.Owners = (*admissionPinnedOwners)(nil)
			case "capacity":
				c.Capacity = nil
			case "relative_registry":
				c.RegistryDirectory = "registries"
			case "issuer":
				c.Issuer = ""
			case "physical_cost_missing":
				c.MeasuredReservationBytes = 0
			case "physical_cost_small":
				c.MeasuredReservationBytes = 3*MaxDownloadAdmissionContentBytes - 1
			case "physical_cost_large":
				c.MeasuredReservationBytes = 1048577
			case "materials_time":
				c.MaterialsUntil = time.Time{}
			case "audit_time":
				c.AuditMinimumRetainUntil = time.Time{}
			}
			if got, err := NewPinnedDownloadAdmissionEnvironment(c); got != nil || err == nil {
				t.Fatal("missing production input accepted")
			}
		})
	}
}
