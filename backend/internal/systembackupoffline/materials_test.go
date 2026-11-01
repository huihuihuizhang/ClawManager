package systembackupoffline

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	root "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/worker"
	reg "clawreef/internal/systembackupkekregistry"
	sec "clawreef/internal/systembackupsecurity"
	wire "clawreef/internal/systembackupwire"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	authz "k8s.io/api/authorization/v1"
)

var testNow = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

func fixture() (Trust, Bundle) {
	t, b := Templates()
	t.InstallationID = "local_test_only"
	t.Namespace = "offline-source"
	t.WorkerNamespace = "offline-worker"
	b.MaterialKind = "local_test_only"
	return t, b
}
func marshal(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func slot(t *testing.T, trust Trust, bundle Bundle, name string) string {
	t.Helper()
	r, e := Review(trust, bundle, testNow)
	if e != nil {
		t.Fatal(e)
	}
	if r.ProductionReady || len(r.Unverified) == 0 {
		t.Fatal("offline result promoted")
	}
	for _, c := range r.Checks {
		if c.Slot == name {
			return c.Status
		}
	}
	t.Fatal("missing check", name)
	return ""
}
func TestTemplateNeverMeansReady(t *testing.T) {
	trust, bundle := Templates()
	r, e := Review(trust, bundle, testNow)
	if e != nil || r.Status != "incomplete" || r.ProductionReady {
		t.Fatal(r, e)
	}
	for _, c := range r.Checks {
		if c.Status != "unverified" {
			t.Fatal(c)
		}
	}
}
func TestStrictPublicInput(t *testing.T) {
	for _, raw := range []string{`{"Protocol":"a","Protocol":"b"}`, `{"protocol":"a"}`, `{"Protocol":"a","protocol":"b"}`, `{"unexpected_token":"do-not-log"}`, `{} {}`, `{"Signing":{"Issuer":"!"}}`} {
		var v Trust
		if Decode([]byte(raw), &v) == nil {
			t.Fatal("accepted ambiguous input", raw)
		}
	}
	trust, bundle := Templates()
	var t2 Trust
	var b2 Bundle
	if Decode(marshal(t, trust), &t2) != nil || Decode(marshal(t, bundle), &b2) != nil {
		t.Fatal("template cannot round trip")
	}
}
func TestSecretPolicyExactEntries(t *testing.T) {
	for _, change := range []string{"valid", "wrong_pin", "wrong_version", "equal_count_substitution", "missing_required", "extra", "duplicate", "wrong_type", "token_secret", "missing_uid", "null_selection"} {
		t.Run(change, func(t *testing.T) {
			trust, bundle := fixture()
			p := root.SecretCapturePolicy{SchemaVersion: root.SecretCapturePolicyVersion, RegistryVersion: "local-r1", RegistryKind: "secret_allowlist", NamespaceScope: "installation_namespace", CaptureMode: "encrypted_full_object", Entries: []root.SecretCapturePolicyEntry{{ID: "db", SecretName: "source-db", Required: true, ExpectedType: "Opaque", Purpose: "database_credentials"}}}
			if change == "wrong_type" {
				p.Entries[0].ExpectedType = "Unknown"
			}
			if change == "token_secret" {
				p.Entries[0].ExpectedType = "kubernetes.io/service-account-token"
			}
			raw, e := jsoncanonicalizer.Transform(marshal(t, p))
			if e != nil {
				t.Fatal(e)
			}
			trust.SecretPolicy = &SecretPin{RegistryVersion: p.RegistryVersion, SHA256: Digest(raw)}
			bundle.SecretPolicy = &SecretMaterial{Policy: raw, Selections: []root.KubernetesSelection{{Version: "v1", Resource: "secrets", Name: "source-db", UID: "local-test-uid"}}}
			switch change {
			case "wrong_pin":
				trust.SecretPolicy.SHA256 = strings.Repeat("0", 64)
			case "wrong_version":
				trust.SecretPolicy.RegistryVersion = "r2"
			case "equal_count_substitution":
				bundle.SecretPolicy.Selections[0].Name = "other"
			case "missing_required":
				bundle.SecretPolicy.Selections = []root.KubernetesSelection{}
			case "extra":
				bundle.SecretPolicy.Selections = append(bundle.SecretPolicy.Selections, root.KubernetesSelection{Version: "v1", Resource: "secrets", Name: "extra", UID: "local-extra"})
			case "duplicate":
				bundle.SecretPolicy.Selections = append(bundle.SecretPolicy.Selections, bundle.SecretPolicy.Selections[0])
			case "missing_uid":
				bundle.SecretPolicy.Selections[0].UID = ""
			case "null_selection":
				bundle.SecretPolicy.Selections = nil
			}
			got := slot(t, trust, bundle, "secret_policy_selection")
			if (got == "checked_offline") != (change == "valid") {
				t.Fatal(got)
			}
		})
	}
}
func TestCapabilityCompleteCodesAndCurrentPins(t *testing.T) {
	for _, change := range []string{"valid", "identity", "scope", "version", "expired", "missing_code", "equal_count_duplicate", "degraded", "raw_material", "cleanup"} {
		t.Run(change, func(t *testing.T) {
			trust, bundle := fixture()
			h := strings.Repeat("a", 64)
			p := sec.CapabilityPolicy{Role: "signing", IdentityHash: h, RefVersion: "r1", ScopeHash: h, MaxValidity: time.Hour, ValidUntil: testNow.Add(time.Hour)}
			e := sec.CapabilityEvidence{SchemaVersion: "system-backup-capability-evidence.v1", Role: p.Role, IdentityHash: h, RefVersion: p.RefVersion, ScopeHash: h, StartedAt: testNow.Add(-time.Minute).Format(time.RFC3339), FinishedAt: testNow.Format(time.RFC3339)}
			e.Redaction.Applied = true
			e.Cleanup.Removed = true
			e.Cleanup.RunID = "cap-local-only-0001"
			e.Cleanup.Owner = "A:local-only"
			e.Cleanup.VerifiedAt = testNow.Format(time.RFC3339)
			for _, code := range requiredCapabilities[p.Role] {
				e.Capabilities = append(e.Capabilities, sec.CapabilityObservation{Code: code, Status: "supported", Reason: "none", RequestScopeHash: h, CheckedAt: e.StartedAt, ExpiresAt: testNow.Add(time.Minute).Format(time.RFC3339)})
			}
			switch change {
			case "identity":
				p.IdentityHash = strings.Repeat("b", 64)
			case "scope":
				p.ScopeHash = strings.Repeat("b", 64)
			case "version":
				p.RefVersion = "r2"
			case "expired":
				e.Capabilities[0].ExpiresAt = testNow.Format(time.RFC3339)
			case "missing_code":
				e.Capabilities = e.Capabilities[:len(e.Capabilities)-1]
			case "equal_count_duplicate":
				e.Capabilities[1] = e.Capabilities[0]
			case "degraded":
				e.Capabilities[0].Status = "degraded"
				e.Capabilities[0].Reason = "permission_denied"
			case "raw_material":
				e.Redaction.RawMaterial = true
			case "cleanup":
				e.Cleanup.Removed = false
			}
			trust.Capabilities[p.Role] = p
			bundle.Capabilities[p.Role] = e
			got := slot(t, trust, bundle, "capability:signing")
			if (got == "checked_offline") != (change == "valid") {
				t.Fatal(got)
			}
		})
	}
}
func TestCapabilityCodeContractParity(t *testing.T) {
	raw, e := os.ReadFile("../../../contracts/system-backup/v12/a-capability-role-mapping.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Codes map[string][]string `json:"codes_by_role"`
	}
	if json.Unmarshal(raw, &v) != nil || !reflect.DeepEqual(v.Codes, requiredCapabilities) {
		t.Fatal("capability contract drift")
	}
}
func TestSourceSignedGrantRefusals(t *testing.T) {
	for _, change := range []string{"valid", "exact_24h", "over_24h", "25h", "wrong_identity", "wrong_scope", "wrong_purpose", "wrong_uid", "revoked", "expired", "future", "signature", "pin"} {
		t.Run(change, func(t *testing.T) {
			trust, bundle := fixture()
			pub, key, e := ed25519.GenerateKey(rand.Reader)
			if e != nil {
				t.Fatal(e)
			}
			h := strings.Repeat("a", 64)
			g := worker.FormalSourceGrant{Version: worker.FormalSourceGrantVersion, InstallationID: trust.InstallationID, ConfigSHA256: h, WorkerNamespace: trust.WorkerNamespace, WorkerServiceAccountUID: "local-sa-uid", Operation: "capture-database", ScopeSHA256: h, CredentialSHA256: h, NotBefore: testNow.Add(-time.Minute), Until: testNow.Add(time.Minute)}
			p := SourcePin{Issuer: pub, Expected: g}
			if change == "exact_24h" || change == "over_24h" || change == "25h" {
				g.Until = g.NotBefore.Add(24 * time.Hour)
				if change == "over_24h" {
					g.Until = g.Until.Add(time.Nanosecond)
				}
				if change == "25h" {
					g.Until = g.NotBefore.Add(25 * time.Hour)
				}
				p.Expected = g
			}
			switch change {
			case "wrong_identity":
				g.InstallationID = "foreign"
			case "wrong_scope":
				g.ScopeSHA256 = strings.Repeat("b", 64)
			case "wrong_purpose":
				g.Operation = "capture-team-objects"
			case "wrong_uid":
				g.WorkerServiceAccountUID = "other"
			case "revoked":
				g.Revoked = true
				p.Expected = g
			case "expired":
				g.Until = testNow
				p.Expected = g
			case "future":
				g.NotBefore = testNow.Add(time.Second)
				p.Expected = g
			}
			raw := marshal(t, g)
			p.RecordSHA256 = Digest(raw)
			sig := ed25519.Sign(key, append([]byte(worker.FormalSourceGrantDomain), raw...))
			if change == "signature" {
				sig[0] ^= 1
			}
			if change == "pin" {
				p.RecordSHA256 = h
			}
			trust.SourceGrants["capture-database"] = p
			bundle.SourceGrants["capture-database"] = SignedMaterial{raw, sig}
			got := slot(t, trust, bundle, "source_grant:capture-database")
			if (got == "checked_offline") != (change == "valid" || change == "exact_24h") {
				t.Fatal(got)
			}
		})
	}
}
func TestResourcePermissionRefusals(t *testing.T) {
	for _, change := range []string{"valid", "write", "list", "wildcard", "different_name", "incomplete", "unknown_url", "extra_privilege"} {
		t.Run(change, func(t *testing.T) {
			trust, bundle := fixture()
			m := &RulesMaterial{Selections: []root.KubernetesSelection{{Version: "v1", Resource: "secrets", Name: "local-secret", UID: "local-uid"}}, Rules: authz.SubjectRulesReviewStatus{ResourceRules: []authz.ResourceRule{{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{"local-secret"}}}}}
			switch change {
			case "write":
				m.Rules.ResourceRules[0].Verbs = []string{"update"}
			case "list":
				m.Rules.ResourceRules[0].Verbs = []string{"list"}
			case "wildcard":
				m.Rules.ResourceRules[0].Resources = []string{"*"}
			case "different_name":
				m.Rules.ResourceRules[0].ResourceNames = []string{"other"}
			case "incomplete":
				m.Rules.Incomplete = true
			case "unknown_url":
				m.Rules.NonResourceRules = []authz.NonResourceRule{{Verbs: []string{"get"}, NonResourceURLs: []string{"/*"}}}
			case "extra_privilege":
				m.Rules.ResourceRules = append(m.Rules.ResourceRules, authz.ResourceRule{Verbs: []string{"create"}, APIGroups: []string{""}, Resources: []string{"pods"}})
			}
			bundle.SourceRules = m
			got := slot(t, trust, bundle, "source_resource_readonly_rules")
			if (got == "checked_offline") != (change == "valid") {
				t.Fatal(got)
			}
		})
	}
}

func coverageFixture(t *testing.T) (Trust, Bundle) {
	trust, bundle := fixture()
	h := strings.Repeat("a", 64)
	src := reg.SourceRecord{SourceID: "local", RecordID: "local-row", RecordVersion: "r1", ContentSHA256: h}
	k := wire.KeyBinding{Provider: "external-kms", IdentityHash: h, RegistryVersion: "r1", ProviderKeyID: "local-key", ProviderVersion: "7"}
	f := reg.BindingFacts{Binding: reg.Binding{InstallationID: trust.InstallationID, ConfigRef: reg.ReferencePin{IdentityHash: h, Version: "r1"}, Key: k}, BindingSHA256: keyHash(k), RowVersion: 1}
	s := reg.Snapshot{Database: reg.DatabaseIdentity{ServerUUID: "local-test-uuid", Database: "local_test"}, InstallationID: trust.InstallationID, Epoch: 3, ObservedAt: testNow, Bindings: []reg.BindingFacts{f}, References: []reg.Reference{}, Coverage: []reg.CoverageSource{}}
	for _, part := range partitions {
		s.Coverage = append(s.Coverage, reg.CoverageSource{Partition: part, SourceID: "local", SnapshotRevision: "s1", FenceRevision: "f1", AdoptionSource: src})
		s.References = append(s.References, reg.Reference{Partition: part, State: reg.ReferenceRetained, SourceRecordID: string(part), SourceRecordVersion: "r1", BackupPublicID: "sbk_local_only", AttemptNo: "1", EnvelopeID: string(part), Key: k, BindingSHA256: keyHash(k), MappingSource: src, ExpectedRequestSource: src, LifecycleSource: src})
	}
	raw := marshal(t, s)
	trust.CoverageInventorySHA256 = Digest(raw)
	bundle.Coverage = &CoverageMaterial{Expected: raw, Observed: s}
	return trust, bundle
}
func TestCoverageMembershipNotCounts(t *testing.T) {
	for _, change := range []string{"valid", "equal_count_replacement", "missing", "extra", "duplicate", "wrong_key_version", "wrong_binding_hash", "wrong_lifecycle", "epoch", "database", "nil_references", "missing_partition", "duplicate_partition", "inventory_pin", "unwrap_revoked", "source_revision"} {
		t.Run(change, func(t *testing.T) {
			trust, bundle := coverageFixture(t)
			m := bundle.Coverage
			switch change {
			case "equal_count_replacement":
				m.Observed.References[0].SourceRecordID = "replacement"
			case "missing":
				m.Observed.References = m.Observed.References[1:]
			case "extra":
				r := m.Observed.References[0]
				r.SourceRecordID = "extra"
				m.Observed.References = append(m.Observed.References, r)
			case "duplicate":
				m.Observed.References[1] = m.Observed.References[0]
			case "wrong_key_version":
				m.Observed.References[0].Key.ProviderVersion = "8"
			case "wrong_binding_hash":
				m.Observed.References[0].BindingSHA256 = strings.Repeat("b", 64)
			case "wrong_lifecycle":
				m.Observed.References[0].LifecycleSource.RecordID = "other"
			case "epoch":
				m.Observed.Epoch++
			case "database":
				m.Observed.Database.Database = "other"
			case "nil_references":
				m.Observed.References = nil
			case "missing_partition":
				m.Observed.Coverage = m.Observed.Coverage[1:]
			case "duplicate_partition":
				m.Observed.Coverage[1] = m.Observed.Coverage[0]
			case "inventory_pin":
				trust.CoverageInventorySHA256 = strings.Repeat("b", 64)
			case "unwrap_revoked":
				m.Observed.Bindings[0].UnwrapRevoked = &reg.Revocation{Purpose: reg.UnwrapRevocation}
			case "source_revision":
				m.Observed.Coverage[0].SnapshotRevision = "s2"
			}
			checks := reviewCoverage(trust, m, testNow)
			all := true
			refs := 0
			for _, c := range checks {
				all = all && c.Status == "checked_offline"
				if strings.HasPrefix(c.Slot, "coverage_reference:") {
					refs++
				}
			}
			if all != (change == "valid") {
				t.Fatal(checks)
			}
			if change == "valid" && refs != 4 {
				t.Fatal("no per-reference checks")
			}
		})
	}
}
func TestEmptyCoverageIsNotProofAndMissingIsNotEmpty(t *testing.T) {
	trust, bundle := coverageFixture(t)
	var expected reg.Snapshot
	if Decode(bundle.Coverage.Expected, &expected) != nil {
		t.Fatal("decode")
	}
	expected.References = []reg.Reference{}
	expected.Bindings = []reg.BindingFacts{}
	bundle.Coverage.Expected = marshal(t, expected)
	bundle.Coverage.Observed = expected
	trust.CoverageInventorySHA256 = Digest(bundle.Coverage.Expected)
	r, e := Review(trust, bundle, testNow)
	if e != nil || r.ProductionReady || !contains(r.Unverified, "coverage_eof_adoption_writer_fence_and_transaction_recheck") {
		t.Fatal(r, e)
	}
	bundle.Coverage = nil
	trust.CoverageInventorySHA256 = ""
	for _, c := range reviewCoverage(trust, nil, testNow) {
		if c.Status != "unverified" {
			t.Fatal(c)
		}
	}
}
func contains(v []string, s string) bool {
	for _, x := range v {
		if x == s {
			return true
		}
	}
	return false
}

func TestCoverageUsesPublicSnakeCaseKeyHash(t *testing.T) {
	// Independently computed by scripts/system-backup-c-crypto-wire.mjs sha(canonical(key)).
	k := wire.KeyBinding{Provider: "external-kms", IdentityHash: strings.Repeat("a", 64), RegistryVersion: "r1", ProviderKeyID: "local-key", ProviderVersion: "7"}
	if keyHash(k) != "170360822fbb796bea31dd2c4581af893a6fb29cc099263c17e2c34c9f37a8da" {
		t.Fatal("public C binding hash drift")
	}
}

func TestSQLSourceGrantsReuseConsumer(t *testing.T) {
	for _, change := range []string{"valid", "write", "wildcard", "missing_table", "extra_control_table", "role", "uuid", "database", "missing_routine"} {
		t.Run(change, func(t *testing.T) {
			trust, bundle := fixture()
			trust.SourceDatabase = reg.DatabaseIdentity{ServerUUID: "local-test-uuid", Database: "source"}
			grants := []string{"GRANT EXECUTE ON PROCEDURE `source`.`" + domain.SchemaCensusRoutine + "` TO 'reader'@'127.0.0.1'", "GRANT SHOW_ROUTINE ON *.* TO 'reader'@'127.0.0.1'"}
			for _, table := range domain.BusinessCaptureTables() {
				grants = append(grants, "GRANT SELECT ON `source`.`"+table+"` TO 'reader'@'127.0.0.1'")
			}
			m := &SQLMaterial{Database: trust.SourceDatabase, CurrentRole: "NONE", Grants: grants}
			switch change {
			case "write":
				m.Grants = append(m.Grants, "GRANT UPDATE ON `source`.`users` TO 'reader'@'127.0.0.1'")
			case "wildcard":
				m.Grants = append(m.Grants, "GRANT SELECT ON `source`.* TO 'reader'@'127.0.0.1'")
			case "missing_table":
				m.Grants = m.Grants[:2]
			case "extra_control_table":
				m.Grants = append(m.Grants, "GRANT SELECT ON `source`.`system_backup_v2_tasks` TO 'reader'@'127.0.0.1'")
			case "role":
				m.CurrentRole = "admin"
			case "uuid":
				m.Database.ServerUUID = "foreign"
			case "database":
				m.Database.Database = "foreign"
			case "missing_routine":
				m.Grants = m.Grants[1:]
			}
			bundle.SourceSQL = m
			got := slot(t, trust, bundle, "source_sql_readonly_grants")
			if (got == "checked_offline") != (change == "valid") {
				t.Fatal(got)
			}
		})
	}
}
