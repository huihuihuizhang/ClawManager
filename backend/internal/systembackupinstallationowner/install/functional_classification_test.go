package install

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

// Classification and original issuer component tests only: original crypto,
// bcrypt and native protocol fixture are real; SQL/Kubernetes are the existing
// explicit models. No other missing owner or complete C1/task admission is
// supplied by these tests. Classification never asserts physical independence.
func functionalRegistryFixture(t *testing.T, installation string, original sec.BootstrapConfig) (sec.BootstrapConfig, FunctionalClassificationDefinition, []byte, []byte) {
	t.Helper()
	failure := FunctionalFailureDomainRegistry{SchemaVersion: "system-backup-original-failure-domains.v1", Installation: installation, Version: "functional-domains-v1", History: []FunctionalFailureDomainEvent{{Sequence: 1, Domain: "original-shared-domain", IdentitySHA256: strings.Repeat("d", 64), State: "active"}}}
	failureRaw, err := canonical(failure)
	if err != nil {
		t.Fatal(err)
	}
	refs := original.References()
	sort.Slice(refs, func(a, b int) bool { return refs[a].Purpose < refs[b].Purpose })
	mapping := FunctionalDisasterIdentityRegistry{SchemaVersion: FunctionalDisasterMappingVersion, Profile: FunctionalNonDRProfile, Installation: installation, Version: "functional-map-v1", State: "unavailable"}
	for _, ref := range refs {
		mapping.Entries = append(mapping.Entries, FunctionalDisasterIdentityEntry{Purpose: ref.Purpose, IdentityHash: ref.IdentityHash, ReferenceVersion: ref.Version, State: "unavailable", Reason: "not_provided"})
	}
	mappingRaw, err := canonical(mapping)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if json.Unmarshal(original.CanonicalJSON(), &config) != nil {
		t.Fatal("original config")
	}
	for _, value := range config["registries"].([]any) {
		pin := value.(map[string]any)
		switch pin["registry_kind"] {
		case "failure_domains":
			pin["version"], pin["sha256"] = failure.Version, hash(failureRaw)
		case "disaster_identity_mapping":
			pin["version"], pin["sha256"] = mapping.Version, hash(mappingRaw)
		}
	}
	configRaw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	next, err := sec.DecodeBootstrapConfig(configRaw)
	if err != nil {
		t.Fatal(err)
	}
	d := FunctionalClassificationDefinition{SchemaVersion: FunctionalClassificationVersion, Profile: FunctionalNonDRProfile, TaskPurpose: "functional_test", TargetClass: "same-cluster-copy", TargetFailureDomain: failure.History[0].Domain, RecoveryEvidenceStatus: "not_provided", FailureRegistrySHA256: hash(failureRaw), MappingRegistrySHA256: hash(mappingRaw), SourceDomains: []string{failure.History[0].Domain}, TargetRisks: []string{"attestation_missing", "same_failure_domain"}}
	return next, d, failureRaw, mappingRaw
}

func TestFunctionalClassificationAcceptsOneDomainAndExplicitUnavailableMap(t *testing.T) {
	f := newAuthorityFixture(t)
	config, d, failure, mapping := functionalRegistryFixture(t, f.record.Target.InstallationID, f.config)
	if err := validateFunctionalRegistries(d, f.record.Target.InstallationID, config, failure, mapping); err != nil {
		t.Fatal("non-DR classification required an invented second domain or disaster credentials", err)
	}
	for _, mutate := range []func(*FunctionalClassificationDefinition){func(d *FunctionalClassificationDefinition) { d.TaskPurpose = "acceptance" }, func(d *FunctionalClassificationDefinition) { d.TargetClass = "dr-ready-external" }, func(d *FunctionalClassificationDefinition) { d.RecoveryEvidenceStatus = "provided" }, func(d *FunctionalClassificationDefinition) {
		d.TargetRisks = []string{"conditional_commit_unavailable", "same_failure_domain"}
	}, func(d *FunctionalClassificationDefinition) { d.SourceDomains = []string{"other-domain"} }, func(d *FunctionalClassificationDefinition) { d.TargetRisks = []string{"same_failure_domain"} }} {
		bad := d
		mutate(&bad)
		if validateFunctionalRegistries(bad, f.record.Target.InstallationID, config, failure, mapping) == nil {
			t.Fatal("invalid classification or a provider failure was treated as harmless functional risk")
		}
	}
	var missing FunctionalDisasterIdentityRegistry
	if decodeExact(mapping, &missing) != nil {
		t.Fatal("mapping")
	}
	missing.Entries = missing.Entries[:19]
	bad, _ := canonical(missing)
	// Re-pin the malformed document exactly: cardinality/content validation
	// must still reject, not only its old byte hash.
	var fields map[string]any
	_ = json.Unmarshal(config.CanonicalJSON(), &fields)
	for _, value := range fields["registries"].([]any) {
		p := value.(map[string]any)
		if p["registry_kind"] == "disaster_identity_mapping" {
			p["sha256"] = hash(bad)
		}
	}
	configRaw, _ := json.Marshal(fields)
	badConfig, err := sec.DecodeBootstrapConfig(configRaw)
	if err != nil {
		t.Fatal(err)
	}
	d.MappingRegistrySHA256 = hash(bad)
	if validateFunctionalRegistries(d, f.record.Target.InstallationID, badConfig, failure, bad) == nil {
		t.Fatal("unavailable mappings omitted an original required reference")
	}
}

func functionalIssueFixture(t *testing.T, ctx context.Context) (*authorityFixture, []byte, pd.BootstrapConsumptionRequest, string, string) {
	t.Helper()
	f := newAuthorityFixture(t)
	config, d, failure, mapping := functionalRegistryFixture(t, f.record.Target.InstallationID, f.config)
	f.config = config
	f.grant.ConfigSHA256 = config.SHA256()
	grantRaw, _ := json.Marshal(f.grant)
	f.record.ConfigSHA256, f.record.GrantSHA256 = config.SHA256(), hash(grantRaw)
	var configFields map[string]json.RawMessage
	_ = json.Unmarshal(config.CanonicalJSON(), &configFields)
	f.record.RegistrySetSHA256, f.record.ReferenceSetSHA256 = hash(configFields["registries"]), hash(configFields["references"])
	if os.WriteFile(f.files.ConfigFile, config.CanonicalJSON(), 0600) != nil {
		t.Fatal("controlled updated config")
	}
	f.files.ConfigFileSHA256 = hash(config.CanonicalJSON())
	offline, err := ReadPrivateFile(f.files.GrantFile, 16384)
	var grantFile sec.BootstrapGrantFile
	if err != nil || decodeExact(offline, &grantFile) != nil {
		t.Fatal("original offline grant")
	}
	grantFile.Grant = f.grant
	offline, err = canonical(grantFile)
	if err != nil || os.WriteFile(f.files.GrantFile, offline, 0600) != nil {
		t.Fatal("controlled selected grant")
	}
	f.files.GrantFileSHA256 = hash(offline)
	raw, err := os.ReadFile("../../../../contracts/system-backup/v12/producer-authority-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Positive []struct {
			ID    string
			Value json.RawMessage
		}
	}
	if json.Unmarshal(raw, &vectors) != nil {
		t.Fatal("original request vectors")
	}
	var result pd.ResultRequest
	for _, v := range vectors.Positive {
		if v.ID == "unconfigured_artifact" && pd.DecodeRecord(v.Value, &result) != nil {
			t.Fatal("result vector")
		}
	}
	if result.Admission.Unconfigured == nil {
		t.Fatal("unconfigured result")
	}
	r := f.record
	result.Scope = pd.Scope{ServerUUID: pd.ServerUUID(r.Target.ServerUUID), Database: pd.Database(r.Target.Database), Installation: pd.Installation(r.Target.InstallationID)}
	result.Evidence.OwnerID = result.Scope.Installation
	result.Admission.Unconfigured.CandidateHash, result.Admission.Unconfigured.RegistrySetHash, result.Admission.Unconfigured.RefSetHash = pd.Hash(r.ConfigSHA256), pd.Hash(r.RegistrySetSHA256), pd.Hash(r.ReferenceSetSHA256)
	selection := pd.BootstrapConsumptionRequest{Scope: result.Scope, OfflineGrantHash: pd.Hash(r.GrantSHA256), ConfigHash: pd.Hash(r.ConfigSHA256), RegistrySetHash: pd.Hash(r.RegistrySetSHA256), RefSetHash: pd.Hash(r.ReferenceSetSHA256), ActorID: pd.Counter(strconv.FormatInt(r.Actor.UserID, 10)), Username: r.Actor.Username, MatrixKey: r.MatrixKey, Endpoint: r.Endpoint, IdempotencyKey: r.IdempotencyKey, Candidates: []pd.BootstrapCandidateSelection{{Purpose: "artifact", ReferenceIdentityHash: pd.Hash(strings.Repeat("b", 64)), ReferenceVersion: "1", MappingHash: pd.Hash(strings.Repeat("c", 64)), Request: result, ResultVersion: "1"}}}
	h, err := pd.BootstrapConsumptionHash(selection)
	if err != nil {
		t.Fatal(err)
	}
	f.record.SelectionSHA256 = string(h)
	f.draft, err = owner.EncodeRecord(f.record)
	if err != nil {
		t.Fatal(err)
	}
	pack := issueFixture(t, f, ctx)
	if _, err := f.i.ImportCapture(ctx, f.password, f.enrollment, pack, hash(pack), f.files); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	d.FailureRegistryFile = filepath.Join(directory, "failure-domains.json")
	d.MappingRegistryFile = filepath.Join(directory, "disaster-unavailable.json")
	if os.WriteFile(d.FailureRegistryFile, failure, 0600) != nil || os.WriteFile(d.MappingRegistryFile, mapping, 0600) != nil {
		t.Fatal("selected classification registries")
	}
	definition, err := canonical(d)
	file := filepath.Join(directory, "classification-intent.json")
	if err != nil || os.WriteFile(file, definition, 0600) != nil {
		t.Fatal("original classification intent")
	}
	return f, pack, selection, file, hash(definition)
}

func TestFunctionalClassificationIssuerUsesActualOriginalAuthorityWithoutDRProbe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f, pack, selection, file, pin := functionalIssueFixture(t, ctx)
	writes, signs := f.s.writes, f.signs.Load()
	signed, err := f.i.IssueFunctionalClassification(ctx, f.password, f.enrollment, pack, hash(pack), file, pin, selection, f.files, f.key)
	if err != nil {
		t.Fatal(err)
	}
	classified, err := verifyFunctionalClassification(signed.Record, signed.Signature, f.i.public)
	if err != nil || classified.TargetClass != "same-cluster-copy" || classified.RecoveryEvidenceStatus != "not_provided" || !classified.Until.Equal(f.record.Until) || !classified.NotBefore.Equal(f.record.NotBefore) || hash(signed.PublicationPolicy) != classified.PublicationPolicySHA256 {
		t.Fatal("actual signed functional classification", err)
	}
	var policy struct {
		RecoveryStatus string `json:"recovery_evidence_status"`
		Recovery       any    `json:"recovery_evidence"`
		Target         struct {
			Class       string `json:"target_class"`
			Attestation any    `json:"attestation_id"`
		} `json:"target"`
	}
	if json.Unmarshal(signed.PublicationPolicy, &policy) != nil || policy.RecoveryStatus != "not_provided" || policy.Recovery != nil || policy.Target.Class != "same-cluster-copy" || policy.Target.Attestation != nil {
		t.Fatal("publication policy manufactured DR evidence")
	}
	if f.s.writes != writes || f.signs.Load() != signs || f.s.openTx.Load() != 0 {
		t.Fatal("classification touched provider/SQL writes or kept original locks")
	}
	bad := append([]byte(nil), signed.Signature...)
	bad[0] ^= 1
	if _, err := verifyFunctionalClassification(signed.Record, bad, f.i.public); err == nil {
		t.Fatal("untrusted classification signature accepted")
	}
	f.s.auth.role = "user"
	if _, err := f.i.IssueFunctionalClassification(ctx, f.password, f.enrollment, pack, hash(pack), file, pin, selection, f.files, f.key); err == nil {
		t.Fatal("revoked original administrator issued classification")
	}
}

func TestFunctionalClassificationOwnerIsConcreteGroupedAndCandidateOnly(t *testing.T) {
	capture, files, resources := terminalSevenConcreteSources(t)
	original, err := NewBootstrapTerminalOriginal(capture, files, resources)
	if err != nil {
		t.Fatal(err)
	}
	classFiles := FunctionalClassificationFiles{RecordFile: filepath.Join(t.TempDir(), "classification.json"), RecordSHA256: strings.Repeat("a", 64), SignatureFile: filepath.Join(t.TempDir(), "classification.signature"), RegistryDirectory: t.TempDir()}
	next, shared, err := original.WithFunctionalClassification(classFiles)
	if err != nil || shared.capture != capture || next.capture != capture || len(next.MissingTerminalResources()) != 21 || len(original.MissingTerminalResources()) != 23 || next.resources["registry:failure_domains"] != shared || next.resources["registry:disaster_identity_mapping"] != shared {
		t.Fatal("classification composition lost actual original capture anchor or changed original terminal", err)
	}
	for key, source := range original.resources {
		if next.resources[key] != source {
			t.Fatal("replaced actual unrelated resource", key)
		}
	}
	base, err := original.Owners()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	linked, classified, err := LinkFunctionalClassificationOwners(base, capture, FunctionalClassificationFiles{RecordFile: filepath.Join(dir, "not-opened.json"), RecordSHA256: strings.Repeat("a", 64), SignatureFile: filepath.Join(dir, "not-opened.sig"), RegistryDirectory: dir})
	if err != nil || linked.Registries["failure_domains"] != classified || linked.Registries["disaster_identity_mapping"] != classified || linked.References["capture_signing"] != capture || len(sec.MissingBootstrapOwnerAdapters(linked)) != 21 {
		t.Fatal("two real classification implementations were not linked or unrelated requirements disappeared", err)
	}
	for key, value := range base.References {
		if linked.References[key] != value {
			t.Fatal("replaced original reference", key)
		}
	}
	if check, err := classified.Prepare(context.Background(), sec.OfflineBootstrapGrant{}, sec.BootstrapConfig{}); err == nil || check != nil {
		t.Fatal("legacy route bypassed required candidate current identity")
	}
	if _, _, err := LinkFunctionalClassificationOwners(linked, capture, classified.files); err == nil {
		t.Fatal("silently overwrote selected classification source")
	}
	check := &functionalClassificationCheck{ctx: context.Background()}
	check.origin = check
	copy := reflect.New(reflect.TypeOf(check).Elem())
	copy.Elem().Set(reflect.ValueOf(check).Elem())
	if _, err := copy.Interface().(*functionalClassificationCheck).AuthorizeIdentity(check.ctx, nil); err == nil || !check.failed.Load() {
		t.Fatal("copied classification revived authority")
	}
}
