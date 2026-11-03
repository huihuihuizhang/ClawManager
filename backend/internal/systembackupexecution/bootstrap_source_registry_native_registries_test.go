package systembackupexecution

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	root "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/recovery"
	ce "clawreef/internal/systembackupcontrolevidence"
	"clawreef/internal/systembackupinstallationowner/install"
)

func TestBootstrapSourceNativeRegistriesUseOneExplicitOriginalOwner(t *testing.T) {
	dir := t.TempDir()
	capture := install.NewCaptureSigningConsumer(filepath.Join(dir, "capture.json"), filepath.Join(dir, "capture.sha256"))
	files := install.BootstrapSourceRegistryFiles{RecordFile: filepath.Join(dir, "source.json"), RecordSHA256: strings.Repeat("a", 64), SignatureFile: filepath.Join(dir, "source.sig")}
	native := BootstrapSourceNativeRegistryFiles{RedisSources: install.BootstrapSourceFilePin{File: filepath.Join(dir, "redis.json"), SHA256: strings.Repeat("b", 64)}, SecretAllowlist: install.BootstrapSourceFilePin{File: filepath.Join(dir, "secrets.json"), SHA256: strings.Repeat("c", 64)}}
	r, err := NewBootstrapSourceRegistryTerminalResourceWithNativeRegistries(capture, files, native)
	if err != nil {
		t.Fatal(err)
	}
	resources := r.TerminalResources()
	if len(resources) != 4 {
		t.Fatal("actual four registry owner aliases missing")
	}
	for _, key := range []string{"registry:parts", "registry:redis_sources", "registry:secret_allowlist", "registry:source_writers"} {
		if resources[key] != r {
			t.Fatal("registry aliases do not share concrete pointer", key)
		}
	}
	binding, err := r.BindingSHA256()
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := NewBootstrapSourceRegistryTerminalResource(capture, files)
	if err != nil {
		t.Fatal(err)
	}
	legacyBinding, _ := legacy.BindingSHA256()
	if len(legacy.TerminalResources()) != 2 || legacyBinding == binding {
		t.Fatal("two-key binding silently upgraded")
	}
	native.RedisSources.SHA256 = strings.Repeat("d", 64)
	same, _ := r.BindingSHA256()
	if same != binding {
		t.Fatal("constructor aliases mutable input")
	}
	other, err := NewBootstrapSourceRegistryTerminalResourceWithNativeRegistries(capture, files, native)
	if err != nil {
		t.Fatal(err)
	}
	otherBinding, _ := other.BindingSHA256()
	if otherBinding == binding {
		t.Fatal("native file pin omitted from signed composition binding")
	}
	native.SecretAllowlist.File = native.RedisSources.File
	if _, err := NewBootstrapSourceRegistryTerminalResourceWithNativeRegistries(capture, files, native); err == nil {
		t.Fatal("aliased native registry files accepted")
	}
}

// Pure DATA regression only: the original source reference digest can later
// reference the completed registry, without appearing inside its own bytes.
func TestBootstrapRedisRegistryDoesNotEmbedFinalReferenceHash(t *testing.T) {
	policy := root.RedisCapturePolicy{Policy: recovery.RedisPolicy{Source: recovery.Reference{ID: "source", Version: "original-1", SHA256: strings.Repeat("a", 64)}, Topology: "shared_keyspace", CaptureMode: "scan_dump", TTLPolicy: "preserve_absolute", Purpose: "functional_test", Prefixes: []string{"app:"}, MaxItems: 10, MaxBytes: 1024, MaxClockSkew: 1000}, ServerID: strings.Repeat("b", 40), ExcludePrefixes: []string{"app:control:"}}
	if policy.Validate() != nil {
		t.Fatal("original finite policy fixture invalid")
	}
	data := bootstrapRedisSourceDeclaration{SourceID: policy.Policy.Source.ID, SourceVersion: policy.Policy.Source.Version, ServerID: policy.ServerID, Database: policy.Policy.DB, Topology: policy.Policy.Topology, CaptureMode: policy.Policy.CaptureMode, TTLPolicy: policy.Policy.TTLPolicy, Purpose: policy.Policy.Purpose, Prefixes: policy.Policy.Prefixes, ExcludePrefixes: policy.ExcludePrefixes, MaxItems: policy.Policy.MaxItems, MaxBytes: policy.Policy.MaxBytes, MaxClockSkew: policy.Policy.MaxClockSkew}
	raw, err := ce.Canonical(bootstrapRedisSourceRegistry{SchemaVersion: bootstrapRedisSourcesVersion, Source: data, Metadata: []root.RedisSourceMetadataEntry{}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), policy.Policy.Source.SHA256) || strings.Contains(string(raw), "MetadataScopeSHA256") || strings.Contains(string(raw), "ConfigSHA256") {
		t.Fatal("self/final authority digest inside Redis fact data")
	}
}

func TestBootstrapSecretAllowlistUsesOriginalFixedPolicy(t *testing.T) {
	policy := root.SecretCapturePolicy{SchemaVersion: root.SecretCapturePolicyVersion, RegistryKind: "secret_allowlist", RegistryVersion: "original-1", NamespaceScope: "installation_namespace", CaptureMode: "encrypted_full_object", Entries: []root.SecretCapturePolicyEntry{{ID: "database", SecretName: "database-credentials", Required: true, ExpectedType: "Opaque", Purpose: "database_credentials"}}}
	raw, err := ce.Canonical(policy)
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := root.DecodeSecretCapturePolicy(raw, policy.RegistryVersion, hash(raw))
	if err != nil {
		t.Fatal(err)
	}
	selected := []root.KubernetesSelection{{Version: "v1", Resource: "secrets", Name: "database-credentials", UID: "actual-secret-uid"}}
	if frozen.ValidateSelections("source", selected) != nil {
		t.Fatal("original policy rejected actual metadata selection")
	}
	if frozen.ValidateSelections("source", []root.KubernetesSelection{}) == nil {
		t.Fatal("missing required Secret was silently treated as no source")
	}
	selected[0].Name = "undeclared"
	if frozen.ValidateSelections("source", selected) == nil {
		t.Fatal("native observation manufactured Secret authorization")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		t.Fatal("original policy JSON")
	}
	fields["observed_uid"] = json.RawMessage(`"not-policy"`)
	changed, err := ce.Canonical(fields)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = root.DecodeSecretCapturePolicy(changed, policy.RegistryVersion, hash(changed)); err == nil {
		t.Fatal("observed facts upgraded the original allowlist policy")
	}
}

func TestBootstrapThirdFactOutputCannotAliasOrReuse(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	parts, writers, redis := filepath.Join(dir, "parts.json"), filepath.Join(dir, "writers.json"), filepath.Join(dir, "redis.json")
	if checkBootstrapSourceFactOutputs(parts, writers) != nil || checkBootstrapSourceRedisOutput(parts, writers, redis) != nil {
		t.Fatal("new private three-file destination refused")
	}
	if checkBootstrapSourceRedisOutput(parts, writers, parts) == nil {
		t.Fatal("third output aliases original part data")
	}
	if err := os.WriteFile(redis, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if checkBootstrapSourceRedisOutput(parts, writers, redis) == nil {
		t.Fatal("existing third output accepted")
	}
}
