package install

import (
	"context"
	"encoding/json"
	"path/filepath"
	"sort"
	"testing"
	"time"

	backup "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/worker"
	sec "clawreef/internal/systembackupsecurity"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

func TestOriginalCrossResourceRejectsDetachedAndCopiedGraphs(t *testing.T) {
	f := newAuthorityFixture(t)
	dir := t.TempDir()
	capture := NewCaptureSigningConsumer(filepath.Join(dir, "original-consumer.json"), filepath.Join(dir, "original-consumer.sha256"))
	resource, e := NewOriginalCrossResourceRelations(capture)
	if e != nil {
		t.Fatal(e)
	}
	binding, e := resource.BindingSHA256()
	if e != nil || !digestPattern.MatchString(binding) {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	raw, e := resource.PrepareTerminalResource(ctx, f.grant, f.config)
	if e != nil {
		t.Fatal(e)
	}
	c := raw.(*originalCrossResourceCheck)
	if c.DependencyDeadline() != nil {
		t.Fatal("detached constructor counted as observed graph")
	}
	if _, e := c.AuthorizeIdentity(ctx, nil); e == nil {
		t.Fatal("detached graph acquired original SQL authority")
	}
	original := &originalCrossResourceCheck{}
	original.origin = original
	copyCheck := &originalCrossResourceCheck{origin: original}
	if copyCheck.DependencyDeadline() != nil || !original.failed.Load() {
		t.Fatal("copied relation capability did not poison origin")
	}
	if _, e := NewOriginalCrossResourceRelations(nil); e == nil {
		t.Fatal("missing actual capture accepted")
	}
}

// Positive typed JOIN semantics only; the original terminal's private hook is
// the only way to attach actual authenticated owner checks and SQL authority.
// This test does not fabricate those checks or assert a terminal/page success.
func TestOriginalCrossResourceJoinsExactDisasterAndSecretSourcePins(t *testing.T) {
	f := newAuthorityFixture(t)
	installation, namespace := f.record.Target.InstallationID, f.record.Target.Namespace
	registry := map[string][]byte{}
	for _, pin := range f.config.Registries() {
		registry[pin.Kind] = []byte(`{"comparison":"other-owner"}`)
	}
	policy := backup.SecretCapturePolicy{SchemaVersion: backup.SecretCapturePolicyVersion, RegistryKind: "secret_allowlist", RegistryVersion: "allow-v1", NamespaceScope: "installation_namespace", CaptureMode: "encrypted_full_object", Entries: []backup.SecretCapturePolicyEntry{{ID: "database", SecretName: "business-secret", Required: true, ExpectedType: "Opaque", Purpose: "database_credentials"}}}
	raw, _ := json.Marshal(policy)
	raw, e := jsoncanonicalizer.Transform(raw)
	if e != nil {
		t.Fatal(e)
	}
	registry["secret_allowlist"] = raw
	frozen, e := backup.DecodeSecretCapturePolicy(raw, "allow-v1", hash(raw))
	if e != nil {
		t.Fatal(e)
	}
	parts := struct {
		SchemaVersion, Installation, Version string
		Secrets                              worker.ResourceCaptureSpec
	}{"system-backup-original-source-parts.v2", installation, "parts-v1", worker.ResourceCaptureSpec{Part: "secret_bundle", Namespace: namespace, NamespaceUID: f.record.Target.NamespaceUID, SecretPolicy: &frozen, Selections: []backup.KubernetesSelection{{Version: "v1", Resource: "secrets", Name: "business-secret", UID: "actual-component-secret-uid"}}}}
	registry["parts"], e = canonical(parts)
	if e != nil {
		t.Fatal(e)
	}
	refs := f.config.References()
	sort.Slice(refs, func(a, b int) bool { return refs[a].Purpose < refs[b].Purpose })
	mapping := FunctionalDisasterIdentityRegistry{SchemaVersion: FunctionalDisasterMappingVersion, Profile: FunctionalNonDRProfile, Installation: installation, Version: "map-v1", State: "unavailable"}
	for _, ref := range refs {
		mapping.Entries = append(mapping.Entries, FunctionalDisasterIdentityEntry{Purpose: ref.Purpose, IdentityHash: ref.IdentityHash, ReferenceVersion: ref.Version, State: "unavailable", Reason: "not_provided"})
	}
	registry["disaster_identity_mapping"], e = canonical(mapping)
	if e != nil {
		t.Fatal(e)
	}
	var values map[string]any
	if json.Unmarshal(f.config.CanonicalJSON(), &values) != nil {
		t.Fatal("config")
	}
	versions := map[string]string{"parts": "parts-v1", "secret_allowlist": "allow-v1", "disaster_identity_mapping": "map-v1"}
	for _, value := range values["registries"].([]any) {
		pin := value.(map[string]any)
		kind := pin["registry_kind"].(string)
		pin["sha256"] = hash(registry[kind])
		if v := versions[kind]; v != "" {
			pin["version"] = v
		}
	}
	raw, e = json.Marshal(values)
	if e != nil {
		t.Fatal(e)
	}
	config, e := sec.DecodeBootstrapConfig(raw)
	if e != nil {
		t.Fatal(e)
	}
	if e := originalCrossResourceRegistryRelations(config, installation, namespace, f.record.Target.NamespaceUID, registry); e != nil {
		t.Fatal("actual typed relation join", e)
	}
	// Actual B28 facts carry observed selections but no derived authority.
	// Re-pin the real modified fact bytes in config, rather than merely testing
	// a stale hash rejection before the typed relation is reached.
	for _, mode := range []string{"actual-B28-no-embedded-policy", "unauthorized-selected-secret", "foreign-embedded-policy"} {
		t.Run(mode, func(t *testing.T) {
			candidate := map[string][]byte{}
			for k, v := range registry {
				candidate[k] = append([]byte(nil), v...)
			}
			p := parts
			p.Secrets.SecretPolicy = nil
			p.Secrets.Selections = append([]backup.KubernetesSelection(nil), parts.Secrets.Selections...)
			if mode == "unauthorized-selected-secret" {
				p.Secrets.Selections[0].Name = "not-in-original-policy"
			}
			if mode == "foreign-embedded-policy" {
				foreign := frozen
				foreign.SHA256 = "foreign-policy"
				p.Secrets.SecretPolicy = &foreign
			}
			candidate["parts"], e = canonical(p)
			if e != nil {
				t.Fatal(e)
			}
			var nextValues map[string]any
			if json.Unmarshal(config.CanonicalJSON(), &nextValues) != nil {
				t.Fatal("config")
			}
			for _, v := range nextValues["registries"].([]any) {
				pin := v.(map[string]any)
				if pin["registry_kind"] == "parts" {
					pin["sha256"] = hash(candidate["parts"])
				}
			}
			nextRaw, e := json.Marshal(nextValues)
			if e != nil {
				t.Fatal(e)
			}
			next, e := sec.DecodeBootstrapConfig(nextRaw)
			if e != nil {
				t.Fatal(e)
			}
			e = originalCrossResourceRegistryRelations(next, installation, namespace, f.record.Target.NamespaceUID, candidate)
			if (mode == "actual-B28-no-embedded-policy") != (e == nil) {
				t.Fatal("actual facts/policy authority join", mode, e)
			}
		})
	}
	for _, fault := range []string{"different-installation", "different-namespace", "missing-registry", "changed-bytes"} {
		t.Run(fault, func(t *testing.T) {
			candidate := map[string][]byte{}
			for k, v := range registry {
				candidate[k] = append([]byte(nil), v...)
			}
			i, n := installation, namespace
			switch fault {
			case "different-installation":
				i += "-foreign"
			case "different-namespace":
				n += "-foreign"
			case "missing-registry":
				delete(candidate, "source_writers")
			case "changed-bytes":
				candidate["secret_allowlist"] = []byte(`{}`)
			}
			if originalCrossResourceRegistryRelations(config, i, n, f.record.Target.NamespaceUID, candidate) == nil {
				t.Fatal("cross source relation mismatch accepted")
			}
		})
	}
}
