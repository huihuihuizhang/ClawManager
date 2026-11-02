package systembackupinstallationowner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

// Contract defaults and synthetic closed references test ONE resource only;
// this fixture does not supply the other missing resource owners or admit v1.
func captureConfigFixture(t *testing.T, reference sec.BootstrapSecretRef) sec.BootstrapConfig {
	t.Helper()
	raw, e := os.ReadFile("../../../contracts/system-backup/v12/admin-control-resources.schema.json")
	if e != nil {
		t.Fatal(e)
	}
	var schema struct {
		Defs map[string]struct {
			Properties map[string]struct {
				Default json.RawMessage `json:"default"`
			} `json:"properties"`
		} `json:"$defs"`
	}
	if json.Unmarshal(raw, &schema) != nil {
		t.Fatal("contract")
	}
	doc := map[string]any{"enabled": false, "alert_profile": "development", "minimum_recovery_points": 1}
	for group, def := range map[string]string{"durations": "DurationConfig", "capacity": "CapacityConfig", "concurrency": "ConcurrencyConfig", "preflight_limits": "PreflightLimits"} {
		values := map[string]json.RawMessage{}
		for name, field := range schema.Defs[def].Properties {
			if len(field.Default) == 0 {
				t.Fatal("missing contract default", name)
			}
			values[name] = field.Default
		}
		doc[group] = values
	}
	var registries []sec.BootstrapRegistryRef
	for _, kind := range []string{"parts", "redis_sources", "failure_domains", "disaster_identity_mapping", "source_writers", "rbac_bindings", "secret_allowlist", "strong_auth_issuers", "provider_proof_issuers"} {
		registries = append(registries, sec.BootstrapRegistryRef{Kind: kind, Version: "registry-1", SHA256: digest([]byte(kind))})
	}
	doc["registries"] = registries
	var refs []sec.BootstrapSecretRef
	for _, purpose := range []string{"artifact_write", "artifact_read", "artifact_delete", "artifact_upload_issuer", "artifact_ca", "evidence_store", "evidence_write", "evidence_read", "evidence_delete", "evidence_ca", "evidence_kek", "kek", "capture_signing", "acceptance_signing", "catalog_signing", "catalog_read", "catalog_append", "catalog_snapshot", "nonce_hmac", "status_relay"} {
		r := sec.BootstrapSecretRef{Purpose: purpose, IdentityHash: digest([]byte(purpose)), Version: "registry-1"}
		if purpose == "capture_signing" {
			r = reference
		}
		refs = append(refs, r)
	}
	doc["references"] = refs
	raw, e = json.Marshal(doc)
	if e != nil {
		t.Fatal(e)
	}
	c, e := sec.DecodeBootstrapConfig(raw)
	if e != nil {
		t.Fatal("contract fixture", e)
	}
	return c
}
func fixtureGrant(r Record, c sec.BootstrapConfig) sec.OfflineBootstrapGrant {
	return sec.OfflineBootstrapGrant{InstallationID: r.Target.InstallationID, ServerUUID: r.Target.ServerUUID, Database: r.Target.Database, Username: r.Actor.Username, UserID: r.Actor.UserID, MatrixKey: r.MatrixKey, ConfigSHA256: c.SHA256(), IdempotencyKey: r.IdempotencyKey, ChangeReason: "exact owner fixture plan"}
}
func bindFixtureConfig(t *testing.T, f *recordFixture) {
	t.Helper()
	c := captureConfigFixture(t, f.record.Reference)
	g := fixtureGrant(f.record, c)
	raw, _ := json.Marshal(g)
	f.record.GrantSHA256 = digest(raw)
	f.record.ConfigSHA256 = c.SHA256()
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(c.CanonicalJSON(), &fields)
	f.record.RegistrySetSHA256 = digest(fields["registries"])
	f.record.ReferenceSetSHA256 = digest(fields["references"])
}
func TestCaptureSigningValidatorPreparesOnlyExactOwnerConfigGrant(t *testing.T) {
	observer, auth, signs := signingObserverFixture(t, "")
	dir := t.TempDir()
	files := RecordFiles{filepath.Join(dir, "owner.record"), filepath.Join(dir, "owner.sig")}
	if os.WriteFile(files.RecordFile, auth.raw, 0600) != nil || os.WriteFile(files.SignatureFile, auth.signature, 0600) != nil {
		t.Fatal("record")
	}
	validator, e := NewCaptureSigningValidator(auth.pin, files, observer)
	if e != nil {
		t.Fatal(e)
	}
	config := captureConfigFixture(t, auth.record.Reference)
	grant := fixtureGrant(auth.record, config)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	checked, e := validator.Prepare(ctx, grant, config)
	if e != nil {
		t.Fatal(e)
	}
	prepared, ok := checked.(*PreparedCaptureSigning)
	if !ok || prepared.observation == nil || *signs != 1 {
		t.Fatal("real TLS resource Prepare not executed")
	}
	if checked.Recheck(ctx, nil, time.Now().UTC().Truncate(time.Microsecond)) == nil {
		t.Fatal("Prepare substituted current L2 owner authority")
	}
	grant.ChangeReason = "different plan"
	if _, e := validator.Prepare(ctx, grant, config); e == nil || *signs != 1 {
		t.Fatal("changed original grant reached provider")
	}
	if _, e := NewCaptureSigningValidator(auth.pin, files, new(CaptureSigningObserver)); e == nil {
		t.Fatal("unconstructed observer accepted")
	}
}
