package systembackupevidence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackupsecurity"
)

func capabilityFixture(t *testing.T) (*CapabilityRedactor, Identity, []byte) {
	t.Helper()
	raw, e := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "system-backup", "v12", "a-owned-redacted-examples.json"))
	if e != nil {
		t.Fatal(e)
	}
	var example struct {
		Evidence systembackupsecurity.CapabilityEvidence `json:"capability_evidence"`
	}
	if e := json.Unmarshal(raw, &example); e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Truncate(time.Second)
	c := example.Evidence
	c.StartedAt = now.Add(-30 * time.Second).Format(time.RFC3339)
	c.FinishedAt = now.Add(-10 * time.Second).Format(time.RFC3339)
	c.Cleanup.VerifiedAt = now.Add(-5 * time.Second).Format(time.RFC3339)
	for n := range c.Capabilities {
		c.Capabilities[n].CheckedAt = now.Add(-20 * time.Second).Format(time.RFC3339)
		c.Capabilities[n].ExpiresAt = now.Add(2 * time.Minute).Format(time.RFC3339)
	}
	p := CapabilityContentPolicy{Installation: "installation_test", EvidenceID: "sev_11111111-2222-4333-8444-555555555555", Classification: "internal",
		Role: c.Role, ProviderIdentity: c.IdentityHash, ProviderVersion: c.RefVersion, ScopeHash: c.ScopeHash, RunID: c.Cleanup.RunID, OwnerMarker: c.Cleanup.Owner,
		ObservedVersion: c.ObservedVersion, MaxValidity: 5 * time.Minute, ValidUntil: now.Add(4 * time.Minute)}
	v, e := NewCapabilityRedactor(p)
	if e != nil {
		t.Fatal(e)
	}
	raw, e = json.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	// JSON whitespace is legal payload and checksum-bound. Padding only exercises
	// the external (>8 KiB) path; it is not prescribed as a producer format.
	raw = padCapability(raw)
	i := Identity{Installation: p.Installation, ID: p.EvidenceID, OwnerType: "system", OwnerID: p.Installation, Type: "capability_snapshot", Media: "application/json", Classification: p.Classification, ContentHash: hash(raw), ContentSize: int64(len(raw))}
	return v, i, raw
}

func padCapability(raw []byte) []byte {
	if len(raw) < 9000 {
		raw = append(raw, bytes.Repeat([]byte(" "), 9000-len(raw))...)
	}
	return raw
}

type countingContentKeys struct {
	delegate testKeys
	calls    int
}

func (k *countingContentKeys) Wrap(ctx context.Context, ref KeyRef, b []byte) ([]byte, error) {
	k.calls++
	return k.delegate.Wrap(ctx, ref, b)
}
func (k *countingContentKeys) Unwrap(ctx context.Context, ref KeyRef, b []byte) ([]byte, error) {
	return k.delegate.Unwrap(ctx, ref, b)
}

func TestCapabilityContentEnvelope(t *testing.T) {
	v, i, raw := capabilityFixture(t)
	_, _, _, keys := fixture(t, 9000)
	var dst bytes.Buffer
	p, e := Prepare(context.Background(), i, KeyRef{strings.Repeat("b", 64), "v1"}, source(raw), v, keys, &dst)
	if e != nil {
		t.Fatal(e)
	}
	ref := Ref{Identity: strings.Repeat("a", 64), Version: "v1", RelativeKey: "evidence/installation_test/capability", ImmutableVersion: "v1"}
	store := &testStore{present: true, data: dst.Bytes(), info: ObjectInfo{Version: ref.ImmutableVersion, SHA256: hash(dst.Bytes()), Size: int64(dst.Len())}}
	got, e := OpenRange(context.Background(), p.Manifest(), ref, store, keys, 0, i.ContentSize-1)
	if e != nil || !bytes.Equal(got, raw) {
		t.Fatal("validated content changed during encryption", e)
	}
	wipe(got)
	if v.policy.ObservedVersion != nil {
		copyPolicy := v.policy
		original := *copyPolicy.ObservedVersion
		copyPolicy.ObservedVersion = &original
		other, e := NewCapabilityRedactor(copyPolicy)
		if e != nil {
			t.Fatal(e)
		}
		original = "changed-after-construction"
		if e := other.Validate(context.Background(), i, bytes.NewReader(raw)); e != nil {
			t.Fatal("policy pointer was not copied")
		}
	}
}

func TestCapabilityContentRejectsUnsafeJSONBeforeKeys(t *testing.T) {
	for _, mode := range []string{"unknown-root", "unknown-redaction", "unknown-cleanup", "unknown-observation", "duplicate-root", "escaped-duplicate", "duplicate-redaction", "duplicate-cleanup", "duplicate-observation", "case-folded-key", "null-raw-flag", "null-removed-list", "wrong-provider", "wrong-run", "wrong-version", "raw-material", "expired-observation", "duplicate-observation-code", "trailing-json", "invalid-utf8"} {
		t.Run(mode, func(t *testing.T) {
			v, i, raw := capabilityFixture(t)
			var document map[string]any
			if e := json.Unmarshal(raw, &document); e != nil {
				t.Fatal(e)
			}
			redaction := document["redaction"].(map[string]any)
			cleanup := document["cleanup"].(map[string]any)
			observation := document["capabilities"].([]any)[0].(map[string]any)
			switch mode {
			case "unknown-root":
				document["credential"] = "PRIVATE rejected value"
			case "unknown-redaction":
				redaction["raw_response"] = "PRIVATE rejected value"
			case "unknown-cleanup":
				cleanup["uri"] = "https://PRIVATE.invalid/secret"
			case "unknown-observation":
				observation["stderr"] = "PRIVATE rejected value"
			case "case-folded-key":
				document["Provider_role"] = document["provider_role"]
				delete(document, "provider_role")
			case "null-raw-flag":
				redaction["raw_material_present"] = nil
			case "null-removed-list":
				redaction["removed_field_classes"] = nil
			case "wrong-provider":
				document["provider_identity_hash"] = strings.Repeat("c", 64)
			case "wrong-run":
				cleanup["run_id"] = "cap-other-run-1234"
			case "wrong-version":
				document["observed_provider_version"] = "other-version"
			case "raw-material":
				redaction["raw_material_present"] = true
			case "expired-observation":
				observation["expires_at"] = time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
			case "duplicate-observation-code":
				document["capabilities"] = append(document["capabilities"].([]any), observation)
			}
			raw, _ = json.Marshal(document)
			switch mode {
			case "duplicate-root":
				raw = bytes.Replace(raw, []byte(`"provider_role":`), []byte(`"provider_role":"evidence","provider_role":`), 1)
			case "escaped-duplicate":
				raw = bytes.Replace(raw, []byte(`"provider_role":`), []byte(`"\u0070rovider_role":"evidence","provider_role":`), 1)
			case "duplicate-redaction":
				raw = bytes.Replace(raw, []byte(`"applied":`), []byte(`"applied":true,"applied":`), 1)
			case "duplicate-cleanup":
				raw = bytes.Replace(raw, []byte(`"run_id":`), []byte(`"run_id":"cap-other-run-1234","run_id":`), 1)
			case "duplicate-observation":
				raw = bytes.Replace(raw, []byte(`"status":`), []byte(`"status":"supported","status":`), 1)
			case "trailing-json":
				raw = append(raw, []byte(` {"credential":"PRIVATE"}`)...)
			case "invalid-utf8":
				raw = append(raw, 0xff)
			}
			raw = padCapability(raw)
			i.ContentHash = hash(raw)
			i.ContentSize = int64(len(raw))
			keys := &countingContentKeys{delegate: testKeys{key: bytes.Repeat([]byte{7}, 32)}}
			var dst bytes.Buffer
			if _, e := Prepare(context.Background(), i, KeyRef{strings.Repeat("b", 64), "v1"}, source(raw), v, keys, &dst); e != ErrRedaction || keys.calls != 0 || dst.Len() != 0 {
				t.Fatal("unsafe content reached keys or staging", e)
			}
		})
	}
}

func TestCapabilityContentRequiresSchemaFields(t *testing.T) {
	rawSchema, e := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "system-backup", "v12", "capability-evidence.schema.json"))
	if e != nil {
		t.Fatal(e)
	}
	var schema struct {
		Required    []string `json:"required"`
		Definitions map[string]struct {
			Required []string `json:"required"`
		} `json:"$defs"`
	}
	if e := json.Unmarshal(rawSchema, &schema); e != nil {
		t.Fatal(e)
	}
	sets := map[string][]string{"root": schema.Required, "Redaction": schema.Definitions["Redaction"].Required, "Cleanup": schema.Definitions["Cleanup"].Required, "Capability": schema.Definitions["Capability"].Required}
	for name, required := range sets {
		if len(required) == 0 {
			t.Fatal("empty contract required-field set")
		}
		for _, field := range required {
			t.Run(name+"/"+field, func(t *testing.T) {
				v, i, raw := capabilityFixture(t)
				var document map[string]any
				json.Unmarshal(raw, &document)
				fields := document
				switch name {
				case "Redaction":
					fields = document["redaction"].(map[string]any)
				case "Cleanup":
					fields = document["cleanup"].(map[string]any)
				case "Capability":
					fields = document["capabilities"].([]any)[0].(map[string]any)
				}
				delete(fields, field)
				raw, _ = json.Marshal(document)
				raw = padCapability(raw)
				i.ContentHash = hash(raw)
				i.ContentSize = int64(len(raw))
				if e := v.Validate(context.Background(), i, bytes.NewReader(raw)); e != ErrRedaction {
					t.Fatal("required contract field omitted")
				}
			})
		}
	}
}

type failingContentReader struct{}

func (failingContentReader) Read([]byte) (int, error) {
	return 0, errors.New("PRIVATE raw source failure")
}

func TestCapabilityContentBindingAndLimits(t *testing.T) {
	v, i, raw := capabilityFixture(t)
	for _, mutate := range []func(*Identity){
		func(i *Identity) { i.Type = "diagnostic" },
		func(i *Identity) { i.Media = "text/plain" },
		func(i *Identity) { i.Classification = "public" },
		func(i *Identity) { i.ID = "sev_22222222-2222-4333-8444-555555555555" },
		func(i *Identity) { i.Installation = "installation_other"; i.OwnerID = i.Installation },
		func(i *Identity) { i.ContentSize = MaxCapabilityContent + 1 },
		func(i *Identity) { i.ContentHash = strings.Repeat("0", 64) },
	} {
		bad := i
		mutate(&bad)
		if e := v.Validate(context.Background(), bad, bytes.NewReader(raw)); e != ErrRedaction {
			t.Fatal("identity binding bypassed")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := v.Validate(ctx, i, bytes.NewReader(raw)); e != ErrRedaction {
		t.Fatal("canceled validation accepted")
	}
	for _, reader := range []io.Reader{nil, failingContentReader{}, bytes.NewReader(raw[:len(raw)-1]), bytes.NewReader(append(append([]byte(nil), raw...), ' '))} {
		if e := v.Validate(context.Background(), i, reader); e != ErrRedaction {
			t.Fatal("source failure or drift accepted")
		}
	}
	for _, mutate := range []func(*CapabilityContentPolicy){
		func(p *CapabilityContentPolicy) { p.ValidUntil = time.Now().Add(-time.Second) },
		func(p *CapabilityContentPolicy) { p.MaxValidity = 0 },
		func(p *CapabilityContentPolicy) { p.ProviderVersion = "https://PRIVATE.invalid/ref" },
		func(p *CapabilityContentPolicy) { x := "https://PRIVATE.invalid/version"; p.ObservedVersion = &x },
		func(p *CapabilityContentPolicy) { p.RunID = "" },
	} {
		bad := v.policy
		mutate(&bad)
		if _, e := NewCapabilityRedactor(bad); e != ErrRedaction {
			t.Fatal("invalid policy accepted")
		}
	}
	v.policy.ValidUntil = time.Now().Add(-time.Second)
	if e := v.Validate(context.Background(), i, bytes.NewReader(raw)); e != ErrRedaction {
		t.Fatal("expired trusted policy accepted")
	}
}

func TestEvidenceTypeOwnerMatrix(t *testing.T) {
	allowed := map[string]string{
		"provider_presence_proof": "external_action", "provider_absence_proof": "external_action",
		"ownership_proof": "backup_staging restore_resource", "provider_deletion_receipt": "backup_staging restore_resource prune_run",
		"catalog_scan_receipt": "catalog_scan", "failure_domain_attestation": "backup promotion system",
		"job_log_chunk": "backup drill preflight artifact_verify", "promotion_release_bundle": "promotion", "capability_snapshot": "system",
		"cleanup_result":  "backup backup_staging drill restore_resource prune_run",
		"verifier_report": "backup drill preflight artifact_verify catalog_import catalog_record prune_run promotion system",
		"diagnostic":      "backup backup_staging external_action drill restore_resource preflight artifact_verify catalog_scan catalog_record catalog_import prune_run promotion system",
	}
	p, _, _, keys := fixture(t, 9000)
	owners := map[string]string{"system": p.manifest.Identity.Installation}
	for name, pattern := range ownerPatterns {
		prefix := strings.Split(strings.TrimPrefix(pattern.String(), "^"), "_[")[0]
		owners[name] = prefix + "_11111111-2222-4333-8444-555555555555"
	}
	checked := 0
	for kind, names := range allowed {
		for owner, id := range owners {
			i := p.manifest.Identity
			i.Type = kind
			i.OwnerType = owner
			i.OwnerID = id
			want := strings.Contains(" "+names+" ", " "+owner+" ")
			if i.valid() != want {
				t.Fatalf("invalid type/owner admission: %s/%s", kind, owner)
			}
			checked++
		}
	}
	if checked != 156 {
		t.Fatal("owner/type coverage changed", checked)
	}
	i := p.manifest.Identity
	i.Type = "provider_absence_proof"
	var dst bytes.Buffer
	if _, e := Prepare(context.Background(), i, p.manifest.Key, source(nil), testRedactor{}, keys, &dst); e != ErrInvalid || dst.Len() != 0 {
		t.Fatal("invalid owner reached preparation")
	}
	m := p.Manifest()
	m.Identity = i
	m.ChunkRoot = hash(canonical(m.Chunks))
	if validateManifest(m) == nil {
		t.Fatal("legacy invalid owner accepted for read")
	}
}
