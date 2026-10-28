package systembackupevidence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackupsecurity"
)

func configResponseContentFixture(t *testing.T) (ConfigResponseContentPolicy, Identity, []byte) {
	t.Helper()
	raw, err := os.ReadFile("../../../docs/evidence/a-config-canonical-request-vectors-20261014.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Vectors []struct {
			Input struct {
				Request struct {
					Config json.RawMessage `json:"config"`
				} `json:"request"`
			} `json:"input"`
		} `json:"vectors"`
	}
	if json.Unmarshal(raw, &vectors) != nil || len(vectors.Vectors) == 0 {
		t.Fatal("missing synthetic config fixture")
	}
	var config map[string]json.RawMessage
	if json.Unmarshal(vectors.Vectors[0].Input.Request.Config, &config) != nil {
		t.Fatal("missing full config")
	}
	var registries []systembackupsecurity.BootstrapRegistryRef
	var refs []systembackupsecurity.BootstrapSecretRef
	if json.Unmarshal(config["registries"], &registries) != nil || json.Unmarshal(config["references"], &refs) != nil {
		t.Fatal("invalid synthetic pins")
	}
	// Legitimate maximum-length immutable versions make a real canonical
	// ConfigResource exceed inline capacity; no padding/truncation is used.
	for n := range registries {
		registries[n].Version = strings.Repeat("v", 128)
	}
	for n := range refs {
		refs[n].Version = strings.Repeat("v", 128)
	}
	config["registries"], _ = json.Marshal(registries)
	config["references"], _ = json.Marshal(refs)
	config["enabled"] = json.RawMessage("true")
	raw, _ = json.Marshal(config)
	values, err := systembackupsecurity.DecodeConfigValues(raw)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	reason := strings.Repeat("维护", 80)
	p := ConfigResponseContentPolicy{EvidenceID: "sev_11111111-2222-4333-8444-555555555555", Classification: "confidential", ValidUntil: now.Add(5 * time.Minute),
		Response: systembackupsecurity.ConfigMutationResponseContentPolicy{InstallationID: "installation_test", CreatedBy: 42, Version: 4, Config: values, RedactedReason: &reason, CreatedAt: now, DeploymentEnabled: true}}
	raw, err = systembackupsecurity.CanonicalConfigMutationResponse(p.Response)
	if err != nil || len(raw) <= 8192 {
		t.Fatal("large canonical fixture", len(raw), err)
	}
	i := Identity{Installation: p.Response.InstallationID, ID: p.EvidenceID, OwnerType: "system", OwnerID: p.Response.InstallationID, Type: "diagnostic", Media: "application/json", Classification: p.Classification, ContentHash: hash(raw), ContentSize: int64(len(raw))}
	return p, i, raw
}

func TestConfigResponseContentDispatchEncryptedRoundTrip(t *testing.T) {
	p, i, raw := configResponseContentFixture(t)
	calls := 0
	d, err := NewContentDispatcher(contentAuthorityFunc(func(context.Context, Identity) (ContentAuthorization, error) {
		calls++
		return ContentAuthorization{Identity: i, ProducerIdentityHash: strings.Repeat("a", 64), ValidUntil: p.ValidUntil, ConfigResponse: &p}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	keys := &countingContentKeys{delegate: testKeys{key: bytes.Repeat([]byte{7}, 32)}}
	var dst bytes.Buffer
	key := KeyRef{Identity: strings.Repeat("b", 64), Version: "v1"}
	prepared, err := Prepare(context.Background(), i, key, source(raw), d, keys, &dst)
	if err != nil || calls != 2 || keys.calls != 1 {
		t.Fatal("complete response prepare", err, calls, keys.calls)
	}
	ref := Ref{Identity: strings.Repeat("a", 64), Version: "v1", RelativeKey: "evidence/config-response", ImmutableVersion: "v1"}
	store := &testStore{present: true, data: dst.Bytes(), info: ObjectInfo{Version: "v1", SHA256: hash(dst.Bytes()), Size: int64(dst.Len())}}
	got, err := OpenRange(context.Background(), prepared.Manifest(), ref, store, keys, 0, i.ContentSize-1)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("response envelope changed full canonical bytes", err)
	}
	wipe(got)
	if prepared.Manifest().Identity.Type != "diagnostic" || prepared.Manifest().Identity.ContentSize != int64(len(raw)) {
		t.Fatal("wrong evidence profile/truncated response")
	}
	// The first validator owns its expected bytes even if a caller later
	// mutates the source's reason pointer or a returned ConfigValues copy.
	v, err := NewConfigResponseRedactor(p)
	if err != nil {
		t.Fatal(err)
	}
	*p.Response.RedactedReason = "changed after construction"
	if err := v.Validate(context.Background(), i, bytes.NewReader(raw)); err != nil {
		t.Fatal("policy alias", err)
	}
}

func TestConfigResponseRejectsUnsafeFieldsAndBodyDriftBeforeKeys(t *testing.T) {
	for _, name := range []string{"extra-secret", "nested-token", "changed-reason", "changed-actor", "changed-version", "changed-enabled", "duplicate", "escaped-duplicate", "whitespace", "trailing-json", "invalid-utf8", "truncated"} {
		t.Run(name, func(t *testing.T) {
			p, i, raw := configResponseContentFixture(t)
			var doc map[string]any
			if json.Unmarshal(raw, &doc) != nil {
				t.Fatal("fixture")
			}
			switch name {
			case "extra-secret":
				doc["credential"] = "PRIVATE synthetic token"
			case "nested-token":
				doc["config"].(map[string]any)["token"] = "PRIVATE synthetic token"
			case "changed-reason":
				doc["change_reason"] = "password=PRIVATE"
			case "changed-actor":
				doc["created_by"] = "7"
			case "changed-version":
				doc["version"] = float64(5)
			case "changed-enabled":
				doc["effective_enabled"] = false
			}
			if name == "extra-secret" || name == "nested-token" || strings.HasPrefix(name, "changed-") {
				raw, _ = json.Marshal(doc)
			}
			switch name {
			case "duplicate":
				raw = bytes.Replace(raw, []byte(`"version":`), []byte(`"version":4,"version":`), 1)
			case "escaped-duplicate":
				raw = bytes.Replace(raw, []byte(`"version":`), []byte(`"\u0076ersion":4,"version":`), 1)
			case "whitespace":
				raw = append(raw, ' ')
			case "trailing-json":
				raw = append(raw, []byte(`{}`)...)
			case "invalid-utf8":
				raw = append(raw, 0xff)
			case "truncated":
				raw = raw[:len(raw)-1]
			}
			// Even replacing the caller's checksum/length cannot replace the
			// authenticated writer policy's independent complete response facts.
			i.ContentHash, i.ContentSize = hash(raw), int64(len(raw))
			v, err := NewConfigResponseRedactor(p)
			if err != nil {
				t.Fatal(err)
			}
			keys := &countingContentKeys{delegate: testKeys{key: bytes.Repeat([]byte{7}, 32)}}
			var dst bytes.Buffer
			if _, err = Prepare(context.Background(), i, KeyRef{strings.Repeat("b", 64), "v1"}, source(raw), v, keys, &dst); err != ErrRedaction || keys.calls != 0 || dst.Len() != 0 {
				t.Fatal("unreviewed response reached keys", err)
			}
		})
	}
}

func TestConfigResponseDispatcherRequiresStableLivePolicy(t *testing.T) {
	for _, name := range []string{"missing-policy", "mixed-policy", "producer-drift", "reason-drift", "config-drift", "deadline-extended", "revoked", "expired", "wrong-type", "wrong-owner", "public"} {
		t.Run(name, func(t *testing.T) {
			p, i, raw := configResponseContentFixture(t)
			calls := 0
			d, _ := NewContentDispatcher(contentAuthorityFunc(func(context.Context, Identity) (ContentAuthorization, error) {
				calls++
				a := ContentAuthorization{Identity: i, ProducerIdentityHash: strings.Repeat("a", 64), ValidUntil: p.ValidUntil, ConfigResponse: &p}
				switch name {
				case "missing-policy":
					a.ConfigResponse = nil
				case "mixed-policy":
					a.JobLog = &JobLogPolicy{}
				case "producer-drift":
					if calls == 2 {
						a.ProducerIdentityHash = strings.Repeat("c", 64)
					}
				case "reason-drift":
					if calls == 2 {
						s := "different reviewed reason"
						p.Response.RedactedReason = &s
					}
				case "config-drift":
					if calls == 2 {
						p.Response.DeploymentEnabled = false
					}
				case "deadline-extended":
					if calls == 2 {
						p.ValidUntil = p.ValidUntil.Add(time.Minute)
					}
				case "revoked":
					if calls == 2 {
						return ContentAuthorization{}, errors.New("PRIVATE revoked producer")
					}
				case "expired":
					p.ValidUntil = time.Now().Add(-time.Second)
				case "wrong-type":
					i.Type = "capability_snapshot"
					a.Identity = i
				case "wrong-owner":
					i.OwnerType = "backup"
					i.OwnerID = "sbk_11111111-2222-4333-8444-555555555555"
					a.Identity = i
				case "public":
					i.Classification = "public"
					p.Classification = "public"
					a.Identity = i
				}
				return a, nil
			}))
			// Change requested identity before entry for identity-negative cases.
			if name == "wrong-type" {
				i.Type = "capability_snapshot"
			}
			if name == "wrong-owner" {
				i.OwnerType = "backup"
				i.OwnerID = "sbk_11111111-2222-4333-8444-555555555555"
			}
			if name == "public" {
				i.Classification = "public"
			}
			keys := &countingContentKeys{delegate: testKeys{key: bytes.Repeat([]byte{7}, 32)}}
			var dst bytes.Buffer
			if _, err := Prepare(context.Background(), i, KeyRef{strings.Repeat("b", 64), "v1"}, source(raw), d, keys, &dst); err != ErrRedaction || keys.calls != 0 || dst.Len() != 0 {
				t.Fatal("unstable/missing content authority accepted", err, calls)
			}
		})
	}
}

func TestConfigResponseRejectsReaderAndContextFailure(t *testing.T) {
	p, i, raw := configResponseContentFixture(t)
	v, err := NewConfigResponseRedactor(p)
	if err != nil {
		t.Fatal(err)
	}
	var typedNil *bytes.Reader
	for _, r := range []io.Reader{nil, typedNil, failingContentReader{}, bytes.NewReader(raw[:len(raw)-1]), bytes.NewReader(append(append([]byte(nil), raw...), ' '))} {
		if err := v.Validate(context.Background(), i, r); err != ErrRedaction {
			t.Fatal("invalid reader accepted", err)
		}
	}
	if err := v.Validate(nil, i, bytes.NewReader(raw)); err != ErrRedaction {
		t.Fatal("nil context accepted", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := v.Validate(ctx, i, bytes.NewReader(raw)); err != ErrRedaction {
		t.Fatal("canceled context accepted", err)
	}
}
