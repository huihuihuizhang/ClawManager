package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
)

func TestEnabledForwardRequiresOriginalPrivateAndPreservesEveryOtherField(t *testing.T) {
	public, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(key)
	_, other, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(other)
	original := c.ExecutionGrant{Version: "system-backup-execution-grant.v1", InstallationID: "installation_original", ControllerOwner: "controller:original", DatabaseAccount: "runtime@localhost", ServerUUID: "original-server", Database: "original", ConfigVersion: 1, ConfigSHA256: strings.Repeat("a", 64), ProfileSHA256: strings.Repeat("b", 64), NotBefore: time.Now().UTC().Add(-time.Minute), ExpiresAt: time.Now().UTC().Add(time.Hour), Actions: []string{"capture"}, RecordKeys: []c.ExecutionRecordKey{{Ref: "record-1", SHA256: strings.Repeat("c", 64)}}}
	payload, e := canonical(original)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := canonical(map[string]string{"payload_base64": base64.StdEncoding.EncodeToString(payload), "signature_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload))})
	if e != nil {
		t.Fatal(e)
	}
	saved := bytes.Clone(raw)
	for _, mode := range []string{"original", "json-marshaled-original", "wrong-issuer", "noncanonical-private", "changed-original-scope", "wrong-version", "same-hash", "tampered-envelope"} {
		t.Run(mode, func(t *testing.T) {
			selected := bytes.Clone(key)
			defer clear(selected)
			g := original
			input := bytes.Clone(raw)
			version := uint64(2)
			sum := strings.Repeat("d", 64)
			switch mode {
			case "json-marshaled-original":
				native, _ := json.Marshal(original)
				input, _ = json.Marshal(map[string]string{"payload_base64": base64.StdEncoding.EncodeToString(native), "signature_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(key, native))})
			case "wrong-issuer":
				copy(selected, other)
			case "noncanonical-private":
				selected[63] ^= 1
			case "changed-original-scope":
				g.ConfigVersion = 9
			case "wrong-version":
				version = 3
			case "same-hash":
				sum = g.ConfigSHA256
			case "tampered-envelope":
				input[len(input)/2] ^= 1
			}
			out, e := signEnabledForward(input, g, version, sum, selected)
			if mode != "original" && mode != "json-marshaled-original" {
				if e == nil {
					t.Fatal("accepted invalid source")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			var envelope struct {
				Payload   string `json:"payload_base64"`
				Signature string `json:"signature_base64"`
			}
			if json.Unmarshal(out, &envelope) != nil {
				t.Fatal("envelope")
			}
			next, _ := base64.StdEncoding.Strict().DecodeString(envelope.Payload)
			sig, _ := base64.StdEncoding.Strict().DecodeString(envelope.Signature)
			if !ed25519.Verify(public, next, sig) {
				t.Fatal("original issuer missing")
			}
			var actual c.ExecutionGrant
			if json.Unmarshal(next, &actual) != nil || actual.ConfigVersion != 2 || actual.ConfigSHA256 != sum {
				t.Fatal("wrong enabled scope")
			}
			actual.ConfigVersion = 1
			actual.ConfigSHA256 = original.ConfigSHA256
			if !reflect.DeepEqual(actual, original) {
				t.Fatal("original rights or deadline changed")
			}
		})
	}
	if !bytes.Equal(raw, saved) {
		t.Fatal("old file data mutated")
	}
}

func TestEnabledPublicationRejectsForgedProof(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, p := range []*OriginalEnabledPublication{nil, {}, {failed: true}} {
		if p.Recheck(ctx) == nil {
			t.Fatal("forged proof accepted")
		}
	}
}

func TestOriginalEnabledRelationAllowsOnlyOneChangedBoolean(t *testing.T) {
	f := newAuthorityFixture(t)
	original := f.config.CanonicalJSON()
	var doc map[string]json.RawMessage
	if json.Unmarshal(original, &doc) != nil {
		t.Fatal("fixture")
	}
	for _, mode := range []string{"enable-only", "still-disabled", "other-value-changed", "invalid-config"} {
		t.Run(mode, func(t *testing.T) {
			fields := map[string]json.RawMessage{}
			for k, v := range doc {
				fields[k] = bytes.Clone(v)
			}
			fields["enabled"] = json.RawMessage("true")
			if mode == "still-disabled" {
				fields["enabled"] = json.RawMessage("false")
			}
			if mode == "other-value-changed" {
				fields["minimum_recovery_points"] = json.RawMessage("2")
			}
			raw, _ := json.Marshal(fields)
			if mode == "invalid-config" {
				raw = []byte(`{"enabled":true}`)
			}
			e := originalEnabledOnlyRelation(original, raw)
			if (e == nil) != (mode == "enable-only") {
				t.Fatalf("wrong result %v", e)
			}
		})
	}
}
