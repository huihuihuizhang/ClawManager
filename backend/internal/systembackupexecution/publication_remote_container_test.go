package systembackupexecution

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
)

func TestOriginalPublicationConfigOnlyDeclaresThreeArtifactReferences(t *testing.T) {
	raw, err := os.ReadFile("../../../contracts/system-backup/v12/admin-control-redacted-examples.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Request struct {
			Config map[string]any `json:"config"`
		} `json:"config_update_request"`
	}
	if json.Unmarshal(raw, &document) != nil {
		t.Fatal("full original config example")
	}
	before, err := ce.Canonical(document.Request.Config)
	if err != nil {
		t.Fatal(err)
	}
	original := map[string]map[string]any{}
	for _, value := range document.Request.Config["references"].([]any) {
		ref := value.(map[string]any)
		copy := map[string]any{}
		for key, item := range ref {
			copy[key] = item
		}
		original[ref["purpose"].(string)] = copy
	}
	store, _ := newANativePublicationStore(t, time.Minute)
	if err := prepareDOriginalPublicationReferences(document.Request.Config, store.config); err != nil {
		t.Fatal(err)
	}
	changed := 0
	for _, value := range document.Request.Config["references"].([]any) {
		ref := value.(map[string]any)
		purpose := ref["purpose"].(string)
		if purpose == "artifact_read" || purpose == "artifact_write" || purpose == "artifact_ca" {
			changed++
			ref["identity_hash"], ref["version"] = original[purpose]["identity_hash"], original[purpose]["version"]
		}
	}
	after, err := ce.Canonical(document.Request.Config)
	if err != nil || changed != 3 || !bytes.Equal(before, after) {
		t.Fatal("fixture changed source/policy/durations or unrelated refs", changed, err)
	}
}

func TestRemoteContainerMemberKeepsAllOriginalLogicalBindings(t *testing.T) {
	_, _, _, facts := artifactContainerReadData(t, "installation_original_binding_DATA")
	original := facts.Header.Members[0]
	for _, mode := range []string{"physical-offsets", "cipher-hash", "stream-path", "key-context", "checkpoint-bytes"} {
		t.Run(mode, func(t *testing.T) {
			actual := original
			switch mode {
			case "physical-offsets":
				actual.CipherOffset += 100
				actual.EnvelopeOffset += 100
			case "cipher-hash":
				actual.CipherSHA256 = hash([]byte("foreign cipher DATA"))
			case "stream-path":
				actual.Stream.Path = "foreign/stream.enc"
			case "key-context":
				actual.Stream.Request.Context.EnvelopeID = "foreign-envelope-DATA"
			case "checkpoint-bytes":
				actual.Checkpoint = bytes.Clone(original.Checkpoint)
				actual.Checkpoint[0] ^= 1
			}
			if sameOriginalContainerMember(original, actual) != (mode == "physical-offsets") {
				t.Fatal("container location replaced an original logical binding", mode)
			}
		})
	}
}
