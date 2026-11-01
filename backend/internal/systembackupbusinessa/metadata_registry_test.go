package systembackupbusinessa

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// Synthetic policy DATA only. Metadata acceptance must not create a source
// CaptureScope or expand the original SQL collector's closed table allowlist.
func TestPinnedMetadataRegistryDoesNotExpandCaptureScope(t *testing.T) {
	for _, mode := range []string{"reviewed-metadata-only", "unreviewed", "wrong-owner", "missing-verifier", "missing-classification", "draft", "wrong-pin", "duplicate-review"} {
		t.Run(mode, func(t *testing.T) {
			document := registryFixture(t, true)
			name := "a_metadata_extension_table"
			extension := map[string]any{"object_type": "table", "name": name, "owner": "A", "category": "ai_gateway", "data_classification": "secret", "backup_strategy": "mysql_dump", "restore_strategy": "normalize", "normalizer_id": "ai_gateway." + name + ".normalize.v1", "verifier_id": "ai_gateway." + name + ".verify.v1", "decision_status": "frozen", "required_cross_reviewers": []any{"B", "C", "D"}, "approved_cross_reviewers": []any{"B", "C", "D"}}
			switch mode {
			case "unreviewed":
				extension["approved_cross_reviewers"] = []any{"B", "C"}
			case "wrong-owner":
				extension["owner"] = "B"
			case "missing-verifier":
				extension["verifier_id"] = nil
			case "missing-classification":
				extension["data_classification"] = nil
			case "draft":
				document["contract_status"] = "draft"
			case "duplicate-review":
				extension["required_cross_reviewers"], extension["approved_cross_reviewers"] = []any{"B", "B"}, []any{"B", "B"}
			}
			objects := append(document["objects"].([]any), extension)
			document["objects"] = objects
			summary := document["summary"].(map[string]any)
			summary["object_count"], summary["policy_recorded"] = len(objects), len(objects)
			raw := registryBytes(t, document)
			digest := sha256.Sum256(raw)
			pin := hex.EncodeToString(digest[:])
			if mode == "wrong-pin" {
				pin = strings.Repeat("0", 64)
			}
			err := ValidatePinnedMetadataRegistry(raw, pin)
			if mode == "reviewed-metadata-only" {
				if err != nil {
					t.Fatal("reviewed metadata refused", err)
				}
			} else if err == nil {
				t.Fatal("unreviewed/incomplete metadata admitted", mode)
			}
			if scope, err := NewPinnedCaptureScope(raw, pin); err == nil || scope != nil {
				t.Fatal("metadata acceptance widened the legacy source CaptureScope")
			}
		})
	}
}
