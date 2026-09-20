package systembackupresources

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func currentRegistry(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile("../../../contracts/system-backup/v12/schema-registry.json")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func frozenFixture(t *testing.T) map[string]any {
	t.Helper()
	document := currentRegistry(t)
	document["contract_status"] = "frozen"
	// Synthetic test-only evidence exercises the collector gate; it is not a
	// reviewed live schema-hash observation or a registry artifact.
	schemaHash := document["schema_hash"].(map[string]any)
	schemaHash["status"] = "observed"
	schemaHash["hash"] = strings.Repeat("a", 64)
	schemaHash["evidence"] = map[string]any{"public_id": "sev_fixture", "sha256": strings.Repeat("b", 64)}
	summary := document["summary"].(map[string]any)
	summary["policy_recorded"] = len(document["objects"].([]any))
	summary["policy_pending"] = 0
	summary["cross_review_pending"] = 0
	for _, raw := range document["objects"].([]any) {
		object := raw.(map[string]any)
		object["decision_status"] = "frozen"
		object["approved_cross_reviewers"] = object["required_cross_reviewers"]
	}
	return document
}

func captureScope(t *testing.T, document map[string]any) ([]string, error) {
	t.Helper()
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return CaptureTableAllowlist(data)
}

func resourceObject(t *testing.T, document map[string]any, name string) map[string]any {
	t.Helper()
	for _, raw := range document["objects"].([]any) {
		object := raw.(map[string]any)
		if object["name"] == name {
			return object
		}
	}
	t.Fatalf("missing fixture object %s", name)
	return nil
}

func TestCaptureTableAllowlistRejectsCurrentDraft(t *testing.T) {
	if tables, err := captureScope(t, currentRegistry(t)); err == nil || tables != nil {
		t.Fatalf("draft registry admitted: tables=%v err=%v", tables, err)
	}
}

func TestCaptureTableAllowlistFrozenResourcesOnly(t *testing.T) {
	tables, err := captureScope(t, frozenFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"audit_logs", "egress_private_exceptions", "northbound_admin_settings",
		"northbound_settings_audit", "security_scan_configs", "security_scan_job_items",
		"security_scan_jobs", "security_scan_reports", "system_image_settings",
	}
	if !reflect.DeepEqual(tables, want) {
		t.Fatalf("scope=%v, want %v", tables, want)
	}
	for _, table := range tables {
		if strings.HasPrefix(table, "system_backup") {
			t.Fatalf("control table admitted: %s", table)
		}
	}
}

func TestCaptureTableAllowlistFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"unreviewed", func(d map[string]any) { resourceObject(t, d, "audit_logs")["approved_cross_reviewers"] = []any{} }},
		{"pending schema hash", func(d map[string]any) { d["schema_hash"].(map[string]any)["status"] = "pending_live_evidence" }},
		{"missing schema evidence", func(d map[string]any) { d["schema_hash"].(map[string]any)["evidence"] = nil }},
		{"malformed schema hash", func(d map[string]any) { d["schema_hash"].(map[string]any)["hash"] = "not-a-sha256" }},
		{"pending policy summary", func(d map[string]any) { d["summary"].(map[string]any)["policy_pending"] = 1 }},
		{"pending review summary", func(d map[string]any) { d["summary"].(map[string]any)["cross_review_pending"] = 1 }},
		{"wrong object count", func(d map[string]any) { d["summary"].(map[string]any)["object_count"] = 1 }},
		{"wrong registry version", func(d map[string]any) { d["registry_version"] = "other" }},
		{"extra reviewer", func(d map[string]any) {
			resourceObject(t, d, "audit_logs")["approved_cross_reviewers"] = []any{"A", "B", "C"}
		}},
		{"duplicate reviewer", func(d map[string]any) {
			resourceObject(t, d, "audit_logs")["approved_cross_reviewers"] = []any{"A", "A"}
		}},
		{"unreviewed other domain", func(d map[string]any) {
			resourceObject(t, d, "audit_events")["required_cross_reviewers"] = []any{"D"}
		}},
		{"self review other domain", func(d map[string]any) {
			resourceObject(t, d, "audit_events")["required_cross_reviewers"] = []any{"A"}
		}},
		{"draft decision", func(d map[string]any) { resourceObject(t, d, "audit_logs")["decision_status"] = "owner_recorded" }},
		{"missing table", func(d map[string]any) { resourceObject(t, d, "audit_logs")["category"] = "system_backup" }},
		{"extra table", func(d map[string]any) { resourceObject(t, d, "system_backups")["category"] = "resources" }},
		{"wrong owner", func(d map[string]any) { resourceObject(t, d, "audit_logs")["owner"] = "A" }},
		{"secret classification", func(d map[string]any) { resourceObject(t, d, "audit_logs")["data_classification"] = "secret" }},
		{"not dumped", func(d map[string]any) { resourceObject(t, d, "audit_logs")["backup_strategy"] = "metadata_only" }},
		{"unregistered verifier", func(d map[string]any) { resourceObject(t, d, "audit_logs")["verifier_id"] = "other" }},
		{"duplicate object", func(d map[string]any) {
			d["objects"] = append(d["objects"].([]any), resourceObject(t, d, "audit_logs"))
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			document := frozenFixture(t)
			tc.mutate(document)
			if tables, err := captureScope(t, document); err == nil || tables != nil {
				t.Fatalf("invalid scope admitted: tables=%v err=%v", tables, err)
			}
		})
	}
}
