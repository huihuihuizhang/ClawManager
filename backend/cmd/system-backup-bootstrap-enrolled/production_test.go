package main

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"
)

func TestEnrolledBootstrapRequirementsReportsUnpreparedSources(t *testing.T) {
	expected := []string{"registry:parts", "registry:redis_sources", "registry:failure_domains", "registry:disaster_identity_mapping", "registry:source_writers", "registry:secret_allowlist", "reference:artifact_write", "reference:artifact_read", "reference:artifact_delete", "reference:artifact_upload_issuer", "reference:artifact_ca", "reference:evidence_store", "reference:evidence_write", "reference:evidence_read", "reference:evidence_delete", "reference:evidence_ca", "reference:evidence_kek", "reference:kek", "reference:acceptance_signing", "reference:catalog_signing", "reference:catalog_read", "reference:catalog_append", "reference:catalog_snapshot", "reference:nonce_hmac", "reference:status_relay"}
	for _, mode := range []string{"--requirements", "--requirements=true"} {
		var out bytes.Buffer
		if code := runEnrolled(context.Background(), []string{mode}, &out); code != 2 {
			t.Fatal("requirements gate", code)
		}
		var report struct {
			Status   string   `json:"status"`
			Missing  []string `json:"missing_adapters"`
			Provider string   `json:"provider_admission"`
			Database bool     `json:"database_opened"`
		}
		if json.Unmarshal(out.Bytes(), &report) != nil || report.Status != "blocked" || !reflect.DeepEqual(report.Missing, expected) || report.Provider != "not_run" || report.Database {
			t.Fatal("constructor link claimed complete admission")
		}
		for _, key := range report.Missing {
			if key == "reference:capture_signing" || key == "cross_resources" {
				t.Fatal("actual constructor was not linked")
			}
		}
	}
}

func TestEnrolledBootstrapRejectsUnpinnedCompositionAndMixedModes(t *testing.T) {
	for _, args := range [][]string{nil, {"--check"}, {"--apply"}, {"--requirements", "--composition-file", "missing"}, {"--requirements", "--apply"}, {"--unknown"}, {"--check", "--deployment-file", "missing", "--deployment-sha256", "missing"}} {
		var out bytes.Buffer
		if code := runEnrolled(context.Background(), args, &out); code != 1 || out.Len() != 0 {
			t.Fatal("uncontrolled composition performed work", code)
		}
	}
}
