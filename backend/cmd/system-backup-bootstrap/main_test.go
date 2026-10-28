package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	security "clawreef/internal/systembackupsecurity"
)

func TestRequirementsReportDoesNotPretendOwnersAreDelivered(t *testing.T) {
	var out bytes.Buffer
	if code := run(context.Background(), []string{"--requirements"}, &out, linkedOwnerAdapters()); code != 2 {
		t.Fatal(code)
	}
	var report struct {
		Status    string   `json:"status"`
		Missing   []string `json:"missing_adapters"`
		Database  bool     `json:"database_opened"`
		Mutated   bool     `json:"configuration_mutated"`
		Admission string   `json:"provider_admission"`
	}
	if json.Unmarshal(out.Bytes(), &report) != nil || report.Status != "blocked" || len(report.Missing) != 27 || report.Database || report.Mutated || report.Admission != "not_run" {
		t.Fatal(out.String())
	}
	for _, missing := range report.Missing {
		if missing == "registry:rbac_bindings" || missing == "registry:provider_proof_issuers" || missing == "registry:strong_auth_issuers" {
			t.Fatal("concrete security registry validator not linked")
		}
	}
}

func TestCommandRejectsMixedModesBypassFlagsAndUnpinnedFiles(t *testing.T) {
	for _, args := range [][]string{nil, {"--apply"}, {"--requirements", "--apply"}, {"--check", "--apply"}, {"--requirements", "--deployment-file", "PRIVATE"}, {"--requirements", "extra"}, {"--skip-owner-validation", "PRIVATE"}, {"--apply", "--deployment-file", "PRIVATE", "--deployment-sha256", "invalid"}} {
		var out bytes.Buffer
		if code := run(context.Background(), args, &out, security.BootstrapOwnerAdapters{}); code != 1 || out.Len() != 0 {
			t.Fatal(args, code, out.String())
		}
	}
}
