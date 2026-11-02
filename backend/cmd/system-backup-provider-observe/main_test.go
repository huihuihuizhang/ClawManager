package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	a "clawreef/internal/systembackupkekadapter"
)

func TestProviderInstallPlanKeepsPrivateOutputAndExplicitNonAdmission(t *testing.T) {
	// These values are installation-plan DATA, never live authentication proof.
	var input observationInput
	input.Provider.Binding.Provider.KeyName = "original-key"
	input.Provider.Binding.Key.ProviderVersion = "1"
	input.Provider.ObserverPolicy = "backup-observer"
	input.Provider.Worker = a.VaultPermissionRole{AuthMount: "backup-worker-jwt", Role: "backup-worker", Policy: "backup-generate", Audience: "clawmanager-backup-worker", Namespace: "backup", ServiceAccountName: "worker", ServiceAccountUID: "worker-sa-data"}
	input.Provider.Publisher = a.VaultPermissionRole{AuthMount: "backup-publisher-jwt", Role: "backup-publisher", Policy: "backup-unwrap", Audience: "clawmanager-backup-publisher", Namespace: "backup", ServiceAccountName: "publisher", ServiceAccountUID: "publisher-sa-data", PodUID: "publisher-pod-data"}
	input.Provider.Trust = a.VaultJWTTrust{Issuer: "https://kubernetes.default.svc.cluster.local", JWKSURL: "https://10.130.14.23:6443/openid/v1/jwks", JWKSCAPEM: "installation CA DATA only", Algorithms: []string{"RS256"}}
	dir := t.TempDir()
	var out bytes.Buffer
	if err := writePlan(input, dir, &out); err != nil {
		t.Fatal("desired installation payloads rejected", err)
	}
	var status map[string]any
	if json.Unmarshal(out.Bytes(), &status) != nil || status["status"] != "desired_installation_payloads_only" || status["provider_observed"] != false || status["bootstrap_admitted"] != false {
		t.Fatal("desired configuration claimed live observation or admission")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 9 {
		t.Fatal("installation payload set incomplete")
	}
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil || !json.Valid(raw) {
			t.Fatal("invalid installation payload", entry.Name())
		}
	}
	if err := writePlan(input, dir, &out); err == nil {
		t.Fatal("existing owner files overwritten")
	}
	if _, err := os.Stat(filepath.Join(dir, "generate.capability.json")); !os.IsNotExist(err) {
		t.Fatal("plan emitted an observed capability")
	}
}
