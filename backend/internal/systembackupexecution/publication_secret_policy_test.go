package systembackupexecution

import (
	"encoding/json"
	"strings"
	"testing"

	root "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
)

// Named policy/config/count DATA. No private capture receipt or authority.
func TestPublicationSecretPolicySummaryRequiresOriginalPinAndCompleteEntries(t *testing.T) {
	for _, mode := range []string{"current", "optional-present", "missing-policy", "wrong-config-version", "wrong-config-sha", "duplicate-config-pin", "missing-required", "extra-selection", "count-only-coverage", "incomplete-coverage", "incomplete-payload", "wrong-policy-sha", "wrong-required-count", "wrong-captured-count", "negative-bytes", "wrong-part"} {
		t.Run(mode, func(t *testing.T) {
			p := root.SecretCapturePolicy{SchemaVersion: root.SecretCapturePolicyVersion, RegistryVersion: "owner-data-r1", RegistryKind: "secret_allowlist", NamespaceScope: "installation_namespace", CaptureMode: "encrypted_full_object", Entries: []root.SecretCapturePolicyEntry{{ID: "required", SecretName: "required", Required: true, ExpectedType: "Opaque", Purpose: "application_secret"}, {ID: "spare", SecretName: "spare", ExpectedType: "Opaque", Purpose: "application_secret"}}}
			raw, err := ce.Canonical(p)
			if err != nil {
				t.Fatal(err)
			}
			policy, err := root.DecodeSecretCapturePolicy(raw, p.RegistryVersion, hash(raw))
			if err != nil {
				t.Fatal(err)
			}
			pin := map[string]string{"registry_kind": "secret_allowlist", "version": p.RegistryVersion, "sha256": policy.SHA256}
			pins := []map[string]string{pin}
			spec := worker.ResourceCaptureSpec{Part: "secret_bundle", Namespace: "source", SecretPolicy: &policy, Selections: []root.KubernetesSelection{{Version: "v1", Resource: "secrets", Name: "required", UID: "actual-uid"}}}
			count := ownedPayloadCounts{Version: "system-backup-inert-payload-counts.v1", Kind: "kubernetes_captured_json_bytes", Complete: true, Items: 1, ContentBytes: 200, SecretPolicy: &ownedSecretPolicyCoverage{Version: "system-backup-secret-policy-coverage.v1", RegistryVersion: p.RegistryVersion, RegistrySHA256: policy.SHA256, RequiredEntries: 1, CapturedEntries: 1, Complete: true}}
			switch mode {
			case "optional-present":
				spec.Selections = append(spec.Selections, root.KubernetesSelection{Version: "v1", Resource: "secrets", Name: "spare", UID: "spare-uid"})
				count.Items++
				count.SecretPolicy.CapturedEntries++
			case "missing-policy":
				spec.SecretPolicy = nil
			case "wrong-config-version":
				pin["version"] = "other"
			case "wrong-config-sha":
				pin["sha256"] = strings.Repeat("0", 64)
			case "duplicate-config-pin":
				pins = append(pins, pin)
			case "missing-required":
				spec.Selections = []root.KubernetesSelection{}
			case "extra-selection":
				spec.Selections[0].Name = "unapproved"
			case "count-only-coverage":
				count.SecretPolicy = nil
			case "incomplete-coverage":
				count.SecretPolicy.Complete = false
			case "incomplete-payload":
				count.Complete = false
			case "wrong-policy-sha":
				policy.SHA256 = strings.Repeat("0", 64)
			case "wrong-required-count":
				count.SecretPolicy.RequiredEntries = 0
			case "wrong-captured-count":
				count.SecretPolicy.CapturedEntries = 0
			case "negative-bytes":
				count.ContentBytes = -1
			case "wrong-part":
				spec.Part = "deployment_resources"
			}
			config, _ := json.Marshal(map[string]any{"registries": pins})
			got, err := derivePublicationSecretPolicySummary(config, spec, count)
			if mode == "current" || mode == "optional-present" {
				if err != nil || got.RequiredEntries != 1 || got.CapturedEntries != count.Items {
					t.Fatal("valid independent coverage rejected", err)
				}
				return
			}
			if err == nil || got.RegistrySHA256 != "" {
				t.Fatal("invalid coverage accepted", mode)
			}
		})
	}
	if _, err := publicationSecretPolicyFacts(publicationVerifiedCapture{}); err == nil {
		t.Fatal("inert data became a current complete capture")
	}
}
