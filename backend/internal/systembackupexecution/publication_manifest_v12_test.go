package systembackupexecution

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
)

// Named content DATA only. This creates no checked capture, upload request,
// provider grant, original task or acceptance/verifier result.
func publicationManifestDataV12(t *testing.T) publicationManifestV12 {
	t.Helper()
	sum := strings.Repeat("a", 64)
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	m := publicationManifestV12{Version: "system-backup.v1", AppVersion: "named-DATA", GitCommit: "0123456789abcdef", Generated: at, Installation: "installation_DATA", Backup: "sbk_DATA", Attempt: 1, Orchestrator: "kubernetes", Profile: "cluster", Runner: "kubernetes", Purpose: "functional_test", MigrationCatalog: sum, Schema: sum, CaptureContext: sum, CaptureCertificate: sum, Target: publicationManifestTarget{Class: "same-cluster-copy", Domain: "named-DATA-domain", Risks: []string{"attestation_missing"}}, KEK: publicationManifestKEK{Provider: "external-kms", KeyID: "named-DATA-key", KeyVersion: "1"}, Consistency: "strong", Eligibility: publicationManifestEligibility{PartsComplete: true, VerifiersComplete: true, Disqualifiers: []string{"functional_test", "target_not_external", "target_risk", "attestation_invalid", "kek_not_recoverable"}, InputsSHA256: sum}, Parts: map[string]publicationManifestPart{}, Index: publicationManifestIndex{Path: "artifact-index.json", Checksum: sum}, Marker: publicationManifestMarker{Path: "_COMMITTED", Version: "system-backup-committed.v1"}, Control: publicationManifestControl{Path: ce.CipherPath, Version: ce.Version, Checksum: sum}, SecretPolicy: publicationSecretPolicySummary{RegistryVersion: "named-DATA-r1", RegistrySHA256: sum}, SchemaCoverage: publicationManifestCoverage{RegistryVersion: "named-DATA-r1", RegistrySHA256: sum, Covered: 82, Excluded: 95}, Config: publicationManifestConfig{Version: 1, SHA256: sum, Parameters: map[string]json.RawMessage{}}, Business: map[string]publicationManifestBusiness{}, Warnings: []publicationManifestWarning{}}
	for _, part := range publicationRequestedParts {
		m.Parts[part] = publicationManifestPart{Required: true, Status: "completed", Consistency: "strong", CheckpointType: "gate_staging", CheckpointSHA256: sum, Captured: at, Objects: 1, Bytes: 2, CipherSHA256: sum, Evidence: []string{"sev_named_DATA"}}
	}
	for _, category := range []string{"users", "instances", "ai_gateway", "teams", "resources", "skill_hub"} {
		m.Business[category] = publicationManifestBusiness{Objects: 1, Rows: 2, Bytes: 3, VerifierSHA256: sum}
	}
	return m
}

func TestPublicationManifestV12AllRequiredContractFields(t *testing.T) {
	m := publicationManifestDataV12(t)
	raw, err := ce.Canonical(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decodePublicationManifestV12(raw); err != nil {
		t.Fatal("complete named public content rejected", err)
	}
	schemaRaw, err := os.ReadFile("../../../contracts/system-backup/v12/manifest-system-backup-v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Required []string `json:"required"`
	}
	if json.Unmarshal(schemaRaw, &schema) != nil || len(schema.Required) != 28 {
		t.Fatal("original contract changed; review producer/reader")
	}
	for _, field := range schema.Required {
		t.Run("missing-"+field, func(t *testing.T) {
			var fields map[string]json.RawMessage
			if json.Unmarshal(raw, &fields) != nil {
				t.Fatal("DATA")
			}
			if _, ok := fields[field]; !ok {
				t.Fatal("DTO lacks contract field", field)
			}
			delete(fields, field)
			changed, err := ce.Canonical(fields)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = decodePublicationManifestV12(changed); err == nil {
				t.Fatal("missing required public field accepted", field)
			}
		})
	}
}

func TestPublicationManifestV12RejectsAliasesEnumsAndFalseCompletionData(t *testing.T) {
	for _, mode := range []string{"alias", "unknown", "whitespace", "partial-acceptance", "false-parts", "false-verifiers", "unknown-risk", "duplicate-risk", "false-recovery-proof", "negative-bytes", "unsafe-json-integer", "bad-business-hash", "unknown-part", "unknown-business", "nil-warnings", "details-null"} {
		t.Run(mode, func(t *testing.T) {
			m := publicationManifestDataV12(t)
			switch mode {
			case "partial-acceptance":
				m.Purpose = "acceptance"
				delete(m.Parts, "workspace")
			case "false-parts":
				m.Eligibility.PartsComplete = false
			case "false-verifiers":
				m.Eligibility.VerifiersComplete = false
			case "unknown-risk":
				m.Target.Risks = append(m.Target.Risks, "unknown")
			case "duplicate-risk":
				m.Target.Risks = append(m.Target.Risks, m.Target.Risks[0])
			case "false-recovery-proof":
				m.KEK.SourceIndependent = true
			case "negative-bytes":
				part := m.Parts["workspace"]
				part.Bytes = -1
				m.Parts["workspace"] = part
			case "unsafe-json-integer":
				m.Attempt = 9007199254740992
			case "bad-business-hash":
				summary := m.Business["users"]
				summary.VerifierSHA256 = "bad"
				m.Business["users"] = summary
			case "unknown-part":
				m.Parts["unknown"] = m.Parts["workspace"]
			case "unknown-business":
				m.Business["unknown"] = m.Business["users"]
			case "nil-warnings":
				m.Warnings = nil
			case "details-null":
				m.Warnings = []publicationManifestWarning{{Code: "named_data", Category: "operational-warning", Details: json.RawMessage("null")}}
			}
			raw, err := ce.Canonical(m)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "alias":
				raw = bytes.Replace(raw, []byte(`"git_commit"`), []byte(`"Git_Commit"`), 1)
			case "unknown":
				raw = bytes.Replace(raw, []byte(`"git_commit":`), []byte(`"manifest_checksum":"`+strings.Repeat("b", 64)+`","git_commit":`), 1)
			case "whitespace":
				raw = append([]byte(" "), raw...)
			}
			_, err = decodePublicationManifestV12(raw)
			if (err == nil) != (mode == "details-null") {
				t.Fatal("wrong closed public content decision", mode, err)
			}
		})
	}
}
