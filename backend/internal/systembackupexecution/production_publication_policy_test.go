package systembackupexecution

import (
	"bytes"
	"context"
	"strings"
	"testing"

	ce "clawreef/internal/systembackupcontrolevidence"
)

// Independent owner/config/profile DATA, never a readiness, grant or positive
// recovery/attestation proof. Positive claims are deliberately unsupported.
func TestOriginalPublicationPolicyPinsDeclaredAbsenceBeforeCaptureData(t *testing.T) {
	for _, mode := range []string{"current", "hash", "config", "installation", "registry", "version", "target", "recovery-positive", "attestation-positive", "nil-risks", "duplicate-risk", "unknown-risk", "whitespace", "alias", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			pin := ce.RegistryPin{Version: "named-domain-r1", SHA256: strings.Repeat("a", 64)}
			target := publicationManifestTarget{Class: "same-cluster-copy", Domain: "named-local-DATA", Risks: []string{}}
			p := originalPublicationPolicy{Version: originalPublicationPolicyVersion, Installation: "installation_DATA", ConfigSHA256: strings.Repeat("b", 64), FailureDomains: pin, Target: target, RecoveryEvidenceStatus: "not_provided"}
			p.Target.Risks = append([]string{}, target.Risks...)
			switch mode {
			case "config":
				p.ConfigSHA256 = strings.Repeat("c", 64)
			case "installation":
				p.Installation = "installation_other"
			case "registry":
				p.FailureDomains.SHA256 = strings.Repeat("c", 64)
			case "version":
				p.Version = "unknown"
			case "target":
				p.Target.Domain = "other"
			case "recovery-positive":
				p.RecoveryEvidenceStatus = "verified"
			case "attestation-positive":
				id, sum := "sev_unverified", strings.Repeat("c", 64)
				p.Target.AttestationID, p.Target.AttestationSHA256 = &id, &sum
			case "nil-risks":
				p.Target.Risks = nil
			case "duplicate-risk":
				p.Target.Risks = []string{"source_overlap", "source_overlap"}
			case "unknown-risk":
				p.Target.Risks = []string{"unknown"}
			}
			raw, err := ce.Canonical(p)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "whitespace":
				raw = append([]byte(" "), raw...)
			case "alias":
				raw = bytes.Replace(raw, []byte(`"target"`), []byte(`"Target"`), 1)
			case "unknown":
				raw = bytes.Replace(raw, []byte(`"target":`), []byte(`"passed":true,"target":`), 1)
			}
			sha := hash(raw)
			if mode == "hash" {
				sha = strings.Repeat("0", 64)
			}
			got, err := decodeOriginalPublicationPolicy(raw, sha, "installation_DATA", strings.Repeat("b", 64), pin, target)
			if mode == "current" {
				if err != nil || got.validate() != nil || got.Policy.RecoveryEvidenceStatus != "not_provided" {
					t.Fatal("explicit original declaration rejected", err)
				}
				return
			}
			if err == nil || got.SHA256 != "" {
				t.Fatal("changed/unsupported policy accepted", mode)
			}
		})
	}
	var absent *originalSourceMetadataAuthority
	if got, err := absent.loadOriginalPublicationPolicy(context.Background()); err == nil || got.SHA256 != "" {
		t.Fatal("missing original source authority produced policy")
	}
}
