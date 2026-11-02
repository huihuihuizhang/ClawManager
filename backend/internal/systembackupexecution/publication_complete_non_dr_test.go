package systembackupexecution

import (
	"reflect"
	"testing"

	ce "clawreef/internal/systembackupcontrolevidence"
)

// Content derivation tests cannot manufacture final proof, Ready or terminal.
func TestPublicationCompleteNonDRQualificationDoesNotWeakenData(t *testing.T) {
	for _, fault := range []string{"complete", "missing-part", "weak-part", "failed-part", "failed-verifier", "disqualifying-warning", "false-qualification", "acceptance-without-recovery"} {
		t.Run(fault, func(t *testing.T) {
			m := publicationManifestDataV12(t)
			switch fault {
			case "missing-part":
				delete(m.Parts, "secret_bundle")
			case "weak-part":
				p := m.Parts["redis"]
				p.Consistency = "weak"
				m.Parts["redis"] = p
			case "failed-part":
				p := m.Parts["workspace"]
				p.Status = "failed"
				m.Parts["workspace"] = p
			case "failed-verifier":
				m.Eligibility.VerifiersComplete = false
			case "disqualifying-warning":
				m.Warnings = []publicationManifestWarning{{Code: "content_failure", Category: "data-integrity-warning", Disqualifying: true}}
			case "false-qualification":
				m.Eligibility.Disqualifiers = []string{}
			case "acceptance-without-recovery":
				m.Purpose = "acceptance"
			}
			eligible, reasons, err := publicationManifestEvaluation(m)
			if fault == "complete" {
				if err != nil || eligible || !reflect.DeepEqual(reasons, []string{"attestation_invalid", "functional_test", "kek_not_recoverable", "target_not_external", "target_risk"}) {
					t.Fatal("truthful complete non-DR evaluation", err, reasons)
				}
			} else if err == nil {
				t.Fatal("ordinary purpose excused failed data/qualification", fault)
			}
		})
	}
	m := publicationManifestDataV12(t)
	m.Purpose, m.Target.Class, m.Target.Risks = "acceptance", "dr-ready-external", []string{}
	id, digest := "sev_actual_attestation_CONTENT", hash([]byte("independent recovery CONTENT"))
	m.Target.AttestationID, m.Target.AttestationSHA256, m.KEK.SourceIndependent, m.KEK.RecoveryProof = &id, &digest, true, &digest
	m.Eligibility.Disqualifiers = []string{}
	if eligible, reasons, err := publicationManifestEvaluation(m); err != nil || !eligible || !reflect.DeepEqual(reasons, []string{"eligible"}) {
		t.Fatal("strict positive content regression", err)
	}
}

func TestPublicationCompleteNonDRSignedDecisionReasonBinding(t *testing.T) {
	p := acceptancePayloadData(t)
	p.Accepted, p.Reasons = false, []string{"attestation_invalid", "functional_test", "kek_not_recoverable"}
	reasons, _ := ce.Canonical(p.Reasons)
	p.ReasonsSHA256 = hash(reasons)
	raw, _ := ce.Canonical(p)
	if _, err := decodePublicationAcceptancePayload(raw); err != nil {
		t.Fatal("closed signed-payload negative evaluation", err)
	}
	decision := publicationDecisionData(t)
	decision.Eligible, decision.Reasons, decision.ReasonsSHA256 = false, p.Reasons, p.ReasonsSHA256
	raw, _ = ce.Canonical(decision)
	if _, _, err := decodePublicationDecision(raw); err != nil {
		t.Fatal("negative immutable decision", err)
	}
	for _, altered := range [][]string{{"eligible"}, {"functional_test", "attestation_invalid"}, {"functional_test", "functional_test"}, {"invented_success"}} {
		decision.Reasons = altered
		reasons, _ = ce.Canonical(altered)
		decision.ReasonsSHA256 = hash(reasons)
		raw, _ = ce.Canonical(decision)
		if _, _, err := decodePublicationDecision(raw); err == nil {
			t.Fatal("malformed negative decision accepted", altered)
		}
	}
}
