package systembackupcontroller

import (
	"errors"
	"fmt"
	"time"
)

// ControllerStateAlertSnapshot contains only the already-aggregated D-side
// facts needed by the four non-PromQL registry rules. Owner collection,
// persistence, alert delivery, and alert-state CAS are outside this predicate.
type ControllerStateAlertSnapshot struct {
	Profile             string
	Now                 time.Time
	AcceptanceAnomalies map[TargetKind]uint64
	EvidenceWrites      []EvidenceWriteAlertCandidate
	ProviderProofIssuer *ProviderProofIssuerAlertCandidate
}

type EvidenceWriteAlertCandidate struct {
	Age               time.Duration
	ImmutableDeadline time.Duration
}

type ProviderProofIssuerAlertCandidate struct {
	ExpiresAt         time.Time
	ProofMaxAge       time.Duration
	EvidenceRetention time.Duration
}

type ControllerStateAlertDecision struct {
	RuleID      string
	Severity    string
	Firing      bool
	TaskType    TargetKind
	TaskPurpose string
}

// EvaluateControllerStateAlerts evaluates the closed controller_state rule
// set. Missing acceptance rows and a missing provider-proof issuer are
// fail-closed; no pending evidence rows are a healthy zero.
func EvaluateControllerStateAlerts(snapshot ControllerStateAlertSnapshot) ([]ControllerStateAlertDecision, error) {
	if snapshot.Profile != "production" && snapshot.Profile != "development" {
		return nil, errors.New("invalid controller-state alert profile")
	}
	if snapshot.Now.IsZero() {
		return nil, errors.New("controller-state alert clock is required")
	}
	decisions, err := evaluateAcceptanceAnomalyDecisions(snapshot.Profile, snapshot.AcceptanceAnomalies)
	if err != nil {
		return nil, err
	}
	evidenceNearDeadline := false
	for _, candidate := range snapshot.EvidenceWrites {
		if candidate.Age < 0 || candidate.ImmutableDeadline <= 0 {
			return nil, errors.New("invalid pending evidence age or immutable deadline")
		}
		// Ceil(0.9 * deadline), without floating point or duration overflow.
		threshold := candidate.ImmutableDeadline - candidate.ImmutableDeadline/10
		evidenceNearDeadline = evidenceNearDeadline || candidate.Age >= threshold
	}
	decisions = append(decisions, ControllerStateAlertDecision{
		RuleID: "evidence-write-near-deadline", Severity: "critical", Firing: evidenceNearDeadline,
	})
	proofKeyExpiring := snapshot.ProviderProofIssuer == nil
	if issuer := snapshot.ProviderProofIssuer; issuer != nil {
		if issuer.ExpiresAt.IsZero() || issuer.ProofMaxAge <= 0 || issuer.EvidenceRetention <= 0 {
			return nil, errors.New("invalid provider-proof issuer expiry inputs")
		}
		threshold := issuer.ProofMaxAge
		if issuer.EvidenceRetention > threshold {
			threshold = issuer.EvidenceRetention
		}
		proofKeyExpiring = issuer.ExpiresAt.Sub(snapshot.Now) < threshold
	}
	decisions = append(decisions, ControllerStateAlertDecision{
		RuleID: "provider-proof-issuer-key-expiring", Severity: "warning", Firing: proofKeyExpiring,
	})
	return decisions, nil
}

func evaluateAcceptanceAnomalyDecisions(profile string, counts map[TargetKind]uint64) ([]ControllerStateAlertDecision, error) {
	if profile != "production" && profile != "development" {
		return nil, errors.New("invalid controller-state alert profile")
	}
	for kind := range counts {
		if kind != TargetBackup && kind != TargetDrill {
			return nil, fmt.Errorf("invalid acceptance anomaly task type %q", kind)
		}
	}
	acceptance := ControllerStateAlertDecision{
		RuleID:      "acceptance-consecutive-anomalies." + profile,
		Severity:    "critical",
		TaskPurpose: "acceptance",
	}
	if profile == "development" {
		acceptance.Severity = "info"
	}
	decisions := make([]ControllerStateAlertDecision, 0, 2)
	for _, kind := range []TargetKind{TargetBackup, TargetDrill} {
		decision := acceptance
		decision.TaskType = kind
		count, present := counts[kind]
		decision.Firing = !present || count >= 3
		decisions = append(decisions, decision)
	}
	return decisions, nil
}
