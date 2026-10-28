package systembackupbusinessa

import (
	"context"
	"errors"
	"testing"
	"time"
)

type gatewayHistoryProofFixture struct {
	failAt string
	calls  []string
}

func (p *gatewayHistoryProofFixture) record(step string) error {
	p.calls = append(p.calls, step)
	if p.failAt == step {
		return errors.New("untrusted " + step)
	}
	return nil
}

func (p *gatewayHistoryProofFixture) VerifyAIGatewayHistorySources(_ context.Context,
	registry, schema, evidence string, set AIGatewayRestoreMappingSet,
	_ []RiskRuleRestoreMapping) error {
	if !hashPattern.MatchString(registry) || !hashPattern.MatchString(schema) ||
		evidence != "sev_gateway_history" || len(set.InvocationSources) != 1 {
		return errors.New("unbound gateway history proof")
	}
	if len(set.Audits) != 0 {
		set.Audits[0].TargetTraceID = "proof-mutated-copy"
	}
	return p.record("batch")
}

func (p *gatewayHistoryProofFixture) VerifyChatSessionSources(_ context.Context,
	_, _, _ string, _ []ChatSessionRestoreSource, _ []ChatSessionRestoreMapping) error {
	return p.record("sessions")
}

func (p *gatewayHistoryProofFixture) VerifyModelInvocationSources(_ context.Context,
	_, _, _ string, _ []ModelInvocationRestoreSource, _ []ModelInvocationRestoreMapping,
	_ []ChatSessionRestoreMapping) error {
	return p.record("invocations")
}

func (p *gatewayHistoryProofFixture) VerifyAuditEventSources(_ context.Context,
	_, _, _ string, _ []AuditEventRestoreSource, _ []AuditEventRestoreMapping,
	_ []ChatSessionRestoreMapping) error {
	return p.record("audits")
}

func (p *gatewayHistoryProofFixture) VerifyCostRecordSources(_ context.Context,
	_, _, _ string, _ []CostRecordRestoreSource, _ []CostRecordRestoreMapping,
	_ []ChatSessionRestoreMapping) error {
	return p.record("costs")
}

func (p *gatewayHistoryProofFixture) VerifyRiskHitSources(_ context.Context,
	_, _, _ string, _ []RiskHitRestoreSource, _ []RiskHitRestoreMapping,
	_ []RiskRuleRestoreMapping) error {
	return p.record("risk_hits")
}

func (p *gatewayHistoryProofFixture) VerifyChatMessageSources(_ context.Context,
	_, _, _ string, _ []ChatMessageRestoreSource, _ []ChatMessageRestoreMapping,
	_ []ChatSessionRestoreMapping) error {
	return p.record("messages")
}

func gatewayHistoryTestInput(t *testing.T) (*CaptureScope,
	AIGatewayRestoreMappingSet, []RiskRuleRestoreMapping) {
	t.Helper()
	scope, err := pinnedScope(t, registryFixture(t, true))
	if err != nil {
		t.Fatal(err)
	}
	set := gatewayCrossTableFixture(t)
	now := time.Date(2026, 9, 20, 1, 2, 3, 0, time.UTC)
	set.SessionSources[0].StartedAt = now
	set.SessionSources[0].LastActivityAt = now
	rules := []RiskRuleRestoreMapping{{
		SourceID: 12, TargetID: 112,
		SourceRuleID: "rule-source", TargetRuleID: "rule-target",
	}}
	return scope, set, rules
}

func gatewayHistoryTestProofs(p *gatewayHistoryProofFixture) AIGatewayHistoryProofs {
	return AIGatewayHistoryProofs{
		Batch: p, Sessions: p, Invocations: p, Audits: p,
		Costs: p, RiskHits: p, Messages: p,
	}
}

func TestAIGatewayHistoryRestoreAllOrNothing(t *testing.T) {
	scope, set, rules := gatewayHistoryTestInput(t)
	proof := &gatewayHistoryProofFixture{}
	rows, err := NormalizeAIGatewayHistoryForRestore(context.Background(), scope,
		set, rules, "sev_gateway_history", gatewayHistoryTestProofs(proof))
	if err != nil || len(rows.Sessions) != 1 || len(rows.Invocations) != 1 ||
		len(rows.Audits) != 1 || len(rows.Costs) != 1 ||
		len(rows.RiskHits) != 1 || len(rows.Messages) != 1 ||
		len(proof.calls) != 7 {
		t.Fatalf("gateway history rows/proofs incomplete: rows=%+v calls=%v err=%v", rows, proof.calls, err)
	}
	if rows.Audits[0].TraceID != "trace-target" ||
		set.Audits[0].TargetTraceID != "trace-target" {
		t.Fatal("batch proof mutated normalized or caller mappings")
	}
	if rows.Messages[0].Content != "[REDACTED]" ||
		rows.RiskHits[0].MatchSummary != "[REDACTED]" {
		t.Fatal("gateway history content was not redacted")
	}
	proof = &gatewayHistoryProofFixture{failAt: "costs"}
	rows, err = NormalizeAIGatewayHistoryForRestore(context.Background(), scope,
		set, rules, "sev_gateway_history", gatewayHistoryTestProofs(proof))
	if err == nil || len(rows.Sessions) != 0 || len(rows.Invocations) != 0 ||
		len(rows.Audits) != 0 || len(rows.Costs) != 0 ||
		len(rows.RiskHits) != 0 || len(rows.Messages) != 0 {
		t.Fatalf("partial gateway history escaped: rows=%+v err=%v", rows, err)
	}
}

func TestAIGatewayHistoryRestoreRequiresCommonProof(t *testing.T) {
	scope, set, rules := gatewayHistoryTestInput(t)
	proof := &gatewayHistoryProofFixture{}
	all := gatewayHistoryTestProofs(proof)
	all.Batch = nil
	rows, err := NormalizeAIGatewayHistoryForRestore(context.Background(), scope,
		set, rules, "sev_gateway_history", all)
	if err == nil || !errors.Is(err, ErrCaptureEvidenceIncomplete) ||
		len(rows.Invocations) != 0 || len(proof.calls) != 0 {
		t.Fatalf("missing common proof accepted: rows=%+v calls=%v err=%v", rows, proof.calls, err)
	}
	all = gatewayHistoryTestProofs(proof)
	set.Costs[0].TargetTraceID = "drifted"
	rows, err = NormalizeAIGatewayHistoryForRestore(context.Background(), scope,
		set, rules, "sev_gateway_history", all)
	if !errors.Is(err, ErrAIGatewayCrossTableRestore) ||
		len(rows.Invocations) != 0 || len(proof.calls) != 0 {
		t.Fatalf("cross-table drift reached proof: rows=%+v calls=%v err=%v", rows, proof.calls, err)
	}
	category, known := KnownVerificationFailureCategory(ErrAIGatewayHistoryRestore)
	if !known || category != "normalization_failed" {
		t.Fatalf("wrong category: %s %v", category, known)
	}
}
