package systembackupbusinessa

import (
	"errors"
	"testing"
)

func gatewayCrossTableFixture(t *testing.T) AIGatewayRestoreMappingSet {
	t.Helper()
	_, invocation, invocationMap, sessions := modelInvocationFixture(t)
	_, audit, auditMap, _ := auditEventFixture(t)
	_, cost, costMap, _ := costRecordFixture(t)
	_, risk, riskMap, _ := riskHitRestoreFixture(t)
	_, message, messageMap, _ := chatMessageRestoreFixture(t)
	risk.TraceID, riskMap.TargetTraceID = "trace-source", "trace-target"
	risk.SessionID, riskMap.TargetSessionID = invocation.SessionID, invocationMap.TargetSessionID
	message.TraceID, messageMap.TargetTraceID = "trace-source", "trace-target"
	message.SessionID = "session-source"
	return AIGatewayRestoreMappingSet{
		Users:  []UserRestoreMapping{{SourceID: 7, TargetID: 107}},
		Models: []LLMModelRestoreMapping{{SourceID: 5, TargetID: 105}},
		SessionSources: []ChatSessionRestoreSource{{
			ID: 15, SessionID: "session-source", UserID: invocation.UserID,
			InstanceID: invocation.InstanceID,
		}},
		Sessions:           sessions,
		InvocationSources:  []ModelInvocationRestoreSource{invocation},
		Invocations:        []ModelInvocationRestoreMapping{invocationMap},
		AuditSources:       []AuditEventRestoreSource{audit},
		Audits:             []AuditEventRestoreMapping{auditMap},
		CostSources:        []CostRecordRestoreSource{cost},
		Costs:              []CostRecordRestoreMapping{costMap},
		RiskHitSources:     []RiskHitRestoreSource{risk},
		RiskHits:           []RiskHitRestoreMapping{riskMap},
		ChatMessageSources: []ChatMessageRestoreSource{message},
		ChatMessages:       []ChatMessageRestoreMapping{messageMap},
	}
}

func TestAIGatewayCrossTableRestoreMappingConsistency(t *testing.T) {
	set := gatewayCrossTableFixture(t)
	if err := CheckAIGatewayRestoreMappingConsistency(set); err != nil {
		t.Fatalf("consistent gateway history rejected: %v", err)
	}
	category, known := KnownVerificationFailureCategory(ErrAIGatewayCrossTableRestore)
	if !known || category != "normalization_failed" {
		t.Fatalf("wrong category: %s %v", category, known)
	}
}

func TestAIGatewayCrossTableRestoreRejectsDrift(t *testing.T) {
	cases := []struct {
		name string
		edit func(*AIGatewayRestoreMappingSet)
	}{
		{"invocation ID", func(s *AIGatewayRestoreMappingSet) { *s.Costs[0].TargetInvocationID = 999 }},
		{"model ID", func(s *AIGatewayRestoreMappingSet) { *s.Invocations[0].TargetModelID = 999 }},
		{"user ID", func(s *AIGatewayRestoreMappingSet) { *s.Audits[0].TargetUserID = 999 }},
		{"source trace split", func(s *AIGatewayRestoreMappingSet) { s.Costs[0].TargetTraceID = "different-trace" }},
		{"source trace reused", func(s *AIGatewayRestoreMappingSet) { s.Audits[0].TargetTraceID = "trace-source" }},
		{"orphan session", func(s *AIGatewayRestoreMappingSet) { *s.RiskHitSources[0].SessionID = "other-session" }},
		{"missing target session", func(s *AIGatewayRestoreMappingSet) { s.Audits[0].TargetSessionID = nil }},
		{"missing invocation", func(s *AIGatewayRestoreMappingSet) { s.Invocations = nil }},
		{"duplicate model target", func(s *AIGatewayRestoreMappingSet) {
			s.Models = append(s.Models, LLMModelRestoreMapping{SourceID: 6, TargetID: 105})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set := gatewayCrossTableFixture(t)
			tc.edit(&set)
			if err := CheckAIGatewayRestoreMappingConsistency(set); !errors.Is(err, ErrAIGatewayCrossTableRestore) {
				t.Fatalf("cross-table drift accepted: %v", err)
			}
		})
	}
}
