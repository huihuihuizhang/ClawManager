package systembackupbusinessa

import (
	"context"
	"errors"
	"testing"
	"time"

	"clawreef/internal/models"
)

type riskHitProofFixture struct {
	calls       int
	failure     error
	mutateInput bool
}

func (p *riskHitProofFixture) VerifyRiskHitSources(_ context.Context,
	registry, schema, evidence string, sources []RiskHitRestoreSource,
	mappings []RiskHitRestoreMapping, rules []RiskRuleRestoreMapping) error {
	p.calls++
	if !hashPattern.MatchString(registry) || !hashPattern.MatchString(schema) ||
		evidence != "sev_risk_hits" || len(sources) != len(mappings) {
		return errors.New("unbound risk hit proof")
	}
	if p.mutateInput && len(sources) == 1 {
		*sources[0].UserID = 999
		*sources[0].SessionID = "mutated"
		*mappings[0].TargetUserID = 999
		mappings[0].TargetTraceID = "mutated"
		rules[0].TargetRuleID = "mutated"
	}
	return p.failure
}

func riskHitRestoreFixture(t *testing.T) (*CaptureScope, RiskHitRestoreSource,
	RiskHitRestoreMapping, []RiskRuleRestoreMapping) {
	t.Helper()
	scope, err := pinnedScope(t, registryFixture(t, true))
	if err != nil {
		t.Fatal(err)
	}
	stringPtr := func(value string) *string { return &value }
	intPtr := func(value int) *int { return &value }
	int64Ptr := func(value int64) *int64 { return &value }
	source := RiskHitRestoreSource{
		ID: 19, TraceID: "trace-19", SessionID: stringPtr("session-source"),
		RequestID: stringPtr("request-19"), UserID: intPtr(7),
		InstanceID: intPtr(8), InstanceMode: stringPtr("lite"),
		RuntimeType: stringPtr("pod"), GatewayID: stringPtr("gateway-source"),
		RuntimePodID: int64Ptr(123), InvocationID: intPtr(9),
		RuleID: "rule-source", RuleName: "Historical rule",
		Severity: models.RiskSeverityHigh, Action: models.RiskActionBlock,
		MatchSummary: "SYNTHETIC_SECRET_MATCH",
		CreatedAt:    time.Date(2026, 9, 20, 1, 2, 3, 0, time.UTC),
	}
	mapping := RiskHitRestoreMapping{
		SourceID: 19, TargetID: 119, TargetTraceID: "trace-119",
		TargetSessionID: stringPtr("session-target"), TargetUserID: intPtr(107),
		TargetInstanceID: intPtr(108), TargetGatewayID: stringPtr("gateway-target"),
		TargetRuntimePodID: int64Ptr(223), TargetInvocationID: intPtr(109),
	}
	rules := []RiskRuleRestoreMapping{{
		SourceID: 12, TargetID: 112,
		SourceRuleID: "rule-source", TargetRuleID: "rule-target",
	}}
	return scope, source, mapping, rules
}

func TestRiskHitRestoreCompleteRedactedRow(t *testing.T) {
	scope, source, mapping, rules := riskHitRestoreFixture(t)
	proof := &riskHitProofFixture{mutateInput: true}
	rows, err := NormalizeRiskHitsForRestore(context.Background(), scope,
		[]RiskHitRestoreSource{source}, []RiskHitRestoreMapping{mapping},
		rules, "sev_risk_hits", proof)
	if err != nil || len(rows) != 1 || proof.calls != 1 {
		t.Fatalf("risk hit row incomplete: %+v, calls=%d, err=%v", rows, proof.calls, err)
	}
	row := rows[0]
	if row.ID != 119 || row.TraceID != "trace-119" ||
		row.SessionID == nil || *row.SessionID != "session-target" ||
		row.RequestID == nil || *row.RequestID != "request-19" ||
		row.UserID == nil || *row.UserID != 107 ||
		row.InstanceID == nil || *row.InstanceID != 108 ||
		row.InstanceMode == nil || *row.InstanceMode != "lite" ||
		row.RuntimeType == nil || *row.RuntimeType != "pod" ||
		row.GatewayID == nil || *row.GatewayID != "gateway-target" ||
		row.RuntimePodID == nil || *row.RuntimePodID != 223 ||
		row.InvocationID == nil || *row.InvocationID != 109 ||
		row.RuleID != "rule-target" || row.RuleName != "Historical rule" ||
		row.Severity != models.RiskSeverityHigh || row.Action != models.RiskActionBlock ||
		row.MatchSummary != "[REDACTED]" || !row.CreatedAt.Equal(source.CreatedAt) {
		t.Fatalf("risk hit mapping or redaction lost: %+v", row)
	}
	*source.UserID = 222
	*mapping.TargetSessionID = "changed"
	if *row.UserID != 107 || *row.SessionID != "session-target" {
		t.Fatal("risk hit output aliases mutable input")
	}
}

func TestRiskHitRestoreRequiresProofForEmptyAndNullableRows(t *testing.T) {
	scope, source, mapping, rules := riskHitRestoreFixture(t)
	proof := &riskHitProofFixture{}
	rows, err := NormalizeRiskHitsForRestore(context.Background(), scope,
		nil, nil, nil, "sev_risk_hits", proof)
	if err != nil || len(rows) != 0 || proof.calls != 1 {
		t.Fatalf("empty risk hits not proved: %+v, calls=%d, err=%v", rows, proof.calls, err)
	}
	for name, candidate := range map[string]RiskHitSourceProofVerifier{
		"nil": nil, "typed nil": (*riskHitProofFixture)(nil),
	} {
		rows, err := NormalizeRiskHitsForRestore(context.Background(), scope,
			[]RiskHitRestoreSource{source}, []RiskHitRestoreMapping{mapping},
			rules, "sev_risk_hits", candidate)
		if !errors.Is(err, ErrCaptureEvidenceIncomplete) || rows != nil {
			t.Fatalf("%s proof accepted: %+v, err=%v", name, rows, err)
		}
	}
	source.SessionID, source.RequestID, source.UserID, source.InstanceID = nil, nil, nil, nil
	source.InstanceMode, source.RuntimeType, source.GatewayID = nil, nil, nil
	source.RuntimePodID, source.InvocationID = nil, nil
	mapping.TargetSessionID, mapping.TargetUserID, mapping.TargetInstanceID = nil, nil, nil
	mapping.TargetGatewayID, mapping.TargetRuntimePodID, mapping.TargetInvocationID = nil, nil, nil
	rows, err = NormalizeRiskHitsForRestore(context.Background(), scope,
		[]RiskHitRestoreSource{source}, []RiskHitRestoreMapping{mapping},
		rules, "sev_risk_hits", proof)
	if err != nil || len(rows) != 1 || rows[0].UserID != nil ||
		rows[0].SessionID != nil || rows[0].InvocationID != nil {
		t.Fatalf("SQL null references were not retained: %+v, err=%v", rows, err)
	}
}

func TestRiskHitRestoreRejectsReferenceDriftAndProofFailure(t *testing.T) {
	scope, source, mapping, rules := riskHitRestoreFixture(t)
	for name, mutate := range map[string]func(*RiskHitRestoreSource, *RiskHitRestoreMapping){
		"missing rule":        func(s *RiskHitRestoreSource, _ *RiskHitRestoreMapping) { s.RuleID = "missing" },
		"source trace reused": func(_ *RiskHitRestoreSource, m *RiskHitRestoreMapping) { m.TargetTraceID = source.TraceID },
		"null user drift":     func(_ *RiskHitRestoreSource, m *RiskHitRestoreMapping) { m.TargetUserID = nil },
		"invalid action":      func(s *RiskHitRestoreSource, _ *RiskHitRestoreMapping) { s.Action = "execute_shell" },
		"bad target ID":       func(_ *RiskHitRestoreSource, m *RiskHitRestoreMapping) { m.TargetID = 0 },
		"invalid summary":     func(s *RiskHitRestoreSource, _ *RiskHitRestoreMapping) { s.MatchSummary = "\xff" },
	} {
		t.Run(name, func(t *testing.T) {
			badSource, badMapping := source, mapping
			mutate(&badSource, &badMapping)
			proof := &riskHitProofFixture{}
			rows, err := NormalizeRiskHitsForRestore(context.Background(), scope,
				[]RiskHitRestoreSource{badSource}, []RiskHitRestoreMapping{badMapping},
				rules, "sev_risk_hits", proof)
			if !errors.Is(err, ErrRiskHitRestore) || rows != nil || proof.calls != 0 {
				t.Fatalf("invalid risk hit reached proof: %+v, calls=%d, err=%v", rows, proof.calls, err)
			}
		})
	}
	second, secondMapping := source, mapping
	second.ID, secondMapping.SourceID, secondMapping.TargetID = 20, 20, 120
	otherUser := 108
	secondMapping.TargetUserID = &otherUser
	proof := &riskHitProofFixture{}
	rows, err := NormalizeRiskHitsForRestore(context.Background(), scope,
		[]RiskHitRestoreSource{source, second},
		[]RiskHitRestoreMapping{mapping, secondMapping}, rules, "sev_risk_hits", proof)
	if !errors.Is(err, ErrRiskHitRestore) || rows != nil || proof.calls != 0 {
		t.Fatalf("inconsistent user mapping accepted: %+v, calls=%d, err=%v", rows, proof.calls, err)
	}
	secondMapping.TargetUserID = mapping.TargetUserID
	second.TraceID = "other-source-trace"
	secondMapping.TargetTraceID = mapping.TargetTraceID
	rows, err = NormalizeRiskHitsForRestore(context.Background(), scope,
		[]RiskHitRestoreSource{source, second},
		[]RiskHitRestoreMapping{mapping, secondMapping}, rules, "sev_risk_hits", proof)
	if !errors.Is(err, ErrRiskHitRestore) || rows != nil || proof.calls != 0 {
		t.Fatalf("distinct risk traces merged into one target: %+v, calls=%d, err=%v", rows, proof.calls, err)
	}
	proof = &riskHitProofFixture{failure: errors.New("dump unavailable")}
	rows, err = NormalizeRiskHitsForRestore(context.Background(), scope,
		[]RiskHitRestoreSource{source}, []RiskHitRestoreMapping{mapping},
		rules, "sev_risk_hits", proof)
	if err == nil || rows != nil || proof.calls != 1 {
		t.Fatalf("proof failure emitted rows: %+v, calls=%d, err=%v", rows, proof.calls, err)
	}
}
