package systembackupbusinessa

import (
	"context"
	"errors"
	"testing"
	"time"

	"clawreef/internal/models"
)

type modelInvocationProofFixture struct {
	calls   int
	failure error
	mutate  bool
}

func (p *modelInvocationProofFixture) VerifyModelInvocationSources(_ context.Context,
	registry, schema, evidence string, sources []ModelInvocationRestoreSource,
	mappings []ModelInvocationRestoreMapping, sessions []ChatSessionRestoreMapping) error {
	p.calls++
	if !hashPattern.MatchString(registry) || !hashPattern.MatchString(schema) ||
		evidence != "sev_model_invocations" || len(sources) != len(mappings) {
		return errors.New("unbound model invocation proof")
	}
	if p.mutate && len(sources) == 1 {
		*sources[0].UserID = 999
		*mappings[0].TargetUserID = 999
		sessions[0].TargetSessionID = "changed"
	}
	return p.failure
}

func modelInvocationFixture(t *testing.T) (*CaptureScope, ModelInvocationRestoreSource,
	ModelInvocationRestoreMapping, []ChatSessionRestoreMapping) {
	t.Helper()
	scope, err := pinnedScope(t, registryFixture(t, true))
	if err != nil {
		t.Fatal(err)
	}
	sp := func(v string) *string { return &v }
	ip := func(v int) *int { return &v }
	lp := func(v int64) *int64 { return &v }
	now := time.Date(2026, 9, 20, 1, 2, 3, 0, time.UTC)
	source := ModelInvocationRestoreSource{
		ID: 9, TraceID: "trace-source", SessionID: sp("session-source"),
		RequestID: "request-9", UserID: ip(7), InstanceID: ip(8),
		InstanceMode: sp("lite"), RuntimeType: sp("pod"), GatewayID: sp("gateway-source"),
		RuntimePodID: lp(10), ModelID: ip(5), ProviderType: "openai",
		RequestedModel: "requested-model", ActualProviderModel: "actual-model",
		TrafficClass: models.TrafficClassLLM, RequestPayloadPresent: true,
		ResponsePayloadPresent: true, PromptTokens: 7, CompletionTokens: 5,
		TotalTokens: 12, CachedTokens: ip(2), ReasoningTokens: ip(1),
		LatencyMs: ip(50), IsStreaming: true, Status: models.ModelInvocationStatusCompleted,
		ErrorMessagePresent: true, CreatedAt: now, CompletedAt: &now,
	}
	mapping := ModelInvocationRestoreMapping{
		SourceID: 9, TargetID: 109, TargetTraceID: "trace-target",
		TargetSessionID: sp("session-target"), TargetUserID: ip(107),
		TargetInstanceID: ip(108), TargetGatewayID: sp("gateway-target"),
		TargetRuntimePodID: lp(110), TargetModelID: ip(105),
	}
	sessions := []ChatSessionRestoreMapping{{
		SourceID: 15, TargetID: 115, SourceSessionID: "session-source",
		TargetSessionID: "session-target", TargetUserID: ip(107),
		TargetInstanceID: ip(108),
	}}
	return scope, source, mapping, sessions
}

func TestModelInvocationRestoreRedactsBodiesAndBindsReferences(t *testing.T) {
	scope, source, mapping, sessions := modelInvocationFixture(t)
	proof := &modelInvocationProofFixture{mutate: true}
	rows, err := NormalizeModelInvocationsForRestore(context.Background(), scope,
		[]ModelInvocationRestoreSource{source}, []ModelInvocationRestoreMapping{mapping},
		sessions, "sev_model_invocations", proof)
	if err != nil || len(rows) != 1 || proof.calls != 1 {
		t.Fatalf("model invocation normalization: rows=%+v calls=%d err=%v", rows, proof.calls, err)
	}
	row := rows[0]
	if row.ID != 109 || row.TraceID != "trace-target" ||
		row.SessionID == nil || *row.SessionID != "session-target" ||
		row.UserID == nil || *row.UserID != 107 ||
		row.InstanceID == nil || *row.InstanceID != 108 ||
		row.ModelID == nil || *row.ModelID != 105 ||
		row.GatewayID == nil || *row.GatewayID != "gateway-target" ||
		row.RuntimePodID == nil || *row.RuntimePodID != 110 ||
		row.RequestPayload == nil || *row.RequestPayload != "[REDACTED]" ||
		row.ResponsePayload == nil || *row.ResponsePayload != "[REDACTED]" ||
		row.ErrorMessage == nil || *row.ErrorMessage != "[REDACTED]" ||
		row.Status != models.ModelInvocationStatusCompleted || row.TotalTokens != 12 {
		t.Fatalf("model invocation mapping or redaction lost: %+v", row)
	}
	*source.UserID = 222
	*mapping.TargetUserID = 333
	if *row.UserID != 107 {
		t.Fatal("normalized model invocation aliases mutable input")
	}
}

func TestModelInvocationRestoreFailsClosed(t *testing.T) {
	scope, source, mapping, sessions := modelInvocationFixture(t)
	proof := &modelInvocationProofFixture{}
	rows, err := NormalizeModelInvocationsForRestore(context.Background(), scope,
		nil, nil, nil, "sev_model_invocations", proof)
	if err != nil || len(rows) != 0 || proof.calls != 1 {
		t.Fatalf("empty source must be proved: rows=%+v calls=%d err=%v", rows, proof.calls, err)
	}
	rows, err = NormalizeModelInvocationsForRestore(context.Background(), scope,
		[]ModelInvocationRestoreSource{source}, []ModelInvocationRestoreMapping{mapping},
		sessions, "sev_model_invocations", nil)
	if len(rows) != 0 || !errors.Is(err, ErrCaptureEvidenceIncomplete) {
		t.Fatalf("missing proof accepted: rows=%+v err=%v", rows, err)
	}
	proof.failure = errors.New("dump not authenticated")
	rows, err = NormalizeModelInvocationsForRestore(context.Background(), scope,
		[]ModelInvocationRestoreSource{source}, []ModelInvocationRestoreMapping{mapping},
		sessions, "sev_model_invocations", proof)
	if len(rows) != 0 || !errors.Is(err, proof.failure) {
		t.Fatalf("proof failure leaked rows: rows=%+v err=%v", rows, err)
	}
	proof.failure = nil
	source.Status = models.ModelInvocationStatusPending
	source.CompletedAt = nil
	source.RequestPayloadPresent = false
	source.ResponsePayloadPresent = false
	source.ErrorMessagePresent = false
	rows, err = NormalizeModelInvocationsForRestore(context.Background(), scope,
		[]ModelInvocationRestoreSource{source}, []ModelInvocationRestoreMapping{mapping},
		sessions, "sev_model_invocations", proof)
	if err != nil || len(rows) != 1 || rows[0].Status != models.ModelInvocationStatusFailed ||
		rows[0].CompletedAt == nil || rows[0].RequestPayload != nil ||
		rows[0].ResponsePayload != nil || rows[0].ErrorMessage != nil {
		t.Fatalf("pending source remained live or NULL changed: rows=%+v err=%v", rows, err)
	}
}

func TestModelInvocationRestoreRejectsDriftAndPartialRows(t *testing.T) {
	scope, source, mapping, sessions := modelInvocationFixture(t)
	proof := &modelInvocationProofFixture{}
	cases := []struct {
		name string
		edit func(*ModelInvocationRestoreSource, *ModelInvocationRestoreMapping, *[]ChatSessionRestoreMapping)
	}{
		{"unknown session", func(s *ModelInvocationRestoreSource, m *ModelInvocationRestoreMapping, _ *[]ChatSessionRestoreMapping) {
			*s.SessionID = "other"
		}},
		{"session mismatch", func(_ *ModelInvocationRestoreSource, m *ModelInvocationRestoreMapping, _ *[]ChatSessionRestoreMapping) {
			*m.TargetSessionID = "wrong"
		}},
		{"reused trace", func(s *ModelInvocationRestoreSource, m *ModelInvocationRestoreMapping, _ *[]ChatSessionRestoreMapping) {
			m.TargetTraceID = s.TraceID
		}},
		{"missing model mapping", func(_ *ModelInvocationRestoreSource, m *ModelInvocationRestoreMapping, _ *[]ChatSessionRestoreMapping) {
			m.TargetModelID = nil
		}},
		{"bad tokens", func(s *ModelInvocationRestoreSource, _ *ModelInvocationRestoreMapping, _ *[]ChatSessionRestoreMapping) {
			s.TotalTokens = -1
		}},
		{"bad status", func(s *ModelInvocationRestoreSource, _ *ModelInvocationRestoreMapping, _ *[]ChatSessionRestoreMapping) {
			s.Status = "running"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := cloneModelInvocationSources([]ModelInvocationRestoreSource{source})[0]
			m := cloneModelInvocationMappings([]ModelInvocationRestoreMapping{mapping})[0]
			ss := cloneChatSessionMappings(sessions)
			tc.edit(&s, &m, &ss)
			before := proof.calls
			rows, err := NormalizeModelInvocationsForRestore(context.Background(), scope,
				[]ModelInvocationRestoreSource{s}, []ModelInvocationRestoreMapping{m},
				ss, "sev_model_invocations", proof)
			if len(rows) != 0 || !errors.Is(err, ErrModelInvocationRestore) || proof.calls != before {
				t.Fatalf("invalid source reached proof or rows: rows=%+v calls=%d err=%v", rows, proof.calls, err)
			}
		})
	}
	category, known := KnownVerificationFailureCategory(ErrModelInvocationRestore)
	if !known || category != "normalization_failed" {
		t.Fatalf("wrong failure category: %s %v", category, known)
	}
}
