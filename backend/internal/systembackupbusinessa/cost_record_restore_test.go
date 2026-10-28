package systembackupbusinessa

import (
	"context"
	"errors"
	"testing"
	"time"
)

type costRecordProofFixture struct {
	calls   int
	failure error
}

func (p *costRecordProofFixture) VerifyCostRecordSources(_ context.Context,
	registry, schema, evidence string, sources []CostRecordRestoreSource,
	mappings []CostRecordRestoreMapping, _ []ChatSessionRestoreMapping) error {
	p.calls++
	if !hashPattern.MatchString(registry) || !hashPattern.MatchString(schema) ||
		evidence != "sev_cost_records" || len(sources) != len(mappings) {
		return errors.New("unbound cost record proof")
	}
	return p.failure
}

func costRecordFixture(t *testing.T) (*CaptureScope, CostRecordRestoreSource,
	CostRecordRestoreMapping, []ChatSessionRestoreMapping) {
	t.Helper()
	scope, err := pinnedScope(t, registryFixture(t, true))
	if err != nil {
		t.Fatal(err)
	}
	sp := func(v string) *string { return &v }
	ip := func(v int) *int { return &v }
	source := CostRecordRestoreSource{
		ID: 21, TraceID: "trace-source", SessionID: sp("session-source"),
		RequestID: sp("request-21"), UserID: ip(7), InstanceID: ip(8),
		InvocationID: ip(9), ModelID: ip(5), ProviderType: "openai",
		ModelName: "model-name", Currency: "USD", PromptTokens: 7,
		CompletionTokens: 5, TotalTokens: 12, InputUnitPrice: "0.12345678",
		OutputUnitPrice: "0.87654321", EstimatedCost: "1.00000001",
		ActualCost: sp("1.00000002"), InternalCost: "0.00000003",
		RecordedAt: time.Date(2026, 9, 20, 1, 2, 3, 0, time.UTC),
	}
	mapping := CostRecordRestoreMapping{
		SourceID: 21, TargetID: 121, TargetTraceID: "trace-target",
		TargetSessionID: sp("session-target"), TargetUserID: ip(107),
		TargetInstanceID: ip(108), TargetInvocationID: ip(109), TargetModelID: ip(105),
	}
	sessions := []ChatSessionRestoreMapping{{
		SourceID: 15, TargetID: 115, SourceSessionID: "session-source",
		TargetSessionID: "session-target", TargetUserID: ip(107), TargetInstanceID: ip(108),
	}}
	return scope, source, mapping, sessions
}

func TestCostRecordRestorePreservesDecimalAndReferences(t *testing.T) {
	scope, source, mapping, sessions := costRecordFixture(t)
	proof := &costRecordProofFixture{}
	rows, err := NormalizeCostRecordsForRestore(context.Background(), scope,
		[]CostRecordRestoreSource{source}, []CostRecordRestoreMapping{mapping},
		sessions, "sev_cost_records", proof)
	if err != nil || len(rows) != 1 || proof.calls != 1 {
		t.Fatalf("cost normalization: rows=%+v calls=%d err=%v", rows, proof.calls, err)
	}
	row := rows[0]
	if row.ID != 121 || row.TraceID != "trace-target" ||
		row.SessionID == nil || *row.SessionID != "session-target" ||
		row.InvocationID == nil || *row.InvocationID != 109 ||
		row.ModelID == nil || *row.ModelID != 105 ||
		row.InputUnitPrice != "0.12345678" || row.OutputUnitPrice != "0.87654321" ||
		row.EstimatedCost != "1.00000001" || row.ActualCost == nil ||
		*row.ActualCost != "1.00000002" || row.InternalCost != "0.00000003" {
		t.Fatalf("cost precision or mapping changed: %+v", row)
	}
	*source.ActualCost = "9.00000000"
	if *row.ActualCost != "1.00000002" {
		t.Fatal("normalized cost aliases mutable source")
	}
}

func TestCostRecordRestoreFailsClosed(t *testing.T) {
	scope, source, mapping, sessions := costRecordFixture(t)
	proof := &costRecordProofFixture{}
	rows, err := NormalizeCostRecordsForRestore(context.Background(), scope,
		nil, nil, nil, "sev_cost_records", proof)
	if err != nil || len(rows) != 0 || proof.calls != 1 {
		t.Fatalf("empty cost batch not proved: rows=%+v calls=%d err=%v", rows, proof.calls, err)
	}
	rows, err = NormalizeCostRecordsForRestore(context.Background(), scope,
		[]CostRecordRestoreSource{source}, []CostRecordRestoreMapping{mapping},
		sessions, "sev_cost_records", nil)
	if len(rows) != 0 || !errors.Is(err, ErrCaptureEvidenceIncomplete) {
		t.Fatalf("missing proof accepted: rows=%+v err=%v", rows, err)
	}
	proof.failure = errors.New("untrusted price")
	rows, err = NormalizeCostRecordsForRestore(context.Background(), scope,
		[]CostRecordRestoreSource{source}, []CostRecordRestoreMapping{mapping},
		sessions, "sev_cost_records", proof)
	if len(rows) != 0 || !errors.Is(err, proof.failure) {
		t.Fatalf("proof failure leaked cost rows: rows=%+v err=%v", rows, err)
	}
	proof.failure = nil
	source.ActualCost = nil
	source.InputUnitPrice = "0.1"
	rows, err = NormalizeCostRecordsForRestore(context.Background(), scope,
		[]CostRecordRestoreSource{source}, []CostRecordRestoreMapping{mapping},
		sessions, "sev_cost_records", proof)
	if err != nil || len(rows) != 1 || rows[0].ActualCost != nil || rows[0].InputUnitPrice != "0.10000000" {
		t.Fatalf("SQL NULL or decimal scale changed: rows=%+v err=%v", rows, err)
	}
}

func TestCostRecordRestoreRejectsDriftAndBadAmounts(t *testing.T) {
	scope, source, mapping, sessions := costRecordFixture(t)
	proof := &costRecordProofFixture{}
	cases := []struct {
		name string
		edit func(*CostRecordRestoreSource, *CostRecordRestoreMapping)
	}{
		{"unknown session", func(s *CostRecordRestoreSource, _ *CostRecordRestoreMapping) { *s.SessionID = "unknown" }},
		{"missing invocation", func(_ *CostRecordRestoreSource, m *CostRecordRestoreMapping) { m.TargetInvocationID = nil }},
		{"reused trace", func(s *CostRecordRestoreSource, m *CostRecordRestoreMapping) { m.TargetTraceID = s.TraceID }},
		{"negative cost", func(s *CostRecordRestoreSource, _ *CostRecordRestoreMapping) { s.InternalCost = "-1.00000000" }},
		{"too precise", func(s *CostRecordRestoreSource, _ *CostRecordRestoreMapping) { s.EstimatedCost = "0.123456789" }},
		{"negative tokens", func(s *CostRecordRestoreSource, _ *CostRecordRestoreMapping) { s.TotalTokens = -1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := cloneCostRecordSources([]CostRecordRestoreSource{source})[0]
			m := cloneCostRecordMappings([]CostRecordRestoreMapping{mapping})[0]
			tc.edit(&s, &m)
			before := proof.calls
			rows, err := NormalizeCostRecordsForRestore(context.Background(), scope,
				[]CostRecordRestoreSource{s}, []CostRecordRestoreMapping{m},
				sessions, "sev_cost_records", proof)
			if len(rows) != 0 || !errors.Is(err, ErrCostRecordRestore) || proof.calls != before {
				t.Fatalf("invalid cost reached proof or rows: rows=%+v calls=%d err=%v", rows, proof.calls, err)
			}
		})
	}
	category, known := KnownVerificationFailureCategory(ErrCostRecordRestore)
	if !known || category != "normalization_failed" {
		t.Fatalf("wrong category: %s %v", category, known)
	}
}
