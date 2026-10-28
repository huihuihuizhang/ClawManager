package systembackupbusinessa

import (
	"context"
	"errors"
	"testing"
	"time"

	"clawreef/internal/models"
)

type auditEventProofFixture struct {
	calls   int
	failure error
}

func (p *auditEventProofFixture) VerifyAuditEventSources(_ context.Context,
	registry, schema, evidence string, sources []AuditEventRestoreSource,
	mappings []AuditEventRestoreMapping, _ []ChatSessionRestoreMapping) error {
	p.calls++
	if !hashPattern.MatchString(registry) || !hashPattern.MatchString(schema) ||
		evidence != "sev_audit_events" || len(sources) != len(mappings) {
		return errors.New("unbound audit event proof")
	}
	return p.failure
}

func auditEventFixture(t *testing.T) (*CaptureScope, AuditEventRestoreSource,
	AuditEventRestoreMapping, []ChatSessionRestoreMapping) {
	t.Helper()
	scope, err := pinnedScope(t, registryFixture(t, true))
	if err != nil {
		t.Fatal(err)
	}
	sp := func(v string) *string { return &v }
	ip := func(v int) *int { return &v }
	source := AuditEventRestoreSource{
		ID: 11, TraceID: "trace-source", SessionID: sp("session-source"),
		RequestID: sp("request-11"), UserID: ip(7), InstanceID: ip(8),
		InvocationID: ip(9), EventType: "model.completed", TrafficClass: models.TrafficClassLLM,
		Severity: models.AuditSeverityInfo, DetailsPresent: true,
		CreatedAt: time.Date(2026, 9, 20, 1, 2, 3, 0, time.UTC),
	}
	mapping := AuditEventRestoreMapping{
		SourceID: 11, TargetID: 111, TargetTraceID: "trace-target",
		TargetSessionID: sp("session-target"), TargetUserID: ip(107),
		TargetInstanceID: ip(108), TargetInvocationID: ip(109),
	}
	sessions := []ChatSessionRestoreMapping{{
		SourceID: 15, TargetID: 115, SourceSessionID: "session-source",
		TargetSessionID: "session-target", TargetUserID: ip(107), TargetInstanceID: ip(108),
	}}
	return scope, source, mapping, sessions
}

func TestAuditEventRestoreRedactsAndRequiresProof(t *testing.T) {
	scope, source, mapping, sessions := auditEventFixture(t)
	proof := &auditEventProofFixture{}
	rows, err := NormalizeAuditEventsForRestore(context.Background(), scope,
		[]AuditEventRestoreSource{source}, []AuditEventRestoreMapping{mapping},
		sessions, "sev_audit_events", proof)
	if err != nil || len(rows) != 1 || proof.calls != 1 {
		t.Fatalf("audit event normalization: rows=%+v calls=%d err=%v", rows, proof.calls, err)
	}
	row := rows[0]
	if row.ID != 111 || row.TraceID != "trace-target" ||
		row.SessionID == nil || *row.SessionID != "session-target" ||
		row.InvocationID == nil || *row.InvocationID != 109 ||
		row.Message != "[REDACTED]" || row.Details == nil || *row.Details != "[REDACTED]" ||
		row.EventType != "model.completed" {
		t.Fatalf("audit event redaction or mapping lost: %+v", row)
	}
	rows, err = NormalizeAuditEventsForRestore(context.Background(), scope,
		[]AuditEventRestoreSource{source}, []AuditEventRestoreMapping{mapping},
		sessions, "sev_audit_events", nil)
	if len(rows) != 0 || !errors.Is(err, ErrCaptureEvidenceIncomplete) {
		t.Fatalf("missing audit proof accepted: rows=%+v err=%v", rows, err)
	}
	proof.failure = errors.New("invalid dump")
	rows, err = NormalizeAuditEventsForRestore(context.Background(), scope,
		[]AuditEventRestoreSource{source}, []AuditEventRestoreMapping{mapping},
		sessions, "sev_audit_events", proof)
	if len(rows) != 0 || !errors.Is(err, proof.failure) {
		t.Fatalf("audit proof failure leaked rows: rows=%+v err=%v", rows, err)
	}
}

func TestAuditEventRestoreRejectsReferenceDrift(t *testing.T) {
	scope, source, mapping, sessions := auditEventFixture(t)
	proof := &auditEventProofFixture{}
	*source.SessionID = "unknown"
	rows, err := NormalizeAuditEventsForRestore(context.Background(), scope,
		[]AuditEventRestoreSource{source}, []AuditEventRestoreMapping{mapping},
		sessions, "sev_audit_events", proof)
	if len(rows) != 0 || !errors.Is(err, ErrAuditEventRestore) || proof.calls != 0 {
		t.Fatalf("orphan session accepted: rows=%+v calls=%d err=%v", rows, proof.calls, err)
	}
	source.SessionID = nil
	mapping.TargetSessionID = nil
	source.DetailsPresent = false
	rows, err = NormalizeAuditEventsForRestore(context.Background(), scope,
		[]AuditEventRestoreSource{source}, []AuditEventRestoreMapping{mapping},
		nil, "sev_audit_events", proof)
	if err != nil || len(rows) != 1 || rows[0].Details != nil {
		t.Fatalf("SQL NULL detail changed: rows=%+v err=%v", rows, err)
	}
	category, known := KnownVerificationFailureCategory(ErrAuditEventRestore)
	if !known || category != "normalization_failed" {
		t.Fatalf("wrong category: %s %v", category, known)
	}
}
