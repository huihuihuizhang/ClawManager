package systembackupbusinessa

import (
	"context"
	"errors"
	"testing"
	"time"
)

type chatMessageProofFixture struct {
	calls       int
	failure     error
	mutateInput bool
}

func (p *chatMessageProofFixture) VerifyChatMessageSources(_ context.Context,
	registry, schema, evidence string, sources []ChatMessageRestoreSource,
	mappings []ChatMessageRestoreMapping, sessions []ChatSessionRestoreMapping) error {
	p.calls++
	if !hashPattern.MatchString(registry) || !hashPattern.MatchString(schema) ||
		evidence != "sev_chat_messages" || len(sources) != len(mappings) {
		return errors.New("unbound chat message source proof")
	}
	if p.mutateInput && len(sources) == 1 {
		*sources[0].UserID = 999
		sources[0].Content = "changed"
		*mappings[0].TargetUserID = 999
		sessions[0].TargetSessionID = "changed"
	}
	return p.failure
}

func chatMessageRestoreFixture(t *testing.T) (*CaptureScope,
	ChatMessageRestoreSource, ChatMessageRestoreMapping, []ChatSessionRestoreMapping) {
	t.Helper()
	scope, err := pinnedScope(t, registryFixture(t, true))
	if err != nil {
		t.Fatal(err)
	}
	stringPtr := func(value string) *string { return &value }
	intPtr := func(value int) *int { return &value }
	source := ChatMessageRestoreSource{
		ID: 16, TraceID: "trace-source", SessionID: "source-session",
		RequestID: stringPtr("request-16"), UserID: intPtr(7),
		InstanceID: intPtr(8), InvocationID: intPtr(9),
		Role: "user", Content: "SYNTHETIC_PRIVATE_CONTENT", SequenceNo: 2,
		CreatedAt: time.Date(2026, 9, 20, 1, 2, 3, 0, time.UTC),
	}
	mapping := ChatMessageRestoreMapping{
		SourceID: 16, TargetID: 116, TargetTraceID: "trace-target",
		TargetUserID: intPtr(107), TargetInstanceID: intPtr(108),
		TargetInvocationID: intPtr(109),
	}
	sessions := []ChatSessionRestoreMapping{{
		SourceID: 15, TargetID: 115,
		SourceSessionID: "source-session", TargetSessionID: "restored-session-15",
		TargetUserID: intPtr(107), TargetInstanceID: intPtr(108),
	}}
	return scope, source, mapping, sessions
}

func TestChatMessageRestoreCompleteRedactedRow(t *testing.T) {
	scope, source, mapping, sessions := chatMessageRestoreFixture(t)
	proof := &chatMessageProofFixture{mutateInput: true}
	rows, err := NormalizeChatMessagesForRestore(context.Background(), scope,
		[]ChatMessageRestoreSource{source}, []ChatMessageRestoreMapping{mapping},
		sessions, "sev_chat_messages", proof)
	if err != nil || len(rows) != 1 || proof.calls != 1 {
		t.Fatalf("chat message row incomplete: %+v, calls=%d, err=%v", rows, proof.calls, err)
	}
	row := rows[0]
	if row.ID != 116 || row.TraceID != "trace-target" ||
		row.SessionID != "restored-session-15" ||
		row.RequestID == nil || *row.RequestID != "request-16" ||
		row.UserID == nil || *row.UserID != 107 ||
		row.InstanceID == nil || *row.InstanceID != 108 ||
		row.InvocationID == nil || *row.InvocationID != 109 ||
		row.Role != "user" || row.Content != "[REDACTED]" ||
		row.SequenceNo != 2 || !row.CreatedAt.Equal(source.CreatedAt) {
		t.Fatalf("chat message mapping or redaction lost: %+v", row)
	}
	*source.RequestID = "source changed"
	*mapping.TargetUserID = 222
	if *row.RequestID != "request-16" || *row.UserID != 107 {
		t.Fatal("restored chat message aliases mutable input")
	}
}

func TestChatMessageRestoreRequiresProofAndPreservesNull(t *testing.T) {
	scope, source, mapping, sessions := chatMessageRestoreFixture(t)
	proof := &chatMessageProofFixture{}
	rows, err := NormalizeChatMessagesForRestore(context.Background(), scope,
		nil, nil, nil, "sev_chat_messages", proof)
	if err != nil || len(rows) != 0 || proof.calls != 1 {
		t.Fatalf("empty chat messages not proved: %+v, calls=%d, err=%v", rows, proof.calls, err)
	}
	for name, candidate := range map[string]ChatMessageSourceProofVerifier{
		"nil": nil, "typed nil": (*chatMessageProofFixture)(nil),
	} {
		rows, err := NormalizeChatMessagesForRestore(context.Background(), scope,
			[]ChatMessageRestoreSource{source}, []ChatMessageRestoreMapping{mapping},
			sessions, "sev_chat_messages", candidate)
		if !errors.Is(err, ErrCaptureEvidenceIncomplete) || rows != nil {
			t.Fatalf("%s proof accepted: %+v, err=%v", name, rows, err)
		}
	}
	source.RequestID, source.UserID, source.InstanceID, source.InvocationID = nil, nil, nil, nil
	mapping.TargetUserID, mapping.TargetInstanceID, mapping.TargetInvocationID = nil, nil, nil
	rows, err = NormalizeChatMessagesForRestore(context.Background(), scope,
		[]ChatMessageRestoreSource{source}, []ChatMessageRestoreMapping{mapping},
		sessions, "sev_chat_messages", proof)
	if err != nil || len(rows) != 1 || rows[0].RequestID != nil ||
		rows[0].UserID != nil || rows[0].InstanceID != nil ||
		rows[0].InvocationID != nil {
		t.Fatalf("nullable chat message references changed: %+v, err=%v", rows, err)
	}
}

func TestChatMessageRestoreRejectsSessionAndTraceDrift(t *testing.T) {
	scope, source, mapping, sessions := chatMessageRestoreFixture(t)
	for name, mutate := range map[string]func(*ChatMessageRestoreSource, *ChatMessageRestoreMapping){
		"missing session":       func(s *ChatMessageRestoreSource, _ *ChatMessageRestoreMapping) { s.SessionID = "missing" },
		"live trace reuse":      func(_ *ChatMessageRestoreSource, m *ChatMessageRestoreMapping) { m.TargetTraceID = source.TraceID },
		"null invocation drift": func(_ *ChatMessageRestoreSource, m *ChatMessageRestoreMapping) { m.TargetInvocationID = nil },
		"empty role":            func(s *ChatMessageRestoreSource, _ *ChatMessageRestoreMapping) { s.Role = "" },
		"negative sequence":     func(s *ChatMessageRestoreSource, _ *ChatMessageRestoreMapping) { s.SequenceNo = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			badSource, badMapping := source, mapping
			mutate(&badSource, &badMapping)
			proof := &chatMessageProofFixture{}
			rows, err := NormalizeChatMessagesForRestore(context.Background(), scope,
				[]ChatMessageRestoreSource{badSource}, []ChatMessageRestoreMapping{badMapping},
				sessions, "sev_chat_messages", proof)
			if !errors.Is(err, ErrChatMessageRestore) || rows != nil || proof.calls != 0 {
				t.Fatalf("invalid message reached proof: %+v, calls=%d, err=%v", rows, proof.calls, err)
			}
		})
	}
	second, secondMapping := source, mapping
	second.ID, secondMapping.SourceID, secondMapping.TargetID = 17, 17, 117
	secondMapping.TargetTraceID = "other-target-trace"
	proof := &chatMessageProofFixture{}
	rows, err := NormalizeChatMessagesForRestore(context.Background(), scope,
		[]ChatMessageRestoreSource{source, second},
		[]ChatMessageRestoreMapping{mapping, secondMapping}, sessions,
		"sev_chat_messages", proof)
	if !errors.Is(err, ErrChatMessageRestore) || rows != nil || proof.calls != 0 {
		t.Fatalf("same source trace split across targets: %+v, calls=%d, err=%v", rows, proof.calls, err)
	}
	second.TraceID = "another-source-trace"
	secondMapping.TargetTraceID = mapping.TargetTraceID
	rows, err = NormalizeChatMessagesForRestore(context.Background(), scope,
		[]ChatMessageRestoreSource{source, second},
		[]ChatMessageRestoreMapping{mapping, secondMapping}, sessions,
		"sev_chat_messages", proof)
	if !errors.Is(err, ErrChatMessageRestore) || rows != nil || proof.calls != 0 {
		t.Fatalf("distinct source traces merged into one target: %+v, calls=%d, err=%v", rows, proof.calls, err)
	}
	proof = &chatMessageProofFixture{failure: errors.New("dump unavailable")}
	rows, err = NormalizeChatMessagesForRestore(context.Background(), scope,
		[]ChatMessageRestoreSource{source}, []ChatMessageRestoreMapping{mapping},
		sessions, "sev_chat_messages", proof)
	if err == nil || rows != nil || proof.calls != 1 {
		t.Fatalf("proof failure emitted rows: %+v, calls=%d, err=%v", rows, proof.calls, err)
	}
}
