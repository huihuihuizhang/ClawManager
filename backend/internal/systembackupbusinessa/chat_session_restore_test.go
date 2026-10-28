package systembackupbusinessa

import (
	"context"
	"errors"
	"testing"
	"time"
)

type chatSessionProofFixture struct {
	calls       int
	failure     error
	mutateInput bool
}

func (p *chatSessionProofFixture) VerifyChatSessionSources(_ context.Context,
	registry, schema, evidence string, sources []ChatSessionRestoreSource,
	mappings []ChatSessionRestoreMapping) error {
	p.calls++
	if !hashPattern.MatchString(registry) || !hashPattern.MatchString(schema) ||
		evidence != "sev_chat_sessions" || len(sources) != len(mappings) {
		return errors.New("unbound chat session source proof")
	}
	if p.mutateInput && len(sources) == 1 {
		*sources[0].Title = "changed"
		*mappings[0].TargetUserID = 999
		mappings[0].TargetSessionID = "changed"
	}
	return p.failure
}

func chatSessionRestoreFixture(t *testing.T) (*CaptureScope,
	ChatSessionRestoreSource, ChatSessionRestoreMapping) {
	t.Helper()
	scope, err := pinnedScope(t, registryFixture(t, true))
	if err != nil {
		t.Fatal(err)
	}
	stringPtr := func(value string) *string { return &value }
	intPtr := func(value int) *int { return &value }
	started := time.Date(2026, 9, 20, 1, 2, 3, 0, time.UTC)
	source := ChatSessionRestoreSource{
		ID: 15, SessionID: "source-session", UserID: intPtr(7),
		InstanceID: intPtr(8), Title: stringPtr("historical title"),
		LastTraceID: stringPtr("source-live-cursor"),
		StartedAt:   started, LastActivityAt: started.Add(time.Hour),
	}
	mapping := ChatSessionRestoreMapping{
		SourceID: 15, TargetID: 115,
		SourceSessionID: "source-session", TargetSessionID: "restored-session-15",
		TargetUserID: intPtr(107), TargetInstanceID: intPtr(108),
	}
	return scope, source, mapping
}

func TestChatSessionRestoreCompleteHistoricalRow(t *testing.T) {
	scope, source, mapping := chatSessionRestoreFixture(t)
	proof := &chatSessionProofFixture{mutateInput: true}
	rows, err := NormalizeChatSessionsForRestore(context.Background(), scope,
		[]ChatSessionRestoreSource{source}, []ChatSessionRestoreMapping{mapping},
		"sev_chat_sessions", proof)
	if err != nil || len(rows) != 1 || proof.calls != 1 {
		t.Fatalf("chat session row incomplete: %+v, calls=%d, err=%v", rows, proof.calls, err)
	}
	row := rows[0]
	if row.ID != 115 || row.SessionID != "restored-session-15" ||
		row.UserID == nil || *row.UserID != 107 ||
		row.InstanceID == nil || *row.InstanceID != 108 ||
		row.Title == nil || *row.Title != "historical title" ||
		row.LastTraceID != nil || !row.StartedAt.Equal(source.StartedAt) ||
		!row.LastActivityAt.Equal(source.LastActivityAt) {
		t.Fatalf("historical chat session can resume or lost SQL fields: %+v", row)
	}
	*source.Title = "source changed"
	*mapping.TargetUserID = 222
	if *row.Title != "historical title" || *row.UserID != 107 {
		t.Fatal("restored chat session aliases mutable input")
	}
}

func TestChatSessionRestoreRequiresProofForEmptyAndNullableRows(t *testing.T) {
	scope, source, mapping := chatSessionRestoreFixture(t)
	proof := &chatSessionProofFixture{}
	rows, err := NormalizeChatSessionsForRestore(context.Background(), scope,
		nil, nil, "sev_chat_sessions", proof)
	if err != nil || len(rows) != 0 || proof.calls != 1 {
		t.Fatalf("empty chat sessions not proved: %+v, calls=%d, err=%v", rows, proof.calls, err)
	}
	for name, candidate := range map[string]ChatSessionSourceProofVerifier{
		"nil": nil, "typed nil": (*chatSessionProofFixture)(nil),
	} {
		rows, err := NormalizeChatSessionsForRestore(context.Background(), scope,
			[]ChatSessionRestoreSource{source}, []ChatSessionRestoreMapping{mapping},
			"sev_chat_sessions", candidate)
		if !errors.Is(err, ErrCaptureEvidenceIncomplete) || rows != nil {
			t.Fatalf("%s proof accepted: %+v, err=%v", name, rows, err)
		}
	}
	source.UserID, source.InstanceID, source.Title, source.LastTraceID = nil, nil, nil, nil
	mapping.TargetUserID, mapping.TargetInstanceID = nil, nil
	rows, err = NormalizeChatSessionsForRestore(context.Background(), scope,
		[]ChatSessionRestoreSource{source}, []ChatSessionRestoreMapping{mapping},
		"sev_chat_sessions", proof)
	if err != nil || len(rows) != 1 || rows[0].UserID != nil ||
		rows[0].InstanceID != nil || rows[0].Title != nil || rows[0].LastTraceID != nil {
		t.Fatalf("nullable chat session fields changed: %+v, err=%v", rows, err)
	}
}

func TestChatSessionRestoreRejectsResumeAndReferenceDrift(t *testing.T) {
	scope, source, mapping := chatSessionRestoreFixture(t)
	for name, mutate := range map[string]func(*ChatSessionRestoreSource, *ChatSessionRestoreMapping){
		"same session ID": func(_ *ChatSessionRestoreSource, m *ChatSessionRestoreMapping) { m.TargetSessionID = m.SourceSessionID },
		"wrong source ID": func(_ *ChatSessionRestoreSource, m *ChatSessionRestoreMapping) { m.SourceSessionID = "other" },
		"null user drift": func(_ *ChatSessionRestoreSource, m *ChatSessionRestoreMapping) { m.TargetUserID = nil },
		"invalid title": func(s *ChatSessionRestoreSource, _ *ChatSessionRestoreMapping) {
			s.Title = testChatSessionString("\xff")
		},
		"reversed times": func(s *ChatSessionRestoreSource, _ *ChatSessionRestoreMapping) {
			s.LastActivityAt = s.StartedAt.Add(-time.Second)
		},
	} {
		t.Run(name, func(t *testing.T) {
			badSource, badMapping := source, mapping
			mutate(&badSource, &badMapping)
			proof := &chatSessionProofFixture{}
			rows, err := NormalizeChatSessionsForRestore(context.Background(), scope,
				[]ChatSessionRestoreSource{badSource}, []ChatSessionRestoreMapping{badMapping},
				"sev_chat_sessions", proof)
			if !errors.Is(err, ErrChatSessionRestore) || rows != nil || proof.calls != 0 {
				t.Fatalf("invalid session reached proof: %+v, calls=%d, err=%v", rows, proof.calls, err)
			}
		})
	}
	second, secondMapping := source, mapping
	second.ID, second.SessionID = 16, "another-source-session"
	secondMapping.SourceID, secondMapping.TargetID = 16, 116
	secondMapping.SourceSessionID = second.SessionID
	secondMapping.TargetSessionID = source.SessionID
	proof := &chatSessionProofFixture{}
	rows, err := NormalizeChatSessionsForRestore(context.Background(), scope,
		[]ChatSessionRestoreSource{source, second},
		[]ChatSessionRestoreMapping{mapping, secondMapping},
		"sev_chat_sessions", proof)
	if !errors.Is(err, ErrChatSessionRestore) || rows != nil || proof.calls != 0 {
		t.Fatalf("target session reused source identifier: %+v, calls=%d, err=%v", rows, proof.calls, err)
	}
	proof = &chatSessionProofFixture{failure: errors.New("dump unavailable")}
	rows, err = NormalizeChatSessionsForRestore(context.Background(), scope,
		[]ChatSessionRestoreSource{source}, []ChatSessionRestoreMapping{mapping},
		"sev_chat_sessions", proof)
	if err == nil || rows != nil || proof.calls != 1 {
		t.Fatalf("proof failure emitted rows: %+v, calls=%d, err=%v", rows, proof.calls, err)
	}
}

func testChatSessionString(value string) *string { return &value }
