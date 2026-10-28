package systembackupbusinessa

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strings"
	"time"

	"clawreef/internal/models"
)

// ChatSessionRestoreSource covers every migration-079 chat_sessions SQL column.
type ChatSessionRestoreSource struct {
	ID             int
	SessionID      string
	UserID         *int
	InstanceID     *int
	Title          *string
	LastTraceID    *string
	StartedAt      time.Time
	LastActivityAt time.Time
}

type ChatSessionRestoreMapping struct {
	SourceID         int
	TargetID         int
	SourceSessionID  string
	TargetSessionID  string
	TargetUserID     *int
	TargetInstanceID *int
}

// B must authenticate every source row, the target user/instance references,
// target uniqueness and the common session-ID mapping used by chat_messages,
// model_invocations and risk_hits. Remapped IDs must not be reusable source IDs.
type ChatSessionSourceProofVerifier interface {
	VerifyChatSessionSources(context.Context, string, string, string,
		[]ChatSessionRestoreSource, []ChatSessionRestoreMapping) error
}

var ErrChatSessionRestore = errors.New("A chat session restore normalization failed")

// NormalizeChatSessionsForRestore clears the live trace cursor and remaps the
// session identifier. B owns the authenticated dump, SQL write and target
// isolation; D must review trace reuse across restored model invocations.
func NormalizeChatSessionsForRestore(ctx context.Context, scope *CaptureScope,
	sources []ChatSessionRestoreSource, mappings []ChatSessionRestoreMapping,
	evidenceRef string, proof ChatSessionSourceProofVerifier) ([]models.ChatSession, error) {
	if ctx == nil || ctx.Err() != nil || scope == nil || len(scope.tables) != len(tables) ||
		!hashPattern.MatchString(scope.registrySHA) || !hashPattern.MatchString(scope.schemaSHA) ||
		!evidencePattern.MatchString(evidenceRef) || len(sources) != len(mappings) {
		return nil, ErrChatSessionRestore
	}
	if nilChatSessionProof(proof) {
		return nil, ErrCaptureEvidenceIncomplete
	}
	projection := cloneChatSessionSources(sources)
	links := cloneChatSessionMappings(mappings)
	sourceSessions := make(map[string]struct{}, len(projection))
	for _, source := range projection {
		if !validUserRestoreText(source.SessionID, 100) {
			return nil, ErrChatSessionRestore
		}
		key := strings.ToLower(source.SessionID)
		if _, duplicate := sourceSessions[key]; duplicate {
			return nil, ErrChatSessionRestore
		}
		sourceSessions[key] = struct{}{}
	}
	bySource := make(map[int]ChatSessionRestoreMapping, len(links))
	targetIDs := make(map[int]struct{}, len(links))
	targetSessions := make(map[string]struct{}, len(links))
	for _, mapping := range links {
		if mapping.SourceID <= 0 || mapping.SourceID > math.MaxInt32 ||
			mapping.TargetID <= 0 || mapping.TargetID > math.MaxInt32 ||
			!validUserRestoreText(mapping.SourceSessionID, 100) ||
			!validUserRestoreText(mapping.TargetSessionID, 100) ||
			strings.EqualFold(mapping.SourceSessionID, mapping.TargetSessionID) {
			return nil, ErrChatSessionRestore
		}
		if _, duplicate := bySource[mapping.SourceID]; duplicate {
			return nil, ErrChatSessionRestore
		}
		if _, duplicate := targetIDs[mapping.TargetID]; duplicate {
			return nil, ErrChatSessionRestore
		}
		key := strings.ToLower(mapping.TargetSessionID)
		if _, duplicate := targetSessions[key]; duplicate {
			return nil, ErrChatSessionRestore
		}
		if _, sourceIdentifier := sourceSessions[key]; sourceIdentifier {
			return nil, ErrChatSessionRestore
		}
		bySource[mapping.SourceID] = mapping
		targetIDs[mapping.TargetID] = struct{}{}
		targetSessions[key] = struct{}{}
	}
	rows := make([]models.ChatSession, 0, len(projection))
	seenSources := make(map[int]struct{}, len(projection))
	seenSessionIDs := make(map[string]struct{}, len(projection))
	users := make(map[int]int)
	instances := make(map[int]int)
	for _, source := range projection {
		mapping, found := bySource[source.ID]
		if !found {
			return nil, ErrChatSessionRestore
		}
		if _, duplicate := seenSources[source.ID]; duplicate {
			return nil, ErrChatSessionRestore
		}
		key := strings.ToLower(source.SessionID)
		if _, duplicate := seenSessionIDs[key]; duplicate {
			return nil, ErrChatSessionRestore
		}
		if !bindRiskHitInt(users, source.UserID, mapping.TargetUserID) ||
			!bindRiskHitInt(instances, source.InstanceID, mapping.TargetInstanceID) {
			return nil, ErrChatSessionRestore
		}
		row, err := NormalizeChatSessionForRestore(source, mapping)
		if err != nil {
			return nil, err
		}
		seenSources[source.ID] = struct{}{}
		seenSessionIDs[key] = struct{}{}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	if err := proof.VerifyChatSessionSources(ctx, scope.registrySHA, scope.schemaSHA,
		evidenceRef, cloneChatSessionSources(projection), cloneChatSessionMappings(links)); err != nil {
		return nil, fmt.Errorf("A chat session source proof: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return rows, nil
}

// NormalizeChatSessionForRestore is a pure row transform without source or
// target authorization. Its batch entry point supplies the B proof.
func NormalizeChatSessionForRestore(source ChatSessionRestoreSource,
	mapping ChatSessionRestoreMapping) (models.ChatSession, error) {
	started := source.StartedAt.UTC().Truncate(time.Second)
	lastActivity := source.LastActivityAt.UTC().Truncate(time.Second)
	if source.ID <= 0 || source.ID > math.MaxInt32 || mapping.SourceID != source.ID ||
		mapping.TargetID <= 0 || mapping.TargetID > math.MaxInt32 ||
		mapping.SourceSessionID != source.SessionID ||
		!validUserRestoreText(source.SessionID, 100) ||
		!validUserRestoreText(mapping.TargetSessionID, 100) ||
		strings.EqualFold(source.SessionID, mapping.TargetSessionID) ||
		!validEnterpriseAuthOptionalText(source.Title, 255) ||
		!validEnterpriseAuthOptionalText(source.LastTraceID, 100) ||
		!bindRiskHitInt(make(map[int]int), source.UserID, mapping.TargetUserID) ||
		!bindRiskHitInt(make(map[int]int), source.InstanceID, mapping.TargetInstanceID) ||
		!validMySQLDateTime(started) || !validMySQLDateTime(lastActivity) ||
		lastActivity.Before(started) {
		return models.ChatSession{}, ErrChatSessionRestore
	}
	return models.ChatSession{
		ID: mapping.TargetID, SessionID: mapping.TargetSessionID,
		UserID:     cloneRiskHitInt(mapping.TargetUserID),
		InstanceID: cloneRiskHitInt(mapping.TargetInstanceID),
		Title:      cloneString(source.Title), LastTraceID: nil,
		StartedAt: started, LastActivityAt: lastActivity,
	}, nil
}

func cloneChatSessionSources(sources []ChatSessionRestoreSource) []ChatSessionRestoreSource {
	result := append([]ChatSessionRestoreSource(nil), sources...)
	for i := range result {
		result[i].UserID = cloneRiskHitInt(result[i].UserID)
		result[i].InstanceID = cloneRiskHitInt(result[i].InstanceID)
		result[i].Title = cloneString(result[i].Title)
		result[i].LastTraceID = cloneString(result[i].LastTraceID)
	}
	return result
}

func cloneChatSessionMappings(mappings []ChatSessionRestoreMapping) []ChatSessionRestoreMapping {
	result := append([]ChatSessionRestoreMapping(nil), mappings...)
	for i := range result {
		result[i].TargetUserID = cloneRiskHitInt(result[i].TargetUserID)
		result[i].TargetInstanceID = cloneRiskHitInt(result[i].TargetInstanceID)
	}
	return result
}

func nilChatSessionProof(proof ChatSessionSourceProofVerifier) bool {
	if proof == nil {
		return true
	}
	value := reflect.ValueOf(proof)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
