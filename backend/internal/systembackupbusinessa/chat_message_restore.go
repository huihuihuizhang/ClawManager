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

// ChatMessageRestoreSource covers every migration-079 chat_messages SQL column.
// Content is confidential source data; it is never copied into the target row.
type ChatMessageRestoreSource struct {
	ID           int
	TraceID      string
	SessionID    string
	RequestID    *string
	UserID       *int
	InstanceID   *int
	InvocationID *int
	Role         string
	Content      string
	SequenceNo   int
	CreatedAt    time.Time
}

type ChatMessageRestoreMapping struct {
	SourceID           int
	TargetID           int
	TargetTraceID      string
	TargetUserID       *int
	TargetInstanceID   *int
	TargetInvocationID *int
}

// B authenticates the dump, target occupancy, references and the common
// source-to-target session/trace maps used across all A-owned AI records.
type ChatMessageSourceProofVerifier interface {
	VerifyChatMessageSources(context.Context, string, string, string,
		[]ChatMessageRestoreSource, []ChatMessageRestoreMapping,
		[]ChatSessionRestoreMapping) error
}

var ErrChatMessageRestore = errors.New("A chat message restore normalization failed")

// NormalizeChatMessagesForRestore produces historical rows with redacted
// content and non-source trace/session IDs. B owns source proof and SQL writes.
func NormalizeChatMessagesForRestore(ctx context.Context, scope *CaptureScope,
	sources []ChatMessageRestoreSource, mappings []ChatMessageRestoreMapping,
	sessions []ChatSessionRestoreMapping, evidenceRef string,
	proof ChatMessageSourceProofVerifier) ([]models.ChatMessageRecord, error) {
	if ctx == nil || ctx.Err() != nil || scope == nil || len(scope.tables) != len(tables) ||
		!hashPattern.MatchString(scope.registrySHA) || !hashPattern.MatchString(scope.schemaSHA) ||
		!evidencePattern.MatchString(evidenceRef) || len(sources) != len(mappings) {
		return nil, ErrChatMessageRestore
	}
	if nilChatMessageProof(proof) {
		return nil, ErrCaptureEvidenceIncomplete
	}
	projection := cloneChatMessageSources(sources)
	links := cloneChatMessageMappings(mappings)
	sessionLinks := cloneChatSessionMappings(sessions)
	sessionBySource := make(map[string]string, len(sessionLinks))
	for _, session := range sessionLinks {
		if session.SourceID <= 0 || session.TargetID <= 0 ||
			!validUserRestoreText(session.SourceSessionID, 100) ||
			!validUserRestoreText(session.TargetSessionID, 100) ||
			strings.EqualFold(session.SourceSessionID, session.TargetSessionID) {
			return nil, ErrChatMessageRestore
		}
		key := strings.ToLower(session.SourceSessionID)
		if _, duplicate := sessionBySource[key]; duplicate {
			return nil, ErrChatMessageRestore
		}
		sessionBySource[key] = session.TargetSessionID
	}
	sourceTraces := make(map[string]struct{}, len(projection))
	for _, source := range projection {
		if !validUserRestoreText(source.TraceID, 100) {
			return nil, ErrChatMessageRestore
		}
		sourceTraces[strings.ToLower(source.TraceID)] = struct{}{}
	}
	bySource := make(map[int]ChatMessageRestoreMapping, len(links))
	targetIDs := make(map[int]struct{}, len(links))
	for _, mapping := range links {
		if mapping.SourceID <= 0 || mapping.SourceID > math.MaxInt32 ||
			mapping.TargetID <= 0 || mapping.TargetID > math.MaxInt32 ||
			!validUserRestoreText(mapping.TargetTraceID, 100) {
			return nil, ErrChatMessageRestore
		}
		if _, sourceIdentifier := sourceTraces[strings.ToLower(mapping.TargetTraceID)]; sourceIdentifier {
			return nil, ErrChatMessageRestore
		}
		if _, duplicate := bySource[mapping.SourceID]; duplicate {
			return nil, ErrChatMessageRestore
		}
		if _, duplicate := targetIDs[mapping.TargetID]; duplicate {
			return nil, ErrChatMessageRestore
		}
		bySource[mapping.SourceID] = mapping
		targetIDs[mapping.TargetID] = struct{}{}
	}
	rows := make([]models.ChatMessageRecord, 0, len(projection))
	seenSources := make(map[int]struct{}, len(projection))
	users := make(map[int]int)
	instances := make(map[int]int)
	invocations := make(map[int]int)
	traces := make(map[string]string)
	targetTraces := make(map[string]string)
	for _, source := range projection {
		mapping, found := bySource[source.ID]
		if !found {
			return nil, ErrChatMessageRestore
		}
		if _, duplicate := seenSources[source.ID]; duplicate {
			return nil, ErrChatMessageRestore
		}
		targetSessionID, found := sessionBySource[strings.ToLower(source.SessionID)]
		if !found || !bindRiskHitInt(users, source.UserID, mapping.TargetUserID) ||
			!bindRiskHitInt(instances, source.InstanceID, mapping.TargetInstanceID) ||
			!bindRiskHitInt(invocations, source.InvocationID, mapping.TargetInvocationID) {
			return nil, ErrChatMessageRestore
		}
		traceKey := strings.ToLower(source.TraceID)
		if prior, found := traces[traceKey]; found && !strings.EqualFold(prior, mapping.TargetTraceID) {
			return nil, ErrChatMessageRestore
		}
		targetTraceKey := strings.ToLower(mapping.TargetTraceID)
		if prior, found := targetTraces[targetTraceKey]; found && prior != traceKey {
			return nil, ErrChatMessageRestore
		}
		traces[traceKey] = mapping.TargetTraceID
		targetTraces[targetTraceKey] = traceKey
		row, err := NormalizeChatMessageForRestore(source, mapping, targetSessionID)
		if err != nil {
			return nil, err
		}
		seenSources[source.ID] = struct{}{}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	if err := proof.VerifyChatMessageSources(ctx, scope.registrySHA, scope.schemaSHA,
		evidenceRef, cloneChatMessageSources(projection), cloneChatMessageMappings(links),
		cloneChatSessionMappings(sessionLinks)); err != nil {
		return nil, fmt.Errorf("A chat message source proof: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return rows, nil
}

// NormalizeChatMessageForRestore is a pure transform. The batch entry point
// supplies the authenticated session map and cross-row consistency checks.
func NormalizeChatMessageForRestore(source ChatMessageRestoreSource,
	mapping ChatMessageRestoreMapping, targetSessionID string) (models.ChatMessageRecord, error) {
	created := source.CreatedAt.UTC().Truncate(time.Second)
	if source.ID <= 0 || source.ID > math.MaxInt32 || mapping.SourceID != source.ID ||
		mapping.TargetID <= 0 || mapping.TargetID > math.MaxInt32 ||
		!validUserRestoreText(source.TraceID, 100) ||
		!validUserRestoreText(source.SessionID, 100) ||
		!validUserRestoreText(targetSessionID, 100) ||
		strings.EqualFold(source.SessionID, targetSessionID) ||
		!validUserRestoreText(mapping.TargetTraceID, 100) ||
		strings.EqualFold(source.TraceID, mapping.TargetTraceID) ||
		!validEnterpriseAuthOptionalText(source.RequestID, 100) ||
		!bindRiskHitInt(make(map[int]int), source.UserID, mapping.TargetUserID) ||
		!bindRiskHitInt(make(map[int]int), source.InstanceID, mapping.TargetInstanceID) ||
		!bindRiskHitInt(make(map[int]int), source.InvocationID, mapping.TargetInvocationID) ||
		!validUserRestoreText(source.Role, 50) ||
		source.SequenceNo < 0 || source.SequenceNo > math.MaxInt32 ||
		!validMySQLDateTime(created) {
		return models.ChatMessageRecord{}, ErrChatMessageRestore
	}
	return models.ChatMessageRecord{
		ID: mapping.TargetID, TraceID: mapping.TargetTraceID,
		SessionID: targetSessionID, RequestID: cloneString(source.RequestID),
		UserID:       cloneRiskHitInt(mapping.TargetUserID),
		InstanceID:   cloneRiskHitInt(mapping.TargetInstanceID),
		InvocationID: cloneRiskHitInt(mapping.TargetInvocationID),
		Role:         source.Role, Content: "[REDACTED]",
		SequenceNo: source.SequenceNo, CreatedAt: created,
	}, nil
}

func cloneChatMessageSources(sources []ChatMessageRestoreSource) []ChatMessageRestoreSource {
	result := append([]ChatMessageRestoreSource(nil), sources...)
	for i := range result {
		result[i].RequestID = cloneString(result[i].RequestID)
		result[i].UserID = cloneRiskHitInt(result[i].UserID)
		result[i].InstanceID = cloneRiskHitInt(result[i].InstanceID)
		result[i].InvocationID = cloneRiskHitInt(result[i].InvocationID)
	}
	return result
}

func cloneChatMessageMappings(mappings []ChatMessageRestoreMapping) []ChatMessageRestoreMapping {
	result := append([]ChatMessageRestoreMapping(nil), mappings...)
	for i := range result {
		result[i].TargetUserID = cloneRiskHitInt(result[i].TargetUserID)
		result[i].TargetInstanceID = cloneRiskHitInt(result[i].TargetInstanceID)
		result[i].TargetInvocationID = cloneRiskHitInt(result[i].TargetInvocationID)
	}
	return result
}

func nilChatMessageProof(proof ChatMessageSourceProofVerifier) bool {
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
