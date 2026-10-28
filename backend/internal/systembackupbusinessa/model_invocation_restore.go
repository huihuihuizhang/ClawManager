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

// ModelInvocationRestoreSource describes every migration-028 column without
// carrying request/response bodies or error text into A's normalizer. B must
// certify their SQL NULL/non-NULL states against the sealed source row.
type ModelInvocationRestoreSource struct {
	ID                     int
	TraceID                string
	SessionID              *string
	RequestID              string
	UserID                 *int
	InstanceID             *int
	InstanceMode           *string
	RuntimeType            *string
	GatewayID              *string
	RuntimePodID           *int64
	ModelID                *int
	ProviderType           string
	RequestedModel         string
	ActualProviderModel    string
	TrafficClass           string
	RequestPayloadPresent  bool
	ResponsePayloadPresent bool
	PromptTokens           int
	CompletionTokens       int
	TotalTokens            int
	CachedTokens           *int
	ReasoningTokens        *int
	LatencyMs              *int
	IsStreaming            bool
	Status                 string
	ErrorMessagePresent    bool
	CreatedAt              time.Time
	CompletedAt            *time.Time
}

type ModelInvocationRestoreMapping struct {
	SourceID           int
	TargetID           int
	TargetTraceID      string
	TargetSessionID    *string
	TargetUserID       *int
	TargetInstanceID   *int
	TargetGatewayID    *string
	TargetRuntimePodID *int64
	TargetModelID      *int
}

// B authenticates the source dump, body presence, all target references,
// the common session/trace mapping, target occupancy and restore-write access.
// The proof must cover an empty source as well as nonempty batches.
type ModelInvocationSourceProofVerifier interface {
	VerifyModelInvocationSources(context.Context, string, string, string,
		[]ModelInvocationRestoreSource, []ModelInvocationRestoreMapping,
		[]ChatSessionRestoreMapping) error
}

var ErrModelInvocationRestore = errors.New("A model invocation restore normalization failed")

// NormalizeModelInvocationsForRestore returns complete historical SQL rows.
// It never forwards payloads or error details, and a pending source call is
// made terminal so it cannot appear to be a resumable in-flight request.
func NormalizeModelInvocationsForRestore(ctx context.Context, scope *CaptureScope,
	sources []ModelInvocationRestoreSource, mappings []ModelInvocationRestoreMapping,
	sessions []ChatSessionRestoreMapping, evidenceRef string,
	proof ModelInvocationSourceProofVerifier) ([]models.ModelInvocation, error) {
	if ctx == nil || ctx.Err() != nil || scope == nil || len(scope.tables) != len(tables) ||
		!hashPattern.MatchString(scope.registrySHA) || !hashPattern.MatchString(scope.schemaSHA) ||
		!evidencePattern.MatchString(evidenceRef) || len(sources) != len(mappings) {
		return nil, ErrModelInvocationRestore
	}
	if nilModelInvocationProof(proof) {
		return nil, ErrCaptureEvidenceIncomplete
	}
	projection := cloneModelInvocationSources(sources)
	links := cloneModelInvocationMappings(mappings)
	sessionLinks := cloneChatSessionMappings(sessions)
	sessionBySource := make(map[string]string, len(sessionLinks))
	for _, session := range sessionLinks {
		if session.SourceID <= 0 || session.TargetID <= 0 ||
			!validUserRestoreText(session.SourceSessionID, 100) ||
			!validUserRestoreText(session.TargetSessionID, 100) ||
			strings.EqualFold(session.SourceSessionID, session.TargetSessionID) {
			return nil, ErrModelInvocationRestore
		}
		key := strings.ToLower(session.SourceSessionID)
		if _, exists := sessionBySource[key]; exists {
			return nil, ErrModelInvocationRestore
		}
		sessionBySource[key] = session.TargetSessionID
	}
	sourceTraces := make(map[string]struct{}, len(projection))
	for _, source := range projection {
		if !validUserRestoreText(source.TraceID, 100) {
			return nil, ErrModelInvocationRestore
		}
		sourceTraces[strings.ToLower(source.TraceID)] = struct{}{}
	}
	bySource := make(map[int]ModelInvocationRestoreMapping, len(links))
	targetIDs := make(map[int]struct{}, len(links))
	for _, mapping := range links {
		if mapping.SourceID <= 0 || mapping.SourceID > math.MaxInt32 ||
			mapping.TargetID <= 0 || mapping.TargetID > math.MaxInt32 ||
			!validUserRestoreText(mapping.TargetTraceID, 100) {
			return nil, ErrModelInvocationRestore
		}
		if _, sourceTrace := sourceTraces[strings.ToLower(mapping.TargetTraceID)]; sourceTrace {
			return nil, ErrModelInvocationRestore
		}
		if _, exists := bySource[mapping.SourceID]; exists {
			return nil, ErrModelInvocationRestore
		}
		if _, exists := targetIDs[mapping.TargetID]; exists {
			return nil, ErrModelInvocationRestore
		}
		bySource[mapping.SourceID] = mapping
		targetIDs[mapping.TargetID] = struct{}{}
	}
	rows := make([]models.ModelInvocation, 0, len(projection))
	seenSources := make(map[int]struct{}, len(projection))
	users := make(map[int]int)
	instances := make(map[int]int)
	modelsBySource := make(map[int]int)
	pods := make(map[int64]int64)
	gateways := make(map[string]string)
	traces := make(map[string]string)
	targetTraces := make(map[string]string)
	for _, source := range projection {
		mapping, found := bySource[source.ID]
		if !found {
			return nil, ErrModelInvocationRestore
		}
		if _, duplicate := seenSources[source.ID]; duplicate ||
			!bindRiskHitInt(users, source.UserID, mapping.TargetUserID) ||
			!bindRiskHitInt(instances, source.InstanceID, mapping.TargetInstanceID) ||
			!bindRiskHitInt(modelsBySource, source.ModelID, mapping.TargetModelID) ||
			!bindRiskHitInt64(pods, source.RuntimePodID, mapping.TargetRuntimePodID) ||
			!bindRiskHitString(gateways, source.GatewayID, mapping.TargetGatewayID, 128) {
			return nil, ErrModelInvocationRestore
		}
		if source.SessionID == nil {
			if mapping.TargetSessionID != nil {
				return nil, ErrModelInvocationRestore
			}
		} else if target, found := sessionBySource[strings.ToLower(*source.SessionID)]; !found || mapping.TargetSessionID == nil || target != *mapping.TargetSessionID {
			return nil, ErrModelInvocationRestore
		}
		traceKey := strings.ToLower(source.TraceID)
		if prior, found := traces[traceKey]; found && !strings.EqualFold(prior, mapping.TargetTraceID) {
			return nil, ErrModelInvocationRestore
		}
		targetTraceKey := strings.ToLower(mapping.TargetTraceID)
		if prior, found := targetTraces[targetTraceKey]; found && prior != traceKey {
			return nil, ErrModelInvocationRestore
		}
		traces[traceKey] = mapping.TargetTraceID
		targetTraces[targetTraceKey] = traceKey
		row, err := NormalizeModelInvocationForRestore(source, mapping)
		if err != nil {
			return nil, err
		}
		seenSources[source.ID] = struct{}{}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	if err := proof.VerifyModelInvocationSources(ctx, scope.registrySHA, scope.schemaSHA,
		evidenceRef, cloneModelInvocationSources(projection), cloneModelInvocationMappings(links),
		cloneChatSessionMappings(sessionLinks)); err != nil {
		return nil, fmt.Errorf("A model invocation source proof: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return rows, nil
}

// NormalizeModelInvocationForRestore is a pure row transform. Only the batch
// entry point verifies the source and bindings before returning rows for SQL.
func NormalizeModelInvocationForRestore(source ModelInvocationRestoreSource,
	mapping ModelInvocationRestoreMapping) (models.ModelInvocation, error) {
	created := source.CreatedAt.UTC().Truncate(time.Second)
	if source.ID <= 0 || source.ID > math.MaxInt32 || mapping.SourceID != source.ID ||
		mapping.TargetID <= 0 || mapping.TargetID > math.MaxInt32 ||
		!validUserRestoreText(source.TraceID, 100) ||
		!validUserRestoreText(mapping.TargetTraceID, 100) ||
		strings.EqualFold(source.TraceID, mapping.TargetTraceID) ||
		!validOptionalRestoreText(source.SessionID, 100) ||
		!bindRiskHitString(make(map[string]string), source.SessionID, mapping.TargetSessionID, 100) ||
		!validUserRestoreText(source.RequestID, 100) ||
		!bindRiskHitInt(make(map[int]int), source.UserID, mapping.TargetUserID) ||
		!bindRiskHitInt(make(map[int]int), source.InstanceID, mapping.TargetInstanceID) ||
		!bindRiskHitInt(make(map[int]int), source.ModelID, mapping.TargetModelID) ||
		!bindRiskHitInt64(make(map[int64]int64), source.RuntimePodID, mapping.TargetRuntimePodID) ||
		!bindRiskHitString(make(map[string]string), source.GatewayID, mapping.TargetGatewayID, 128) ||
		!validEnterpriseAuthOptionalText(source.InstanceMode, 16) ||
		!validEnterpriseAuthOptionalText(source.RuntimeType, 32) ||
		!validUserRestoreText(source.ProviderType, 100) ||
		!validUserRestoreText(source.RequestedModel, 255) ||
		!validUserRestoreText(source.ActualProviderModel, 255) ||
		!validUserRestoreText(source.TrafficClass, 50) ||
		!validModelInvocationStatus(source.Status) ||
		!validModelInvocationCounters(source) || !validMySQLDateTime(created) {
		return models.ModelInvocation{}, ErrModelInvocationRestore
	}
	var completed *time.Time
	if source.CompletedAt != nil {
		value := source.CompletedAt.UTC().Truncate(time.Second)
		if !validMySQLDateTime(value) || value.Before(created) {
			return models.ModelInvocation{}, ErrModelInvocationRestore
		}
		completed = &value
	}
	status := source.Status
	if status == models.ModelInvocationStatusPending {
		status = models.ModelInvocationStatusFailed
		if completed == nil {
			value := created
			completed = &value
		}
	}
	return models.ModelInvocation{
		ID: mapping.TargetID, TraceID: mapping.TargetTraceID,
		SessionID: cloneString(mapping.TargetSessionID), RequestID: source.RequestID,
		UserID: cloneRiskHitInt(mapping.TargetUserID), InstanceID: cloneRiskHitInt(mapping.TargetInstanceID),
		InstanceMode: cloneString(source.InstanceMode), RuntimeType: cloneString(source.RuntimeType),
		GatewayID: cloneString(mapping.TargetGatewayID), RuntimePodID: cloneRiskHitInt64(mapping.TargetRuntimePodID),
		ModelID: cloneRiskHitInt(mapping.TargetModelID), ProviderType: source.ProviderType,
		RequestedModel: source.RequestedModel, ActualProviderModel: source.ActualProviderModel,
		TrafficClass: source.TrafficClass, RequestPayload: redactedNullable(source.RequestPayloadPresent),
		ResponsePayload: redactedNullable(source.ResponsePayloadPresent),
		PromptTokens:    source.PromptTokens, CompletionTokens: source.CompletionTokens,
		TotalTokens: source.TotalTokens, CachedTokens: cloneRiskHitInt(source.CachedTokens),
		ReasoningTokens: cloneRiskHitInt(source.ReasoningTokens), LatencyMs: cloneRiskHitInt(source.LatencyMs),
		IsStreaming: source.IsStreaming, Status: status,
		ErrorMessage: redactedNullable(source.ErrorMessagePresent), CreatedAt: created, CompletedAt: completed,
	}, nil
}

func validModelInvocationStatus(status string) bool {
	switch status {
	case models.ModelInvocationStatusPending, models.ModelInvocationStatusCompleted,
		models.ModelInvocationStatusFailed, models.ModelInvocationStatusBlocked:
		return true
	default:
		return false
	}
}

func validModelInvocationCounters(source ModelInvocationRestoreSource) bool {
	if source.PromptTokens < 0 || source.CompletionTokens < 0 || source.TotalTokens < 0 ||
		source.PromptTokens > math.MaxInt32 || source.CompletionTokens > math.MaxInt32 ||
		source.TotalTokens > math.MaxInt32 ||
		source.TotalTokens < source.PromptTokens || source.TotalTokens < source.CompletionTokens {
		return false
	}
	for _, value := range []*int{source.CachedTokens, source.ReasoningTokens, source.LatencyMs} {
		if value != nil && (*value < 0 || *value > math.MaxInt32) {
			return false
		}
	}
	return true
}

func redactedNullable(present bool) *string {
	if !present {
		return nil
	}
	value := "[REDACTED]"
	return &value
}

func cloneModelInvocationSources(sources []ModelInvocationRestoreSource) []ModelInvocationRestoreSource {
	result := append([]ModelInvocationRestoreSource(nil), sources...)
	for i := range result {
		result[i].SessionID = cloneString(result[i].SessionID)
		result[i].UserID = cloneRiskHitInt(result[i].UserID)
		result[i].InstanceID = cloneRiskHitInt(result[i].InstanceID)
		result[i].InstanceMode = cloneString(result[i].InstanceMode)
		result[i].RuntimeType = cloneString(result[i].RuntimeType)
		result[i].GatewayID = cloneString(result[i].GatewayID)
		result[i].RuntimePodID = cloneRiskHitInt64(result[i].RuntimePodID)
		result[i].ModelID = cloneRiskHitInt(result[i].ModelID)
		result[i].CachedTokens = cloneRiskHitInt(result[i].CachedTokens)
		result[i].ReasoningTokens = cloneRiskHitInt(result[i].ReasoningTokens)
		result[i].LatencyMs = cloneRiskHitInt(result[i].LatencyMs)
		if result[i].CompletedAt != nil {
			value := *result[i].CompletedAt
			result[i].CompletedAt = &value
		}
	}
	return result
}

func cloneModelInvocationMappings(mappings []ModelInvocationRestoreMapping) []ModelInvocationRestoreMapping {
	result := append([]ModelInvocationRestoreMapping(nil), mappings...)
	for i := range result {
		result[i].TargetSessionID = cloneString(result[i].TargetSessionID)
		result[i].TargetUserID = cloneRiskHitInt(result[i].TargetUserID)
		result[i].TargetInstanceID = cloneRiskHitInt(result[i].TargetInstanceID)
		result[i].TargetGatewayID = cloneString(result[i].TargetGatewayID)
		result[i].TargetRuntimePodID = cloneRiskHitInt64(result[i].TargetRuntimePodID)
		result[i].TargetModelID = cloneRiskHitInt(result[i].TargetModelID)
	}
	return result
}

func nilModelInvocationProof(proof ModelInvocationSourceProofVerifier) bool {
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
