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
)

// CostRecordRestoreSource covers migration-028 cost_records. Money is read
// from SQL DECIMAL as text so a float conversion cannot change the amount.
type CostRecordRestoreSource struct {
	ID               int
	TraceID          string
	SessionID        *string
	RequestID        *string
	UserID           *int
	InstanceID       *int
	InstanceMode     *string
	RuntimeType      *string
	GatewayID        *string
	RuntimePodID     *int64
	InvocationID     *int
	ModelID          *int
	ProviderType     string
	ModelName        string
	Currency         string
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
	InputUnitPrice   string
	OutputUnitPrice  string
	EstimatedCost    string
	ActualCost       *string
	InternalCost     string
	RecordedAt       time.Time
}

type CostRecordRestoreMapping struct {
	SourceID           int
	TargetID           int
	TargetTraceID      string
	TargetSessionID    *string
	TargetUserID       *int
	TargetInstanceID   *int
	TargetGatewayID    *string
	TargetRuntimePodID *int64
	TargetInvocationID *int
	TargetModelID      *int
}

// NormalizedCostRecord is a complete parameterized SQL row. It intentionally
// does not use models.CostRecord because its float64 prices lose SQL precision.
type NormalizedCostRecord struct {
	ID               int
	TraceID          string
	SessionID        *string
	RequestID        *string
	UserID           *int
	InstanceID       *int
	InstanceMode     *string
	RuntimeType      *string
	GatewayID        *string
	RuntimePodID     *int64
	InvocationID     *int
	ModelID          *int
	ProviderType     string
	ModelName        string
	Currency         string
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
	InputUnitPrice   string
	OutputUnitPrice  string
	EstimatedCost    string
	ActualCost       *string
	InternalCost     string
	RecordedAt       time.Time
}

// B must authenticate source rows and their DECIMAL/NULL values, the common
// trace/session/invocation mapping, target occupancy and SQL write authority.
type CostRecordSourceProofVerifier interface {
	VerifyCostRecordSources(context.Context, string, string, string,
		[]CostRecordRestoreSource, []CostRecordRestoreMapping,
		[]ChatSessionRestoreMapping) error
}

var ErrCostRecordRestore = errors.New("A cost record restore normalization failed")

func NormalizeCostRecordsForRestore(ctx context.Context, scope *CaptureScope,
	sources []CostRecordRestoreSource, mappings []CostRecordRestoreMapping,
	sessions []ChatSessionRestoreMapping, evidenceRef string,
	proof CostRecordSourceProofVerifier) ([]NormalizedCostRecord, error) {
	if ctx == nil || ctx.Err() != nil || scope == nil || len(scope.tables) != len(tables) ||
		!hashPattern.MatchString(scope.registrySHA) || !hashPattern.MatchString(scope.schemaSHA) ||
		!evidencePattern.MatchString(evidenceRef) || len(sources) != len(mappings) {
		return nil, ErrCostRecordRestore
	}
	if nilCostRecordProof(proof) {
		return nil, ErrCaptureEvidenceIncomplete
	}
	projection := cloneCostRecordSources(sources)
	links := cloneCostRecordMappings(mappings)
	sessionLinks := cloneChatSessionMappings(sessions)
	sessionBySource := make(map[string]string, len(sessionLinks))
	for _, session := range sessionLinks {
		if session.SourceID <= 0 || session.TargetID <= 0 ||
			!validUserRestoreText(session.SourceSessionID, 100) ||
			!validUserRestoreText(session.TargetSessionID, 100) ||
			strings.EqualFold(session.SourceSessionID, session.TargetSessionID) {
			return nil, ErrCostRecordRestore
		}
		key := strings.ToLower(session.SourceSessionID)
		if _, duplicate := sessionBySource[key]; duplicate {
			return nil, ErrCostRecordRestore
		}
		sessionBySource[key] = session.TargetSessionID
	}
	sourceTraces := make(map[string]struct{}, len(projection))
	for _, source := range projection {
		if !validUserRestoreText(source.TraceID, 100) {
			return nil, ErrCostRecordRestore
		}
		sourceTraces[strings.ToLower(source.TraceID)] = struct{}{}
	}
	bySource := make(map[int]CostRecordRestoreMapping, len(links))
	targetIDs := make(map[int]struct{}, len(links))
	for _, mapping := range links {
		if mapping.SourceID <= 0 || mapping.SourceID > math.MaxInt32 ||
			mapping.TargetID <= 0 || mapping.TargetID > math.MaxInt32 ||
			!validUserRestoreText(mapping.TargetTraceID, 100) {
			return nil, ErrCostRecordRestore
		}
		if _, reused := sourceTraces[strings.ToLower(mapping.TargetTraceID)]; reused {
			return nil, ErrCostRecordRestore
		}
		if _, duplicate := bySource[mapping.SourceID]; duplicate {
			return nil, ErrCostRecordRestore
		}
		if _, duplicate := targetIDs[mapping.TargetID]; duplicate {
			return nil, ErrCostRecordRestore
		}
		bySource[mapping.SourceID] = mapping
		targetIDs[mapping.TargetID] = struct{}{}
	}
	rows := make([]NormalizedCostRecord, 0, len(projection))
	seenSources := make(map[int]struct{}, len(projection))
	users := make(map[int]int)
	instances := make(map[int]int)
	invocations := make(map[int]int)
	modelIDs := make(map[int]int)
	pods := make(map[int64]int64)
	gateways := make(map[string]string)
	traces := make(map[string]string)
	targetTraces := make(map[string]string)
	for _, source := range projection {
		mapping, found := bySource[source.ID]
		if !found {
			return nil, ErrCostRecordRestore
		}
		if _, duplicate := seenSources[source.ID]; duplicate ||
			!bindRiskHitInt(users, source.UserID, mapping.TargetUserID) ||
			!bindRiskHitInt(instances, source.InstanceID, mapping.TargetInstanceID) ||
			!bindRiskHitInt(invocations, source.InvocationID, mapping.TargetInvocationID) ||
			!bindRiskHitInt(modelIDs, source.ModelID, mapping.TargetModelID) ||
			!bindRiskHitInt64(pods, source.RuntimePodID, mapping.TargetRuntimePodID) ||
			!bindRiskHitString(gateways, source.GatewayID, mapping.TargetGatewayID, 128) {
			return nil, ErrCostRecordRestore
		}
		if source.SessionID == nil {
			if mapping.TargetSessionID != nil {
				return nil, ErrCostRecordRestore
			}
		} else if target, found := sessionBySource[strings.ToLower(*source.SessionID)]; !found || mapping.TargetSessionID == nil || target != *mapping.TargetSessionID {
			return nil, ErrCostRecordRestore
		}
		traceKey := strings.ToLower(source.TraceID)
		if prior, found := traces[traceKey]; found && !strings.EqualFold(prior, mapping.TargetTraceID) {
			return nil, ErrCostRecordRestore
		}
		targetTraceKey := strings.ToLower(mapping.TargetTraceID)
		if prior, found := targetTraces[targetTraceKey]; found && prior != traceKey {
			return nil, ErrCostRecordRestore
		}
		traces[traceKey] = mapping.TargetTraceID
		targetTraces[targetTraceKey] = traceKey
		row, err := NormalizeCostRecordForRestore(source, mapping)
		if err != nil {
			return nil, err
		}
		seenSources[source.ID] = struct{}{}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	if err := proof.VerifyCostRecordSources(ctx, scope.registrySHA, scope.schemaSHA,
		evidenceRef, cloneCostRecordSources(projection), cloneCostRecordMappings(links),
		cloneChatSessionMappings(sessionLinks)); err != nil {
		return nil, fmt.Errorf("A cost record source proof: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return rows, nil
}

// The pure row transform does not authorize a SQL write; use the batch entry
// point with B's proof before any row can be supplied to a restore writer.
func NormalizeCostRecordForRestore(source CostRecordRestoreSource,
	mapping CostRecordRestoreMapping) (NormalizedCostRecord, error) {
	recorded := source.RecordedAt.UTC().Truncate(time.Second)
	inputPrice, inputOK := canonicalLLMPrice(source.InputUnitPrice)
	outputPrice, outputOK := canonicalLLMPrice(source.OutputUnitPrice)
	estimated, estimatedOK := canonicalLLMPrice(source.EstimatedCost)
	internal, internalOK := canonicalLLMPrice(source.InternalCost)
	var actual *string
	if source.ActualCost != nil {
		value, ok := canonicalLLMPrice(*source.ActualCost)
		if !ok {
			return NormalizedCostRecord{}, ErrCostRecordRestore
		}
		actual = &value
	}
	if source.ID <= 0 || source.ID > math.MaxInt32 || mapping.SourceID != source.ID ||
		mapping.TargetID <= 0 || mapping.TargetID > math.MaxInt32 ||
		!validUserRestoreText(source.TraceID, 100) ||
		!validUserRestoreText(mapping.TargetTraceID, 100) ||
		strings.EqualFold(source.TraceID, mapping.TargetTraceID) ||
		!validOptionalRestoreText(source.SessionID, 100) ||
		!bindRiskHitString(make(map[string]string), source.SessionID, mapping.TargetSessionID, 100) ||
		!validEnterpriseAuthOptionalText(source.RequestID, 100) ||
		!bindRiskHitInt(make(map[int]int), source.UserID, mapping.TargetUserID) ||
		!bindRiskHitInt(make(map[int]int), source.InstanceID, mapping.TargetInstanceID) ||
		!bindRiskHitInt(make(map[int]int), source.InvocationID, mapping.TargetInvocationID) ||
		!bindRiskHitInt(make(map[int]int), source.ModelID, mapping.TargetModelID) ||
		!bindRiskHitInt64(make(map[int64]int64), source.RuntimePodID, mapping.TargetRuntimePodID) ||
		!bindRiskHitString(make(map[string]string), source.GatewayID, mapping.TargetGatewayID, 128) ||
		!validEnterpriseAuthOptionalText(source.InstanceMode, 16) ||
		!validEnterpriseAuthOptionalText(source.RuntimeType, 32) ||
		!validUserRestoreText(source.ProviderType, 100) ||
		!validUserRestoreText(source.ModelName, 255) ||
		!validUserRestoreText(source.Currency, 16) ||
		!inputOK || !outputOK || !estimatedOK || !internalOK ||
		source.PromptTokens < 0 || source.CompletionTokens < 0 || source.TotalTokens < 0 ||
		source.PromptTokens > math.MaxInt32 || source.CompletionTokens > math.MaxInt32 ||
		source.TotalTokens > math.MaxInt32 ||
		source.TotalTokens < source.PromptTokens || source.TotalTokens < source.CompletionTokens ||
		!validMySQLDateTime(recorded) {
		return NormalizedCostRecord{}, ErrCostRecordRestore
	}
	return NormalizedCostRecord{
		ID: mapping.TargetID, TraceID: mapping.TargetTraceID,
		SessionID: cloneString(mapping.TargetSessionID), RequestID: cloneString(source.RequestID),
		UserID: cloneRiskHitInt(mapping.TargetUserID), InstanceID: cloneRiskHitInt(mapping.TargetInstanceID),
		InstanceMode: cloneString(source.InstanceMode), RuntimeType: cloneString(source.RuntimeType),
		GatewayID: cloneString(mapping.TargetGatewayID), RuntimePodID: cloneRiskHitInt64(mapping.TargetRuntimePodID),
		InvocationID: cloneRiskHitInt(mapping.TargetInvocationID), ModelID: cloneRiskHitInt(mapping.TargetModelID),
		ProviderType: source.ProviderType, ModelName: source.ModelName, Currency: source.Currency,
		PromptTokens: source.PromptTokens, CompletionTokens: source.CompletionTokens,
		TotalTokens: source.TotalTokens, InputUnitPrice: inputPrice,
		OutputUnitPrice: outputPrice, EstimatedCost: estimated, ActualCost: actual,
		InternalCost: internal, RecordedAt: recorded,
	}, nil
}

func cloneCostRecordSources(sources []CostRecordRestoreSource) []CostRecordRestoreSource {
	result := append([]CostRecordRestoreSource(nil), sources...)
	for i := range result {
		result[i].SessionID = cloneString(result[i].SessionID)
		result[i].RequestID = cloneString(result[i].RequestID)
		result[i].UserID = cloneRiskHitInt(result[i].UserID)
		result[i].InstanceID = cloneRiskHitInt(result[i].InstanceID)
		result[i].InstanceMode = cloneString(result[i].InstanceMode)
		result[i].RuntimeType = cloneString(result[i].RuntimeType)
		result[i].GatewayID = cloneString(result[i].GatewayID)
		result[i].RuntimePodID = cloneRiskHitInt64(result[i].RuntimePodID)
		result[i].InvocationID = cloneRiskHitInt(result[i].InvocationID)
		result[i].ModelID = cloneRiskHitInt(result[i].ModelID)
		result[i].ActualCost = cloneString(result[i].ActualCost)
	}
	return result
}

func cloneCostRecordMappings(mappings []CostRecordRestoreMapping) []CostRecordRestoreMapping {
	result := append([]CostRecordRestoreMapping(nil), mappings...)
	for i := range result {
		result[i].TargetSessionID = cloneString(result[i].TargetSessionID)
		result[i].TargetUserID = cloneRiskHitInt(result[i].TargetUserID)
		result[i].TargetInstanceID = cloneRiskHitInt(result[i].TargetInstanceID)
		result[i].TargetGatewayID = cloneString(result[i].TargetGatewayID)
		result[i].TargetRuntimePodID = cloneRiskHitInt64(result[i].TargetRuntimePodID)
		result[i].TargetInvocationID = cloneRiskHitInt(result[i].TargetInvocationID)
		result[i].TargetModelID = cloneRiskHitInt(result[i].TargetModelID)
	}
	return result
}

func nilCostRecordProof(proof CostRecordSourceProofVerifier) bool {
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
