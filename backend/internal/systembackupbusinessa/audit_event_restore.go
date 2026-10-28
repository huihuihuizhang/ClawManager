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

// AuditEventRestoreSource covers the migration-028 audit_events row without
// carrying message or details text into A. B certifies their original values
// and the SQL NULL state of details against the sealed dump.
type AuditEventRestoreSource struct {
	ID             int
	TraceID        string
	SessionID      *string
	RequestID      *string
	UserID         *int
	InstanceID     *int
	InstanceMode   *string
	RuntimeType    *string
	GatewayID      *string
	RuntimePodID   *int64
	InvocationID   *int
	EventType      string
	TrafficClass   string
	Severity       string
	DetailsPresent bool
	CreatedAt      time.Time
}

type AuditEventRestoreMapping struct {
	SourceID           int
	TargetID           int
	TargetTraceID      string
	TargetSessionID    *string
	TargetUserID       *int
	TargetInstanceID   *int
	TargetGatewayID    *string
	TargetRuntimePodID *int64
	TargetInvocationID *int
}

// B owns source authentication, the common trace/session/invocation map,
// target occupancy and SQL write authority, including for an empty batch.
type AuditEventSourceProofVerifier interface {
	VerifyAuditEventSources(context.Context, string, string, string,
		[]AuditEventRestoreSource, []AuditEventRestoreMapping,
		[]ChatSessionRestoreMapping) error
}

var ErrAuditEventRestore = errors.New("A audit event restore normalization failed")

func NormalizeAuditEventsForRestore(ctx context.Context, scope *CaptureScope,
	sources []AuditEventRestoreSource, mappings []AuditEventRestoreMapping,
	sessions []ChatSessionRestoreMapping, evidenceRef string,
	proof AuditEventSourceProofVerifier) ([]models.AuditEvent, error) {
	if ctx == nil || ctx.Err() != nil || scope == nil || len(scope.tables) != len(tables) ||
		!hashPattern.MatchString(scope.registrySHA) || !hashPattern.MatchString(scope.schemaSHA) ||
		!evidencePattern.MatchString(evidenceRef) || len(sources) != len(mappings) {
		return nil, ErrAuditEventRestore
	}
	if nilAuditEventProof(proof) {
		return nil, ErrCaptureEvidenceIncomplete
	}
	projection := cloneAuditEventSources(sources)
	links := cloneAuditEventMappings(mappings)
	sessionLinks := cloneChatSessionMappings(sessions)
	sessionBySource := make(map[string]string, len(sessionLinks))
	for _, session := range sessionLinks {
		if session.SourceID <= 0 || session.TargetID <= 0 ||
			!validUserRestoreText(session.SourceSessionID, 100) ||
			!validUserRestoreText(session.TargetSessionID, 100) ||
			strings.EqualFold(session.SourceSessionID, session.TargetSessionID) {
			return nil, ErrAuditEventRestore
		}
		key := strings.ToLower(session.SourceSessionID)
		if _, duplicate := sessionBySource[key]; duplicate {
			return nil, ErrAuditEventRestore
		}
		sessionBySource[key] = session.TargetSessionID
	}
	sourceTraces := make(map[string]struct{}, len(projection))
	for _, source := range projection {
		if !validUserRestoreText(source.TraceID, 100) {
			return nil, ErrAuditEventRestore
		}
		sourceTraces[strings.ToLower(source.TraceID)] = struct{}{}
	}
	bySource := make(map[int]AuditEventRestoreMapping, len(links))
	targetIDs := make(map[int]struct{}, len(links))
	for _, mapping := range links {
		if mapping.SourceID <= 0 || mapping.SourceID > math.MaxInt32 ||
			mapping.TargetID <= 0 || mapping.TargetID > math.MaxInt32 ||
			!validUserRestoreText(mapping.TargetTraceID, 100) {
			return nil, ErrAuditEventRestore
		}
		if _, reused := sourceTraces[strings.ToLower(mapping.TargetTraceID)]; reused {
			return nil, ErrAuditEventRestore
		}
		if _, duplicate := bySource[mapping.SourceID]; duplicate {
			return nil, ErrAuditEventRestore
		}
		if _, duplicate := targetIDs[mapping.TargetID]; duplicate {
			return nil, ErrAuditEventRestore
		}
		bySource[mapping.SourceID] = mapping
		targetIDs[mapping.TargetID] = struct{}{}
	}
	rows := make([]models.AuditEvent, 0, len(projection))
	seenSources := make(map[int]struct{}, len(projection))
	users := make(map[int]int)
	instances := make(map[int]int)
	invocations := make(map[int]int)
	pods := make(map[int64]int64)
	gateways := make(map[string]string)
	traces := make(map[string]string)
	targetTraces := make(map[string]string)
	for _, source := range projection {
		mapping, found := bySource[source.ID]
		if !found {
			return nil, ErrAuditEventRestore
		}
		if _, duplicate := seenSources[source.ID]; duplicate ||
			!bindRiskHitInt(users, source.UserID, mapping.TargetUserID) ||
			!bindRiskHitInt(instances, source.InstanceID, mapping.TargetInstanceID) ||
			!bindRiskHitInt(invocations, source.InvocationID, mapping.TargetInvocationID) ||
			!bindRiskHitInt64(pods, source.RuntimePodID, mapping.TargetRuntimePodID) ||
			!bindRiskHitString(gateways, source.GatewayID, mapping.TargetGatewayID, 128) {
			return nil, ErrAuditEventRestore
		}
		if source.SessionID == nil {
			if mapping.TargetSessionID != nil {
				return nil, ErrAuditEventRestore
			}
		} else if target, found := sessionBySource[strings.ToLower(*source.SessionID)]; !found || mapping.TargetSessionID == nil || target != *mapping.TargetSessionID {
			return nil, ErrAuditEventRestore
		}
		traceKey := strings.ToLower(source.TraceID)
		if prior, found := traces[traceKey]; found && !strings.EqualFold(prior, mapping.TargetTraceID) {
			return nil, ErrAuditEventRestore
		}
		targetTraceKey := strings.ToLower(mapping.TargetTraceID)
		if prior, found := targetTraces[targetTraceKey]; found && prior != traceKey {
			return nil, ErrAuditEventRestore
		}
		traces[traceKey] = mapping.TargetTraceID
		targetTraces[targetTraceKey] = traceKey
		row, err := NormalizeAuditEventForRestore(source, mapping)
		if err != nil {
			return nil, err
		}
		seenSources[source.ID] = struct{}{}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	if err := proof.VerifyAuditEventSources(ctx, scope.registrySHA, scope.schemaSHA,
		evidenceRef, cloneAuditEventSources(projection), cloneAuditEventMappings(links),
		cloneChatSessionMappings(sessionLinks)); err != nil {
		return nil, fmt.Errorf("A audit event source proof: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return rows, nil
}

// Only NormalizeAuditEventsForRestore can produce rows after B's proof. This
// pure transform is also used to check a row before the batch proof runs.
func NormalizeAuditEventForRestore(source AuditEventRestoreSource,
	mapping AuditEventRestoreMapping) (models.AuditEvent, error) {
	created := source.CreatedAt.UTC().Truncate(time.Second)
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
		!bindRiskHitInt64(make(map[int64]int64), source.RuntimePodID, mapping.TargetRuntimePodID) ||
		!bindRiskHitString(make(map[string]string), source.GatewayID, mapping.TargetGatewayID, 128) ||
		!validEnterpriseAuthOptionalText(source.InstanceMode, 16) ||
		!validEnterpriseAuthOptionalText(source.RuntimeType, 32) ||
		!validUserRestoreText(source.EventType, 100) ||
		!validUserRestoreText(source.TrafficClass, 50) ||
		(source.Severity != models.AuditSeverityInfo &&
			source.Severity != models.AuditSeverityWarn &&
			source.Severity != models.AuditSeverityError) ||
		!validMySQLDateTime(created) {
		return models.AuditEvent{}, ErrAuditEventRestore
	}
	return models.AuditEvent{
		ID: mapping.TargetID, TraceID: mapping.TargetTraceID,
		SessionID: cloneString(mapping.TargetSessionID), RequestID: cloneString(source.RequestID),
		UserID: cloneRiskHitInt(mapping.TargetUserID), InstanceID: cloneRiskHitInt(mapping.TargetInstanceID),
		InstanceMode: cloneString(source.InstanceMode), RuntimeType: cloneString(source.RuntimeType),
		GatewayID: cloneString(mapping.TargetGatewayID), RuntimePodID: cloneRiskHitInt64(mapping.TargetRuntimePodID),
		InvocationID: cloneRiskHitInt(mapping.TargetInvocationID), EventType: source.EventType,
		TrafficClass: source.TrafficClass, Severity: source.Severity,
		Message: "[REDACTED]", Details: redactedNullable(source.DetailsPresent), CreatedAt: created,
	}, nil
}

func cloneAuditEventSources(sources []AuditEventRestoreSource) []AuditEventRestoreSource {
	result := append([]AuditEventRestoreSource(nil), sources...)
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
	}
	return result
}

func cloneAuditEventMappings(mappings []AuditEventRestoreMapping) []AuditEventRestoreMapping {
	result := append([]AuditEventRestoreMapping(nil), mappings...)
	for i := range result {
		result[i].TargetSessionID = cloneString(result[i].TargetSessionID)
		result[i].TargetUserID = cloneRiskHitInt(result[i].TargetUserID)
		result[i].TargetInstanceID = cloneRiskHitInt(result[i].TargetInstanceID)
		result[i].TargetGatewayID = cloneString(result[i].TargetGatewayID)
		result[i].TargetRuntimePodID = cloneRiskHitInt64(result[i].TargetRuntimePodID)
		result[i].TargetInvocationID = cloneRiskHitInt(result[i].TargetInvocationID)
	}
	return result
}

func nilAuditEventProof(proof AuditEventSourceProofVerifier) bool {
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
