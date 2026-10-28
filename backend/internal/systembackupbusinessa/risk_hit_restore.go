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

// RiskHitRestoreSource covers every migration-028 risk_hits SQL column. The
// source summary is confidential and is never copied into a target row.
type RiskHitRestoreSource struct {
	ID           int
	TraceID      string
	SessionID    *string
	RequestID    *string
	UserID       *int
	InstanceID   *int
	InstanceMode *string
	RuntimeType  *string
	GatewayID    *string
	RuntimePodID *int64
	InvocationID *int
	RuleID       string
	RuleName     string
	Severity     string
	Action       string
	MatchSummary string
	CreatedAt    time.Time
}

// Each non-null target reference must be certified against its owner table by
// B. SQL-null source references stay null; a mapping cannot invent a link.
type RiskHitRestoreMapping struct {
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

// RiskHitSourceProofVerifier belongs to B. It authenticates the source dump,
// mappings to users/instances/runtime pods/model invocations/chat sessions,
// the shared trace and risk-rule maps, target occupancy and write authority.
type RiskHitSourceProofVerifier interface {
	VerifyRiskHitSources(context.Context, string, string, string,
		[]RiskHitRestoreSource, []RiskHitRestoreMapping, []RiskRuleRestoreMapping) error
}

var ErrRiskHitRestore = errors.New("A risk hit restore normalization failed")

// NormalizeRiskHitsForRestore emits complete historical rows with a fixed
// redacted summary, or no rows on any validation or proof failure. B still owns
// the SQL write and independent proof of every target reference.
func NormalizeRiskHitsForRestore(ctx context.Context, scope *CaptureScope,
	sources []RiskHitRestoreSource, mappings []RiskHitRestoreMapping,
	rules []RiskRuleRestoreMapping, evidenceRef string,
	proof RiskHitSourceProofVerifier) ([]models.RiskHit, error) {
	if ctx == nil || ctx.Err() != nil || scope == nil || len(scope.tables) != len(tables) ||
		!hashPattern.MatchString(scope.registrySHA) || !hashPattern.MatchString(scope.schemaSHA) ||
		!evidencePattern.MatchString(evidenceRef) || len(sources) != len(mappings) {
		return nil, ErrRiskHitRestore
	}
	if nilRiskHitProof(proof) {
		return nil, ErrCaptureEvidenceIncomplete
	}
	projection := cloneRiskHitSources(sources)
	links := cloneRiskHitMappings(mappings)
	sourceTraces := make(map[string]struct{}, len(projection))
	for _, source := range projection {
		if !validUserRestoreText(source.TraceID, 100) {
			return nil, ErrRiskHitRestore
		}
		sourceTraces[strings.ToLower(source.TraceID)] = struct{}{}
	}
	ruleLinks := append([]RiskRuleRestoreMapping(nil), rules...)
	ruleBySource := make(map[string]string, len(ruleLinks))
	for _, rule := range ruleLinks {
		if rule.SourceID <= 0 || rule.TargetID <= 0 ||
			!validUserRestoreText(rule.SourceRuleID, 100) ||
			!validUserRestoreText(rule.TargetRuleID, 100) {
			return nil, ErrRiskHitRestore
		}
		key := strings.ToLower(rule.SourceRuleID)
		if _, duplicate := ruleBySource[key]; duplicate {
			return nil, ErrRiskHitRestore
		}
		ruleBySource[key] = rule.TargetRuleID
	}
	bySource := make(map[int]RiskHitRestoreMapping, len(links))
	targetIDs := make(map[int]struct{}, len(links))
	for _, mapping := range links {
		if mapping.SourceID <= 0 || mapping.SourceID > math.MaxInt32 ||
			mapping.TargetID <= 0 || mapping.TargetID > math.MaxInt32 ||
			!validUserRestoreText(mapping.TargetTraceID, 100) {
			return nil, ErrRiskHitRestore
		}
		if _, sourceIdentifier := sourceTraces[strings.ToLower(mapping.TargetTraceID)]; sourceIdentifier {
			return nil, ErrRiskHitRestore
		}
		if _, duplicate := bySource[mapping.SourceID]; duplicate {
			return nil, ErrRiskHitRestore
		}
		if _, duplicate := targetIDs[mapping.TargetID]; duplicate {
			return nil, ErrRiskHitRestore
		}
		bySource[mapping.SourceID] = mapping
		targetIDs[mapping.TargetID] = struct{}{}
	}
	rows := make([]models.RiskHit, 0, len(projection))
	seenSources := make(map[int]struct{}, len(projection))
	users := make(map[int]int)
	instances := make(map[int]int)
	invocations := make(map[int]int)
	pods := make(map[int64]int64)
	sessions := make(map[string]string)
	gateways := make(map[string]string)
	traces := make(map[string]string)
	targetTraces := make(map[string]string)
	for _, source := range projection {
		mapping, found := bySource[source.ID]
		if !found {
			return nil, ErrRiskHitRestore
		}
		if _, duplicate := seenSources[source.ID]; duplicate {
			return nil, ErrRiskHitRestore
		}
		targetRuleID, found := ruleBySource[strings.ToLower(source.RuleID)]
		if !found || !bindRiskHitInt(users, source.UserID, mapping.TargetUserID) ||
			!bindRiskHitInt(instances, source.InstanceID, mapping.TargetInstanceID) ||
			!bindRiskHitInt(invocations, source.InvocationID, mapping.TargetInvocationID) ||
			!bindRiskHitInt64(pods, source.RuntimePodID, mapping.TargetRuntimePodID) ||
			!bindRiskHitString(sessions, source.SessionID, mapping.TargetSessionID, 100) ||
			!bindRiskHitString(gateways, source.GatewayID, mapping.TargetGatewayID, 128) {
			return nil, ErrRiskHitRestore
		}
		traceKey := strings.ToLower(source.TraceID)
		if prior, found := traces[traceKey]; found && !strings.EqualFold(prior, mapping.TargetTraceID) {
			return nil, ErrRiskHitRestore
		}
		targetTraceKey := strings.ToLower(mapping.TargetTraceID)
		if prior, found := targetTraces[targetTraceKey]; found && prior != traceKey {
			return nil, ErrRiskHitRestore
		}
		traces[traceKey] = mapping.TargetTraceID
		targetTraces[targetTraceKey] = traceKey
		row, err := NormalizeRiskHitForRestore(source, mapping, targetRuleID)
		if err != nil {
			return nil, err
		}
		seenSources[source.ID] = struct{}{}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	if err := proof.VerifyRiskHitSources(ctx, scope.registrySHA, scope.schemaSHA,
		evidenceRef, cloneRiskHitSources(projection), cloneRiskHitMappings(links),
		append([]RiskRuleRestoreMapping(nil), ruleLinks...)); err != nil {
		return nil, fmt.Errorf("A risk hit source proof: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return rows, nil
}

// NormalizeRiskHitForRestore is only a pure row transform; its mappings are
// authorized by the batch proof, not by this function.
func NormalizeRiskHitForRestore(source RiskHitRestoreSource,
	mapping RiskHitRestoreMapping, targetRuleID string) (models.RiskHit, error) {
	created := source.CreatedAt.UTC().Truncate(time.Second)
	if source.ID <= 0 || source.ID > math.MaxInt32 || mapping.SourceID != source.ID ||
		mapping.TargetID <= 0 || mapping.TargetID > math.MaxInt32 ||
		!validUserRestoreText(source.TraceID, 100) ||
		!validUserRestoreText(mapping.TargetTraceID, 100) ||
		strings.EqualFold(source.TraceID, mapping.TargetTraceID) ||
		!validOptionalRestoreText(source.SessionID, 100) ||
		!validOptionalRestoreText(source.RequestID, 100) ||
		!validEnterpriseAuthOptionalText(source.InstanceMode, 16) ||
		!validEnterpriseAuthOptionalText(source.RuntimeType, 32) ||
		!validUserRestoreText(source.RuleID, 100) ||
		!validUserRestoreText(targetRuleID, 100) ||
		!validUserRestoreText(source.RuleName, 255) ||
		!validEnterpriseAuthText(source.MatchSummary, 500) ||
		(source.Severity != models.RiskSeverityLow &&
			source.Severity != models.RiskSeverityMedium &&
			source.Severity != models.RiskSeverityHigh) ||
		(source.Action != models.RiskActionAllow &&
			source.Action != models.RiskActionRouteSecureModel &&
			source.Action != models.RiskActionBlock && source.Action != "require_approval") ||
		!validMySQLDateTime(created) ||
		!bindRiskHitInt(make(map[int]int), source.UserID, mapping.TargetUserID) ||
		!bindRiskHitInt(make(map[int]int), source.InstanceID, mapping.TargetInstanceID) ||
		!bindRiskHitInt(make(map[int]int), source.InvocationID, mapping.TargetInvocationID) ||
		!bindRiskHitInt64(make(map[int64]int64), source.RuntimePodID, mapping.TargetRuntimePodID) ||
		!bindRiskHitString(make(map[string]string), source.SessionID, mapping.TargetSessionID, 100) ||
		!bindRiskHitString(make(map[string]string), source.GatewayID, mapping.TargetGatewayID, 128) {
		return models.RiskHit{}, ErrRiskHitRestore
	}
	return models.RiskHit{
		ID: mapping.TargetID, TraceID: mapping.TargetTraceID,
		SessionID: cloneString(mapping.TargetSessionID), RequestID: cloneString(source.RequestID),
		UserID: cloneRiskHitInt(mapping.TargetUserID), InstanceID: cloneRiskHitInt(mapping.TargetInstanceID),
		InstanceMode: cloneString(source.InstanceMode), RuntimeType: cloneString(source.RuntimeType),
		GatewayID: cloneString(mapping.TargetGatewayID), RuntimePodID: cloneRiskHitInt64(mapping.TargetRuntimePodID),
		InvocationID: cloneRiskHitInt(mapping.TargetInvocationID),
		RuleID:       targetRuleID, RuleName: source.RuleName,
		Severity: source.Severity, Action: source.Action,
		MatchSummary: "[REDACTED]", CreatedAt: created,
	}, nil
}

func bindRiskHitInt(links map[int]int, source, target *int) bool {
	if source == nil || target == nil {
		return source == nil && target == nil
	}
	if *source <= 0 || *source > math.MaxInt32 || *target <= 0 || *target > math.MaxInt32 {
		return false
	}
	if prior, found := links[*source]; found && prior != *target {
		return false
	}
	links[*source] = *target
	return true
}

func bindRiskHitInt64(links map[int64]int64, source, target *int64) bool {
	if source == nil || target == nil {
		return source == nil && target == nil
	}
	if *source <= 0 || *target <= 0 {
		return false
	}
	if prior, found := links[*source]; found && prior != *target {
		return false
	}
	links[*source] = *target
	return true
}

func bindRiskHitString(links map[string]string, source, target *string, max int) bool {
	if source == nil || target == nil {
		return source == nil && target == nil
	}
	if !validUserRestoreText(*source, max) || !validUserRestoreText(*target, max) {
		return false
	}
	key := strings.ToLower(*source)
	if prior, found := links[key]; found && !strings.EqualFold(prior, *target) {
		return false
	}
	links[key] = *target
	return true
}

func validEnterpriseAuthOptionalText(value *string, max int) bool {
	return value == nil || validEnterpriseAuthText(*value, max)
}

func cloneRiskHitSources(sources []RiskHitRestoreSource) []RiskHitRestoreSource {
	result := append([]RiskHitRestoreSource(nil), sources...)
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

func cloneRiskHitMappings(mappings []RiskHitRestoreMapping) []RiskHitRestoreMapping {
	result := append([]RiskHitRestoreMapping(nil), mappings...)
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

func cloneRiskHitInt(value *int) *int {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneRiskHitInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func nilRiskHitProof(proof RiskHitSourceProofVerifier) bool {
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
