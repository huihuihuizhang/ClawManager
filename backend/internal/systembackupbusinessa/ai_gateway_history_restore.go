package systembackupbusinessa

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"clawreef/internal/models"
)

// AIGatewayHistorySourceProofVerifier belongs to B. It must authenticate all
// input rows and dependency mappings against one sealed dump, one checkpoint,
// the registered evidence, and the isolated target's occupancy and write
// authority. Individual table proofs below remain required as well.
type AIGatewayHistorySourceProofVerifier interface {
	VerifyAIGatewayHistorySources(context.Context, string, string, string,
		AIGatewayRestoreMappingSet, []RiskRuleRestoreMapping) error
}

type AIGatewayHistoryProofs struct {
	Batch       AIGatewayHistorySourceProofVerifier
	Sessions    ChatSessionSourceProofVerifier
	Invocations ModelInvocationSourceProofVerifier
	Audits      AuditEventSourceProofVerifier
	Costs       CostRecordSourceProofVerifier
	RiskHits    RiskHitSourceProofVerifier
	Messages    ChatMessageSourceProofVerifier
}

// AIGatewayHistoryRows are returned only when the common proof, every table
// proof, all normalizers and the cross-table check succeed. These rows are not
// a restore authorization or a write result; B owns the isolated SQL write.
type AIGatewayHistoryRows struct {
	Sessions    []models.ChatSession
	Invocations []models.ModelInvocation
	Audits      []models.AuditEvent
	Costs       []NormalizedCostRecord
	RiskHits    []models.RiskHit
	Messages    []models.ChatMessageRecord
}

var ErrAIGatewayHistoryRestore = errors.New("A gateway history restore normalization failed")

func NormalizeAIGatewayHistoryForRestore(ctx context.Context, scope *CaptureScope,
	set AIGatewayRestoreMappingSet, rules []RiskRuleRestoreMapping,
	evidenceRef string, proofs AIGatewayHistoryProofs) (AIGatewayHistoryRows, error) {
	var empty AIGatewayHistoryRows
	if ctx == nil || ctx.Err() != nil || scope == nil || len(scope.tables) != len(tables) ||
		!hashPattern.MatchString(scope.registrySHA) || !hashPattern.MatchString(scope.schemaSHA) ||
		!evidencePattern.MatchString(evidenceRef) {
		return empty, ErrAIGatewayHistoryRestore
	}
	if nilAIGatewayHistoryProof(proofs.Batch) {
		return empty, ErrCaptureEvidenceIncomplete
	}
	snapshot := cloneAIGatewayMappingSet(set)
	ruleSnapshot := append([]RiskRuleRestoreMapping(nil), rules...)
	if err := CheckAIGatewayRestoreMappingConsistency(snapshot); err != nil {
		return empty, err
	}
	if err := proofs.Batch.VerifyAIGatewayHistorySources(ctx, scope.registrySHA,
		scope.schemaSHA, evidenceRef, cloneAIGatewayMappingSet(snapshot),
		append([]RiskRuleRestoreMapping(nil), ruleSnapshot...)); err != nil {
		return empty, fmt.Errorf("A gateway history source proof: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	var rows AIGatewayHistoryRows
	var err error
	rows.Sessions, err = NormalizeChatSessionsForRestore(ctx, scope,
		snapshot.SessionSources, snapshot.Sessions, evidenceRef, proofs.Sessions)
	if err != nil {
		return empty, err
	}
	rows.Invocations, err = NormalizeModelInvocationsForRestore(ctx, scope,
		snapshot.InvocationSources, snapshot.Invocations, snapshot.Sessions, evidenceRef, proofs.Invocations)
	if err != nil {
		return empty, err
	}
	rows.Audits, err = NormalizeAuditEventsForRestore(ctx, scope,
		snapshot.AuditSources, snapshot.Audits, snapshot.Sessions, evidenceRef, proofs.Audits)
	if err != nil {
		return empty, err
	}
	rows.Costs, err = NormalizeCostRecordsForRestore(ctx, scope,
		snapshot.CostSources, snapshot.Costs, snapshot.Sessions, evidenceRef, proofs.Costs)
	if err != nil {
		return empty, err
	}
	rows.RiskHits, err = NormalizeRiskHitsForRestore(ctx, scope,
		snapshot.RiskHitSources, snapshot.RiskHits, ruleSnapshot, evidenceRef, proofs.RiskHits)
	if err != nil {
		return empty, err
	}
	rows.Messages, err = NormalizeChatMessagesForRestore(ctx, scope,
		snapshot.ChatMessageSources, snapshot.ChatMessages, snapshot.Sessions, evidenceRef, proofs.Messages)
	if err != nil {
		return empty, err
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	return rows, nil
}

func cloneAIGatewayMappingSet(set AIGatewayRestoreMappingSet) AIGatewayRestoreMappingSet {
	return AIGatewayRestoreMappingSet{
		Users:              append([]UserRestoreMapping(nil), set.Users...),
		Models:             append([]LLMModelRestoreMapping(nil), set.Models...),
		SessionSources:     cloneChatSessionSources(set.SessionSources),
		Sessions:           cloneChatSessionMappings(set.Sessions),
		InvocationSources:  cloneModelInvocationSources(set.InvocationSources),
		Invocations:        cloneModelInvocationMappings(set.Invocations),
		AuditSources:       cloneAuditEventSources(set.AuditSources),
		Audits:             cloneAuditEventMappings(set.Audits),
		CostSources:        cloneCostRecordSources(set.CostSources),
		Costs:              cloneCostRecordMappings(set.Costs),
		RiskHitSources:     cloneRiskHitSources(set.RiskHitSources),
		RiskHits:           cloneRiskHitMappings(set.RiskHits),
		ChatMessageSources: cloneChatMessageSources(set.ChatMessageSources),
		ChatMessages:       cloneChatMessageMappings(set.ChatMessages),
	}
}

func nilAIGatewayHistoryProof(proof AIGatewayHistorySourceProofVerifier) bool {
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
