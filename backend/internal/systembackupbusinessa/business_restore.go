package systembackupbusinessa

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"clawreef/internal/models"
)

// BusinessRestoreBinding identifies one authenticated dump and one isolated
// target. TargetIdentitySHA256 and TargetNow must be supplied and authenticated
// by B's target authority, never inferred from a restore request or local clock.
type BusinessRestoreBinding struct {
	Dump                 CaptureEvidence
	TargetIdentitySHA256 string
	TargetNow            time.Time
}

// BusinessRestoreInput contains all fifteen A-owned projections. Gateway.Users
// and Gateway.Models are the single identity maps for both dependency rows and
// gateway history. Instances is B's common instance map, including instances
// referenced by history even when they have no token alias.
type BusinessRestoreInput struct {
	Users              []UserRestoreSource
	Quotas             []UserQuotaRestoreSource
	QuotaMappings      []UserQuotaRestoreMapping
	QuotaCapacities    map[int]UserQuotaCapacity
	EnterpriseAuth     []EnterpriseAuthRestoreSource
	EnterpriseMappings []EnterpriseAuthRestoreMapping
	Challenges         []NorthboundChallengeRestoreSource
	ChallengeMappings  []NorthboundChallengeRestoreMapping
	NorthboundSessions []NorthboundSessionRestoreSource
	NorthboundMappings []NorthboundSessionRestoreMapping
	CallerPolicies     []NorthboundCallerPolicyRestoreSource
	Models             []LLMModelRestoreSource
	Rules              []RiskRuleRestoreSource
	RuleMappings       []RiskRuleRestoreMapping
	Aliases            []GatewayAliasRestoreSource
	AliasMappings      []GatewayAliasRestoreMapping
	Instances          []GatewayAliasInstanceMapping
	Gateway            AIGatewayRestoreMappingSet
}

// BusinessRestoreSourceProofVerifier belongs to B. The initial check must
// authenticate the complete projections (including empty tables), mappings,
// capacities, exact Secret/ref versions, sealed dump/checkpoint/evidence and
// isolated target identity, clock, occupancy, startup fence and write authority.
// The final check must revalidate that same binding and current authority.
// A only returns candidate rows; B must guard its actual SQL transaction again.
type BusinessRestoreSourceProofVerifier interface {
	VerifyBusinessRestoreSources(context.Context, BusinessRestoreBinding, BusinessRestoreInput) error
	RecheckBusinessRestoreSources(context.Context, BusinessRestoreBinding, BusinessRestoreInput) error
}

type BusinessRestoreProofs struct {
	Batch          BusinessRestoreSourceProofVerifier
	EnterpriseAuth EnterpriseAuthSourceProofVerifier
	Models         LLMModelSourceProofVerifier
	Rules          RiskRuleSourceProofVerifier
	Aliases        GatewayAliasRestoreProofVerifier
	Gateway        AIGatewayHistoryProofs
}

// BusinessRestoreRows is one complete candidate batch. It contains no success,
// eligibility or SQL-commit claim. Callers must not log its credential hashes
// or feed it into a production database.
type BusinessRestoreRows struct {
	Users              []models.User
	Quotas             []NormalizedUserQuota
	EnterpriseAuth     []models.EnterpriseAuthSetting
	Challenges         []models.NorthboundAuthChallenge
	NorthboundSessions []models.NorthboundSession
	CallerPolicies     []models.NorthboundCallerPolicy
	Models             []NormalizedLLMModel
	Rules              []models.RiskRule
	Aliases            []NormalizedGatewayAlias
	Gateway            AIGatewayHistoryRows
}

var ErrBusinessRestore = errors.New("A business restore batch invalid")

// NormalizeBusinessForRestore freezes all caller input before consulting proof
// adapters, closes cross-table dependencies, and returns nothing unless all
// fifteen normalizers and the final B authority check succeed.
func NormalizeBusinessForRestore(ctx context.Context, scope *CaptureScope,
	binding BusinessRestoreBinding, input BusinessRestoreInput,
	proofs BusinessRestoreProofs) (BusinessRestoreRows, error) {
	var empty BusinessRestoreRows
	if ctx == nil || scope == nil || len(scope.tables) != len(tables) {
		return empty, ErrBusinessRestore
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	binding = cloneBusinessRestoreBinding(binding)
	snapshot := cloneBusinessRestoreInput(input)
	if err := validateBusinessRestoreBinding(scope, binding, snapshot); err != nil {
		return empty, err
	}
	if err := CheckAIGatewayRestoreMappingConsistency(snapshot.Gateway); err != nil {
		return empty, err
	}
	if err := checkBusinessRestoreInstances(snapshot); err != nil {
		return empty, err
	}
	for _, proof := range []any{proofs.Batch, proofs.EnterpriseAuth, proofs.Models,
		proofs.Rules, proofs.Aliases, proofs.Gateway.Batch, proofs.Gateway.Sessions,
		proofs.Gateway.Invocations, proofs.Gateway.Audits, proofs.Gateway.Costs,
		proofs.Gateway.RiskHits, proofs.Gateway.Messages} {
		if nilBusinessRestoreProof(proof) {
			return empty, ErrCaptureEvidenceIncomplete
		}
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if err := proofs.Batch.VerifyBusinessRestoreSources(ctx,
		cloneBusinessRestoreBinding(binding), cloneBusinessRestoreInput(snapshot)); err != nil {
		return empty, fmt.Errorf("A business restore source proof: %w", err)
	}
	var rows BusinessRestoreRows
	var users *UserRestoreBatch
	var err error
	evidence := binding.Dump.EvidenceRef
	steps := []func() error{
		func() error {
			users, err = NormalizeUsersForRestore(snapshot.Users, snapshot.Gateway.Users)
			if err == nil {
				rows.Users = users.Rows()
			}
			return err
		},
		func() error {
			rows.Quotas, err = NormalizeUserQuotasForRestore(users, snapshot.Quotas,
				snapshot.QuotaMappings, snapshot.QuotaCapacities)
			return err
		},
		func() error {
			rows.EnterpriseAuth, err = NormalizeEnterpriseAuthSettingsForRestore(ctx, scope,
				users, snapshot.EnterpriseAuth, snapshot.EnterpriseMappings, evidence, proofs.EnterpriseAuth)
			return err
		},
		func() error {
			rows.Challenges, err = NormalizeNorthboundChallengesForRestore(snapshot.Challenges,
				snapshot.ChallengeMappings, binding.TargetNow)
			return err
		},
		func() error {
			rows.NorthboundSessions, err = NormalizeNorthboundSessionsForRestore(users,
				snapshot.NorthboundSessions, snapshot.NorthboundMappings, binding.TargetNow)
			return err
		},
		func() error {
			rows.CallerPolicies, err = NormalizeNorthboundCallerPoliciesForRestore(users, snapshot.CallerPolicies)
			return err
		},
		func() error {
			rows.Models, err = NormalizeLLMModelsForRestore(ctx, scope, snapshot.Models,
				snapshot.Gateway.Models, evidence, proofs.Models)
			return err
		},
		func() error {
			rows.Rules, err = NormalizeRiskRulesForRestore(ctx, scope, snapshot.Rules,
				snapshot.RuleMappings, evidence, proofs.Rules)
			return err
		},
		func() error {
			rows.Aliases, err = NormalizeGatewayAliasesForRestore(ctx, scope, snapshot.Aliases,
				snapshot.AliasMappings, snapshot.Instances, binding.TargetNow, evidence, proofs.Aliases)
			return err
		},
		func() error {
			rows.Gateway, err = NormalizeAIGatewayHistoryForRestore(ctx, scope, snapshot.Gateway,
				snapshot.RuleMappings, evidence, proofs.Gateway)
			return err
		},
	}
	for _, step := range steps {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		if err := step(); err != nil {
			return empty, err
		}
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	costHash, err := normalizedCostAggregateHash(rows.Gateway.Costs)
	if err != nil {
		return empty, ErrRestoreNormalizationMismatch
	}
	if costHash != binding.Dump.Snapshot.CostAggregateSHA256 {
		return empty, ErrRestoreNormalizationMismatch
	}
	if err := proofs.Batch.RecheckBusinessRestoreSources(ctx,
		cloneBusinessRestoreBinding(binding), cloneBusinessRestoreInput(snapshot)); err != nil {
		return empty, fmt.Errorf("A business restore final proof: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	return rows, nil
}

func businessRestoreSourceCounts(input BusinessRestoreInput) map[string]int {
	return map[string]int{
		"users": len(input.Users), "user_quotas": len(input.Quotas),
		"enterprise_auth_settings":   len(input.EnterpriseAuth),
		"northbound_auth_challenges": len(input.Challenges),
		"northbound_sessions":        len(input.NorthboundSessions),
		"northbound_caller_policies": len(input.CallerPolicies),
		"llm_models":                 len(input.Models), "risk_rules": len(input.Rules),
		"instance_gateway_token_aliases": len(input.Aliases),
		"chat_sessions":                  len(input.Gateway.SessionSources),
		"model_invocations":              len(input.Gateway.InvocationSources),
		"audit_events":                   len(input.Gateway.AuditSources),
		"cost_records":                   len(input.Gateway.CostSources),
		"risk_hits":                      len(input.Gateway.RiskHitSources),
		"chat_messages":                  len(input.Gateway.ChatMessageSources),
	}
}

func validateBusinessRestoreBinding(scope *CaptureScope, binding BusinessRestoreBinding,
	input BusinessRestoreInput) error {
	dump := binding.Dump
	if !hashPattern.MatchString(scope.registrySHA) || !hashPattern.MatchString(scope.schemaSHA) ||
		dump.RegistrySHA256 != scope.registrySHA || dump.SchemaSHA256 != scope.schemaSHA ||
		!hashPattern.MatchString(dump.CheckpointHash) || !hashPattern.MatchString(dump.CaptureContextHash) ||
		!evidencePattern.MatchString(dump.EvidenceRef) ||
		!hashPattern.MatchString(binding.TargetIdentitySHA256) || !validMySQLDateTime(binding.TargetNow) {
		return ErrBusinessRestore
	}
	if err := validateSnapshot(dump.Snapshot, scope.tables); err != nil {
		return err
	}
	counts := businessRestoreSourceCounts(input)
	for _, table := range dump.Snapshot.Tables {
		if table.Rows != int64(counts[table.Table]) {
			return ErrSnapshotMismatch
		}
	}
	return nil
}

func checkBusinessRestoreInstances(input BusinessRestoreInput) error {
	instances, err := indexGatewayMappings(input.Instances,
		func(m GatewayAliasInstanceMapping) (int, int) { return m.SourceID, m.TargetID })
	if err != nil {
		return err
	}
	ids := make(map[int]int, len(instances))
	for source, mapping := range instances {
		ids[source] = mapping.TargetID
	}
	set := input.Gateway
	// The existing cross-table check has already closed each source-row map.
	// Match every optional history instance to B's canonical instance mapping.
	check := func(source, target *int) error {
		if !matchGatewayIntRef(source, target, ids) {
			return ErrAIGatewayCrossTableRestore
		}
		return nil
	}
	for _, pair := range []struct {
		sources map[int]*int
		targets map[int]*int
	}{
		{businessInstanceRefs(set.SessionSources, func(s ChatSessionRestoreSource) (int, *int) { return s.ID, s.InstanceID }),
			businessInstanceRefs(set.Sessions, func(m ChatSessionRestoreMapping) (int, *int) { return m.SourceID, m.TargetInstanceID })},
		{businessInstanceRefs(set.InvocationSources, func(s ModelInvocationRestoreSource) (int, *int) { return s.ID, s.InstanceID }),
			businessInstanceRefs(set.Invocations, func(m ModelInvocationRestoreMapping) (int, *int) { return m.SourceID, m.TargetInstanceID })},
		{businessInstanceRefs(set.AuditSources, func(s AuditEventRestoreSource) (int, *int) { return s.ID, s.InstanceID }),
			businessInstanceRefs(set.Audits, func(m AuditEventRestoreMapping) (int, *int) { return m.SourceID, m.TargetInstanceID })},
		{businessInstanceRefs(set.CostSources, func(s CostRecordRestoreSource) (int, *int) { return s.ID, s.InstanceID }),
			businessInstanceRefs(set.Costs, func(m CostRecordRestoreMapping) (int, *int) { return m.SourceID, m.TargetInstanceID })},
		{businessInstanceRefs(set.RiskHitSources, func(s RiskHitRestoreSource) (int, *int) { return s.ID, s.InstanceID }),
			businessInstanceRefs(set.RiskHits, func(m RiskHitRestoreMapping) (int, *int) { return m.SourceID, m.TargetInstanceID })},
		{businessInstanceRefs(set.ChatMessageSources, func(s ChatMessageRestoreSource) (int, *int) { return s.ID, s.InstanceID }),
			businessInstanceRefs(set.ChatMessages, func(m ChatMessageRestoreMapping) (int, *int) { return m.SourceID, m.TargetInstanceID })},
	} {
		for id, source := range pair.sources {
			if err := check(source, pair.targets[id]); err != nil {
				return err
			}
		}
	}
	return nil
}

func businessInstanceRefs[T any](items []T, refs func(T) (int, *int)) map[int]*int {
	result := make(map[int]*int, len(items))
	for _, item := range items {
		id, instance := refs(item)
		result[id] = instance
	}
	return result
}

func cloneBusinessRestoreBinding(binding BusinessRestoreBinding) BusinessRestoreBinding {
	binding.Dump.Snapshot = cloneSourceSnapshot(binding.Dump.Snapshot)
	return binding
}

func cloneBusinessRestoreInput(input BusinessRestoreInput) BusinessRestoreInput {
	input.Users = append([]UserRestoreSource(nil), input.Users...)
	input.Quotas = append([]UserQuotaRestoreSource(nil), input.Quotas...)
	for i := range input.Quotas {
		source := &input.Quotas[i]
		source.MaxInstances = cloneRiskHitInt(source.MaxInstances)
		source.MaxMemoryGB = cloneRiskHitInt(source.MaxMemoryGB)
		source.MaxStorageGB = cloneRiskHitInt(source.MaxStorageGB)
		source.MaxGPUCount = cloneRiskHitInt(source.MaxGPUCount)
	}
	input.QuotaMappings = append([]UserQuotaRestoreMapping(nil), input.QuotaMappings...)
	capacities := make(map[int]UserQuotaCapacity, len(input.QuotaCapacities))
	for user, capacity := range input.QuotaCapacities {
		capacities[user] = capacity
	}
	input.QuotaCapacities = capacities
	input.EnterpriseAuth = cloneEnterpriseAuthSources(input.EnterpriseAuth)
	input.EnterpriseMappings = append([]EnterpriseAuthRestoreMapping(nil), input.EnterpriseMappings...)
	input.Challenges = append([]NorthboundChallengeRestoreSource(nil), input.Challenges...)
	input.ChallengeMappings = append([]NorthboundChallengeRestoreMapping(nil), input.ChallengeMappings...)
	input.NorthboundSessions = append([]NorthboundSessionRestoreSource(nil), input.NorthboundSessions...)
	for i := range input.NorthboundSessions {
		source := &input.NorthboundSessions[i]
		source.PreviousRefreshTokenHash = cloneString(source.PreviousRefreshTokenHash)
		source.LastUsedAt = cloneTime(source.LastUsedAt)
		source.LastIP = cloneString(source.LastIP)
		source.UserAgent = cloneString(source.UserAgent)
		source.RevokedAt = cloneTime(source.RevokedAt)
	}
	input.NorthboundMappings = append([]NorthboundSessionRestoreMapping(nil), input.NorthboundMappings...)
	input.CallerPolicies = append([]NorthboundCallerPolicyRestoreSource(nil), input.CallerPolicies...)
	for i := range input.CallerPolicies {
		input.CallerPolicies[i].UpdatedBy = cloneRiskHitInt(input.CallerPolicies[i].UpdatedBy)
	}
	input.Models = cloneLLMModelSources(input.Models)
	input.Rules = cloneRiskRuleSources(input.Rules)
	input.RuleMappings = append([]RiskRuleRestoreMapping(nil), input.RuleMappings...)
	input.Aliases = cloneGatewayAliasSources(input.Aliases)
	input.AliasMappings = append([]GatewayAliasRestoreMapping(nil), input.AliasMappings...)
	input.Instances = append([]GatewayAliasInstanceMapping(nil), input.Instances...)
	input.Gateway = cloneAIGatewayMappingSet(input.Gateway)
	return input
}

func nilBusinessRestoreProof(proof any) bool {
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
