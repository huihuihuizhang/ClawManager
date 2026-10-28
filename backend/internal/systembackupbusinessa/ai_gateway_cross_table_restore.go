package systembackupbusinessa

import (
	"errors"
	"math"
	"strings"
)

// AIGatewayRestoreMappingSet is the common mapping input for A-owned gateway
// history. It is checked after each table's B-authenticated normalizer and
// before B writes any target rows. This value does not itself authenticate a
// dump, establish target occupancy or grant restore-write authority.
type AIGatewayRestoreMappingSet struct {
	Users              []UserRestoreMapping
	Models             []LLMModelRestoreMapping
	SessionSources     []ChatSessionRestoreSource
	Sessions           []ChatSessionRestoreMapping
	InvocationSources  []ModelInvocationRestoreSource
	Invocations        []ModelInvocationRestoreMapping
	AuditSources       []AuditEventRestoreSource
	Audits             []AuditEventRestoreMapping
	CostSources        []CostRecordRestoreSource
	Costs              []CostRecordRestoreMapping
	RiskHitSources     []RiskHitRestoreSource
	RiskHits           []RiskHitRestoreMapping
	ChatMessageSources []ChatMessageRestoreSource
	ChatMessages       []ChatMessageRestoreMapping
}

var ErrAIGatewayCrossTableRestore = errors.New("A gateway cross-table restore mapping inconsistent")

type gatewayHistoryLink struct {
	sourceTrace, targetTrace           string
	sourceSession, targetSession       *string
	sourceUser, targetUser             *int
	sourceInstance, targetInstance     *int
	sourceGateway, targetGateway       *string
	sourcePod, targetPod               *int64
	sourceInvocation, targetInvocation *int
	sourceModel, targetModel           *int
	deriveSession                      bool
}

func indexGatewayMappings[M any](items []M, ids func(M) (int, int)) (map[int]M, error) {
	bySource := make(map[int]M, len(items))
	targets := make(map[int]struct{}, len(items))
	for _, item := range items {
		source, target := ids(item)
		if source <= 0 || source > math.MaxInt32 || target <= 0 || target > math.MaxInt32 {
			return nil, ErrAIGatewayCrossTableRestore
		}
		if _, duplicate := bySource[source]; duplicate {
			return nil, ErrAIGatewayCrossTableRestore
		}
		if _, duplicate := targets[target]; duplicate {
			return nil, ErrAIGatewayCrossTableRestore
		}
		bySource[source] = item
		targets[target] = struct{}{}
	}
	return bySource, nil
}

func appendGatewayLinks[S, M any](rows *[]gatewayHistoryLink, sources []S, mappings []M,
	sourceID func(S) int, mappingIDs func(M) (int, int),
	link func(S, M) gatewayHistoryLink) error {
	if len(sources) != len(mappings) {
		return ErrAIGatewayCrossTableRestore
	}
	bySource, err := indexGatewayMappings(mappings, mappingIDs)
	if err != nil {
		return err
	}
	seen := make(map[int]struct{}, len(sources))
	for _, source := range sources {
		id := sourceID(source)
		if id <= 0 || id > math.MaxInt32 {
			return ErrAIGatewayCrossTableRestore
		}
		if _, duplicate := seen[id]; duplicate {
			return ErrAIGatewayCrossTableRestore
		}
		mapping, found := bySource[id]
		if !found {
			return ErrAIGatewayCrossTableRestore
		}
		seen[id] = struct{}{}
		*rows = append(*rows, link(source, mapping))
	}
	return nil
}

// CheckAIGatewayRestoreMappingConsistency rejects references that disagree
// across the six A-owned gateway history tables. All source data and mappings
// must have passed their own B proof; this check alone never authorizes SQL.
func CheckAIGatewayRestoreMappingConsistency(set AIGatewayRestoreMappingSet) error {
	users, err := indexGatewayMappings(set.Users, func(m UserRestoreMapping) (int, int) { return m.SourceID, m.TargetID })
	if err != nil {
		return err
	}
	models, err := indexGatewayMappings(set.Models, func(m LLMModelRestoreMapping) (int, int) { return m.SourceID, m.TargetID })
	if err != nil {
		return err
	}
	userIDs := make(map[int]int, len(users))
	for source, mapping := range users {
		userIDs[source] = mapping.TargetID
	}
	modelIDs := make(map[int]int, len(models))
	for source, mapping := range models {
		modelIDs[source] = mapping.TargetID
	}
	instances := make(map[int]int)
	if len(set.SessionSources) != len(set.Sessions) {
		return ErrAIGatewayCrossTableRestore
	}
	sessions, err := indexGatewayMappings(set.Sessions, func(m ChatSessionRestoreMapping) (int, int) { return m.SourceID, m.TargetID })
	if err != nil {
		return err
	}
	sessionByID := make(map[string]string, len(set.Sessions))
	targetSessionIDs := make(map[string]struct{}, len(set.Sessions))
	seenSessionSources := make(map[int]struct{}, len(set.SessionSources))
	for _, source := range set.SessionSources {
		mapping, found := sessions[source.ID]
		if !found || source.ID <= 0 || source.SessionID != mapping.SourceSessionID ||
			!validUserRestoreText(source.SessionID, 100) ||
			!validUserRestoreText(mapping.TargetSessionID, 100) ||
			strings.EqualFold(source.SessionID, mapping.TargetSessionID) ||
			!matchGatewayIntRef(source.UserID, mapping.TargetUserID, userIDs) ||
			!bindRiskHitInt(instances, source.InstanceID, mapping.TargetInstanceID) {
			return ErrAIGatewayCrossTableRestore
		}
		if _, duplicate := seenSessionSources[source.ID]; duplicate {
			return ErrAIGatewayCrossTableRestore
		}
		sourceKey := strings.ToLower(source.SessionID)
		targetKey := strings.ToLower(mapping.TargetSessionID)
		if _, duplicate := sessionByID[sourceKey]; duplicate {
			return ErrAIGatewayCrossTableRestore
		}
		if _, duplicate := targetSessionIDs[targetKey]; duplicate {
			return ErrAIGatewayCrossTableRestore
		}
		seenSessionSources[source.ID] = struct{}{}
		sessionByID[sourceKey] = mapping.TargetSessionID
		targetSessionIDs[targetKey] = struct{}{}
	}
	for target := range targetSessionIDs {
		if _, reused := sessionByID[target]; reused {
			return ErrAIGatewayCrossTableRestore
		}
	}
	invocations, err := indexGatewayMappings(set.Invocations, func(m ModelInvocationRestoreMapping) (int, int) { return m.SourceID, m.TargetID })
	if err != nil {
		return err
	}
	invocationIDs := make(map[int]int, len(invocations))
	for source, mapping := range invocations {
		invocationIDs[source] = mapping.TargetID
	}
	invocationSources := make(map[int]ModelInvocationRestoreSource, len(set.InvocationSources))
	rows := make([]gatewayHistoryLink, 0, len(set.InvocationSources)+len(set.AuditSources)+
		len(set.CostSources)+len(set.RiskHitSources)+len(set.ChatMessageSources))
	if err := appendGatewayLinks(&rows, set.InvocationSources, set.Invocations,
		func(s ModelInvocationRestoreSource) int { return s.ID },
		func(m ModelInvocationRestoreMapping) (int, int) { return m.SourceID, m.TargetID },
		func(s ModelInvocationRestoreSource, m ModelInvocationRestoreMapping) gatewayHistoryLink {
			invocationSources[s.ID] = s
			return gatewayHistoryLink{sourceTrace: s.TraceID, targetTrace: m.TargetTraceID,
				sourceSession: s.SessionID, targetSession: m.TargetSessionID,
				sourceUser: s.UserID, targetUser: m.TargetUserID,
				sourceInstance: s.InstanceID, targetInstance: m.TargetInstanceID,
				sourceGateway: s.GatewayID, targetGateway: m.TargetGatewayID,
				sourcePod: s.RuntimePodID, targetPod: m.TargetRuntimePodID,
				sourceModel: s.ModelID, targetModel: m.TargetModelID}
		}); err != nil {
		return err
	}
	for _, item := range []struct {
		name string
		run  func() error
	}{
		{"audit", func() error {
			return appendGatewayLinks(&rows, set.AuditSources, set.Audits,
				func(s AuditEventRestoreSource) int { return s.ID },
				func(m AuditEventRestoreMapping) (int, int) { return m.SourceID, m.TargetID },
				func(s AuditEventRestoreSource, m AuditEventRestoreMapping) gatewayHistoryLink {
					return gatewayHistoryLink{sourceTrace: s.TraceID, targetTrace: m.TargetTraceID,
						sourceSession: s.SessionID, targetSession: m.TargetSessionID,
						sourceUser: s.UserID, targetUser: m.TargetUserID,
						sourceInstance: s.InstanceID, targetInstance: m.TargetInstanceID,
						sourceGateway: s.GatewayID, targetGateway: m.TargetGatewayID,
						sourcePod: s.RuntimePodID, targetPod: m.TargetRuntimePodID,
						sourceInvocation: s.InvocationID, targetInvocation: m.TargetInvocationID}
				})
		}},
		{"cost", func() error {
			return appendGatewayLinks(&rows, set.CostSources, set.Costs,
				func(s CostRecordRestoreSource) int { return s.ID },
				func(m CostRecordRestoreMapping) (int, int) { return m.SourceID, m.TargetID },
				func(s CostRecordRestoreSource, m CostRecordRestoreMapping) gatewayHistoryLink {
					return gatewayHistoryLink{sourceTrace: s.TraceID, targetTrace: m.TargetTraceID,
						sourceSession: s.SessionID, targetSession: m.TargetSessionID,
						sourceUser: s.UserID, targetUser: m.TargetUserID,
						sourceInstance: s.InstanceID, targetInstance: m.TargetInstanceID,
						sourceGateway: s.GatewayID, targetGateway: m.TargetGatewayID,
						sourcePod: s.RuntimePodID, targetPod: m.TargetRuntimePodID,
						sourceInvocation: s.InvocationID, targetInvocation: m.TargetInvocationID,
						sourceModel: s.ModelID, targetModel: m.TargetModelID}
				})
		}},
		{"risk", func() error {
			return appendGatewayLinks(&rows, set.RiskHitSources, set.RiskHits,
				func(s RiskHitRestoreSource) int { return s.ID },
				func(m RiskHitRestoreMapping) (int, int) { return m.SourceID, m.TargetID },
				func(s RiskHitRestoreSource, m RiskHitRestoreMapping) gatewayHistoryLink {
					return gatewayHistoryLink{sourceTrace: s.TraceID, targetTrace: m.TargetTraceID,
						sourceSession: s.SessionID, targetSession: m.TargetSessionID,
						sourceUser: s.UserID, targetUser: m.TargetUserID,
						sourceInstance: s.InstanceID, targetInstance: m.TargetInstanceID,
						sourceGateway: s.GatewayID, targetGateway: m.TargetGatewayID,
						sourcePod: s.RuntimePodID, targetPod: m.TargetRuntimePodID,
						sourceInvocation: s.InvocationID, targetInvocation: m.TargetInvocationID}
				})
		}},
		{"message", func() error {
			return appendGatewayLinks(&rows, set.ChatMessageSources, set.ChatMessages,
				func(s ChatMessageRestoreSource) int { return s.ID },
				func(m ChatMessageRestoreMapping) (int, int) { return m.SourceID, m.TargetID },
				func(s ChatMessageRestoreSource, m ChatMessageRestoreMapping) gatewayHistoryLink {
					return gatewayHistoryLink{sourceTrace: s.TraceID, targetTrace: m.TargetTraceID,
						sourceSession: &s.SessionID, deriveSession: true,
						sourceUser: s.UserID, targetUser: m.TargetUserID,
						sourceInstance: s.InstanceID, targetInstance: m.TargetInstanceID,
						sourceInvocation: s.InvocationID, targetInvocation: m.TargetInvocationID}
				})
		}},
	} {
		if err := item.run(); err != nil {
			return err
		}
	}
	for i := range rows {
		if rows[i].deriveSession && rows[i].sourceSession != nil && rows[i].targetSession == nil {
			target, found := sessionByID[strings.ToLower(*rows[i].sourceSession)]
			if !found {
				return ErrAIGatewayCrossTableRestore
			}
			rows[i].targetSession = &target
		}
	}
	sourceTraces := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		if !validUserRestoreText(row.sourceTrace, 100) {
			return ErrAIGatewayCrossTableRestore
		}
		sourceTraces[strings.ToLower(row.sourceTrace)] = struct{}{}
	}
	traceTargets := make(map[string]string)
	targetTraces := make(map[string]string)
	gateways := make(map[string]string)
	pods := make(map[int64]int64)
	for _, row := range rows {
		if !validUserRestoreText(row.targetTrace, 100) ||
			!matchGatewayIntRef(row.sourceUser, row.targetUser, userIDs) ||
			!matchGatewayIntRef(row.sourceModel, row.targetModel, modelIDs) ||
			!matchGatewayIntRef(row.sourceInvocation, row.targetInvocation, invocationIDs) ||
			!bindRiskHitInt(instances, row.sourceInstance, row.targetInstance) ||
			!bindRiskHitString(gateways, row.sourceGateway, row.targetGateway, 128) ||
			!bindRiskHitInt64(pods, row.sourcePod, row.targetPod) ||
			!matchGatewaySession(row.sourceSession, row.targetSession, sessionByID) {
			return ErrAIGatewayCrossTableRestore
		}
		sourceKey := strings.ToLower(row.sourceTrace)
		targetKey := strings.ToLower(row.targetTrace)
		if _, reused := sourceTraces[targetKey]; reused {
			return ErrAIGatewayCrossTableRestore
		}
		if prior, found := traceTargets[sourceKey]; found && !strings.EqualFold(prior, row.targetTrace) {
			return ErrAIGatewayCrossTableRestore
		}
		if prior, found := targetTraces[targetKey]; found && prior != sourceKey {
			return ErrAIGatewayCrossTableRestore
		}
		traceTargets[sourceKey] = row.targetTrace
		targetTraces[targetKey] = sourceKey
		if row.sourceInvocation != nil {
			invocation, found := invocationSources[*row.sourceInvocation]
			if !found || !strings.EqualFold(invocation.TraceID, row.sourceTrace) {
				return ErrAIGatewayCrossTableRestore
			}
		}
	}
	return nil
}

func matchGatewayIntRef(source, target *int, mappings map[int]int) bool {
	if source == nil || target == nil {
		return source == nil && target == nil
	}
	if *source <= 0 || *target <= 0 {
		return false
	}
	actual, found := mappings[*source]
	return found && actual == *target
}

func matchGatewaySession(source, target *string, sessions map[string]string) bool {
	if source == nil || target == nil {
		return source == nil && target == nil
	}
	actual, found := sessions[strings.ToLower(*source)]
	return found && actual == *target
}
