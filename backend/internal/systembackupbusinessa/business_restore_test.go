package systembackupbusinessa

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// This is an isolated source/target proof fixture, not B's production issuer.
type businessRestoreProofFixture struct {
	gatewayHistoryProofFixture
	wantBinding BusinessRestoreBinding
	wantInput   BusinessRestoreInput
	onVerify    func(BusinessRestoreBinding, BusinessRestoreInput)
	onRecheck   func()
	finalError  error
}

func (p *businessRestoreProofFixture) VerifyBusinessRestoreSources(_ context.Context,
	binding BusinessRestoreBinding, input BusinessRestoreInput) error {
	if !reflect.DeepEqual(binding, p.wantBinding) || !reflect.DeepEqual(input, p.wantInput) {
		return errors.New("business proof binding differs")
	}
	if p.onVerify != nil {
		p.onVerify(binding, input)
	}
	return p.record("business")
}

func (p *businessRestoreProofFixture) RecheckBusinessRestoreSources(_ context.Context,
	binding BusinessRestoreBinding, input BusinessRestoreInput) error {
	if !reflect.DeepEqual(binding, p.wantBinding) || !reflect.DeepEqual(input, p.wantInput) {
		return errors.New("business final proof binding differs")
	}
	if p.onRecheck != nil {
		p.onRecheck()
	}
	if p.finalError != nil {
		return p.finalError
	}
	return p.record("final")
}

func (p *businessRestoreProofFixture) VerifyAIGatewayHistorySources(_ context.Context,
	_, _, evidence string, set AIGatewayRestoreMappingSet, rules []RiskRuleRestoreMapping) error {
	if evidence != p.wantBinding.Dump.EvidenceRef ||
		!reflect.DeepEqual(set, p.wantInput.Gateway) || !reflect.DeepEqual(rules, p.wantInput.RuleMappings) {
		return errors.New("gateway proof differs from common dump")
	}
	return p.record("batch")
}

func (p *businessRestoreProofFixture) VerifyEnterpriseAuthSource(_ context.Context,
	_, _, _ string, _ []EnterpriseAuthRestoreSource) error {
	return p.record("enterprise")
}

func (p *businessRestoreProofFixture) VerifyLLMModelSources(_ context.Context,
	_, _, _ string, _ []LLMModelRestoreSource) error {
	return p.record("models")
}

func (p *businessRestoreProofFixture) VerifyRiskRuleSources(_ context.Context,
	_, _, _ string, _ []RiskRuleRestoreSource, _ []RiskRuleRestoreMapping) error {
	return p.record("rules")
}

func (p *businessRestoreProofFixture) VerifyGatewayAliasRestore(_ context.Context,
	_, _, _ string, _ []GatewayAliasRestoreSource, _ []GatewayAliasRestoreMapping,
	_ []GatewayAliasInstanceMapping, _ time.Time) error {
	return p.record("aliases")
}

func businessRestoreTestProofs(p *businessRestoreProofFixture) BusinessRestoreProofs {
	return BusinessRestoreProofs{
		Batch: p, EnterpriseAuth: p, Models: p, Rules: p, Aliases: p,
		Gateway: AIGatewayHistoryProofs{Batch: p, Sessions: p, Invocations: p,
			Audits: p, Costs: p, RiskHits: p, Messages: p},
	}
}

func businessRestoreFixture(t *testing.T) (*CaptureScope, BusinessRestoreBinding,
	BusinessRestoreInput, *businessRestoreProofFixture) {
	t.Helper()
	scope, gateway, ruleMappings := gatewayHistoryTestInput(t)
	_, _, enterprise, enterpriseMap := enterpriseAuthRestoreFixture(t)
	_, model, _ := llmModelRestoreFixture(t)
	_, rule, _ := riskRuleRestoreFixture(t)
	_, alias, aliasMap, instances, now := gatewayAliasRestoreFixture(t)
	challenge, challengeMap, _ := challengeRestoreFixture()
	_, session, sessionMap, _ := sessionRestoreFixture(t)
	_, caller := callerPolicyRestoreFixture(t)
	caller.UpdatedBy = callerInt(7)
	gateway.Users[0].TargetUsername = "target"
	gateway.Users[0].TargetEmail = "target@example.invalid"
	rule.RuleID = ruleMappings[0].SourceRuleID
	input := BusinessRestoreInput{
		Users: []UserRestoreSource{{ID: 7, Username: "source", Email: "source@example.invalid",
			Role: "user", CreatedAt: enterprise.CreatedAt, UpdatedAt: enterprise.UpdatedAt}},
		Quotas: []UserQuotaRestoreSource{{ID: 9, UserID: 7,
			MaxInstances: quotaInt(1), MaxCPUCores: "1.25", MaxMemoryGB: quotaInt(2),
			MaxStorageGB: quotaInt(3), MaxGPUCount: quotaInt(0),
			CreatedAt: enterprise.CreatedAt, UpdatedAt: enterprise.UpdatedAt}},
		QuotaMappings: []UserQuotaRestoreMapping{{SourceID: 9, TargetID: 109}},
		QuotaCapacities: map[int]UserQuotaCapacity{107: {MaxInstances: 2, MaxCPUCores: "2.00",
			MaxMemoryGB: 4, MaxStorageGB: 5, MaxGPUCount: 0}},
		EnterpriseAuth: []EnterpriseAuthRestoreSource{enterprise}, EnterpriseMappings: []EnterpriseAuthRestoreMapping{enterpriseMap},
		Challenges: []NorthboundChallengeRestoreSource{challenge}, ChallengeMappings: []NorthboundChallengeRestoreMapping{challengeMap},
		NorthboundSessions: []NorthboundSessionRestoreSource{session}, NorthboundMappings: []NorthboundSessionRestoreMapping{sessionMap},
		CallerPolicies: []NorthboundCallerPolicyRestoreSource{caller}, Models: []LLMModelRestoreSource{model},
		Rules: []RiskRuleRestoreSource{rule}, RuleMappings: ruleMappings,
		Aliases: []GatewayAliasRestoreSource{alias}, AliasMappings: []GatewayAliasRestoreMapping{aliasMap},
		Instances: instances, Gateway: gateway,
	}
	binding := BusinessRestoreBinding{
		Dump: CaptureEvidence{RegistrySHA256: scope.registrySHA, SchemaSHA256: scope.schemaSHA,
			CheckpointHash: strings.Repeat("b", 64), CaptureContextHash: strings.Repeat("c", 64),
			EvidenceRef: "sev_gateway_history"},
		TargetIdentitySHA256: strings.Repeat("d", 64), TargetNow: now,
	}
	counts := businessRestoreSourceCounts(input)
	for _, name := range scope.tables {
		binding.Dump.Snapshot.Tables = append(binding.Dump.Snapshot.Tables, TableCount{Table: name, Rows: int64(counts[name])})
	}
	costHash, err := costSourceAggregateHash(input.Gateway.CostSources)
	binding.Dump.Snapshot.CostAggregateSHA256 = costHash
	if err != nil {
		t.Fatal(err)
	}
	proof := &businessRestoreProofFixture{
		wantBinding: cloneBusinessRestoreBinding(binding), wantInput: cloneBusinessRestoreInput(input),
	}
	return scope, binding, input, proof
}

func TestBusinessRestoreAllFifteenTablesAndInertCredentials(t *testing.T) {
	scope, binding, input, proof := businessRestoreFixture(t)
	rows, err := NormalizeBusinessForRestore(context.Background(), scope, binding, input, businessRestoreTestProofs(proof))
	if err != nil {
		t.Fatal(err)
	}
	for _, count := range []int{len(rows.Users), len(rows.Quotas), len(rows.EnterpriseAuth),
		len(rows.Challenges), len(rows.NorthboundSessions), len(rows.CallerPolicies),
		len(rows.Models), len(rows.Rules), len(rows.Aliases), len(rows.Gateway.Sessions),
		len(rows.Gateway.Invocations), len(rows.Gateway.Audits), len(rows.Gateway.Costs),
		len(rows.Gateway.RiskHits), len(rows.Gateway.Messages)} {
		if count != 1 {
			t.Fatal("business batch omitted or duplicated a table")
		}
	}
	if rows.Users[0].IsActive || rows.Users[0].PasswordHash != DisabledUserPasswordHash ||
		rows.EnterpriseAuth[0].Enabled || rows.EnterpriseAuth[0].LDAPBindPasswordCiphertext == nil ||
		*rows.EnterpriseAuth[0].LDAPBindPasswordCiphertext != "" ||
		rows.Challenges[0].Status != "expired" || rows.NorthboundSessions[0].Status != "revoked" ||
		rows.CallerPolicies[0].Enabled || rows.Models[0].IsActive || rows.Models[0].APIKey != nil ||
		rows.Models[0].APIKeySecretRef != nil || rows.Rules[0].IsEnabled ||
		!rows.Aliases[0].ExpiresAt.Before(binding.TargetNow) ||
		rows.Gateway.Messages[0].Content != "[REDACTED]" ||
		rows.Gateway.RiskHits[0].MatchSummary != "[REDACTED]" {
		t.Fatal("restored batch retained an active credential or raw history content")
	}
	if rows.Quotas[0].UserID != rows.Users[0].ID ||
		*rows.Gateway.Invocations[0].ModelID != rows.Models[0].ID ||
		rows.Aliases[0].InstanceID != *rows.Gateway.Invocations[0].InstanceID ||
		rows.Gateway.RiskHits[0].RuleID != rows.Rules[0].RuleID {
		t.Fatal("business dependencies differ from normalized dependency rows")
	}
	if len(proof.calls) != 13 || proof.calls[0] != "business" || proof.calls[12] != "final" {
		t.Fatalf("missing proof stage: %v", proof.calls)
	}
}

func TestBusinessRestoreProofFailuresReturnNoPartialBatch(t *testing.T) {
	for _, stage := range []string{"business", "enterprise", "models", "rules", "aliases",
		"batch", "sessions", "invocations", "audits", "costs", "risk_hits", "messages", "final"} {
		t.Run(stage, func(t *testing.T) {
			scope, binding, input, proof := businessRestoreFixture(t)
			proof.failAt = stage
			rows, err := NormalizeBusinessForRestore(context.Background(), scope, binding, input, businessRestoreTestProofs(proof))
			if err == nil || !reflect.DeepEqual(rows, BusinessRestoreRows{}) {
				t.Fatal("proof failure returned partial business rows")
			}
			if proof.calls[len(proof.calls)-1] != stage {
				t.Fatal("normalization continued after proof failure")
			}
		})
	}
}

func TestBusinessRestoreRejectsBindingAndInstanceDriftBeforeProof(t *testing.T) {
	for name, edit := range map[string]func(*BusinessRestoreBinding, *BusinessRestoreInput){
		"registry": func(b *BusinessRestoreBinding, _ *BusinessRestoreInput) {
			b.Dump.RegistrySHA256 = strings.Repeat("f", 64)
		},
		"checkpoint":      func(b *BusinessRestoreBinding, _ *BusinessRestoreInput) { b.Dump.CheckpointHash = "" },
		"capture context": func(b *BusinessRestoreBinding, _ *BusinessRestoreInput) { b.Dump.CaptureContextHash = "" },
		"target":          func(b *BusinessRestoreBinding, _ *BusinessRestoreInput) { b.TargetIdentitySHA256 = "" },
		"target clock":    func(b *BusinessRestoreBinding, _ *BusinessRestoreInput) { b.TargetNow = time.Time{} },
		"missing table": func(b *BusinessRestoreBinding, _ *BusinessRestoreInput) {
			b.Dump.Snapshot.Tables = b.Dump.Snapshot.Tables[:14]
		},
		"missing row":      func(_ *BusinessRestoreBinding, i *BusinessRestoreInput) { i.Models = nil },
		"instance drift":   func(_ *BusinessRestoreBinding, i *BusinessRestoreInput) { i.Instances[0].TargetID++ },
		"missing instance": func(_ *BusinessRestoreBinding, i *BusinessRestoreInput) { i.Instances = nil },
		"duplicate instance": func(_ *BusinessRestoreBinding, i *BusinessRestoreInput) {
			i.Instances = append(i.Instances, i.Instances[0])
		},
	} {
		t.Run(name, func(t *testing.T) {
			scope, binding, input, proof := businessRestoreFixture(t)
			edit(&binding, &input)
			rows, err := NormalizeBusinessForRestore(context.Background(), scope, binding, input, businessRestoreTestProofs(proof))
			if err == nil || !reflect.DeepEqual(rows, BusinessRestoreRows{}) || len(proof.calls) != 0 {
				t.Fatal("binding or mapping drift reached proof or returned rows")
			}
		})
	}
}

func TestBusinessRestoreFrozenInputAndFinalAuthority(t *testing.T) {
	scope, binding, input, proof := businessRestoreFixture(t)
	proof.onVerify = func(b BusinessRestoreBinding, i BusinessRestoreInput) {
		b.Dump.Snapshot.Tables[0].Rows = 999
		*i.Quotas[0].MaxInstances = 999
		delete(i.QuotaCapacities, 107)
		*i.EnterpriseAuth[0].UpdatedBy = 999
		*i.NorthboundSessions[0].PreviousRefreshTokenHash = "changed"
		*i.CallerPolicies[0].UpdatedBy = 999
		*i.Models[0].Description = "changed"
		*i.Aliases[0].LastUsedAt = time.Time{}
		*i.Gateway.Invocations[0].TargetUserID = 999
		// Also mutate the caller's original memory after the entry snapshot.
		input.Gateway.Users[0].TargetID = 999
		*input.Quotas[0].MaxInstances = 999
		*input.NorthboundSessions[0].LastIP = "changed"
	}
	rows, err := NormalizeBusinessForRestore(context.Background(), scope, binding, input, businessRestoreTestProofs(proof))
	if err != nil || rows.Users[0].ID != 107 || rows.Quotas[0].MaxInstances != 1 ||
		*rows.NorthboundSessions[0].LastIP != "192.0.2.8" {
		t.Fatalf("proof or caller mutation changed frozen batch: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scope, binding, input, proof = businessRestoreFixture(t)
	proof.onRecheck = cancel
	rows, err = NormalizeBusinessForRestore(ctx, scope, binding, input, businessRestoreTestProofs(proof))
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(rows, BusinessRestoreRows{}) {
		t.Fatal("canceled final authority returned candidate rows")
	}
	scope, binding, input, proof = businessRestoreFixture(t)
	revoked := errors.New("B target authority revoked")
	proof.finalError = revoked
	rows, err = NormalizeBusinessForRestore(context.Background(), scope, binding, input, businessRestoreTestProofs(proof))
	if !errors.Is(err, revoked) || !reflect.DeepEqual(rows, BusinessRestoreRows{}) {
		t.Fatal("final revocation returned rows or lost B error")
	}
}

func TestBusinessRestoreRequiresProofsEvenForEmptyTables(t *testing.T) {
	scope, binding, _, proof := businessRestoreFixture(t)
	input := BusinessRestoreInput{}
	binding.Dump.Snapshot.CostAggregateSHA256 = fixtureCostAggregateHash(t, 0)
	for i := range binding.Dump.Snapshot.Tables {
		binding.Dump.Snapshot.Tables[i].Rows = 0
	}
	proof.wantBinding = cloneBusinessRestoreBinding(binding)
	proof.wantInput = cloneBusinessRestoreInput(input)
	proofs := businessRestoreTestProofs(proof)
	var missing *businessRestoreProofFixture
	proofs.Batch = missing
	rows, err := NormalizeBusinessForRestore(context.Background(), scope, binding, input, proofs)
	if !errors.Is(err, ErrCaptureEvidenceIncomplete) || !reflect.DeepEqual(rows, BusinessRestoreRows{}) || len(proof.calls) != 0 {
		t.Fatal("typed nil proof authenticated empty business tables")
	}
	proofs = businessRestoreTestProofs(proof)
	proofs.Gateway.Messages = nil
	rows, err = NormalizeBusinessForRestore(context.Background(), scope, binding, input, proofs)
	if !errors.Is(err, ErrCaptureEvidenceIncomplete) || !reflect.DeepEqual(rows, BusinessRestoreRows{}) || len(proof.calls) != 0 {
		t.Fatal("missing leaf proof authenticated empty business tables")
	}
	rows, err = NormalizeBusinessForRestore(context.Background(), scope, binding, input, businessRestoreTestProofs(proof))
	if err != nil || len(rows.Users) != 0 || len(rows.Gateway.Invocations) != 0 || len(proof.calls) != 13 {
		t.Fatalf("empty tables bypassed common or table proof: calls=%v err=%v", proof.calls, err)
	}
	category, known := KnownVerificationFailureCategory(ErrBusinessRestore)
	if !known || category != "normalization_failed" {
		t.Fatal("business normalization error lost its failure category")
	}
}

func TestBusinessRestoreNormalizerFailuresReturnNoPartialBatch(t *testing.T) {
	for name, edit := range map[string]func(*BusinessRestoreInput){
		"users":               func(i *BusinessRestoreInput) { i.Users[0].Role = "root" },
		"quotas":              func(i *BusinessRestoreInput) { i.Quotas[0].MaxInstances = nil },
		"enterprise":          func(i *BusinessRestoreInput) { i.EnterpriseAuth[0].Provider = "unknown" },
		"challenges":          func(i *BusinessRestoreInput) { i.Challenges[0].NonceHash = "invalid" },
		"northbound sessions": func(i *BusinessRestoreInput) { i.NorthboundSessions[0].ScopesJSON = `["unknown"]` },
		"caller policies":     func(i *BusinessRestoreInput) { i.CallerPolicies[0].UserID = 999 },
		"models":              func(i *BusinessRestoreInput) { i.Models[0].InputPrice = "NaN" },
		"rules":               func(i *BusinessRestoreInput) { i.Rules[0].Pattern = "(" },
		"aliases":             func(i *BusinessRestoreInput) { i.Aliases[0].TokenHash = "invalid" },
		"history":             func(i *BusinessRestoreInput) { i.Gateway.ChatMessageSources[0].SequenceNo = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			scope, binding, input, proof := businessRestoreFixture(t)
			edit(&input)
			proof.wantInput = cloneBusinessRestoreInput(input)
			rows, err := NormalizeBusinessForRestore(context.Background(), scope, binding, input, businessRestoreTestProofs(proof))
			if err == nil || !reflect.DeepEqual(rows, BusinessRestoreRows{}) {
				t.Fatal("normalizer failure returned partial business rows")
			}
			for _, stage := range proof.calls {
				if stage == "final" {
					t.Fatal("failed normalization reached final acceptance")
				}
			}
		})
	}
}

func TestBusinessRestoreRejectsEveryMissingProof(t *testing.T) {
	var typedNil *businessRestoreProofFixture
	for name, remove := range map[string]func(*BusinessRestoreProofs){
		"batch":         func(p *BusinessRestoreProofs) { p.Batch = typedNil },
		"enterprise":    func(p *BusinessRestoreProofs) { p.EnterpriseAuth = typedNil },
		"models":        func(p *BusinessRestoreProofs) { p.Models = typedNil },
		"rules":         func(p *BusinessRestoreProofs) { p.Rules = typedNil },
		"aliases":       func(p *BusinessRestoreProofs) { p.Aliases = typedNil },
		"gateway batch": func(p *BusinessRestoreProofs) { p.Gateway.Batch = typedNil },
		"sessions":      func(p *BusinessRestoreProofs) { p.Gateway.Sessions = typedNil },
		"invocations":   func(p *BusinessRestoreProofs) { p.Gateway.Invocations = typedNil },
		"audits":        func(p *BusinessRestoreProofs) { p.Gateway.Audits = typedNil },
		"costs":         func(p *BusinessRestoreProofs) { p.Gateway.Costs = typedNil },
		"risk hits":     func(p *BusinessRestoreProofs) { p.Gateway.RiskHits = typedNil },
		"messages":      func(p *BusinessRestoreProofs) { p.Gateway.Messages = typedNil },
	} {
		t.Run(name, func(t *testing.T) {
			scope, binding, input, proof := businessRestoreFixture(t)
			proofs := businessRestoreTestProofs(proof)
			remove(&proofs)
			rows, err := NormalizeBusinessForRestore(context.Background(), scope, binding, input, proofs)
			if !errors.Is(err, ErrCaptureEvidenceIncomplete) ||
				!reflect.DeepEqual(rows, BusinessRestoreRows{}) || len(proof.calls) != 0 {
				t.Fatal("missing proof reached another adapter or returned rows")
			}
		})
	}
}

func TestBusinessRestoreCancellationBeforeAndAfterInitialProof(t *testing.T) {
	for _, afterProof := range []bool{false, true} {
		scope, binding, input, proof := businessRestoreFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		if afterProof {
			proof.onVerify = func(BusinessRestoreBinding, BusinessRestoreInput) { cancel() }
		} else {
			cancel()
		}
		rows, err := NormalizeBusinessForRestore(ctx, scope, binding, input, businessRestoreTestProofs(proof))
		cancel()
		if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(rows, BusinessRestoreRows{}) ||
			(!afterProof && len(proof.calls) != 0) || (afterProof && len(proof.calls) != 1) {
			t.Fatal("canceled restore continued normalization or returned rows")
		}
	}
}

type cancelAfterFirstRestoreCheck struct {
	context.Context
	cancel context.CancelFunc
	checks int
}

func (c *cancelAfterFirstRestoreCheck) Err() error {
	err := c.Context.Err()
	c.checks++
	if c.checks == 1 {
		c.cancel() // Cancellation races with freezing/validating a large batch.
	}
	return err
}

func TestBusinessRestoreCancellationDuringInputValidationDoesNotCallProof(t *testing.T) {
	scope, binding, input, proof := businessRestoreFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rows, err := NormalizeBusinessForRestore(&cancelAfterFirstRestoreCheck{Context: ctx, cancel: cancel},
		scope, binding, input, businessRestoreTestProofs(proof))
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(rows, BusinessRestoreRows{}) || len(proof.calls) != 0 {
		t.Fatal("cancellation during validation reached source proof or returned rows")
	}
}
