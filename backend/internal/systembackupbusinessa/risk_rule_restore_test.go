package systembackupbusinessa

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"clawreef/internal/models"
)

type riskRuleProofFixture struct {
	calls             int
	startupSuppressed bool
	failure           error
	mutateInput       bool
}

func (p *riskRuleProofFixture) VerifyRiskRuleSources(_ context.Context,
	registry, schema, evidence string, sources []RiskRuleRestoreSource,
	mappings []RiskRuleRestoreMapping) error {
	p.calls++
	if !hashPattern.MatchString(registry) || !hashPattern.MatchString(schema) ||
		evidence != "sev_risk_rules" || !p.startupSuppressed ||
		len(sources) != len(mappings) {
		return errors.New("unbound risk-rule startup or dump proof")
	}
	for i, source := range sources {
		if source.RuleID == "private_key_marker" && mappings[i].TargetRuleID != source.RuleID {
			return ErrRiskRuleRestore
		}
	}
	if p.mutateInput && len(sources) == 1 {
		*sources[0].Description = "changed"
		sources[0].Pattern = "changed"
		mappings[0].TargetRuleID = "changed"
	}
	return p.failure
}

func riskRuleRestoreFixture(t *testing.T) (*CaptureScope, RiskRuleRestoreSource, RiskRuleRestoreMapping) {
	t.Helper()
	scope, err := pinnedScope(t, registryFixture(t, true))
	if err != nil {
		t.Fatal(err)
	}
	created := time.Date(2026, 9, 20, 1, 2, 3, 0, time.UTC)
	description := "historical custom rule"
	source := RiskRuleRestoreSource{
		ID: 12, RuleID: "custom-risk-rule", DisplayName: "Custom risk rule",
		Description: &description, Pattern: `(?i)secret-[0-9]+`,
		Severity: models.RiskSeverityHigh, Action: models.RiskActionBlock,
		IsEnabled: true, SortOrder: 42,
		CreatedAt: created, UpdatedAt: created.Add(time.Hour),
	}
	return scope, source, RiskRuleRestoreMapping{
		SourceID: 12, TargetID: 112,
		SourceRuleID: "custom-risk-rule", TargetRuleID: "restored-custom-rule",
	}
}

func TestRiskRuleRestoreCompleteInertRow(t *testing.T) {
	scope, source, mapping := riskRuleRestoreFixture(t)
	proof := &riskRuleProofFixture{startupSuppressed: true, mutateInput: true}
	rows, err := NormalizeRiskRulesForRestore(context.Background(), scope,
		[]RiskRuleRestoreSource{source}, []RiskRuleRestoreMapping{mapping},
		"sev_risk_rules", proof)
	if err != nil || len(rows) != 1 || proof.calls != 1 {
		t.Fatalf("incomplete risk rule restore: %+v, calls=%d, err=%v", rows, proof.calls, err)
	}
	row := rows[0]
	if row.ID != 112 || row.RuleID != "restored-custom-rule" ||
		row.DisplayName != source.DisplayName || row.Description == nil ||
		*row.Description != *source.Description || row.Pattern != source.Pattern ||
		row.Severity != models.RiskSeverityHigh || row.Action != models.RiskActionBlock ||
		row.IsEnabled || row.SortOrder != 42 || !row.CreatedAt.Equal(source.CreatedAt) ||
		!row.UpdatedAt.Equal(source.UpdatedAt) {
		t.Fatalf("restored risk rule became active or lost SQL fields: %+v", row)
	}
	*source.Description = "source changed"
	if *row.Description != "historical custom rule" {
		t.Fatal("restored rule aliases mutable source description")
	}
}

func TestRiskRuleRestoreRequiresProofEvenForEmptyTable(t *testing.T) {
	scope, source, mapping := riskRuleRestoreFixture(t)
	proof := &riskRuleProofFixture{startupSuppressed: true}
	rows, err := NormalizeRiskRulesForRestore(context.Background(), scope, nil, nil,
		"sev_risk_rules", proof)
	if err != nil || len(rows) != 0 || proof.calls != 1 {
		t.Fatalf("empty risk table not proved: %+v, calls=%d, err=%v", rows, proof.calls, err)
	}
	for name, candidate := range map[string]RiskRuleSourceProofVerifier{
		"nil": nil, "typed nil": (*riskRuleProofFixture)(nil),
	} {
		rows, err := NormalizeRiskRulesForRestore(context.Background(), scope,
			[]RiskRuleRestoreSource{source}, []RiskRuleRestoreMapping{mapping},
			"sev_risk_rules", candidate)
		if !errors.Is(err, ErrCaptureEvidenceIncomplete) || rows != nil {
			t.Fatalf("%s proof accepted: %+v, err=%v", name, rows, err)
		}
	}
	proof = &riskRuleProofFixture{}
	rows, err = NormalizeRiskRulesForRestore(context.Background(), scope,
		[]RiskRuleRestoreSource{source}, []RiskRuleRestoreMapping{mapping},
		"sev_risk_rules", proof)
	if err == nil || rows != nil || proof.calls != 1 {
		t.Fatalf("startup seed gate failure emitted rows: %+v, err=%v", rows, err)
	}
	proof = &riskRuleProofFixture{startupSuppressed: true, failure: errors.New("dump unavailable")}
	rows, err = NormalizeRiskRulesForRestore(context.Background(), scope,
		[]RiskRuleRestoreSource{source}, []RiskRuleRestoreMapping{mapping},
		"sev_risk_rules", proof)
	if err == nil || rows != nil {
		t.Fatalf("dump proof failure emitted rows: %+v, err=%v", rows, err)
	}
}

func TestRiskRuleRestoreRejectsInvalidSource(t *testing.T) {
	scope, source, mapping := riskRuleRestoreFixture(t)
	for name, mutate := range map[string]func(*RiskRuleRestoreSource, *RiskRuleRestoreMapping){
		"wrong source rule ID": func(_ *RiskRuleRestoreSource, m *RiskRuleRestoreMapping) { m.SourceRuleID = "other" },
		"bad target ID":        func(_ *RiskRuleRestoreSource, m *RiskRuleRestoreMapping) { m.TargetID = 0 },
		"unknown action":       func(s *RiskRuleRestoreSource, _ *RiskRuleRestoreMapping) { s.Action = "execute_shell" },
		"deprecated action":    func(s *RiskRuleRestoreSource, _ *RiskRuleRestoreMapping) { s.Action = "require_approval" },
		"unknown severity":     func(s *RiskRuleRestoreSource, _ *RiskRuleRestoreMapping) { s.Severity = "critical" },
		"invalid regex":        func(s *RiskRuleRestoreSource, _ *RiskRuleRestoreMapping) { s.Pattern = "(" },
		"oversized pattern":    func(s *RiskRuleRestoreSource, _ *RiskRuleRestoreMapping) { s.Pattern = strings.Repeat("a", 65536) },
		"empty rule name":      func(s *RiskRuleRestoreSource, _ *RiskRuleRestoreMapping) { s.DisplayName = " " },
		"sort overflow":        func(s *RiskRuleRestoreSource, _ *RiskRuleRestoreMapping) { s.SortOrder = 1 << 40 },
		"reversed times":       func(s *RiskRuleRestoreSource, _ *RiskRuleRestoreMapping) { s.UpdatedAt = s.CreatedAt.Add(-time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			badSource, badMapping := source, mapping
			mutate(&badSource, &badMapping)
			proof := &riskRuleProofFixture{startupSuppressed: true}
			rows, err := NormalizeRiskRulesForRestore(context.Background(), scope,
				[]RiskRuleRestoreSource{badSource}, []RiskRuleRestoreMapping{badMapping},
				"sev_risk_rules", proof)
			if !errors.Is(err, ErrRiskRuleRestore) || rows != nil || proof.calls != 0 {
				t.Fatalf("invalid rule reached proof or emitted rows: %+v, calls=%d, err=%v", rows, proof.calls, err)
			}
		})
	}
}

func TestRiskRuleRestoreRejectsCollisionsAndBuiltInRemap(t *testing.T) {
	scope, source, mapping := riskRuleRestoreFixture(t)
	other := source
	other.ID, other.RuleID = 13, "CUSTOM-RISK-RULE"
	proof := &riskRuleProofFixture{startupSuppressed: true}
	rows, err := NormalizeRiskRulesForRestore(context.Background(), scope,
		[]RiskRuleRestoreSource{source, other},
		[]RiskRuleRestoreMapping{mapping, {
			SourceID: 13, TargetID: 113, SourceRuleID: other.RuleID,
			TargetRuleID: "different-rule",
		}}, "sev_risk_rules", proof)
	if !errors.Is(err, ErrRiskRuleRestore) || rows != nil || proof.calls != 0 {
		t.Fatalf("colliding rule IDs emitted rows: %+v, calls=%d, err=%v", rows, proof.calls, err)
	}
	builtIn := source
	builtIn.RuleID = "private_key_marker"
	mapping.SourceRuleID = builtIn.RuleID
	rows, err = NormalizeRiskRulesForRestore(context.Background(), scope,
		[]RiskRuleRestoreSource{builtIn}, []RiskRuleRestoreMapping{mapping},
		"sev_risk_rules", proof)
	if !errors.Is(err, ErrRiskRuleRestore) || rows != nil || proof.calls != 1 {
		t.Fatalf("built-in rule ID remap passed B proof: %+v, calls=%d, err=%v", rows, proof.calls, err)
	}
}
