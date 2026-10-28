package systembackupbusinessa

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"clawreef/internal/models"
)

// RiskRuleRestoreSource covers every migration-079 risk_rules SQL column.
// Source enabled state remains visible to B's dump proof, but is never copied
// into the isolated target row.
type RiskRuleRestoreSource struct {
	ID          int
	RuleID      string
	DisplayName string
	Description *string
	Pattern     string
	Severity    string
	Action      string
	IsEnabled   bool
	SortOrder   int
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type RiskRuleRestoreMapping struct {
	SourceID     int
	TargetID     int
	SourceRuleID string
	TargetRuleID string
}

// RiskRuleSourceProofVerifier is B's authority over the dump, rule-ID mapping,
// target occupancy and startup gate. The target app must not run its repository
// constructor before A's inert-state verification: that constructor seeds
// absent built-in rules as enabled. B must also preserve built-in rule IDs and
// use the same mapping for A-owned risk_hits.rule_id string references.
type RiskRuleSourceProofVerifier interface {
	VerifyRiskRuleSources(context.Context, string, string, string,
		[]RiskRuleRestoreSource, []RiskRuleRestoreMapping) error
}

var ErrRiskRuleRestore = errors.New("A risk rule restore normalization failed")

// NormalizeRiskRulesForRestore produces no partial rows and requires B's proof
// even for an empty source table. B owns SQL writes and the isolated app-start
// fence; D must review when that fence may be released.
func NormalizeRiskRulesForRestore(ctx context.Context, scope *CaptureScope,
	sources []RiskRuleRestoreSource, mappings []RiskRuleRestoreMapping,
	evidenceRef string, proof RiskRuleSourceProofVerifier) ([]models.RiskRule, error) {
	if ctx == nil || ctx.Err() != nil || scope == nil || len(scope.tables) != len(tables) ||
		!hashPattern.MatchString(scope.registrySHA) || !hashPattern.MatchString(scope.schemaSHA) ||
		!evidencePattern.MatchString(evidenceRef) || len(sources) != len(mappings) {
		return nil, ErrRiskRuleRestore
	}
	if nilRiskRuleProof(proof) {
		return nil, ErrCaptureEvidenceIncomplete
	}
	projection := cloneRiskRuleSources(sources)
	bySource := make(map[int]RiskRuleRestoreMapping, len(mappings))
	targetIDs := make(map[int]struct{}, len(mappings))
	targetRuleIDs := make(map[string]struct{}, len(mappings))
	for _, mapping := range mappings {
		if mapping.SourceID <= 0 || mapping.SourceID > math.MaxInt32 ||
			mapping.TargetID <= 0 || mapping.TargetID > math.MaxInt32 ||
			!validUserRestoreText(mapping.SourceRuleID, 100) ||
			!validUserRestoreText(mapping.TargetRuleID, 100) {
			return nil, ErrRiskRuleRestore
		}
		if _, duplicate := bySource[mapping.SourceID]; duplicate {
			return nil, ErrRiskRuleRestore
		}
		if _, duplicate := targetIDs[mapping.TargetID]; duplicate {
			return nil, ErrRiskRuleRestore
		}
		key := strings.ToLower(mapping.TargetRuleID)
		if _, duplicate := targetRuleIDs[key]; duplicate {
			return nil, ErrRiskRuleRestore
		}
		bySource[mapping.SourceID] = mapping
		targetIDs[mapping.TargetID] = struct{}{}
		targetRuleIDs[key] = struct{}{}
	}
	rows := make([]models.RiskRule, 0, len(projection))
	seenSources := make(map[int]struct{}, len(projection))
	seenRuleIDs := make(map[string]struct{}, len(projection))
	for _, source := range projection {
		mapping, found := bySource[source.ID]
		if !found {
			return nil, ErrRiskRuleRestore
		}
		if _, duplicate := seenSources[source.ID]; duplicate {
			return nil, ErrRiskRuleRestore
		}
		key := strings.ToLower(source.RuleID)
		if _, duplicate := seenRuleIDs[key]; duplicate {
			return nil, ErrRiskRuleRestore
		}
		row, err := NormalizeRiskRuleForRestore(source, mapping)
		if err != nil {
			return nil, err
		}
		seenSources[source.ID] = struct{}{}
		seenRuleIDs[key] = struct{}{}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	if err := proof.VerifyRiskRuleSources(ctx, scope.registrySHA, scope.schemaSHA,
		evidenceRef, cloneRiskRuleSources(projection),
		append([]RiskRuleRestoreMapping(nil), mappings...)); err != nil {
		return nil, fmt.Errorf("A risk rule source proof: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return rows, nil
}

// NormalizeRiskRuleForRestore is a pure single-row transform; it does not
// authenticate source data, rule identities or target startup state.
func NormalizeRiskRuleForRestore(source RiskRuleRestoreSource,
	mapping RiskRuleRestoreMapping) (models.RiskRule, error) {
	created := source.CreatedAt.UTC().Truncate(time.Second)
	updated := source.UpdatedAt.UTC().Truncate(time.Second)
	if source.ID <= 0 || source.ID > math.MaxInt32 || mapping.SourceID != source.ID ||
		mapping.TargetID <= 0 || mapping.TargetID > math.MaxInt32 ||
		mapping.SourceRuleID != source.RuleID ||
		!validUserRestoreText(source.RuleID, 100) ||
		!validUserRestoreText(mapping.TargetRuleID, 100) ||
		!validUserRestoreText(source.DisplayName, 255) ||
		len(source.Pattern) > 65535 || !validEnterpriseAuthText(source.Pattern, 65535) ||
		strings.TrimSpace(source.Pattern) == "" ||
		(source.Description != nil && (len(*source.Description) > 65535 ||
			!validEnterpriseAuthText(*source.Description, 65535))) ||
		(source.Severity != models.RiskSeverityLow &&
			source.Severity != models.RiskSeverityMedium &&
			source.Severity != models.RiskSeverityHigh) ||
		(source.Action != models.RiskActionAllow &&
			source.Action != models.RiskActionRouteSecureModel &&
			source.Action != models.RiskActionBlock) ||
		source.SortOrder < math.MinInt32 || source.SortOrder > math.MaxInt32 ||
		!validMySQLDateTime(created) || !validMySQLDateTime(updated) || updated.Before(created) {
		return models.RiskRule{}, ErrRiskRuleRestore
	}
	if _, err := regexp.Compile(source.Pattern); err != nil {
		return models.RiskRule{}, ErrRiskRuleRestore
	}
	return models.RiskRule{
		ID: mapping.TargetID, RuleID: mapping.TargetRuleID,
		DisplayName: source.DisplayName, Description: copyLLMString(source.Description),
		Pattern: source.Pattern, Severity: source.Severity, Action: source.Action,
		IsEnabled: false, SortOrder: source.SortOrder,
		CreatedAt: created, UpdatedAt: updated,
	}, nil
}

func cloneRiskRuleSources(sources []RiskRuleRestoreSource) []RiskRuleRestoreSource {
	result := append([]RiskRuleRestoreSource(nil), sources...)
	for i := range result {
		result[i].Description = copyLLMString(result[i].Description)
	}
	return result
}

func nilRiskRuleProof(proof RiskRuleSourceProofVerifier) bool {
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
