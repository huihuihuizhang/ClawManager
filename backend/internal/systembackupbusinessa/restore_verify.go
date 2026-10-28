package systembackupbusinessa

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// RestoreTargetReadProofVerifier is B's independently credentialed boundary.
// It must authenticate the isolated target identity, completed normalization,
// expected table counts, cost aggregate digest and evidence. It must prove
// this transaction can only use a SELECT-only credential. Recheck runs before
// the read transaction commits.
type RestoreTargetReadProofVerifier interface {
	VerifyReadOnlyTarget(context.Context, *sql.Tx, string, string, SourceSnapshot, string) error
	RecheckReadOnlyTarget(context.Context, *sql.Tx, string, string, string) error
}

type SQLRestoreVerifier struct {
	DB    *sql.DB
	Proof RestoreTargetReadProofVerifier
}

var ErrRestoreNormalizationMismatch = errors.New("A business restore normalization mismatch")

type restoreSafetyRule struct {
	table, category, id, query string
	args                       []any
}

var restoreSafetyRules = []restoreSafetyRule{
	{"enterprise_auth_settings", "users", "users.restore_inert.enterprise_auth_settings", `SELECT COUNT(*) FROM enterprise_auth_settings WHERE enabled IS NULL OR enabled<>FALSE OR ldap_bind_password_ciphertext IS NULL OR BINARY ldap_bind_password_ciphertext<>BINARY ''`, nil},
	{"northbound_auth_challenges", "users", "users.restore_inert.northbound_auth_challenges", `SELECT COUNT(*) FROM northbound_auth_challenges WHERE BINARY status<>BINARY 'expired' OR expires_at>UTC_TIMESTAMP(6) OR used_at IS NULL OR used_at>UTC_TIMESTAMP(6)`, nil},
	{"northbound_caller_policies", "users", "users.restore_inert.northbound_caller_policies", `SELECT COUNT(*) FROM northbound_caller_policies WHERE enabled IS NULL OR enabled<>FALSE`, nil},
	{"northbound_sessions", "users", "users.restore_inert.northbound_sessions", `SELECT COUNT(*) FROM northbound_sessions WHERE BINARY status<>BINARY 'revoked' OR access_expires_at>UTC_TIMESTAMP(6) OR refresh_expires_at>UTC_TIMESTAMP(6) OR revoked_at IS NULL OR revoked_at>UTC_TIMESTAMP(6)`, nil},
	{"users", "users", "users.restore_inert.users", `SELECT COUNT(*) FROM users WHERE is_active IS NULL OR is_active<>FALSE OR password_hash IS NULL OR BINARY password_hash<>BINARY ? OR role IS NULL OR role NOT IN ('admin','user') OR auth_provider IS NULL OR BINARY auth_provider<>BINARY 'local' OR login_alias IS NOT NULL OR external_id IS NOT NULL OR last_login IS NOT NULL`, []any{DisabledUserPasswordHash}},
	{"chat_sessions", "ai_gateway", "ai_gateway.restore_inert.chat_sessions", `SELECT COUNT(*) FROM chat_sessions WHERE last_trace_id IS NOT NULL`, nil},
	{"instance_gateway_token_aliases", "ai_gateway", "ai_gateway.restore_inert.instance_gateway_token_aliases", `SELECT COUNT(*) FROM instance_gateway_token_aliases WHERE expires_at>UTC_TIMESTAMP(6)`, nil},
	{"llm_models", "ai_gateway", "ai_gateway.restore_inert.llm_models", `SELECT COUNT(*) FROM llm_models WHERE is_active IS NULL OR is_active<>FALSE OR api_key IS NOT NULL OR api_key_secret_ref IS NOT NULL`, nil},
	{"risk_rules", "ai_gateway", "ai_gateway.restore_inert.risk_rules", `SELECT COUNT(*) FROM risk_rules WHERE is_enabled IS NULL OR is_enabled<>FALSE`, nil},
}

// VerifyRestoreTarget compares all 15 A table counts with B-authenticated
// expected counts and cost aggregates, and checks restored execution/credential
// state in one read-only RepeatableRead target transaction. SQL/proof failure returns no
// checks; a completed comparison returns failed checks with an integrity error.
func (v SQLRestoreVerifier) VerifyRestoreTarget(ctx context.Context, scope *CaptureScope,
	expected SourceSnapshot, evidenceRef string) (CategoryChecks, error) {
	if ctx == nil {
		return CategoryChecks{}, errors.New("nil A restore verification context")
	}
	if err := ctx.Err(); err != nil {
		return CategoryChecks{}, err
	}
	if scope == nil || len(scope.tables) != len(tables) || !hashPattern.MatchString(scope.registrySHA) ||
		!hashPattern.MatchString(scope.schemaSHA) || !evidencePattern.MatchString(evidenceRef) ||
		v.DB == nil || nilRestoreProof(v.Proof) {
		return CategoryChecks{}, ErrCaptureEvidenceIncomplete
	}
	if err := validateSnapshot(expected, scope.tables); err != nil {
		return CategoryChecks{}, err
	}
	want := cloneSourceSnapshot(expected)
	tx, err := v.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return CategoryChecks{}, fmt.Errorf("begin A restore read-only snapshot: %w", err)
	}
	defer tx.Rollback()
	proofSnapshot := cloneSourceSnapshot(want)
	if err := v.Proof.VerifyReadOnlyTarget(ctx, tx, scope.registrySHA, scope.schemaSHA, proofSnapshot, evidenceRef); err != nil {
		return CategoryChecks{}, fmt.Errorf("A restore target proof: %w", err)
	}
	checks := CategoryChecks{Users: make([]Check, 0, 11), AIGateway: make([]Check, 0, 14)}
	actualCostRows := int64(-1)
	for i, table := range scope.tables {
		var engine string
		if err := tx.QueryRowContext(ctx, `SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND TABLE_TYPE='BASE TABLE'`, table).Scan(&engine); err != nil {
			return CategoryChecks{}, fmt.Errorf("inspect A restored table %s: %w", table, err)
		}
		if !strings.EqualFold(engine, "InnoDB") {
			return CategoryChecks{}, fmt.Errorf("A restored table %s is not transactional InnoDB", table)
		}
		var rows int64
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM `"+table+"`").Scan(&rows); err != nil {
			return CategoryChecks{}, fmt.Errorf("count A restored table %s: %w", table, err)
		}
		if rows < 0 {
			return CategoryChecks{}, fmt.Errorf("negative A restored count for %s", table)
		}
		if table == "cost_records" {
			actualCostRows = rows
		}
		category := tables[table].category
		appendRestoreCheck(&checks, category, restoreCheck(category+".restore_count."+table,
			"rows", want.Tables[i].Rows, rows, evidenceRef))
	}
	for _, rule := range restoreSafetyRules {
		var violations int64
		if err := tx.QueryRowContext(ctx, rule.query, rule.args...).Scan(&violations); err != nil {
			return CategoryChecks{}, fmt.Errorf("inspect A restore safety for %s: %w", rule.table, err)
		}
		if violations < 0 {
			return CategoryChecks{}, fmt.Errorf("negative A restore safety count for %s", rule.table)
		}
		appendRestoreCheck(&checks, rule.category, restoreCheck(rule.id, "violations", int64(0), violations, evidenceRef))
	}
	actualCostHash, err := readCostAggregateHash(ctx, tx, actualCostRows)
	if err != nil {
		return CategoryChecks{}, err
	}
	appendRestoreCheck(&checks, "ai_gateway", restoreCheck("ai_gateway.restore_cost_aggregates", "hash", want.CostAggregateSHA256, actualCostHash, evidenceRef))
	if err := v.Proof.RecheckReadOnlyTarget(ctx, tx, scope.registrySHA, scope.schemaSHA, evidenceRef); err != nil {
		return CategoryChecks{}, fmt.Errorf("A restore target final proof: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return CategoryChecks{}, fmt.Errorf("commit A restore read-only snapshot: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return CategoryChecks{}, err
	}
	for _, check := range append(checks.Users, checks.AIGateway...) {
		if check.Status != "passed" {
			return checks, ErrRestoreNormalizationMismatch
		}
	}
	return checks, nil
}

func appendRestoreCheck(checks *CategoryChecks, category string, check Check) {
	if category == "users" {
		checks.Users = append(checks.Users, check)
	} else {
		checks.AIGateway = append(checks.AIGateway, check)
	}
}

func restoreCheck(id, key string, expected, actual any, evidenceRef string) Check {
	check := compare(id, key, expected, actual, evidenceRef)
	if check.Status == "failed" {
		check.FailureCategory = "normalization_failed"
	}
	return check
}

func nilRestoreProof(proof RestoreTargetReadProofVerifier) bool {
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
