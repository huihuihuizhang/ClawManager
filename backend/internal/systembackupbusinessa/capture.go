// Package systembackupbusinessa defines A's users and AI Gateway backup scope.
// It only collects redacted source counts; B's capture certificate must bind
// these counts to a dump before they can be used as backup evidence.
package systembackupbusinessa

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
)

type tablePolicy struct {
	category       string
	classification string
}

// This set is intentionally closed. A new business table needs an explicit
// plan, registry, reviewer and collector change before it can be captured.
var tables = map[string]tablePolicy{
	"users":                          {"users", "confidential"},
	"user_quotas":                    {"users", "confidential"},
	"enterprise_auth_settings":       {"users", "secret"},
	"northbound_auth_challenges":     {"users", "secret"},
	"northbound_sessions":            {"users", "secret"},
	"northbound_caller_policies":     {"users", "confidential"},
	"llm_models":                     {"ai_gateway", "secret"},
	"model_invocations":              {"ai_gateway", "confidential"},
	"audit_events":                   {"ai_gateway", "confidential"},
	"cost_records":                   {"ai_gateway", "confidential"},
	"risk_rules":                     {"ai_gateway", "internal"},
	"risk_hits":                      {"ai_gateway", "confidential"},
	"chat_sessions":                  {"ai_gateway", "confidential"},
	"chat_messages":                  {"ai_gateway", "confidential"},
	"instance_gateway_token_aliases": {"ai_gateway", "secret"},
}

var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var evidencePattern = regexp.MustCompile(`^sev_[A-Za-z0-9_-]+$`)

// CaptureScope is the immutable result of matching a frozen registry to an
// independently reviewed deployment digest. Its fields cannot be changed by
// a caller after construction.
type CaptureScope struct {
	tables      []string
	registrySHA string
	schemaSHA   string
}

// NewPinnedCaptureScope is the only construction path for a collector or
// verifier scope. expectedSHA256 must come from trusted deployment state,
// never from the registry bytes or task request being checked.
func NewPinnedCaptureScope(registryJSON []byte, expectedSHA256 string) (*CaptureScope, error) {
	if !hashPattern.MatchString(expectedSHA256) {
		return nil, errors.New("invalid A business registry pin")
	}
	digest := sha256.Sum256(registryJSON)
	if hex.EncodeToString(digest[:]) != expectedSHA256 {
		return nil, errors.New("A business registry pin mismatch")
	}
	tableNames, schemaSHA, err := parseCaptureTableAllowlist(registryJSON)
	if err != nil {
		return nil, err
	}
	return &CaptureScope{tables: tableNames, registrySHA: expectedSHA256, schemaSHA: schemaSHA}, nil
}

// RegistrySHA256 and SchemaSHA256 identify the pinned registry bytes and its
// observed source schema. They are metadata, not a capture certificate.
func (s *CaptureScope) RegistrySHA256() string {
	if s == nil {
		return ""
	}
	return s.registrySHA
}

func (s *CaptureScope) SchemaSHA256() string {
	if s == nil {
		return ""
	}
	return s.schemaSHA
}

func (s *CaptureScope) Tables() []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s.tables...)
}

type registry struct {
	Kind            string `json:"kind"`
	RegistryVersion string `json:"registry_version"`
	ContractVersion string `json:"contract_version"`
	ContractStatus  string `json:"contract_status"`
	SchemaHash      struct {
		Algorithm string  `json:"algorithm"`
		Status    string  `json:"status"`
		Hash      *string `json:"hash"`
		Evidence  *struct {
			PublicID string `json:"public_id"`
			SHA256   string `json:"sha256"`
		} `json:"evidence"`
	} `json:"schema_hash"`
	Summary struct {
		ObjectCount        int `json:"object_count"`
		PolicyRecorded     int `json:"policy_recorded"`
		PolicyPending      int `json:"policy_pending"`
		CrossReviewPending int `json:"cross_review_pending"`
	} `json:"summary"`
	Objects []struct {
		ObjectType             string   `json:"object_type"`
		Name                   string   `json:"name"`
		Owner                  string   `json:"owner"`
		Category               string   `json:"category"`
		Classification         *string  `json:"data_classification"`
		BackupStrategy         string   `json:"backup_strategy"`
		RestoreStrategy        string   `json:"restore_strategy"`
		NormalizerID           string   `json:"normalizer_id"`
		VerifierID             string   `json:"verifier_id"`
		DecisionStatus         string   `json:"decision_status"`
		RequiredCrossReviewers []string `json:"required_cross_reviewers"`
		ApprovedCrossReviewers []string `json:"approved_cross_reviewers"`
	} `json:"objects"`
}

// parseCaptureTableAllowlist validates registry structure. It alone does not
// establish provenance; only NewPinnedCaptureScope can authorize SQL use.
func parseCaptureTableAllowlist(registryJSON []byte) ([]string, string, error) {
	var r registry
	if err := json.Unmarshal(registryJSON, &r); err != nil {
		return nil, "", fmt.Errorf("decode schema registry: %w", err)
	}
	if r.Kind != "system_backup_schema_registry" || r.RegistryVersion != "system-backup-schema-registry.v1" ||
		r.ContractVersion != "system-backup-plan.v12" || r.ContractStatus != "frozen" {
		return nil, "", errors.New("A business capture requires frozen v12 schema registry")
	}
	if r.SchemaHash.Algorithm != "sha256-information-schema-canonical-v1" || r.SchemaHash.Status != "observed" ||
		r.SchemaHash.Hash == nil || !hashPattern.MatchString(*r.SchemaHash.Hash) || r.SchemaHash.Evidence == nil ||
		!evidencePattern.MatchString(r.SchemaHash.Evidence.PublicID) || !hashPattern.MatchString(r.SchemaHash.Evidence.SHA256) {
		return nil, "", errors.New("A business capture requires observed schema evidence")
	}
	if r.Summary.ObjectCount != len(r.Objects) || r.Summary.PolicyRecorded != len(r.Objects) ||
		r.Summary.PolicyPending != 0 || r.Summary.CrossReviewPending != 0 {
		return nil, "", errors.New("A business capture requires complete registry summary")
	}
	seenObjects := make(map[string]struct{}, len(r.Objects))
	seenTables := make(map[string]struct{}, len(tables))
	for _, object := range r.Objects {
		key := object.ObjectType + ":" + object.Name
		if object.ObjectType == "" || object.Name == "" {
			return nil, "", errors.New("unnamed schema object")
		}
		if _, exists := seenObjects[key]; exists {
			return nil, "", fmt.Errorf("duplicate schema object %s", key)
		}
		seenObjects[key] = struct{}{}
		if object.DecisionStatus != "frozen" || !reviewed(object.Owner, object.RequiredCrossReviewers, object.ApprovedCrossReviewers) {
			return nil, "", fmt.Errorf("unfrozen or unreviewed schema object %s", key)
		}
		policy, named := tables[object.Name]
		inCategory := object.Category == "users" || object.Category == "ai_gateway"
		// Other A-owned categories, such as system control objects, are outside
		// this collector. A table name or category collision must still fail.
		if !named && !inCategory {
			continue
		}
		if !named || object.ObjectType != "table" || object.Owner != "A" || object.Category != policy.category ||
			object.Classification == nil || *object.Classification != policy.classification ||
			object.BackupStrategy != "mysql_dump" || object.RestoreStrategy != "normalize" ||
			object.NormalizerID != policy.category+"."+object.Name+".normalize.v1" ||
			object.VerifierID != policy.category+"."+object.Name+".verify.v1" || len(object.RequiredCrossReviewers) == 0 {
			return nil, "", fmt.Errorf("A business capture policy mismatch at %s", key)
		}
		seenTables[object.Name] = struct{}{}
	}
	if len(seenTables) != len(tables) {
		return nil, "", fmt.Errorf("A business capture scope incomplete: %d of %d tables", len(seenTables), len(tables))
	}
	result := make([]string, 0, len(tables))
	for table := range seenTables {
		result = append(result, table)
	}
	sort.Strings(result)
	return result, *r.SchemaHash.Hash, nil
}

func reviewed(owner string, required, approved []string) bool {
	valid := func(role string) bool { return role == "A" || role == "B" || role == "C" || role == "D" }
	if !valid(owner) || len(required) != len(approved) {
		return false
	}
	want := make(map[string]struct{}, len(required))
	for _, role := range required {
		if !valid(role) || role == owner {
			return false
		}
		if _, duplicate := want[role]; duplicate {
			return false
		}
		want[role] = struct{}{}
	}
	seen := make(map[string]struct{}, len(approved))
	for _, role := range approved {
		if _, expected := want[role]; !expected {
			return false
		}
		if _, duplicate := seen[role]; duplicate {
			return false
		}
		seen[role] = struct{}{}
	}
	return true
}

// TableCount contains no business row contents, identifiers or secret values.
type TableCount struct {
	Table string `json:"table"`
	Rows  int64  `json:"rows"`
}

// SourceSnapshot is a single source transaction's redacted counts and cost
// aggregate digest. The digest is required even for empty cost_records. This
// is not proof that a dump captured those rows or used the same checkpoint.
type SourceSnapshot struct {
	Tables              []TableCount `json:"tables"`
	CostAggregateSHA256 string       `json:"cost_aggregate_sha256"`
}

type SQLCountCollector struct{ DB *sql.DB }

// CollectSnapshot returns no partial result if any table or transaction fails.
func (c SQLCountCollector) CollectSnapshot(ctx context.Context, scope *CaptureScope) (SourceSnapshot, error) {
	if ctx == nil {
		return SourceSnapshot{}, errors.New("nil A business snapshot context")
	}
	if err := ctx.Err(); err != nil {
		return SourceSnapshot{}, err
	}
	if scope == nil || len(scope.tables) != len(tables) || !hashPattern.MatchString(scope.registrySHA) || !hashPattern.MatchString(scope.schemaSHA) {
		return SourceSnapshot{}, errors.New("A business pinned scope required")
	}
	if c.DB == nil {
		return SourceSnapshot{}, errors.New("nil A business database")
	}
	tx, err := c.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return SourceSnapshot{}, fmt.Errorf("begin A business snapshot: %w", err)
	}
	defer tx.Rollback()
	snapshot := SourceSnapshot{Tables: make([]TableCount, 0, len(scope.tables))}
	var total int64
	for _, table := range scope.tables {
		var engine string
		if err := tx.QueryRowContext(ctx, `SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND TABLE_TYPE = 'BASE TABLE'`, table).Scan(&engine); err != nil {
			return SourceSnapshot{}, fmt.Errorf("inspect A business table %s: %w", table, err)
		}
		if !strings.EqualFold(engine, "InnoDB") {
			return SourceSnapshot{}, fmt.Errorf("A business table %s is not transactional InnoDB", table)
		}
		// Table identifiers come exclusively from the closed allowlist above.
		var rows int64
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM `"+table+"`").Scan(&rows); err != nil {
			return SourceSnapshot{}, fmt.Errorf("count A business table %s: %w", table, err)
		}
		if rows < 0 || rows > math.MaxInt64-total {
			return SourceSnapshot{}, fmt.Errorf("invalid A business count for %s", table)
		}
		total += rows
		snapshot.Tables = append(snapshot.Tables, TableCount{Table: table, Rows: rows})
	}
	snapshot.CostAggregateSHA256, err = readCostAggregateHash(ctx, tx, snapshotCostRows(snapshot))
	if err != nil {
		return SourceSnapshot{}, err
	}
	if err := tx.Commit(); err != nil {
		return SourceSnapshot{}, fmt.Errorf("commit A business snapshot: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return SourceSnapshot{}, err
	}
	return snapshot, nil
}
