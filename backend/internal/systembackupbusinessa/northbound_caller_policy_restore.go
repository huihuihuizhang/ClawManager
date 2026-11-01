package systembackupbusinessa

import (
	"encoding/json"
	"errors"
	"sort"
	"time"

	"clawreef/internal/models"
	"clawreef/internal/nbkeys"
)

// NorthboundCallerPolicyRestoreSource carries migration-057 columns and the
// explicit migration-066 extension. A nil APIKeysVersion means the old schema,
// not version zero; a current-schema reader must set it even when SQL stores 0.
// APIKeysJSON nil with a nonnil version means SQL NULL. The authenticated source
// schema must match this selection. Display-only username/email are not columns.
type NorthboundCallerPolicyRestoreSource struct {
	UserID         int
	Enabled        bool
	ScopesJSON     string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	UpdatedBy      *int
	APIKeysJSON    *string
	APIKeysVersion *int64
}

var ErrNorthboundCallerPolicyRestore = errors.New("A northbound caller policy restore normalization failed")

// NormalizeNorthboundCallerPoliciesForRestore requires a closed normalized
// users mapping and at most one source policy per user. It returns no partial
// target rows. B still proves the dump, target identity and SQL write rights.
func NormalizeNorthboundCallerPoliciesForRestore(users *UserRestoreBatch,
	sources []NorthboundCallerPolicyRestoreSource) ([]models.NorthboundCallerPolicy, error) {
	if users == nil {
		return nil, ErrNorthboundCallerPolicyRestore
	}
	rows := make([]models.NorthboundCallerPolicy, 0, len(sources))
	seenSource := make(map[int]struct{}, len(sources))
	seenTarget := make(map[int]struct{}, len(sources))
	for _, source := range sources {
		if _, duplicate := seenSource[source.UserID]; duplicate {
			return nil, ErrNorthboundCallerPolicyRestore
		}
		row, err := NormalizeNorthboundCallerPolicyForRestore(users, source)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seenTarget[row.UserID]; duplicate {
			return nil, ErrNorthboundCallerPolicyRestore
		}
		rows = append(rows, row)
		seenSource[source.UserID] = struct{}{}
		seenTarget[row.UserID] = struct{}{}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UserID < rows[j].UserID })
	return rows, nil
}

// NormalizeNorthboundCallerPolicyForRestore remaps both user references,
// validates every historical scope against the runtime allowlist and writes
// an inert policy. A target administrator must explicitly re-enable it.
func NormalizeNorthboundCallerPolicyForRestore(users *UserRestoreBatch,
	source NorthboundCallerPolicyRestoreSource) (models.NorthboundCallerPolicy, error) {
	created := source.CreatedAt.UTC().Truncate(time.Microsecond)
	updated := source.UpdatedAt.UTC().Truncate(time.Microsecond)
	if users == nil || source.UserID <= 0 || !validMySQLDateTime(created) ||
		!validMySQLDateTime(updated) || updated.Before(created) {
		return models.NorthboundCallerPolicy{}, ErrNorthboundCallerPolicyRestore
	}
	var disabledKeys *string
	var keyVersion int64
	if source.APIKeysVersion == nil {
		if source.APIKeysJSON != nil {
			return models.NorthboundCallerPolicy{}, ErrNorthboundCallerPolicyRestore
		}
	} else {
		keyVersion = *source.APIKeysVersion
		if keyVersion < 0 || (source.APIKeysJSON != nil && (len(*source.APIKeysJSON) > nbkeys.MaxDocumentBytes || !json.Valid([]byte(*source.APIKeysJSON)))) {
			return models.NorthboundCallerPolicy{}, ErrNorthboundCallerPolicyRestore
		}
		if _, err := nbkeys.Decode(source.APIKeysJSON); err != nil {
			return models.NorthboundCallerPolicy{}, ErrNorthboundCallerPolicyRestore
		}
		// Never carry a source hash into a target credential. This is the
		// existing isolated-copy rule, not key rotation or a successful CAS.
		// The source document/version stay in the protected original evidence.
		empty := "[]"
		disabledKeys = &empty
	}
	targetUserID, ok := users.TargetID(source.UserID)
	if !ok {
		return models.NorthboundCallerPolicy{}, ErrNorthboundCallerPolicyRestore
	}
	var targetUpdatedBy *int
	if source.UpdatedBy != nil {
		if *source.UpdatedBy <= 0 {
			return models.NorthboundCallerPolicy{}, ErrNorthboundCallerPolicyRestore
		}
		actorID, exists := users.TargetID(*source.UpdatedBy)
		if !exists {
			return models.NorthboundCallerPolicy{}, ErrNorthboundCallerPolicyRestore
		}
		targetUpdatedBy = &actorID
	}
	scopesJSON, err := normalizedNorthboundScopes(source.ScopesJSON)
	if err != nil {
		return models.NorthboundCallerPolicy{}, ErrNorthboundCallerPolicyRestore
	}
	var scopes []string
	if err := json.Unmarshal([]byte(scopesJSON), &scopes); err != nil || (source.Enabled && len(scopes) == 0) {
		return models.NorthboundCallerPolicy{}, ErrNorthboundCallerPolicyRestore
	}
	return models.NorthboundCallerPolicy{
		UserID: targetUserID, Enabled: false, ScopesJSON: scopesJSON,
		CreatedAt: created, UpdatedAt: updated, UpdatedBy: targetUpdatedBy,
		APIKeysJSON: disabledKeys, APIKeysVersion: keyVersion,
	}, nil
}
