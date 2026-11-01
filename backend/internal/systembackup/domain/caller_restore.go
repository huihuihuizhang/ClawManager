package domain

import (
	"context"
	"reflect"
	"strings"

	businessa "clawreef/internal/systembackupbusinessa"
)

// CallerPolicy066Normalizer consumes the current eight-column caller policy.
// Selection still requires the authenticated source/observed target schema pin
// through TableAdapter. This name alone neither authenticates nor grants writes.
const CallerPolicy066Normalizer = "northbound-caller-policy.066"

const caller066Columns = "user_id enabled scopes_json created_at updated_at updated_by api_keys_json api_keys_version"

func validateOwnerNormalizer(a TableAdapter, t Table) error {
	if a.Normalizer == LLMModel071Normalizer || a.Normalizer == LLMModelGrant062Normalizer {
		return validateModelAdapter(a, t)
	}
	if a.Normalizer == RoutingClassifier061Normalizer {
		return validateRouting061Adapter(a, t)
	}
	if a.Normalizer == NorthboundOperation077Normalizer {
		return validateOperation077Adapter(a, t)
	}
	if a.Normalizer != CallerPolicy066Normalizer || a.InterruptedAt != "" || t.Name != "northbound_caller_policies" || len(t.Columns) != 8 || len(t.PrimaryKey) != 1 || t.PrimaryKey[0] != "user_id" {
		return ErrSchema
	}
	for _, name := range strings.Fields(caller066Columns) {
		// Validate the original bytes, never a caller-supplied fixed/null/stub
		// replacement that could hide malformed history from the owner.
		if !hasColumn(t, name) || a.Columns[name] != "preserve" {
			return ErrSchema
		}
	}
	return nil
}

// The public SQL transaction preserves IDs across domains. Build the owner's
// closed identity map from actual captured users; do not invent missing fields
// or apply the separate business writer's user policy to this transaction.
func prepareCallerUsers(ctx context.Context, source Snapshot, adapters map[string]TableAdapter) (*businessa.UserRestoreBatch, error) {
	a, selected := adapters["northbound_caller_policies"]
	if !selected || a.Normalizer != CallerPolicy066Normalizer {
		return nil, nil
	}
	nonempty := false
	for _, t := range source.Tables {
		if t.Name == "northbound_caller_policies" && len(t.Rows) > 0 {
			if a.validate(t) != nil {
				return nil, ErrSchema
			}
			nonempty = true
		}
	}
	if !nonempty {
		return nil, nil
	}
	return callerUsersFromSnapshot(ctx, source)
}

func callerUsersFromSnapshot(ctx context.Context, source Snapshot) (*businessa.UserRestoreBatch, error) {
	var users []businessa.UserRestoreSource
	var mappings []businessa.UserRestoreMapping
	for _, t := range source.Tables {
		if t.Name != "users" {
			continue
		}
		for _, row := range t.Rows {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			var user businessa.UserRestoreSource
			if err := decodeOwnerCells(row, map[string]any{"id": &user.ID, "username": &user.Username, "email": &user.Email, "role": &user.Role, "created_at": &user.CreatedAt, "updated_at": &user.UpdatedAt}); err != nil {
				return nil, err
			}
			users = append(users, user)
			mappings = append(mappings, businessa.UserRestoreMapping{SourceID: user.ID, TargetID: user.ID, TargetUsername: user.Username, TargetEmail: user.Email})
		}
	}
	batch, err := businessa.NormalizeUsersForRestore(users, mappings)
	if err != nil {
		return nil, ErrData
	}
	return batch, nil
}

// VerifyCallerQuarantine checks the expected projection before independent SQL
// readback. An encrypted expected file alone is not evidence that keys are inert.
// No schema pins or write authority are created by this semantic check.
func VerifyCallerQuarantine(ctx context.Context, snapshot Snapshot) error {
	for _, t := range snapshot.Tables {
		if t.Name != "northbound_caller_policies" || len(t.Rows) == 0 {
			continue
		}
		if len(t.Columns) != 8 || len(t.PrimaryKey) != 1 || t.PrimaryKey[0] != "user_id" {
			return ErrSchema
		}
		for _, name := range strings.Fields(caller066Columns) {
			if !hasColumn(t, name) {
				return ErrSchema
			}
		}
		users, err := callerUsersFromSnapshot(ctx, snapshot)
		if err != nil {
			return err
		}
		for _, row := range t.Rows {
			if err := ctx.Err(); err != nil {
				return err
			}
			if row["enabled"].Null || row["enabled"].String() != "0" || row["api_keys_json"].Null || row["api_keys_json"].String() != "[]" {
				return ErrNormalization
			}
			if err := normalizeCaller066(cloneRow(row), users); err != nil {
				return err
			}
		}
	}
	return nil
}

// Only explicitly named fields are projected; model additions are not an
// allowlist. Raw archived cells remain the source of all unchanged writes.
func decodeOwnerCells(row Row, fields map[string]any) error {
	for name, ptr := range fields {
		cell, ok := row[name]
		if !ok {
			return ErrSchema
		}
		if err := skillCell(reflect.ValueOf(ptr).Elem(), cell); err != nil {
			return err
		}
	}
	return nil
}

func normalizeCaller066(row Row, users *businessa.UserRestoreBatch) error {
	var source businessa.NorthboundCallerPolicyRestoreSource
	var version int64 // Explicitly current schema, including version zero.
	if err := decodeOwnerCells(row, map[string]any{
		"user_id": &source.UserID, "enabled": &source.Enabled, "scopes_json": &source.ScopesJSON,
		"created_at": &source.CreatedAt, "updated_at": &source.UpdatedAt, "updated_by": &source.UpdatedBy,
		"api_keys_json": &source.APIKeysJSON, "api_keys_version": &version,
	}); err != nil {
		return err
	}
	source.APIKeysVersion = &version
	normalized, err := businessa.NormalizeNorthboundCallerPolicyForRestore(users, source)
	if err != nil {
		return ErrData
	}
	row["enabled"] = Text("0")
	row["api_keys_json"] = Text(*normalized.APIKeysJSON)
	// The owner validates scopes without changing their meaning. Preserve the
	// captured MySQL JSON rendering: compacting it would differ from MySQL's
	// rendering on independent readback. IDs, actor, times/version stay exact too.
	return nil
}
