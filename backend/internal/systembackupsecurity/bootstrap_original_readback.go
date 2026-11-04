package systembackupsecurity

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
)

// ReadbackOriginalBootstrapCommit compares one retained original request. It
// never runs admission/KEK preparation, creates a config, repairs rows or
// grants retry authority. The authenticated installer caller owns its input.
func ReadbackOriginalBootstrapCommit(ctx context.Context, db *sql.DB, grant OfflineBootstrapGrant, config BootstrapConfig, expectedRequestHash string) (ConfigBootstrapResult, error) {
	var zero ConfigBootstrapResult
	if ctx == nil || ctx.Err() != nil || db == nil || !validBootstrapGrant(grant) || config.SHA256() != grant.ConfigSHA256 || !providerHashPattern.MatchString(expectedRequestHash) {
		return zero, ErrRegistrationCommitUnknown
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return zero, ErrRegistrationCommitUnknown
	}
	defer tx.Rollback()
	var op, actualHash, status string
	var version, httpStatus int64
	// Exact-key locking waits for an original in-flight COMMIT. Nothing here
	// acquires a new operation or interprets absence as permission to resend.
	if tx.QueryRowContext(ctx, `SELECT public_id,result_config_version,request_hash,status,http_status FROM system_backup_v2_operations WHERE origin_installation_id=? AND actor_type='admin' AND actor_id=? AND endpoint=? AND idempotency_key=? FOR SHARE`, grant.InstallationID, strconv.FormatInt(grant.UserID, 10), BootstrapConfigEndpoint, grant.IdempotencyKey).Scan(&op, &version, &actualHash, &status, &httpStatus) != nil || version != 1 || httpStatus != 201 || status != "succeeded" || actualHash != expectedRequestHash {
		return zero, ErrRegistrationCommitUnknown
	}
	var configHash, matrix string
	var activeVersion int64
	var enabled bool
	if tx.QueryRowContext(ctx, `SELECT c.config_sha256,s.active_config_version,c.enabled,s.matrix_key FROM system_backup_v2_installation_state s JOIN system_backup_v2_configs c ON c.origin_installation_id=s.origin_installation_id AND c.version=s.active_config_version WHERE s.origin_installation_id=? FOR SHARE`, grant.InstallationID).Scan(&configHash, &activeVersion, &enabled, &matrix) != nil || configHash != grant.ConfigSHA256 || activeVersion != 1 || enabled || matrix != grant.MatrixKey {
		return zero, ErrRegistrationCommitUnknown
	}
	// The production candidate branch uses the canonical snapshot column.
	// Reuse its exact full scalar/registry/reference/config comparison.
	if readbackOriginalBootstrapConfigValues(ctx, tx, grant, config) != nil || tx.Rollback() != nil {
		return zero, ErrRegistrationCommitUnknown
	}
	return ConfigBootstrapResult{OperationPublicID: op, Version: 1, ConfigSHA256: configHash, Replayed: true}, nil
}

// Preserve the original canonical config column codec and cell comparator,
// using shared locks for an inspection that neither changes nor admits data.
func readbackOriginalBootstrapConfigValues(ctx context.Context, tx *sql.Tx, g OfflineBootstrapGrant, c BootstrapConfig) error {
	columns, expected := c.sqlValuesWithCanonical(g.InstallationID, strconv.FormatInt(g.UserID, 10), g.ChangeReason)
	actual := make([]any, len(columns))
	dest := make([]any, len(columns))
	for n := range actual {
		dest[n] = &actual[n]
	}
	if tx.QueryRowContext(ctx, "SELECT "+strings.Join(columns, ",")+" FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=1 FOR SHARE", g.InstallationID).Scan(dest...) != nil {
		return ErrRegistrationCommitUnknown
	}
	for n, column := range columns {
		if !configMutationCellEqual(column, actual[n], expected[n], ConfigValues{snapshot: c}) {
			return ErrRegistrationCommitUnknown
		}
	}
	return nil
}
