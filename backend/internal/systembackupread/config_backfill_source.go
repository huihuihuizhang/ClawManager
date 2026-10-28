package systembackupread

import (
	"context"
	"database/sql"
	"errors"
)

// VerifiedConfigBackfillSource is an internal receipt for exact original
// canonical bytes. It cannot be serialized or used as an Admin response.
// A later reviewed migration writer may use the private byte copy only after
// rechecking the same row in its own transaction.
type VerifiedConfigBackfillSource struct {
	installationID string
	version        uint64
	configSHA256   string
	canonical      []byte
}

func (VerifiedConfigBackfillSource) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// VerifyConfigBackfillSource works against the current 066 table, before the
// candidate canonical_config_json column exists. It is read-only: an exact
// original source must match the stored hash, size and every materialized
// ConfigValues column for the caller's freshly authorized installation.
func (r *Reader) VerifyConfigBackfillSource(ctx context.Context, version uint64, source []byte) (VerifiedConfigBackfillSource, error) {
	if r == nil || r.db == nil || nilScope(r.scope) || ctx == nil || ctx.Err() != nil {
		return VerifiedConfigBackfillSource{}, ErrDenied
	}
	if version == 0 || version > maxJSONSafeInteger || len(source) < 2 || len(source) > 262144 {
		return VerifiedConfigBackfillSource{}, ErrInvalid
	}
	// Freeze the original before validation or any SQL/authority callback. A
	// caller-owned buffer must not replace the bytes after their hash/columns
	// have already been verified, including during the final read recheck.
	source = append([]byte(nil), source...)
	if _, ok := validConfigValues(source); !ok {
		return VerifiedConfigBackfillSource{}, ErrInvalid
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return VerifiedConfigBackfillSource{}, ErrUnavailable
	}
	defer tx.Rollback()
	installation, err := r.scope.AuthorizeRead(ctx, tx)
	if err != nil {
		return VerifiedConfigBackfillSource{}, scopeReadFailure(err)
	}
	if !installationID.MatchString(installation) {
		return VerifiedConfigBackfillSource{}, ErrDenied
	}
	query := `SELECT c.schema_version,c.origin_installation_id,c.version,c.row_version,
  c.config_sha256,c.config_size_bytes,c.created_by,c.change_reason,c.created_at,` + configMaterializedSelect() + `
FROM system_backup_v2_configs AS c
WHERE c.origin_installation_id=? AND c.version=? FOR SHARE`
	var row ConfigSnapshot
	var schemaVersion string
	var size int64
	stored := make([]any, len(configMaterializedColumns))
	scan := []any{&schemaVersion, &row.installationID, &row.version, &row.rowVersion,
		&row.configSHA256, &size, &row.createdBy, &row.changeReason, &row.createdAt}
	for i := range stored {
		scan = append(scan, &stored[i])
	}
	err = tx.QueryRowContext(ctx, query, installation, version).Scan(scan...)
	missing := errors.Is(err, sql.ErrNoRows)
	if err != nil && !missing {
		return VerifiedConfigBackfillSource{}, ErrUnavailable
	}
	if !missing {
		row.canonical = source
		if row.version != version || !validConfigSnapshot(row, installation, schemaVersion, size) ||
			!configMaterializedMatch(source, stored) {
			return VerifiedConfigBackfillSource{}, ErrUnavailable
		}
	}
	if err := r.scope.RecheckRead(ctx, tx, installation); err != nil {
		return VerifiedConfigBackfillSource{}, scopeReadFailure(err)
	}
	if err := tx.Commit(); err != nil || ctx.Err() != nil {
		return VerifiedConfigBackfillSource{}, ErrUnavailable
	}
	if missing {
		return VerifiedConfigBackfillSource{}, ErrNotFound
	}
	return VerifiedConfigBackfillSource{installationID: installation, version: version,
		configSHA256: row.configSHA256, canonical: append([]byte(nil), source...)}, nil
}
