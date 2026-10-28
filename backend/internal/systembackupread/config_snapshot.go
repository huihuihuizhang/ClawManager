package systembackupread

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
	"unicode/utf8"
)

// ConfigSnapshot is an internal, authorized row, not a ConfigResource wire DTO.
// The canonical bytes still require closed-schema review before projection.
type ConfigSnapshot struct {
	installationID string
	version        uint64
	rowVersion     uint64
	configSHA256   string
	canonical      []byte
	active         bool
	effective      bool
	createdBy      string
	changeReason   sql.NullString
	createdAt      time.Time
}

type configScanner interface{ Scan(...any) error }

func (ConfigSnapshot) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// ReadActiveConfig requires the candidate canonical_config_json column. On
// existing schema, a missing column fails closed as ErrUnavailable. The scope
// provider must check current system_backup.read authority and hold its
// authorization boundary through the final recheck and transaction commit.
func (r *Reader) ReadActiveConfig(ctx context.Context) (ConfigSnapshot, error) {
	return r.readConfig(ctx, 0)
}

// ReadConfigVersion selects an exact historical version under the same
// installation and authority boundary as the active read. A historical row
// is never reported as effectively enabled.
func (r *Reader) ReadConfigVersion(ctx context.Context, version uint64) (ConfigSnapshot, error) {
	if version == 0 || version > maxJSONSafeInteger {
		return ConfigSnapshot{}, ErrInvalid
	}
	return r.readConfig(ctx, version)
}

func (r *Reader) readConfig(ctx context.Context, selectedVersion uint64) (ConfigSnapshot, error) {
	if r == nil || r.db == nil || nilScope(r.scope) || ctx == nil || ctx.Err() != nil {
		return ConfigSnapshot{}, ErrDenied
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return ConfigSnapshot{}, ErrUnavailable
	}
	defer tx.Rollback()
	installation, err := r.scope.AuthorizeRead(ctx, tx)
	if err != nil {
		return ConfigSnapshot{}, scopeReadFailure(err)
	}
	if !installationID.MatchString(installation) {
		return ConfigSnapshot{}, ErrDenied
	}
	query := `SELECT c.schema_version,c.origin_installation_id,c.version,c.row_version,
  c.config_sha256,c.config_size_bytes,c.canonical_config_json,c.created_by,c.change_reason,c.created_at,
  s.active_config_version,s.last_effective_enabled,` + configMaterializedSelect() + `
FROM system_backup_v2_installation_state AS s
JOIN system_backup_v2_configs AS c
	ON c.origin_installation_id=s.origin_installation_id
WHERE s.origin_installation_id=? AND c.version=s.active_config_version FOR SHARE`
	args := []any{installation}
	if selectedVersion != 0 {
		query = `SELECT c.schema_version,c.origin_installation_id,c.version,c.row_version,
  c.config_sha256,c.config_size_bytes,c.canonical_config_json,c.created_by,c.change_reason,c.created_at,
  s.active_config_version,s.last_effective_enabled,` + configMaterializedSelect() + `
FROM system_backup_v2_installation_state AS s
JOIN system_backup_v2_configs AS c ON c.origin_installation_id=s.origin_installation_id
WHERE s.origin_installation_id=? AND c.version=? FOR SHARE`
		args = append(args, selectedVersion)
	}
	result, err := scanConfigSnapshot(tx.QueryRowContext(ctx, query, args...), installation)
	missing := errors.Is(err, sql.ErrNoRows)
	if err != nil && !missing {
		return ConfigSnapshot{}, ErrUnavailable
	}
	if !missing && (selectedVersion == 0 && !result.active || selectedVersion != 0 && result.version != selectedVersion) {
		return ConfigSnapshot{}, ErrUnavailable
	}
	if err := r.scope.RecheckRead(ctx, tx, installation); err != nil {
		return ConfigSnapshot{}, scopeReadFailure(err)
	}
	if err := tx.Commit(); err != nil || ctx.Err() != nil {
		return ConfigSnapshot{}, ErrUnavailable
	}
	if missing {
		return ConfigSnapshot{}, ErrNotFound
	}
	result.canonical = append([]byte(nil), result.canonical...)
	return result, nil
}

func scanConfigSnapshot(scanner configScanner, installation string) (ConfigSnapshot, error) {
	var result ConfigSnapshot
	var schemaVersion string
	var size int64
	var activeVersion uint64
	var lastEffective bool
	materialized := make([]any, len(configMaterializedColumns))
	scan := []any{
		&schemaVersion, &result.installationID, &result.version, &result.rowVersion,
		&result.configSHA256, &size, &result.canonical, &result.createdBy,
		&result.changeReason, &result.createdAt, &activeVersion, &lastEffective,
	}
	for i := range materialized {
		scan = append(scan, &materialized[i])
	}
	if err := scanner.Scan(scan...); err != nil {
		return ConfigSnapshot{}, err
	}
	result.active = result.version == activeVersion
	result.effective = result.active && lastEffective
	if activeVersion == 0 || activeVersion > maxJSONSafeInteger ||
		!validConfigSnapshot(result, installation, schemaVersion, size) ||
		!configMaterializedMatch(result.canonical, materialized) {
		return ConfigSnapshot{}, ErrUnavailable
	}
	return result, nil
}

func validConfigSnapshot(row ConfigSnapshot, installation, schemaVersion string, size int64) bool {
	if schemaVersion != "system-backup-config.v1" || row.installationID != installation ||
		row.version == 0 || row.version > maxJSONSafeInteger ||
		row.rowVersion == 0 || row.rowVersion > maxJSONSafeInteger ||
		size < 2 || size > 262144 || int64(len(row.canonical)) != size ||
		!taskHash.MatchString(row.configSHA256) || !utf8.Valid(row.canonical) ||
		!json.Valid(row.canonical) || row.canonical[0] != '{' ||
		row.canonical[len(row.canonical)-1] != '}' ||
		len(row.createdBy) == 0 || len(row.createdBy) > 128 ||
		row.changeReason.Valid && (len(row.changeReason.String) == 0 || len(row.changeReason.String) > 512) ||
		row.createdAt.IsZero() || row.effective && !row.active {
		return false
	}
	digest := sha256.Sum256(row.canonical)
	return hex.EncodeToString(digest[:]) == row.configSHA256
}
