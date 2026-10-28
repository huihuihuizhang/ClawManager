package systembackupread

import (
	"context"
	"database/sql"
)

// ConfigPageRequest is an authenticated internal keyset position. A zero
// cutoff starts a new sequence; subsequent positions come only from a signed
// cursor and are checked again against current read authority.
type ConfigPageRequest struct {
	InstallationID string
	Limit          int
	CutoffVersion  uint64
	BeforeVersion  uint64
}

type ConfigPage struct {
	Items          []ConfigSnapshot
	InstallationID string
	CutoffVersion  uint64
	BeforeVersion  uint64
	HasMore        bool
}

func (ConfigPage) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

func (r *Reader) ListConfigVersions(ctx context.Context, request ConfigPageRequest) (ConfigPage, error) {
	if r == nil || r.db == nil || nilScope(r.scope) || ctx == nil || ctx.Err() != nil {
		return ConfigPage{}, ErrDenied
	}
	if request.Limit < 1 || request.Limit > 500 ||
		request.CutoffVersion == 0 && (request.BeforeVersion != 0 || request.InstallationID != "") ||
		request.CutoffVersion != 0 && (!installationID.MatchString(request.InstallationID) ||
			request.CutoffVersion > maxJSONSafeInteger || request.BeforeVersion == 0 ||
			request.BeforeVersion > request.CutoffVersion) {
		return ConfigPage{}, ErrInvalid
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return ConfigPage{}, ErrUnavailable
	}
	defer tx.Rollback()
	installation, err := r.scope.AuthorizeRead(ctx, tx)
	if err != nil {
		return ConfigPage{}, scopeReadFailure(err)
	}
	if !installationID.MatchString(installation) {
		return ConfigPage{}, ErrDenied
	}
	if request.InstallationID != "" && request.InstallationID != installation {
		return ConfigPage{}, ErrDenied
	}
	query := `SELECT c.schema_version,c.origin_installation_id,c.version,c.row_version,
  c.config_sha256,c.config_size_bytes,c.canonical_config_json,c.created_by,c.change_reason,c.created_at,
  s.active_config_version,s.last_effective_enabled,` + configMaterializedSelect() + `
FROM system_backup_v2_installation_state AS s
JOIN system_backup_v2_configs AS c ON c.origin_installation_id=s.origin_installation_id
WHERE s.origin_installation_id=? ORDER BY c.version DESC LIMIT ? FOR SHARE`
	args := []any{installation, request.Limit + 1}
	if request.CutoffVersion != 0 {
		query = `SELECT c.schema_version,c.origin_installation_id,c.version,c.row_version,
  c.config_sha256,c.config_size_bytes,c.canonical_config_json,c.created_by,c.change_reason,c.created_at,
  s.active_config_version,s.last_effective_enabled,` + configMaterializedSelect() + `
FROM system_backup_v2_installation_state AS s
JOIN system_backup_v2_configs AS c ON c.origin_installation_id=s.origin_installation_id
WHERE s.origin_installation_id=? AND c.version<=? AND c.version<?
ORDER BY c.version DESC LIMIT ? FOR SHARE`
		args = []any{installation, request.CutoffVersion, request.BeforeVersion, request.Limit + 1}
	}
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return ConfigPage{}, ErrUnavailable
	}
	defer rows.Close()
	page := ConfigPage{Items: make([]ConfigSnapshot, 0, request.Limit), InstallationID: installation,
		CutoffVersion: request.CutoffVersion}
	var prior uint64
	for rows.Next() {
		row, err := scanConfigSnapshot(rows, installation)
		if err != nil || prior != 0 && row.version >= prior ||
			request.CutoffVersion != 0 && (row.version > request.CutoffVersion || row.version >= request.BeforeVersion) {
			return ConfigPage{}, ErrUnavailable
		}
		if page.CutoffVersion == 0 {
			page.CutoffVersion = row.version
		}
		prior = row.version
		if len(page.Items) == request.Limit {
			page.HasMore = true
			break
		}
		page.Items = append(page.Items, row)
	}
	if err := rows.Close(); err != nil {
		return ConfigPage{}, ErrUnavailable
	}
	if err := rows.Err(); err != nil {
		return ConfigPage{}, ErrUnavailable
	}
	if page.HasMore {
		page.BeforeVersion = page.Items[len(page.Items)-1].version
	}
	if err := r.scope.RecheckRead(ctx, tx, installation); err != nil {
		return ConfigPage{}, scopeReadFailure(err)
	}
	if err := tx.Commit(); err != nil || ctx.Err() != nil {
		return ConfigPage{}, ErrUnavailable
	}
	for i := range page.Items {
		page.Items[i].canonical = append([]byte(nil), page.Items[i].canonical...)
	}
	return page, nil
}
