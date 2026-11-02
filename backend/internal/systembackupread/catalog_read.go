package systembackupread

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	contract "clawreef/internal/systembackupcontract"
)

// Candidate comparison data comes only from the authenticated installation's
// existing backup registration. C must independently verify its native object.
type CatalogRecordControl struct {
	Task                               TaskHeader
	RegistrationID, RegistrationSHA256 string
}

func (CatalogRecordControl) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

type CatalogRecordReader interface {
	Catalog(context.Context, CurrentFactsSQL, CatalogRecordControl) (contract.CatalogRecordResource, time.Time, error)
}

const catalogCursorDomain = "system-backup-local-catalog-page.v1\x00"

type CatalogCursorCodec struct{ key []byte }
type catalogCursor struct {
	Installation   string `json:"installation"`
	Limit          int    `json:"limit"`
	Cutoff, Before uint64
}

func NewCatalogCursorCodec(key []byte) (*CatalogCursorCodec, error) {
	if len(key) < 32 {
		return nil, ErrInvalid
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte(catalogCursorDomain + "derived-key"))
	return &CatalogCursorCodec{key: h.Sum(nil)}, nil
}

func (c *CatalogCursorCodec) encode(p catalogCursor) (string, error) {
	if c == nil || len(c.key) != 32 || !installationID.MatchString(p.Installation) || p.Limit < 1 || p.Limit > 500 || p.Before == 0 || p.Before > p.Cutoff {
		return "", ErrInvalid
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return "", ErrInvalid
	}
	h := hmac.New(sha256.New, c.key)
	h.Write([]byte(catalogCursorDomain))
	h.Write(raw)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

func (c *CatalogCursorCodec) decode(token string, limit int) (catalogCursor, error) {
	var p catalogCursor
	if c == nil || len(c.key) != 32 || len(token) > 4096 {
		return p, ErrInvalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return p, ErrInvalid
	}
	raw, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil {
		return p, ErrInvalid
	}
	sig, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil {
		return p, ErrInvalid
	}
	h := hmac.New(sha256.New, c.key)
	h.Write([]byte(catalogCursorDomain))
	h.Write(raw)
	if !hmac.Equal(sig, h.Sum(nil)) || json.Unmarshal(raw, &p) != nil || p.Limit != limit {
		return catalogCursor{}, ErrInvalid
	}
	canonical, e := c.encode(p)
	if e != nil || canonical != token {
		return catalogCursor{}, ErrInvalid
	}
	return p, nil
}

func validCatalogRecordID(id string) bool {
	return len(id) == 40 && strings.HasPrefix(id, "scr_") && taskUUID.MatchString(id[4:])
}

// This deliberately lists this installation's existing local registrations,
// not unindexed foreign/native records. Mutable status filters are eventual.
func (r *Reader) ListCatalogRecordsCurrentV1(ctx context.Context, limit int, token string, codec *CatalogCursorCodec, provider CatalogRecordReader) (contract.CatalogRecordList, error) {
	return r.readCatalogRecordsCurrent(ctx, limit, token, "", codec, provider)
}

func (r *Reader) ReadCatalogRecordCurrentV1(ctx context.Context, id string, provider CatalogRecordReader) (contract.CatalogRecordResource, error) {
	if !validCatalogRecordID(id) {
		return contract.CatalogRecordResource{}, ErrInvalid
	}
	page, e := r.readCatalogRecordsCurrent(ctx, 1, "", id, nil, provider)
	if e != nil {
		return contract.CatalogRecordResource{}, e
	}
	if len(page.Items) != 1 {
		return contract.CatalogRecordResource{}, ErrNotFound
	}
	return page.Items[0], nil
}

func (r *Reader) readCatalogRecordsCurrent(ctx context.Context, limit int, token, id string, codec *CatalogCursorCodec, provider CatalogRecordReader) (contract.CatalogRecordList, error) {
	var zero contract.CatalogRecordList
	if r == nil || r.db == nil || nilScope(r.scope) || ctx == nil || ctx.Err() != nil {
		return zero, ErrDenied
	}
	if missingCurrent(provider) || id == "" && codec == nil {
		return zero, ErrUnavailable
	}
	if limit < 1 || limit > 500 {
		return zero, ErrInvalid
	}
	var position catalogCursor
	var err error
	if token != "" {
		position, err = codec.decode(token, limit)
		if err != nil {
			return zero, err
		}
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return zero, ErrUnavailable
	}
	defer tx.Rollback()
	installation, err := r.scope.AuthorizeRead(ctx, tx)
	if err != nil {
		return zero, scopeReadFailure(err)
	}
	if !installationID.MatchString(installation) || position.Installation != "" && position.Installation != installation {
		return zero, ErrDenied
	}
	if position.Cutoff == 0 {
		if tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(id),0) FROM system_backup_v2_backups WHERE origin_installation_id=?`, installation).Scan(&position.Cutoff) != nil {
			return zero, ErrUnavailable
		}
	}
	position.Installation, position.Limit = installation, limit
	query := `SELECT id,public_id,row_version,config_version,artifact_registration_id,artifact_registration_hash FROM system_backup_v2_backups WHERE origin_installation_id=? AND id<=? AND (?=0 OR id<?) AND status='succeeded' AND artifact_state='committed' AND artifact_registration_id IS NOT NULL AND artifact_registration_hash IS NOT NULL`
	args := []any{installation, position.Cutoff, position.Before, position.Before}
	if id != "" {
		query += ` AND artifact_registration_id=?`
		args = append(args, id)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return zero, ErrUnavailable
	}
	var candidates []CatalogRecordControl
	var previous uint64
	for rows.Next() {
		var row CatalogRecordControl
		if rows.Scan(&row.Task.ID, &row.Task.PublicID, &row.Task.RowVersion, &row.Task.ConfigVersion, &row.RegistrationID, &row.RegistrationSHA256) != nil || !validCatalogRecordID(row.RegistrationID) || !taskHash.MatchString(row.RegistrationSHA256) || row.Task.ID == 0 || row.Task.ID > position.Cutoff || previous != 0 && row.Task.ID >= previous || row.Task.RowVersion == 0 || row.Task.ConfigVersion == 0 || !strings.HasPrefix(row.Task.PublicID, "sbk_") || len(row.Task.PublicID) != 40 || !taskUUID.MatchString(row.Task.PublicID[4:]) {
			rows.Close()
			return zero, ErrUnavailable
		}
		row.Task.InstallationID, row.Task.Kind, row.Task.Status = installation, BackupTask, "succeeded"
		previous = row.Task.ID
		candidates = append(candidates, row)
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil || closeErr != nil || id != "" && len(candidates) > 1 {
		return zero, ErrUnavailable
	}
	out := contract.CatalogRecordList{Items: []contract.CatalogRecordResource{}, Consistency: "eventual"}
	hasMore := len(candidates) > limit
	if hasMore {
		candidates = candidates[:limit]
	}
	var until time.Time
	for _, candidate := range candidates {
		entryCtx := ctx
		cancel := func() {}
		if !until.IsZero() {
			entryCtx, cancel = context.WithDeadline(ctx, until)
		}
		capability := &currentFactsQuery{ctx: entryCtx, q: detailReadTx{tx}}
		item, bound, e := provider.Catalog(entryCtx, capability, candidate)
		capability.close()
		cancel()
		sum := sha256.Sum256(item.Record)
		if e != nil || item.ID != candidate.RegistrationID || item.RecordSHA256 != candidate.RegistrationSHA256 || len(item.Record) == 0 || len(item.Record) > 16384 || !json.Valid(item.Record) || hex.EncodeToString(sum[:]) != item.RecordSHA256 || bound.IsZero() {
			return zero, ErrUnavailable
		}
		item.Record = append(json.RawMessage(nil), item.Record...)
		out.Items = append(out.Items, item)
		if until.IsZero() || bound.Before(until) {
			until = bound
		}
	}
	if hasMore {
		position.Before = candidates[len(candidates)-1].Task.ID
		next, e := codec.encode(position)
		if e != nil {
			return zero, e
		}
		out.NextCursor = &next
	}
	if ctx.Err() != nil {
		return zero, ErrUnavailable
	}
	if err = r.scope.RecheckRead(ctx, tx, installation); err != nil {
		return zero, scopeReadFailure(err)
	}
	if !until.IsZero() {
		var now time.Time
		if tx.QueryRowContext(ctx, `SELECT UTC_TIMESTAMP(6)`).Scan(&now) != nil || !now.Before(until) {
			return zero, ErrUnavailable
		}
	}
	if tx.Commit() != nil || ctx.Err() != nil {
		return zero, ErrUnavailable
	}
	return out, nil
}
