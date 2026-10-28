package systembackupread

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"strconv"
	"strings"
)

const operationCursorDomain = "system-backup-admin-operation-page.v1\n"

type operationPageRequest struct {
	installation string
	limit        int
	cutoff       uint64
	before       uint64
}

type operationPageItem struct {
	id  uint64
	row OperationSnapshot
}

type operationPage struct {
	items        []operationPageItem
	installation string
	cutoff       uint64
	before       uint64
	hasMore      bool
}

func (operationPage) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// listOperations returns only the D-owned operation columns needed by the
// public contract. Its internal primary keys and rows cannot be serialized.
func (r *Reader) listOperations(ctx context.Context, request operationPageRequest) (operationPage, error) {
	if r == nil || r.db == nil || nilScope(r.scope) || ctx == nil || ctx.Err() != nil {
		return operationPage{}, ErrDenied
	}
	if request.limit < 1 || request.limit > 500 ||
		request.cutoff == 0 && (request.before != 0 || request.installation != "") ||
		request.cutoff != 0 && (!installationID.MatchString(request.installation) ||
			request.before == 0 || request.before > request.cutoff) ||
		request.cutoff == ^uint64(0) {
		return operationPage{}, ErrInvalid
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return operationPage{}, ErrUnavailable
	}
	defer tx.Rollback()
	installation, err := r.scope.AuthorizeRead(ctx, tx)
	if err != nil {
		return operationPage{}, scopeReadFailure(err)
	}
	if !installationID.MatchString(installation) ||
		request.installation != "" && request.installation != installation {
		return operationPage{}, ErrDenied
	}
	cutoff := request.cutoff
	if cutoff == 0 {
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(id),0) FROM system_backup_v2_operations WHERE origin_installation_id=?`, installation).Scan(&cutoff); err != nil {
			return operationPage{}, ErrUnavailable
		}
	}
	page := operationPage{items: make([]operationPageItem, 0, request.limit), installation: installation, cutoff: cutoff}
	if cutoff != 0 {
		if cutoff == ^uint64(0) {
			return operationPage{}, ErrUnavailable
		}
		upper := cutoff + 1
		if request.before != 0 {
			upper = request.before
		}
		rows, err := tx.QueryContext(ctx, operationPageSQL, installation, upper, request.limit+1)
		if err != nil {
			return operationPage{}, ErrUnavailable
		}
		previous := upper
		for rows.Next() {
			var item operationPageItem
			item.row, err = scanOperationWithID(rows, installation, &item.id)
			if err != nil || item.id == 0 || item.id >= previous || item.id > cutoff {
				rows.Close()
				return operationPage{}, ErrUnavailable
			}
			previous = item.id
			if len(page.items) == request.limit {
				page.hasMore = true
				break
			}
			page.items = append(page.items, item)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return operationPage{}, ErrUnavailable
		}
		if err := rows.Close(); err != nil {
			return operationPage{}, ErrUnavailable
		}
		if page.hasMore {
			page.before = page.items[len(page.items)-1].id
		}
	}
	if err := r.scope.RecheckRead(ctx, tx, installation); err != nil {
		return operationPage{}, scopeReadFailure(err)
	}
	if err := tx.Commit(); err != nil || ctx.Err() != nil {
		return operationPage{}, ErrUnavailable
	}
	return page, nil
}

type OperationListDTO struct {
	Items       []OperationDTO `json:"items"`
	NextCursor  *string        `json:"next_cursor"`
	Consistency string         `json:"consistency"`
}

func (s *Service) ListOperationDTO(ctx context.Context, limit int, token string) (OperationListDTO, error) {
	if s == nil || s.reader == nil || s.cursor == nil {
		return OperationListDTO{}, ErrDenied
	}
	request := operationPageRequest{limit: limit}
	if token != "" {
		var err error
		request, err = s.cursor.decodeOperation(token, limit)
		if err != nil {
			return OperationListDTO{}, err
		}
	}
	page, err := s.reader.listOperations(ctx, request)
	if err != nil {
		return OperationListDTO{}, err
	}
	result := OperationListDTO{Items: make([]OperationDTO, 0, len(page.items)), Consistency: "stable_cutoff"}
	previous := page.cutoff + 1
	for _, item := range page.items {
		if item.id == 0 || item.id >= previous || item.id > page.cutoff || item.row.installationID != page.installation {
			return OperationListDTO{}, ErrUnavailable
		}
		previous = item.id
		projected, err := ProjectOperation(item.row)
		if err != nil {
			return OperationListDTO{}, err
		}
		result.Items = append(result.Items, projected)
	}
	if page.hasMore {
		cursor, err := s.cursor.encodeOperation(request, page)
		if err != nil {
			return OperationListDTO{}, ErrUnavailable
		}
		result.NextCursor = &cursor
	}
	return result, nil
}

func (c *CursorCodec) encodeOperation(request operationPageRequest, page operationPage) (string, error) {
	if c == nil || len(c.key) < 32 || request.limit < 1 || request.limit > 500 ||
		!page.hasMore || len(page.items) != request.limit || !installationID.MatchString(page.installation) ||
		page.cutoff == 0 || page.before == 0 || page.before > page.cutoff ||
		page.items[len(page.items)-1].id != page.before ||
		request.installation != "" && request.installation != page.installation ||
		request.cutoff != 0 && request.cutoff != page.cutoff {
		return "", ErrInvalid
	}
	payload := strings.Join([]string{"v1", page.installation, strconv.Itoa(request.limit),
		strconv.FormatUint(page.cutoff, 10), strconv.FormatUint(page.before, 10)}, "|")
	mac := hmac.New(sha256.New, c.key)
	mac.Write([]byte(operationCursorDomain))
	mac.Write([]byte(payload))
	token := base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if len(token) > maxCursorBytes {
		return "", ErrInvalid
	}
	return token, nil
}

func (c *CursorCodec) decodeOperation(token string, limit int) (operationPageRequest, error) {
	if c == nil || len(c.key) < 32 || len(token) == 0 || len(token) > maxCursorBytes || limit < 1 || limit > 500 {
		return operationPageRequest{}, ErrInvalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return operationPageRequest{}, ErrInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != parts[0] {
		return operationPageRequest{}, ErrInvalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(signature) != sha256.Size || base64.RawURLEncoding.EncodeToString(signature) != parts[1] {
		return operationPageRequest{}, ErrInvalid
	}
	mac := hmac.New(sha256.New, c.key)
	mac.Write([]byte(operationCursorDomain))
	mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return operationPageRequest{}, ErrInvalid
	}
	fields := strings.Split(string(payload), "|")
	if len(fields) != 5 || fields[0] != "v1" || !installationID.MatchString(fields[1]) || fields[2] != strconv.Itoa(limit) {
		return operationPageRequest{}, ErrInvalid
	}
	cutoff, err := canonicalUint(fields[3])
	if err != nil || cutoff == 0 || cutoff == ^uint64(0) {
		return operationPageRequest{}, ErrInvalid
	}
	before, err := canonicalUint(fields[4])
	if err != nil || before == 0 || before > cutoff {
		return operationPageRequest{}, ErrInvalid
	}
	return operationPageRequest{installation: fields[1], limit: limit, cutoff: cutoff, before: before}, nil
}
