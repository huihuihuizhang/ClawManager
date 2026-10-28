package systembackupread

import (
	"context"
	"database/sql"
	"errors"
)

// detailReadSQL exposes only query methods to trusted internal builders. The
// wrapper prevents transaction-control assertions; builders must still use
// reviewed read-only SQL and the deployment must enforce database privileges.
// Future per-kind builders run before the final authority check and must use
// the trusted installation on the TaskHeader in every additional SQL scope.
type detailReadSQL interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type detailReadTx struct{ tx *sql.Tx }

func (q detailReadTx) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return q.tx.QueryContext(ctx, query, args...)
}
func (q detailReadTx) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return q.tx.QueryRowContext(ctx, query, args...)
}

// readTaskInTransaction keeps all future owner projections under one read
// authority decision. A builder error rolls back and no partial result escapes.
func readTaskInTransaction[T any](ctx context.Context, r *Reader, kind TaskKind, publicID string,
	build func(context.Context, detailReadSQL, TaskHeader) (T, error)) (T, error) {
	var zero T
	if r == nil || r.db == nil || nilScope(r.scope) || ctx == nil || ctx.Err() != nil {
		return zero, ErrDenied
	}
	table, ok := taskTables[kind]
	if !ok || len(publicID) != len(table.prefix)+36 || publicID[:len(table.prefix)] != table.prefix ||
		!taskUUID.MatchString(publicID[len(table.prefix):]) {
		return zero, ErrInvalid
	}
	if build == nil {
		return zero, ErrUnavailable
	}
	// Task, attempts and later owner projections must share one snapshot. A's
	// locking authorization reads and final recheck retain current authority.
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return zero, ErrUnavailable
	}
	defer tx.Rollback()
	installation, err := r.scope.AuthorizeRead(ctx, tx)
	if err != nil {
		return zero, scopeReadFailure(err)
	}
	if !installationID.MatchString(installation) {
		return zero, ErrDenied
	}
	query := "SELECT " + taskProjectionColumns + " FROM " + table.name +
		" WHERE origin_installation_id=? AND public_id=?"
	item, err := scanTask(tx.QueryRowContext(ctx, query, installation, publicID), kind, table, installation)
	missing := errors.Is(err, sql.ErrNoRows)
	if err != nil && !missing || !missing && item.PublicID != publicID {
		return zero, ErrUnavailable
	}
	var result T
	if !missing {
		result, err = build(ctx, detailReadTx{tx}, item)
		if err != nil {
			return zero, ErrUnavailable
		}
	}
	if ctx.Err() != nil {
		return zero, ErrUnavailable
	}
	// A missing row must still pass the final authority check. In particular,
	// revocation racing a miss must never be reported as an authorized 404.
	if err := r.scope.RecheckRead(ctx, tx, installation); err != nil {
		return zero, scopeReadFailure(err)
	}
	if err := tx.Commit(); err != nil || ctx.Err() != nil {
		return zero, ErrUnavailable
	}
	if missing {
		return zero, ErrNotFound
	}
	return result, nil
}

// GetTaskBase reads only the common Task projection for a detail request.
// It is not a v12 DetailResource: owner execution, artifact and evidence
// fields still require separately reviewed authoritative projections.
func (r *Reader) GetTaskBase(ctx context.Context, kind TaskKind, publicID string) (TaskHeader, error) {
	return readTaskInTransaction(ctx, r, kind, publicID,
		func(_ context.Context, _ detailReadSQL, item TaskHeader) (TaskHeader, error) { return item, nil })
}

// GetTaskBase returns a redacted common task only. The caller cannot treat it
// as the complete per-kind detail response.
func (s *Service) GetTaskBase(ctx context.Context, kind TaskKind, publicID string) (TaskDTO, error) {
	if s == nil || s.reader == nil {
		return TaskDTO{}, ErrDenied
	}
	item, err := s.reader.GetTaskBase(ctx, kind, publicID)
	if err != nil {
		return TaskDTO{}, err
	}
	return ProjectTask(item)
}
