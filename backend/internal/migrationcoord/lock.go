// Package migrationcoord serializes application schema migrations with the
// system-backup capture gate. The lock is connection-scoped so it remains held
// across MySQL DDL statements, which may implicitly commit transactions.
package migrationcoord

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"time"
)

const LockName = "clawmanager:system-backup:migration-capture:v1"

const DefaultAcquireTimeout = 60 * time.Second

type Lock interface {
	Release(context.Context) error
}

type Locker interface {
	Acquire(context.Context) (Lock, error)
}

type SQLLocker struct {
	DB      *sql.DB
	Timeout time.Duration
}

// SQLLock owns one dedicated database connection. GET_LOCK is scoped to that
// connection; callers that execute migrations may use the same handle so a
// pooled connection cannot accidentally release or inherit the exclusion.
type SQLLock struct {
	conn     *sql.Conn
	released bool
}

func (l SQLLocker) Acquire(ctx context.Context) (Lock, error) {
	return l.AcquireSQL(ctx)
}

func (l SQLLocker) AcquireSQL(ctx context.Context) (*SQLLock, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	timeout := l.Timeout
	if timeout == 0 {
		timeout = DefaultAcquireTimeout
	}
	if timeout < 0 || timeout%time.Second != 0 {
		return nil, errors.New("migration coordination timeout must be non-negative whole seconds")
	}
	if l.DB == nil {
		return nil, errors.New("nil migration coordination database")
	}
	conn, err := l.DB.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("open migration coordination connection: %w", err)
	}
	var acquired sql.NullInt64
	if err := conn.QueryRowContext(ctx, "SELECT GET_LOCK(?, ?)", LockName, int64(timeout/time.Second)).Scan(&acquired); err != nil {
		return nil, errors.Join(fmt.Errorf("acquire migration coordination lock: %w", err), discardConnection(conn))
	}
	if !acquired.Valid || acquired.Int64 != 1 {
		return nil, errors.Join(errors.New("migration coordination lock is busy"), discardConnection(conn))
	}
	return &SQLLock{conn: conn}, nil
}

func (l *SQLLock) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if l == nil || l.conn == nil || l.released {
		return nil, errors.New("migration coordination lock is not active")
	}
	return l.conn.ExecContext(ctx, query, args...)
}

func (l *SQLLock) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	if l == nil || l.conn == nil || l.released {
		return nil, errors.New("migration coordination lock is not active")
	}
	return l.conn.QueryContext(ctx, query, args...)
}

func (l *SQLLock) Release(ctx context.Context) error {
	if l == nil || l.conn == nil || l.released {
		return errors.New("migration coordination lock is not active")
	}
	l.released = true
	var released sql.NullInt64
	releaseErr := l.conn.QueryRowContext(ctx, "SELECT RELEASE_LOCK(?)", LockName).Scan(&released)
	if releaseErr != nil || !released.Valid || released.Int64 != 1 {
		// A failed/ambiguous RELEASE_LOCK must not return a possibly locked
		// physical connection to the pool. Raw's ErrBadConn discards it.
		if releaseErr != nil {
			return errors.Join(fmt.Errorf("release migration coordination lock: %w", releaseErr), discardConnection(l.conn))
		}
		return errors.Join(errors.New("migration coordination lock ownership was lost"), discardConnection(l.conn))
	}
	closeErr := l.conn.Close()
	if closeErr != nil {
		return fmt.Errorf("close migration coordination connection: %w", closeErr)
	}
	return nil
}

func discardConnection(conn *sql.Conn) error {
	if conn == nil {
		return nil
	}
	// database/sql must not reuse a connection whose advisory-lock state is
	// unknown. Returning ErrBadConn from Raw closes the physical connection.
	discardErr := conn.Raw(func(any) error { return driver.ErrBadConn })
	closeErr := conn.Close()
	if errors.Is(discardErr, driver.ErrBadConn) {
		discardErr = nil
	}
	return errors.Join(discardErr, closeErr)
}
