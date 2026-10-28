package systembackupevidence

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"time"
)

// The collector owns the connection as well as its sole RR transaction. Tx
// completion must not return the underlying session to an unrelated borrower.
// This boundary acquires no backup lock and grants no metadata-GC authority.
// A future freeze still needs approved privileges, admission/lock ordering,
// explicit cleanup outcomes and actual MySQL proof through commit.
type downloadGCConnection struct {
	conn            *sql.Conn
	tx              *sql.Tx
	commitAttempted bool
	closeErr        error
}

const downloadGCConnectionIdentitySQL = "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))"

func beginDownloadGCConnection(ctx context.Context, r SQLRegistry) (*downloadGCConnection, time.Time, error) {
	if ctx == nil || ctx.Err() != nil || r.DB == nil || nilSystemAdapter(r.Policy) || !installationPattern.MatchString(r.Installation) || r.ServerUUID == "" || r.Database == "" {
		return nil, time.Time{}, ErrUnavailable
	}
	c, err := r.DB.Conn(ctx)
	if err != nil {
		return nil, time.Time{}, ErrUnavailable
	}
	owned := &downloadGCConnection{conn: c}
	owned.tx, err = c.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		owned.close()
		return nil, time.Time{}, ErrUnavailable
	}
	var server, database string
	var now time.Time
	var offset int64
	err = owned.tx.QueryRowContext(ctx, downloadGCConnectionIdentitySQL).Scan(&server, &database, &now, &offset)
	if err != nil || server != r.ServerUUID || database != r.Database || now.IsZero() || offset != 0 {
		owned.close()
		return nil, time.Time{}, ErrUnavailable
	}
	return owned, now, nil
}

// commit records the attempt before invoking database/sql. An error may follow
// a server commit; cleanup must neither retry nor claim it rolled back.
func (c *downloadGCConnection) commit() error {
	if c == nil || c.conn == nil || c.tx == nil || c.commitAttempted {
		return ErrDownloadRetentionGCCommitUnknown
	}
	c.commitAttempted = true
	if c.tx.Commit() != nil {
		return ErrDownloadRetentionGCCommitUnknown
	}
	return nil
}

// Rollback first: discarding a Conn while its Tx still holds the connection
// can block. Only an observed nil Rollback response establishes this outcome;
// ErrTxDone may hide an automatic rollback whose driver result we never saw.
// After any commit attempt, do not attempt or claim a rollback. ErrBadConn
// requests driver closure
// and forbids pool reuse even if that driver's Close reports an error.
// This is pool disposal, not an assertion that a remote server released a
// lock. There is no UNLOCK/other SQL on a fresh pool connection or new context.
// Only the collector owns this private value; close is sequential/idempotent.
func (c *downloadGCConnection) close() error {
	if c == nil {
		return nil
	}
	if c.conn == nil {
		return c.closeErr
	}
	conn, tx := c.conn, c.tx
	c.conn, c.tx = nil, nil
	if tx != nil && !c.commitAttempted {
		if tx.Rollback() != nil {
			c.closeErr = ErrDownloadRetentionGCRollbackUnknown
		}
	}
	_ = conn.Raw(func(any) error { return driver.ErrBadConn })
	_ = conn.Close()
	return c.closeErr
}
