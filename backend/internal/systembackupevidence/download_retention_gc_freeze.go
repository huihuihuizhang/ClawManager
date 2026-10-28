package systembackupevidence

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"reflect"
	"time"
)

// Private protocol engine. Collect reaches it only through the explicit full
// adapter and mandatory deployment protocol authority. Historical candidates
// remain transport-only; no default production policy or grants are supplied.
type downloadGCFreezeConfig struct {
	Connector                 driver.Connector // A new private pool, never a borrowed shared pool.
	Server, Database, Account string
	WaitSeconds               int
	// Trusted read-only admission on the exact fresh session, before and after
	// acquisition. It must authenticate actual worker/grants/schema authority;
	// this seam itself is not that implementation or a production permission.
	Admit func(context.Context, *sql.Conn) error
	// Fixed full-adapter observation, after acquisition and before Begin.
	// Historical transport-only candidates leave it nil.
	Observe func(context.Context, *sql.Conn) error
}

type downloadGCFreezeOutcome struct {
	Transaction      string // not_started, rolled_back, committed, unknown
	Unlock           string // not_acquired, confirmed, unknown
	DiscardRequested bool   // not an assertion about server-side release
}

var (
	errDownloadGCFreezeDenied          = errors.New("download_gc_freeze_candidate_denied")
	errDownloadGCFreezeCommitUnknown   = errors.New("download_gc_freeze_candidate_commit_unknown")
	errDownloadGCFreezeRollbackUnknown = errors.New("download_gc_freeze_candidate_rollback_unknown")
	errDownloadGCFreezeReleaseUnknown  = errors.New("download_gc_freeze_candidate_release_unknown")
)

const downloadGCFreezeSessionSQL = "SELECT @@server_uuid,DATABASE(),CURRENT_USER(),CURRENT_ROLE(),@@session.time_zone,CONNECTION_ID()"
const downloadGCFreezeHeldSQL = "SELECT COUNT(*) FROM performance_schema.metadata_locks l JOIN performance_schema.threads t ON t.THREAD_ID=l.OWNER_THREAD_ID WHERE t.PROCESSLIST_ID=CONNECTION_ID() AND l.OBJECT_TYPE='BACKUP LOCK' AND l.LOCK_TYPE='SHARED' AND l.LOCK_DURATION='EXPLICIT' AND l.LOCK_STATUS='GRANTED'"

// runDownloadGCFreeze retains one physical session through acquisition, one RR
// transaction and explicit release. Metadata/work starts only after this
// session's exact lock is observed. No retries, provider calls or shared pool
// returns occur. Every path discards this private session. Work is a trusted
// transaction-local seam, not a default full-GC policy.
func runDownloadGCFreeze(ctx context.Context, c downloadGCFreezeConfig, work func(context.Context, *sql.Tx) error) (out downloadGCFreezeOutcome, err error) {
	// Transport-only historical candidate. It supplies no metadata-GC authority
	// or completed-work capability. Concrete GC candidate wiring below always
	// uses a private captured finalizer through runDownloadGCFreezeProtocol.
	return runDownloadGCFreezeProtocol(ctx, c, work, nil)
}

func runDownloadGCFreezeProtocol(ctx context.Context, c downloadGCFreezeConfig, work func(context.Context, *sql.Tx) error, finalize func(context.Context, *sql.Tx) error) (out downloadGCFreezeOutcome, err error) {
	out.Transaction = "not_started"
	out.Unlock = "not_acquired"
	if ctx == nil || ctx.Err() != nil || c.Connector == nil || c.Admit == nil || work == nil || c.Server == "" || c.Database == "" || c.Account == "" || c.WaitSeconds < 1 || c.WaitSeconds > 5 {
		return out, errDownloadGCFreezeDenied
	}
	v := reflect.ValueOf(c.Connector)
	if (v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface || v.Kind() == reflect.Map || v.Kind() == reflect.Slice || v.Kind() == reflect.Func || v.Kind() == reflect.Chan) && v.IsNil() {
		return out, errDownloadGCFreezeDenied
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || time.Until(deadline) > 30*time.Second {
		return out, errDownloadGCFreezeDenied
	}
	db := sql.OpenDB(c.Connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)
	defer db.Close()
	conn, connectErr := db.Conn(ctx)
	if connectErr != nil {
		return out, errDownloadGCFreezeDenied
	}
	var tx *sql.Tx
	commitAttempted, acquisitionAttempted, held := false, false, false
	defer func() {
		knownEnd := tx == nil
		if tx != nil && !commitAttempted {
			if tx.Rollback() == nil {
				out.Transaction = "rolled_back"
				knownEnd = true
			} else {
				out.Transaction = "unknown"
				knownEnd = false
				err = errors.Join(err, errDownloadGCFreezeRollbackUnknown)
			}
		} else if commitAttempted {
			knownEnd = out.Transaction == "committed"
		}
		if acquisitionAttempted {
			out.Unlock = "unknown"
			if held && knownEnd && ctx.Err() == nil {
				if _, unlockErr := conn.ExecContext(ctx, "UNLOCK INSTANCE"); unlockErr == nil {
					var remaining int
					if conn.QueryRowContext(ctx, downloadGCFreezeHeldSQL).Scan(&remaining) == nil && remaining == 0 {
						out.Unlock = "confirmed"
					}
				}
			}
			if out.Unlock != "confirmed" {
				err = errors.Join(err, errDownloadGCFreezeReleaseUnknown)
			}
		}
		// ErrBadConn requests physical disposal. Close alone is pool return; the
		// outcome intentionally never asserts remote lock release on disposal.
		_ = conn.Raw(func(any) error { out.DiscardRequested = true; return driver.ErrBadConn })
		_ = conn.Close()
	}()
	var pinnedID int64
	verifySession := func() error {
		var server, database, account, role, zone string
		var id int64
		if conn.QueryRowContext(ctx, downloadGCFreezeSessionSQL).Scan(&server, &database, &account, &role, &zone, &id) != nil || server != c.Server || database != c.Database || account != c.Account || role != "NONE" || zone != "+00:00" || id <= 0 {
			return errDownloadGCFreezeDenied
		}
		if pinnedID != 0 && id != pinnedID {
			return errDownloadGCFreezeDenied
		}
		pinnedID = id
		return nil
	}
	if verifySession() != nil || c.Admit(ctx, conn) != nil || verifySession() != nil {
		return out, errDownloadGCFreezeDenied
	}
	if _, err = conn.ExecContext(ctx, "SET SESSION lock_wait_timeout = ?", c.WaitSeconds); err != nil {
		return out, errDownloadGCFreezeDenied
	}
	acquisitionAttempted = true
	if _, err = conn.ExecContext(ctx, "LOCK INSTANCE FOR BACKUP"); err != nil {
		return out, errDownloadGCFreezeDenied
	}
	held = true
	var tickets int
	if conn.QueryRowContext(ctx, downloadGCFreezeHeldSQL).Scan(&tickets) != nil || tickets != 1 || c.Admit(ctx, conn) != nil || verifySession() != nil {
		return out, errDownloadGCFreezeDenied
	}
	if c.Observe != nil {
		if c.Observe(ctx, conn) != nil || c.Admit(ctx, conn) != nil || verifySession() != nil || conn.QueryRowContext(ctx, downloadGCFreezeHeldSQL).Scan(&tickets) != nil || tickets != 1 {
			return out, errDownloadGCFreezeDenied
		}
	}
	tx, err = conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return out, errDownloadGCFreezeDenied
	}
	out.Transaction = "unknown"
	if work(ctx, tx) != nil || ctx.Err() != nil {
		return out, errDownloadGCFreezeDenied
	}
	if tx.QueryRowContext(ctx, downloadGCFreezeHeldSQL).Scan(&tickets) != nil || tickets != 1 {
		return out, errDownloadGCFreezeDenied
	}
	if finalize != nil && finalize(ctx, tx) != nil {
		return out, errDownloadGCFreezeDenied
	}
	if ctx.Err() != nil {
		return out, errDownloadGCFreezeDenied
	}
	commitAttempted = true
	if tx.Commit() != nil {
		return out, errDownloadGCFreezeCommitUnknown
	}
	out.Transaction = "committed"
	if ctx.Err() != nil {
		return out, errDownloadGCFreezeDenied
	}
	return out, nil
}
