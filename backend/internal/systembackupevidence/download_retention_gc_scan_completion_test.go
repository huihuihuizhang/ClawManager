package systembackupevidence

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"reflect"
	"testing"
)

// Replace only the scan transaction's completion response. These tests run
// the real hint scan and batch boundary; they do not prove server cleanup.
type gcScanCompletionConnector struct {
	*gcRollbackFaultConnector
	finish func(error) error
}

type gcScanCompletionConn struct {
	*gcRollbackFaultConn
	finish func(error) error
}

type gcScanCompletionTx struct {
	driver.Tx
	finish func(error) error
}

func (p *gcScanCompletionConnector) Connect(ctx context.Context) (driver.Conn, error) {
	c, err := p.gcRollbackFaultConnector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &gcScanCompletionConn{c.(*gcRollbackFaultConn), p.finish}, nil
}

func (c *gcScanCompletionConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	tx, err := c.gcRollbackFaultConn.BeginTx(ctx, o)
	if err != nil {
		return nil, err
	}
	return &gcScanCompletionTx{tx, c.finish}, nil
}

func (tx *gcScanCompletionTx) Rollback() error { return tx.finish(tx.Tx.Rollback()) }

func TestDownloadRetentionGCScanCompletion(t *testing.T) {
	for _, shape := range []string{"empty_epoch", "closed_cursor", "empty_tail", "page", "invalid_page"} {
		for _, completion := range []string{"known", "lost_reply", "tx_done", "canceled"} {
			t.Run(shape+"/"+completion, func(t *testing.T) {
				f, m := newDownloadGCBatchFixture(t)
				ctx, cancel := context.WithCancel(f.ctx)
				defer cancel()
				cursor := DownloadRetentionGCBatchCursor{}
				switch shape {
				case "empty_epoch":
					m.upper, m.rows = int64(0), nil
				case "closed_cursor":
					cursor = DownloadRetentionGCBatchCursor{AfterID: 74, ThroughID: 74}
					m.rows = nil
				case "empty_tail":
					cursor = DownloadRetentionGCBatchCursor{AfterID: 73, ThroughID: 74}
					m.rows = nil
				case "invalid_page":
					m.rows[0][1] = "PRIVATE invalid hint"
				}
				p := &gcScanCompletionConnector{gcRollbackFaultConnector: &gcRollbackFaultConnector{inner: m}}
				p.finish = func(err error) error {
					if err != nil {
						t.Fatalf("underlying model rollback failed: %v", err)
					}
					switch completion {
					case "lost_reply":
						return errors.New("PRIVATE rollback reply lost")
					case "tx_done":
						return sql.ErrTxDone
					case "canceled":
						cancel()
					}
					return nil
				}
				db := sql.OpenDB(p)
				db.SetMaxOpenConns(1)
				t.Cleanup(func() { db.Close() })
				f.s.c.Registry.DB = db
				before := gcConnectionGroupSnapshot(f.d)
				// Inspect the scan directly: canceled completion must not release
				// hints even when the caller is not CollectBatch.
				rows, through, more, err := f.s.scanDownloadGCBatch(ctx, cursor, 1, f.s.c.ExpiresAt)
				wantError := completion != "known" || shape == "invalid_page"
				wantRows, wantThrough := 0, int64(74)
				if shape == "page" {
					wantRows = 1
				}
				if shape == "empty_epoch" {
					wantThrough = 0
				}
				if wantError {
					if err != ErrAudit || rows != nil || through != 0 || more {
						t.Fatalf("unconfirmed scan escaped: rows=%v through=%d more=%v err=%v", rows, through, more, err)
					}
				} else if err != nil || len(rows) != wantRows || more != (shape == "page") || through != wantThrough {
					t.Fatalf("known completion changed hints: rows=%v through=%d more=%v err=%v", rows, through, more, err)
				}
				if p.begun != 1 || p.rollbacks != 1 || p.commits != 0 || m.scanRollbacks != 1 || f.d.active || len(f.d.writes) != 0 || !reflect.DeepEqual(before, gcConnectionGroupSnapshot(f.d)) {
					t.Fatal("scan retried, mutated data or failed to end its transaction")
				}
			})
		}
	}
}

func TestDownloadRetentionGCBatchScanRollbackFailure(t *testing.T) {
	for _, shape := range []string{"empty_epoch", "closed_cursor", "empty_tail", "page"} {
		t.Run(shape, func(t *testing.T) {
			f, m := newDownloadGCBatchFixture(t)
			cursor := DownloadRetentionGCBatchCursor{AfterID: 72, ThroughID: 74}
			if shape == "empty_epoch" {
				cursor = DownloadRetentionGCBatchCursor{}
				m.upper = int64(0)
			}
			if shape == "closed_cursor" {
				cursor.AfterID = cursor.ThroughID
			}
			if shape != "page" {
				m.rows = nil
			}
			p := installGCRollbackFault(t, f, m, 1)
			result, err := f.s.CollectBatch(f.ctx, cursor, 1)
			if err != ErrAudit || result != (DownloadRetentionGCBatchResult{Cursor: cursor}) || p.begun != 1 || p.rollbacks != 1 || p.commits != 0 || len(f.d.writes) != 0 || f.d.active {
				t.Fatal("failed scan advanced cursor, reported completion or reached collector", result, err)
			}
		})
	}
}
