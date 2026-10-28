package systembackupevidence

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"reflect"
	"testing"
	"time"
)

// Full collector SQL/state model under the private freeze owner. Only the
// transport and authority/metadata observations are synthetic: this is neither
// actual BACKUP LOCK behavior nor production policy/grant acceptance.
type gcFrozenWorkConnector struct{ c *gcFrozenWorkConn }

func (c gcFrozenWorkConnector) Connect(context.Context) (driver.Conn, error) {
	c.c.connections++
	return c.c, nil
}
func (c gcFrozenWorkConnector) Driver() driver.Driver { return c.c.Driver() }

type gcFrozenWorkConn struct {
	*retentionGCModel
	held, lateLockLoss            bool
	connections, begins, releases int
	afterTicket                   func()
	beforeQuery                   func(string)
	ticketObserved                bool
}

func (c *gcFrozenWorkConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	if !c.held || c.begins != 0 {
		return nil, errors.New("work started outside sole frozen transaction")
	}
	c.begins++
	return c.retentionGCModel.BeginTx(ctx, o)
}
func (c *gcFrozenWorkConn) ExecContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Result, error) {
	switch q {
	case "SET SESSION lock_wait_timeout = ?":
		return driver.RowsAffected(0), nil
	case "LOCK INSTANCE FOR BACKUP":
		c.held = true
		return driver.RowsAffected(0), nil
	case "UNLOCK INSTANCE":
		if c.active {
			return nil, errors.New("unlock preceded transaction end")
		}
		c.held = false
		c.releases++
		return driver.RowsAffected(0), nil
	}
	return c.retentionGCModel.ExecContext(ctx, q, a)
}
func (c *gcFrozenWorkConn) QueryContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	if c.beforeQuery != nil {
		c.beforeQuery(q)
	}
	switch q {
	case downloadGCFreezeSessionSQL:
		return admissionTxRow(c.identity.ServerUUID, c.identity.Database, "gc-fixture@%", "NONE", "+00:00", int64(41)), nil
	case downloadGCFreezeHeldSQL:
		if c.begins == 1 && len(c.writes) > 0 && !c.ticketObserved {
			c.ticketObserved = true
			if c.afterTicket != nil {
				c.afterTicket()
			}
		}
		if c.held && !(c.lateLockLoss && len(c.writes) > 0) {
			return admissionTxRow(int64(1)), nil
		}
		return admissionTxRow(int64(0)), nil
	}
	return c.retentionGCModel.QueryContext(ctx, q, a)
}

func TestDownloadRetentionGCProtectedWorkWithFreezeOwner(t *testing.T) {
	for _, mode := range []string{"commit", "caller_late_failure", "final_lock_loss", "last_delete_failure"} {
		t.Run(mode, func(t *testing.T) {
			f := newRetentionGCFixture(t)
			c := &gcFrozenWorkConn{retentionGCModel: f.d, lateLockLoss: mode == "final_lock_loss"}
			if mode == "last_delete_failure" {
				f.d.fail = "exec:" + downloadGCDeleteAuditSQL
			}
			beforeReserved, beforeEvidence := f.d.reserved, f.d.record
			ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
			defer cancel()
			peer, err := pinnedPeerExpiry(ctx, f.s, f.s.roots, f.s.c.CertificateSHA256, f.s.c.ExpiresAt)
			if err != nil {
				t.Fatal(err)
			}
			workCompleted := false
			out, err := runDownloadGCFreeze(ctx, downloadGCFreezeConfig{
				Connector: gcFrozenWorkConnector{c}, Server: c.identity.ServerUUID, Database: c.identity.Database,
				Account: "gc-fixture@%", WaitSeconds: 1,
				Admit: func(context.Context, *sql.Conn) error { return nil }, // Synthetic authority only.
			}, func(ctx context.Context, tx *sql.Tx) error {
				if err := f.s.collectInTransaction(ctx, tx, f.operation, peer, f.d.now); err != nil {
					return err
				}
				workCompleted = true
				if !f.d.active || f.d.commits != f.commits || f.d.rollbacks != f.rollbacks || len(f.d.m.op) != 0 || len(f.d.stone) != 23 {
					t.Fatal("work ended transaction or skipped mutations")
				}
				if mode == "caller_late_failure" {
					return errors.New("late caller denial after all GC mutations")
				}
				return nil
			})
			if c.connections != 1 || c.begins != 1 || c.releases != 1 || !out.DiscardRequested || out.Unlock != "confirmed" || f.d.active || !reflect.DeepEqual(f.d.record, beforeEvidence) {
				t.Fatalf("connection/transaction/release boundary differs: %+v", out)
			}
			if mode == "commit" {
				if err != nil || !workCompleted || out.Transaction != "committed" || f.d.commits != f.commits+1 || f.d.rollbacks != f.rollbacks {
					t.Fatalf("sole owner commit failed: %v %+v", err, out)
				}
			} else if err == nil || out.Transaction != "rolled_back" || f.d.commits != f.commits || f.d.rollbacks != f.rollbacks+1 || len(f.d.stone) != 0 || len(f.d.m.op) != 14 || len(f.d.m.receipt) != 16 || len(f.d.nonce) != 16 || len(f.d.resultRetention) != 11 || len(f.d.body) == 0 || len(f.d.resultBody) == 0 || f.d.reserved != beforeReserved {
				t.Fatalf("late failure escaped shared rollback: %v %+v", err, out)
			}
			if mode != "last_delete_failure" && !workCompleted || len(f.d.writes) == 0 {
				t.Fatal("failure fixture did not reach protected mutations")
			}
		})
	}
}

func TestDownloadRetentionGCProtectedWorkRejectsUnboundContext(t *testing.T) {
	f := newRetentionGCFixture(t)
	owned, now, err := beginDownloadGCConnection(f.ctx, f.s.c.Registry)
	if err != nil {
		t.Fatal(err)
	}
	defer owned.close()
	queries := len(f.d.queries)
	if err := f.s.collectInTransaction(context.Background(), owned.tx, f.operation, now.Add(time.Minute), now); err == nil || len(f.d.queries) != queries || len(f.d.writes) != 0 {
		t.Fatal("unrelated context reached protected SQL")
	}
}
