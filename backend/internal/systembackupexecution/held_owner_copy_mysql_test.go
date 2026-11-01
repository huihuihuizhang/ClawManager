package systembackupexecution

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
)

type dHeldReadCopyProbe struct {
	mode    string
	calls   int
	saved   c.HeldExecutionRead
	closed  *c.HeldExecutionRead
	child   c.HeldExecutionAuthorizationGuard
	mutated bool
}
type dHeldReadCopyAuthorization struct {
	original c.ExecutionAuthorization
	probe    *dHeldReadCopyProbe
}
type dHeldReadCopyGuard struct{ probe *dHeldReadCopyProbe }

func (o dHeldReadCopyAuthorization) AuthorizeExecution(ctx context.Context, tx *sql.Tx, a d.Authority, now time.Time) (c.ExecutionAuthorizationGuard, error) {
	guard, err := o.original.AuthorizeExecution(ctx, tx, a, now)
	if err != nil {
		return nil, err
	}
	child, ok := guard.(c.HeldExecutionAuthorizationGuard)
	if !ok || !child.SupportsHeldExecutionRecheck() {
		return nil, c.ErrExecutionAuthority
	}
	o.probe.child = child
	return dHeldReadCopyGuard{o.probe}, nil
}
func (g dHeldReadCopyGuard) ValidUntil() time.Time { return g.probe.child.ValidUntil() }
func (g dHeldReadCopyGuard) RecheckExecution(ctx context.Context, tx *sql.Tx, a d.Authority, now time.Time) error {
	return g.probe.child.RecheckExecution(ctx, tx, a, now)
}
func (g dHeldReadCopyGuard) SupportsHeldExecutionRecheck() bool { return true }
func (g dHeldReadCopyGuard) PrepareHeldExecutionRecheck(ctx context.Context, tx *sql.Tx, a d.Authority, now time.Time, read *c.HeldExecutionRead) error {
	p := g.probe
	p.calls++
	switch p.mode {
	case "copied-body":
		copy := *read
		return p.child.PrepareHeldExecutionRecheck(ctx, tx, a, now, &copy)
	case "copy-back-before-use":
		before := *read
		if err := p.child.PrepareHeldExecutionRecheck(ctx, tx, a, now, read); err != nil {
			return err
		}
		*read = before
		return p.child.PrepareHeldExecutionRecheck(ctx, tx, a, now, read)
	case "old-valid-into-new":
		if p.calls > 1 {
			*read = p.saved
			return p.child.PrepareHeldExecutionRecheck(ctx, tx, a, now, read)
		}
		if err := p.child.PrepareHeldExecutionRecheck(ctx, tx, a, now, read); err != nil {
			return err
		}
		p.saved = *read
		return nil
	case "closed":
		if err := p.child.PrepareHeldExecutionRecheck(ctx, tx, a, now, read); err != nil {
			return err
		}
		p.closed = read
		return nil
	case "write-after-register":
		if err := p.child.PrepareHeldExecutionRecheck(ctx, tx, a, now, read); err != nil {
			return err
		}
		var before, after uint64
		if tx.QueryRowContext(ctx, "SELECT row_version FROM system_backup_v2_backups WHERE public_id=?", a.TaskPublicID).Scan(&before) != nil {
			return errors.New("callback original row version unavailable")
		}
		result, err := tx.ExecContext(ctx, "UPDATE system_backup_v2_backups SET row_version=row_version+1 WHERE public_id=?", a.TaskPublicID)
		if err != nil {
			return err
		}
		count, err := result.RowsAffected()
		if err != nil || count != 1 || tx.QueryRowContext(ctx, "SELECT row_version FROM system_backup_v2_backups WHERE public_id=?", a.TaskPublicID).Scan(&after) != nil || after != before+1 {
			return errors.New("callback row version mutation not independently observed")
		}
		p.mutated = true
		return nil
	}
	return c.ErrExecutionAuthority
}

func TestHeldOwnerOpaqueCopyCannotTransferOrResetActualCurrentRead(t *testing.T) {
	if os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS") == "" {
		t.Skip("requires disposable local MySQL")
	}
	for _, mode := range []string{"copied-body", "copy-back-before-use", "old-valid-into-new", "closed", "write-after-register"} {
		t.Run(mode, func(t *testing.T) {
			owner, _, _, _, a, _, _, _, refresh := newConsumerMySQLFixtureOptions(t, &consumerFixtureOptions{})
			refresh()
			probe := &dHeldReadCopyProbe{mode: mode}
			store := owner.Gate.Authority
			store.Authorization = dHeldReadCopyAuthorization{original: store.Authorization, probe: probe}
			ctx := context.Background()
			tx, err := store.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			journalRows := func() [3]uint64 {
				t.Helper()
				var counts [3]uint64
				if tx.QueryRowContext(ctx, `SELECT
(SELECT COUNT(*) FROM system_backup_v2_evidence),
(SELECT COUNT(*) FROM system_backup_v2_job_observations),
(SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE key_use_json IS NOT NULL)`).Scan(&counts[0], &counts[1], &counts[2]) != nil {
					t.Fatal("original provider/worker journal census")
				}
				return counts
			}
			beforeRows := journalRows()
			defer func() {
				if journalRows() != beforeRows {
					t.Error("opaque/callback fault added original evidence, observation or key-use rows")
				}
			}()
			guard, err := store.Bind(ctx, tx, a)
			if err != nil {
				t.Fatal("original actual SQL binding", err)
			}
			if mode == "old-valid-into-new" || mode == "closed" {
				// A real signed owner and complete current SQL read must first
				// succeed; no timestamp, permission or snapshot flag is forged.
				if guard.Recheck(ctx, tx) != nil || probe.calls != 1 {
					t.Fatal("actual current SQL read baseline")
				}
			}
			if mode == "closed" {
				if probe.closed == nil || probe.child.PrepareHeldExecutionRecheck(ctx, tx, a, time.Now().UTC(), probe.closed) == nil {
					t.Fatal("actual finished read reused after callback closed")
				}
				return
			}
			if guard.Recheck(ctx, tx) == nil || !guard.ValidUntil().IsZero() || guard.Recheck(ctx, tx) == nil {
				t.Fatal("copy/whole-struct assignment transferred or reset current SQL permission")
			}
			if mode == "write-after-register" && !probe.mutated {
				t.Fatal("post-registration callback mutation was not actually exercised")
			}
		})
	}
}
