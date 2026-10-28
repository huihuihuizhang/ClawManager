package systembackupbusinessa

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"reflect"
	"testing"
	"time"
)

// Test transport only. It delegates the original transaction and queries, and
// schedules a separate writer only after one exact COUNT result has closed.
type costSnapshotHookConnector struct {
	inner driver.Connector
	query string
	after func(context.Context) error
}

func (c costSnapshotHookConnector) Driver() driver.Driver { return c.inner.Driver() }
func (c costSnapshotHookConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.inner.Connect(ctx)
	if err != nil {
		return nil, err
	}
	begin, ok := conn.(driver.ConnBeginTx)
	query, queryOK := conn.(driver.QueryerContext)
	if !ok || !queryOK || c.after == nil {
		_ = conn.Close()
		return nil, errors.New("snapshot test transport lacks required interfaces")
	}
	return &costSnapshotHookConn{Conn: conn, begin: begin, query: query, hook: c}, nil
}

type costSnapshotHookConn struct {
	driver.Conn
	begin driver.ConnBeginTx
	query driver.QueryerContext
	hook  costSnapshotHookConnector
}

func (c *costSnapshotHookConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return c.begin.BeginTx(ctx, opts)
}
func (c *costSnapshotHookConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	rows, err := c.query.QueryContext(ctx, query, args)
	if err != nil || query != c.hook.query {
		return rows, err
	}
	return &costSnapshotHookRows{Rows: rows, ctx: ctx, after: c.hook.after}, nil
}
func (c *costSnapshotHookConn) ResetSession(ctx context.Context) error {
	if reset, ok := c.Conn.(driver.SessionResetter); ok {
		return reset.ResetSession(ctx)
	}
	return nil
}
func (c *costSnapshotHookConn) IsValid() bool {
	if valid, ok := c.Conn.(driver.Validator); ok {
		return valid.IsValid()
	}
	return true
}

type costSnapshotHookRows struct {
	driver.Rows
	ctx      context.Context
	after    func(context.Context) error
	closed   bool
	closeErr error
}

func (r *costSnapshotHookRows) Close() error {
	if !r.closed {
		r.closed = true
		r.closeErr = r.Rows.Close()
		if r.closeErr == nil {
			r.closeErr = r.ctx.Err()
		}
		if r.closeErr == nil {
			r.closeErr = r.after(r.ctx)
		}
	}
	return r.closeErr
}

func TestCostSnapshotHookDelegatesOriginalTransaction(t *testing.T) {
	for _, mode := range []string{"matched", "non_matching", "hook_error", "query_error"} {
		t.Run(mode, func(t *testing.T) {
			scope, err := pinnedScope(t, registryFixture(t, true))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			state := &countState{}
			query := "SELECT COUNT(*) FROM `" + scope.tables[0] + "`"
			if mode == "non_matching" {
				query = "SELECT COUNT(*) FROM `not_in_scope`"
			}
			if mode == "query_error" {
				state.failure = "count:" + scope.tables[0]
			}
			calls := 0
			hookErr := errors.New("separate writer failed")
			db := sql.OpenDB(costSnapshotHookConnector{inner: countConnector{state}, query: query, after: func(got context.Context) error {
				calls++
				if got != ctx || len(state.queries) != 2 || state.queries[1] != query || state.commits != 0 {
					t.Error("writer ran outside the original first-count boundary")
				}
				if mode == "hook_error" {
					return hookErr
				}
				return nil
			}})
			t.Cleanup(func() { db.Close() })
			got, err := (SQLCountCollector{DB: db}).CollectSnapshot(ctx, scope)
			if state.begin.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || !state.begin.ReadOnly {
				t.Fatal("test transport replaced transaction options")
			}
			wantCalls := 1
			if mode == "non_matching" || mode == "query_error" {
				wantCalls = 0
			}
			if calls != wantCalls {
				t.Fatal("wrong writer dispatch count", calls)
			}
			if mode == "hook_error" || mode == "query_error" {
				if err == nil || !reflect.DeepEqual(got, SourceSnapshot{}) || state.commits != 0 || state.rollbacks != 1 {
					t.Fatal("failed writer/query released a partial snapshot", err)
				}
				if mode == "hook_error" && !errors.Is(err, hookErr) {
					t.Fatal("lost writer failure", err)
				}
				return
			}
			if err != nil || state.commits != 1 || len(state.queries) != 31 || len(got.Tables) != 15 {
				t.Fatal("transport changed collector reads or commit", err)
			}
		})
	}
}

type costSnapshotCloseRows struct {
	driver.Rows
	close func() error
}

func (r costSnapshotCloseRows) Close() error { return r.close() }

func TestCostSnapshotHookRunsOnceAfterSuccessfulClose(t *testing.T) {
	for _, mode := range []string{"closed", "close_error", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			closes, writes := 0, 0
			closeErr := errors.New("count result close failed")
			rows := &costSnapshotHookRows{ctx: ctx, Rows: costSnapshotCloseRows{Rows: &countRows{}, close: func() error {
				closes++
				if mode == "canceled" {
					cancel()
				}
				if mode == "close_error" {
					return closeErr
				}
				return nil
			}}, after: func(context.Context) error {
				writes++
				if closes != 1 {
					t.Error("write preceded result close")
				}
				return nil
			}}
			first, second := rows.Close(), rows.Close()
			if closes != 1 || writes > 1 || first != second {
				t.Fatal("close or writer repeated")
			}
			if mode == "closed" && (first != nil || writes != 1) || mode == "close_error" && (!errors.Is(first, closeErr) || writes != 0) || mode == "canceled" && (!errors.Is(first, context.Canceled) || writes != 0) {
				t.Fatal("write escaped failed or canceled count result", first)
			}
		})
	}
}
