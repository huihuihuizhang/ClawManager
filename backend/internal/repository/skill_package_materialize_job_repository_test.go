package repository_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"clawreef/internal/repository"
	"github.com/upper/db/v4/adapter/mysql"
)

// The real upper/db adapter and database/sql execute repository SQL against a
// scripted transport. Faults occur after a prior claim has been acknowledged.
func TestMaterializeClaimReturnsAcknowledgedJobsOnPartialFailure(t *testing.T) {
	for _, mode := range []string{"update", "rows_affected", "load", "missing", "lost_race", "success"} {
		t.Run(mode, func(t *testing.T) {
			fault := errors.New("injected claim failure")
			state := &materializeClaimConnector{mode: mode, fault: fault}
			pool := sql.OpenDB(state)
			t.Cleanup(func() { pool.Close() })
			session, err := mysql.New(pool)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { session.Close() })
			jobs, err := repository.NewSkillPackageMaterializeJobRepository(session).ClaimNextPending(context.Background(), 3)
			switch mode {
			case "success":
				if err != nil || len(jobs) != 3 {
					t.Fatalf("jobs=%v error=%v", jobs, err)
				}
			case "lost_race":
				if err != nil || len(jobs) != 2 || jobs[0].ID != 1 || jobs[1].ID != 3 {
					t.Fatalf("jobs=%v error=%v", jobs, err)
				}
			case "missing":
				if err == nil || len(jobs) != 2 || jobs[1].ID != 2 {
					t.Fatalf("lost acknowledged claim: jobs=%v error=%v", jobs, err)
				}
			default:
				if !errors.Is(err, fault) {
					t.Fatalf("error=%v", err)
				}
				want := 1
				if mode == "load" {
					want = 2
				}
				if len(jobs) != want || jobs[0].ID != 1 {
					t.Fatalf("acknowledged claims=%v want=%d", jobs, want)
				}
				if mode == "load" && jobs[1].ID != 2 {
					t.Fatal("missing minimal cleanup claim")
				}
			}
			// On SQL acknowledgement failure, ownership of job 2 is unknown. It must
			// not be returned as owned and accidentally released by this worker.
			if (mode == "update" || mode == "rows_affected") && len(jobs) != 1 {
				t.Fatal("invented ownership")
			}
		})
	}
}

type materializeClaimConnector struct {
	mode  string
	fault error
}

func (c *materializeClaimConnector) Connect(context.Context) (driver.Conn, error) {
	return &materializeClaimConn{c}, nil
}
func (c *materializeClaimConnector) Driver() driver.Driver { return materializeClaimDriver{} }

type materializeClaimDriver struct{}

func (materializeClaimDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("connector required")
}

type materializeClaimConn struct{ state *materializeClaimConnector }

func (*materializeClaimConn) Close() error { return nil }
func (*materializeClaimConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (*materializeClaimConn) Begin() (driver.Tx, error) {
	return nil, errors.New("unexpected transaction")
}
func (c *materializeClaimConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	q = strings.Join(strings.Fields(q), " ")
	if q == "SELECT DATABASE() AS name" {
		return &materializeClaimRows{columns: []string{"name"}, rows: [][]driver.Value{{"offline_materialize"}}}, nil
	}
	if strings.HasPrefix(q, "SELECT id FROM skill_package_materialize_jobs") {
		return &materializeClaimRows{columns: []string{"id"}, rows: [][]driver.Value{{int64(1)}, {int64(2)}, {int64(3)}}}, nil
	}
	if strings.Contains(q, "`information_schema`.`key_column_usage`") {
		return &materializeClaimRows{columns: []string{"column_name"}, rows: [][]driver.Value{{"id"}}}, nil
	}
	if strings.Contains(q, "skill_package_materialize_jobs") && len(args) > 0 {
		id, ok := args[0].Value.(int64)
		if !ok {
			return nil, fmt.Errorf("unexpected id %T", args[0].Value)
		}
		if id == 2 && c.state.mode == "load" {
			return nil, c.state.fault
		}
		rows := [][]driver.Value{{id, int64(10), "running"}}
		if id == 2 && c.state.mode == "missing" {
			rows = nil
		}
		return &materializeClaimRows{columns: []string{"id", "instance_id", "status"}, rows: rows}, nil
	}
	return nil, fmt.Errorf("unexpected query: %s", q)
}
func (c *materializeClaimConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if !strings.Contains(q, "WHERE id = ? AND status = 'pending'") || len(args) != 3 {
		return nil, fmt.Errorf("unexpected update: %s", q)
	}
	id, ok := args[2].Value.(int64)
	if !ok {
		return nil, fmt.Errorf("unexpected id %T", args[2].Value)
	}
	if id == 2 {
		switch c.state.mode {
		case "update":
			return nil, c.state.fault
		case "rows_affected":
			return materializeClaimResult{err: c.state.fault}, nil
		case "lost_race":
			return driver.RowsAffected(0), nil
		}
	}
	return driver.RowsAffected(1), nil
}

type materializeClaimResult struct{ err error }

func (r materializeClaimResult) LastInsertId() (int64, error) { return 0, nil }
func (r materializeClaimResult) RowsAffected() (int64, error) { return 0, r.err }

type materializeClaimRows struct {
	columns []string
	rows    [][]driver.Value
	index   int
}

func (r *materializeClaimRows) Columns() []string { return r.columns }
func (*materializeClaimRows) Close() error        { return nil }
func (r *materializeClaimRows) Next(dest []driver.Value) error {
	if r.index >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.index])
	r.index++
	return nil
}
