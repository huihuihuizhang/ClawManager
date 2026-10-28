package systembackupread

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// The driver deliberately ignores SQL LIMIT. The reader must independently
// reject overflow, close that cursor and never invoke the detail builder.
type executionBoundsFixture struct {
	*executionFixture
	attemptCount, jobCount           int
	attemptsDelivered, jobsDelivered int
	attemptCloses, jobCloses         int
}
type executionBoundsConnector struct{ f *executionBoundsFixture }

func (c executionBoundsConnector) Connect(context.Context) (driver.Conn, error) {
	return &executionBoundsConn{executionConn: &executionConn{c.f.executionFixture}, f: c.f}, nil
}
func (executionBoundsConnector) Driver() driver.Driver { return pageDriver{} }

type executionBoundsConn struct {
	*executionConn
	f *executionBoundsFixture
}

func (c *executionBoundsConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	rows, err := c.executionConn.QueryContext(ctx, query, args)
	if err != nil {
		return nil, err
	}
	attempts := strings.Contains(query, "system_backup_v2_attempts AS a")
	jobs := query == taskJobsSQL
	if !attempts && !jobs {
		return rows, nil
	}
	// Reuse the established argument/installation validation, but supply a
	// lazy, syntactically valid large stream rather than a materialized fixture.
	columns := rows.Columns()
	if err := rows.Close(); err != nil {
		return nil, err
	}
	count, template := c.f.jobCount, c.f.jobs[0]
	if attempts {
		count, template = c.f.attemptCount, c.f.attempts[0]
	}
	return &executionBoundsRows{f: c.f, columns: columns, template: template, count: count, attempts: attempts}, nil
}

type executionBoundsRows struct {
	f                *executionBoundsFixture
	columns          []string
	template         []driver.Value
	count, index     int
	attempts, closed bool
}

func (r *executionBoundsRows) Columns() []string { return r.columns }
func (r *executionBoundsRows) Close() error {
	if r.closed {
		return errors.New("execution cursor closed twice")
	}
	r.closed = true
	if r.attempts {
		r.f.attemptCloses++
	} else {
		r.f.jobCloses++
	}
	return nil
}
func (r *executionBoundsRows) Next(dest []driver.Value) error {
	if r.closed {
		return errors.New("read after execution cursor close")
	}
	if r.index == r.count {
		return io.EOF
	}
	r.index++
	copy(dest, r.template)
	if r.attempts {
		dest[2] = int64(r.index)
		r.f.attemptsDelivered++
	} else {
		dest[6] = fmt.Sprintf("source_%05d", r.index)
		dest[7] = fmt.Sprintf("00000000-0000-4000-8000-%012d", r.index)
		r.f.jobsDelivered++
	}
	return nil
}
func TestTaskExecutionRowBounds(t *testing.T) {
	for _, kind := range []TaskKind{BackupTask, DrillTask, PreflightTask, VerificationTask} {
		for _, component := range []string{"attempts", "jobs"} {
			for _, count := range []int{0, 1, 9999, 10000, 10001, 10002} {
				t.Run(fmt.Sprintf("%s/%s/%d", kind, component, count), func(t *testing.T) {
					f := &executionBoundsFixture{executionFixture: newExecutionFixture(kind), attemptCount: 1}
					if component == "attempts" {
						f.attemptCount = count
					} else {
						f.jobCount = count
					}
					db := sql.OpenDB(executionBoundsConnector{f})
					t.Cleanup(func() { db.Close() })
					reader, err := NewReader(db, f.executionFixture)
					if err != nil {
						t.Fatal(err)
					}
					built := false
					snapshot, err := readTaskExecutionInTransaction(context.Background(), reader, kind, f.rows[0][1].(string),
						func(_ context.Context, _ detailReadSQL, s TaskExecutionSnapshot) (TaskExecutionSnapshot, error) {
							built = true
							return s, nil
						})
					if count > 10000 {
						if !errors.Is(err, ErrUnavailable) || built || snapshot.Task().PublicID != "" || len(snapshot.attempts) != 0 || len(snapshot.jobs) != 0 || f.commits != 0 || f.rollbacks != 1 || f.rechecks != 0 {
							t.Fatalf("overflow escaped: error=%v builder=%t attempts=%d jobs=%d commit=%d rollback=%d recheck=%d", err, built, len(snapshot.attempts), len(snapshot.jobs), f.commits, f.rollbacks, f.rechecks)
						}
						if component == "attempts" {
							if f.attemptsDelivered != 10001 || f.jobsDelivered != 0 || f.attemptCloses != 1 || f.jobCloses != 0 || len(f.queries) != 2 {
								t.Fatal("attempt overflow continued into jobs", f.attemptsDelivered, f.jobsDelivered, f.attemptCloses, f.jobCloses, len(f.queries))
							}
						} else if f.attemptsDelivered != 1 || f.jobsDelivered != 10001 || f.attemptCloses != 1 || f.jobCloses != 1 || len(f.queries) != 3 {
							t.Fatal("job overflow read past sentinel or leaked cursor", f.attemptsDelivered, f.jobsDelivered, f.attemptCloses, f.jobCloses, len(f.queries))
						}
						return
					}
					if err != nil || !built || len(snapshot.attempts) != f.attemptCount || len(snapshot.jobs) != f.jobCount || f.commits != 1 || f.rollbacks != 0 || f.rechecks != 1 || f.options.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
						t.Fatalf("complete bounded snapshot rejected: error=%v builder=%t attempts=%d jobs=%d commit=%d rollback=%d recheck=%d", err, built, len(snapshot.attempts), len(snapshot.jobs), f.commits, f.rollbacks, f.rechecks)
					}
					if f.attemptsDelivered != f.attemptCount || f.jobsDelivered != f.jobCount || f.attemptCloses != 1 || f.jobCloses != 1 {
						t.Fatal("rows lost or cursor left open", f.attemptsDelivered, f.jobsDelivered, f.attemptCloses, f.jobCloses)
					}
					if component == "attempts" && count > 0 && snapshot.attempts[count-1].Number != uint64(count) {
						t.Fatal("last historical attempt lost")
					}
					if component == "jobs" && count > 0 && snapshot.jobs[count-1].JobUnitKey != fmt.Sprintf("source_%05d", count) {
						t.Fatal("last Job unit lost")
					}
				})
			}
		}
	}
}
func TestTaskExecutionRowLimitSQL(t *testing.T) {
	for _, kind := range []TaskKind{BackupTask, DrillTask, PreflightTask, VerificationTask} {
		for component, query := range map[string]string{"attempts": taskAttemptsSQL(taskTables[kind]), "jobs": taskJobsSQL} {
			t.Run(string(kind)+"/"+component, func(t *testing.T) {
				if !strings.HasSuffix(query, " LIMIT 10001") || strings.Count(query, "LIMIT") != 1 {
					t.Fatal("execution query lacks the bounded overflow sentinel", query)
				}
			})
		}
	}
}
