package systembackupread

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type executionFixture struct {
	*pageFixture
	attempts, jobs                    [][]driver.Value
	options                           driver.TxOptions
	authorizeErr, finalErr, commitErr error
	queryError, streamError           string
	commits, rollbacks                int
	rollbackDone                      chan struct{}
}

func newExecutionFixture(kind TaskKind) *executionFixture {
	table := taskTables[kind]
	page := makePageFixture(table.name, string(kind), table.prefix)
	phase := map[TaskKind]string{BackupTask: "capture", DrillTask: "restore", PreflightTask: "preflight", VerificationTask: "verify"}[kind]
	now := page.rows[0][20].(time.Time)
	id := page.rows[0][1].(string)
	return &executionFixture{pageFixture: page, rollbackDone: make(chan struct{}),
		attempts: [][]driver.Value{{string(kind), id, int64(1), phase, "running", "none", int64(1), now, nil, now, now}},
		jobs: [][]driver.Value{{"system-backup-job-observation.v1", "installation_test", string(kind), id, int64(1), phase, "source_mysql",
			"00000000-0000-4000-8000-000000000010", int64(2), int64(5), strings.Repeat("a", 64), "running", now.Add(4 * time.Second),
			int64(3), strings.Repeat("b", 64), now.Add(2 * time.Second), int64(2), now, now.Add(time.Minute), now, now.Add(4 * time.Second)}},
	}
}
func (f *executionFixture) AuthorizeRead(ctx context.Context, tx *sql.Tx) (string, error) {
	if f.authorizeErr != nil {
		return "", f.authorizeErr
	}
	return f.pageFixture.AuthorizeRead(ctx, tx)
}
func (f *executionFixture) RecheckRead(ctx context.Context, tx *sql.Tx, installation string) error {
	if err := f.pageFixture.RecheckRead(ctx, tx, installation); err != nil {
		return err
	}
	return f.finalErr
}

type executionConnector struct{ f *executionFixture }

func (c executionConnector) Connect(context.Context) (driver.Conn, error) {
	return &executionConn{c.f}, nil
}
func (executionConnector) Driver() driver.Driver { return pageDriver{} }

type executionConn struct{ f *executionFixture }

func (*executionConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (*executionConn) Close() error { return nil }
func (c *executionConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}
func (c *executionConn) BeginTx(_ context.Context, options driver.TxOptions) (driver.Tx, error) {
	c.f.options = options
	return executionTx{c.f}, nil
}

type executionTx struct{ f *executionFixture }

func (tx executionTx) Commit() error   { tx.f.commits++; return tx.f.commitErr }
func (tx executionTx) Rollback() error { tx.f.rollbacks++; close(tx.f.rollbackDone); return nil }
func (c *executionConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	f := c.f
	if strings.Contains(query, "system_backup_v2_attempts AS a") || query == taskJobsSQL {
		f.queries = append(f.queries, query)
		if query == f.queryError {
			return nil, errors.New("execution query failure")
		}
		if len(args) != 3 || args[0].Value != "installation_test" {
			return nil, errors.New("unscoped execution query")
		}
		var values [][]driver.Value
		var columns []string
		if query == taskJobsSQL {
			if args[1].Value != f.rows[0][3] || args[2].Value != f.rows[0][1] {
				return nil, errors.New("incorrect job binding")
			}
			values = f.jobs
			columns = strings.Split(taskJobColumns, ",")
		} else {
			if query != taskAttemptsSQL(taskTables[TaskKind(f.rows[0][3].(string))]) || args[1].Value != f.rows[0][1] || args[2].Value != f.rows[0][3] {
				return nil, errors.New("incorrect installation task join")
			}
			values = f.attempts
			columns = strings.Split(taskAttemptColumns, ",")
		}
		rows := &pageRows{columns: columns, values: values}
		if f.streamError == query {
			return &overviewErrorRows{rows, true}, nil
		}
		return rows, nil
	}
	return (&pageConn{f.pageFixture}).QueryContext(ctx, query, args)
}
func executionReader(t *testing.T, f *executionFixture) *Reader {
	t.Helper()
	db := sql.OpenDB(executionConnector{f})
	t.Cleanup(func() { db.Close() })
	r, err := NewReader(db, f)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestTaskExecutionFourKindsScopedCompleteAndPrivate(t *testing.T) {
	for _, kind := range []TaskKind{BackupTask, DrillTask, PreflightTask, VerificationTask} {
		t.Run(string(kind), func(t *testing.T) {
			f := newExecutionFixture(kind)
			r := executionReader(t, f)
			// Two current units and an earlier attempt are all preserved.
			old := append([]driver.Value{}, f.attempts[0]...)
			f.attempts[0][2] = int64(2)
			f.attempts = append([][]driver.Value{old}, f.attempts...)
			f.jobs[0][4] = int64(2)
			second := append([]driver.Value{}, f.jobs[0]...)
			second[6] = "source_redis"
			second[7] = "00000000-0000-4000-8000-000000000011"
			f.jobs = append(f.jobs, second)
			s, err := r.ReadTaskExecution(context.Background(), kind, f.rows[0][1].(string))
			if err != nil || len(s.Attempts()) != 2 || len(s.JobObservations()) != 2 || s.Task().Kind != kind || f.options.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || f.rechecks != 1 || f.commits != 1 || f.rollbacks != 0 {
				t.Fatal("incomplete snapshot", s, err, f.options, f.rechecks, f.commits)
			}
			if len(f.queries) != 3 || !strings.Contains(f.queries[1], "a.target_type=t.task_type WHERE t.origin_installation_id=? AND t.public_id=?") {
				t.Fatal("attempts did not rejoin scoped task", f.queries)
			}
			for _, query := range f.queries {
				for _, forbidden := range []string{"failure_message", "config_snapshot_json", "relay_identity_ref,", "command_nonce", "certificate_sha256", "SELECT *"} {
					if strings.Contains(query, forbidden) {
						t.Fatal("private payload selected", forbidden)
					}
				}
			}
			attempts, jobs := s.Attempts(), s.JobObservations()
			attempts[0].Status = "corrupted"
			jobs[0].JobUID = "corrupted"
			if s.Attempts()[0].Status == "corrupted" || s.JobObservations()[0].JobUID == "corrupted" {
				t.Fatal("accessor aliases snapshot")
			}
			for _, value := range []any{s, s.Attempts()[0], s.JobObservations()[0]} {
				if _, err = json.Marshal(value); !errors.Is(err, ErrInvalid) {
					t.Fatal("internal contribution serialized", err)
				}
			}
			// A heartbeat advancing observation does not advance progress.
			before := s.JobObservations()[0].BusinessProgressAt
			f.jobs[0][9] = int64(6)
			f.jobs[0][12] = f.jobs[0][12].(time.Time).Add(time.Second)
			after, err := r.ReadTaskExecution(context.Background(), kind, f.rows[0][1].(string))
			if err != nil || after.JobObservations()[0].BusinessProgressAt != before {
				t.Fatal("heartbeat changed progress", err)
			}
		})
	}
}

func TestTaskExecutionRejectsCorruptAttemptsAndObservations(t *testing.T) {
	cases := map[string]func(*executionFixture){
		"attempt foreign ID":                  func(f *executionFixture) { f.attempts[0][1] = "sbk_00000000-0000-4000-8000-000000000099" },
		"attempt wrong kind":                  func(f *executionFixture) { f.attempts[0][0] = "drill" },
		"attempt zero":                        func(f *executionFixture) { f.attempts[0][2] = int64(0) },
		"attempt outside unsigned int":        func(f *executionFixture) { f.attempts[0][2] = int64(1 << 32) },
		"attempt phase":                       func(f *executionFixture) { f.attempts[0][3] = "restore" },
		"attempt unknown status":              func(f *executionFixture) { f.attempts[0][4] = "done" },
		"attempt unknown failure":             func(f *executionFixture) { f.attempts[0][5] = "unreviewed_failure" },
		"attempt unsafe version":              func(f *executionFixture) { f.attempts[0][6] = int64(maxJSONSafeInteger + 1) },
		"running missing start":               func(f *executionFixture) { f.attempts[0][7] = nil },
		"running finished":                    func(f *executionFixture) { f.attempts[0][8] = f.attempts[0][9] },
		"capture succeeded instead of sealed": func(f *executionFixture) { f.attempts[0][4] = "succeeded"; f.attempts[0][8] = f.attempts[0][9] },
		"failed missing category":             func(f *executionFixture) { f.attempts[0][4] = "failed"; f.attempts[0][8] = f.attempts[0][9] },
		"failed canceled category": func(f *executionFixture) {
			f.attempts[0][4] = "failed"
			f.attempts[0][5] = "canceled_by_actor"
			f.attempts[0][8] = f.attempts[0][9]
		},
		"canceled wrong category": func(f *executionFixture) {
			f.attempts[0][4] = "canceled"
			f.attempts[0][5] = "internal_error"
			f.attempts[0][8] = f.attempts[0][9]
		},
		"attempt backwards update":       func(f *executionFixture) { f.attempts[0][10] = f.attempts[0][9].(time.Time).Add(-time.Second) },
		"duplicate attempt":              func(f *executionFixture) { f.attempts = append(f.attempts, f.attempts[0]) },
		"job schema":                     func(f *executionFixture) { f.jobs[0][0] = "system-backup-job-observation.v2" },
		"job foreign installation":       func(f *executionFixture) { f.jobs[0][1] = "installation_other" },
		"job foreign ID":                 func(f *executionFixture) { f.jobs[0][3] = "sbk_00000000-0000-4000-8000-000000000099" },
		"job wrong kind":                 func(f *executionFixture) { f.jobs[0][2] = "drill" },
		"job missing attempt":            func(f *executionFixture) { f.jobs[0][4] = int64(2) },
		"job wrong phase":                func(f *executionFixture) { f.jobs[0][5] = "publish" },
		"job unit key":                   func(f *executionFixture) { f.jobs[0][6] = "1_bad" },
		"job UID":                        func(f *executionFixture) { f.jobs[0][7] = "unreviewed" },
		"job zero generation":            func(f *executionFixture) { f.jobs[0][8] = int64(0) },
		"job unsafe generation":          func(f *executionFixture) { f.jobs[0][8] = int64(maxJSONSafeInteger + 1) },
		"job unsafe accepted sequence":   func(f *executionFixture) { f.jobs[0][9] = int64(maxJSONSafeInteger + 1) },
		"job body hash":                  func(f *executionFixture) { f.jobs[0][10] = "bad" },
		"job observed status":            func(f *executionFixture) { f.jobs[0][11] = "Running" },
		"job missing observation time":   func(f *executionFixture) { f.jobs[0][12] = nil },
		"job observation before binding": func(f *executionFixture) { f.jobs[0][12] = f.jobs[0][17].(time.Time).Add(-time.Second) },
		"job progress beyond accepted":   func(f *executionFixture) { f.jobs[0][13] = int64(6) },
		"job progress digest":            func(f *executionFixture) { f.jobs[0][14] = "bad" },
		"job missing progress time":      func(f *executionFixture) { f.jobs[0][15] = nil },
		"job progress after observation": func(f *executionFixture) { f.jobs[0][15] = f.jobs[0][12].(time.Time).Add(time.Second) },
		"job zero version":               func(f *executionFixture) { f.jobs[0][16] = int64(0) },
		"job expired before bound":       func(f *executionFixture) { f.jobs[0][18] = f.jobs[0][17] },
		"job zero created":               func(f *executionFixture) { f.jobs[0][19] = time.Time{} },
		"duplicate job unit":             func(f *executionFixture) { f.jobs = append(f.jobs, f.jobs[0]) },
		"duplicate job UID": func(f *executionFixture) {
			j := append([]driver.Value{}, f.jobs[0]...)
			j[6] = "source_redis"
			f.jobs = append(f.jobs, j)
		},
		"zero cursor has payload":   func(f *executionFixture) { f.jobs[0][9] = int64(0); f.jobs[0][13] = int64(0) },
		"zero progress has payload": func(f *executionFixture) { f.jobs[0][13] = int64(0) },
		"attempt scan error":        func(f *executionFixture) { f.attempts[0][2] = "not-a-number" },
		"job scan error":            func(f *executionFixture) { f.jobs[0][8] = "not-a-number" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newExecutionFixture(BackupTask)
			mutate(f)
			r := executionReader(t, f)
			s, err := r.ReadTaskExecution(context.Background(), BackupTask, f.rows[0][1].(string))
			if !errors.Is(err, ErrUnavailable) || s.Task().PublicID != "" || len(s.Attempts()) != 0 || len(s.JobObservations()) != 0 || f.commits != 0 || f.rollbacks != 1 {
				t.Fatal("partial/corrupt execution escaped", s, err, f.commits, f.rollbacks)
			}
		})
	}
}

func TestTaskExecutionKnownEmptyAndStatusVariants(t *testing.T) {
	for _, status := range []string{"empty", "preparing", "sealed", "failed", "canceled", "no progress", "no observation", "succeeded"} {
		t.Run(status, func(t *testing.T) {
			kind := BackupTask
			if status == "succeeded" {
				kind = DrillTask
			}
			f := newExecutionFixture(kind)
			now := f.attempts[0][9]
			switch status {
			case "empty":
				f.attempts = nil
				f.jobs = nil
			case "preparing":
				f.attempts[0][4] = "preparing"
				f.attempts[0][7] = nil
				f.jobs = nil
			case "sealed", "succeeded":
				f.attempts[0][4] = status
				f.attempts[0][8] = now
			case "failed":
				f.attempts[0][4] = "failed"
				f.attempts[0][5] = "internal_error"
				f.attempts[0][8] = now
			case "canceled":
				f.attempts[0][4] = "canceled"
				f.attempts[0][5] = "canceled_by_actor"
				f.attempts[0][8] = now
			case "no progress":
				f.jobs[0][13] = int64(0)
				f.jobs[0][14] = nil
				f.jobs[0][15] = nil
			case "no observation":
				f.jobs[0][9] = int64(0)
				f.jobs[0][10] = nil
				f.jobs[0][11] = nil
				f.jobs[0][12] = nil
				f.jobs[0][13] = int64(0)
				f.jobs[0][14] = nil
				f.jobs[0][15] = nil
			}
			r := executionReader(t, f)
			s, err := r.ReadTaskExecution(context.Background(), kind, f.rows[0][1].(string))
			if err != nil || s.Task().PublicID == "" {
				t.Fatal("valid execution rejected", s, err)
			}
			if status == "empty" && (s.Attempts() == nil || s.JobObservations() == nil || len(s.Attempts()) != 0 || len(s.JobObservations()) != 0) {
				t.Fatal("known empty contribution absent")
			}
		})
	}
}

func TestTaskExecutionTransactionFailureAndAuthorityCauses(t *testing.T) {
	permission := errors.New("authority permission rejected")
	for _, stage := range []string{"authorize", "recheck", "commit", "attempt SQL", "job SQL", "attempt stream", "job stream", "missing", "missing revoked"} {
		t.Run(stage, func(t *testing.T) {
			f := newExecutionFixture(BackupTask)
			id := f.rows[0][1].(string)
			want := ErrUnavailable
			switch stage {
			case "authorize":
				f.authorizeErr = permission
				want = ErrDenied
			case "recheck":
				f.finalErr = permission
				want = ErrDenied
			case "commit":
				f.commitErr = errors.New("commit unknown")
			case "attempt SQL":
				f.queryError = taskAttemptsSQL(taskTables[BackupTask])
			case "job SQL":
				f.queryError = taskJobsSQL
			case "attempt stream":
				f.streamError = taskAttemptsSQL(taskTables[BackupTask])
			case "job stream":
				f.streamError = taskJobsSQL
			case "missing":
				id = "sbk_00000000-0000-4000-8000-000000000099"
				want = ErrNotFound
			case "missing revoked":
				id = "sbk_00000000-0000-4000-8000-000000000099"
				f.finalErr = permission
				want = ErrDenied
			}
			r := executionReader(t, f)
			s, err := r.ReadTaskExecution(context.Background(), BackupTask, id)
			if !errors.Is(err, want) || !reflect.DeepEqual(s, TaskExecutionSnapshot{}) {
				t.Fatal("transaction failure leaked result", s, err)
			}
			if (stage == "authorize" || stage == "recheck" || stage == "missing revoked") && !errors.Is(err, permission) {
				t.Fatal("authority cause lost", err)
			}
			if stage == "authorize" && len(f.queries) != 0 {
				t.Fatal("unauthorized query")
			}
			if strings.HasPrefix(stage, "missing") && (f.rechecks != 1 || len(f.queries) != 1) {
				t.Fatal("missing queried attempts or skipped authority recheck", f.rechecks, f.queries)
			}
		})
	}
}

func TestTaskExecutionBuilderSharesSnapshotAndCannotCommit(t *testing.T) {
	for _, stage := range []string{"success", "owner failure", "revoked", "canceled"} {
		t.Run(stage, func(t *testing.T) {
			f := newExecutionFixture(BackupTask)
			r := executionReader(t, f)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result, err := readTaskExecutionInTransaction(ctx, r, BackupTask, f.rows[0][1].(string), func(ctx context.Context, q detailReadSQL, s TaskExecutionSnapshot) (string, error) {
				if len(s.attempts) != 1 || len(s.jobs) != 1 || f.rechecks != 0 || f.commits != 0 {
					t.Fatal("builder lacks uncommitted execution")
				}
				if _, ok := q.(*sql.Tx); ok {
					t.Fatal("raw transaction escaped")
				}
				if _, ok := q.(interface{ Commit() error }); ok {
					t.Fatal("commit escaped")
				}
				if _, ok := q.(interface {
					ExecContext(context.Context, string, ...any) (sql.Result, error)
				}); ok {
					t.Fatal("exec escaped")
				}
				var count int
				if e := q.QueryRowContext(ctx, "SELECT COALESCE(MAX(id),0) FROM system_backup_v2_backups WHERE origin_installation_id=?", s.task.InstallationID).Scan(&count); e != nil || count != 3 {
					t.Fatal("builder query unavailable", count, e)
				}
				switch stage {
				case "owner failure":
					return "partial", errors.New("missing owner proof")
				case "revoked":
					f.recheckErr = true
				case "canceled":
					cancel()
				}
				return "complete", nil
			})
			if stage == "success" {
				if err != nil || result != "complete" || f.commits != 1 {
					t.Fatal("complete builder rejected", result, err)
				}
			} else {
				if result != "" || err == nil {
					t.Fatal("failed builder escaped", result, err)
				}
				if stage == "canceled" {
					select {
					case <-f.rollbackDone:
					case <-time.After(time.Second):
						t.Fatal("canceled transaction did not roll back")
					}
				}
				if f.commits != 0 {
					t.Fatal("failed builder committed")
				}
			}
		})
	}
}
