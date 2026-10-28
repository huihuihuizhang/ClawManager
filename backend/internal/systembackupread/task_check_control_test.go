package systembackupread

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

type taskCheckFixture struct {
	*detailControlFixture
	checks                 [][]driver.Value
	fault                  string
	checkQueries, readRows int
	onCheck                func(context.Context)
	missingTask            bool
}

func newTaskCheckFixture(kind TaskKind) *taskCheckFixture {
	f := &taskCheckFixture{detailControlFixture: newDetailControlFixture(kind)}
	second := append([]driver.Value(nil), f.attempts[0]...)
	second[2] = int64(2)
	f.attempts = append(f.attempts, second)
	mode := map[TaskKind]string{BackupTask: "backup_validate", DrillTask: "restore_validate", PreflightTask: "preflight_diff", VerificationTask: "artifact_health"}[kind]
	category := "users"
	if kind == VerificationTask {
		category = "artifact"
	}
	for i, status := range []string{"passed", "warning", "failed", "skipped"} {
		at := f.rows[0][20].(time.Time).Add(time.Duration(i+1) * time.Second)
		row := []driver.Value{int64(i + 1), "system-backup-check-result.v1", "installation_test", string(kind), f.rows[0][1], int64(i%2 + 1), category, mode, fmt.Sprintf("owners.check.%d", i), status,
			nil, "sev_00000000-0000-4000-8000-000000000010", strings.Repeat("a", 64), nil, nil, "none", at, at.Add(time.Second)}
		switch status {
		case "warning":
			row[13] = "dependency.slow"
		case "failed":
			row[14], row[15] = "integrity", "checksum_mismatch"
		case "skipped":
			row[10] = "optional"
		}
		f.checks = append(f.checks, row)
	}
	return f
}

type taskCheckConnector struct{ f *taskCheckFixture }

func (c taskCheckConnector) Driver() driver.Driver { return pageDriver{} }
func (c taskCheckConnector) Connect(ctx context.Context) (driver.Conn, error) {
	var base driver.Connector = detailControlConnector{c.f.detailControlFixture}
	if c.f.missingTask {
		base = pageConnector{c.f.pageFixture}
	}
	conn, err := base.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &taskCheckConn{Conn: conn, f: c.f}, nil
}

type taskCheckConn struct {
	driver.Conn
	f *taskCheckFixture
}

func (c *taskCheckConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
}

func (c *taskCheckConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if !strings.Contains(query, "FROM system_backup_v2_check_results") {
		return c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
	}
	f := c.f
	f.checkQueries++
	if query != taskCheckControlSQL || !strings.Contains(query, "WHERE origin_installation_id=? AND target_type=? AND target_public_id=? ORDER BY checked_at,id LIMIT 10001") ||
		len(args) != 3 || args[0].Value != "installation_test" || args[1].Value != f.rows[0][3] || args[2].Value != f.rows[0][1] || f.rechecks != 0 || f.commits != 0 {
		return nil, errors.New("unscoped check read or read outside original authorized transaction")
	}
	if f.fault == "query" {
		return nil, errors.New("private check SQL address")
	}
	if f.onCheck != nil {
		f.onCheck(ctx)
	}
	return &taskCheckRows{pageRows: &pageRows{columns: strings.Split(taskCheckControlColumns, ","), values: f.checks}, f: f}, nil
}

type taskCheckRows struct {
	*pageRows
	f *taskCheckFixture
}

func (r *taskCheckRows) Next(dst []driver.Value) error {
	if r.f.fault == "stream" && r.f.readRows == 1 {
		return errors.New("private check stream failure")
	}
	err := r.pageRows.Next(dst)
	if err == nil {
		r.f.readRows++
	}
	return err
}

func (r *taskCheckRows) Close() error {
	if r.f.fault == "close" {
		return errors.New("private check close failure")
	}
	return nil
}

func taskCheckReader(t *testing.T, f *taskCheckFixture, probe *readCommitProbe) *Reader {
	t.Helper()
	var connector driver.Connector = taskCheckConnector{f}
	if probe != nil {
		probe.base = connector
		connector = probe
	}
	db := sql.OpenDB(connector)
	t.Cleanup(func() { db.Close() })
	r, err := NewReader(db, f)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestTaskCheckControlKindsHistoryAndPrivacy(t *testing.T) {
	for _, kind := range []TaskKind{BackupTask, DrillTask, PreflightTask, VerificationTask} {
		t.Run(string(kind), func(t *testing.T) {
			f := newTaskCheckFixture(kind)
			r := taskCheckReader(t, f, nil)
			s, err := r.ReadTaskCheckControl(context.Background(), kind, f.rows[0][1].(string))
			if err != nil || len(s.Checks()) != 4 || len(s.Detail().Execution().Attempts()) != 2 || f.checkQueries != 1 || f.rechecks != 1 || f.commits != 1 || f.rollbacks != 0 || f.options.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
				t.Fatal("check rows escaped original detail snapshot", err)
			}
			for i, c := range s.Checks() {
				if c.AttemptNumber != uint64(i%2+1) || c.Status != f.checks[i][9] || c.Code != f.checks[i][8] || !c.Evidence.PublicID.Valid {
					t.Fatal("original historical identity, outcome or evidence binding changed")
				}
			}
			copy := s.Checks()
			copy[0].Code = "changed"
			if s.Checks()[0].Code == "changed" {
				t.Fatal("mutable slice escaped")
			}
			for _, value := range []any{s, s.Checks()[0], s.Detail()} {
				if data, err := json.Marshal(value); !errors.Is(err, ErrInvalid) || len(data) != 0 {
					t.Fatal("private check contribution became a wire resource")
				}
			}
		})
	}
}

func TestTaskCheckControlRejectsCorruptRecords(t *testing.T) {
	mutations := map[string]func(*taskCheckFixture){
		"schema":               func(f *taskCheckFixture) { f.checks[0][1] = "system-backup-check-result.v2" },
		"installation":         func(f *taskCheckFixture) { f.checks[0][2] = "installation_other" },
		"kind":                 func(f *taskCheckFixture) { f.checks[0][3] = "drill" },
		"task":                 func(f *taskCheckFixture) { f.checks[0][4] = "sbk_00000000-0000-4000-8000-000000000099" },
		"zero_id":              func(f *taskCheckFixture) { f.checks[0][0] = int64(0) },
		"null_attempt":         func(f *taskCheckFixture) { f.checks[0][5] = nil },
		"zero_attempt":         func(f *taskCheckFixture) { f.checks[0][5] = int64(0) },
		"orphan_attempt":       func(f *taskCheckFixture) { f.checks[0][5] = int64(3) },
		"bad_scan":             func(f *taskCheckFixture) { f.checks[0][5] = "private nonnumeric attempt" },
		"mode":                 func(f *taskCheckFixture) { f.checks[0][7] = "restore_validate" },
		"category":             func(f *taskCheckFixture) { f.checks[0][6] = "artifact" },
		"code":                 func(f *taskCheckFixture) { f.checks[0][8] = "private message" },
		"long_code":            func(f *taskCheckFixture) { f.checks[0][8] = strings.Repeat("a", 129) },
		"status":               func(f *taskCheckFixture) { f.checks[0][9] = "pending" },
		"passed_skip":          func(f *taskCheckFixture) { f.checks[0][10] = "optional" },
		"passed_class":         func(f *taskCheckFixture) { f.checks[0][14] = "validation" },
		"warning_missing":      func(f *taskCheckFixture) { f.checks[1][13] = nil },
		"warning_invalid":      func(f *taskCheckFixture) { f.checks[1][13] = "Private Warning" },
		"failed_class":         func(f *taskCheckFixture) { f.checks[2][14] = nil },
		"failed_unknown_class": func(f *taskCheckFixture) { f.checks[2][14] = "private" },
		"failed_none":          func(f *taskCheckFixture) { f.checks[2][15] = "none" },
		"failed_unknown":       func(f *taskCheckFixture) { f.checks[2][15] = "private failure" },
		"skipped_missing":      func(f *taskCheckFixture) { f.checks[3][10] = nil },
		"skipped_unknown":      func(f *taskCheckFixture) { f.checks[3][10] = "private skip" },
		"evidence_id_only":     func(f *taskCheckFixture) { f.checks[0][12] = nil },
		"evidence_hash_only":   func(f *taskCheckFixture) { f.checks[0][11] = nil },
		"evidence_id":          func(f *taskCheckFixture) { f.checks[0][11] = "private locator" },
		"evidence_hash":        func(f *taskCheckFixture) { f.checks[0][12] = "bad" },
		"checked_zero":         func(f *taskCheckFixture) { f.checks[0][16] = time.Time{} },
		"created_zero":         func(f *taskCheckFixture) { f.checks[0][17] = time.Time{} },
		"inverted_time":        func(f *taskCheckFixture) { f.checks[0][17] = f.rows[0][20] },
		"before_attempt":       func(f *taskCheckFixture) { f.checks[0][16] = f.rows[0][20].(time.Time).Add(-time.Second) },
		"duplicate_id":         func(f *taskCheckFixture) { f.checks[1][0] = f.checks[0][0] },
		"out_of_order":         func(f *taskCheckFixture) { f.checks[0], f.checks[1] = f.checks[1], f.checks[0] },
		"duplicate_identity": func(f *taskCheckFixture) {
			row := append([]driver.Value(nil), f.checks[0]...)
			row[0] = int64(5)
			f.checks = append(f.checks, row)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			f := newTaskCheckFixture(BackupTask)
			mutate(f)
			s, err := taskCheckReader(t, f, nil).ReadTaskCheckControl(context.Background(), BackupTask, f.rows[0][1].(string))
			if err != ErrUnavailable || !reflect.ValueOf(s).IsZero() || f.commits != 0 || f.rechecks != 0 || f.rollbacks != 1 {
				t.Fatal("corrupt check row returned a partial contribution", err)
			}
		})
	}
}

func TestTaskCheckControlModeAndCategory(t *testing.T) {
	for _, tc := range []struct {
		name, category, mode, scope string
		kind                        TaskKind
		valid                       bool
	}{
		{"backup_control", "control_plane", "backup_validate", "", BackupTask, true},
		{"drill_resources", "resources", "restore_validate", "", DrillTask, true},
		{"drill_isolation", "isolation", "restore_validate", "", DrillTask, false},
		{"preflight_isolation", "isolation", "preflight_diff", "", PreflightTask, true},
		{"health_artifact", "artifact", "artifact_health", "health", VerificationTask, true},
		{"full_artifact", "artifact", "artifact_full", "full", VerificationTask, true},
		{"full_not_health", "artifact", "artifact_health", "full", VerificationTask, false},
		{"health_not_full", "artifact", "artifact_full", "health", VerificationTask, false},
		{"health_not_business", "users", "artifact_health", "health", VerificationTask, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newTaskCheckFixture(tc.kind)
			if tc.scope != "" {
				f.values["verification_scope"] = tc.scope
			}
			for _, row := range f.checks {
				row[6], row[7] = tc.category, tc.mode
			}
			s, err := taskCheckReader(t, f, nil).ReadTaskCheckControl(context.Background(), tc.kind, f.rows[0][1].(string))
			if tc.valid && (err != nil || len(s.Checks()) != 4) || !tc.valid && (err != ErrUnavailable || !reflect.ValueOf(s).IsZero()) {
				t.Fatal("task mode/category binding changed", err)
			}
		})
	}
}

func TestTaskCheckControlEmptyAndBudget(t *testing.T) {
	for _, count := range []int{0, maxTaskCheckControlRows, maxTaskCheckControlRows + 50} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			f := newTaskCheckFixture(BackupTask)
			seed := f.checks[0]
			f.checks = nil
			for i := 0; i < count; i++ {
				row := append([]driver.Value(nil), seed...)
				row[0], row[8] = int64(i+1), fmt.Sprintf("check.%d", i)
				f.checks = append(f.checks, row)
			}
			s, err := taskCheckReader(t, f, nil).ReadTaskCheckControl(context.Background(), BackupTask, f.rows[0][1].(string))
			if count <= maxTaskCheckControlRows {
				if err != nil || len(s.Checks()) != count || s.Checks() == nil || f.readRows != count {
					t.Fatal("complete or empty bounded result changed", err)
				}
			} else if err != ErrUnavailable || !reflect.ValueOf(s).IsZero() || f.readRows != maxTaskCheckControlRows+1 || f.commits != 0 {
				t.Fatal("check budget truncated or consumed an unbounded result", err, f.readRows)
			}
		})
	}
}

func TestTaskCheckControlAuthorityAndCompletion(t *testing.T) {
	for _, name := range []string{"deny", "revoke", "query", "stream", "close", "cancel", "commit", "late_commit", "missing"} {
		t.Run(name, func(t *testing.T) {
			f := newTaskCheckFixture(BackupTask)
			id := f.rows[0][1].(string)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := ErrUnavailable
			var probe *readCommitProbe
			switch name {
			case "deny":
				f.deny, want = true, ErrDenied
			case "revoke":
				f.recheckErr, want = true, ErrDenied
			case "query", "stream", "close":
				f.fault = name
			case "cancel":
				f.onCheck = func(context.Context) { cancel() }
			case "commit":
				f.commitErr = errors.New("private commit failure")
			case "late_commit":
				probe = &readCommitProbe{afterCommit: cancel}
			case "missing":
				f.missingTask, f.rows, want = true, nil, ErrNotFound
			}
			s, err := taskCheckReader(t, f, probe).ReadTaskCheckControl(ctx, BackupTask, id)
			if !errors.Is(err, want) || !reflect.ValueOf(s).IsZero() {
				t.Fatal("authority, SQL or completion failure returned contribution", err)
			}
			if name == "deny" || name == "missing" {
				if f.checkQueries != 0 {
					t.Fatal("check rows read without an authorized existing task")
				}
			} else if f.checkQueries != 1 {
				t.Fatal("fault did not reach the intended check read")
			}
			if name == "late_commit" && (f.commits != 1 || f.rollbacks != 0 || f.rechecks != 1 || ctx.Err() != context.Canceled) {
				t.Fatal("late-commit fault missed original authority boundary")
			}
		})
	}
}

func TestTaskCheckControlFutureBuilderIsAtomic(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(fmt.Sprint(reject), func(t *testing.T) {
			f := newTaskCheckFixture(BackupTask)
			r := taskCheckReader(t, f, nil)
			got, err := readTaskCheckControlInTransaction(context.Background(), r, BackupTask, f.rows[0][1].(string),
				func(ctx context.Context, q detailReadSQL, s TaskCheckControlSnapshot) (int, error) {
					if _, exposed := any(q).(interface{ Commit() error }); exposed {
						t.Fatal("builder received transaction control")
					}
					again, err := readTaskCheckControl(ctx, q, s.detail)
					if err != nil || len(again.checks) != 4 || f.commits != 0 || f.rechecks != 0 {
						t.Fatal("future Owner composition left the original snapshot", err)
					}
					if reject {
						return 4, errors.New("private later Owner failure")
					}
					return len(s.Checks()), nil
				})
			if reject && (err != ErrUnavailable || got != 0 || f.commits != 0 || f.rollbacks != 1) || !reject && (err != nil || got != 4 || f.commits != 1 || f.rechecks != 1) || f.checkQueries != 2 {
				t.Fatal("builder failure or success was not atomic", err)
			}
		})
	}
}

func TestTaskCheckControlUsesCheckTimeAndIDOrder(t *testing.T) {
	for _, name := range []string{"check_time", "equal_time_ids", "equal_time_out_of_order"} {
		t.Run(name, func(t *testing.T) {
			f := newTaskCheckFixture(BackupTask)
			for i, row := range f.checks {
				if name == "check_time" {
					// Check time, not insertion ID or attempt, defines query order.
					row[0] = int64(100 - i)
				} else {
					row[16], row[17] = f.checks[0][16], f.checks[0][17]
				}
			}
			if name == "equal_time_out_of_order" {
				f.checks[0], f.checks[1] = f.checks[1], f.checks[0]
			}
			s, err := taskCheckReader(t, f, nil).ReadTaskCheckControl(context.Background(), BackupTask, f.rows[0][1].(string))
			if name == "equal_time_out_of_order" {
				if err != ErrUnavailable || !reflect.ValueOf(s).IsZero() {
					t.Fatal("unstable equal-time check order accepted", err)
				}
			} else if err != nil || len(s.Checks()) != 4 || s.Checks()[0].ID != uint64(f.checks[0][0].(int64)) {
				t.Fatal("check time and ID query order changed", err)
			}
		})
	}
}

func TestTaskCheckControlSQLContract(t *testing.T) {
	ddl, err := os.ReadFile("../db/migrations/103_backup_v2_add_system_backup_check_authority.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, column := range strings.Split(taskCheckControlColumns, ",") {
		if !regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(column) + `\s`).Match(ddl) {
			t.Fatal("check projection column missing from reviewed migration", column)
		}
	}
	for _, private := range []string{"expected_", "actual_", "canonical_json", "SELECT *"} {
		if strings.Contains(taskCheckControlSQL, private) {
			t.Fatal("private payload selected")
		}
	}
	if !strings.HasPrefix(taskCheckControlSQL, "SELECT ") || !strings.HasSuffix(taskCheckControlSQL, "WHERE origin_installation_id=? AND target_type=? AND target_public_id=? ORDER BY checked_at,id LIMIT 10001") {
		t.Fatal("check query lacks installation/type/task binding, order or bounded lookahead")
	}
	if !strings.Contains(string(ddl), "KEY idx_sb_check_result_target (target_type, target_public_id, checked_at, id)") {
		t.Fatal("reviewed index no longer supports check-time and ID ordering")
	}
}
