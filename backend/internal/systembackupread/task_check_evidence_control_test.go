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
)

type checkEvidenceFixture struct {
	*taskCheckFixture
	bindings          [][]driver.Value
	fault             string
	queries, readRows int
	onRead            func()
}

func newCheckEvidenceFixture(kind TaskKind) *checkEvidenceFixture {
	f := &checkEvidenceFixture{taskCheckFixture: newTaskCheckFixture(kind)}
	for _, c := range f.checks {
		f.bindings = append(f.bindings, []driver.Value{c[0], c[11], c[12], "system-backup-evidence.v1", c[11], string(kind), f.rows[0][1], c[12]})
	}
	return f
}

type checkEvidenceConnector struct{ f *checkEvidenceFixture }

func (c checkEvidenceConnector) Driver() driver.Driver { return pageDriver{} }
func (c checkEvidenceConnector) Connect(ctx context.Context) (driver.Conn, error) {
	base, err := (taskCheckConnector{c.f.taskCheckFixture}).Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &checkEvidenceConn{Conn: base, f: c.f}, nil
}

type checkEvidenceConn struct {
	driver.Conn
	f *checkEvidenceFixture
}

func (c *checkEvidenceConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
}
func (c *checkEvidenceConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if query != taskCheckEvidenceControlSQL {
		return c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
	}
	f := c.f
	f.queries++
	if len(args) != 3 || args[0].Value != "installation_test" || args[1].Value != f.rows[0][3] || args[2].Value != f.rows[0][1] || f.checkQueries != 1 || f.rechecks != 0 || f.commits != 0 {
		return nil, errors.New("evidence bindings read outside the original task transaction")
	}
	if f.fault == "query" {
		return nil, errors.New("private evidence SQL failure")
	}
	if f.onRead != nil {
		f.onRead()
	}
	return &checkEvidenceRows{pageRows: &pageRows{columns: []string{"check_id", "ref_id", "ref_hash", "schema", "id", "owner_type", "owner_id", "hash"}, values: f.bindings}, f: f}, nil
}

type checkEvidenceRows struct {
	*pageRows
	f *checkEvidenceFixture
}

func (r *checkEvidenceRows) Next(dst []driver.Value) error {
	if r.f.fault == "stream" && r.f.readRows == 1 {
		return errors.New("private evidence stream failure")
	}
	err := r.pageRows.Next(dst)
	if err == nil {
		r.f.readRows++
	}
	return err
}
func (r *checkEvidenceRows) Close() error {
	if r.f.fault == "close" {
		return errors.New("private evidence close failure")
	}
	return nil
}
func checkEvidenceReader(t *testing.T, f *checkEvidenceFixture, probe *readCommitProbe) *Reader {
	t.Helper()
	var connector driver.Connector = checkEvidenceConnector{f}
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

func TestTaskCheckEvidenceControlKindsAndCopies(t *testing.T) {
	for _, kind := range []TaskKind{BackupTask, DrillTask, PreflightTask, VerificationTask} {
		t.Run(string(kind), func(t *testing.T) {
			f := newCheckEvidenceFixture(kind)
			s, err := checkEvidenceReader(t, f, nil).ReadTaskCheckEvidenceControl(context.Background(), kind, f.rows[0][1].(string))
			if err != nil || len(s.Checks().Checks()) != 4 || len(s.BoundReferences()) != 1 || f.queries != 1 || f.readRows != 4 || f.rechecks != 1 || f.commits != 1 || f.rollbacks != 0 || f.options.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
				t.Fatal("original checks/evidence snapshot was not committed atomically", err)
			}
			refs := s.BoundReferences()
			refs[0].SHA256.String = "changed"
			if s.BoundReferences()[0].SHA256.String != strings.Repeat("a", 64) {
				t.Fatal("binding alias escaped")
			}
			checks := s.Checks().Checks()
			checks[0].Evidence.SHA256.String = "changed"
			if s.Checks().Checks()[0].Evidence.SHA256.String != strings.Repeat("a", 64) {
				t.Fatal("check alias escaped")
			}
			if _, err := json.Marshal(s); err == nil {
				t.Fatal("internal binding became public detail")
			}
		})
	}
}

func TestTaskCheckEvidenceControlMissingAndCorrupt(t *testing.T) {
	mutations := map[string]func(*checkEvidenceFixture){
		"missing_evidence": func(f *checkEvidenceFixture) {
			for n := 3; n < 8; n++ {
				f.bindings[0][n] = nil
			}
		},
		"wrong_owner_type":     func(f *checkEvidenceFixture) { f.bindings[0][5] = "system" },
		"other_owner":          func(f *checkEvidenceFixture) { f.bindings[0][6] = "sbk_00000000-0000-4000-8000-000000000099" },
		"wrong_checksum":       func(f *checkEvidenceFixture) { f.bindings[0][7] = strings.Repeat("b", 64) },
		"wrong_schema":         func(f *checkEvidenceFixture) { f.bindings[0][3] = "system-backup-evidence.v2" },
		"wrong_evidence_id":    func(f *checkEvidenceFixture) { f.bindings[0][4] = "sev_00000000-0000-4000-8000-000000000099" },
		"wrong_check_id":       func(f *checkEvidenceFixture) { f.bindings[0][0] = int64(99) },
		"wrong_reference_id":   func(f *checkEvidenceFixture) { f.bindings[0][1] = "sev_00000000-0000-4000-8000-000000000099" },
		"wrong_reference_hash": func(f *checkEvidenceFixture) { f.bindings[0][2] = strings.Repeat("b", 64) },
		"missing_join_row":     func(f *checkEvidenceFixture) { f.bindings = f.bindings[:3] },
		"extra_join_row":       func(f *checkEvidenceFixture) { f.bindings = append(f.bindings, f.bindings[0]) },
		"out_of_order":         func(f *checkEvidenceFixture) { f.bindings[0], f.bindings[1] = f.bindings[1], f.bindings[0] },
		"scan":                 func(f *checkEvidenceFixture) { f.bindings[0][0] = "private invalid integer" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			f := newCheckEvidenceFixture(BackupTask)
			mutate(f)
			s, err := checkEvidenceReader(t, f, nil).ReadTaskCheckEvidenceControl(context.Background(), BackupTask, f.rows[0][1].(string))
			if err != ErrUnavailable || !reflect.ValueOf(s).IsZero() || f.queries != 1 || f.commits != 0 || f.rechecks != 0 || f.rollbacks != 1 {
				t.Fatal("missing/corrupt evidence returned a partial reference", err)
			}
		})
	}
}

func TestTaskCheckEvidenceControlReferenceSets(t *testing.T) {
	for _, name := range []string{"no_references", "two_references", "conflicting_digest"} {
		t.Run(name, func(t *testing.T) {
			f := newCheckEvidenceFixture(BackupTask)
			wantRefs, wantQueries := 0, 0
			switch name {
			case "no_references":
				for _, c := range f.checks {
					c[11], c[12] = nil, nil
				}
				f.bindings = nil
			case "two_references":
				f.checks[3][11], f.checks[3][12] = "sev_00000000-0000-4000-8000-000000000011", strings.Repeat("b", 64)
				f.bindings[3][1], f.bindings[3][4] = f.checks[3][11], f.checks[3][11]
				f.bindings[3][2], f.bindings[3][7] = f.checks[3][12], f.checks[3][12]
				wantRefs, wantQueries = 2, 1
			case "conflicting_digest":
				f.checks[3][12] = strings.Repeat("b", 64)
			}
			s, err := checkEvidenceReader(t, f, nil).ReadTaskCheckEvidenceControl(context.Background(), BackupTask, f.rows[0][1].(string))
			if name == "conflicting_digest" {
				if err != ErrUnavailable || !reflect.ValueOf(s).IsZero() || f.queries != 0 || f.commits != 0 {
					t.Fatal("conflicting historical binding reached evidence SQL", err)
				}
			} else if err != nil || len(s.BoundReferences()) != wantRefs || s.BoundReferences() == nil || f.queries != wantQueries || f.rechecks != 1 || f.commits != 1 {
				t.Fatal("absent/deduplicated bindings changed", err)
			}
		})
	}
}

func TestTaskCheckEvidenceControlAuthorityAndCompletion(t *testing.T) {
	for _, name := range []string{"deny", "missing_task", "revoke", "query", "stream", "close", "cancel", "commit", "late_commit"} {
		t.Run(name, func(t *testing.T) {
			f := newCheckEvidenceFixture(BackupTask)
			id := f.rows[0][1].(string)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := ErrUnavailable
			var probe *readCommitProbe
			switch name {
			case "deny":
				f.deny, want = true, ErrDenied
			case "missing_task":
				f.missingTask, f.rows, want = true, nil, ErrNotFound
			case "revoke":
				f.recheckErr = true
				want = ErrDenied
			case "query", "stream", "close":
				f.fault = name
			case "cancel":
				f.onRead = cancel
			case "commit":
				f.commitErr = errors.New("private commit failure")
			case "late_commit":
				probe = &readCommitProbe{afterCommit: cancel}
			}
			s, err := checkEvidenceReader(t, f, probe).ReadTaskCheckEvidenceControl(ctx, BackupTask, id)
			if !errors.Is(err, want) || !reflect.ValueOf(s).IsZero() {
				t.Fatal("authority/completion failure returned bound references", err)
			}
			if (name == "deny" || name == "missing_task") && f.queries != 0 {
				t.Fatal("read evidence without an authorized existing task")
			}
			if name == "late_commit" && (f.commits != 1 || f.rollbacks != 0 || f.rechecks != 1 || ctx.Err() != context.Canceled) {
				t.Fatal("fault missed actual commit boundary")
			}
		})
	}
}

func TestTaskCheckEvidenceControlBuilderAtomic(t *testing.T) {
	for _, reject := range []bool{false, true} {
		name := "commit"
		if reject {
			name = "rollback"
		}
		t.Run(name, func(t *testing.T) {
			f := newCheckEvidenceFixture(BackupTask)
			got, err := readTaskCheckEvidenceControlInTransaction(context.Background(), checkEvidenceReader(t, f, nil), BackupTask, f.rows[0][1].(string), func(ctx context.Context, q detailReadSQL, s TaskCheckEvidenceControlSnapshot) (int, error) {
				if _, exposed := any(q).(interface{ Commit() error }); exposed || f.commits != 0 || f.rechecks != 0 || len(s.BoundReferences()) != 1 {
					t.Fatal("builder escaped original transaction")
				}
				if reject {
					return 1, errors.New("private later owner failure")
				}
				return len(s.BoundReferences()), nil
			})
			if reject && (err != ErrUnavailable || got != 0 || f.commits != 0 || f.rollbacks != 1) || !reject && (err != nil || got != 1 || f.commits != 1 || f.rechecks != 1) {
				t.Fatal("later builder failure leaked partial reference", err)
			}
		})
	}
}
