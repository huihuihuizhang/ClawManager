package systembackupskillhub

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"clawreef/internal/models"
)

type restoreSQLAudit struct {
	begins, commits, rollbacks, writes int
	options                            driver.TxOptions
	queries                            []string
}
type restoreSQLState struct {
	mu              sync.Mutex
	audit           restoreSQLAudit
	target          Rows
	failure         string
	wrongEngine     string
	payloadOverride int64
	countOverride   *int64
	missingExternal string
	queryHook       func(string)
	rowHook         func(string, int)
}

func (s *restoreSQLState) observed() restoreSQLAudit {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.audit
	a.queries = append([]string(nil), a.queries...)
	return a
}

type restoreSQLConnector struct{ s *restoreSQLState }

func (c restoreSQLConnector) Connect(context.Context) (driver.Conn, error) {
	return &restoreSQLConn{s: c.s}, nil
}
func (c restoreSQLConnector) Driver() driver.Driver { return restoreSQLDriver{} }

type restoreSQLDriver struct{}

func (restoreSQLDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("connector required")
}

type restoreSQLConn struct{ s *restoreSQLState }

func (c *restoreSQLConn) Close() error { return nil }
func (c *restoreSQLConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (c *restoreSQLConn) Begin() (driver.Tx, error) {
	return nil, errors.New("context transaction required")
}
func (c *restoreSQLConn) BeginTx(_ context.Context, opts driver.TxOptions) (driver.Tx, error) {
	c.s.mu.Lock()
	c.s.audit.begins++
	c.s.audit.options = opts
	c.s.mu.Unlock()
	if c.s.failure == "begin" {
		return nil, errors.New("SECRET begin")
	}
	return &restoreSQLTx{s: c.s}, nil
}
func (c *restoreSQLConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	c.s.mu.Lock()
	c.s.audit.writes++
	c.s.mu.Unlock()
	return nil, errors.New("forbidden write")
}

type restoreSQLTx struct{ s *restoreSQLState }

func (t *restoreSQLTx) Commit() error {
	t.s.mu.Lock()
	t.s.audit.commits++
	t.s.mu.Unlock()
	if t.s.failure == "commit" {
		return errors.New("SECRET commit")
	}
	return nil
}
func (t *restoreSQLTx) Rollback() error {
	t.s.mu.Lock()
	t.s.audit.rollbacks++
	t.s.mu.Unlock()
	return nil
}
func (c *restoreSQLConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	c.s.mu.Lock()
	c.s.audit.queries = append(c.s.audit.queries, q)
	c.s.mu.Unlock()
	if c.s.queryHook != nil {
		c.s.queryHook(q)
	}
	if strings.HasPrefix(q, "SELECT ENGINE") {
		if len(args) != 1 {
			return nil, errors.New("bad engine query")
		}
		table := args[0].Value.(string)
		if c.s.failure == "engine" {
			return nil, errors.New("SECRET engine")
		}
		engine := "InnoDB"
		if c.s.wrongEngine == table {
			engine = "MyISAM"
		}
		return &restoreSQLRows{columns: []string{"ENGINE"}, values: [][]driver.Value{{engine}}}, nil
	}
	for _, t := range tables(c.s.target) {
		if !strings.Contains(q, "FROM `"+t.name+"`") {
			continue
		}
		if strings.HasPrefix(q, "SELECT COUNT(*)") {
			if c.s.failure == "count" {
				return nil, errors.New("SECRET count")
			}
			count := int64(t.rows.Len())
			if c.s.countOverride != nil {
				count = *c.s.countOverride
			}
			var payload int64
			for i := 0; i < t.rows.Len(); i++ {
				r := t.rows.Index(i)
				for j := 0; j < r.NumField(); j++ {
					f := r.Field(j)
					if f.Kind() == reflect.Pointer {
						if f.IsNil() {
							continue
						}
						f = f.Elem()
					}
					if f.Kind() == reflect.String {
						payload += int64(len(f.String()))
					}
				}
			}
			if c.s.payloadOverride != 0 {
				payload = c.s.payloadOverride
			}
			return &restoreSQLRows{columns: []string{"COUNT(*)", "bytes"}, values: [][]driver.Value{{count, payload}}}, nil
		}
		if c.s.failure == "query" {
			return nil, errors.New("SECRET query")
		}
		if len(args) != 1 || !strings.HasSuffix(q, "ORDER BY `id` LIMIT ?") {
			return nil, errors.New("unbounded target query")
		}
		if args[0].Value != int64(t.rows.Len())+1 {
			return nil, errors.New("missing sentinel limit")
		}
		model := t.rows.Type().Elem()
		columns := []string{}
		selectCols := []string{}
		for i := 0; i < model.NumField(); i++ {
			col := strings.Split(model.Field(i).Tag.Get("db"), ",")[0]
			columns = append(columns, col)
			selectCols = append(selectCols, "`"+col+"`")
		}
		if q != "SELECT "+strings.Join(selectCols, ",")+" FROM `"+t.name+"` ORDER BY `id` LIMIT ?" {
			return nil, errors.New("wrong model columns")
		}
		values := [][]driver.Value{}
		for i := 0; i < t.rows.Len(); i++ {
			row := t.rows.Index(i)
			data := make([]driver.Value, row.NumField())
			for j := range data {
				data[j] = sqlFixtureValue(row.Field(j))
			}
			values = append(values, data)
		}
		result := &restoreSQLRows{columns: columns, values: values, table: t.name, hook: c.s.rowHook}
		switch c.s.failure {
		case "stream":
			result.nextErr = errors.New("SECRET stream")
		case "close":
			result.closeErr = errors.New("SECRET close")
		case "columns":
			result.columns = append([]string(nil), columns...)
			result.columns[0] = "wrong_id"
		case "scan":
			if len(result.values) > 0 {
				result.values[0][0] = "not-an-int SECRET"
			}
		case "short":
			if len(result.values) > 0 {
				result.values = result.values[:len(result.values)-1]
			}
		case "extra":
			if len(result.values) > 0 {
				result.values = append(result.values, result.values[0])
			}
		}
		return result, nil
	}
	for _, table := range []string{"users", "instances"} {
		if strings.HasPrefix(q, "SELECT `id` FROM `"+table+"` WHERE `id` IN (") {
			values := [][]driver.Value{}
			for i, arg := range args {
				if c.s.missingExternal == table && i == 0 {
					continue
				}
				values = append(values, []driver.Value{arg.Value})
			}
			return &restoreSQLRows{columns: []string{"id"}, values: values}, nil
		}
	}
	return nil, fmt.Errorf("unexpected query: %s", q)
}
func sqlFixtureValue(field reflect.Value) driver.Value {
	if field.Kind() == reflect.Pointer {
		if field.IsNil() {
			return nil
		}
		field = field.Elem()
	}
	if field.Type() == reflect.TypeOf(time.Time{}) {
		return field.Interface().(time.Time)
	}
	switch field.Kind() {
	case reflect.String:
		return field.String()
	case reflect.Int, reflect.Int64:
		return field.Int()
	case reflect.Bool:
		return field.Bool()
	}
	panic("unknown fixture type")
}

type restoreSQLRows struct {
	columns           []string
	values            [][]driver.Value
	index             int
	nextErr, closeErr error
	table             string
	hook              func(string, int)
}

func (r *restoreSQLRows) Columns() []string { return r.columns }
func (r *restoreSQLRows) Close() error      { return r.closeErr }
func (r *restoreSQLRows) Next(dest []driver.Value) error {
	if r.nextErr != nil {
		return r.nextErr
	}
	if r.index >= len(r.values) {
		return io.EOF
	}
	if r.hook != nil {
		r.hook(r.table, r.index)
	}
	copy(dest, r.values[r.index])
	r.index++
	return nil
}
func restoreSQLDB(t *testing.T, s *restoreSQLState) *sql.DB {
	t.Helper()
	db := sql.OpenDB(restoreSQLConnector{s: s})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return db
}

type targetReadAuthorityStub struct {
	starts, ends    int
	verify, recheck func(context.Context, ReadOnlyQueries, RestoreRequest) error
}

func (p *targetReadAuthorityStub) VerifyTargetRead(ctx context.Context, q ReadOnlyQueries, r RestoreRequest) error {
	p.starts++
	if p.verify != nil {
		return p.verify(ctx, q, r)
	}
	return nil
}
func (p *targetReadAuthorityStub) RecheckTargetRead(ctx context.Context, q ReadOnlyQueries, r RestoreRequest) error {
	p.ends++
	if p.recheck != nil {
		return p.recheck(ctx, q, r)
	}
	return nil
}

func TestSQLRestoreVerifierReadsAllFieldsInOneAuthenticatedSnapshot(t *testing.T) {
	request := restoreRequestFixture()
	original := cloneRestoreRequest(request)
	state := &restoreSQLState{target: goldenRows(request.Source)}
	proof := &targetReadAuthorityStub{
		verify: func(_ context.Context, q ReadOnlyQueries, r RestoreRequest) error {
			if _, ok := q.(*sql.Tx); ok {
				t.Error("raw transaction leaked to authority")
			}
			if !reflect.DeepEqual(r, original) {
				t.Error("initial binding changed")
			}
			r.Source.Skills[0].Visibility = "public"
			r.Mapping.IDs["skills"][10] = 999
			*r.Mapping.BindingPaths[500].InstallPath = "bad/path"
			request.Source.Skills[0].Visibility = "public"
			request.Mapping.IDs["users"][1] = 999
			return nil
		},
		recheck: func(_ context.Context, _ ReadOnlyQueries, r RestoreRequest) error {
			if !reflect.DeepEqual(r, original) {
				t.Error("expected source/mapping was mutable")
			}
			return nil
		},
	}
	err := (SQLRestoreVerifier{DB: restoreSQLDB(t, state), Authority: proof}).Verify(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	a := state.observed()
	if a.begins != 1 || a.commits != 1 || a.rollbacks != 0 || a.writes != 0 || !a.options.ReadOnly || a.options.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
		t.Fatalf("transaction lifecycle: %+v", a)
	}
	if proof.starts != 1 || proof.ends != 1 {
		t.Fatal("missing authority checks")
	}
	if len(a.queries) != 28 {
		t.Fatalf("query coverage=%d want=28", len(a.queries))
	}
	for _, q := range a.queries {
		if !strings.HasPrefix(q, "SELECT ") || strings.Contains(q, "SELECT *") {
			t.Fatalf("unexpected query: %s", q)
		}
	}
	// Capacity for all eight tables must be established before reading payloads.
	for _, q := range a.queries[:16] {
		if strings.Contains(q, " ORDER BY ") {
			t.Fatal("payload read before capacity check")
		}
	}
}
func TestSQLRestoreVerifierFailureMatrix(t *testing.T) {
	for _, name := range []string{"begin", "engine", "count", "query", "stream", "close", "columns", "scan", "short", "extra", "commit", "nontransactional", "payload_limit", "negative_count", "count_mismatch", "missing_user", "missing_instance", "target_drift", "initial_proof", "final_proof"} {
		t.Run(name, func(t *testing.T) {
			request := restoreRequestFixture()
			state := &restoreSQLState{target: goldenRows(request.Source), failure: name}
			proof := &targetReadAuthorityStub{}
			want := ErrTargetRead
			switch name {
			case "nontransactional":
				state.wrongEngine = "skill_versions"
			case "payload_limit":
				state.payloadOverride = request.Limits.MaxPayloadBytes + 1
				want = ErrCapacity
			case "negative_count":
				state.countOverride = ptr(int64(-1))
			case "count_mismatch":
				state.countOverride = ptr(int64(999))
				want = ErrMismatch
			case "missing_user":
				state.missingExternal = "users"
				want = ErrMismatch
			case "missing_instance":
				state.missingExternal = "instances"
				want = ErrMismatch
			case "target_drift":
				state.target.Scans[0].FindingsJSON = ptr("SECRET lost historical content")
				want = ErrMismatch
			case "short", "extra":
				want = ErrMismatch
			case "initial_proof":
				proof.verify = func(context.Context, ReadOnlyQueries, RestoreRequest) error { return errors.New("SECRET initial") }
				want = ErrRestoreAuthority
			case "final_proof":
				proof.recheck = func(context.Context, ReadOnlyQueries, RestoreRequest) error { return errors.New("SECRET final") }
				want = ErrRestoreAuthority
			}
			err := (SQLRestoreVerifier{DB: restoreSQLDB(t, state), Authority: proof}).Verify(context.Background(), request)
			if !errors.Is(err, want) {
				t.Fatalf("error=%v want=%v", err, want)
			}
			if strings.Contains(err.Error(), "SECRET") {
				t.Fatalf("unredacted error: %v", err)
			}
			a := state.observed()
			if a.writes != 0 {
				t.Fatal("verifier issued writes")
			}
			if name == "commit" {
				if a.commits != 1 {
					t.Fatal("commit not tested")
				}
			} else if a.commits != 0 {
				t.Fatal("failure committed")
			}
			if name != "begin" && name != "commit" && a.rollbacks != 1 {
				t.Fatalf("missing rollback: %+v", a)
			}
			if name == "initial_proof" && len(a.queries) != 0 {
				t.Fatal("read rows before authority accepted")
			}
			if name == "payload_limit" {
				for _, q := range a.queries {
					if strings.Contains(q, " ORDER BY ") {
						t.Fatal("oversized payload reached client")
					}
				}
			}
		})
	}
}
func TestSQLRestoreVerifierRequiresAuthorityBeforeDatabase(t *testing.T) {
	for _, name := range []string{"nil", "typed_nil", "binding", "capacity", "canceled"} {
		t.Run(name, func(t *testing.T) {
			request := restoreRequestFixture()
			state := &restoreSQLState{target: goldenRows(request.Source)}
			var proof TargetReadAuthority = &targetReadAuthorityStub{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch name {
			case "nil":
				proof = nil
			case "typed_nil":
				proof = (*targetReadAuthorityStub)(nil)
			case "binding":
				request.Binding.TargetIdentitySHA256 = "missing"
			case "capacity":
				request.Limits.MaxRows = 1
			case "canceled":
				cancel()
			}
			err := (SQLRestoreVerifier{DB: restoreSQLDB(t, state), Authority: proof}).Verify(ctx, request)
			if err == nil || state.observed().begins != 0 {
				t.Fatal("invalid authority/input touched database")
			}
		})
	}
}

func TestSQLRestoreVerifierChecksAllEmptyTables(t *testing.T) {
	request := restoreRequestFixture()
	request.Source = Rows{}
	request.Mapping = RestoreMapping{IDs: map[string]map[int]int{"users": {}, "instances": {}}}
	for _, table := range tables(request.Source) {
		request.Mapping.IDs[table.name] = map[int]int{}
	}
	state := &restoreSQLState{target: Rows{}}
	proof := &targetReadAuthorityStub{}
	if err := (SQLRestoreVerifier{DB: restoreSQLDB(t, state), Authority: proof}).Verify(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	a := state.observed()
	if len(a.queries) != 24 || a.commits != 1 || proof.starts != 1 || proof.ends != 1 {
		t.Fatalf("empty-table coverage: %+v", a)
	}
}

func TestSQLRestoreVerifierCancelsDuringPayloadRead(t *testing.T) {
	request := restoreRequestFixture()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	state := &restoreSQLState{target: goldenRows(request.Source), rowHook: func(table string, index int) {
		if table == "skills" && index == 0 {
			cancel()
		}
	}}
	proof := &targetReadAuthorityStub{}
	err := (SQLRestoreVerifier{DB: restoreSQLDB(t, state), Authority: proof}).Verify(ctx, request)
	if !errors.Is(err, context.Canceled) || state.observed().commits != 0 || proof.ends != 0 {
		t.Fatalf("continued after read cancellation: %v", err)
	}
}

func TestSQLRestoreVerifierPagesDependencyReferences(t *testing.T) {
	request := restoreRequestFixture()
	request.Source = Rows{}
	request.Mapping = RestoreMapping{IDs: map[string]map[int]int{"users": {}, "instances": {}}}
	for _, table := range tables(request.Source) {
		request.Mapping.IDs[table.name] = map[int]int{}
	}
	for id := 1; id <= 300; id++ {
		request.Source.Skills = append(request.Source.Skills, models.Skill{ID: id, UserID: id, SkillKey: "demo", Visibility: "private"})
		request.Mapping.IDs["skills"][id] = id + 1000
		request.Mapping.IDs["users"][id] = id + 1000
	}
	target := cloneRows(request.Source)
	for i := range target.Skills {
		target.Skills[i].ID += 1000
		target.Skills[i].UserID += 1000
	}
	state := &restoreSQLState{target: target}
	if err := (SQLRestoreVerifier{DB: restoreSQLDB(t, state), Authority: &targetReadAuthorityStub{}}).Verify(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	pages := 0
	for _, query := range state.observed().queries {
		if strings.Contains(query, " WHERE `id` IN (") {
			pages++
			if strings.Count(query, "?") > 256 {
				t.Fatal("unbounded dependency query")
			}
		}
	}
	if pages != 2 {
		t.Fatalf("expected two dependency pages, got %d", pages)
	}
}

func TestSQLRestoreVerifierCancellationBeforeFinalCommit(t *testing.T) {
	request := restoreRequestFixture()
	state := &restoreSQLState{target: goldenRows(request.Source)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proof := &targetReadAuthorityStub{recheck: func(context.Context, ReadOnlyQueries, RestoreRequest) error { cancel(); return nil }}
	err := (SQLRestoreVerifier{DB: restoreSQLDB(t, state), Authority: proof}).Verify(ctx, request)
	if !errors.Is(err, context.Canceled) || state.observed().commits != 0 {
		t.Fatalf("cancel accepted: %v", err)
	}
}
