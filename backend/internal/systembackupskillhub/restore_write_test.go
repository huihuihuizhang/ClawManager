package systembackupskillhub

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type writeSQLState struct {
	base          restoreSQLState
	failWriteAt   int
	badAffected   bool
	affectedError bool
	tamper        bool
	tampered      bool
	statements    []string
	onWrite       func(int)
	onCommit      func()
}
type writeSQLConnector struct{ s *writeSQLState }

func (c writeSQLConnector) Connect(context.Context) (driver.Conn, error) {
	return &writeSQLConn{restoreSQLConn: &restoreSQLConn{s: &c.s.base}, state: c.s}, nil
}
func (c writeSQLConnector) Driver() driver.Driver { return restoreSQLDriver{} }

type writeSQLConn struct {
	*restoreSQLConn
	state *writeSQLState
}

func (c *writeSQLConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	tx, err := c.restoreSQLConn.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &writeSQLTx{inner: tx, state: c.state, before: cloneRows(c.state.base.target)}, nil
}

type writeSQLTx struct {
	inner  driver.Tx
	state  *writeSQLState
	before Rows
}

func (tx *writeSQLTx) Commit() error {
	err := tx.inner.Commit()
	if err == nil && tx.state.onCommit != nil {
		tx.state.onCommit()
	}
	return err
}
func (tx *writeSQLTx) Rollback() error {
	tx.state.base.target = cloneRows(tx.before)
	return tx.inner.Rollback()
}
func (c *writeSQLConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if strings.HasSuffix(q, " LIMIT 1 FOR UPDATE") {
		c.state.base.mu.Lock()
		c.state.base.audit.queries = append(c.state.base.audit.queries, q)
		c.state.base.mu.Unlock()
		for _, table := range tables(c.state.base.target) {
			if q == "SELECT `id` FROM `"+table.name+"` ORDER BY `id` LIMIT 1 FOR UPDATE" {
				rows := &restoreSQLRows{columns: []string{"id"}}
				if table.rows.Len() > 0 {
					rows.values = [][]driver.Value{{table.rows.Index(0).FieldByName("ID").Int()}}
				}
				return rows, nil
			}
		}
		return nil, errors.New("unexpected locking read")
	}
	if c.state.tamper && !c.state.tampered && strings.HasPrefix(q, "SELECT COUNT(*)") {
		c.state.base.target.Skills[0].Visibility = "public"
		c.state.tampered = true
	}
	return c.restoreSQLConn.QueryContext(ctx, q, args)
}
func (c *writeSQLConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	s := c.state
	s.base.mu.Lock()
	s.base.audit.writes++
	writeNo := s.base.audit.writes
	s.base.mu.Unlock()
	s.statements = append(s.statements, q)
	if s.onWrite != nil {
		s.onWrite(writeNo)
	}
	if s.failWriteAt == writeNo {
		return nil, errors.New("SECRET write failure")
	}
	if strings.HasPrefix(q, "INSERT INTO ") {
		if err := s.applyInsert(q, args); err != nil {
			return nil, err
		}
	} else if strings.HasPrefix(q, "UPDATE ") {
		if err := s.applyBackReference(q, args); err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("unexpected non-insert/update SQL")
	}
	if s.affectedError {
		return writeAffectedResult{}, nil
	}
	if s.badAffected {
		return driver.RowsAffected(0), nil
	}
	return driver.RowsAffected(1), nil
}

type writeAffectedResult struct{}

func (writeAffectedResult) RowsAffected() (int64, error) {
	return 0, errors.New("SECRET rows affected")
}
func (writeAffectedResult) LastInsertId() (int64, error) { return 0, nil }
func (s *writeSQLState) applyInsert(query string, args []driver.NamedValue) error {
	for ti, table := range tables(s.base.target) {
		if !strings.HasPrefix(query, "INSERT INTO `"+table.name+"` ") {
			continue
		}
		model := table.rows.Type().Elem()
		cols := []string{}
		for i := 0; i < model.NumField(); i++ {
			cols = append(cols, "`"+strings.Split(model.Field(i).Tag.Get("db"), ",")[0]+"`")
		}
		expected := "INSERT INTO `" + table.name + "` (" + strings.Join(cols, ",") + ") VALUES (" + strings.TrimSuffix(strings.Repeat("?,", len(cols)), ",") + ")"
		if query != expected || len(args) != model.NumField() {
			return errors.New("incorrect insert columns")
		}
		row := reflect.New(model).Elem()
		for i, arg := range args {
			setFixtureSQLValue(row.Field(i), arg.Value)
		}
		// Enforce local reference availability at INSERT time. Cyclic references
		// must be deferred, without disabling foreign-key checks.
		for _, ref := range table.refs {
			id, present := intField(row.FieldByName(ref.field))
			if !present {
				continue
			}
			if ref.table == "users" || ref.table == "instances" {
				continue
			}
			found := false
			for _, dependency := range tables(s.base.target) {
				if dependency.name == ref.table {
					for i := 0; i < dependency.rows.Len(); i++ {
						if dependency.rows.Index(i).FieldByName("ID").Int() == int64(id) {
							found = true
						}
					}
				}
			}
			if !found {
				return errors.New("foreign key target not inserted")
			}
		}
		target := reflect.ValueOf(&s.base.target).Elem().Field(ti)
		target.Set(reflect.Append(target, row))
		return nil
	}
	return errors.New("write outside closed table scope")
}
func setFixtureSQLValue(field reflect.Value, value driver.Value) {
	if value == nil {
		field.SetZero()
		return
	}
	if field.Kind() == reflect.Pointer {
		field.Set(reflect.New(field.Type().Elem()))
		field = field.Elem()
	}
	if field.Type() == reflect.TypeOf(time.Time{}) {
		field.Set(reflect.ValueOf(value.(time.Time)))
		return
	}
	switch field.Kind() {
	case reflect.Int, reflect.Int64:
		field.SetInt(value.(int64))
	case reflect.String:
		field.SetString(value.(string))
	case reflect.Bool:
		field.SetBool(value.(bool))
	default:
		panic("unknown fixture field")
	}
}
func (s *writeSQLState) applyBackReference(query string, args []driver.NamedValue) error {
	switch {
	case strings.HasPrefix(query, "UPDATE `skill_blobs`"):
		if len(args) != 3 || !strings.Contains(query, "`updated_at`=?") || !strings.HasSuffix(query, "AND `last_scan_result_id` IS NULL") {
			return errors.New("unsafe blob update")
		}
		for i := range s.base.target.Blobs {
			b := &s.base.target.Blobs[i]
			if b.ID == int(args[2].Value.(int64)) {
				if b.LastScanResultID != nil {
					return errors.New("blob backref already exists")
				}
				b.LastScanResultID = ptr(int(args[0].Value.(int64)))
				b.UpdatedAt = args[1].Value.(time.Time)
				return nil
			}
		}
	case strings.HasPrefix(query, "UPDATE `skills`"):
		if len(args) != 4 || !strings.Contains(query, "`updated_at`=?") || !strings.HasSuffix(query, "AND `current_version_id` IS NULL AND `last_scan_result_id` IS NULL") {
			return errors.New("unsafe skill update")
		}
		for i := range s.base.target.Skills {
			skill := &s.base.target.Skills[i]
			if skill.ID == int(args[3].Value.(int64)) {
				if skill.CurrentVersionID != nil || skill.LastScanResultID != nil {
					return errors.New("skill backref already exists")
				}
				if args[0].Value != nil {
					skill.CurrentVersionID = ptr(int(args[0].Value.(int64)))
				}
				if args[1].Value != nil {
					skill.LastScanResultID = ptr(int(args[1].Value.(int64)))
				}
				skill.UpdatedAt = args[2].Value.(time.Time)
				return nil
			}
		}
	}
	return errors.New("backref target missing")
}
func writeSQLDB(t *testing.T, state *writeSQLState) *sql.DB {
	t.Helper()
	db := sql.OpenDB(writeSQLConnector{s: state})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return db
}

type writeAuthorityStub struct {
	starts, ends    int
	verify, recheck func(context.Context, ReadOnlyQueries, RestoreRequest) error
}

func (a *writeAuthorityStub) VerifyTargetWrite(ctx context.Context, q ReadOnlyQueries, r RestoreRequest) error {
	a.starts++
	if a.verify != nil {
		return a.verify(ctx, q, r)
	}
	return nil
}
func (a *writeAuthorityStub) RecheckTargetWrite(ctx context.Context, q ReadOnlyQueries, r RestoreRequest) error {
	a.ends++
	if a.recheck != nil {
		return a.recheck(ctx, q, r)
	}
	return nil
}

func TestSQLRestorerWritesAllTablesAndIndependentVerifierReadsThem(t *testing.T) {
	request := restoreRequestFixture()
	original := cloneRestoreRequest(request)
	state := &writeSQLState{}
	authority := &writeAuthorityStub{
		verify: func(_ context.Context, _ ReadOnlyQueries, r RestoreRequest) error {
			if state.base.observed().writes != 0 {
				t.Error("wrote before authorization")
			}
			r.Source.Skills[0].Visibility = "public"
			r.Mapping.IDs["skills"][10] = 777
			request.Source.Skills[0].Visibility = "public"
			request.Mapping.IDs["skills"][10] = 888
			return nil
		},
		recheck: func(_ context.Context, _ ReadOnlyQueries, r RestoreRequest) error {
			if !reflect.DeepEqual(r, original) {
				t.Error("authority input mutated")
			}
			if !reflect.DeepEqual(state.base.target, goldenRows(original.Source)) {
				t.Error("final check preceded complete readback")
			}
			return nil
		},
	}
	if err := (SQLRestorer{DB: writeSQLDB(t, state), Authority: authority}).Restore(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(state.base.target, goldenRows(original.Source)) {
		t.Fatal("persisted rows differ from golden data")
	}
	a := state.base.observed()
	if a.begins != 1 || a.commits != 1 || a.rollbacks != 0 || a.options.ReadOnly || a.options.Isolation != driver.IsolationLevel(sql.LevelSerializable) || authority.starts != 1 || authority.ends != 1 {
		t.Fatalf("transaction lifecycle: %+v", a)
	}
	if a.writes != 29 {
		t.Fatalf("expected 24 inserts and 5 cyclic-reference updates, got %d", a.writes)
	}
	locks := 0
	for _, q := range a.queries {
		if strings.HasSuffix(q, "FOR UPDATE") {
			locks++
		}
	}
	if locks != 8 {
		t.Fatal("did not lock all owned tables before writing")
	}
	for _, q := range state.statements {
		for _, unsafe := range []string{"DELETE", "TRUNCATE", "REPLACE", "IGNORE", "FOREIGN_KEY_CHECKS"} {
			if strings.Contains(q, unsafe) {
				t.Fatal("destructive/replay SQL")
			}
		}
	}
	// This is a separate database/sql pool and SELECT-only verifier code path.
	readProof := &targetReadAuthorityStub{}
	if err := (SQLRestoreVerifier{DB: restoreSQLDB(t, &state.base), Authority: readProof}).Verify(context.Background(), original); err != nil {
		t.Fatal(err)
	}
	if !state.base.observed().options.ReadOnly {
		t.Fatal("verifier reused writing transaction")
	}
}
func TestSQLRestorerRollsBackFailures(t *testing.T) {
	for _, name := range []string{"initial_authority", "final_authority", "insert", "backref", "rows_affected", "rows_affected_error", "readback", "engine", "missing_user", "occupied", "cancel", "query"} {
		t.Run(name, func(t *testing.T) {
			request := restoreRequestFixture()
			state := &writeSQLState{}
			authority := &writeAuthorityStub{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := ErrTargetWrite
			switch name {
			case "initial_authority":
				authority.verify = func(context.Context, ReadOnlyQueries, RestoreRequest) error { return errors.New("SECRET authority") }
				want = ErrRestoreAuthority
			case "final_authority":
				authority.recheck = func(context.Context, ReadOnlyQueries, RestoreRequest) error {
					return errors.New("SECRET expired fence")
				}
				want = ErrRestoreAuthority
			case "insert":
				state.failWriteAt = 8
			case "backref":
				state.failWriteAt = 25
			case "rows_affected":
				state.badAffected = true
			case "rows_affected_error":
				state.affectedError = true
			case "readback":
				state.tamper = true
				want = ErrMismatch
			case "engine":
				state.base.wrongEngine = "skill_blobs"
				want = ErrTargetRead
			case "missing_user":
				state.base.missingExternal = "users"
				want = ErrMismatch
			case "occupied":
				state.base.target.Tags = goldenRows(request.Source).Tags
				want = ErrTargetOccupied
			case "cancel":
				state.onWrite = func(n int) {
					if n == 8 {
						cancel()
					}
				}
				want = context.Canceled
			case "query":
				state.base.failure = "query"
				want = ErrTargetRead
			}
			before := cloneRows(state.base.target)
			db := writeSQLDB(t, state)
			err := (SQLRestorer{DB: db, Authority: authority}).Restore(ctx, request)
			if !errors.Is(err, want) {
				t.Fatalf("error=%v want=%v", err, want)
			}
			if strings.Contains(err.Error(), "SECRET") {
				t.Fatal("write error leaked private data")
			}
			if state.base.observed().commits != 0 {
				t.Fatal("failed restore committed")
			}
			// Cancellation rollback may be started by database/sql's awaitDone.
			// This single-connection pool becomes reusable only after it finishes.
			if name == "cancel" {
				waitCtx, waitCancel := context.WithTimeout(context.Background(), 3*time.Second)
				conn, waitErr := db.Conn(waitCtx)
				if waitErr != nil {
					waitCancel()
					t.Fatal(waitErr)
				}
				_ = conn.Close()
				waitCancel()
			}
			if !reflect.DeepEqual(cloneRows(state.base.target), before) || state.base.observed().rollbacks != 1 {
				t.Fatal("partial rows escaped rollback")
			}
			if name == "occupied" || name == "initial_authority" || name == "engine" || name == "missing_user" {
				if state.base.observed().writes != 0 {
					t.Fatal("wrote before prerequisites")
				}
			}
		})
	}
}
func TestSQLRestorerAmbiguousCommitIsNotRetried(t *testing.T) {
	request := restoreRequestFixture()
	state := &writeSQLState{}
	state.base.failure = "commit"
	err := (SQLRestorer{DB: writeSQLDB(t, state), Authority: &writeAuthorityStub{}}).Restore(context.Background(), request)
	if !errors.Is(err, ErrRestoreCommitUnknown) {
		t.Fatalf("commit error=%v", err)
	}
	a := state.base.observed()
	if a.commits != 1 || a.begins != 1 || a.writes != 29 {
		t.Fatal("automatically retried ambiguous commit")
	}
	// The simulated server made all rows durable before acknowledgement was lost.
	if !reflect.DeepEqual(state.base.target, goldenRows(request.Source)) {
		t.Fatal("ambiguous outcome triggered cleanup")
	}
}

func TestSQLRestorerReportsAcknowledgedCommitDespiteLateCancellation(t *testing.T) {
	request := restoreRequestFixture()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	state := &writeSQLState{onCommit: cancel}
	err := (SQLRestorer{DB: writeSQLDB(t, state), Authority: &writeAuthorityStub{}}).Restore(ctx, request)
	if err != nil || state.base.observed().commits != 1 || !reflect.DeepEqual(state.base.target, goldenRows(request.Source)) {
		t.Fatalf("acknowledged writes were reported as interrupted: %v", err)
	}
}
func TestSQLRestorerRefusesSecondRestoreWithoutChangingRows(t *testing.T) {
	request := restoreRequestFixture()
	state := &writeSQLState{}
	writer := SQLRestorer{DB: writeSQLDB(t, state), Authority: &writeAuthorityStub{}}
	if err := writer.Restore(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := writer.Restore(context.Background(), request); !errors.Is(err, ErrTargetOccupied) {
		t.Fatal(err)
	}
	if state.base.observed().writes != 29 || !reflect.DeepEqual(state.base.target, goldenRows(request.Source)) {
		t.Fatal("second invocation changed existing rows")
	}
}

func TestSQLRestorerRequiresIndependentWriteAuthority(t *testing.T) {
	for _, authority := range []RestoreWriteAuthority{nil, (*writeAuthorityStub)(nil)} {
		state := &writeSQLState{}
		err := (SQLRestorer{DB: writeSQLDB(t, state), Authority: authority}).Restore(context.Background(), restoreRequestFixture())
		if !errors.Is(err, ErrRestoreAuthority) || state.base.observed().begins != 0 {
			t.Fatal("unapproved write transaction started")
		}
	}
}
