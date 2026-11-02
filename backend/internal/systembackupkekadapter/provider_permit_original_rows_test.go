package systembackupkekadapter

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"reflect"
	"testing"

	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
)

// Synthetic SQL verifies private scope and current data, not MySQL locking or
// provider authority. The real StageOriginal differential must also run.
func originalRowsIssue(tx *sql.Tx, ctx context.Context) (*PreparedProviderPermitIssue, *heldProviderOriginalRows) {
	p := &PreparedProviderPermitIssue{issuer: &ProviderPermitIssuer{}, original: new(c.OriginalCapturePlan), planHash: "plan", specHash: "spec"}
	p.scope.Input.Authority = d.Authority{InstallationID: "installation", TaskPublicID: "task", AttemptNo: 7}
	p.scope.Job.Namespace, p.scope.Job.Name, p.scope.Job.UID = "ns", "job", "uid"
	p.grant.DatabaseAccount, p.grant.Database.ServerUUID, p.grant.Database.Database = "account", "server", "database"
	r := &heldProviderOriginalRows{ctx: ctx, tx: tx, issue: p, guard: new(c.ExecutionAuthorityGuard), plan: p.original, authority: p.scope.Input.Authority}
	return p, r
}

func TestHeldProviderOriginalRowsRejectsForeignScopeBeforeSQL(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tx := new(sql.Tx)
	p, r := originalRowsIssue(tx, ctx)
	for _, tc := range []struct {
		name string
		edit func(*heldProviderOriginalRows)
	}{
		{"context", func(r *heldProviderOriginalRows) { r.ctx = context.Background() }},
		{"transaction", func(r *heldProviderOriginalRows) { r.tx = new(sql.Tx) }},
		{"issue", func(r *heldProviderOriginalRows) { r.issue = new(PreparedProviderPermitIssue) }},
		{"guard", func(r *heldProviderOriginalRows) { r.guard = new(c.ExecutionAuthorityGuard) }},
		{"plan", func(r *heldProviderOriginalRows) { r.plan = new(c.OriginalCapturePlan) }},
		{"authority", func(r *heldProviderOriginalRows) { r.authority.AttemptNo++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := *r
			tc.edit(&copy)
			if _, err := copy.read(ctx, tx, p, r.guard); err == nil {
				t.Fatal("foreign scope reached SQL")
			}
		})
	}
	if _, err := (*heldProviderOriginalRows)(nil).read(ctx, tx, p, r.guard); err == nil {
		t.Fatal("nil lock fact accepted")
	}
	cancel()
	if _, err := r.read(ctx, tx, p, r.guard); err == nil {
		t.Fatal("canceled original context accepted")
	}
}

type originalRowsConnector struct{ conn *originalRowsSQL }

func (c originalRowsConnector) Driver() driver.Driver                        { return ownerDriver{} }
func (c originalRowsConnector) Connect(context.Context) (driver.Conn, error) { return c.conn, nil }

type originalRowsSQL struct {
	values   []driver.Value
	calls    int
	queryErr error
	args     []any
}

func (*originalRowsSQL) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (*originalRowsSQL) Close() error                        { return nil }
func (s *originalRowsSQL) Begin() (driver.Tx, error)         { return s, nil }
func (s *originalRowsSQL) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return s, nil
}
func (*originalRowsSQL) Commit() error   { return nil }
func (*originalRowsSQL) Rollback() error { return nil }
func (s *originalRowsSQL) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	s.calls++
	if query != heldProviderOriginalRowsQuery {
		return nil, errors.New("unexpected query")
	}
	s.args = nil
	for _, arg := range args {
		s.args = append(s.args, arg.Value)
	}
	if s.queryErr != nil {
		return nil, s.queryErr
	}
	return &ownerRows{columns: []string{"account", "server", "database", "plan", "key_use", "spec"}, values: s.values}, nil
}

func TestHeldProviderOriginalRowsReadsEveryCurrentFieldAndOwnChanges(t *testing.T) {
	ctx := context.Background()
	s := &originalRowsSQL{}
	db := sql.OpenDB(originalRowsConnector{conn: s})
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	p, r := originalRowsIssue(tx, ctx)
	valid := []driver.Value{"account", "server", "database", "plan", []byte("original lease"), "spec"}
	for _, tc := range []struct {
		name   string
		column int
		value  driver.Value
	}{
		{"account", 0, "foreign"}, {"server", 1, "foreign"}, {"database", 2, "foreign"},
		{"plan", 3, "changed"}, {"missing_plan", 3, nil}, {"spec", 5, "changed"}, {"null_spec", 5, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s.values = append([]driver.Value(nil), valid...)
			s.values[tc.column] = tc.value
			if _, err := r.read(ctx, tx, p, r.guard); err == nil {
				t.Fatal("changed current field admitted")
			}
		})
	}
	s.values = append([]driver.Value(nil), valid...)
	first, err := r.read(ctx, tx, p, r.guard)
	if err != nil || !bytes.Equal(first, []byte("original lease")) {
		t.Fatal("valid current row rejected", err)
	}
	s.values[4] = []byte("same transaction changed lease")
	second, err := r.read(ctx, tx, p, r.guard)
	if err != nil || bytes.Equal(first, second) {
		t.Fatal("current lease bytes were reused", err)
	}
	wantArgs := []any{"installation", "task", int64(7), "task", int64(7), "ns", "job", "uid"}
	if !reflect.DeepEqual(s.args, wantArgs) {
		t.Fatal("original exact SQL scope changed", s.args)
	}
	s.values = nil
	if _, err = r.read(ctx, tx, p, r.guard); err == nil {
		t.Fatal("missing current Job admitted")
	}
	s.queryErr = errors.New("read unavailable")
	if _, err = r.read(ctx, tx, p, r.guard); err == nil {
		t.Fatal("query error admitted")
	}
	s.queryErr = nil
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	calls := s.calls
	if _, err = r.read(ctx, tx, p, r.guard); err == nil || s.calls != calls {
		t.Fatal("finished transaction reused")
	}
}
