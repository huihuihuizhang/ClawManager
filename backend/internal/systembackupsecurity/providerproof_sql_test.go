package systembackupsecurity

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"
)

// A standard-library driver exercises the real database/sql transaction API;
// it is not a substitute for D's MySQL migration/integration validation.
type proofSQLState struct {
	rowVersion             int64
	affected               int64
	queryError, writeError bool
	staged, committed      int
	query                  string
	args                   []driver.NamedValue
}
type proofConnector struct{ s *proofSQLState }
type proofDriver struct{}

func (proofDriver) Open(string) (driver.Conn, error)                  { return nil, errors.New("connector required") }
func (c proofConnector) Driver() driver.Driver                        { return proofDriver{} }
func (c proofConnector) Connect(context.Context) (driver.Conn, error) { return &proofConn{s: c.s}, nil }

type proofConn struct{ s *proofSQLState }

func (c *proofConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (c *proofConn) Close() error                        { return nil }
func (c *proofConn) Begin() (driver.Tx, error)           { return &proofTx{s: c.s}, nil }
func (c *proofConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	c.s.query = q
	c.s.args = args
	if c.s.queryError {
		return nil, errors.New("SYNTHETIC_PRIVATE_DB_ERROR")
	}
	return &proofRows{version: c.s.rowVersion}, nil
}
func (c *proofConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	c.s.query = q
	c.s.args = args
	if c.s.writeError {
		return nil, errors.New("SYNTHETIC_PRIVATE_DB_ERROR")
	}
	if c.s.affected == 1 {
		c.s.staged++
	}
	return driver.RowsAffected(c.s.affected), nil
}

type proofTx struct{ s *proofSQLState }

func (t *proofTx) Commit() error   { t.s.committed += t.s.staged; t.s.staged = 0; return nil }
func (t *proofTx) Rollback() error { t.s.staged = 0; return nil }

type proofRows struct {
	version int64
	done    bool
}

func (*proofRows) Columns() []string { return []string{"row_version"} }
func (*proofRows) Close() error      { return nil }
func (r *proofRows) Next(v []driver.Value) error {
	if r.done {
		return io.EOF
	}
	v[0] = r.version
	r.done = true
	return nil
}

func TestProviderSQLStagesOnlyVerifiedInlineAndCallerCommits(t *testing.T) {
	r, c, _ := providerSignedFixture(t)
	p, err := PrepareProviderProofEvidence(r, c)
	if err != nil {
		t.Fatal(err)
	}
	s := &proofSQLState{rowVersion: 3, affected: 1}
	db := sql.OpenDB(proofConnector{s})
	defer db.Close()
	tx, _ := db.BeginTx(context.Background(), nil)
	if err = StageProviderProofEvidence(context.Background(), tx, "sev_11111111-1111-4111-8111-111111111111", p); err != nil {
		t.Fatal(err)
	}
	if s.committed != 0 || s.staged != 1 {
		t.Fatal("writer committed early")
	}
	if !strings.Contains(s.query, "UTC_TIMESTAMP(6) >= ? AND UTC_TIMESTAMP(6) < ?") || !strings.Contains(s.query, "'inline'") || len(s.args) != 10 {
		t.Fatal("missing DB expiry guard or inline binding")
	}
	if s.args[1].Value != r.Target.TargetType || s.args[3].Value != "provider_presence_proof" || s.args[5].Value != p.checksum {
		t.Fatal("incorrect SQL binding")
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if s.staged != 0 || s.committed != 0 {
		t.Fatal("rollback failed")
	}
	tx, _ = db.BeginTx(context.Background(), nil)
	if err = StageProviderProofEvidence(context.Background(), tx, "sev_22222222-2222-4222-8222-222222222222", p); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil || s.committed != 1 {
		t.Fatal("caller commit failed", err)
	}
}

func TestProviderSQLFailsClosedAndRedactsCauses(t *testing.T) {
	r, c, _ := providerSignedFixture(t)
	p, _ := PrepareProviderProofEvidence(r, c)
	for _, tc := range []struct {
		name string
		s    proofSQLState
		code ProviderFailureCode
	}{
		{"row-drift", proofSQLState{rowVersion: 4, affected: 1}, ProviderVersionConflict},
		{"expired-at-insert", proofSQLState{rowVersion: 3, affected: 0}, ProviderValidationFailed},
		{"lookup-error", proofSQLState{rowVersion: 3, queryError: true}, "storage"},
		{"insert-error", proofSQLState{rowVersion: 3, writeError: true}, "storage"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := sql.OpenDB(proofConnector{&tc.s})
			defer db.Close()
			tx, _ := db.BeginTx(context.Background(), nil)
			defer tx.Rollback()
			err := StageProviderProofEvidence(context.Background(), tx, "sev_11111111-1111-4111-8111-111111111111", p)
			if tc.code == "storage" {
				if err != ErrProviderEvidenceStorage {
					t.Fatal("storage error misclassified", err)
				}
			} else {
				providerWantCode(t, err, tc.code)
			}
			if tc.s.staged != 0 || tc.s.committed != 0 || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("failure wrote or leaked")
			}
		})
	}
	providerWantCode(t, StageProviderProofEvidence(context.Background(), nil, "", PreparedProviderEvidence{}), ProviderValidationFailed)
}
