package install

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// A database/sql locking/identity protocol MODEL, not MySQL or original admin
// authentication. No replacement DB/Kube/physical success proof is produced.
type installedConfigTestState struct {
	account, server, database, installation  string
	version                                  uint64
	rows                                     [][]driver.Value
	missing, rollbackError                   bool
	begins, rollbacks, commits, writes, open int
	queries                                  []string
}
type installedConfigTestConnector struct{ state *installedConfigTestState }

func (c installedConfigTestConnector) Driver() driver.Driver { return installedConfigTestDriver{} }
func (c installedConfigTestConnector) Connect(context.Context) (driver.Conn, error) {
	return &installedConfigTestConn{state: c.state}, nil
}

type installedConfigTestDriver struct{}

func (installedConfigTestDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

type installedConfigTestConn struct {
	state  *installedConfigTestState
	active bool
}

func (c *installedConfigTestConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unused")
}
func (c *installedConfigTestConn) Close() error { return nil }
func (c *installedConfigTestConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{Isolation: driver.IsolationLevel(sql.LevelRepeatableRead)})
}
func (c *installedConfigTestConn) BeginTx(_ context.Context, o driver.TxOptions) (driver.Tx, error) {
	if c.active || o.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
		return nil, errors.New("wrong transaction")
	}
	c.state.begins++
	c.state.open++
	c.active = true
	return installedConfigTestTx{c}, nil
}

type installedConfigTestTx struct{ c *installedConfigTestConn }

func (t installedConfigTestTx) Commit() error {
	t.c.active = false
	t.c.state.open--
	t.c.state.commits++
	return nil
}
func (t installedConfigTestTx) Rollback() error {
	t.c.active = false
	t.c.state.open--
	t.c.state.rollbacks++
	if t.c.state.rollbackError {
		return errors.New("rollback failed")
	}
	return nil
}

type installedConfigTestRows struct {
	width  int
	values [][]driver.Value
	at     int
}

func (r *installedConfigTestRows) Columns() []string { return make([]string, r.width) }
func (r *installedConfigTestRows) Close() error      { return nil }
func (r *installedConfigTestRows) Next(out []driver.Value) error {
	if r.at >= len(r.values) {
		return io.EOF
	}
	copy(out, r.values[r.at])
	r.at++
	return nil
}
func (c *installedConfigTestConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if !c.active || ctx.Err() != nil || len(args) != 0 {
		return nil, errors.New("unbound source query")
	}
	s := c.state
	s.queries = append(s.queries, q)
	switch q {
	case `SELECT CURRENT_USER(),@@server_uuid,DATABASE(),UTC_TIMESTAMP(6)`:
		return &installedConfigTestRows{width: 4, values: [][]driver.Value{{s.account, s.server, s.database, time.Now().UTC().Truncate(time.Microsecond)}}}, nil
	case `SELECT origin_installation_id,config_version FROM system_backup_installation_state WHERE singleton_id=1 FOR SHARE`:
		values := [][]driver.Value{{s.installation, int64(s.version)}}
		if s.missing {
			values = nil
		}
		return &installedConfigTestRows{width: 2, values: values}, nil
	case `SELECT version,config_json FROM system_backup_config_versions ORDER BY version FOR SHARE`:
		return &installedConfigTestRows{width: 2, values: s.rows}, nil
	}
	return nil, errors.New("unexpected source query")
}
func (c *installedConfigTestConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	c.state.writes++
	return nil, errors.New("source reader cannot write")
}

func installedConfigTest(t *testing.T) (context.Context, *sql.DB, *installedConfigTestState, time.Time) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	s := &installedConfigTestState{account: "installer@original", server: "01234567-89ab-cdef-0123-456789abcdef", database: "original_db", installation: "installation_original", version: 2,
		rows: [][]driver.Value{{int64(1), `{"enabled":false,"artifact_target":{"provider":"kubernetes","name":"retired-target","version":"v1","purpose":"artifact"},"original_unmodelled_field":"retained"}`}, {int64(2), `{"enabled":false}`}}}
	db := sql.OpenDB(installedConfigTestConnector{s})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	deadline, _ := ctx.Deadline()
	return ctx, db, s, deadline
}

func TestOriginalInstalledBackupConfigActualSQLSourceAndRetiredRefs(t *testing.T) {
	ctx, db, state, until := installedConfigTest(t)
	r, err := readOriginalInstalledBackupConfiguration(ctx, db, until)
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	if r.installation != state.installation || r.version != 2 || len(r.versions) != 2 || len(r.versions[0].references) != 1 || len(r.versions[1].references) != 0 ||
		r.versions[0].references[0].Name != "retired-target" || !strings.Contains(string(r.versions[0].raw), "original_unmodelled_field") {
		t.Fatal("original identity/history/reference was replaced by current defaults")
	}
	if r.recheck(ctx) != nil || state.writes != 0 || state.commits != 0 || state.open != 0 {
		t.Fatal("source recheck wrote/retained SQL state")
	}
	if raw, err := json.Marshal(r); err == nil || raw != nil {
		t.Fatal("private source serialized")
	}
	copy := *r
	if copy.recheck(ctx) == nil {
		t.Fatal("copied source accepted")
	}
	for _, q := range state.queries {
		if strings.Contains(q, "FROM system_backup_") && !strings.HasSuffix(q, " FOR SHARE") {
			t.Fatal("unlocked source read")
		}
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	before := state.begins
	if r.recheckLocked(ctx, tx) != nil || state.begins != before {
		t.Fatal("locked check opened a detached transaction")
	}
	if tx.Rollback() != nil || state.open != 0 {
		t.Fatal("test transaction leak")
	}
}

func TestOriginalInstalledBackupConfigSourceRefusals(t *testing.T) {
	for _, mode := range []string{"absent_state", "empty_identity", "foreign_identity_format", "missing_version", "gap", "future_version", "bad_json", "duplicate_key", "latest_ref", "wrong_purpose", "unknown_ref_field", "missing_enabled", "null_enabled", "active_missing_refs", "rollback_failed"} {
		t.Run(mode, func(t *testing.T) {
			ctx, db, s, until := installedConfigTest(t)
			switch mode {
			case "absent_state":
				s.missing = true
			case "empty_identity":
				s.installation = ""
			case "foreign_identity_format":
				s.installation = "../replacement"
			case "missing_version":
				s.rows = s.rows[:1]
			case "gap":
				s.rows[1][0] = int64(3)
			case "future_version":
				s.version = 1
			case "bad_json":
				s.rows[1][1] = `{`
			case "duplicate_key":
				s.rows[1][1] = `{"enabled":false,"enabled":true}`
			case "latest_ref":
				s.rows[0][1] = strings.Replace(s.rows[0][1].(string), `"v1"`, `"latest"`, 1)
			case "wrong_purpose":
				s.rows[0][1] = strings.Replace(s.rows[0][1].(string), `"purpose":"artifact"`, `"purpose":"catalog"`, 1)
			case "unknown_ref_field":
				s.rows[0][1] = strings.Replace(s.rows[0][1].(string), `"provider":"kubernetes"`, `"secret":"untrusted","provider":"kubernetes"`, 1)
			case "missing_enabled":
				s.rows[1][1] = `{}`
			case "null_enabled":
				s.rows[1][1] = `{"enabled":null}`
			case "active_missing_refs":
				s.rows[1][1] = `{"enabled":true}`
			case "rollback_failed":
				s.rollbackError = true
			}
			if r, err := readOriginalInstalledBackupConfiguration(ctx, db, until); err == nil || r != nil {
				t.Fatal("incomplete source became default/empty config", mode)
			}
			if s.open != 0 || s.writes != 0 {
				t.Fatal("failed source read leaked state")
			}
		})
	}
}

func TestOriginalInstalledBackupConfigRecheckRefusals(t *testing.T) {
	for _, mode := range []string{"wrong_context", "expired", "identity_changed", "old_reference_changed", "new_config", "database_changed", "nil_transaction"} {
		t.Run(mode, func(t *testing.T) {
			ctx, db, s, until := installedConfigTest(t)
			r, err := readOriginalInstalledBackupConfiguration(ctx, db, until)
			if err != nil {
				t.Fatal(err)
			}
			defer r.close()
			checkCtx := ctx
			switch mode {
			case "wrong_context":
				var cancel context.CancelFunc
				checkCtx, cancel = context.WithCancel(ctx)
				defer cancel()
			case "expired":
				r.until = time.Now().Add(-time.Second)
			case "identity_changed":
				s.installation = "installation_replacement"
			case "old_reference_changed":
				s.rows[0][1] = strings.Replace(s.rows[0][1].(string), "retired-target", "replacement-target", 1)
			case "new_config":
				s.version++
				s.rows = append(s.rows, []driver.Value{int64(3), `{"enabled":false}`})
			case "database_changed":
				s.database = "other_db"
			case "nil_transaction":
				if r.recheckLocked(ctx, nil) == nil {
					t.Fatal("nil source transaction accepted")
				}
				return
			}
			if r.recheck(checkCtx) == nil {
				t.Fatal("source drift accepted", mode)
			}
			if s.open != 0 || s.writes != 0 {
				t.Fatal("source drift leaked state")
			}
		})
	}
}
