package systembackupexecution

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"
)

// SQL DATA-only observation driver. No work, token, passed authority, write,
// transaction, native call or permission constructor can be produced here.
type dTerminalDataDriver struct {
	status, category string
	queries          *int
}
type dTerminalDataConn struct{ dTerminalDataDriver }
type dTerminalDataRows struct {
	values []driver.Value
	done   bool
}

func (d dTerminalDataDriver) Connect(context.Context) (driver.Conn, error) {
	return dTerminalDataConn{d}, nil
}
func (d dTerminalDataDriver) Driver() driver.Driver { return d }
func (d dTerminalDataDriver) Open(string) (driver.Conn, error) {
	return d.Connect(context.Background())
}
func (dTerminalDataConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("DATA observer cannot prepare")
}
func (dTerminalDataConn) Close() error { return nil }
func (dTerminalDataConn) Begin() (driver.Tx, error) {
	return nil, errors.New("DATA observer cannot begin")
}
func (d dTerminalDataConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if q != "SELECT status,failure_category FROM system_backup_v2_backups WHERE public_id=?" || len(args) != 1 || args[0].Value != "original-task-DATA" {
		return nil, errors.New("unexpected DATA observation")
	}
	*d.queries++
	return &dTerminalDataRows{values: []driver.Value{d.status, d.category}}, nil
}
func (*dTerminalDataRows) Columns() []string { return []string{"status", "failure_category"} }
func (*dTerminalDataRows) Close() error      { return nil }
func (d *dTerminalDataRows) Next(values []driver.Value) error {
	if d.done {
		return io.EOF
	}
	copy(values, d.values)
	d.done = true
	return nil
}

func TestOriginalSelectionTerminalDataNeverBecomesWork(t *testing.T) {
	for _, state := range []string{"failed", "canceled", "succeeded", "ready_for_capture", "unrecognized"} {
		t.Run(state, func(t *testing.T) {
			queries := 0
			db := sql.OpenDB(dTerminalDataDriver{state, "quiesce_timeout", &queries})
			defer db.Close()
			err := readDOriginalSelectionTerminal(context.Background(), db, "original-task-DATA")
			if queries != 1 {
				t.Fatal("observer replayed state read", queries)
			}
			if state == "ready_for_capture" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if state == "unrecognized" {
				if err == nil {
					t.Fatal("unknown state treated as pending")
				}
				return
			}
			if !errors.Is(err, errDOriginalSelectionTerminal) || !strings.Contains(err.Error(), "category=quiesce_timeout") {
				t.Fatal("terminal lost original category", err)
			}
		})
	}
	cause := errors.New("concrete SQL observation failed")
	queries := 0
	db := sql.OpenDB(descriptionErrorConnector{queries: &queries, cause: cause})
	defer db.Close()
	if err := readDOriginalSelectionTerminal(context.Background(), db, "original-task-DATA"); !errors.Is(err, cause) || queries != 1 {
		t.Fatal("unknown SQL became terminal/absence", err, queries)
	}
}
