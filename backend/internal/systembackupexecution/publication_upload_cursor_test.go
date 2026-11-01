package systembackupexecution

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"testing"
)

type publicationCursorConnector struct{ values []driver.Value }

func (c publicationCursorConnector) Driver() driver.Driver { return publicationCursorDriver{} }
func (c publicationCursorConnector) Connect(context.Context) (driver.Conn, error) {
	return &publicationCursorConn{values: c.values}, nil
}

type publicationCursorDriver struct{}

func (publicationCursorDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

type publicationCursorConn struct{ values []driver.Value }

func (*publicationCursorConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("read-only cursor fixture")
}
func (*publicationCursorConn) Close() error { return nil }
func (*publicationCursorConn) Begin() (driver.Tx, error) {
	return nil, errors.New("read-only cursor fixture")
}
func (c *publicationCursorConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return &publicationCursorRows{values: c.values}, nil
}

type publicationCursorRows struct {
	values []driver.Value
	done   bool
}

func (*publicationCursorRows) Columns() []string {
	return []string{"last_accepted_sequence", "last_observed_status", "last_accepted_body_sha256"}
}
func (*publicationCursorRows) Close() error { return nil }
func (r *publicationCursorRows) Next(dst []driver.Value) error {
	if r.done || r.values == nil {
		return io.EOF
	}
	r.done = true
	copy(dst, r.values)
	return nil
}

// database/sql performs the same actual NULL scans as production. This is a
// read-only row transport fixture, not a Job/result/claim authority or DDL test.
func TestOriginalUploadProductionCursorScansSQLNullsAndHashes(t *testing.T) {
	body := []byte("named original received result body DATA")
	for _, mode := range []string{"initial-null", "partial", "complete", "initial-empty-strings", "initial-status-only", "initial-sha-only", "partial-null-status", "partial-null-sha", "partial-bad-sha", "partial-bad-status", "complete-bad-status", "overflow", "missing-row", "last-body-mismatch"} {
		t.Run(mode, func(t *testing.T) {
			values := []driver.Value{int64(3), "upload_objects", hash(body)}
			switch mode {
			case "initial-null":
				values = []driver.Value{int64(0), nil, nil}
			case "complete":
				values = []driver.Value{int64(16), "upload_candidate", hash(body)}
			case "initial-empty-strings":
				values = []driver.Value{int64(0), "", ""}
			case "initial-status-only":
				values = []driver.Value{int64(0), "upload_objects", nil}
			case "initial-sha-only":
				values = []driver.Value{int64(0), nil, hash(body)}
			case "partial-null-status":
				values[1] = nil
			case "partial-null-sha":
				values[2] = nil
			case "partial-bad-sha":
				values[2] = "bad"
			case "partial-bad-status":
				values[1] = "upload_candidate"
			case "complete-bad-status":
				values[0] = int64(16)
			case "overflow":
				values[0] = int64(17)
			case "missing-row":
				values = nil
			}
			pool := sql.OpenDB(publicationCursorConnector{values: values})
			defer pool.Close()
			row := pool.QueryRowContext(context.Background(), "SELECT last_accepted_sequence,last_observed_status,last_accepted_body_sha256 FROM original_cursor_DATA")
			cursor, err := scanPublicationUploadCursor(row, 16)
			switch mode {
			case "initial-null":
				if err != nil || cursor.Sequence != 0 || cursor.Status.Valid || cursor.LastSHA.Valid {
					t.Fatal("true SQL NULL initial cursor rejected", cursor, err)
				}
			case "partial", "complete":
				if err != nil || !cursor.matchesLastBody(body) {
					t.Fatal("valid actual scanned cursor rejected", err)
				}
			case "last-body-mismatch":
				if err != nil || cursor.matchesLastBody([]byte("changed received body DATA")) {
					t.Fatal("cursor accepted different last result body", err)
				}
			default:
				if err == nil {
					t.Fatal("inconsistent SQL cursor accepted", mode, cursor)
				}
			}
		})
	}
}
