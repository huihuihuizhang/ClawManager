package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"
)

type legacy177StreamModel struct {
	values            [][]driver.Value
	expected, largest int64
	late              bool
	reads             int
}
type legacy177StreamConnector struct{ m *legacy177StreamModel }

func (c legacy177StreamConnector) Connect(context.Context) (driver.Conn, error) {
	return &legacy177StreamConn{c.m}, nil
}
func (c legacy177StreamConnector) Driver() driver.Driver { return legacy177StreamDriver{c.m} }

type legacy177StreamDriver struct{ m *legacy177StreamModel }

func (d legacy177StreamDriver) Open(string) (driver.Conn, error) {
	return &legacy177StreamConn{d.m}, nil
}

type legacy177StreamConn struct{ m *legacy177StreamModel }

func (c *legacy177StreamConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepared statement")
}
func (c *legacy177StreamConn) Close() error { return nil }
func (c *legacy177StreamConn) Begin() (driver.Tx, error) {
	return nil, errors.New("unexpected transaction")
}
func (c *legacy177StreamConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if strings.HasPrefix(query, "SELECT COUNT(*),COALESCE(MAX(") {
		return &legacy177StreamRows{columns: []string{"count", "max"}, values: [][]driver.Value{{c.m.expected, c.m.largest}}}, nil
	}
	if !strings.HasPrefix(query, "SELECT `a`,`b` FROM `original_rows`") {
		return nil, errors.New("unexpected row query")
	}
	c.m.reads++
	return &legacy177StreamRows{columns: []string{"a", "b"}, values: c.m.values, late: c.m.late}, nil
}

type legacy177StreamRows struct {
	columns []string
	values  [][]driver.Value
	at      int
	late    bool
}

func (r *legacy177StreamRows) Columns() []string { return r.columns }
func (r *legacy177StreamRows) Close() error      { return nil }
func (r *legacy177StreamRows) Next(dest []driver.Value) error {
	if r.at == len(r.values) {
		if r.late {
			return errors.New("injected late read failure")
		}
		return io.EOF
	}
	copy(dest, r.values[r.at])
	r.at++
	return nil
}

func TestLegacy177StreamRowsKeepsExactOriginalFramingAndEOF(t *testing.T) {
	for _, fault := range []string{"none", "empty", "late_read", "count_mismatch", "large_row_preflight", "row_ceiling_preflight"} {
		t.Run(fault, func(t *testing.T) {
			m := &legacy177StreamModel{values: [][]driver.Value{{nil, []byte{}}, {[]byte{}, nil}, {[]byte("same"), []byte{0, 1, 255}}, {[]byte("same"), []byte{0, 1, 255}}, {"中文", int64(42)}}, expected: 5, largest: 32}
			switch fault {
			case "empty":
				m.values = nil
				m.expected = 0
				m.largest = 0
			case "late_read":
				m.late = true
			case "count_mismatch":
				m.expected++
			case "large_row_preflight":
				m.largest = legacy177MaxRowBytes + 1
			case "row_ceiling_preflight":
				m.expected = legacy177MaxRows + 1
			}
			pool := sql.OpenDB(legacy177StreamConnector{m})
			defer pool.Close()
			table := importTable{Name: "original_rows", Columns: []string{"a", "b"}}
			actual, e := proveLegacy177TableRows(context.Background(), pool, table, table.Name, backupImportMap{})
			if fault == "none" || fault == "empty" {
				if e != nil {
					t.Fatal(e)
				}
				expected, e := proveImportTable(context.Background(), pool, table, table.Name, backupImportMap{})
				if e != nil || actual.Rows != expected.Rows || actual.SHA256 != expected.SHA256 {
					t.Fatal("original row framing/NULL/empty/duplicates changed", e)
				}
			} else {
				if e == nil {
					t.Fatal("incomplete/oversized proof accepted")
				}
				if strings.HasSuffix(fault, "preflight") {
					var b *Legacy177RowProofBudgetError
					if !errors.As(e, &b) || b.Table != "original_rows" || m.reads != 0 {
						t.Fatal("large rows fetched before size guard", e)
					}
				}
			}
		})
	}
}
