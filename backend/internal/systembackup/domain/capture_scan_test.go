package domain

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"reflect"
	"testing"
)

// A standalone database/sql driver, with no server/network, exercises the exact
// production scan helper. It does not model RR, grants or a real MySQL driver.
type captureScanConnector struct{ count int }

func (c captureScanConnector) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c captureScanConnector) Driver() driver.Driver                        { return c }
func (c captureScanConnector) Open(string) (driver.Conn, error)             { return c, nil }
func (c captureScanConnector) Close() error                                 { return nil }
func (c captureScanConnector) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("not used")
}
func (c captureScanConnector) Begin() (driver.Tx, error) { return nil, errors.New("not used") }
func (c captureScanConnector) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return &captureScanRows{left: c.count, buffer: []byte{0, 0, 0, 0}}, nil
}

type captureScanRows struct {
	left, index int
	buffer      []byte
}

func (r *captureScanRows) Columns() []string { return []string{"binary", "nullable", "unsigned"} }
func (r *captureScanRows) Close() error      { clear(r.buffer); return nil }
func (r *captureScanRows) Next(values []driver.Value) error {
	if r.left == 0 {
		return io.EOF
	}
	r.left--
	r.index++
	r.buffer[0], r.buffer[1], r.buffer[2], r.buffer[3] = byte(r.index), 0, 255, byte(r.index+1)
	values[0], values[1], values[2] = r.buffer, nil, []byte("18446744073709551615")
	if r.index%2 == 0 {
		values[1] = []byte{}
	}
	return nil
}

func TestCaptureScanReusesSlotsWithoutLosingRawValues(t *testing.T) {
	db := sql.OpenDB(captureScanConnector{count: 3})
	defer db.Close()
	rows, err := db.QueryContext(context.Background(), "opaque fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var timing CaptureTimings
	ctx := WithCaptureTimings(context.Background(), &timing)
	slots := newCaptureScanSlots(3)
	first := &slots.values[0]
	var copies [][]byte
	for index := 1; rows.Next(); index++ {
		values, err := slots.scan(ctx, rows)
		if err != nil || &values[0] != first || !reflect.DeepEqual(values[0], []byte{byte(index), 0, 255, byte(index + 1)}) || string(values[2].([]byte)) != "18446744073709551615" {
			t.Fatal("scan changed binary/unsigned value or allocated new slots", err)
		}
		if index%2 == 1 && values[1] != nil || index%2 == 0 && (values[1] == nil || len(values[1].([]byte)) != 0) {
			t.Fatal("NULL and empty collapsed")
		}
		// The production caller uses rawCell to make this owning copy.
		copies = append(copies, append([]byte(nil), values[0].([]byte)...))
		clear(values)
	}
	if rows.Err() != nil || !reflect.DeepEqual(copies, [][]byte{{1, 0, 255, 2}, {2, 0, 255, 3}, {3, 0, 255, 4}}) {
		t.Fatal("driver reuse contaminated caller-owned bytes")
	}
	if samples := timing.Snapshot(); len(samples) != 1 || samples[0].Calls != 3 || samples[0].Failures != 0 {
		t.Fatal("scan measurement changed operation count", samples)
	}
}

func TestCaptureScanFailureClearsScratchAndReturnsNoValues(t *testing.T) {
	db := sql.OpenDB(captureScanConnector{count: 1})
	defer db.Close()
	rows, err := db.QueryContext(context.Background(), "opaque fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatal("missing fixture row")
	}
	var timing CaptureTimings
	ctx := WithCaptureTimings(context.Background(), &timing)
	slots := newCaptureScanSlots(2) // driver has three columns
	slots.values[0], slots.values[1] = "old private value", "old private value"
	got, err := slots.scan(ctx, rows)
	if err == nil || got != nil || slots.values[0] != nil || slots.values[1] != nil {
		t.Fatal("failed scan exposed prior/partial values")
	}
	if samples := timing.Snapshot(); len(samples) != 1 || samples[0].Failures != 1 {
		t.Fatal("scan failure not counted", samples)
	}
}

func BenchmarkCaptureScanSlots(b *testing.B) {
	for _, reuse := range []bool{false, true} {
		name := "per_row_baseline"
		if reuse {
			name = "per_table_reuse"
		}
		b.Run(name, func(b *testing.B) {
			db := sql.OpenDB(captureScanConnector{count: b.N})
			defer db.Close()
			rows, err := db.QueryContext(context.Background(), "opaque fixture")
			if err != nil {
				b.Fatal(err)
			}
			defer rows.Close()
			ctx := context.Background()
			slots := newCaptureScanSlots(3)
			b.ReportAllocs()
			b.ResetTimer()
			for rows.Next() {
				if !reuse {
					slots = newCaptureScanSlots(3)
				}
				values, err := slots.scan(ctx, rows)
				if err != nil {
					b.Fatal(err)
				}
				clear(values)
			}
			if rows.Err() != nil {
				b.Fatal(rows.Err())
			}
		})
	}
}
