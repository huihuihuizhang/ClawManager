package systembackupcontroller

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type utcProbeState struct {
	offsetMicros int64
	queryErr     error
	calls        int
}

type utcProbeConnector struct{ state *utcProbeState }

func (c utcProbeConnector) Connect(context.Context) (driver.Conn, error) {
	return &utcProbeConn{state: c.state}, nil
}
func (c utcProbeConnector) Driver() driver.Driver { return utcProbeDriver{state: c.state} }

type utcProbeDriver struct{ state *utcProbeState }

func (d utcProbeDriver) Open(string) (driver.Conn, error) {
	return &utcProbeConn{state: d.state}, nil
}

type utcProbeConn struct{ state *utcProbeState }

func (*utcProbeConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected UTC probe preparation")
}
func (*utcProbeConn) Close() error { return nil }
func (*utcProbeConn) Begin() (driver.Tx, error) {
	return nil, errors.New("unexpected UTC probe transaction")
}
func (c *utcProbeConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.state.calls++
	if len(args) != 0 || !strings.Contains(query, "TIMESTAMPDIFF(MICROSECOND, UTC_TIMESTAMP(6), CURRENT_TIMESTAMP(6))") {
		return nil, errors.New("unexpected UTC probe query")
	}
	if c.state.queryErr != nil {
		return nil, c.state.queryErr
	}
	return &utcProbeRows{offsetMicros: c.state.offsetMicros}, nil
}

type utcProbeRows struct {
	offsetMicros int64
	read         bool
}

func (*utcProbeRows) Columns() []string { return []string{"offset_microseconds"} }
func (*utcProbeRows) Close() error      { return nil }
func (r *utcProbeRows) Next(dest []driver.Value) error {
	if r.read {
		return io.EOF
	}
	r.read = true
	dest[0] = r.offsetMicros
	return nil
}

func TestSQLUTCReadinessProbeRequiresUTCAndFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name       string
		offset     int64
		queryErr   error
		wantFailed bool
	}{
		{name: "UTC"},
		{name: "non-UTC", offset: int64((8 * time.Hour) / time.Microsecond), wantFailed: true},
		{name: "query error", queryErr: errors.New("database unavailable"), wantFailed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := &utcProbeState{offsetMicros: test.offset, queryErr: test.queryErr}
			db := sql.OpenDB(utcProbeConnector{state: state})
			defer db.Close()
			err := (SQLUTCReadinessProbe{DB: db}).Check(context.Background())
			if (err != nil) != test.wantFailed || state.calls != 1 {
				t.Fatalf("offset=%d error=%v calls=%d", test.offset, err, state.calls)
			}
		})
	}
	if err := (SQLUTCReadinessProbe{}).Check(context.Background()); err == nil {
		t.Fatal("nil UTC probe database was accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (SQLUTCReadinessProbe{}).Check(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled UTC probe error=%v", err)
	}
}
