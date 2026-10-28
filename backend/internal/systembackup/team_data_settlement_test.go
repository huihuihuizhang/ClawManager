package systembackup

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// Every normal statement still reaches disposable MySQL. Only one terminal
// write is refused, after execute has returned from the actual operation.
type failedSettlementConnector struct {
	driver.Connector
	Fail *atomic.Bool
}

func (c failedSettlementConnector) Connect(ctx context.Context) (driver.Conn, error) {
	v, e := c.Connector.Connect(ctx)
	if e != nil {
		return nil, e
	}
	return failedSettlementConn{Conn: v, Fail: c.Fail}, nil
}

type failedSettlementConn struct {
	driver.Conn
	Fail *atomic.Bool
}

func (c failedSettlementConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if strings.HasPrefix(q, "UPDATE system_team_data_backup_jobs SET status=?") && c.Fail.Swap(false) {
		return nil, errors.New("injected terminal write failure")
	}
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
}
func (c failedSettlementConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
}
func (c failedSettlementConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, o)
}

func TestTeamDataExitedExecutionWithFailedResultWriteDoesNotRemainRunning(t *testing.T) {
	s := teamDataJobFixture(t)
	var database string
	if e := s.db.QueryRow("SELECT DATABASE()").Scan(&database); e != nil {
		t.Fatal(e)
	}
	cfg := mysql.Config{User: "root", Net: "tcp", Addr: "127.0.0.1:" + os.Getenv("TEST_SYSTEM_BACKUP_MYSQL_PORT"), DBName: database, ParseTime: true, Loc: time.UTC, AllowNativePasswords: true}
	connector, e := mysql.NewConnector(&cfg)
	if e != nil {
		t.Fatal(e)
	}
	fail := &atomic.Bool{}
	fail.Store(true)
	wrapped := sql.OpenDB(failedSettlementConnector{Connector: connector, Fail: fail})
	defer wrapped.Close()
	s.db = wrapped
	s.cfg.InstallationID = "result-write-failure"
	s.cfg.DeadlineSeconds = 60
	ctx := context.Background()
	original, e := s.Create(ctx, 1, "terminal-write-failed-original", "backup", "")
	if e != nil {
		t.Fatal(e)
	}
	// Use the existing disabled-work rejection to prove executor exit without
	// dispatching a real collector or claiming remote process termination.
	s.cfg.Disabled = true
	run, stop := context.WithTimeout(ctx, 8*time.Second)
	defer stop()
	done := make(chan struct{})
	go func() { defer close(done); s.Run(run) }()
	var actual TeamDataJob
	for run.Err() == nil {
		actual, e = s.Get(ctx, original.ID)
		if e == nil && actual.Status == "failed" && actual.Error == "process_interrupted" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	stop()
	<-done
	if e != nil || actual.Status != "failed" || actual.Error != "process_interrupted" || fail.Load() {
		t.Fatal("exited execution kept an active slot", e, actual.Status, actual.Error)
	}
	s.cfg.Disabled = false
	if _, e = s.Create(ctx, 1, "new-backup-after-result-reconciliation", "backup", ""); e != nil {
		t.Fatal("lost result prevented later work", e)
	}
}
