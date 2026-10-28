package systembackupread

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// Cancel only after the real database/sql transaction has entered its driver's
// Commit. The driver can acknowledge success after the request is canceled;
// database/sql does not promise a second context check after that acknowledgement.
type readCommitProbe struct {
	base               driver.Connector
	afterCommit        func()
	commitErr          error
	zeroTaskCutoff     bool
	commits, rollbacks int
}

func (p *readCommitProbe) Driver() driver.Driver { return p.base.Driver() }
func (p *readCommitProbe) Connect(ctx context.Context) (driver.Conn, error) {
	c, err := p.base.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &readCommitConn{Conn: c, probe: p}, nil
}

type readCommitConn struct {
	driver.Conn
	probe *readCommitProbe
}

func (c *readCommitConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	tx, err := c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return readCommitTx{Tx: tx, probe: c.probe}, nil
}

func (c *readCommitConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if c.probe.zeroTaskCutoff && strings.HasPrefix(query, "SELECT COALESCE(MAX(id),0) FROM system_") {
		if len(args) != 1 || args[0].Value != "installation_test" {
			return nil, errors.New("unscoped empty task query")
		}
		return &pageRows{columns: []string{"cutoff"}, values: [][]driver.Value{{int64(0)}}}, nil
	}
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
}

type readCommitTx struct {
	driver.Tx
	probe *readCommitProbe
}

func (tx readCommitTx) Commit() error {
	tx.probe.commits++
	err := tx.Tx.Commit()
	if tx.probe.afterCommit != nil {
		tx.probe.afterCommit()
	}
	if err != nil {
		return err
	}
	return tx.probe.commitErr
}

func (tx readCommitTx) Rollback() error {
	tx.probe.rollbacks++
	return tx.Tx.Rollback()
}

type readCommitCase struct {
	base           driver.Connector
	scope          ScopeProvider
	read           func(context.Context, *Service) (any, error)
	rechecks       func() int
	healthyErr     error
	zeroTaskCutoff bool
}

func TestReadCommitContextBoundary(t *testing.T) {
	factories := make(map[string]func(*testing.T) readCommitCase)
	for _, name := range []string{"active", "version", "active_missing", "version_missing", "history", "empty_history", "backfill_control"} {
		factories["config_"+name] = func(t *testing.T) readCommitCase {
			f := configHistoryFixture(t, 3)
			row := append([]byte(nil), f.row[6].([]byte)...)
			var healthyErr error
			if name == "active_missing" || name == "version_missing" {
				f.row = nil
				healthyErr = ErrNotFound
			}
			if name == "empty_history" {
				f.rows = nil
			}
			return readCommitCase{base: configConnector{f}, scope: f, rechecks: func() int { return f.rechecks }, healthyErr: healthyErr,
				read: func(ctx context.Context, s *Service) (any, error) {
					switch name {
					case "active", "active_missing":
						return s.ReadActiveConfigDTO(ctx)
					case "version", "version_missing":
						return s.ReadConfigVersionDTO(ctx, 1)
					case "backfill_control":
						return s.reader.VerifyConfigBackfillSource(ctx, 1, row)
					default:
						return s.ListConfigDTO(ctx, 2, "")
					}
				}}
		}
	}
	for _, name := range []string{"detail", "missing", "list", "empty_list"} {
		factories["operation_"+name] = func(t *testing.T) readCommitCase {
			if name == "list" || name == "empty_list" {
				f := makeOperationListFixture()
				if name == "empty_list" {
					f.rows = nil
				}
				return readCommitCase{base: operationListConnector{f}, scope: f, rechecks: func() int { return f.rechecks },
					read: func(ctx context.Context, s *Service) (any, error) { return s.ListOperationDTO(ctx, 2, "") }}
			}
			f := operationTestFixture()
			var healthyErr error
			if name == "missing" {
				f.row = nil
				healthyErr = ErrNotFound
			}
			return readCommitCase{base: operationConnector{f}, scope: f, rechecks: func() int { return f.rechecks }, healthyErr: healthyErr,
				read: func(ctx context.Context, s *Service) (any, error) { return s.GetOperationDTO(ctx, operationTestID) }}
		}
	}
	factories["overview_control"] = func(t *testing.T) readCommitCase {
		f := newOverviewFixture()
		return readCommitCase{base: overviewConnector{f}, scope: f, rechecks: func() int { return f.rechecks },
			read: func(ctx context.Context, s *Service) (any, error) { return s.reader.ReadOverviewControl(ctx) }}
	}
	for _, kind := range []TaskKind{BackupTask, DrillTask, PreflightTask, VerificationTask} {
		for _, name := range []string{"list", "empty_list", "base", "missing", "execution", "control", "events"} {
			factories[string(kind)+"_"+name] = func(t *testing.T) readCommitCase {
				f := newDetailControlFixture(kind)
				id := f.rows[0][1].(string)
				var healthyErr error
				if name == "missing" {
					f.rows = nil
					healthyErr = ErrNotFound
				}
				var connector driver.Connector = detailControlConnector{f}
				if name == "base" || name == "missing" {
					connector = pageConnector{f.pageFixture}
				}
				if name == "events" {
					e := newEventControlFixture(kind)
					f.executionFixture = e.executionFixture
					connector = eventControlConnector{e}
				}
				return readCommitCase{base: connector, scope: f, rechecks: func() int { return f.rechecks }, healthyErr: healthyErr, zeroTaskCutoff: name == "empty_list",
					read: func(ctx context.Context, s *Service) (any, error) {
						switch name {
						case "list", "empty_list":
							return s.ListTaskDTO(ctx, kind, "", 2, "")
						case "base", "missing":
							return s.GetTaskBase(ctx, kind, id)
						case "execution":
							return s.reader.ReadTaskExecution(ctx, kind, id)
						case "control":
							return s.reader.ReadTaskDetailControl(ctx, kind, id)
						default:
							return s.ListTaskEventsDTO(ctx, kind, id, 2, "")
						}
					}}
			}
		}
	}
	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			for _, mode := range []string{"healthy", "canceled_in_commit", "commit_error"} {
				t.Run(mode, func(t *testing.T) {
					f := factory(t)
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					probe := &readCommitProbe{base: f.base, zeroTaskCutoff: f.zeroTaskCutoff}
					if mode == "canceled_in_commit" {
						probe.afterCommit = cancel
					}
					if mode == "commit_error" {
						probe.commitErr = errors.New("private driver commit failure")
					}
					db := sql.OpenDB(probe)
					defer db.Close()
					s, err := NewService(db, f.scope, []byte(strings.Repeat("k", 32)))
					if err != nil {
						t.Fatal(err)
					}
					result, err := f.read(ctx, s)
					if probe.commits != 1 || probe.rollbacks != 0 || f.rechecks() != 1 {
						t.Fatalf("probe missed final transaction boundary: commits=%d rollbacks=%d rechecks=%d", probe.commits, probe.rollbacks, f.rechecks())
					}
					if mode == "healthy" {
						if !errors.Is(err, f.healthyErr) || f.healthyErr == nil && reflect.ValueOf(result).IsZero() || f.healthyErr != nil && !reflect.ValueOf(result).IsZero() {
							t.Fatal("healthy read or authorized missing/empty outcome changed", err)
						}
						return
					}
					if mode == "canceled_in_commit" && ctx.Err() != context.Canceled {
						t.Fatal("fault did not cancel the live request during driver Commit")
					}
					if err != ErrUnavailable || !reflect.ValueOf(result).IsZero() {
						t.Error("late or failed commit returned data, cursor, metadata or an authorized missing result", err)
					}
				})
			}
		})
	}
}
