package systembackupcontroller

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type healthExecutor struct {
	queries []string
	args    [][]any
	rows    int64
	err     error
}

type healthConnector struct{ executor *healthExecutor }
type healthDriver struct{}
type healthConn struct{ executor *healthExecutor }

func (healthDriver) Open(string) (driver.Conn, error) { return nil, errors.New("use connector") }
func (c healthConnector) Driver() driver.Driver       { return healthDriver{} }
func (c healthConnector) Connect(context.Context) (driver.Conn, error) {
	return healthConn{c.executor}, nil
}
func (healthConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unexpected prepare") }
func (healthConn) Begin() (driver.Tx, error) {
	return nil, errors.New("health statements must autocommit")
}
func (healthConn) Close() error { return nil }
func (c healthConn) ExecContext(ctx context.Context, query string, values []driver.NamedValue) (driver.Result, error) {
	args := make([]any, len(values))
	for i, value := range values {
		args[i] = value.Value
	}
	return c.executor.ExecContext(ctx, query, args...)
}
func (e *healthExecutor) store(t *testing.T) ControlHealthStore {
	db := sql.OpenDB(healthConnector{e})
	t.Cleanup(func() { db.Close() })
	return ControlHealthStore{DB: db}
}

func (e *healthExecutor) ExecContext(_ context.Context, query string, args ...any) (sql.Result, error) {
	e.queries = append(e.queries, query)
	e.args = append(e.args, args)
	return fixedSQLResult{rows: e.rows}, e.err
}

func TestControlHealthEpochStartsUnknownAndObservationsRequireExactFence(t *testing.T) {
	e := &healthExecutor{rows: 1}
	s := e.store(t)
	writer, err := s.BeginWriter(context.Background(), "installation_test", 3, "controller:pod-uid", 0)
	if err != nil || writer.epoch != 1 || writer.sequence != 0 || e.queries[0] != controlHealthInitialSQL {
		t.Fatal("initial writer admission failed", writer, err)
	}
	if !strings.Contains(e.queries[0], "0,'unknown','unknown'") || !reflect.DeepEqual(e.args[0], []any{"controller:pod-uid", "installation_test", int64(3)}) {
		t.Fatal("writer startup manufactured health or lost scope")
	}
	probeCalls := 0
	probe := ReadinessProbeFunc(func(context.Context) error { probeCalls++; return nil })
	next, err := s.Observe(context.Background(), writer, ControlLoopResult{}, probe)
	if err != nil || next.sequence != 1 || probeCalls != 1 || e.queries[1] != controlHealthRecordSQL {
		t.Fatal("observation did not use actual database probe", next, err)
	}
	if !reflect.DeepEqual(e.args[1], []any{"healthy", "healthy", "installation_test", int64(3), "controller:pod-uid", int64(1), int64(0)}) {
		t.Fatal("observation is not bound to installation/config/owner/epoch/sequence", e.args[1])
	}
	for _, predicate := range []string{"c.version=h.config_version", "h.writer_epoch=?", "h.observation_sequence=?", "UTC_TIMESTAMP(6)<h.expires_at", "UTC_TIMESTAMP(6)>=h.observed_at", "CURRENT_TIMESTAMP(6)"} {
		if !strings.Contains(controlHealthRecordSQL, predicate) {
			t.Fatal("observation lacks fence", predicate)
		}
	}
	newWriter, err := s.BeginWriter(context.Background(), "installation_test", 4, "controller:new-pod", 1)
	if err != nil || newWriter.epoch != 2 || newWriter.sequence != 0 || e.queries[2] != controlHealthTakeoverSQL {
		t.Fatal("takeover did not reset observations and increment epoch", err)
	}
	// A real SQL zero-row CAS response must not issue any next token.
	e.rows = 0
	if token, err := s.Observe(context.Background(), next, ControlLoopResult{}, probe); !errors.Is(err, ErrControlHealthFence) || token != (ControlHealthWriter{}) {
		t.Fatal("rejected old writer produced a token", token, err)
	}
}

func TestControlHealthKeepsControllerAndDatabaseResultsIndependent(t *testing.T) {
	for _, controllerFailed := range []bool{false, true} {
		for _, databaseFailed := range []bool{false, true} {
			e := &healthExecutor{rows: 1}
			s := e.store(t)
			writer, err := s.BeginWriter(context.Background(), "installation_test", 1, "pod", 3)
			if err != nil {
				t.Fatal(err)
			}
			result := ControlLoopResult{}
			controllerState, databaseState := "healthy", "healthy"
			if controllerFailed {
				result.Err = errors.New("pass failed")
				controllerState = "degraded"
			}
			probe := ReadinessProbeFunc(func(context.Context) error {
				if databaseFailed {
					return errors.New("claim or grant probe failed")
				}
				return nil
			})
			if databaseFailed {
				databaseState = "degraded"
			}
			if _, err := s.Observe(context.Background(), writer, result, probe); err != nil {
				t.Fatal(err)
			}
			if e.args[1][0] != controllerState || e.args[1][1] != databaseState {
				t.Fatal("health dimensions conflated", e.args[1])
			}
		}
	}
}

func TestControlHealthRejectsMissingIdentityInvalidVersionsAndCancelledProbe(t *testing.T) {
	e := &healthExecutor{rows: 1}
	s := e.store(t)
	for _, input := range []struct {
		installation string
		config       uint64
		owner        string
		epoch        uint64
	}{
		{"", 1, "pod", 0}, {"installation_test", 0, "pod", 0}, {"installation_test", 1, "", 0},
		{"installation_test", maxHealthVersion + 1, "pod", 0}, {"installation_test", 1, "pod", maxHealthVersion},
	} {
		if _, err := s.BeginWriter(context.Background(), input.installation, input.config, input.owner, input.epoch); err == nil {
			t.Fatal("invalid writer admitted", input)
		}
	}
	if len(e.queries) != 0 {
		t.Fatal("invalid inputs reached SQL")
	}
	writer, err := s.BeginWriter(context.Background(), "installation_test", 1, "pod", 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := s.Observe(ctx, writer, ControlLoopResult{}, ReadinessProbeFunc(func(context.Context) error { cancel(); return nil })); err == nil {
		t.Fatal("cancelled probe wrote health")
	}
	if len(e.queries) != 1 {
		t.Fatal("cancellation reached health UPDATE")
	}
	if _, err := s.Observe(context.Background(), writer, ControlLoopResult{}, nil); err == nil {
		t.Fatal("missing database probe admitted")
	}
	e.err = errors.New("commit reply lost")
	if next, err := s.Observe(context.Background(), writer, ControlLoopResult{}, ReadinessProbeFunc(func(context.Context) error { return nil })); err == nil || next != (ControlHealthWriter{}) {
		t.Fatal("unknown write issued a token")
	}
}
