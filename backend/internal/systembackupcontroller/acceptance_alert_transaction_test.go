package systembackupcontroller

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

type acceptanceTransactionTestState struct {
	now          time.Time
	terminalRows int64
	sequenceRows int64
	preStatus    string
	preVersion   uint64
	postStatus   string
	postPurpose  string
	postConfig   uint64
	postVersion  uint64
	postEligible bool
	postDecided  bool
	eventZero    bool
	eventErr     error
	order        []string
	updateArgs   []driver.NamedValue
	taskArgs     [][]driver.NamedValue
	eventArgs    []driver.NamedValue
}

type acceptanceTransactionConnector struct {
	state *acceptanceTransactionTestState
}

func (c acceptanceTransactionConnector) Connect(context.Context) (driver.Conn, error) {
	return acceptanceTransactionConn{state: c.state}, nil
}
func (acceptanceTransactionConnector) Driver() driver.Driver { return acceptanceTransactionDriver{} }

type acceptanceTransactionDriver struct{}

func (acceptanceTransactionDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("use connector")
}

type acceptanceTransactionConn struct {
	state *acceptanceTransactionTestState
}

func (acceptanceTransactionConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (acceptanceTransactionConn) Close() error { return nil }
func (acceptanceTransactionConn) Begin() (driver.Tx, error) {
	return nil, errors.New("unexpected unbounded begin")
}
func (c acceptanceTransactionConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	c.state.order = append(c.state.order, "begin")
	return acceptanceTransactionTx{state: c.state}, nil
}
func (c acceptanceTransactionConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	switch {
	case strings.HasPrefix(query, "UPDATE system_backups SET status = 'failed'") || strings.HasPrefix(query, "UPDATE system_backups SET status = 'succeeded'"):
		c.state.order = append(c.state.order, "task-cas")
		return driver.RowsAffected(c.state.terminalRows), nil
	case strings.HasPrefix(query, "INSERT INTO system_backup_events"):
		c.state.order = append(c.state.order, "event")
		c.state.eventArgs = append([]driver.NamedValue(nil), args...)
		if c.state.eventErr != nil {
			return nil, c.state.eventErr
		}
		if c.state.eventZero {
			return driver.RowsAffected(0), nil
		}
		return driver.RowsAffected(1), nil
	case strings.HasPrefix(query, "INSERT INTO system_backup_alert_states"):
		c.state.order = append(c.state.order, "ensure-state")
		return driver.RowsAffected(1), nil
	case strings.HasPrefix(query, "UPDATE system_backup_alert_states"):
		c.state.order = append(c.state.order, "sequence-cas")
		c.state.updateArgs = append([]driver.NamedValue(nil), args...)
		return driver.RowsAffected(c.state.sequenceRows), nil
	default:
		return nil, errors.New("unexpected acceptance transaction SQL")
	}
}
func (c acceptanceTransactionConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	switch {
	case strings.HasPrefix(query, "SELECT status, row_version FROM system_backups"):
		c.state.order = append(c.state.order, "lock-task")
		c.state.taskArgs = append(c.state.taskArgs, append([]driver.NamedValue(nil), args...))
		status, version := c.state.preStatus, c.state.preVersion
		if status == "" {
			status = "pending"
		}
		if version == 0 {
			version = 4
		}
		return &acceptanceTransactionRows{columns: []string{"status", "row_version"}, values: [][]driver.Value{{status, int64(version)}}}, nil
	case strings.HasPrefix(query, "SELECT status, task_purpose, config_version, acceptance_eligible, eligibility_decided_at, row_version FROM system_backups"):
		c.state.order = append(c.state.order, "verify-task")
		c.state.taskArgs = append(c.state.taskArgs, append([]driver.NamedValue(nil), args...))
		status, purpose, config, version := c.state.postStatus, c.state.postPurpose, c.state.postConfig, c.state.postVersion
		if status == "" {
			status = "failed"
		}
		if purpose == "" {
			purpose = "acceptance"
		}
		if config == 0 {
			config = 7
		}
		if version == 0 {
			version = 5
		}
		var decidedAt driver.Value
		if c.state.postDecided {
			decidedAt = c.state.now
		}
		return &acceptanceTransactionRows{columns: []string{"status", "task_purpose", "config_version", "acceptance_eligible", "eligibility_decided_at", "row_version"}, values: [][]driver.Value{{status, purpose, int64(config), c.state.postEligible, decidedAt, int64(version)}}}, nil
	case strings.Contains(query, "FROM system_backup_alert_states"):
		c.state.order = append(c.state.order, "lock-state")
		return &acceptanceTransactionRows{
			columns: []string{"id", "consecutive_anomaly_count", "first_anomaly_at", "last_observed_at", "last_eligible_success_at", "row_version"},
			values:  [][]driver.Value{{int64(5), int64(0), nil, nil, nil, int64(1)}},
		}, nil
	case query == "SELECT UTC_TIMESTAMP(6)":
		c.state.order = append(c.state.order, "db-clock")
		return &acceptanceTransactionRows{columns: []string{"utc_now"}, values: [][]driver.Value{{c.state.now}}}, nil
	default:
		return nil, errors.New("unexpected acceptance transaction query")
	}
}

type acceptanceTransactionTx struct {
	state *acceptanceTransactionTestState
}

func (t acceptanceTransactionTx) Commit() error {
	t.state.order = append(t.state.order, "commit")
	return nil
}
func (t acceptanceTransactionTx) Rollback() error {
	t.state.order = append(t.state.order, "rollback")
	return nil
}

type acceptanceTransactionRows struct {
	columns []string
	values  [][]driver.Value
	index   int
}

func (r *acceptanceTransactionRows) Columns() []string { return r.columns }
func (r *acceptanceTransactionRows) Close() error      { return nil }
func (r *acceptanceTransactionRows) Next(dest []driver.Value) error {
	if r.index >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.index])
	r.index++
	return nil
}

func acceptanceTaskCASTest(ctx context.Context, executor Executor) (sql.Result, error) {
	return executor.ExecContext(ctx, "UPDATE system_backups SET status = 'failed', row_version = row_version + 1 WHERE origin_installation_id = ? AND public_id = ? AND row_version = ? AND status = 'pending'", "installation_test", "sbk_11111111-1111-4111-8111-111111111111", uint64(4))
}

func acceptanceSuccessCASTest(ctx context.Context, executor Executor) (sql.Result, error) {
	return executor.ExecContext(ctx, "UPDATE system_backups SET status = 'succeeded', acceptance_eligible = TRUE, eligibility_reason_codes = 'eligible', eligibility_decided_at = UTC_TIMESTAMP(6), row_version = row_version + 1 WHERE origin_installation_id = ? AND public_id = ? AND row_version = ? AND status = 'validating'", "installation_test", "sbk_11111111-1111-4111-8111-111111111111", uint64(4))
}

func acceptanceTarget() Target {
	return Target{Kind: TargetBackup, PublicID: "sbk_11111111-1111-4111-8111-111111111111"}
}

func TestAcceptanceTerminalSequenceCommitsOnlyAfterOneRowTaskCAS(t *testing.T) {
	now := time.Unix(2_000_000_000, 123456000).UTC()
	state := &acceptanceTransactionTestState{now: now, terminalRows: 1, sequenceRows: 1}
	db := sql.OpenDB(acceptanceTransactionConnector{state: state})
	defer db.Close()
	err := ApplyAcceptanceTerminalWithSequence(context.Background(), db, "installation_test", 7, acceptanceTarget(), 4,
		AcceptanceTerminalOutcome{TaskType: TargetBackup, Purpose: "acceptance", Status: "failed"}, acceptanceTaskCASTest)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"begin", "lock-task", "task-cas", "verify-task", "event", "ensure-state", "lock-state", "db-clock", "sequence-cas", "commit"}
	if !reflect.DeepEqual(state.order, want) {
		t.Fatalf("transaction order = %#v, want %#v", state.order, want)
	}
	if len(state.updateArgs) != 8 || state.updateArgs[0].Value != int64(1) || state.updateArgs[4].Value != int64(7) || state.updateArgs[5].Value != int64(5) {
		t.Fatalf("unexpected acceptance sequence update arguments: %#v", state.updateArgs)
	}
	if len(state.taskArgs) != 2 || len(state.taskArgs[0]) != 2 || state.taskArgs[0][0].Value != "installation_test" || state.taskArgs[0][1].Value != acceptanceTarget().PublicID {
		t.Fatalf("terminal task read escaped installation: %#v", state.taskArgs)
	}
	if len(state.eventArgs) != 6 || state.eventArgs[0].Value != string(TargetBackup) || state.eventArgs[1].Value != "pending" || state.eventArgs[2].Value != "installation_test" || state.eventArgs[3].Value != acceptanceTarget().PublicID || state.eventArgs[4].Value != int64(5) || state.eventArgs[5].Value != "failed" {
		t.Fatalf("terminal event identity arguments = %#v", state.eventArgs)
	}
}

func TestAcceptanceTerminalSequenceRollsBackLostTaskOrSequenceCAS(t *testing.T) {
	for _, test := range []struct {
		name         string
		terminalRows int64
		sequenceRows int64
		want         []string
	}{
		{name: "lost terminal CAS", terminalRows: 0, sequenceRows: 1, want: []string{"begin", "lock-task", "task-cas", "rollback"}},
		{name: "lost sequence CAS", terminalRows: 1, sequenceRows: 0, want: []string{"begin", "lock-task", "task-cas", "verify-task", "event", "ensure-state", "lock-state", "db-clock", "sequence-cas", "rollback"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := &acceptanceTransactionTestState{now: time.Unix(2_000_000_000, 0).UTC(), terminalRows: test.terminalRows, sequenceRows: test.sequenceRows}
			db := sql.OpenDB(acceptanceTransactionConnector{state: state})
			defer db.Close()
			err := ApplyAcceptanceTerminalWithSequence(context.Background(), db, "installation_test", 7, acceptanceTarget(), 4,
				AcceptanceTerminalOutcome{TaskType: TargetBackup, Purpose: "acceptance", Status: "failed"}, acceptanceTaskCASTest)
			if err == nil || !reflect.DeepEqual(state.order, test.want) {
				t.Fatalf("unsafe terminal transaction: err=%v order=%#v", err, state.order)
			}
		})
	}
}

func TestAcceptanceTerminalEligibleSuccessRequiresRecordedDecision(t *testing.T) {
	state := &acceptanceTransactionTestState{
		now: time.Unix(2_000_000_000, 0).UTC(), terminalRows: 1, sequenceRows: 1,
		preStatus: "validating", postStatus: "succeeded", postEligible: true, postDecided: true,
	}
	db := sql.OpenDB(acceptanceTransactionConnector{state: state})
	defer db.Close()
	err := ApplyAcceptanceTerminalWithSequence(context.Background(), db, "installation_test", 7, acceptanceTarget(), 4,
		AcceptanceTerminalOutcome{TaskType: TargetBackup, Purpose: "acceptance", Status: "succeeded", EligibilityDecided: true, Eligible: true}, acceptanceSuccessCASTest)
	if err != nil {
		t.Fatal(err)
	}
	if state.order[len(state.order)-1] != "commit" || !strings.Contains(strings.Join(state.order, ","), "sequence-cas") {
		t.Fatalf("eligible success did not reset sequence transactionally: %#v", state.order)
	}
}

func TestAcceptanceTerminalSequenceSkipsNonSequenceOutcomes(t *testing.T) {
	state := &acceptanceTransactionTestState{terminalRows: 1, postPurpose: "functional_test"}
	db := sql.OpenDB(acceptanceTransactionConnector{state: state})
	defer db.Close()
	err := ApplyAcceptanceTerminalWithSequence(context.Background(), db, "installation_test", 7, acceptanceTarget(), 4,
		AcceptanceTerminalOutcome{TaskType: TargetBackup, Purpose: "functional_test", Status: "failed"}, acceptanceTaskCASTest)
	if err != nil || !reflect.DeepEqual(state.order, []string{"begin", "lock-task", "task-cas", "verify-task", "event", "commit"}) {
		t.Fatalf("functional test changed acceptance sequence: err=%v order=%#v", err, state.order)
	}
}

func TestAcceptanceTerminalEventFailureRollsBackTaskAndSequence(t *testing.T) {
	for _, test := range []struct {
		name      string
		eventZero bool
		eventErr  error
	}{
		{name: "missing event row", eventZero: true},
		{name: "event insert error", eventErr: errors.New("event unavailable")},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := &acceptanceTransactionTestState{terminalRows: 1, sequenceRows: 1, eventZero: test.eventZero, eventErr: test.eventErr}
			db := sql.OpenDB(acceptanceTransactionConnector{state: state})
			defer db.Close()
			err := ApplyAcceptanceTerminalWithSequence(context.Background(), db, "installation_test", 7, acceptanceTarget(), 4,
				AcceptanceTerminalOutcome{TaskType: TargetBackup, Purpose: "acceptance", Status: "failed"}, acceptanceTaskCASTest)
			if err == nil || !reflect.DeepEqual(state.order, []string{"begin", "lock-task", "task-cas", "verify-task", "event", "rollback"}) {
				t.Fatalf("event failure committed terminal sequence: err=%v order=%#v", err, state.order)
			}
		})
	}
}

func TestAcceptanceTerminalSequenceRejectsWrongTaskFactsBeforeSequenceWrite(t *testing.T) {
	for _, test := range []struct {
		name    string
		state   acceptanceTransactionTestState
		wantCAS bool
	}{
		{name: "already terminal", state: acceptanceTransactionTestState{preStatus: "failed"}},
		{name: "stale version", state: acceptanceTransactionTestState{preVersion: 9}},
		{name: "wrong status", state: acceptanceTransactionTestState{postStatus: "pending"}, wantCAS: true},
		{name: "wrong purpose", state: acceptanceTransactionTestState{postPurpose: "functional_test"}, wantCAS: true},
		{name: "wrong config", state: acceptanceTransactionTestState{postConfig: 8}, wantCAS: true},
		{name: "wrong version", state: acceptanceTransactionTestState{postVersion: 6}, wantCAS: true},
		{name: "wrong eligibility", state: acceptanceTransactionTestState{postEligible: true}, wantCAS: true},
		{name: "wrong decision state", state: acceptanceTransactionTestState{postDecided: true}, wantCAS: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := &test.state
			state.terminalRows = 1
			state.sequenceRows = 1
			state.now = time.Unix(2_000_000_000, 0).UTC()
			db := sql.OpenDB(acceptanceTransactionConnector{state: state})
			defer db.Close()
			err := ApplyAcceptanceTerminalWithSequence(context.Background(), db, "installation_test", 7, acceptanceTarget(), 4,
				AcceptanceTerminalOutcome{TaskType: TargetBackup, Purpose: "acceptance", Status: "failed"}, acceptanceTaskCASTest)
			if !errors.Is(err, ErrAcceptanceTerminalCASRejected) {
				t.Fatalf("mismatched task fact error = %v", err)
			}
			if state.order[len(state.order)-1] != "rollback" || strings.Contains(strings.Join(state.order, ","), "ensure-state") {
				t.Fatalf("mismatched task reached sequence or commit: %#v", state.order)
			}
			gotCAS := strings.Contains(strings.Join(state.order, ","), "task-cas")
			if gotCAS != test.wantCAS {
				t.Fatalf("CAS occurrence=%t, want %t: %#v", gotCAS, test.wantCAS, state.order)
			}
		})
	}
}

func TestAcceptanceTerminalSequenceRejectsInvalidTargetBeforeTransaction(t *testing.T) {
	state := &acceptanceTransactionTestState{}
	db := sql.OpenDB(acceptanceTransactionConnector{state: state})
	defer db.Close()
	if err := ApplyAcceptanceTerminalWithSequence(context.Background(), db, "installation_test", 7,
		Target{Kind: TargetDrill, PublicID: "sdr_11111111-1111-4111-8111-111111111111"}, 4,
		AcceptanceTerminalOutcome{TaskType: TargetBackup, Purpose: "acceptance", Status: "failed"}, acceptanceTaskCASTest); err == nil {
		t.Fatal("mismatched target accepted")
	}
	if len(state.order) != 0 {
		t.Fatalf("invalid target began transaction: %#v", state.order)
	}
}
