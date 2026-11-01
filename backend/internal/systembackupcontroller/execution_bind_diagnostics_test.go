package systembackupcontroller

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	dispatch "clawreef/internal/systembackupdispatch"
	"github.com/go-sql-driver/mysql"
)

type executionDiagnosticDriver struct {
	model   *executionModel
	prefix  string
	failure error
}
type executionDiagnosticConn struct {
	*executionConn
	prefix  string
	failure error
}

func (d executionDiagnosticDriver) Open(string) (driver.Conn, error) {
	return &executionDiagnosticConn{&executionConn{m: d.model}, d.prefix, d.failure}, nil
}
func (c *executionDiagnosticConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if c.prefix != "" && strings.HasPrefix(query, c.prefix) {
		return nil, c.failure
	}
	return c.executionConn.QueryContext(ctx, query, args)
}

func TestExecutionBindDiagnosticsPreserveErrorsAndPrivateInputs(t *testing.T) {
	for _, mode := range []string{"healthy", "dependencies", "gate-deadlock", "task-lock-timeout", "no-rows", "task-predicate", "authorization", "owner-until"} {
		t.Run(mode, func(t *testing.T) {
			store, model := newExecutionModel(t)
			secret := "PRIVATE_SQL_AUTHORITY_TOKEN_BODY_MUST_NOT_APPEAR"
			prefix, wantStage, wantClass := "", "", ""
			var failure error
			switch mode {
			case "dependencies":
				store.DeploymentEnabled = false
				wantStage, wantClass = "bind-dependencies", "predicate"
			case "gate-deadlock":
				prefix = "SELECT gate_state"
				failure = &mysql.MySQLError{Number: 1213, SQLState: [5]byte{'4', '0', '0', '0', '1'}, Message: secret}
				wantStage, wantClass = "bind-snapshot-maintenance-gate", "sql_deadlock"
			case "task-lock-timeout":
				prefix = "SELECT schema_version,origin_installation_id"
				failure = &mysql.MySQLError{Number: 1205, SQLState: [5]byte{'H', 'Y', '0', '0', '0'}, Message: secret}
				wantStage, wantClass = "bind-snapshot-task", "sql_lock_timeout"
			case "no-rows":
				prefix = "SELECT gate_state"
				failure = sql.ErrNoRows
				wantStage, wantClass = "bind-snapshot-maintenance-gate", "sql_no_rows"
			case "task-predicate":
				model.drift = "owner"
				wantStage, wantClass = "bind-snapshot-task", "predicate"
			case "authorization":
				store.Authorization.(*executionAuth).deny = true
				wantStage, wantClass = "bind-authorization", "authority_rejected"
			case "owner-until":
				store.Authorization.(*executionAuth).until = model.now
				wantStage, wantClass = "bind-owner-until", "predicate"
			}
			name := fmt.Sprintf("execution-diagnostic-%d", executionModelCounter.Add(1))
			sql.Register(name, executionDiagnosticDriver{model, prefix, failure})
			db, err := sql.Open(name, "")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			store.DB = db
			ctx := context.Background()
			tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			var observed []ExecutionBindDiagnostic
			guard, err := store.BindObserved(ctx, tx, model.a, func(v ExecutionBindDiagnostic) { observed = append(observed, v) })
			if mode == "healthy" {
				if err != nil || guard == nil || len(observed) != 0 {
					t.Fatal("healthy bind changed", err, observed)
				}
				return
			}
			if err != ErrExecutionAuthority || guard != nil || len(observed) != 1 || observed[0].Stage() != wantStage || observed[0].Class() != wantClass {
				t.Fatal("diagnostic altered failure or boundary", err, observed)
			}
			if strings.Contains(fmt.Sprintf("%+v", observed), secret) {
				t.Fatal("driver message exposed")
			}
			if mode == "gate-deadlock" && (observed[0].SQLNumber() != 1213 || observed[0].SQLState() != "40001") {
				t.Fatal("deadlock code lost")
			}
		})
	}
}

func TestExecutionBindDiagnosticClassifiesOnlyFixedSafeErrorData(t *testing.T) {
	secret := "PRIVATE_ERROR_BODY_MUST_NOT_APPEAR"
	for _, err := range []error{context.Canceled, context.DeadlineExceeded, sql.ErrTxDone, errors.New(secret), fmt.Errorf("%s: %w", secret, &mysql.MySQLError{Number: 1213, SQLState: [5]byte{'\n', '?', 'x', 0, '\r'}, Message: secret})} {
		v := executionBindDiagnostic("bind-snapshot-task", err)
		if strings.Contains(fmt.Sprintf("%+v", v), secret) || strings.ContainsAny(v.SQLState(), "\x00\r\n?") {
			t.Fatal("unsafe diagnostic output", v)
		}
	}
}

func TestExecutionBindDiagnosticsPreferJoinedDriverCauseAndContext(t *testing.T) {
	secret := "PRIVATE_SQL_ARGS_BODY_GRANT_TOKEN_MUST_NOT_APPEAR"
	for _, number := range []uint16{1213, 1205} {
		driver := &mysql.MySQLError{Number: number, SQLState: [5]byte{'4', '0', '0', '0', '1'}, Message: secret}
		for _, err := range []error{fmt.Errorf("%s: %w", secret, driver), errors.Join(ErrExecutionAuthority, driver), fmt.Errorf("%s: %w", secret, errors.Join(ErrExecutionAuthority, driver))} {
			v := executionBindDiagnostic("bind-snapshot-task", err)
			if v.SQLNumber() != number || v.SQLState() != "40001" || number == 1213 && v.Class() != "sql_deadlock" || number == 1205 && v.Class() != "sql_lock_timeout" || strings.Contains(fmt.Sprintf("%+v", v), secret) {
				t.Fatal("joined driver classification or privacy lost", v)
			}
		}
	}
	for _, expired := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		want := "context_canceled"
		if expired {
			ctx, cancel = context.WithDeadline(context.Background(), time.Unix(1, 0))
			want = "context_deadline"
		} else {
			cancel()
		}
		var observed []ExecutionBindDiagnostic
		guard, err := (SQLExecutionAuthority{}).BindObserved(ctx, nil, dispatch.Authority{}, func(v ExecutionBindDiagnostic) { observed = append(observed, v) })
		cancel()
		if guard != nil || err != ErrExecutionAuthority || len(observed) != 1 || observed[0].Stage() != "bind-dependencies" || observed[0].Class() != want {
			t.Fatal("context diagnostic changed original rejection", err, observed)
		}
	}
}
