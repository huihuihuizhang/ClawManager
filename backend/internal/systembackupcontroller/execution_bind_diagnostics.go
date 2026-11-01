package systembackupcontroller

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/go-sql-driver/mysql"
)

// Detached diagnostic DATA. Fields are constructed only inside this package
// from source-code stage literals and fixed classifications, never SQL text,
// parameters, authority, grants or driver error messages.
type ExecutionBindDiagnostic struct {
	stage, class, state, reason string
	number                      uint16
}

func (v ExecutionBindDiagnostic) Stage() string     { return v.stage }
func (v ExecutionBindDiagnostic) Class() string     { return v.class }
func (v ExecutionBindDiagnostic) SQLState() string  { return v.state }
func (v ExecutionBindDiagnostic) SQLNumber() uint16 { return v.number }
func (v ExecutionBindDiagnostic) Reason() string    { return v.reason }

func executionBindDiagnostic(stage string, err error) ExecutionBindDiagnostic {
	v := ExecutionBindDiagnostic{stage: stage, class: "predicate"}
	if err == nil {
		return v
	}
	// A joined authority sentinel must not hide the structured driver cause.
	// Driver messages are never copied into the detached diagnostic.
	var driver *mysql.MySQLError
	if errors.As(err, &driver) {
		v.class, v.number = "sql_driver", driver.Number
		if driver.Number == 1213 {
			v.class = "sql_deadlock"
		} else if driver.Number == 1205 {
			v.class = "sql_lock_timeout"
		}
		valid := true
		for _, b := range driver.SQLState {
			if !(b >= '0' && b <= '9' || b >= 'A' && b <= 'Z') {
				valid = false
			}
		}
		if valid {
			v.state = string(driver.SQLState[:])
		}
		return v
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		v.class = "context_deadline"
	case errors.Is(err, context.Canceled):
		v.class = "context_canceled"
	case errors.Is(err, sql.ErrNoRows):
		v.class = "sql_no_rows"
	case errors.Is(err, sql.ErrTxDone):
		v.class = "sql_tx_done"
	case errors.Is(err, ErrExecutionAuthority):
		v.class = "authority_rejected"
	default:
		v.class = "unclassified"
	}
	return v
}

func reportExecutionBindDiagnostic(report func(ExecutionBindDiagnostic), stage string, err error) {
	if report != nil {
		report(executionBindDiagnostic(stage, err))
	}
}

func reportExecutionBindClockDiagnostic(report func(ExecutionBindDiagnostic), v executionSnapshot, deadline time.Time, err error) {
	if report == nil {
		return
	}
	diagnostic := executionBindDiagnostic("bind-snapshot-held-delivered-clock", err)
	if err != nil {
		diagnostic.reason = "sql_error"
	} else {
		switch {
		case v.now.IsZero():
			diagnostic.reason = "clock_missing"
		case !v.now.Before(v.claimUntil):
			diagnostic.reason = "claim_expired"
		case !v.now.Before(deadline):
			diagnostic.reason = "task_deadline"
		case !v.now.Before(v.gateUntil):
			diagnostic.reason = "gate_lease_expired"
		case !v.now.Before(v.holdUntil):
			diagnostic.reason = "hold_deadline_expired"
		}
	}
	report(diagnostic)
}
