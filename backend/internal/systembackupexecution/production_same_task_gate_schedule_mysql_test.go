package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	"github.com/go-sql-driver/mysql"
)

// Transparent REAL connector: the optional local test barrier neither rewrites
// SQL/arguments nor substitutes its result. Normal fixture uses no wrapper.
type dOriginalGateQueryConnector struct {
	driver.Connector
	before func(context.Context, string) error
	after  func(string, error)
}
type dOriginalGateQueryConn struct {
	driver.Conn
	before func(context.Context, string) error
	after  func(string, error)
}

func (v dOriginalGateQueryConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := v.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &dOriginalGateQueryConn{conn, v.before, v.after}, nil
}
func (v *dOriginalGateQueryConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if v.before != nil {
		if err := v.before(ctx, q); err != nil {
			return nil, err
		}
	}
	rows, err := v.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
	if v.after != nil {
		v.after(q, err)
	}
	return rows, err
}
func (v *dOriginalGateQueryConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	return v.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
}
func (v *dOriginalGateQueryConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return v.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
}
func (v *dOriginalGateQueryConn) CheckNamedValue(value *driver.NamedValue) error {
	if checker, ok := v.Conn.(driver.NamedValueChecker); ok {
		return checker.CheckNamedValue(value)
	}
	return driver.ErrSkip
}
func (v *dOriginalGateQueryConn) ResetSession(ctx context.Context) error {
	if reset, ok := v.Conn.(driver.SessionResetter); ok {
		return reset.ResetSession(ctx)
	}
	return nil
}
func (v *dOriginalGateQueryConn) IsValid() bool {
	if validator, ok := v.Conn.(driver.Validator); ok {
		return validator.IsValid()
	}
	return true
}
func (v *dOriginalGateQueryConn) Ping(ctx context.Context) error {
	if ping, ok := v.Conn.(driver.Pinger); ok {
		return ping.Ping(ctx)
	}
	return nil
}

// A controlled in-flight-request DATA transaction, not an actual HTTP request
// authorization or the retrospective holder of a terminated earlier task.
// PFS is queried only through f.db's existing local administrator connection;
// the production controller account is never given PROCESS/PFS privileges.
type dOriginalInflightGateData struct {
	tx                *sql.Tx
	connection        uint64
	transaction, mode string
}

func holdDOriginalInflightGateData(ctx context.Context, f *dOriginalSixPartTask) (dOriginalInflightGateData, error) {
	var data dOriginalInflightGateData
	tx, err := f.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return data, err
	}
	data.tx = tx
	var phase string
	if tx.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&data.connection) != nil || tx.QueryRowContext(ctx, "SELECT phase FROM system_backup_gate WHERE scope=? FOR SHARE", f.service.Config.ApplicationScope).Scan(&phase) != nil || phase != "idle" {
		tx.Rollback()
		return data, errors.New("controlled in-flight DATA gate share lock unavailable")
	}
	err = f.db.QueryRowContext(ctx, `SELECT l.ENGINE_TRANSACTION_ID,l.LOCK_MODE FROM performance_schema.data_locks l JOIN performance_schema.threads t ON t.THREAD_ID=l.THREAD_ID WHERE l.OBJECT_SCHEMA=? AND l.OBJECT_NAME='system_backup_gate' AND l.LOCK_TYPE='RECORD' AND l.LOCK_STATUS='GRANTED' AND l.LOCK_MODE LIKE 'S%' AND t.PROCESSLIST_ID=? LIMIT 1`, f.database, data.connection).Scan(&data.transaction, &data.mode)
	if err != nil {
		tx.Rollback()
		return data, errors.New("local admin PFS did not witness actual DATA holder")
	}
	return data, nil
}

type dOriginalGateScheduleSnapshot struct {
	status, category, owner, phase, admissionOwner, planSHA, configSHA string
	row, generation, epochs, jobs, tasks, attempts                     uint64
	started, lease, admissionUntil                                     sql.NullTime
	now                                                                time.Time
}

func readDOriginalGateScheduleSnapshot(ctx context.Context, f *dOriginalSixPartTask) (dOriginalGateScheduleSnapshot, error) {
	var v dOriginalGateScheduleSnapshot
	err := f.db.QueryRowContext(ctx, `SELECT b.status,b.failure_category,COALESCE(b.controller_owner,''),b.row_version,b.source_gate_wait_started_at,b.controller_lease_expires_at,b.config_snapshot_sha256,g.phase,g.generation,COALESCE(a.owner,''),a.close_until,r.payload_sha256,UTC_TIMESTAMP(6),
(SELECT COUNT(*) FROM system_backup_v2_runtime_captures WHERE task_public_id=b.public_id),
(SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE task_public_id=b.public_id AND resource_kind='Job'),
(SELECT COUNT(*) FROM system_backup_v2_backups),
(SELECT COUNT(*) FROM system_backup_v2_attempts WHERE target_type='backup' AND target_public_id=b.public_id AND attempt_no=1)
FROM system_backup_v2_backups b JOIN system_backup_gate g ON g.scope=? JOIN system_backup_gate_admissions a ON a.scope=g.scope JOIN system_backup_v2_execution_records r ON r.task_public_id=b.public_id AND r.record_kind='plan' AND r.phase='capture' AND r.attempt_no=1 WHERE b.public_id=?`, f.service.Config.ApplicationScope, f.publicID).Scan(&v.status, &v.category, &v.owner, &v.row, &v.started, &v.lease, &v.configSHA, &v.phase, &v.generation, &v.admissionOwner, &v.admissionUntil, &v.planSHA, &v.now, &v.epochs, &v.jobs, &v.tasks, &v.attempts)
	return v, err
}

// Fixture work selection follows the actual production outer scheduler. It
// neither renews a claim nor changes retry policy, SQL clocks or source budget.
// Cancel only this selection loop when real Store.Next returns work; the
// original task context remains the capture context.
func nextDOriginalWorkUsingDeploymentScheduler(ctx context.Context, f *dOriginalSixPartTask) (*c.ExecutionWork, error) {
	selection, stop := context.WithCancel(ctx)
	defer stop()
	var work *c.ExecutionWork
	var observationErr error
	err := runDeploymentPasses(selection, func(active context.Context) error {
		var nextErr error
		work, nextErr = f.service.Runtime.Loop.Store.Next(active)
		if work == nil && active.Err() == nil {
			// Observation only: a terminal task cannot produce more capture
			// work. Do not wait until its parent/test timeout or reset it.
			observationErr = readDOriginalSelectionTerminal(active, f.db, f.publicID)
			if observationErr != nil {
				stop()
			}
		}
		return nextErr
	}, f.queue.Policy.ReconcileInterval, func(error) {
		if work != nil {
			stop()
		}
	})
	if observationErr != nil {
		return nil, observationErr
	}
	if work != nil && errors.Is(err, context.Canceled) && ctx.Err() == nil {
		return work, nil
	}
	return nil, err
}

var errDOriginalSelectionTerminal = errors.New("original task terminal before collector work")

// Original SQL state DATA only. A nil result never authorizes work: the
// actual Store.Next must still supply its original fully bound work object.
func readDOriginalSelectionTerminal(ctx context.Context, db *sql.DB, task string) error {
	if ctx == nil || db == nil || task == "" {
		return errors.New("original selection observation unavailable")
	}
	var status, category string
	if err := db.QueryRowContext(ctx, "SELECT status,failure_category FROM system_backup_v2_backups WHERE public_id=?", task).Scan(&status, &category); err != nil {
		return fmt.Errorf("original selection state unavailable: %w", err)
	}
	switch status {
	case "failed", "canceled", "succeeded":
		return fmt.Errorf("%w: status=%s category=%s", errDOriginalSelectionTerminal, status, category)
	case "pending", "preparing", "ready_for_capture", "acquiring_gate", "capturing", "validating", "publishing", "finalization_unknown", "canceling":
		return nil
	default:
		return errors.New("original selection task state unrecognized")
	}
}

func TestOriginalTaskGateNOWAITUsesExistingDeploymentSchedulingMySQL(t *testing.T) {
	for _, release := range []bool{true, false} {
		name := "hold-to-original-budget"
		if release {
			name = "release-after-first-real-NOWAIT"
		}
		t.Run(name, func(t *testing.T) {
			var fixture *dOriginalSixPartTask
			var armed, fired atomic.Bool
			var actualNOWAIT atomic.Uint64
			var actualHolderObserved atomic.Bool
			var holder dOriginalInflightGateData
			options := dOriginalSixPartFixtureOptions{}
			options.ControlAfterQuery = func(q string, err error) {
				if strings.HasPrefix(q, "SELECT phase,generation,fencing_token FROM system_backup_gate") && strings.HasSuffix(q, "FOR UPDATE NOWAIT") {
					var rejection *mysql.MySQLError
					if errors.As(err, &rejection) && rejection.Number == 3572 && string(rejection.SQLState[:]) == "HY000" {
						actualNOWAIT.Add(1)
						for _, value := range logDOriginalGateLocks(t, fixture) {
							if value.Connection == holder.connection && value.Table == "system_backup_gate" && strings.HasPrefix(value.Mode, "S") && value.Status == "GRANTED" {
								actualHolderObserved.Store(true)
							}
						}
					}
				}
			}
			options.ControlBeforeQuery = func(ctx context.Context, q string) error {
				if !armed.Load() || !strings.HasPrefix(q, "SELECT phase,generation,fencing_token FROM system_backup_gate") || !strings.HasSuffix(q, "FOR UPDATE NOWAIT") || !fired.CompareAndSwap(false, true) {
					return nil
				}
				var err error
				holder, err = holdDOriginalInflightGateData(ctx, fixture)
				return err
			}
			options.AfterOriginalPrepare = func(parent context.Context, t *testing.T, f *dOriginalSixPartTask, plan d.Plan) error {
				fixture = f
				ctx, cancel := context.WithTimeout(parent, 130*time.Second)
				defer cancel()
				defer func() {
					if holder.tx != nil {
						holder.tx.Rollback()
					}
				}()
				armed.Store(true)
				var work *c.ExecutionWork
				var first dOriginalGateScheduleSnapshot
				var invariant error
				busy := 0
				loopErr := runDeploymentPasses(ctx, func(active context.Context) error {
					var err error
					work, err = f.service.Runtime.Loop.Store.Next(active)
					return err
				}, f.queue.Policy.ReconcileInterval, func(passErr error) {
					v, err := readDOriginalGateScheduleSnapshot(parent, f)
					fail := func(message string) {
						if invariant == nil {
							invariant = errors.New(message)
						}
						cancel()
					}
					if err != nil {
						fail("original scheduled state unavailable")
						return
					}
					if v.planSHA != plan.SHA256 || v.configSHA != f.input.Authority.ConfigSHA256 || v.tasks != 1 || v.attempts != 2 || v.jobs != 0 {
						fail("existing scheduler changed original task/plan/config/attempt or sent a collector")
						return
					}
					if fired.Load() && passErr != nil {
						if closedExecutionCode(passErr) != "unavailable" || actualNOWAIT.Load() == 0 {
							fail("controlled gate yielded an unrelated scheduling error")
							return
						}
						if !actualHolderObserved.Load() {
							fail("actual refusal PFS sample did not identify the controlled real holder")
							return
						}
						busy++
						if busy == 1 {
							if !v.started.Valid || !v.admissionUntil.Valid || v.admissionOwner != f.publicID || v.phase != "idle" || v.generation != 0 || v.epochs != 0 {
								fail("NOWAIT did not retain original pending acquisition")
								return
							}
							first = v
							t.Log("PFS controlled in-flight-request DATA holder connection/transaction/mode", holder.connection, holder.transaction, holder.mode, "actual NOWAIT3572; existing deployment scheduler retains task")
							if release {
								if holder.tx.Rollback() != nil {
									fail("controlled DATA holder release failed")
									return
								}
								holder.tx = nil
							}
						}
					}
					if busy > 0 {
						if !v.started.Valid || !v.started.Time.Equal(first.started.Time) {
							fail("source gate wait timestamp refreshed")
							return
						}
						if first.lease.Valid && v.now.Before(first.lease.Time) && v.row != first.row {
							fail("scheduler adopted a still-live claim")
							return
						}
						if v.status != "failed" && (!v.admissionUntil.Valid || !v.admissionUntil.Time.Equal(first.admissionUntil.Time)) {
							fail("original admission deadline extended")
							return
						}
					}
					if work != nil {
						if !release || busy == 0 || work.Step != c.ExecutionCapture || work.Input.Authority.TaskPublicID != f.publicID || work.Input.Authority.AttemptNo != 1 || work.Plan.SHA256 != plan.SHA256 || !bytes.Equal(work.Plan.CanonicalJSON, plan.CanonicalJSON) || v.epochs != 1 || v.generation != 1 || v.status != "capturing" {
							fail("existing scheduling did not return the same original first capture epoch")
							return
						}
						cancel()
						return
					}
					if v.status == "failed" {
						if release || busy == 0 || v.category != "quiesce_timeout" || v.epochs != 0 || v.generation != 0 || v.admissionOwner != "" {
							fail("held source budget did not settle untouched without epoch")
							return
						}
						cancel()
					}
				})
				if invariant != nil {
					return invariant
				}
				if !errors.Is(loopErr, context.Canceled) || busy == 0 || release && work == nil || !release && work != nil {
					return fmt.Errorf("existing bounded deployment scheduling counter did not finish: busy=%d", busy)
				}
				if !release {
					// This task REALLY failed through the original source budget
					// above, never through a test UPDATE. Reenter only selection:
					// it must surface that terminal instead of waiting for work.
					before, err := readDOriginalGateScheduleSnapshot(parent, f)
					if err != nil {
						return err
					}
					observe, finish := context.WithTimeout(parent, 3*time.Second)
					started := time.Now()
					again, terminalErr := nextDOriginalWorkUsingDeploymentScheduler(observe, f)
					finish()
					if again != nil || !errors.Is(terminalErr, errDOriginalSelectionTerminal) || time.Since(started) >= 3*time.Second {
						return fmt.Errorf("actual failed original task did not end fixture selection: %w", terminalErr)
					}
					after, err := readDOriginalGateScheduleSnapshot(parent, f)
					if err != nil {
						return err
					}
					if after.row != before.row || after.status != before.status || after.category != before.category || after.jobs != before.jobs || after.epochs != before.epochs || after.planSHA != before.planSHA || after.configSHA != before.configSHA {
						return errors.New("terminal observation changed original task or dispatched work")
					}
					t.Log("actual quiesce-timeout terminal surfaced without new work/token/epoch; fixture selection elapsed", time.Since(started))
				}
				f.provider.mu.Lock()
				generated := f.provider.generateCalls
				f.provider.mu.Unlock()
				if generated != 0 {
					return errors.New("pre-collector counter issued a provider key")
				}
				t.Log("same original task/plan/config/first wait/admission deadline; existing interval and30/5 claim policy unchanged; no collector/key/capture receipt; release", release)
				return nil
			}
			runDOriginalSixPartCaptureWithOptions(t, false, false, options, nil)
		})
	}
}
