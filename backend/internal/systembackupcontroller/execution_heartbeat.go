package systembackupcontroller

import (
	"context"
	"database/sql"
	"errors"
	"time"

	d "clawreef/internal/systembackupdispatch"
)

// RenewExecutionLease renews ONLY the lifetime of the same execution epoch.
// Phase changes and new acquisitions still increment row_version. Keeping the
// epoch stable lets the frozen runner input survive heartbeats; the SQL guard
// locks the task during every effect and checks the original transaction expiry.
// An expired/stolen epoch cannot be renewed, even by the same logical owner.
func (s SQLExecutionWorkStore) RenewExecutionLease(ctx context.Context, a d.Authority) error {
	_, err := s.renewExecutionLease(ctx, a)
	return err
}

// interrupted identifies cancellation of the SQL call itself. A zero-row
// result or an independent database failure still means claim loss, even if
// shutdown cancels the context at the same time.
func (s SQLExecutionWorkStore) renewExecutionLease(ctx context.Context, a d.Authority) (interrupted bool, renewalErr error) {
	if s.Queue.Policy.Validate() != nil || s.Queue.DB == nil || a.InstallationID != s.Queue.InstallationID || a.ClaimOwner != s.Queue.Owner {
		return false, ErrClaimLost
	}
	interruptedCall := func(err error) (bool, error) {
		return errors.Is(err, context.Canceled) && errors.Is(ctx.Err(), context.Canceled), ErrClaimLost
	}
	tx, err := s.Queue.DB.BeginTx(ctx, nil)
	if err != nil {
		return interruptedCall(err)
	}
	defer tx.Rollback()
	// A statement-start UTC can precede a row-lock wait. First acquire this
	// exact original epoch, then sample SQL time AFTER its actual delivery.
	var originalUntil, statementAt, now time.Time
	var originalHeartbeat sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT controller_lease_expires_at,UTC_TIMESTAMP(6),heartbeat_at FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=? AND controller_owner=? AND row_version=? AND status IN ('preparing','ready_for_capture','acquiring_gate','capturing','canceling') FOR UPDATE`, a.InstallationID, a.TaskPublicID, a.ClaimOwner, a.ClaimRowVersion).Scan(&originalUntil, &statementAt, &originalHeartbeat)
	if err != nil {
		return interruptedCall(err)
	}
	if err = tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil {
		return interruptedCall(err)
	}
	if now.IsZero() || statementAt.IsZero() || now.Before(statementAt) || !now.Before(originalUntil) || (originalHeartbeat.Valid && now.Before(originalHeartbeat.Time)) {
		return false, ErrClaimLost
	}
	r, err := tx.ExecContext(ctx, `UPDATE system_backup_v2_backups SET heartbeat_at=UTC_TIMESTAMP(6),controller_lease_expires_at=GREATEST(controller_lease_expires_at,TIMESTAMPADD(MICROSECOND,?,UTC_TIMESTAMP(6))) WHERE origin_installation_id=? AND public_id=? AND controller_owner=? AND row_version=? AND controller_lease_expires_at=? AND controller_lease_expires_at>UTC_TIMESTAMP(6) AND status IN ('preparing','ready_for_capture','acquiring_gate','capturing','canceling')`, s.Queue.Policy.TTL.Microseconds(), a.InstallationID, a.TaskPublicID, a.ClaimOwner, a.ClaimRowVersion, originalUntil)
	if err != nil {
		return interruptedCall(err)
	}
	if ok, e := exactlyOneRow(r); e != nil || !ok {
		return false, ErrClaimLost
	}
	var heartbeatAt, renewedUntil, rowAt, deliveredAt time.Time
	err = tx.QueryRowContext(ctx, `SELECT heartbeat_at,controller_lease_expires_at,UTC_TIMESTAMP(6) FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=? AND controller_owner=? AND row_version=? AND status IN ('preparing','ready_for_capture','acquiring_gate','capturing','canceling') FOR UPDATE`, a.InstallationID, a.TaskPublicID, a.ClaimOwner, a.ClaimRowVersion).Scan(&heartbeatAt, &renewedUntil, &rowAt)
	if err != nil {
		return interruptedCall(err)
	}
	if err = tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&deliveredAt); err != nil {
		return interruptedCall(err)
	}
	wantUntil := heartbeatAt.Add(s.Queue.Policy.TTL)
	if originalUntil.After(wantUntil) {
		wantUntil = originalUntil
	}
	if heartbeatAt.IsZero() || rowAt.IsZero() || deliveredAt.IsZero() || heartbeatAt.Before(now) || (originalHeartbeat.Valid && heartbeatAt.Before(originalHeartbeat.Time)) || rowAt.Before(heartbeatAt) || deliveredAt.Before(rowAt) || !deliveredAt.Before(originalUntil) || !deliveredAt.Before(renewedUntil) || !renewedUntil.Equal(wantUntil) {
		return false, ErrClaimLost
	}
	if err = tx.Commit(); err != nil {
		return interruptedCall(err)
	}
	return false, nil
}

// RunWithExecutionHeartbeat joins the renewer before returning. Cancellation
// only interrupts cooperative execution; stop/resume remains the recovery path.
func (s SQLExecutionWorkStore) RunWithExecutionHeartbeat(ctx context.Context, a d.Authority, run func(context.Context) error) error {
	if run == nil || ctx == nil || s.Queue.Policy.Validate() != nil {
		return ErrClaimLost
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	live := newOriginalControllerRun(s, a, child)
	active := context.WithValue(child, originalControllerRunKey{}, live)
	defer live.close(cancel)
	done := make(chan error, 1)
	go func() {
		tick := time.NewTicker(s.Queue.Policy.HeartbeatInterval)
		defer tick.Stop()
		for {
			select {
			case <-child.Done():
				done <- nil
				return
			case <-tick.C:
				if interrupted, err := s.renewExecutionLease(child, a); err != nil {
					if interrupted {
						// The callback or parent stopped cooperative execution.
						// Joining its canceled SQL call is normal shutdown, not
						// evidence that the original owner/epoch was lost.
						done <- nil
						return
					}
					cancel()
					done <- err
					return
				}
			}
		}
	}()
	err := run(active)
	live.close(cancel)
	renewErr := <-done
	if err != nil {
		return err
	}
	return renewErr
}
