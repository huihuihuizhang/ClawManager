package systembackupcontroller

import (
	"context"
	"time"

	d "clawreef/internal/systembackupdispatch"
)

// RenewExecutionLease renews ONLY the lifetime of the same execution epoch.
// Phase changes and new acquisitions still increment row_version. Keeping the
// epoch stable lets the frozen runner input survive heartbeats; the SQL guard
// locks the task during every effect and checks the original transaction expiry.
// An expired/stolen epoch cannot be renewed, even by the same logical owner.
func (s SQLExecutionWorkStore) RenewExecutionLease(ctx context.Context, a d.Authority) error {
	if s.Queue.Policy.Validate() != nil || s.Queue.DB == nil || a.InstallationID != s.Queue.InstallationID || a.ClaimOwner != s.Queue.Owner {
		return ErrClaimLost
	}
	r, err := s.Queue.DB.ExecContext(ctx, `UPDATE system_backup_v2_backups SET heartbeat_at=UTC_TIMESTAMP(6),controller_lease_expires_at=TIMESTAMPADD(MICROSECOND,?,UTC_TIMESTAMP(6)) WHERE origin_installation_id=? AND public_id=? AND controller_owner=? AND row_version=? AND controller_lease_expires_at>UTC_TIMESTAMP(6) AND status IN ('preparing','ready_for_capture','acquiring_gate','capturing','canceling')`, s.Queue.Policy.TTL.Microseconds(), a.InstallationID, a.TaskPublicID, a.ClaimOwner, a.ClaimRowVersion)
	if ok, e := exactlyOneRow(r); err != nil || e != nil || !ok {
		return ErrClaimLost
	}
	return nil
}

// RunWithExecutionHeartbeat joins the renewer before returning. Cancellation
// only interrupts cooperative execution; stop/resume remains the recovery path.
func (s SQLExecutionWorkStore) RunWithExecutionHeartbeat(ctx context.Context, a d.Authority, run func(context.Context) error) error {
	if run == nil || ctx == nil || s.Queue.Policy.Validate() != nil {
		return ErrClaimLost
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
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
				if err := s.RenewExecutionLease(child, a); err != nil {
					cancel()
					done <- err
					return
				}
			}
		}
	}()
	err := run(child)
	cancel()
	renewErr := <-done
	if err != nil {
		return err
	}
	return renewErr
}
