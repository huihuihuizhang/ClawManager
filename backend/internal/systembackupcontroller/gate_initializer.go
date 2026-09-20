package systembackupcontroller

import (
	"context"
	"errors"
	"fmt"
)

const CaptureGateScope = "system-backup:capture"

type GateInitializer interface {
	Ensure(context.Context, string, GatePolicy) error
}

// SQLGateInitializer materializes the one D-owned capture gate row after this
// replica becomes leader. The duplicate path is an intentional no-op: an
// existing acquiring/held/releasing row must retain its owner, deadlines,
// policy snapshot, generation, fence and row version for recovery.
type SQLGateInitializer struct {
	DB Executor
}

func (i SQLGateInitializer) Ensure(ctx context.Context, installationID string, policy GatePolicy) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if i.DB == nil {
		return errors.New("nil system backup gate initializer database")
	}
	key := GateKey{InstallationID: installationID, Scope: CaptureGateScope}
	if err := key.validate(); err != nil {
		return err
	}
	if err := policy.Validate(); err != nil {
		return err
	}
	_, err := i.DB.ExecContext(ctx, `INSERT INTO system_maintenance_locks (
  origin_installation_id,
  scope,
  lock_ttl_seconds
) VALUES (?, ?, ?)
ON DUPLICATE KEY UPDATE id = id`, installationID, CaptureGateScope, gateSeconds(policy.LockTTL))
	if err != nil {
		return fmt.Errorf("ensure system backup capture gate: %w", err)
	}
	return nil
}
