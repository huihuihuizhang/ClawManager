package systembackupcontroller

import (
	"context"
	"errors"
	"fmt"
)

const (
	gateReasonCaptureRequested            = "capture_requested"
	gateReasonParticipantsPaused          = "participants_paused"
	gateReasonAcquisitionAborted          = "acquisition_aborted"
	gateReasonReleaseRequested            = "release_requested"
	gateReasonParticipantsResumed         = "participants_resumed"
	gateReasonExpiredAcquisitionRecovered = "expired_acquisition_recovered"
	gateReasonExpiredOwnerFenced          = "expired_owner_fenced"
)

func insertGateTransitionEvent(ctx context.Context, executor Executor, key GateKey, previous, current GateState, reason, message string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if executor == nil {
		return errors.New("nil system backup gate event executor")
	}
	if err := key.validate(); err != nil {
		return err
	}
	if previous != GateIdle && previous != GateAcquiring && previous != GateHeld && previous != GateReleasing {
		return errors.New("invalid previous maintenance gate event state")
	}
	if current != GateIdle && current != GateAcquiring && current != GateHeld && current != GateReleasing {
		return errors.New("invalid current maintenance gate event state")
	}
	if reason == "" || message == "" {
		return errors.New("maintenance gate event reason and message are required")
	}
	result, err := executor.ExecContext(ctx, `INSERT INTO system_backup_events (
  origin_installation_id,
  target_type,
  target_public_id,
  event_type,
  level,
  task_status,
  message,
  details_present,
  detail_previous_status,
  detail_current_status,
  detail_reason,
  request_id
) VALUES (?, 'system', ?, 'gate_changed', 'info', NULL, ?, TRUE, ?, ?, ?, NULL)`,
		key.InstallationID, key.InstallationID, message, previous, current, reason,
	)
	if err != nil {
		return fmt.Errorf("record system backup gate transition event: %w", err)
	}
	inserted, err := exactlyOneRow(result)
	if err != nil {
		return err
	}
	if !inserted {
		return errors.New("maintenance gate transition did not produce exactly one event")
	}
	return nil
}
