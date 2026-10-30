import type { EventResource } from '../../../types/systemBackupContract';

export const activeBackupRecoveryStates = new Set(['preparing', 'ready_for_capture', 'acquiring_gate', 'capturing', 'canceling']);

// Historical diagnostics explain protection, never override the task authority.
export function hasProtectedRecovery(status: string, task: string, events: EventResource[]): boolean {
  return activeBackupRecoveryStates.has(status) && events.some(event => event.target_type === 'backup'
    && event.target_public_id === task && event.event_type === 'diagnostic.d.recovery_blocked');
}

// Once capture starts, this historical wait is no longer a current blocker.
export function hasSourceGateWait(status: string, task: string, events: EventResource[]): boolean {
  return ['preparing', 'ready_for_capture', 'acquiring_gate'].includes(status) && events.some(event =>
    event.target_type === 'backup' && event.target_public_id === task && event.event_type === 'diagnostic.d.source_gate_wait');
}
