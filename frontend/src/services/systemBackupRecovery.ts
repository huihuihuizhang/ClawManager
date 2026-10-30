import api from './api';
import { validOperation } from '../pages/admin/backups/backupApiRead';
import type { BackupDetailSelection } from '../pages/admin/backups/backupLiveDetail';

export interface RecoveryActions {
  schema_version: 'system-backup-recovery-actions.v1'; origin_installation_id: string;
  public_id: string; row_version: number; status: string; can_reconcile: boolean; reason: string;
}
function target(selection: BackupDetailSelection) {
  if (selection.kind !== 'backups' || !/^sbk_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(selection.public_id)) throw new Error('invalid_target');
  return `/admin/system-backups/${selection.public_id}`;
}
export async function readRecoveryActions(selection: BackupDetailSelection, signal: AbortSignal): Promise<RecoveryActions> {
  const response = await api.get(`${target(selection)}/recovery-actions`, { signal });
  const a: RecoveryActions = response.data;
  if (response.status !== 200 || response.headers['x-system-backup-data-source'] !== 'live' ||
      !a || a.schema_version !== 'system-backup-recovery-actions.v1' || a.public_id !== selection.public_id ||
      a.origin_installation_id !== selection.origin_installation_id || !Number.isSafeInteger(a.row_version) || a.row_version < selection.row_version ||
      typeof a.status !== 'string' || typeof a.can_reconcile !== 'boolean' || typeof a.reason !== 'string' ||
      a.can_reconcile && (!['capturing', 'canceling'].includes(a.status) || a.reason !== 'original_recovery_only')) throw new Error('unconfirmed_response');
  return a;
}
export async function reconcileOriginalBackup(selection: BackupDetailSelection, key: string, signal: AbortSignal, lookupOnly = false) {
  if (!/^[A-Za-z0-9._:-]{16,128}$/.test(key)) throw new Error('invalid_key');
  const response = await api.post(`${target(selection)}/reconcile`, lookupOnly ? { lookup_only: true } : {}, { signal, headers: { 'Idempotency-Key': key } });
  const op: unknown = response.data;
  if (response.status !== 202 || response.headers['x-system-backup-data-source'] !== 'live' || !validOperation(op) ||
      op.origin_installation_id !== selection.origin_installation_id || op.target_public_id !== selection.public_id ||
      op.target_type !== 'backup' || op.operation_type !== 'capture_reconcile' || op.endpoint !== 'reconcileSystemBackup' ||
      op.idempotency_key !== key || op.status !== 'succeeded') throw new Error('unconfirmed_response');
  return op; // only scheduling acknowledged; never a completed backup
}
