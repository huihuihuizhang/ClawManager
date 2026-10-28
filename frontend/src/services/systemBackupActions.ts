import api from './api';
import { validOperation } from '../pages/admin/backups/backupApiRead';
import type { BackupDetailSelection } from '../pages/admin/backups/backupLiveDetail';

// A retry keeps the caller's key. An uncertain POST must never silently mint a
// second operation, and no stored provider/configuration data is sent back.
export async function cancelUnstartedBackup(selection: BackupDetailSelection, key: string, signal: AbortSignal) {
  const { kind, public_id, origin_installation_id } = selection;
  const prefix = kind === 'backups' ? 'sbk_' : kind === 'preflights' ? 'spf_' : '';
  if (!prefix || !new RegExp(`^${prefix}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).test(public_id)) throw new Error('invalid_target');
  const group = kind === 'backups' ? 'system-backups' : 'system-backup-preflights';
  const response = await api.post(`/admin/${group}/${public_id}/cancel`, {}, {
    signal, headers: { 'Idempotency-Key': key },
  });
  const op: unknown = response.data;
  if (response.status !== 202 || response.headers['x-system-backup-data-source'] !== 'live'
    || !validOperation(op) || op.origin_installation_id !== origin_installation_id
    || op.operation_type !== 'cancel' || op.target_public_id !== public_id
    || op.target_type !== (kind === 'backups' ? 'backup' : 'preflight')
    || op.idempotency_key !== key || !['pending', 'running', 'succeeded'].includes(op.status)) throw new Error('unconfirmed_response');
  return op;
}
