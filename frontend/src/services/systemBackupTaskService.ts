import api from './api';
import type { SystemBackupTask } from '../types/systemBackupContract';
import { isBackupTaskListResource } from '../pages/admin/backups/backupApiRead.ts';

// Supply owner-reviewed JSON and retain the exact body/key on an unknown result.
// This transport does not invent the missing backup/preflight request DTOs.
export async function createSystemBackupTask(
  kind: 'backup' | 'preflight', reviewedRequestJSON: string, idempotencyKey: string, signal?: AbortSignal,
): Promise<SystemBackupTask> {
  if ((kind !== 'backup' && kind !== 'preflight') || typeof reviewedRequestJSON !== 'string' ||
      typeof idempotencyKey !== 'string' || !/^[A-Za-z0-9._:-]{16,128}$/.test(idempotencyKey)) {
    throw new Error('validation_failed');
  }
  try { JSON.parse(reviewedRequestJSON); } catch { throw new Error('validation_failed'); }
  const path = kind === 'backup' ? '/admin/system-backups' : '/admin/system-backup-preflights';
  const response = await api.post<SystemBackupTask>(path, reviewedRequestJSON, {
    signal, headers: { 'Content-Type': 'application/json', 'Idempotency-Key': idempotencyKey },
  });
  const task = response.data;
  const endpoint = kind === 'backup' ? 'createSystemBackup' : 'createSystemBackupPreflight';
  if (response.status !== 202 || response.headers['x-system-backup-data-source'] !== 'live' ||
      !isBackupTaskListResource(kind === 'backup' ? 'backups' : 'preflights', task) ||
      task.endpoint !== endpoint || task.idempotency_key !== idempotencyKey) {
    throw new Error('not_ready');
  }
  return task;
}
