import api from './api';
import type { SystemBackupTask } from '../types/systemBackupContract';
import { isBackupTaskListResource } from '../pages/admin/backups/backupApiRead.ts';

const completeBackupParts = ['mysql', 'redis', 'object_storage', 'workspace', 'deployment_resources', 'secret_bundle'];

// Retain the separate DR acceptance request for its existing callers.
export const acceptanceBackupRequestJSON = JSON.stringify({
  task_purpose: 'acceptance',
  requested_parts: completeBackupParts,
});

// Existing non-DR wire purpose; this request still captures every domain.
// Keep these exact bytes with the same key when an outcome is unknown.
export const completeBackupRequestJSON = JSON.stringify({
  task_purpose: 'functional_test',
  requested_parts: completeBackupParts,
});

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
