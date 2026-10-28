import { BackupReadError } from './backupApiRead.ts';
import type { BackupTaskKind, BackupTaskListResource } from './backupApiRead.ts';
import { readFirstBackupTaskPage, readNextBackupTaskPage } from './backupReadPages.ts';
import type { BackupPageReader, BackupPagedTasks } from './backupReadPages.ts';
import type { ConfigResource } from '../../../types/systemBackupContract';

export interface BackupRecordsClient extends BackupPageReader {
  config(signal: AbortSignal): Promise<ConfigResource>;
}
export type BackupReadAvailability<T> = { kind: 'ready'; value: T } | { kind: 'unavailable' };
export interface BackupRecordsData {
  config: BackupReadAvailability<ConfigResource>;
  backups: BackupReadAvailability<BackupPagedTasks<BackupTaskListResource>>;
  drills: BackupReadAvailability<BackupPagedTasks<BackupTaskListResource>>;
  preflights: BackupReadAvailability<BackupPagedTasks<BackupTaskListResource>>;
  verifications: BackupReadAvailability<BackupPagedTasks<BackupTaskListResource>>;
  origin_installation_id: string | null;
}
export function backupReadNotReady(error: unknown): boolean {
  return error instanceof BackupReadError && error.status === 503 && error.code === 'not_ready';
}
async function available<T>(read: () => Promise<T>, signal: AbortSignal): Promise<BackupReadAvailability<T>> {
  signal.throwIfAborted();
  try {
    const value = await read();
    signal.throwIfAborted();
    return { kind: 'ready', value };
  } catch (error) {
    if (signal.aborted) throw new DOMException('Read canceled', 'AbortError');
    if (backupReadNotReady(error)) return { kind: 'unavailable' };
    throw error;
  }
}
function configSnapshot(config: BackupReadAvailability<ConfigResource>) {
  return config.kind === 'unavailable' ? { kind: 'unavailable' as const } : {
    kind: 'ready' as const, installation: config.value.origin_installation_id,
    version: config.value.version, rowVersion: config.value.row_version, enabled: config.value.effective_enabled,
  };
}
function checkConfig(before: ReturnType<typeof configSnapshot>, after: BackupReadAvailability<ConfigResource>) {
  if (before.kind !== after.kind || before.kind === 'ready' && after.kind === 'ready'
    && (before.installation !== after.value.origin_installation_id || before.version !== after.value.version
      || before.rowVersion !== after.value.row_version || before.enabled !== after.value.effective_enabled)) {
    throw new BackupReadError(200, 'snapshot_changed');
  }
}
function recordsInstallation(data: Omit<BackupRecordsData, 'origin_installation_id'>): string | null {
  let installation = data.config.kind === 'ready' ? data.config.value.origin_installation_id : null;
  for (const group of [data.backups, data.drills, data.preflights, data.verifications]) {
    if (group.kind === 'unavailable' || group.value.origin_installation_id === null) continue;
    if (installation !== null && installation !== group.value.origin_installation_id) throw new BackupReadError(200, 'installation_changed');
    installation = group.value.origin_installation_id;
  }
  return installation;
}

// Records are independent authenticated read resources, never an Overview DTO.
// Missing resources remain unavailable; their counts/health are not invented.
export async function readBackupRecords(client: BackupRecordsClient, signal: AbortSignal): Promise<BackupRecordsData | null> {
  const config = await available(() => client.config(signal), signal);
  const before = configSnapshot(config);
  const [backups, drills, preflights, verifications] = await Promise.all([
    available(() => readFirstBackupTaskPage(client, 'backups', signal), signal),
    available(() => readFirstBackupTaskPage(client, 'drills', signal), signal),
    available(() => readFirstBackupTaskPage(client, 'preflights', signal), signal),
    available(() => readFirstBackupTaskPage(client, 'verifications', signal), signal),
  ]);
  checkConfig(before, await available(() => client.config(signal), signal));
  signal.throwIfAborted();
  if (![config, backups, drills, preflights, verifications].some((item) => item.kind === 'ready')) return null;
  const data = { config, backups, drills, preflights, verifications };
  return { ...data, origin_installation_id: recordsInstallation(data) };
}

export async function loadMoreBackupRecords(
  client: BackupRecordsClient, kind: BackupTaskKind, baseline: BackupRecordsData, signal: AbortSignal,
): Promise<BackupRecordsData> {
  signal.throwIfAborted();
  const group = baseline[kind];
  if (group.kind !== 'ready') throw new BackupReadError(0, 'unavailable_resource');
  if (group.value.next_cursor === null) return baseline;
  const before = configSnapshot(baseline.config);
  const installation = baseline.origin_installation_id;
  checkConfig(before, await available(() => client.config(signal), signal));
  const next = await readNextBackupTaskPage(client, kind, group.value, signal);
  if (installation !== null && next.origin_installation_id !== null && installation !== next.origin_installation_id) {
    throw new BackupReadError(200, 'installation_changed');
  }
  checkConfig(before, await available(() => client.config(signal), signal));
  signal.throwIfAborted();
  const data = { ...baseline, [kind]: { kind: 'ready' as const, value: next } };
  return { ...data, origin_installation_id: recordsInstallation(data) };
}
