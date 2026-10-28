import { BackupReadError } from './backupApiRead.ts';
import type { ConfigResource, ConfigResourceList } from '../../../types/systemBackupContract';

export type BackupConfigBaseline = Pick<ConfigResource, 'origin_installation_id' | 'version' | 'row_version' | 'effective_enabled'>;
export interface BackupConfigReader {
  config(signal: AbortSignal): Promise<ConfigResource>;
  configVersion(version: number, signal: AbortSignal): Promise<ConfigResource>;
  configVersions(signal: AbortSignal, options?: { limit?: number; cursor?: string }): Promise<ConfigResourceList>;
}
export interface BackupConfigHistory extends ConfigResourceList {
  baseline: BackupConfigBaseline;
  requested_cursors: string[];
}

function baselineOf(value: BackupConfigBaseline): BackupConfigBaseline {
  const { origin_installation_id, version, row_version, effective_enabled } = value;
  return { origin_installation_id, version, row_version, effective_enabled };
}
function sameBaseline(left: BackupConfigBaseline, right: BackupConfigBaseline): boolean {
  return left.origin_installation_id === right.origin_installation_id && left.version === right.version
    && left.row_version === right.row_version && left.effective_enabled === right.effective_enabled;
}
async function checkCurrent(client: BackupConfigReader, baseline: BackupConfigBaseline, signal: AbortSignal) {
  signal.throwIfAborted();
  const current = await client.config(signal);
  signal.throwIfAborted();
  if (!current.active || !sameBaseline(current, baseline)) throw new BackupReadError(200, 'snapshot_changed');
}
function checkVersion(resource: ConfigResource, baseline: BackupConfigBaseline) {
  if (resource.origin_installation_id !== baseline.origin_installation_id
    || resource.active !== (resource.version === baseline.version)
    || resource.active && resource.row_version !== baseline.row_version
    || resource.effective_enabled !== (resource.active && baseline.effective_enabled)) {
    throw new BackupReadError(200, 'snapshot_changed');
  }
}

// Current activation is mutable even on an immutable historical version.
// Keep each page bound to the current configuration shown by the workspace.
export async function readBackupConfigHistory(
  client: BackupConfigReader, selected: BackupConfigBaseline, signal: AbortSignal, current?: BackupConfigHistory,
): Promise<BackupConfigHistory> {
  const baseline = baselineOf(selected);
  signal.throwIfAborted();
  if (current !== undefined && !sameBaseline(current.baseline, baseline)) throw new BackupReadError(0, 'invalid_config_continuation');
  if (current !== undefined && current.next_cursor === null) return current;
  const items = current === undefined ? [] : [...current.items];
  const cursors = current === undefined ? [] : [...current.requested_cursors];
  const cursor = current?.next_cursor ?? undefined;
  await checkCurrent(client, baseline, signal);
  const page = await client.configVersions(signal, { limit: 50, ...(cursor === undefined ? {} : { cursor }) });
  signal.throwIfAborted();
  if (page.consistency !== 'stable_cutoff'
    || page.next_cursor !== null && cursors.includes(page.next_cursor)
    || items.length > 0 && page.items.length > 0 && page.items[0].version >= items[items.length - 1].version
    || current === undefined && page.items.length === 0) throw new BackupReadError(200, 'invalid_config_continuation');
  page.items.forEach((item) => checkVersion(item, baseline));
  await checkCurrent(client, baseline, signal);
  return {
    baseline, items: [...items, ...page.items], next_cursor: page.next_cursor, consistency: page.consistency,
    requested_cursors: page.next_cursor === null ? cursors : [...cursors, page.next_cursor],
  };
}

export async function readBackupConfigVersion(
  client: BackupConfigReader, selected: BackupConfigBaseline, version: number, minimumRowVersion: number, signal: AbortSignal,
): Promise<ConfigResource> {
  const baseline = baselineOf(selected);
  signal.throwIfAborted();
  if (!Number.isSafeInteger(version) || version < 1 || !Number.isSafeInteger(minimumRowVersion) || minimumRowVersion < 1) {
    throw new BackupReadError(0, 'invalid_version');
  }
  await checkCurrent(client, baseline, signal);
  const resource = await client.configVersion(version, signal);
  signal.throwIfAborted();
  if (resource.version !== version || resource.row_version < minimumRowVersion) throw new BackupReadError(200, 'snapshot_changed');
  checkVersion(resource, baseline);
  await checkCurrent(client, baseline, signal);
  return resource;
}
