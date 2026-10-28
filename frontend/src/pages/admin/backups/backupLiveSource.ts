import { BackupReadError } from './backupApiRead.ts';
import type { BackupTaskKind, BackupTaskListResource } from './backupApiRead.ts';
import { readFirstBackupTaskPage, readNextBackupTaskPage } from './backupReadPages.ts';
import type { BackupPagedTasks } from './backupReadPages.ts';
import type { ConfigResource, OverviewResource } from '../../../types/systemBackupContract';
import { backupReadNotReady, readBackupRecords, loadMoreBackupRecords } from './backupLiveRecords.ts';
import type { BackupRecordsClient, BackupRecordsData } from './backupLiveRecords.ts';

export interface BackupLiveClient extends BackupRecordsClient {
  overview(signal: AbortSignal): Promise<OverviewResource>;
  config(signal: AbortSignal): Promise<ConfigResource>;
}

export interface BackupLiveData {
  overview: OverviewResource;
  config: ConfigResource;
  backups: BackupPagedTasks<BackupTaskListResource>;
  drills: BackupPagedTasks<BackupTaskListResource>;
  preflights: BackupPagedTasks<BackupTaskListResource>;
  verifications: BackupPagedTasks<BackupTaskListResource>;
}

export type BackupLiveState =
  | { kind: 'unavailable' }
  | { kind: 'error' }
  | { kind: 'records'; data: BackupRecordsData }
  | { kind: 'ready'; data: BackupLiveData };

// Reads are observational. Retry errors with a bounded delay; never spin on
// a missing adapter or keep a successful snapshot indefinitely stale.
export function nextBackupReadDelay(state: BackupLiveState, failures: number): number {
  if (state.kind === 'ready' || state.kind === 'records') return 30_000;
  if (state.kind === 'unavailable') return 60_000;
  return Math.min(60_000, 5_000 * 2 ** Math.min(Math.max(failures - 1, 0), 4));
}

export function liveBackupReadEnabled(value: string | undefined): boolean { return value === '1'; }

export function createBackupLiveSource(client: BackupLiveClient) {
  return {
    async read(signal: AbortSignal): Promise<BackupLiveState> {
      try {
        signal.throwIfAborted();
        let overview: OverviewResource;
        try {
          overview = await client.overview(signal);
        } catch (error) {
          signal.throwIfAborted();
          if (!backupReadNotReady(error)) throw error;
          const data = await readBackupRecords(client, signal);
          return data === null ? { kind: 'unavailable' } : { kind: 'records', data };
        }
        const config = await client.config(signal);
        signal.throwIfAborted();
        if (overview.origin_installation_id !== config.origin_installation_id
          || overview.config_version !== config.version
          || overview.effective_enabled !== config.effective_enabled) {
          throw new BackupReadError(200, 'snapshot_changed');
        }
        const [backups, drills, preflights, verifications] = await Promise.all([
          readFirstBackupTaskPage(client, 'backups', signal),
          readFirstBackupTaskPage(client, 'drills', signal),
          readFirstBackupTaskPage(client, 'preflights', signal),
          readFirstBackupTaskPage(client, 'verifications', signal),
        ]);
        signal.throwIfAborted();
        const finalOverview = await client.overview(signal);
        signal.throwIfAborted();
        if (finalOverview.origin_installation_id !== overview.origin_installation_id
          || finalOverview.config_version !== overview.config_version
          || finalOverview.effective_enabled !== overview.effective_enabled) {
          throw new BackupReadError(200, 'snapshot_changed');
        }
        for (const group of [backups, drills, preflights, verifications]) {
          if (group.origin_installation_id !== null && group.origin_installation_id !== overview.origin_installation_id) {
            throw new BackupReadError(200, 'installation_changed');
          }
        }
        return { kind: 'ready', data: {
          overview: finalOverview, config, backups, drills, preflights, verifications,
        } };
      } catch (error) {
        if (signal.aborted) throw new DOMException('Read canceled', 'AbortError');
        if (error instanceof BackupReadError && (error.code === 'fixture_source'
          || (error.status === 503 && error.code === 'not_ready'))) return { kind: 'unavailable' };
        return { kind: 'error' };
      }
    },
    loadMoreRecords(kind: BackupTaskKind, baseline: BackupRecordsData, signal: AbortSignal): Promise<BackupRecordsData> {
      return loadMoreBackupRecords(client, kind, baseline, signal);
    },
    async loadMore<K extends BackupTaskKind>(kind: K, current: BackupPagedTasks<BackupTaskListResource>,
      baseline: OverviewResource, signal: AbortSignal): Promise<BackupPagedTasks<BackupTaskListResource>> {
      const next = await readNextBackupTaskPage(client, kind, current, signal);
      if (next.origin_installation_id !== null && next.origin_installation_id !== baseline.origin_installation_id) {
        throw new BackupReadError(200, 'installation_changed');
      }
      signal.throwIfAborted();
      const overview = await client.overview(signal);
      signal.throwIfAborted();
      if (overview.origin_installation_id !== baseline.origin_installation_id
        || overview.config_version !== baseline.config_version
        || overview.effective_enabled !== baseline.effective_enabled) {
        throw new BackupReadError(200, 'snapshot_changed');
      }
      return next;
    },
  };
}
