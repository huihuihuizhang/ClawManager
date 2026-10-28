import { BackupReadError } from './backupApiRead.ts';
import type { BackupReadPage, BackupTaskKind } from './backupApiRead.ts';
import { readBackupLiveDetail } from './backupLiveDetail.ts';
import type { BackupDetailReader, BackupDetailSelection } from './backupLiveDetail.ts';
import type { EventResource, LogEntryResource } from '../../../types/systemBackupContract';

export type BackupActivityChannel = 'events' | 'logs';
export type BackupActivityItem<C extends BackupActivityChannel> = C extends 'events' ? EventResource : LogEntryResource;
export interface BackupActivityReader extends BackupDetailReader {
  activity<C extends BackupActivityChannel>(kind: BackupTaskKind, id: string, channel: C, signal: AbortSignal,
    options?: { limit?: number; cursor?: string }): Promise<BackupReadPage<BackupActivityItem<C>>>;
}
export interface BackupActivityPage<C extends BackupActivityChannel> extends BackupReadPage<BackupActivityItem<C>> {
  channel: C;
  selection: BackupDetailSelection;
  requested_cursors: string[];
}

// Activity has no installation field. Check the selected task before and
// after each page, without treating events/logs as task state authority.
export async function readBackupLiveActivity<C extends BackupActivityChannel>(
  client: BackupActivityReader, selected: BackupDetailSelection, channel: C, signal: AbortSignal,
  current?: BackupActivityPage<C>,
): Promise<BackupActivityPage<C>> {
  const selection = { ...selected };
  signal.throwIfAborted();
  if (current !== undefined && (current.channel !== channel
    || current.selection.kind !== selection.kind || current.selection.public_id !== selection.public_id
    || current.selection.origin_installation_id !== selection.origin_installation_id
    || current.selection.row_version !== selection.row_version)) {
    throw new BackupReadError(0, 'invalid_activity_continuation');
  }
  if (current !== undefined && current.next_cursor === null) return current;
  const cursor = current?.next_cursor ?? undefined;
  const items = current === undefined ? [] : [...current.items];
  const requested = current === undefined ? [] : [...current.requested_cursors];
  const consistency = current?.consistency;
  await readBackupLiveDetail(client, selection, signal);
  const page = await client.activity(selection.kind, selection.public_id, channel, signal, {
    limit: 50, ...(cursor === undefined ? {} : { cursor }),
  });
  signal.throwIfAborted();
  if (consistency !== undefined && consistency !== page.consistency) throw new BackupReadError(200, 'consistency_changed');
  if (page.next_cursor !== null && requested.includes(page.next_cursor)) throw new BackupReadError(200, 'cursor_loop');
  await readBackupLiveDetail(client, selection, signal);
  signal.throwIfAborted();
  // Event DTOs do not expose an event ID; identical events may be distinct.
  return {
    channel, selection, items: [...items, ...page.items], consistency: page.consistency, next_cursor: page.next_cursor,
    requested_cursors: page.next_cursor === null ? requested : [...requested, page.next_cursor],
  };
}

export function backupActivityExpired(channel: BackupActivityChannel, error: unknown): boolean {
  return channel === 'logs' && error instanceof BackupReadError && error.code === 'logs_expired'
    && error.status >= 400 && error.status < 500 && error.status !== 401 && error.status !== 403;
}
