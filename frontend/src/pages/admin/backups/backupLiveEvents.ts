import { BackupReadError } from './backupApiRead.ts';
import type { BackupActivityContext, BackupReadPage, BackupTaskKind } from './backupApiRead.ts';
import type { BackupActivityPage } from './backupLiveActivity.ts';
import type { BackupDetailSelection } from './backupLiveDetail.ts';
import type { EventResource } from '../../../types/systemBackupContract';

interface EventReader {
  activity(kind: BackupTaskKind, id: string, channel: 'events', signal: AbortSignal,
    options: { limit: number; cursor?: string; context: BackupActivityContext }): Promise<BackupReadPage<EventResource>>;
}

// The event endpoint authenticates its task in the same transaction and returns
// installation/version response headers. Full multi-owner detail is independent.
export async function readBackupLiveEvents(client: EventReader, selected: BackupDetailSelection,
  signal: AbortSignal, current?: BackupActivityPage<'events'>): Promise<BackupActivityPage<'events'>> {
  const selection = { ...selected };
  signal.throwIfAborted();
  if (!selection.origin_installation_id || !Number.isSafeInteger(selection.row_version) || selection.row_version < 1) {
    throw new BackupReadError(0, 'invalid_activity_selection');
  }
  if (current !== undefined && (current.channel !== 'events' || current.selection.kind !== selection.kind
    || current.selection.public_id !== selection.public_id || current.selection.origin_installation_id !== selection.origin_installation_id
    || current.selection.row_version !== selection.row_version)) throw new BackupReadError(0, 'invalid_activity_continuation');
  if (current !== undefined && current.next_cursor === null) return current;
  const cursor = current?.next_cursor ?? undefined;
  const items = current === undefined ? [] : [...current.items];
  const requested = current === undefined ? [] : [...current.requested_cursors];
  const consistency = current?.consistency;
  const page = await client.activity(selection.kind, selection.public_id, 'events', signal, {
    limit: 50, ...(cursor === undefined ? {} : { cursor }),
    context: { origin_installation_id: selection.origin_installation_id, minimum_row_version: selection.row_version },
  });
  signal.throwIfAborted();
  if (page.consistency !== 'stable_cutoff' || consistency !== undefined && consistency !== page.consistency) {
    throw new BackupReadError(200, 'consistency_changed');
  }
  if (page.next_cursor !== null && requested.includes(page.next_cursor)) throw new BackupReadError(200, 'cursor_loop');
  return { channel: 'events', selection, items: [...items, ...page.items], consistency: page.consistency, next_cursor: page.next_cursor,
    requested_cursors: page.next_cursor === null ? requested : [...requested, page.next_cursor] };
}
