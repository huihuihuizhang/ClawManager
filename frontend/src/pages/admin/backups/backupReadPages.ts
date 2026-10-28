import { BackupReadError } from './backupApiRead.ts';
import type { BackupReadPage, BackupTaskKind, BackupTaskListResource } from './backupApiRead.ts';

export interface BackupPageReader {
  list<K extends BackupTaskKind>(kind: K, signal: AbortSignal,
    options?: { limit?: number; status?: string; cursor?: string }): Promise<BackupReadPage<BackupTaskListResource>>;
}

export interface BackupPageCollection<T> {
  items: T[];
  consistency: 'stable_cutoff' | 'eventual';
  origin_installation_id: string | null;
}

export interface BackupPagedTasks<T> extends BackupPageCollection<T> {
  next_cursor: string | null;
  requested_cursors: string[];
  limit: number;
}

function checkItems<T extends { public_id: string; origin_installation_id: string }>(
  items: T[], previous: T[] = [], installation: string | null = null,
): string | null {
  const ids = new Set(previous.map((item) => item.public_id));
  for (const item of items) {
    if (ids.has(item.public_id)) throw new BackupReadError(200, 'duplicate_resource');
    if (installation !== null && installation !== item.origin_installation_id) {
      throw new BackupReadError(200, 'installation_changed');
    }
    ids.add(item.public_id);
    installation = item.origin_installation_id;
  }
  return installation;
}

export async function readFirstBackupTaskPage<K extends BackupTaskKind>(
  reader: BackupPageReader, kind: K, signal: AbortSignal, limit = 50,
): Promise<BackupPagedTasks<BackupTaskListResource>> {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) throw new BackupReadError(0, 'invalid_pagination_budget');
  signal.throwIfAborted();
  const page = await reader.list(kind, signal, { limit });
  signal.throwIfAborted();
  return {
    items: page.items, next_cursor: page.next_cursor, consistency: page.consistency,
    origin_installation_id: checkItems(page.items),
    requested_cursors: page.next_cursor === null ? [] : [page.next_cursor], limit,
  };
}

export async function readNextBackupTaskPage<K extends BackupTaskKind>(
  reader: BackupPageReader, kind: K, current: BackupPagedTasks<BackupTaskListResource>, signal: AbortSignal,
): Promise<BackupPagedTasks<BackupTaskListResource>> {
  if (current.next_cursor === null) return current;
  signal.throwIfAborted();
  const page = await reader.list(kind, signal, { limit: current.limit, cursor: current.next_cursor });
  signal.throwIfAborted();
  if (page.consistency !== current.consistency) throw new BackupReadError(200, 'consistency_changed');
  if (page.next_cursor !== null && current.requested_cursors.includes(page.next_cursor)) {
    throw new BackupReadError(200, 'cursor_loop');
  }
  const installation = checkItems(page.items, current.items, current.origin_installation_id);
  return {
    items: [...current.items, ...page.items], next_cursor: page.next_cursor,
    consistency: current.consistency, origin_installation_id: installation,
    requested_cursors: page.next_cursor === null ? current.requested_cursors : [...current.requested_cursors, page.next_cursor],
    limit: current.limit,
  };
}

// A complete read either returns every requested page or fails. In particular,
// a page budget never turns an unfinished result into an apparently empty list.
export async function collectBackupTaskPages<K extends BackupTaskKind>(
  reader: BackupPageReader, kind: K, signal: AbortSignal,
  options: { limit?: number; status?: string; maxPages?: number; maxItems?: number } = {},
): Promise<BackupPageCollection<BackupTaskListResource>> {
  const limit = options.limit ?? 50;
  const maxPages = options.maxPages ?? 20;
  const maxItems = options.maxItems ?? 10000;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500
    || !Number.isSafeInteger(maxPages) || maxPages < 1
    || !Number.isSafeInteger(maxItems) || maxItems < 1) {
    throw new BackupReadError(0, 'invalid_pagination_budget');
  }

  const items: BackupTaskListResource[] = [];
  const ids = new Set<string>();
  const cursors = new Set<string>();
  let cursor: string | undefined;
  let consistency: 'stable_cutoff' | 'eventual' | undefined;
  let installation: string | null = null;

  for (let pageNumber = 0; pageNumber < maxPages; pageNumber += 1) {
    signal.throwIfAborted();
    const page = await reader.list(kind, signal, { limit, status: options.status, cursor });
    signal.throwIfAborted();
    if (consistency !== undefined && consistency !== page.consistency) throw new BackupReadError(200, 'consistency_changed');
    consistency = page.consistency;
    for (const item of page.items) {
      const task = item;
      if (ids.has(task.public_id)) throw new BackupReadError(200, 'duplicate_resource');
      if (installation !== null && installation !== task.origin_installation_id) {
        throw new BackupReadError(200, 'installation_changed');
      }
      ids.add(task.public_id);
      installation = task.origin_installation_id;
      items.push(item);
      if (items.length > maxItems) throw new BackupReadError(200, 'pagination_limit');
    }
    if (page.next_cursor === null) return { items, consistency: page.consistency, origin_installation_id: installation };
    if (cursors.has(page.next_cursor)) throw new BackupReadError(200, 'cursor_loop');
    cursors.add(page.next_cursor);
    cursor = page.next_cursor;
  }
  throw new BackupReadError(200, 'pagination_limit');
}
