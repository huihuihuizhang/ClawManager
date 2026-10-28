import { BackupReadError } from './backupApiRead.ts';
import type { BackupReadPage } from './backupApiRead.ts';
import type { SystemBackupOperation } from '../../../types/systemBackupContract.ts';
import type { BackupPagedTasks } from './backupReadPages.ts';

export interface BackupOperationsClient {
  operations(signal: AbortSignal, options?: { limit?: number; cursor?: string }): Promise<BackupReadPage<SystemBackupOperation>>;
  operation(id: string, signal: AbortSignal): Promise<SystemBackupOperation>;
}
export type BackupOperationPage = BackupPagedTasks<SystemBackupOperation>;
export type BackupOperationSelection = Pick<SystemBackupOperation, 'public_id' | 'origin_installation_id' | 'row_version'>;

// Operation records are an independent read resource. No overview, health,
// configuration availability or mutation permission is inferred from them.
export async function readBackupOperations(client: BackupOperationsClient, installation: string | null,
  signal: AbortSignal, previous?: BackupOperationPage): Promise<BackupOperationPage> {
  signal.throwIfAborted();
  if (previous && installation !== null && previous.origin_installation_id !== null
    && previous.origin_installation_id !== installation) throw new BackupReadError(200, 'installation_changed');
  if (previous?.next_cursor === null) return previous;
  const limit = previous?.limit ?? 50;
  const cursor = previous?.next_cursor;
  const consistency = previous?.consistency;
  const items = previous?.items.map((item) => ({ ...item })) ?? [];
  const requested = [...previous?.requested_cursors ?? []];
  let expected = installation ?? previous?.origin_installation_id ?? null;
  const ids = new Set(items.map((item) => item.public_id));
  const page = await client.operations(signal, { limit, ...(cursor == null ? {} : { cursor }) });
  signal.throwIfAborted();
  if (consistency !== undefined && consistency !== page.consistency) throw new BackupReadError(200, 'consistency_changed');
  if (page.next_cursor !== null && requested.includes(page.next_cursor)) {
    throw new BackupReadError(200, 'cursor_loop');
  }
  for (const item of page.items) {
    if (expected !== null && item.origin_installation_id !== expected) throw new BackupReadError(200, 'installation_changed');
    if (ids.has(item.public_id)) throw new BackupReadError(200, 'duplicate_resource');
    ids.add(item.public_id);
    expected = item.origin_installation_id;
  }
  return { items: [...items, ...page.items], next_cursor: page.next_cursor,
    consistency: page.consistency, origin_installation_id: expected, limit,
    requested_cursors: page.next_cursor === null ? requested : [...requested, page.next_cursor] };
}

export async function readBackupOperation(client: BackupOperationsClient, selection: BackupOperationSelection,
  signal: AbortSignal): Promise<SystemBackupOperation> {
  signal.throwIfAborted();
  const { public_id, origin_installation_id, row_version } = selection;
  const operation = await client.operation(public_id, signal);
  signal.throwIfAborted();
  if (operation.public_id !== public_id || operation.origin_installation_id !== origin_installation_id
    || operation.row_version < row_version) throw new BackupReadError(200, 'snapshot_changed');
  return operation;
}
