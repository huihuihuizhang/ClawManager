import { BackupReadError } from './backupApiRead.ts';
import type { BackupTaskKind, BackupTaskResource } from './backupApiRead.ts';

export interface BackupDetailSelection {
  kind: BackupTaskKind;
  public_id: string;
  origin_installation_id: string;
  row_version: number;
}

export interface BackupDetailReader {
  detail<K extends BackupTaskKind>(kind: K, id: string, signal: AbortSignal): Promise<BackupTaskResource[K]>;
}

// A detail can advance beyond its list row. It cannot belong to another
// installation or regress behind the row the user selected.
export async function readBackupLiveDetail(
  client: BackupDetailReader, selection: BackupDetailSelection, signal: AbortSignal,
): Promise<BackupTaskResource[BackupTaskKind]> {
  const { kind, public_id, origin_installation_id, row_version } = selection;
  signal.throwIfAborted();
  const detail = await client.detail(kind, public_id, signal);
  signal.throwIfAborted();
  if (detail.task.public_id !== public_id || detail.task.origin_installation_id !== origin_installation_id) {
    throw new BackupReadError(200, 'installation_changed');
  }
  if (detail.task.row_version < row_version) throw new BackupReadError(200, 'snapshot_changed');
  return detail;
}
