import api from './api';

export interface LegacyTeamBackupJob {
  public_id: string; operation: string; status: string; phase: string;
  created_at: string; error_code?: string; source_backup_id?: string;
  requires_inspection: boolean; report?: unknown;
}
export interface LegacyTeamBackupPage {
  items: LegacyTeamBackupJob[]; next_cursor?: string; unfinished_count: number;
  history_only: true; writes_available: false;
}
const base = '/admin/system-backup/team-data/jobs';
const isID = (id: string) => /^(sbk|sdr|spf|sav)_[a-f0-9]{32}$/.test(id);
const isJob = (job: LegacyTeamBackupJob) => job && isID(job.public_id) &&
  ['operation', 'status', 'phase', 'created_at'].every(key => typeof job[key as keyof LegacyTeamBackupJob] === 'string') &&
  typeof job.requires_inspection === 'boolean';

// Deliberately read-only: legacy records never gain public-v1 mutation authority.
export async function listLegacyTeamBackupHistory(before?: string, signal?: AbortSignal): Promise<LegacyTeamBackupPage> {
  if (before !== undefined && !isID(before)) throw new Error('validation_failed');
  const response = await api.get(base, { signal, params: before ? { before } : undefined });
  const data = response.data?.data as LegacyTeamBackupPage;
  if (response.status !== 200 || response.data?.success !== true || !data || data.history_only !== true ||
      data.writes_available !== false || !Array.isArray(data.items) || !data.items.every(isJob) ||
      !Number.isSafeInteger(data.unfinished_count) || data.unfinished_count < 0 ||
      (data.next_cursor !== undefined && !isID(data.next_cursor))) throw new Error('unconfirmed_response');
  return data;
}

export async function getLegacyTeamBackupHistory(id: string, signal?: AbortSignal): Promise<LegacyTeamBackupJob> {
  if (!isID(id)) throw new Error('validation_failed');
  const response = await api.get(`${base}/${encodeURIComponent(id)}`, { signal });
  const data = response.data?.data as LegacyTeamBackupJob;
  if (response.status !== 200 || response.data?.success !== true || response.data?.history_only !== true ||
      response.data?.writes_available !== false || !isJob(data) || data.public_id !== id) throw new Error('unconfirmed_response');
  return data;
}
