import type {
  ArtifactVerificationDetailResource, BackupDetailResource, ConfigResource, ConfigValues, DrillDetailResource, EventResource,
  LogEntryResource, OverviewResource, PreflightDetailResource, PromotionHealth,
} from '../../../types/systemBackupContract';

// Presentation-only model. Catalog/report payload contracts are still owned by
// their producers; these summaries are deliberately not new wire DTOs.
export interface CatalogSummary {
  id: string;
  backupId: string;
  registration: 'registered' | 'pending' | 'unavailable';
  imported: boolean;
  verification: 'passed' | 'pending' | 'failed';
}

export interface ReportDifference {
  resource: string;
  source: string;
  target: string;
  result: 'passed' | 'warning' | 'failed';
}

export interface BackupSnapshot {
  source: 'preview';
  overview: OverviewResource;
  config: Pick<ConfigResource, 'version' | 'active' | 'effective_enabled' | 'change_reason'> & {
    values: Pick<ConfigValues, 'minimum_recovery_points' | 'alert_profile' | 'registries' | 'references'>;
  };
  backups: BackupDetailResource[];
  drills: DrillDetailResource[];
  preflights: PreflightDetailResource[];
  verifications: ArtifactVerificationDetailResource[];
  catalog: CatalogSummary[];
  events: EventResource[];
  logs: LogEntryResource[];
  logsExpired: boolean;
  differences: Record<string, ReportDifference[]>;
  promotionHealth: PromotionHealth['current_health'];
}

export const previewScenarios = ['ready', 'empty', 'loading', 'error', 'disabled', 'unsupported', 'logs_expired'] as const;
export const backupEntryPoints = [
  { tab: 'backups', label: 'entry_backups', description: 'entry_backups_desc' },
  { tab: 'drills', label: 'entry_drills', description: 'entry_drills_desc' },
  { tab: 'preflight', label: 'entry_preflight', description: 'entry_preflight_desc' },
  { tab: 'verification', label: 'entry_verification', description: 'entry_verification_desc' },
  { tab: 'catalog', label: 'entry_catalog', description: 'entry_catalog_desc' },
  { tab: 'retention', label: 'entry_retention', description: 'entry_retention_desc' },
  { tab: 'config', label: 'entry_config', description: 'entry_config_desc' },
  { tab: 'baseline', label: 'entry_baseline', description: 'entry_baseline_desc' },
] as const;
export type PreviewScenario = (typeof previewScenarios)[number];
export type BackupReadState =
  | { kind: 'unavailable' }
  | { kind: 'loading' }
  | { kind: 'error'; code: 'readError' | 'previewError' }
  | { kind: 'unsupported' }
  | { kind: 'ready'; data: BackupSnapshot };

export interface BackupReadSource {
  read(signal: AbortSignal): Promise<BackupReadState>;
}

// No guessed endpoints or implicit fixture fallback. Replace this source only
// after the Admin read API contract and authenticated transport are accepted.
export const unavailableBackupSource: BackupReadSource = {
  async read() { return { kind: 'unavailable' }; },
};

export function filterBackups(backups: BackupDetailResource[], query: string, status: string) {
  const term = query.trim().toLowerCase();
  return backups.filter(({ task, matrix }) =>
    (status === 'all' || task.status === status)
    && `${task.public_id} ${matrix}`.toLowerCase().includes(term),
  );
}

export function formatBytes(value: number | null, locale = 'en-US'): string {
  if (value === null) return '—';
  if (value < 1024) return `${new Intl.NumberFormat(locale).format(value)} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let size = value / 1024;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit += 1; }
  return `${new Intl.NumberFormat(locale, { minimumFractionDigits: 1, maximumFractionDigits: 1 }).format(size)} ${units[unit]}`;
}
