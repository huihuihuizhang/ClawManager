import type { BackupLiveState } from './backupLiveSource';

// This controls whether an authenticated user can submit a request, not whether
// execution is authorized. The POST remains the only current admission source.
// Records mode has no current readiness claim: last_effective_enabled is cached.
export function canSubmitCompleteBackup(state: BackupLiveState): boolean {
  if (state.kind === 'ready') {
    return state.data.config.active
      && state.data.config.origin_installation_id === state.data.overview.origin_installation_id
      && state.data.config.version === state.data.overview.config_version
      && state.data.overview.effective_enabled && state.data.config.effective_enabled;
  }
  if (state.kind !== 'records' || state.data.config.kind !== 'ready' || state.data.backups.kind !== 'ready') return false;
  const config = state.data.config.value;
  const backups = state.data.backups.value;
  return config.active && config.origin_installation_id.length > 0
    && config.origin_installation_id === state.data.origin_installation_id
    && (backups.origin_installation_id === null || backups.origin_installation_id === config.origin_installation_id)
    && backups.items.every(task => task.origin_installation_id === config.origin_installation_id);
}
