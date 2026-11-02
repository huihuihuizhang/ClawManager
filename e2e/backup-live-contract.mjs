// Public HTTP contract checks only; these do not grant full backup acceptance.
export const parts = ['mysql', 'redis', 'object_storage', 'workspace', 'deployment_resources', 'secret_bundle'];
const statuses = new Set(['pending','preparing','ready_for_capture','acquiring_gate','capturing','validating','publishing','finalization_unknown','canceling','succeeded','failed','canceled']);
const idOK = value => typeof value === 'string' && /^sbk_[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(value);
const installationOK = value => typeof value === 'string' && /^installation_[A-Za-z0-9._:-]{1,115}$/.test(value);
const checksumOK = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const positiveVersion = value => Number.isSafeInteger(value) && value > 0;
const fail = () => { throw new Error('invalid_live_contract'); };

export function acceptedTask(status, headers, data, key) {
  // tasks.go:Create writes the projected task directly, not {data: task}.
  if (status !== 202 || headers['x-system-backup-data-source'] !== 'live' ||
      data?.schema_version !== 'system-backup-task.v1' || data.task_type !== 'backup' ||
      !idOK(data.public_id) || !installationOK(data.origin_installation_id) ||
      data.endpoint !== 'createSystemBackup' || data.idempotency_key !== key ||
      !positiveVersion(data.row_version) || !statuses.has(data.status)) fail();
  if (headers.location !== `/api/v1/admin/system-backups/${data.public_id}`) fail();
  return { public_id: data.public_id, origin_installation_id: data.origin_installation_id,
    initial_row_version: data.row_version };
}

export function advanceDetail(previous, accepted, headers, data) {
  const task = data?.task;
  if (data?.schema_version !== 'system-backup-backup-detail.v1' ||
      task?.schema_version !== 'system-backup-task.v1' || task.task_type !== 'backup' ||
      task.public_id !== accepted.public_id || task.origin_installation_id !== accepted.origin_installation_id ||
      !positiveVersion(task.row_version) || !statuses.has(task.status) ||
      headers['x-system-backup-data-source'] !== 'live' ||
      headers['x-system-backup-origin-installation-id'] !== accepted.origin_installation_id ||
      headers['x-system-backup-task-row-version'] !== String(task.row_version)) fail();
  // Ignore late snapshots, including repeated versions. Never regress ready/failure.
  if (task.row_version < accepted.initial_row_version || (previous && task.row_version <= previous.row_version)) return previous;
  const observation = { status: task.status, row_version: task.row_version,
    artifact_committed: data.artifact_state === 'committed', artifact_usable: data.artifact_usable === true,
    acceptance_ready: data.acceptance_ready === true, acceptance_eligible: data.acceptance_eligible === true };
  const ready = task.status === 'succeeded' && data.task_purpose === 'acceptance' &&
    Array.isArray(data.requested_parts) && data.requested_parts.length === parts.length && parts.every(p => data.requested_parts.includes(p)) &&
    observation.artifact_committed && observation.artifact_usable && observation.acceptance_ready && observation.acceptance_eligible &&
    data.consistency === 'strong' && data.verifier_summary?.aggregate_status === 'passed' &&
    ['manifest','index','marker','acceptance','catalog'].every(k => checksumOK(data.checksums?.[k]));
  return { ...observation, ready };
}
