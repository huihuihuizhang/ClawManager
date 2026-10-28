import type {
  ArtifactVerificationDetailResource, BackupDetailResource, DrillDetailResource, PreflightDetailResource, SystemBackupTask,
} from '../../../types/systemBackupContract';
import type { BackupReadSource, BackupSnapshot, PreviewScenario } from './backupReadModel';

const time = '2026-09-30T02:30:00Z';
const checksums = { manifest: 'a'.repeat(64), index: 'b'.repeat(64), marker: 'c'.repeat(64), acceptance: 'd'.repeat(64), catalog: 'e'.repeat(64) };
const execution = { current_attempt_number: 1, current_phase: null, job_generation: 1, last_business_progress_at: time };
const verifier = { aggregate_status: 'passed' as const, passed: 6, warning: 0, failed: 0, skipped: 0, report_evidence: null };

function task(id: string, type: SystemBackupTask['task_type'], status: SystemBackupTask['status']): SystemBackupTask {
  const settled = ['succeeded', 'failed', 'canceled'].includes(status);
  return {
    schema_version: 'system-backup-task.v1', public_id: id, origin_installation_id: 'installation_preview',
    task_type: type, actor_type: 'admin', actor_id: 'preview-admin', endpoint: 'preview-only',
    idempotency_key: `preview-${id}`, request_hash: '0'.repeat(64), request_id: `preview-${id}`,
    retry_of_public_id: null, status, pending_reason: 'none', attention_reason: status === 'finalization_unknown' ? 'external_result_unknown' : 'none',
    can_cancel: !settled && status !== 'finalization_unknown', config_version: 3, retryable: false, failure_category: 'none', failure_message: null,
    heartbeat_at: time, row_version: 1, next_reconcile_at: null, deadline_at: '2026-09-30T04:00:00Z',
    started_at: time, finished_at: settled ? time : null, created_at: time, updated_at: time,
  };
}

function backup(id: string, patch: Partial<BackupDetailResource> = {}): BackupDetailResource {
  return {
    schema_version: 'system-backup-backup-detail.v1', task: task(id, 'backup', 'succeeded'), execution,
    task_purpose: 'acceptance', source_orchestrator: 'kubernetes', source_profile: 'cluster', matrix: 'k8s-cluster',
    datasource_topology: 'in_cluster', runner: 'k8s',
    requested_parts: ['mysql', 'redis', 'object_storage', 'workspace', 'deployment_resources', 'secret_bundle'],
    artifact_state: 'committed', artifact_usable: true, artifact_unusable_reason: 'none', artifact_committed_at: time,
    acceptance_ready: true, acceptance_eligible: true, eligibility_reason_codes: ['eligible'], eligibility_decision_hash: 'f'.repeat(64),
    target_class: 'dr-ready-external', target_risks: [], target_failure_domain_id: 'preview-external-zone', consistency: 'strong',
    checksums, artifact_registration_id: `preview-reg-${id}`, artifact_registration_hash: 'e'.repeat(64), verifier_summary: verifier,
    manual_hold: false, manual_hold_reason: null, manual_hold_actor: null, manual_hold_at: null, promotion_hold: false,
    bytes: 18253611008, prune_guard_version: 1, ...patch,
  };
}

export const defaultPreviewCopy = {
  changeReason: 'Sample: adjust retained recovery points',
  eventMessage: 'Sample: artifact committed; execution and eligibility are recorded separately.',
  logMessage: '[Sample / redacted] Artifact publication completed',
  schema: 'Sample schema v3', schemaLabel: 'MySQL schema', workspace: 'Workspace capacity', capacity: '32 GiB available',
  freshness: 'Report freshness', expired: 'Validity period ended',
};
export type BackupPreviewCopy = typeof defaultPreviewCopy;

export function createBackupPreview(scenario: PreviewScenario, copy: BackupPreviewCopy = defaultPreviewCopy): BackupSnapshot {
  const backups = [
    backup('sbk_00000000-0000-4000-8000-000000000003'),
    backup('sbk_00000000-0000-4000-8000-000000000002', {
      task: task('sbk_00000000-0000-4000-8000-000000000002', 'backup', 'finalization_unknown'),
      artifact_state: 'staging', artifact_usable: false, artifact_unusable_reason: 'finalization_pending', artifact_committed_at: null,
      acceptance_ready: false, acceptance_eligible: false, eligibility_reason_codes: ['artifact_not_committed'], eligibility_decision_hash: null,
      artifact_registration_id: null, artifact_registration_hash: null, bytes: null,
      checksums: { manifest: null, index: null, marker: null, acceptance: null, catalog: null },
    }),
    backup('sbk_00000000-0000-4000-8000-000000000001', {
      task_purpose: 'functional_test', acceptance_ready: false, acceptance_eligible: false, eligibility_reason_codes: ['functional_test'],
      target_class: 'same-cluster-copy', target_risks: ['same_failure_domain'], bytes: 2147483648,
    }),
  ];
  const drills: DrillDetailResource[] = [{
    schema_version: 'system-backup-drill-detail.v1', task: task('sdr_00000000-0000-4000-8000-000000000001', 'drill', 'succeeded'), execution,
    source: { source_artifact_type: 'backup', source_public_id: backups[0].task.public_id }, source_checksums: checksums,
    task_purpose: 'acceptance', target_profile: 'cluster', restore_target_config_hash: '1'.repeat(64),
    cleanup_policy: 'delete-on-success', cleanup_status: 'running', cleanup_failure_code: 'none',
    preflight_evidence: null, diff_evidence: null, verifier_summary: verifier, consistency: 'strong',
    acceptance_eligible: false, eligibility_reason_codes: ['evidence_incomplete'], eligibility_decision_hash: null,
  }];
  const preflights: PreflightDetailResource[] = [{
    schema_version: 'system-backup-preflight-detail.v1', task: task('spf_00000000-0000-4000-8000-000000000001', 'preflight', 'succeeded'), execution,
    source: { source_artifact_type: 'backup', source_public_id: backups[0].task.public_id }, source_checksums: checksums,
    preflight_mode: 'production_readonly', target_profile: 'cluster', restore_target_config_hash: '2'.repeat(64),
    artifact_compatibility: 'compatible_with_warnings', report_evidence: { public_id: 'sev_00000000-0000-4000-8000-000000000001', sha256: '3'.repeat(64) },
    diff_evidence: { public_id: 'sev_00000000-0000-4000-8000-000000000002', sha256: '4'.repeat(64) }, report_validity_reason: 'report_expired',
    verifier_summary: { ...verifier, aggregate_status: 'warning', passed: 5, warning: 1 },
  }];
  const empty = scenario === 'empty';
  const verifications: ArtifactVerificationDetailResource[] = [{
    schema_version: 'system-backup-artifact-verification-detail.v1',
    task: task('sav_00000000-0000-4000-8000-000000000001', 'artifact_verify', 'succeeded'), execution,
    verification_scope: 'full', source: { source_artifact_type: 'backup', source_public_id: backups[0].task.public_id },
    observed_checksums: checksums, health_report_evidence: { public_id: 'sev_00000000-0000-4000-8000-000000000003', sha256: '5'.repeat(64) },
    artifact_state_before: 'committed', artifact_state_after: 'committed', usable_before: false, usable_after: true,
    unusable_reason_before: 'verification_pending', unusable_reason_after: 'none', decision_reason: 'restored_usable', verifier_summary: verifier,
  }];
  const snapshot: BackupSnapshot = {
    source: 'preview',
    overview: {
      schema_version: 'system-backup-overview.v1', origin_installation_id: 'installation_preview', config_version: 3,
      effective_enabled: scenario !== 'disabled', monitoring_armed: true, monitoring_armed_reason: 'previously_enabled',
      matrix: 'k8s-cluster', backup_recovery_readiness: false, baseline_present: false,
      controller_health: 'healthy', database_health: 'healthy', artifact_target_health: 'healthy', evidence_store_health: 'healthy',
      catalog_health: 'degraded', source_writer_state: 'clean', active_task_count: empty ? 0 : 1, active_operation_count: empty ? 0 : 1,
      finalization_unknown_count: empty ? 0 : 1, cleanup_backlog_count: empty ? 0 : 1, ownership_resolution_backlog_count: 0,
      shortage_failure_domains: [{ target_failure_domain_id: 'preview-external-zone', minimum_recovery_points: 2, eligible_usable_recovery_points: empty ? 0 : 1 }],
      observed_at: time,
    },
    config: {
      version: 3, active: true, effective_enabled: scenario !== 'disabled', change_reason: copy.changeReason,
      values: { minimum_recovery_points: 2, alert_profile: 'development', registries: [], references: [] },
    },
    backups: empty ? [] : backups, drills: empty ? [] : drills, preflights: empty ? [] : preflights,
    verifications: empty ? [] : verifications,
    catalog: empty ? [] : backups.map((item) => ({
      id: item.artifact_registration_id ?? `preview-pending-${item.task.public_id}`, backupId: item.task.public_id,
      registration: item.artifact_registration_id ? 'registered' : 'pending', imported: false,
      verification: item.artifact_state === 'committed' ? 'passed' : 'pending',
    })),
    events: empty ? [] : [{
      schema_version: 'system-backup-event.v1', target_type: 'backup', target_public_id: backups[0].task.public_id,
      event_type: 'artifact_committed', level: 'info', task_status: 'succeeded',
      message: copy.eventMessage, details: null, request_id: null, created_at: time,
    }],
    logs: empty ? [] : [{
      schema_version: 'system-backup-log-entry.v1', task_type: 'backup', task_public_id: backups[0].task.public_id,
      attempt_number: 1, phase: 'publish', job_generation: 1, chunk_sequence: 1, line_index: 1,
      timestamp: time, stream: 'stdout', level: 'info', message: copy.logMessage,
    }],
    logsExpired: scenario === 'logs_expired',
    differences: empty ? {} : { [preflights[0].task.public_id]: [
      { resource: copy.schemaLabel, source: copy.schema, target: copy.schema, result: 'passed' },
      { resource: copy.workspace, source: '16 GiB', target: copy.capacity, result: 'passed' },
      { resource: copy.freshness, source: time, target: copy.expired, result: 'warning' },
    ] },
    promotionHealth: 'unknown',
  };
  return structuredClone(snapshot);
}

export function previewBackupSource(scenario: PreviewScenario, copy: BackupPreviewCopy = defaultPreviewCopy): BackupReadSource {
  return {
    async read(signal) {
      signal.throwIfAborted();
      if (scenario === 'loading') return { kind: 'loading' };
      if (scenario === 'error') return { kind: 'error', code: 'previewError' };
      if (scenario === 'unsupported') return { kind: 'unsupported' };
      return { kind: 'ready', data: createBackupPreview(scenario, copy) };
    },
  };
}
