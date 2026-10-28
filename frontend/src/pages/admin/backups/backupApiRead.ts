import type {
  ArtifactVerificationDetailResource, BackupDetailResource, ConfigResource, ConfigResourceList, DrillDetailResource, SystemBackupTask,
  EventResource, LogEntryResource, OverviewResource, PreflightDetailResource, SystemBackupOperation,
} from '../../../types/systemBackupContract';
import { backupStatuses, drillStatuses, simpleTaskStatuses, operationStatuses, operationTypes, failureCategories } from '../../../types/systemBackupContract.ts';

// The caller supplies the authenticated transport. This module never reads a
// token, retries a mutation, or silently substitutes preview/fixture data.
export type BackupReadTransport = (path: string, signal: AbortSignal) => Promise<Response>;

export type BackupTaskKind = 'backups' | 'drills' | 'preflights' | 'verifications';
export type BackupTaskResource = {
  backups: BackupDetailResource;
  drills: DrillDetailResource;
  preflights: PreflightDetailResource;
  verifications: ArtifactVerificationDetailResource;
};
export type BackupTaskListResource = SystemBackupTask;

const taskPaths: Record<BackupTaskKind, string> = {
  backups: '/api/v1/admin/system-backups',
  drills: '/api/v1/admin/system-restore-drills',
  preflights: '/api/v1/admin/system-backup-preflights',
  verifications: '/api/v1/admin/system-backup-artifact-verifications',
};
const taskIdentities = {
  backups: { prefix: 'sbk_', type: 'backup', schema: 'system-backup-backup-detail.v1' },
  drills: { prefix: 'sdr_', type: 'drill', schema: 'system-backup-drill-detail.v1' },
  preflights: { prefix: 'spf_', type: 'preflight', schema: 'system-backup-preflight-detail.v1' },
  verifications: { prefix: 'sav_', type: 'artifact_verify', schema: 'system-backup-artifact-verification-detail.v1' },
} as const;
const publicIdPattern = /^(sbk|sdr|spf|sav)_[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const operationIdPattern = /^sop_[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const installationPattern = /^installation_[A-Za-z0-9._:-]{1,115}$/;
const taskListFields = new Set([
  'schema_version', 'public_id', 'origin_installation_id', 'task_type', 'actor_type', 'actor_id',
  'endpoint', 'idempotency_key', 'request_hash', 'request_id', 'retry_of_public_id', 'status',
  'pending_reason', 'attention_reason', 'can_cancel', 'config_version', 'retryable',
  'failure_category', 'failure_message', 'heartbeat_at', 'row_version', 'next_reconcile_at',
  'deadline_at', 'started_at', 'finished_at', 'created_at', 'updated_at',
]);
const configResourceFields = new Set([
  'schema_version', 'origin_installation_id', 'version', 'row_version', 'active', 'effective_enabled',
  'config', 'created_by', 'change_reason', 'created_at',
]);
const configValueFields = new Set([
  'enabled', 'alert_profile', 'minimum_recovery_points', 'durations', 'capacity', 'concurrency',
  'preflight_limits', 'registries', 'references',
]);
const configNumericFields = {
  durations: new Set(`controller_claim_ttl_seconds controller_claim_heartbeat_seconds controller_reconcile_interval_seconds
    mutation_lease_ttl_seconds mutation_lease_heartbeat_seconds artifact_lease_ttl_seconds artifact_lease_heartbeat_seconds
    gate_acquisition_timeout_seconds quiesce_max_hold_seconds maintenance_lock_ttl_seconds
    watchdog_db_unavailable_grace_seconds watchdog_safety_margin_seconds staging_retention_seconds
    retention_seconds prune_candidate_ttl_seconds confirmation_ttl_seconds logs_retention_seconds
    evidence_retention_seconds promotion_health_max_age_seconds task_cancel_deadline_seconds
    cleanup_deadline_seconds retry_initial_backoff_seconds retry_max_backoff_seconds orphan_safety_window_seconds
    artifact_health_interval_seconds catalog_scan_interval_seconds catalog_scan_deadline_seconds
    provider_consistency_window_seconds redis_clock_skew_seconds strong_auth_max_age_seconds
    strong_auth_clock_skew_seconds provider_proof_max_age_seconds capture_certificate_ttl_seconds
    finalization_resolution_grace_seconds recovery_point_objective_seconds first_enable_recovery_alert_grace_seconds
    control_metadata_retention_seconds backup_task_deadline_seconds drill_task_deadline_seconds
    preflight_task_deadline_seconds artifact_verify_task_deadline_seconds operation_deadline_seconds
    finalization_resolution_deadline_seconds prune_operation_deadline_seconds`.trim().split(/\s+/)),
  capacity: new Set(`control_metadata_capacity_bytes staging_capacity_bytes max_artifact_bytes max_index_bytes
    max_plaintext_buffer_bytes max_source_items minimum_capture_throughput_bytes_per_second source_size_safety_factor
    max_log_bytes max_log_lines log_chunk_bytes log_chunk_lines`.trim().split(/\s+/)),
  concurrency: new Set(`max_concurrent_drills max_concurrent_preflights max_concurrent_artifact_verifications
    max_pending_tasks max_auto_attempts`.trim().split(/\s+/)),
  preflight_limits: new Set(`query_timeout_seconds provider_qps max_scan_bytes max_scan_items`.split(' ')),
} as const;
const registryKinds = new Set(`parts redis_sources failure_domains disaster_identity_mapping source_writers
  rbac_bindings secret_allowlist strong_auth_issuers provider_proof_issuers`.trim().split(/\s+/));
const referencePurposes = new Set(`artifact_write artifact_read artifact_delete artifact_upload_issuer artifact_ca
  evidence_store evidence_write evidence_read evidence_delete evidence_ca evidence_kek kek capture_signing
  acceptance_signing catalog_signing catalog_read catalog_append catalog_snapshot nonce_hmac status_relay`.trim().split(/\s+/));
const registryFields = new Set(['registry_kind', 'version', 'sha256']);
const referenceFields = new Set(['purpose', 'identity_hash', 'version']);
const configHashPattern = /^[0-9a-f]{64}$/;
const configVersionPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const operationFields = new Set([
  'schema_version', 'public_id', 'origin_installation_id', 'operation_type', 'target_type',
  'target_public_id', 'actor_type', 'actor_id', 'endpoint', 'idempotency_key', 'request_hash',
  'status', 'result_resource_public_id', 'result_config_version', 'retryable', 'failure_category',
  'failure_message', 'http_status', 'row_version', 'deadline_at', 'started_at', 'finished_at',
  'created_at', 'updated_at',
]);
const operationTargetPrefixes: Record<string, string> = {
  backup: 'sbk_', backup_staging: 'sbs_', external_action: 'sxa_', drill: 'sdr_', restore_resource: 'srr_',
  preflight: 'spf_', artifact_verify: 'sav_', catalog_scan: 'scs_', catalog_import: 'sci_',
  prune_run: 'spr_', promotion: 'spm_', evidence: 'sev_',
};
const operationResultPrefixes: Record<string, string> = {
  provider_proof_register: 'sev_', promotion_create: 'spm_', catalog_scan: 'scs_', catalog_import: 'sci_',
};
const synchronousOperationTypes = new Set(['config_update', 'provider_proof_register', 'manual_hold_update', 'promotion_create', 'promotion_revoke']);
const eventFields = new Set([
  'schema_version', 'target_type', 'target_public_id', 'event_type', 'level', 'task_status',
  'message', 'details', 'request_id', 'created_at',
]);
const eventDetailFields = new Set([
  'previous_status', 'current_status', 'reason', 'attempt_number', 'operation_public_id',
  'evidence_public_id', 'truncated', 'original_size', 'content_hash',
]);
const logFields = new Set([
  'schema_version', 'task_type', 'task_public_id', 'attempt_number', 'phase', 'job_generation',
  'chunk_sequence', 'line_index', 'timestamp', 'stream', 'level', 'message',
]);
const coreEventTypes = new Set(`task_status_changed attempt_started attempt_finished gate_changed participant_changed
  artifact_committed artifact_health_changed external_action_changed evidence_changed log_persistence_changed
  provider_capability_changed dependency_health_changed catalog_scan_changed catalog_record_changed cleanup_changed
  ownership_resolved prune_changed promotion_changed operation_finished`.trim().split(/\s+/));
const overviewFields = new Set([
  'schema_version', 'origin_installation_id', 'config_version', 'effective_enabled', 'monitoring_armed',
  'monitoring_armed_reason', 'matrix', 'backup_recovery_readiness', 'baseline_present', 'controller_health',
  'database_health', 'artifact_target_health', 'evidence_store_health', 'catalog_health', 'source_writer_state',
  'active_task_count', 'active_operation_count', 'finalization_unknown_count', 'cleanup_backlog_count',
  'ownership_resolution_backlog_count', 'shortage_failure_domains', 'observed_at',
]);
const shortageFields = new Set(['target_failure_domain_id', 'minimum_recovery_points', 'eligible_usable_recovery_points']);
const healthStates = new Set(['healthy', 'degraded', 'unknown', 'stale']);
const overviewCountFields = [
  'active_task_count', 'active_operation_count', 'finalization_unknown_count', 'cleanup_backlog_count',
  'ownership_resolution_backlog_count',
];
const detailFields: Record<BackupTaskKind, ReadonlySet<string>> = {
  backups: new Set(`schema_version task execution task_purpose source_orchestrator source_profile matrix
    datasource_topology runner requested_parts artifact_state artifact_usable artifact_unusable_reason
    artifact_committed_at acceptance_ready acceptance_eligible eligibility_reason_codes eligibility_decision_hash
    target_class target_risks target_failure_domain_id consistency checksums artifact_registration_id
    artifact_registration_hash verifier_summary manual_hold manual_hold_reason manual_hold_actor manual_hold_at
    promotion_hold bytes prune_guard_version`.trim().split(/\s+/)),
  drills: new Set(`schema_version task execution source source_checksums task_purpose target_profile
    restore_target_config_hash cleanup_policy cleanup_status cleanup_failure_code preflight_evidence diff_evidence
    verifier_summary consistency acceptance_eligible eligibility_reason_codes eligibility_decision_hash`.trim().split(/\s+/)),
  preflights: new Set(`schema_version task execution source source_checksums preflight_mode target_profile
    restore_target_config_hash artifact_compatibility report_evidence diff_evidence report_validity_reason
    verifier_summary`.trim().split(/\s+/)),
  verifications: new Set(`schema_version task execution verification_scope source observed_checksums
    health_report_evidence artifact_state_before artifact_state_after usable_before usable_after
    unusable_reason_before unusable_reason_after decision_reason verifier_summary`.trim().split(/\s+/)),
};
const executionFields = new Set(['current_attempt_number', 'current_phase', 'job_generation', 'last_business_progress_at']);
const sourceFields = new Set(['source_artifact_type', 'source_public_id']);
const checksumFields = new Set(['manifest', 'index', 'marker', 'acceptance', 'catalog']);
const evidenceFields = new Set(['public_id', 'sha256']);
const verifierFields = new Set(['aggregate_status', 'passed', 'warning', 'failed', 'skipped', 'report_evidence']);
const hashPattern = /^[0-9a-f]{64}$/;
const evidenceIdPattern = /^sev_[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const artifactStates = new Set(['staging', 'committed', 'deleting', 'delete_failed', 'deleted', 'corrupt']);
const backupUnusableReasons = new Set(`none not_committed finalization_pending deleting delete_failed deleted corrupt
  provider_unavailable credential_unavailable kek_unavailable evidence_unavailable verification_inconclusive`.trim().split(/\s+/));
const unusableReasons = new Set(`none not_committed finalization_pending deleting delete_failed deleted corrupt
  verification_pending catalog_tombstoned acceptance_invalid provider_unavailable credential_unavailable
  kek_unavailable signing_key_unavailable catalog_unavailable evidence_unavailable verification_inconclusive`.trim().split(/\s+/));
const eligibilityReasons = new Set(`eligible functional_test task_not_succeeded artifact_not_committed required_part_failed
  required_verifier_failed staging_cleanup_failed consistency_not_strong disqualifying_warning target_not_external
  target_risk attestation_invalid kek_not_recoverable catalog_unavailable source_backup_not_eligible
  source_artifact_unusable manifest_drift isolation_invalid evidence_incomplete`.trim().split(/\s+/));
const targetRisks = new Set(`source_overlap same_failure_domain artifact_credential_source_dependent kek_source_dependent
  signing_key_source_dependent catalog_source_dependent attestation_missing attestation_expired
  conditional_commit_unavailable transport_unverified broad_egress provider_capability_degraded`.trim().split(/\s+/));
const requestedParts = new Set(['mysql', 'redis', 'object_storage', 'workspace', 'deployment_resources', 'secret_bundle']);

export class BackupReadError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string) {
    super(`System backup read failed: ${code}`);
    this.name = 'BackupReadError';
    this.status = status;
    this.code = code;
  }
}

export interface BackupReadPage<T> {
  items: T[];
  next_cursor: string | null;
  consistency: 'stable_cutoff' | 'eventual';
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function invalidResponse(): never { throw new BackupReadError(200, 'invalid_response'); }
function positiveInteger(value: unknown): boolean { return typeof value === 'number' && Number.isSafeInteger(value) && value >= 1; }
function validDateTime(value: unknown): boolean {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value)
    && !Number.isNaN(Date.parse(value));
}
function validCursor(value: unknown): boolean {
  return typeof value === 'string' && value.length > 0 && new TextEncoder().encode(value).length <= 4096;
}
function validInstallation(value: unknown): boolean {
  return typeof value === 'string' && installationPattern.test(value);
}
function exactFields(value: Record<string, unknown>, fields: ReadonlySet<string>): boolean {
  return Object.keys(value).length === fields.size && Object.keys(value).every((field) => fields.has(field));
}
function nonnegativeInteger(value: unknown): boolean {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}
function nullableHash(value: unknown): boolean { return value === null || typeof value === 'string' && hashPattern.test(value); }
function validEvidence(value: unknown): boolean {
  return value === null || record(value) && exactFields(value, evidenceFields)
    && typeof value.public_id === 'string' && evidenceIdPattern.test(value.public_id)
    && typeof value.sha256 === 'string' && hashPattern.test(value.sha256);
}
function validSource(value: unknown): boolean {
  if (!record(value) || !exactFields(value, sourceFields) || typeof value.source_public_id !== 'string') return false;
  const prefix = value.source_artifact_type === 'backup' ? 'sbk_' : value.source_artifact_type === 'catalog_import' ? 'sci_' : '';
  return prefix !== '' && new RegExp(`^${prefix}[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$`).test(value.source_public_id);
}
function validExecution(value: unknown): boolean {
  return record(value) && exactFields(value, executionFields)
    && (value.current_attempt_number === null || positiveInteger(value.current_attempt_number))
    && (value.current_phase === null || typeof value.current_phase === 'string'
      && ['capture', 'secret_capture', 'publish', 'restore', 'normalize', 'verify', 'preflight'].includes(value.current_phase))
    && (value.job_generation === null || positiveInteger(value.job_generation))
    && (value.last_business_progress_at === null || validDateTime(value.last_business_progress_at));
}
function validChecksums(value: unknown): boolean {
  return record(value) && exactFields(value, checksumFields)
    && [...checksumFields].every((name) => nullableHash(value[name]));
}
function validVerifier(value: unknown): boolean {
  return record(value) && exactFields(value, verifierFields)
    && ['passed', 'warning', 'failed', 'skipped'].includes(value.aggregate_status as string)
    && ['passed', 'warning', 'failed', 'skipped'].every((name) => nonnegativeInteger(value[name]))
    && validEvidence(value.report_evidence);
}
function uniqueEnumArray(value: unknown, allowed: ReadonlySet<string>, minimum: number, maximum: number): boolean {
  return Array.isArray(value) && value.length >= minimum && value.length <= maximum
    && value.every((item) => typeof item === 'string' && allowed.has(item))
    && new Set(value).size === value.length;
}
function nullableDate(value: unknown): boolean { return value === null || validDateTime(value); }
function boundedString(value: unknown, minimum: number, maximum: number): boolean {
  return typeof value === 'string' && [...value].length >= minimum && [...value].length <= maximum;
}
function validEligibility(value: Record<string, unknown>): boolean {
  if (typeof value.acceptance_eligible !== 'boolean'
    || !uniqueEnumArray(value.eligibility_reason_codes, eligibilityReasons, 1, eligibilityReasons.size)
    || !nullableHash(value.eligibility_decision_hash)) return false;
  return value.acceptance_eligible
    ? (value.eligibility_reason_codes as string[]).length === 1
      && (value.eligibility_reason_codes as string[])[0] === 'eligible' && value.eligibility_decision_hash !== null
    : !(value.eligibility_reason_codes as string[]).includes('eligible');
}
function validConfigValues(value: Record<string, unknown>): boolean {
  for (const [group, fields] of Object.entries(configNumericFields)) {
    const numeric = value[group];
    if (!record(numeric) || !exactFields(numeric, fields)
      || Object.entries(numeric).some(([name, number]) => typeof number !== 'number' || !Number.isFinite(number)
        || number < 0 || name !== 'source_size_safety_factor' && !Number.isSafeInteger(number))) return false;
  }
  const registries = value.registries;
  const references = value.references;
  if (!Array.isArray(registries) || registries.length !== registryKinds.size
    || !Array.isArray(references) || references.length !== referencePurposes.size) return false;
  const seenRegistries = new Set<string>();
  for (const entry of registries) {
    if (!record(entry) || !exactFields(entry, registryFields) || typeof entry.registry_kind !== 'string'
      || !registryKinds.has(entry.registry_kind) || seenRegistries.has(entry.registry_kind)
      || typeof entry.version !== 'string' || !configVersionPattern.test(entry.version)
      || typeof entry.sha256 !== 'string' || !configHashPattern.test(entry.sha256)) return false;
    seenRegistries.add(entry.registry_kind);
  }
  const seenPurposes = new Set<string>();
  for (const entry of references) {
    if (!record(entry) || !exactFields(entry, referenceFields) || typeof entry.purpose !== 'string'
      || !referencePurposes.has(entry.purpose) || seenPurposes.has(entry.purpose)
      || typeof entry.version !== 'string' || !configVersionPattern.test(entry.version)
      || typeof entry.identity_hash !== 'string' || !configHashPattern.test(entry.identity_hash)) return false;
    seenPurposes.add(entry.purpose);
  }
  return true;
}
function validConfigResource(value: unknown, expectedVersion?: number): value is ConfigResource {
  if (!record(value) || !exactFields(value, configResourceFields) || !record(value.config)
    || !exactFields(value.config, configValueFields)
    || value.schema_version !== 'system-backup-config.v1' || !validInstallation(value.origin_installation_id)
    || !positiveInteger(value.version) || !positiveInteger(value.row_version)
    || (expectedVersion !== undefined && value.version !== expectedVersion)
    || typeof value.active !== 'boolean' || typeof value.effective_enabled !== 'boolean'
    || value.effective_enabled && !value.active
    || typeof value.config.enabled !== 'boolean' || value.effective_enabled && !value.config.enabled
    || typeof value.config.alert_profile !== 'string'
    || !['production', 'development'].includes(value.config.alert_profile)
    || typeof value.config.minimum_recovery_points !== 'number'
    || !Number.isSafeInteger(value.config.minimum_recovery_points)
    || value.config.minimum_recovery_points < 1 || value.config.minimum_recovery_points > 100
    || !validConfigValues(value.config)
    || typeof value.created_by !== 'string' || value.created_by.length < 1 || value.created_by.length > 128
    || value.change_reason !== null && (typeof value.change_reason !== 'string' || value.change_reason.length > 512)
    || !validDateTime(value.created_at)) return false;
  return true;
}
function validOverview(value: unknown): value is OverviewResource {
  if (!record(value) || !exactFields(value, overviewFields)
    || value.schema_version !== 'system-backup-overview.v1' || !validInstallation(value.origin_installation_id)
    || !positiveInteger(value.config_version)
    || typeof value.effective_enabled !== 'boolean' || typeof value.monitoring_armed !== 'boolean'
    || typeof value.backup_recovery_readiness !== 'boolean' || typeof value.baseline_present !== 'boolean'
    || !['none', 'deployment_required', 'previously_enabled'].includes(value.monitoring_armed_reason as string)
    || !['k8s-cluster', 'k3s-cluster', 'k8s-single-node', 'k3s-single-node'].includes(value.matrix as string)
    || !['controller_health', 'database_health', 'artifact_target_health', 'evidence_store_health', 'catalog_health']
      .every((field) => healthStates.has(value[field] as string))
    || !['clean', 'drift', 'unknown'].includes(value.source_writer_state as string)
    || !overviewCountFields.every((field) => typeof value[field] === 'number'
      && Number.isSafeInteger(value[field]) && (value[field] as number) >= 0)
    || !Array.isArray(value.shortage_failure_domains) || value.shortage_failure_domains.length > 1000
    || !validDateTime(value.observed_at)) return false;
  return value.shortage_failure_domains.every((item) => record(item) && exactFields(item, shortageFields)
    && typeof item.target_failure_domain_id === 'string'
    && [...item.target_failure_domain_id].length >= 1 && [...item.target_failure_domain_id].length <= 128
    && positiveInteger(item.minimum_recovery_points)
    && typeof item.eligible_usable_recovery_points === 'number'
    && Number.isSafeInteger(item.eligible_usable_recovery_points)
    && item.eligible_usable_recovery_points >= 0);
}
function validOperationTarget(kind: unknown, id: unknown, installation: unknown): boolean {
  if (typeof kind !== 'string' || typeof id !== 'string' || id.length < 1 || id.length > 128) return false;
  if (kind === 'system') return id === installation;
  if (kind === 'matrix') return ['k8s-cluster', 'k3s-cluster', 'k8s-single-node', 'k3s-single-node'].includes(id);
  const prefix = operationTargetPrefixes[kind];
  return prefix !== undefined && new RegExp(`^${prefix}[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$`).test(id);
}
function validOperation(value: unknown, expectedId?: string): value is SystemBackupOperation {
  if (!record(value) || !exactFields(value, operationFields)
    || value.schema_version !== 'system-backup-operation.v1'
    || typeof value.public_id !== 'string' || !operationIdPattern.test(value.public_id)
    || expectedId !== undefined && value.public_id !== expectedId
    || !validInstallation(value.origin_installation_id)
    || typeof value.operation_type !== 'string'
    || !operationTypes.includes(value.operation_type as typeof operationTypes[number])
    || !validOperationTarget(value.target_type, value.target_public_id, value.origin_installation_id)
    || value.actor_type !== 'admin' && value.actor_type !== 'system'
    || typeof value.actor_id !== 'string'
    || value.actor_type === 'admin' && !/^[0-9]+$/.test(value.actor_id)
    || value.actor_type === 'system' && value.actor_id !== 'system:controller'
    || typeof value.endpoint !== 'string' || !/^[A-Za-z][A-Za-z0-9_]{0,127}$/.test(value.endpoint)
    || typeof value.idempotency_key !== 'string' || !/^[A-Za-z0-9._:-]{16,128}$/.test(value.idempotency_key)
    || typeof value.request_hash !== 'string' || !/^[0-9a-f]{64}$/.test(value.request_hash)
    || typeof value.status !== 'string'
    || !operationStatuses.includes(value.status as typeof operationStatuses[number])
    || typeof value.retryable !== 'boolean'
    || typeof value.failure_category !== 'string'
    || !failureCategories.includes(value.failure_category as typeof failureCategories[number])
    || value.failure_message !== null || !positiveInteger(value.row_version)
    || !validDateTime(value.deadline_at) || !validDateTime(value.created_at) || !validDateTime(value.updated_at)
    || value.started_at !== null && !validDateTime(value.started_at)
    || value.finished_at !== null && !validDateTime(value.finished_at)
    || value.http_status !== null && (typeof value.http_status !== 'number' || !Number.isInteger(value.http_status)
      || value.http_status < 100 || value.http_status > 599)) return false;
  if (value.operation_type === 'evidence_download_admission' || value.target_type === 'evidence') {
    const admitted = operationUTCInstant(value.created_at);
    const deadline = operationUTCInstant(value.deadline_at);
    return value.operation_type === 'evidence_download_admission' && value.target_type === 'evidence'
      && value.endpoint === 'getSystemBackupEvidence' && value.actor_type === 'admin'
      && /^[1-9][0-9]*$/.test(value.actor_id) && Number(value.actor_id) <= 2147483647
      && value.status === 'succeeded' && value.http_status === 200 && !value.retryable && value.failure_category === 'none'
      && value.result_resource_public_id === null && value.result_config_version === null
      && admitted !== null && deadline !== null && deadline > admitted
      && operationUTCInstant(value.started_at) === admitted && operationUTCInstant(value.finished_at) === admitted
      && operationUTCInstant(value.updated_at) === admitted;
  }
  const terminal = value.status === 'succeeded' || value.status === 'failed';
  if (value.status === 'pending' && (value.started_at !== null || value.finished_at !== null)
    || value.status === 'running' && (value.started_at === null || value.finished_at !== null)
    || terminal && value.finished_at === null || !terminal && value.http_status !== null
    || value.status !== 'failed' && (value.failure_category !== 'none' || value.retryable)
    || value.status === 'failed' && value.failure_category === 'none'
    || synchronousOperationTypes.has(value.operation_type) && !terminal) return false;
  if (value.status === 'succeeded' && value.operation_type === 'config_update') {
    if (!positiveInteger(value.result_config_version) || value.result_resource_public_id !== null) return false;
  } else if (value.result_config_version !== null) return false;
  const resultPrefix = value.status === 'succeeded' ? operationResultPrefixes[value.operation_type] : undefined;
  return resultPrefix === undefined ? value.result_resource_public_id === null
    : typeof value.result_resource_public_id === 'string'
      && new RegExp(`^${resultPrefix}[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$`).test(value.result_resource_public_id);
}
// Preserve sub-millisecond SQL precision when checking the immutable admission
// instant and deadline. Date.parse alone truncates distinct microseconds.
function operationUTCInstant(value: unknown): bigint | null {
  if (typeof value !== 'string') return null;
  const parts = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$/.exec(value);
  if (!parts) return null;
  const milliseconds = Date.parse(`${parts[1]}Z`);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString().slice(0, 19) !== parts[1]) return null;
  return BigInt(milliseconds) * 1000000n + BigInt((parts[2] ?? '').padEnd(9, '0'));
}
function validTask(kind: BackupTaskKind, value: unknown, expectedId?: string): boolean {
  if (!record(value) || !exactFields(value, detailFields[kind])
    || value.schema_version !== taskIdentities[kind].schema || !record(value.task)
    || !validExecution(value.execution) || !validVerifier(value.verifier_summary)) return false;
  const task = value.task;
  if (!validTaskListItem(kind, task) || expectedId !== undefined && task.public_id !== expectedId) return false;
  switch (kind) {
    case 'backups': return validBackupDetail(value);
    case 'drills': return validDrillDetail(value);
    case 'preflights': return validPreflightDetail(value);
    case 'verifications': return validVerificationDetail(value);
  }
}
function validBackupDetail(value: Record<string, unknown>): boolean {
  if (!['acceptance', 'functional_test'].includes(value.task_purpose as string)
    || !['kubernetes', 'k3s'].includes(value.source_orchestrator as string)
    || !['cluster', 'single-node'].includes(value.source_profile as string)
    || !['k8s-cluster', 'k3s-cluster', 'k8s-single-node', 'k3s-single-node'].includes(value.matrix as string)
    || value.datasource_topology !== 'in_cluster' || !['k8s', 'k3s'].includes(value.runner as string)
    || !uniqueEnumArray(value.requested_parts, requestedParts, 1, 6)
    || !artifactStates.has(value.artifact_state as string) || typeof value.artifact_usable !== 'boolean'
    || !backupUnusableReasons.has(value.artifact_unusable_reason as string)
    || value.artifact_usable !== (value.artifact_unusable_reason === 'none')
    || !nullableDate(value.artifact_committed_at)
    || typeof value.acceptance_ready !== 'boolean' || !validEligibility(value)
    || value.acceptance_ready && (!value.artifact_usable || !value.acceptance_eligible)
    || !['dr-ready-external', 'same-cluster-copy'].includes(value.target_class as string)
    || !uniqueEnumArray(value.target_risks, targetRisks, 0, 12)
    || !boundedString(value.target_failure_domain_id, 1, 128)
    || !['strong', 'bounded', 'weak'].includes(value.consistency as string)
    || !validChecksums(value.checksums)
    || value.artifact_registration_id !== null && !boundedString(value.artifact_registration_id, 1, 128)
    || !nullableHash(value.artifact_registration_hash)
    || (value.artifact_registration_id === null) !== (value.artifact_registration_hash === null)
    || value.acceptance_eligible && value.artifact_registration_id === null
    || typeof value.manual_hold !== 'boolean' || typeof value.promotion_hold !== 'boolean'
    || value.bytes !== null && !nonnegativeInteger(value.bytes) || !positiveInteger(value.prune_guard_version)) return false;
  return value.manual_hold
    ? boundedString(value.manual_hold_reason, 1, 512)
      && boundedString(value.manual_hold_actor, 1, 128) && validDateTime(value.manual_hold_at)
    : value.manual_hold_reason === null && value.manual_hold_actor === null && value.manual_hold_at === null;
}
function validDrillDetail(value: Record<string, unknown>): boolean {
  const cleanupFailed = value.cleanup_status === 'failed' || value.cleanup_status === 'partial_failed';
  if (!validSource(value.source) || !validChecksums(value.source_checksums)
    || !['acceptance', 'functional_test'].includes(value.task_purpose as string)
    || !['cluster', 'single-node'].includes(value.target_profile as string)
    || typeof value.restore_target_config_hash !== 'string' || !hashPattern.test(value.restore_target_config_hash)
    || !['delete-on-success', 'retain-always'].includes(value.cleanup_policy as string)
    || !['not_started', 'pending', 'running', 'succeeded', 'failed', 'partial_failed', 'retained'].includes(value.cleanup_status as string)
    || !['none', 'deadline_exceeded', 'provider_unavailable', 'permission_denied', 'identity_mismatch',
      'checksum_mismatch', 'ownership_unknown', 'residual_data', 'internal'].includes(value.cleanup_failure_code as string)
    || cleanupFailed !== (value.cleanup_failure_code !== 'none')
    || !validEvidence(value.preflight_evidence) || !validEvidence(value.diff_evidence)
    || value.consistency !== null && !['strong', 'bounded', 'weak'].includes(value.consistency as string)
    || !validEligibility(value)) return false;
  return !value.acceptance_eligible || value.task_purpose === 'acceptance'
    && value.cleanup_policy === 'delete-on-success' && value.cleanup_status === 'succeeded';
}
function validPreflightDetail(value: Record<string, unknown>): boolean {
  return validSource(value.source) && validChecksums(value.source_checksums)
    && ['production_readonly', 'functional_test'].includes(value.preflight_mode as string)
    && ['cluster', 'single-node'].includes(value.target_profile as string)
    && typeof value.restore_target_config_hash === 'string' && hashPattern.test(value.restore_target_config_hash)
    && ['supported', 'compatible_with_warnings', 'unsupported'].includes(value.artifact_compatibility as string)
    && validEvidence(value.report_evidence) && validEvidence(value.diff_evidence)
    && ['pending', 'valid', 'functional_test_only', 'source_changed', 'dependency_unhealthy', 'report_expired',
      'evidence_unavailable', 'incomplete'].includes(value.report_validity_reason as string);
}
function validVerificationDetail(value: Record<string, unknown>): boolean {
  if (!['health', 'full'].includes(value.verification_scope as string) || !validSource(value.source)
    || !validChecksums(value.observed_checksums) || !validEvidence(value.health_report_evidence)
    || typeof value.usable_before !== 'boolean' || typeof value.usable_after !== 'boolean'
    || !unusableReasons.has(value.unusable_reason_before as string)
    || !unusableReasons.has(value.unusable_reason_after as string)
    || value.usable_after !== (value.unusable_reason_after === 'none')
    || !['pending', 'unchanged', 'restored_usable', 'marked_unusable', 'marked_corrupt',
      'catalog_tombstoned', 'verification_inconclusive'].includes(value.decision_reason as string)) return false;
  const source = value.source as { source_artifact_type: string };
  return source.source_artifact_type === 'backup'
    ? artifactStates.has(value.artifact_state_before as string) && artifactStates.has(value.artifact_state_after as string)
    : value.artifact_state_before === null && value.artifact_state_after === null;
}
function validTaskListItem(kind: BackupTaskKind, value: unknown): boolean {
  if (!record(value) || value.schema_version !== 'system-backup-task.v1'
    || value.task_type !== taskIdentities[kind].type || typeof value.public_id !== 'string'
    || !publicIdPattern.test(value.public_id) || !value.public_id.startsWith(taskIdentities[kind].prefix)
    || !validInstallation(value.origin_installation_id) || !positiveInteger(value.row_version)
    || !positiveInteger(value.config_version) || typeof value.status !== 'string'
    || typeof value.actor_type !== 'string' || !['admin', 'system'].includes(value.actor_type)
    || typeof value.actor_id !== 'string' || !value.actor_id
    || typeof value.endpoint !== 'string' || !value.endpoint
    || typeof value.idempotency_key !== 'string' || !/^[A-Za-z0-9._:-]{16,128}$/.test(value.idempotency_key)
    || typeof value.request_hash !== 'string' || !/^[0-9a-f]{64}$/.test(value.request_hash)
    || typeof value.request_id !== 'string' || !/^[A-Za-z0-9._:-]{1,128}$/.test(value.request_id)
    || typeof value.pending_reason !== 'string' || !['none', 'global_capture_queue', 'kill_switch', 'dependency_backoff'].includes(value.pending_reason)
    || typeof value.attention_reason !== 'string' || !['none', 'external_result_unknown'].includes(value.attention_reason)
    || typeof value.can_cancel !== 'boolean' || typeof value.retryable !== 'boolean'
    || typeof value.failure_category !== 'string' || !failureCategories.includes(value.failure_category as typeof failureCategories[number])
    || !validDateTime(value.deadline_at) || !validDateTime(value.created_at) || !validDateTime(value.updated_at)) return false;
  const statuses = kind === 'backups' ? backupStatuses : kind === 'drills' ? drillStatuses : simpleTaskStatuses;
  return statuses.some((status) => status === value.status)
    && Object.keys(value).length === taskListFields.size
    && Object.keys(value).every((field) => taskListFields.has(field))
    && (value.retry_of_public_id === null
      || (typeof value.retry_of_public_id === 'string' && publicIdPattern.test(value.retry_of_public_id)
        && value.retry_of_public_id.startsWith(taskIdentities[kind].prefix)))
    && (value.failure_message === null
      || (typeof value.failure_message === 'string' && value.failure_message.length <= 2048))
    && ['heartbeat_at', 'next_reconcile_at', 'started_at', 'finished_at'].every((field) =>
      value[field] === null || validDateTime(value[field]));
}
// Creation responses use the same existing closed task DTO as list reads.
export function isBackupTaskListResource(kind: BackupTaskKind, value: unknown): value is SystemBackupTask {
  return Object.hasOwn(taskIdentities, kind) && validTaskListItem(kind, value);
}
function taskStatuses(kind: BackupTaskKind): readonly string[] {
  return kind === 'backups' ? backupStatuses : kind === 'drills' ? drillStatuses : simpleTaskStatuses;
}
function validActivity(channel: 'events' | 'logs', value: unknown, kind: BackupTaskKind, id: string): boolean {
  if (!record(value)) return false;
  if (channel === 'events') {
    if (!exactFields(value, eventFields) || value.schema_version !== 'system-backup-event.v1'
      || value.target_type !== taskIdentities[kind].type || value.target_public_id !== id
      || typeof value.event_type !== 'string'
      || !coreEventTypes.has(value.event_type) && !/^diagnostic\.[a-d]\.[a-z0-9_-]{1,64}$/.test(value.event_type)
      || !['info', 'warning', 'error', 'critical'].includes(value.level as string)
      || value.task_status !== null && (typeof value.task_status !== 'string'
        || !taskStatuses(kind).includes(value.task_status))
      || typeof value.message !== 'string' || [...value.message].length > 2048
      || value.request_id !== null && (typeof value.request_id !== 'string'
        || !/^[A-Za-z0-9._:-]{1,128}$/.test(value.request_id))
      || !validDateTime(value.created_at)) return false;
    if (value.details === null) return true;
    if (!record(value.details) || !exactFields(value.details, eventDetailFields)) return false;
    const details = value.details;
    return (details.previous_status === null || typeof details.previous_status === 'string' && [...details.previous_status].length <= 64)
      && (details.current_status === null || typeof details.current_status === 'string' && [...details.current_status].length <= 64)
      && (details.reason === null || typeof details.reason === 'string' && /^[a-z][a-z0-9_]{0,127}$/.test(details.reason))
      && (details.attempt_number === null || positiveInteger(details.attempt_number))
      && (details.operation_public_id === null || typeof details.operation_public_id === 'string'
        && operationIdPattern.test(details.operation_public_id))
      && (details.evidence_public_id === null || typeof details.evidence_public_id === 'string'
        && /^sev_[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(details.evidence_public_id))
      && typeof details.truncated === 'boolean'
      && (details.truncated
        ? typeof details.original_size === 'number' && Number.isSafeInteger(details.original_size)
          && details.original_size >= 0 && typeof details.content_hash === 'string'
          && /^[0-9a-f]{64}$/.test(details.content_hash)
        : details.original_size === null && details.content_hash === null);
  }
  const phases: Record<BackupTaskKind, readonly string[]> = {
    backups: ['capture', 'secret_capture', 'publish'], drills: ['restore', 'normalize', 'verify'],
    preflights: ['preflight'], verifications: ['verify'],
  };
  return exactFields(value, logFields) && value.schema_version === 'system-backup-log-entry.v1'
    && value.task_type === taskIdentities[kind].type && value.task_public_id === id
    && positiveInteger(value.attempt_number) && positiveInteger(value.job_generation)
    && typeof value.chunk_sequence === 'number' && Number.isSafeInteger(value.chunk_sequence) && value.chunk_sequence >= 0
    && typeof value.line_index === 'number' && Number.isSafeInteger(value.line_index) && value.line_index >= 0
    && typeof value.phase === 'string' && phases[kind].includes(value.phase)
    && validDateTime(value.timestamp) && (value.stream === 'stdout' || value.stream === 'stderr')
    && ['info', 'warning', 'error', 'unknown'].includes(value.level as string)
    && typeof value.message === 'string' && [...value.message].length <= 8192;
}

function taskPath(kind: BackupTaskKind, id: string): string {
  if (!publicIdPattern.test(id)) {
    throw new BackupReadError(0, 'invalid_resource_id');
  }
  if (!id.startsWith(taskIdentities[kind].prefix)) throw new BackupReadError(0, 'invalid_resource_id');
  return `${taskPaths[kind]}/${id}`;
}

function listQuery(limit: number | undefined, cursor: string | undefined, maximum: number): string {
  const params = new URLSearchParams();
  if (limit !== undefined) {
    if (!Number.isInteger(limit) || limit < 1 || limit > maximum) throw new BackupReadError(0, 'invalid_limit');
    params.set('limit', String(limit));
  }
  if (cursor !== undefined) {
    if (!validCursor(cursor)) throw new BackupReadError(0, 'invalid_cursor');
    params.set('cursor', cursor);
  }
  const query = params.toString();
  return query ? `?${query}` : '';
}

export interface BackupActivityContext {
  origin_installation_id: string;
  minimum_row_version: number;
}

export function createBackupApiReadClient(transport: BackupReadTransport) {
  async function get<T>(path: string, signal: AbortSignal, context?: BackupActivityContext): Promise<T> {
    const response = await transport(path, signal);
    if (signal.aborted) throw new DOMException('Read canceled', 'AbortError');
    if (response.headers.get('X-System-Backup-Data-Source') === 'fixture') {
      throw new BackupReadError(response.status, 'fixture_source');
    }
    let body: unknown;
    try { body = await response.json(); } catch {
      if (signal.aborted) throw new DOMException('Read canceled', 'AbortError');
      throw new BackupReadError(response.status, 'invalid_response');
    }
    if (!response.ok) {
      throw new BackupReadError(response.status, record(body) && typeof body.code === 'string' ? body.code : 'invalid_response');
    }
    if (context !== undefined) {
      if (response.headers.get('X-System-Backup-Data-Source') !== 'live') throw new BackupReadError(response.status, 'invalid_response');
      if (response.headers.get('X-System-Backup-Origin-Installation-ID') !== context.origin_installation_id) {
        throw new BackupReadError(response.status, 'installation_changed');
      }
      const version = response.headers.get('X-System-Backup-Task-Row-Version') ?? '';
      if (!/^[1-9][0-9]*$/.test(version) || !Number.isSafeInteger(Number(version)) || Number(version) < context.minimum_row_version) {
        throw new BackupReadError(response.status, 'snapshot_changed');
      }
    }
    if (!record(body)) throw new BackupReadError(response.status, 'invalid_response');
    if (signal.aborted) throw new DOMException('Read canceled', 'AbortError');
    return body as T;
  }

  async function page<T>(path: string, signal: AbortSignal, maximum: number, validItem: (value: unknown) => boolean, context?: BackupActivityContext): Promise<BackupReadPage<T>> {
    const body = await get<BackupReadPage<T>>(path, signal, context);
    if (Object.keys(body).sort().join(',') !== 'consistency,items,next_cursor' || !Array.isArray(body.items)
      || body.items.length > maximum || !body.items.every(validItem)
      || (body.next_cursor !== null && !validCursor(body.next_cursor))
      || !['stable_cutoff', 'eventual'].includes(body.consistency)) invalidResponse();
    return body;
  }

  return {
    async overview(signal: AbortSignal): Promise<OverviewResource> {
      const body = await get<OverviewResource>('/api/v1/admin/system-backup-overview', signal);
      if (!validOverview(body)) invalidResponse();
      return body;
    },
    async config(signal: AbortSignal): Promise<ConfigResource> {
      const body = await get<ConfigResource>('/api/v1/admin/system-backup-config', signal);
      if (!validConfigResource(body) || !body.active) invalidResponse();
      return body;
    },
    async configVersion(version: number, signal: AbortSignal): Promise<ConfigResource> {
      if (!Number.isSafeInteger(version) || version < 1) throw new BackupReadError(0, 'invalid_version');
      const body = await get<ConfigResource>(`/api/v1/admin/system-backup-config/versions/${version}`, signal);
      if (!validConfigResource(body, version)) invalidResponse();
      return body;
    },
    async configVersions(signal: AbortSignal, options: { limit?: number; cursor?: string } = {}): Promise<ConfigResourceList> {
      const result = await page<ConfigResource>(
        `/api/v1/admin/system-backup-config/versions${listQuery(options.limit, options.cursor, 500)}`,
        signal, options.limit ?? 50, (item) => validConfigResource(item));
      if (result.consistency !== 'stable_cutoff' || result.next_cursor !== null && result.items.length !== (options.limit ?? 50)
        || result.items.filter((item) => item.active).length > 1
        || result.items.some((item, index) => index > 0 && (item.version >= result.items[index - 1].version
          || item.origin_installation_id !== result.items[0].origin_installation_id))) invalidResponse();
      return result;
    },
    async operation(id: string, signal: AbortSignal): Promise<SystemBackupOperation> {
      if (!operationIdPattern.test(id)) throw new BackupReadError(0, 'invalid_resource_id');
      const body = await get<SystemBackupOperation>(`/api/v1/admin/system-backup-operations/${id}`, signal);
      if (!validOperation(body, id)) invalidResponse();
      return body;
    },
    async operations(signal: AbortSignal, options: { limit?: number; cursor?: string } = {}): Promise<BackupReadPage<SystemBackupOperation>> {
      const result = await page<SystemBackupOperation>(
        `/api/v1/admin/system-backup-operations${listQuery(options.limit, options.cursor, 500)}`,
        signal, options.limit ?? 50, (item) => validOperation(item));
      if (result.consistency !== 'stable_cutoff' || result.next_cursor !== null && result.items.length !== (options.limit ?? 50)
        || new Set(result.items.map((item) => item.public_id)).size !== result.items.length
        || result.items.some((item, index) => index > 0 && item.origin_installation_id !== result.items[0].origin_installation_id)) invalidResponse();
      return result;
    },
    async detail<K extends BackupTaskKind>(kind: K, id: string, signal: AbortSignal): Promise<BackupTaskResource[K]> {
      const body = await get<BackupTaskResource[K]>(taskPath(kind, id), signal);
      if (!validTask(kind, body, id)) invalidResponse();
      return body;
    },
    async list<K extends BackupTaskKind>(kind: K, signal: AbortSignal, options: { limit?: number; status?: string; cursor?: string } = {}): Promise<BackupReadPage<BackupTaskListResource>> {
      const params = new URLSearchParams(listQuery(options.limit, options.cursor, 500).slice(1));
      if (options.status !== undefined) {
        if (!taskStatuses(kind).includes(options.status)) throw new BackupReadError(0, 'invalid_status');
        params.set('status', options.status);
      }
      const query = params.toString();
      const result = await page<BackupTaskListResource>(`${taskPaths[kind]}${query ? `?${query}` : ''}`,
        signal, options.limit ?? 50, (item) => validTaskListItem(kind, item));
      if (result.consistency !== (options.status === undefined ? 'stable_cutoff' : 'eventual')
        || options.status !== undefined && result.items.some((item) => item.status !== options.status)) invalidResponse();
      return result;
    },
    activity<K extends 'events' | 'logs'>(kind: BackupTaskKind, id: string, channel: K, signal: AbortSignal,
      options: { limit?: number; cursor?: string; context?: BackupActivityContext } = {}): Promise<BackupReadPage<K extends 'events' ? EventResource : LogEntryResource>> {
      const maximum = channel === 'events' ? 500 : 1000;
      return page<K extends 'events' ? EventResource : LogEntryResource>(
        `${taskPath(kind, id)}/${channel}${listQuery(options.limit, options.cursor, maximum)}`,
        signal, options.limit ?? 50, (item) => validActivity(channel, item, kind, id), options.context);
    },
  };
}
