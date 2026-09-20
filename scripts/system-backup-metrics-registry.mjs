import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const planPath = join(root, 'docs/system-backup-restore-division-plan.md');
const outputPath = join(root, 'contracts/system-backup/v12/metrics-alert-registry.json');
const prefix = 'clawmanager_system_backup_';

const metricParagraphMarkers = [
  '任务/协调核心集为：',
  '数据/artifact 核心集为：',
  '运维/API 核心集为：',
  'v12补充且不得由通用request counter替代的安全/新鲜度指标为：',
  'Status-relay核心集为：',
  '依赖保护窗口另输出',
  '告警表达所需配置 gauge 固定为：',
  '队列不可变预算指标为：',
  '补充队列类别指标为：',
];

function planMetricNames(plan) {
  const lines = plan.split(/\r?\n/);
  const names = [];
  for (const marker of metricParagraphMarkers) {
    const line = lines.find((candidate) => candidate.includes(marker));
    if (!line) throw new Error(`missing plan metric paragraph: ${marker}`);
    for (const match of line.matchAll(/`([^`]+)`/g)) {
      const token = match[1];
      const parsed = token.match(/^([a-z][a-z0-9_]+)(?:\{[^}]+\})?(?:=[^`]*)?$/);
      if (parsed && parsed[1] !== 'clawmanager_system_backup_') names.push(parsed[1]);
    }
  }
  const unique = [...new Set(names)];
  return unique;
}

const labelSets = {
  task_transitions_total: ['task_type', 'task_purpose', 'status'],
  tasks_current: ['task_type', 'task_purpose', 'status'],
  task_status_duration_seconds: ['task_type', 'task_purpose', 'status'],
  task_queue_age_seconds: ['task_type', 'task_purpose'],
  task_queue_deadline_utilization_ratio: ['task_type', 'task_purpose'],
  task_stuck: ['task_type', 'task_purpose'],
  operation_queue_age_seconds: ['operation_type'],
  operation_queue_deadline_utilization_ratio: ['operation_type'],
  preflight_queue_deadline_utilization_ratio: ['preflight_mode'],
  artifact_verify_queue_deadline_utilization_ratio: ['verification_scope'],
  operations_stuck: ['operation_type'],
  queue_rejections_total: ['task_type', 'failure_category'],
  eligibility_decisions_total: ['task_type', 'task_purpose', 'metric_result', 'failure_category'],
  capture_hold_seconds: ['profile', 'runner'],
  capture_hold_current_seconds: ['profile', 'runner'],
  gate_state: ['profile', 'gate_state'],
  gate_wait_seconds: ['profile', 'gate_state'],
  gate_wait_current_seconds: ['profile'],
  mutation_leases_current: ['operation_type'],
  mutation_lease_blockers_current: ['operation_type'],
  mutation_lease_oldest_age_seconds: ['operation_type'],
  mutation_lease_failures_total: ['operation_type', 'failure_category'],
  participant_state: ['participant_state'],
  participant_transition_seconds: ['participant_state'],
  participant_heartbeat_age_seconds: ['participant_state'],
  participant_heartbeat_failures_total: ['failure_category'],
  participant_resume_failures_total: ['failure_category'],
  controller_reconcile_total: ['metric_result'],
  controller_reconcile_seconds: ['metric_result'],
  claim_renew_total: ['metric_result'],
  claim_renew_failures_total: ['failure_category'],
  lease_renew_total: ['metric_result'],
  lease_renew_failures_total: ['failure_category'],
  lock_renew_failures_total: ['failure_category'],
  job_attempts_total: ['task_type', 'runner', 'metric_result'],
  job_restarts_total: ['task_type', 'runner'],
  job_start_latency_seconds: ['task_type', 'runner'],
  job_business_progress_age_seconds: ['task_type', 'runner'],
  part_bytes_total: ['task_type', 'task_purpose', 'part'],
  part_items_total: ['task_type', 'task_purpose', 'part'],
  provider_requests_total: ['provider', 'provider_role', 'metric_result'],
  provider_request_seconds: ['provider', 'provider_role', 'metric_result'],
  provider_capability_health: ['provider', 'provider_role', 'capability', 'capability_state'],
  provider_capability_expiry_timestamp_seconds: ['provider', 'provider_role', 'capability'],
  kms_requests_total: ['provider', 'metric_result'],
  kms_request_seconds: ['provider', 'metric_result'],
  dependency_health: ['dependency_kind', 'health_state'],
  dependency_last_success_timestamp_seconds: ['dependency_kind'],
  credential_expiry_timestamp_seconds: ['provider_role'],
  signing_key_expiry_timestamp_seconds: ['key_purpose'],
  signature_operations_total: ['key_purpose', 'metric_result'],
  finalizer_request_failures_total: ['external_action_type', 'failure_category'],
  external_actions_current: ['external_action_type', 'external_action_state'],
  external_action_reconcile_total: ['external_action_type', 'metric_result'],
  external_action_oldest_age_seconds: ['external_action_type', 'external_action_state'],
  finalization_resolution_rejections_total: ['failure_category'],
  provider_proof_registrations_total: ['metric_result', 'failure_category'],
  verifier_checks_total: ['task_type', 'metric_result', 'warning_category', 'failure_category'],
  normalization_failures_total: ['task_type', 'failure_category'],
  control_evidence_failures_total: ['task_type', 'failure_category'],
  isolation_rejections_total: ['profile', 'failure_category'],
  preflight_budget_utilization_ratio: ['preflight_mode', 'budget_dimension'],
  artifact_health_checks_total: ['verification_scope', 'metric_result'],
  artifact_health_check_seconds: ['verification_scope', 'metric_result'],
  artifact_usability_changes_total: ['artifact_state', 'health_reason'],
  evidence_writes_total: ['metric_result', 'failure_category'],
  evidence_download_requests_total: ['metric_result'],
  evidence_download_seconds: ['metric_result'],
  artifacts_current: ['artifact_state'],
  reader_schema_support: ['metric_result'],
  cleanup_resources_current: ['resource_lifecycle', 'cleanup_status'],
  cleanup_operations_total: ['cleanup_status', 'metric_result'],
  cleanup_duration_seconds: ['cleanup_status'],
  staging_resources_current: ['resource_lifecycle'],
  orphan_resources_current: ['resource_lifecycle'],
  prune_runs_total: ['status', 'metric_result'],
  prune_run_duration_seconds: ['status'],
  prune_delete_failures_total: ['failure_category'],
  catalog_requests_total: ['catalog_record_type', 'metric_result'],
  catalog_request_seconds: ['catalog_record_type', 'metric_result'],
  catalog_scan_total: ['status', 'metric_result'],
  catalog_scan_seconds: ['status'],
  catalog_scan_records_total: ['catalog_record_type', 'metric_result'],
  catalog_imports_current: ['status'],
  promotion_health: ['matrix', 'health_state'],
  promotion_baseline_present: ['matrix'],
  backup_recovery_readiness: ['matrix'],
  recovery_point_shortage_domains: ['matrix'],
  audit_intents_current: ['metric_result'],
  audit_failures_total: ['failure_category'],
  redaction_failures_total: ['failure_category'],
  confirmation_rejections_total: ['failure_category'],
  strong_auth_rejections_total: ['failure_category'],
  admin_api_requests_total: ['operation_type', 'metric_result'],
  admin_api_request_seconds: ['operation_type', 'metric_result'],
  artifact_finalization_pending_current: ['external_action_type'],
  artifact_finalization_oldest_age_seconds: ['external_action_type'],
  cancel_completion_seconds: ['task_type', 'metric_result'],
  orphan_gc_runs_total: ['metric_result'],
  restore_credential_destroy_failures_total: ['failure_category'],
  preflight_report_invalidations_total: ['preflight_mode', 'failure_category'],
  alert_rule_evaluations_total: ['metric_result'],
  last_succeeded_timestamp_seconds: ['task_type', 'task_purpose', 'matrix'],
  last_eligible_usable_timestamp_seconds: ['task_type', 'task_purpose', 'matrix'],
  eligible_usable_recovery_points: ['matrix'],
  contract_info: ['matrix', 'profile', 'runner'],
  provider_capability_last_success_timestamp_seconds: ['provider', 'provider_role'],
  provider_capability_refresh_failures_total: ['provider', 'provider_role', 'failure_category'],
  catalog_records_current: ['catalog_record_type', 'metric_result'],
  catalog_records_unimported_current: ['catalog_record_type'],
  catalog_record_invalid_current: ['catalog_record_type', 'failure_category'],
  status_relay_requests_total: ['metric_result', 'failure_category'],
  status_relay_request_seconds: ['metric_result'],
  status_relay_rejections_total: ['metric_result', 'failure_category'],
  dependency_protection_margin_seconds: ['dependency_kind'],
  dependency_protection_active: ['dependency_kind'],
  configured_task_deadline_seconds: ['task_type'],
  configured_operation_deadline_seconds: ['operation_type'],
  alert_profile_info: ['alert_profile'],
};

const longDurationMetrics = new Set([
  'task_status_duration_seconds', 'capture_hold_seconds', 'gate_wait_seconds',
  'cleanup_duration_seconds', 'prune_run_duration_seconds', 'cancel_completion_seconds',
]);
const requestDurationMetrics = new Set([
  'provider_request_seconds', 'kms_request_seconds', 'catalog_request_seconds',
  'admin_api_request_seconds', 'status_relay_request_seconds',
]);
const buckets = {
  request: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30],
  execution: [0.1, 0.5, 1, 2.5, 5, 10, 30, 60, 300, 900, 1800, 3600, 7200, 21600],
  standard: [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 300],
};

function metricType(name) {
  if (name.startsWith('configured_')) return 'gauge';
  if (name.endsWith('_total')) return 'counter';
  if (name.endsWith('_seconds') && !/(?:timestamp|age|margin|current)_seconds$/.test(name)) return 'histogram';
  return 'gauge';
}

function aggregation(name, type) {
  if (type === 'counter') return 'sum';
  if (type === 'histogram') return 'observe';
  if (name === 'provider_capability_health') return 'one_hot_worst_capability';
  if (name === 'dependency_health' || name === 'promotion_health') return 'one_hot_worst_health';
  if (name.endsWith('_last_success_timestamp_seconds') || name.startsWith('last_')) return 'latest_success';
  if (name.endsWith('_expiry_timestamp_seconds') || name === 'dependency_protection_margin_seconds') return 'min';
  if (name.endsWith('_queue_deadline_utilization_ratio')) return 'max';
  if (name.endsWith('_age_seconds') || name.endsWith('_current_seconds')) return 'max';
  if (/(?:_stuck|_state|_present|_readiness|_incomplete|_support|_unknown|_active|_enabled|_estimated)$/.test(name)) return 'boolean';
  return 'sum';
}

function noData(name, type, aggregate) {
  if (name.endsWith('_last_success_timestamp_seconds') || name.startsWith('last_')) return 'timestamp_zero';
  if (aggregate === 'one_hot_worst_health' || aggregate === 'one_hot_worst_capability') return 'one_hot_unknown';
  if (type === 'histogram') return 'not_emitted';
  return 'zero';
}

function metricBuckets(name, type) {
  if (type !== 'histogram') return [];
  if (requestDurationMetrics.has(name)) return buckets.request;
  if (longDurationMetrics.has(name)) return buckets.execution;
  return buckets.standard;
}

function words(name) {
  return name.replace(/_total$/, '').replace(/_seconds$/, '').replaceAll('_', ' ');
}

function help(name, type) {
  const subject = words(name);
  if (name.endsWith('_queue_deadline_utilization_ratio')) return `Maximum pending ${name.replace('_queue_deadline_utilization_ratio', '').replaceAll('_', ' ')} queue age divided by its immutable creation-time deadline window; values above one are not clipped.`;
  if (type === 'counter') return `Total number of system backup ${subject} observations.`;
  if (type === 'histogram') return `Observed system backup ${subject} in seconds.`;
  if (name.endsWith('_timestamp_seconds')) return `Unix timestamp for the system backup ${subject} value; zero means never successful.`;
  if (name.endsWith('_age_seconds') || name.endsWith('_current_seconds')) return `Current system backup ${subject} value in seconds.`;
  if (name.startsWith('configured_')) return `System backup ${words(name.slice('configured_'.length))} configured for alert evaluation.`;
  if (name.endsWith('_bytes')) return `Current system backup ${subject} value in bytes.`;
  return `Current system backup ${subject} value using the declared bounded labels.`;
}

const metric = (name) => `${prefix}${name}`;
const alerts = [];

function addAlert({
  id,
  expression,
  severity,
  forSeconds = 0,
  thresholdSource = 'current_system_config',
  dedupeKey = [],
  recoveryCondition,
  missingSeries = 'firing',
  profiles = ['production', 'development'],
  expressionLanguage = 'promql',
  counterReset,
}) {
  const clock = 2000000000;
  const fixedClockCases = [
    {
      case: 'recovered',
      clock_unix_seconds: clock,
      condition_result: false,
      condition_true_since_unix_seconds: null,
      expected_firing: false,
    },
  ];
  if (forSeconds > 0) {
    fixedClockCases.push({
      case: 'before_for',
      clock_unix_seconds: clock,
      condition_result: true,
      condition_true_since_unix_seconds: clock - forSeconds + 1,
      expected_firing: false,
    });
  }
  fixedClockCases.push({
    case: 'at_for',
    clock_unix_seconds: clock,
    condition_result: true,
    condition_true_since_unix_seconds: clock - forSeconds,
    expected_firing: true,
  });
  alerts.push({
    id,
    expression_language: expressionLanguage,
    expression,
    severity,
    for_seconds: forSeconds,
    threshold_source: thresholdSource,
    dedupe_key: dedupeKey,
    recovery_condition: recoveryCondition,
    missing_series: missingSeries,
    counter_reset: counterReset ?? (expression.includes('increase(') ? 'prometheus_increase' : expressionLanguage === 'controller_state' ? 'persisted_state_not_reset_by_restart' : 'not_applicable'),
    runbook: `system-backup/${id.replaceAll('.', '-')}`,
    profiles,
    fixed_clock_cases: fixedClockCases,
  });
}

function addProfiledInfo(base) {
  addAlert({ ...base, id: `${base.id}.production`, profiles: ['production'] });
  addAlert({ ...base, id: `${base.id}.development`, severity: 'info', profiles: ['development'] });
}

addAlert({
  id: 'backup-disabled-after-monitoring-armed.warning',
  expression: `${metric('backup_monitoring_armed')} == 1 and ${metric('effective_enabled')} == 0 and on() (${metric('alert_profile_info')}{alert_profile="production"} == 1)`,
  severity: 'warning', forSeconds: 900, profiles: ['production'], missingSeries: 'firing',
  recoveryCondition: 'effective_enabled returns to 1; monitoring armed is irreversible and kill switch does not suppress this alert',
});
addAlert({
  id: 'backup-disabled-after-monitoring-armed.critical',
  expression: `${metric('backup_monitoring_armed')} == 1 and ${metric('effective_enabled')} == 0 and on() (${metric('alert_profile_info')}{alert_profile="production"} == 1)`,
  severity: 'critical', forSeconds: 86400, profiles: ['production'], missingSeries: 'firing',
  recoveryCondition: 'effective_enabled returns to 1; monitoring armed is irreversible and kill switch does not suppress this alert',
});

addProfiledInfo({
  id: 'eligible-recovery-point-missing',
  expression: `${metric('eligible_usable_recovery_points')} == 0 and on() (${metric('backup_monitoring_armed')} == 1) and on() (time() >= ${metric('recovery_alert_deadline_timestamp_seconds')})`,
  severity: 'critical', forSeconds: 0, dedupeKey: ['matrix'], missingSeries: 'firing',
  recoveryCondition: 'an eligible usable recovery point exists for the current matrix',
});
addProfiledInfo({
  id: 'eligible-recovery-point-rpo-exceeded',
  expression: `${metric('last_eligible_usable_timestamp_seconds')} > 0 and (time() - ${metric('last_eligible_usable_timestamp_seconds')} > scalar(${metric('configured_recovery_point_objective_seconds')})) and on() (${metric('backup_monitoring_armed')} == 1)`,
  severity: 'critical', forSeconds: 300, dedupeKey: ['task_type', 'task_purpose', 'matrix'], missingSeries: 'firing',
  recoveryCondition: 'the latest eligible usable recovery point is within the configured RPO',
});
addProfiledInfo({
  id: 'recovery-point-failure-domain-shortage',
  expression: `${metric('recovery_point_shortage_domains')} > 0 and on() (${metric('backup_monitoring_armed')} == 1)`,
  severity: 'critical', forSeconds: 300, dedupeKey: ['matrix'], missingSeries: 'firing',
  recoveryCondition: 'every required failure domain has the configured minimum recovery points',
});
addProfiledInfo({
  id: 'promotion-baseline-missing',
  expression: `${metric('promotion_baseline_present')} == 0 and on() (${metric('backup_monitoring_armed')} == 1) and on() (time() >= ${metric('recovery_alert_deadline_timestamp_seconds')})`,
  severity: 'critical', forSeconds: 0, dedupeKey: ['matrix'], missingSeries: 'firing',
  recoveryCondition: 'an active promotion baseline exists for the current matrix',
});
addAlert({
  id: 'promotion-baseline-degraded',
  expression: `${metric('promotion_health')}{health_state=~"degraded|stale|unknown"} == 1`,
  severity: 'critical', dedupeKey: ['matrix', 'health_state'], missingSeries: 'unknown',
  recoveryCondition: 'all seven promotion dependency groups derive healthy',
});

for (const kind of ['task', 'operation']) {
  const utilization = kind === 'task' ? metric('task_queue_deadline_utilization_ratio') : metric('operation_queue_deadline_utilization_ratio');
  const key = kind === 'task' ? ['task_type', 'task_purpose'] : ['operation_type'];
  addProfiledInfo({
    id: `${kind}-queue-age-warning`,
    expression: `${utilization} >= 0.5`, severity: 'warning', forSeconds: 300,
    thresholdSource: 'immutable_task_config', dedupeKey: key, missingSeries: 'healthy_zero',
    recoveryCondition: `${kind} queue age falls below 50 percent of its immutable deadline or the queued work starts`,
  });
  addProfiledInfo({
    id: `${kind}-queue-age-critical`,
    expression: `${utilization} >= 0.9`, severity: 'critical', forSeconds: 0,
    thresholdSource: 'immutable_task_config', dedupeKey: key, missingSeries: 'healthy_zero',
    recoveryCondition: `${kind} queue age falls below 90 percent of its immutable deadline or the queued work starts`,
  });
}
for (const [id, metricName, key] of [
  ['preflight', 'preflight_queue_deadline_utilization_ratio', 'preflight_mode'],
  ['artifact-verify', 'artifact_verify_queue_deadline_utilization_ratio', 'verification_scope'],
]) {
  addProfiledInfo({
    id: `${id}-queue-age-warning`, expression: `${metric(metricName)} >= 0.5`, severity: 'warning', forSeconds: 300,
    thresholdSource: 'immutable_task_config', dedupeKey: [key], missingSeries: 'healthy_zero',
    recoveryCondition: `${id} queue age falls below 50 percent of its immutable deadline or the queued work starts`,
  });
  addProfiledInfo({
    id: `${id}-queue-age-critical`, expression: `${metric(metricName)} >= 0.9`, severity: 'critical', forSeconds: 0,
    thresholdSource: 'immutable_task_config', dedupeKey: [key], missingSeries: 'healthy_zero',
    recoveryCondition: `${id} queue age falls below 90 percent of its immutable deadline or the queued work starts`,
  });
}
addAlert({
  id: 'task-stuck', expression: `${metric('task_stuck')} == 1`, severity: 'critical',
  thresholdSource: 'current_system_config', dedupeKey: ['task_type', 'task_purpose'], missingSeries: 'healthy_zero',
  recoveryCondition: 'authoritative business progress resumes or the task reaches a terminal status',
});
addAlert({
  id: 'operation-stuck', expression: `${metric('operations_stuck')} == 1`, severity: 'critical',
  thresholdSource: 'current_system_config', dedupeKey: ['operation_type'], missingSeries: 'healthy_zero',
  recoveryCondition: 'authoritative business progress resumes or the operation reaches a terminal status',
});
addAlert({
  id: 'acceptance-task-failed', expression: `increase(${metric('task_transitions_total')}{task_purpose="acceptance",status="failed"}[5m]) > 0`,
  severity: 'warning', thresholdSource: 'contract_default', dedupeKey: ['task_type', 'task_purpose'], missingSeries: 'healthy_zero',
  recoveryCondition: 'the five-minute window contains no new acceptance task failure',
});
addProfiledInfo({
  id: 'acceptance-consecutive-anomalies', expressionLanguage: 'controller_state',
  expression: 'system_backup_alert_states.consecutive_anomaly_count(task_purpose=acceptance) >= 3',
  severity: 'critical', thresholdSource: 'contract_default', dedupeKey: ['task_type', 'task_purpose'], missingSeries: 'firing',
  recoveryCondition: 'an eligible success of the same acceptance task type resets the persisted sequence; functional tests never reset it',
});

addAlert({
  id: 'gate-wait-near-timeout', expression: `${metric('gate_wait_current_seconds')} >= scalar(${metric('configured_gate_acquisition_timeout_seconds')}) * 0.8`,
  severity: 'warning', thresholdSource: 'immutable_task_config', dedupeKey: ['profile'], missingSeries: 'healthy_zero',
  recoveryCondition: 'the gate is acquired, released, or wait falls below 80 percent of timeout',
});
addAlert({
  id: 'gate-wait-timeout', expression: `${metric('gate_wait_current_seconds')} >= scalar(${metric('configured_gate_acquisition_timeout_seconds')})`,
  severity: 'critical', thresholdSource: 'immutable_task_config', dedupeKey: ['profile'], missingSeries: 'healthy_zero',
  recoveryCondition: 'no gate wait remains at or beyond the acquisition timeout',
});
addAlert({
  id: 'capture-hold-near-limit', expression: `${metric('capture_hold_current_seconds')} >= scalar(${metric('configured_quiesce_max_hold_seconds')}) * 0.8`,
  severity: 'warning', thresholdSource: 'immutable_task_config', dedupeKey: ['profile', 'runner'], missingSeries: 'healthy_zero',
  recoveryCondition: 'capture hold ends or falls below 80 percent of its absolute limit',
});
addAlert({
  id: 'capture-hold-limit', expression: `${metric('capture_hold_current_seconds')} >= scalar(${metric('configured_quiesce_max_hold_seconds')})`,
  severity: 'critical', thresholdSource: 'immutable_task_config', dedupeKey: ['profile', 'runner'], missingSeries: 'healthy_zero',
  recoveryCondition: 'no capture remains at or beyond the absolute hold limit',
});
addAlert({
  id: 'mutation-lease-blocked', expression: `${metric('mutation_lease_blockers_current')} > 0 and ${metric('mutation_lease_oldest_age_seconds')} >= scalar(${metric('configured_mutation_lease_ttl_seconds')})`,
  severity: 'critical', dedupeKey: ['operation_type'], missingSeries: 'healthy_zero',
  recoveryCondition: 'all blocking mutation leases drain or return within their TTL',
});
addAlert({
  id: 'participant-error', expression: `${metric('participant_state')}{participant_state="error"} == 1`, severity: 'critical',
  thresholdSource: 'contract_default', dedupeKey: ['participant_state'], missingSeries: 'unknown',
  recoveryCondition: 'all required participants return to a non-error state and resume is confirmed',
});
addAlert({
  id: 'participant-forced-resume', expression: `increase(${metric('participant_forced_resume_total')}[5m]) > 0`, severity: 'critical',
  thresholdSource: 'contract_default', missingSeries: 'healthy_zero', recoveryCondition: 'the five-minute window contains no new forced resume',
});
addAlert({
  id: 'participant-resume-failure', expression: `increase(${metric('participant_resume_failures_total')}[5m]) > 0`, severity: 'critical',
  thresholdSource: 'contract_default', dedupeKey: ['failure_category'], missingSeries: 'healthy_zero', recoveryCondition: 'the five-minute window contains no new resume failure',
});
addAlert({
  id: 'capture-kms-identity-revocation-pending', expression: `${metric('capture_kms_identity_revocation_pending_current')} > 0`, severity: 'critical',
  thresholdSource: 'contract_default', missingSeries: 'healthy_zero', recoveryCondition: 'all capture KMS task identities have confirmed revocation',
});
addAlert({
  id: 'restore-credential-destroy-pending', expression: `${metric('restore_credential_destroy_pending_current')} > 0`, severity: 'critical',
  thresholdSource: 'contract_default', missingSeries: 'healthy_zero', recoveryCondition: 'all restore credentials have confirmed destruction',
});

addAlert({
  id: 'controller-reconcile-stale', expression: `time() - ${metric('controller_last_success_timestamp_seconds')} > 3 * ${metric('configured_controller_reconcile_interval_seconds')}`,
  severity: 'critical', missingSeries: 'firing', recoveryCondition: 'a complete controller reconcile succeeds within three configured intervals',
});
addAlert({
  id: 'artifact-health-stale', expression: `time() - ${metric('artifact_health_last_success_timestamp_seconds')} > 2 * ${metric('configured_artifact_health_interval_seconds')}`,
  severity: 'critical', missingSeries: 'firing', recoveryCondition: 'a complete artifact health pass succeeds within two configured intervals',
});
addAlert({
  id: 'catalog-scan-stale', expression: `time() - ${metric('catalog_scan_last_success_timestamp_seconds')} > 2 * ${metric('configured_catalog_scan_interval_seconds')}`,
  severity: 'critical', missingSeries: 'firing', recoveryCondition: 'a stable full catalog scan succeeds within two configured intervals',
});
addAlert({
  id: 'alert-evaluator-stale', expression: `time() - ${metric('alert_evaluator_last_success_timestamp_seconds')} > 3 * ${metric('configured_controller_reconcile_interval_seconds')}`,
  severity: 'critical', missingSeries: 'firing', recoveryCondition: 'the alert evaluator completes successfully within three controller intervals',
});

addAlert({
  id: 'finalization-unknown-over-grace', expression: `${metric('artifact_finalization_pending_current')} > 0 and ${metric('artifact_finalization_oldest_age_seconds')} > scalar(${metric('configured_finalization_resolution_grace_seconds')})`,
  severity: 'critical', dedupeKey: ['external_action_type'], missingSeries: 'healthy_zero', recoveryCondition: 'all unknown finalization actions are authoritatively resolved',
});
addAlert({
  id: 'external-action-reconcile-warning', expression: `${metric('external_actions_current')} > 0 and on() (time() - ${metric('external_action_reconcile_last_success_timestamp_seconds')} > 2 * ${metric('configured_retry_max_backoff_seconds')})`,
  severity: 'warning', dedupeKey: ['external_action_type', 'external_action_state'], missingSeries: 'firing',
  recoveryCondition: 'a bounded external-action reconcile reaches EOF and all claimed rows settle',
});
addAlert({
  id: 'external-action-reconcile-critical', expression: `${metric('external_actions_current')} > 0 and on() (time() - ${metric('external_action_reconcile_last_success_timestamp_seconds')} > 3 * ${metric('configured_retry_max_backoff_seconds')})`,
  severity: 'critical', dedupeKey: ['external_action_type', 'external_action_state'], missingSeries: 'firing',
  recoveryCondition: 'a bounded external-action reconcile reaches EOF and all claimed rows settle',
});
addAlert({
  id: 'evidence-write-near-deadline', expressionLanguage: 'controller_state',
  expression: 'oldest_pending_or_write_unknown_evidence_age >= owner_immutable_deadline * 0.9', severity: 'critical',
  thresholdSource: 'immutable_task_config', missingSeries: 'healthy_zero',
  recoveryCondition: 'every pending or write-unknown evidence row becomes ready or reaches a terminal write failure',
});

addAlert({
  id: 'cleanup-overdue', expression: `${metric('cleanup_oldest_age_seconds')} > ${metric('configured_cleanup_deadline_seconds')}`,
  severity: 'critical', dedupeKey: ['cleanup_status'], missingSeries: 'healthy_zero', recoveryCondition: 'no cleanup resource exceeds its immutable cleanup deadline',
});
addAlert({
  id: 'restore-residual-volume', expression: `${metric('restore_residual_volumes_current')} > 0`, severity: 'warning',
  thresholdSource: 'immutable_task_config', missingSeries: 'healthy_zero', recoveryCondition: 'no restore residual volume remains',
});
addAlert({
  id: 'restore-residual-volume-overdue', expression: `${metric('restore_residual_volumes_current')} > 0 and ${metric('restore_residual_volume_oldest_age_seconds')} > ${metric('configured_cleanup_deadline_seconds')}`,
  severity: 'critical', thresholdSource: 'immutable_task_config', missingSeries: 'healthy_zero', recoveryCondition: 'no restore residual volume remains beyond cleanup deadline',
});
addProfiledInfo({
  id: 'staging-capacity-warning', expression: `${metric('staging_bytes')} >= ${metric('configured_staging_capacity_bytes')} * 0.8`,
  severity: 'warning', missingSeries: 'unknown', recoveryCondition: 'staging usage falls below 80 percent of configured capacity',
});
addProfiledInfo({
  id: 'staging-capacity-critical', expression: `${metric('staging_bytes')} >= ${metric('configured_staging_capacity_bytes')}`,
  severity: 'critical', missingSeries: 'unknown', recoveryCondition: 'staging usage falls below configured capacity',
});
addAlert({
  id: 'staging-retention-overdue', expression: `${metric('staging_oldest_age_seconds')} > ${metric('configured_retention_seconds')}`,
  severity: 'critical', missingSeries: 'healthy_zero', recoveryCondition: 'no staging resource exceeds its retention deadline',
});

for (const item of [
  ['catalog-import-verification', 'catalog_import_verification_pending_current', 'catalog_import_verification_pending_oldest_age_seconds'],
  ['catalog-tombstone', 'catalog_tombstones_pending_current', 'catalog_tombstone_oldest_age_seconds'],
]) {
  addAlert({
    id: `${item[0]}-pending-warning`, expression: `${metric(item[1])} > 0 and ${metric(item[2])} > 900`,
    severity: 'warning', forSeconds: 0, thresholdSource: 'contract_default', missingSeries: 'healthy_zero',
    recoveryCondition: `no ${item[0]} remains pending beyond 900 seconds`,
  });
  addAlert({
    id: `${item[0]}-pending-critical`, expression: `${metric(item[1])} > 0 and ${metric(item[2])} > 3600`,
    severity: 'critical', forSeconds: 0, thresholdSource: 'contract_default', missingSeries: 'healthy_zero',
    recoveryCondition: `no ${item[0]} remains pending beyond 3600 seconds`,
  });
}
addAlert({
  id: 'catalog-record-invalid', expression: `${metric('catalog_record_invalid_current')} > 0`, severity: 'critical',
  thresholdSource: 'contract_default', dedupeKey: ['catalog_record_type', 'failure_category'], missingSeries: 'healthy_zero',
  recoveryCondition: 'the current succeeded catalog snapshot contains no invalid records',
});
addAlert({
  id: 'catalog-conflict', expression: `increase(${metric('catalog_conflicts_total')}[5m]) > 0`, severity: 'critical',
  thresholdSource: 'contract_default', missingSeries: 'healthy_zero', recoveryCondition: 'the five-minute window contains no new catalog conflict',
});

addAlert({
  id: 'dependency-health-unhealthy', expression: `${metric('dependency_health')}{health_state=~"degraded|unknown|stale"} == 1`, severity: 'critical',
  dedupeKey: ['dependency_kind', 'health_state'], missingSeries: 'unknown', recoveryCondition: 'the active dependency group derives healthy',
});
addAlert({
  id: 'dependency-expiry-warning',
  expression: `min({__name__=~"${prefix}(credential|ca|catalog_credential|kek|signing_key|attestation|evidence)_expiry_timestamp_seconds"}) - time() < clamp_min(${metric('configured_retention_seconds')} * 0.1, 86400)`,
  severity: 'warning', missingSeries: 'unknown', recoveryCondition: 'every active dependency expiry exceeds the configured warning window',
});
addAlert({
  id: 'dependency-protection-expired', expression: `${metric('dependency_protection_active')} == 1 and ${metric('dependency_protection_margin_seconds')} < 0`,
  severity: 'critical', dedupeKey: ['dependency_kind'], missingSeries: 'unknown', recoveryCondition: 'every protected dependency version covers its protected-until timestamp',
});
addAlert({
  id: 'strong-auth-nonce-key-expiring', expression: `${metric('strong_auth_nonce_key_expiry_timestamp_seconds')} - time() < ${metric('configured_control_metadata_retention_seconds')}`,
  severity: 'warning', missingSeries: 'firing', recoveryCondition: 'current and referenced historical nonce keys cover control metadata retention',
});
addAlert({
  id: 'strong-auth-nonce-key-expired', expression: `${metric('strong_auth_nonce_key_expiry_timestamp_seconds')} <= time()`, severity: 'critical',
  missingSeries: 'firing', recoveryCondition: 'all current and referenced nonce keys are present and unexpired',
});
addAlert({
  id: 'provider-proof-issuer-key-expiring', expressionLanguage: 'controller_state',
  expression: 'provider_proof_issuer_key_expiry_timestamp_seconds - now < max(provider_proof_max_age_seconds,evidence_retention_seconds)',
  severity: 'warning', missingSeries: 'firing', recoveryCondition: 'issuer key expiry covers provider-proof and evidence retention',
});
addAlert({
  id: 'provider-proof-issuer-key-expired', expression: `${metric('provider_proof_issuer_key_expiry_timestamp_seconds')} <= time()`, severity: 'critical',
  missingSeries: 'firing', recoveryCondition: 'all required provider-proof issuer keys are present and unexpired',
});

for (const [id, counter] of [
  ['confirmation-rejections', 'confirmation_rejections_total'],
  ['idempotency-conflicts', 'idempotency_conflicts_total'],
  ['redaction-failures', 'redaction_failures_total'],
  ['isolation-rejections', 'isolation_rejections_total'],
  ['strong-auth-rejections', 'strong_auth_rejections_total'],
]) {
  addAlert({
    id: `${id}-warning`, expression: `increase(${metric(counter)}[5m]) >= 5`, severity: 'warning',
    thresholdSource: 'contract_default', missingSeries: 'healthy_zero', recoveryCondition: `the five-minute window contains fewer than five ${id.replaceAll('-', ' ')}`,
  });
  addAlert({
    id: `${id}-critical`, expression: `increase(${metric(counter)}[5m]) >= 20`, severity: 'critical',
    thresholdSource: 'contract_default', missingSeries: 'healthy_zero', recoveryCondition: `the five-minute window contains fewer than twenty ${id.replaceAll('-', ' ')}`,
  });
}
addAlert({
  id: 'evidence-integrity-failure', expression: `increase(${metric('evidence_integrity_failures_total')}[5m]) > 0`, severity: 'critical',
  thresholdSource: 'contract_default', missingSeries: 'healthy_zero', recoveryCondition: 'the five-minute window contains no new evidence integrity failure',
});
addAlert({
  id: 'signature-or-checksum-failure', expression: `increase(${metric('signature_operations_total')}{metric_result="failed"}[5m]) > 0 or increase(${metric('verifier_checks_total')}{failure_category=~"checksum_mismatch|signature_invalid"}[5m]) > 0`,
  severity: 'critical', thresholdSource: 'contract_default', dedupeKey: ['task_type', 'failure_category'], missingSeries: 'healthy_zero',
  recoveryCondition: 'the five-minute window contains no new signature or checksum failure',
});

addProfiledInfo({
  id: 'control-metadata-capacity-warning', expression: `${metric('control_metadata_bytes')} >= ${metric('configured_control_metadata_capacity_bytes')} * 0.8`,
  severity: 'warning', missingSeries: 'unknown', recoveryCondition: 'control metadata usage falls below 80 percent of configured capacity',
});
addAlert({
  id: 'control-metadata-safety-reserve',
  expression: `${metric('configured_control_metadata_capacity_bytes')} - ${metric('control_metadata_bytes')} < ${metric('control_metadata_safety_reserve_bytes')} or ${metric('control_database_available_bytes')} < ${metric('control_metadata_safety_reserve_bytes')} or ${metric('control_metadata_size_estimated')} == 1`,
  severity: 'critical', missingSeries: 'firing', recoveryCondition: 'both logical and physical headroom exceed the safety reserve with a reliable size measurement',
});
for (const owner of ['control_metadata', 'evidence']) {
  const failures = owner === 'control_metadata' ? 'control_metadata_gc_failures_total' : 'evidence_gc_failures_total';
  const last = owner === 'control_metadata' ? 'control_metadata_gc_last_success_timestamp_seconds' : 'evidence_gc_last_success_timestamp_seconds';
  const enabled = owner === 'control_metadata' ? `${metric('control_metadata_prunable_oldest_age_seconds')} > 0` : `${metric('evidence_gc_pending_objects')} > 0`;
  addAlert({
    id: `${owner.replace('_', '-')}-gc-consecutive-failures`, expression: `increase(${metric(failures)}[15m]) >= 3`, severity: 'critical',
    thresholdSource: 'contract_default', missingSeries: 'healthy_zero', recoveryCondition: `fewer than three ${owner} GC failures occur in fifteen minutes`,
  });
  addAlert({
    id: `${owner.replace('_', '-')}-gc-stale`, expression: `${enabled} and time() - ${metric(last)} > 3 * clamp_min(2 * ${metric('configured_controller_reconcile_interval_seconds')}, 300)`,
    severity: 'critical', missingSeries: 'firing', recoveryCondition: `${owner} GC completes an enabled bounded scan within three evaluation periods`,
  });
}

addAlert({
  id: 'provider-capability-refresh-stale',
  expression: `time() - ${metric('provider_capability_last_success_timestamp_seconds')} > 3 * scalar(${metric('configured_artifact_health_interval_seconds')})`,
  severity: 'critical', dedupeKey: ['provider', 'provider_role'], missingSeries: 'firing', recoveryCondition: 'the full required capability probe set succeeds atomically for the current references',
});
addAlert({
  id: 'source-writer-registry-drift', expression: `${metric('source_writer_registry_drift_current')} == 1 or ${metric('source_writer_registry_check_unknown')} == 1`,
  severity: 'critical', missingSeries: 'firing', recoveryCondition: 'a complete source-writer inventory check records clean',
});
addAlert({
  id: 'source-writer-registry-check-stale',
  expression: `time() - ${metric('source_writer_registry_check_last_success_timestamp_seconds')} > 3 * ${metric('configured_artifact_health_interval_seconds')}`,
  severity: 'critical', missingSeries: 'firing', recoveryCondition: 'a complete source-writer registry check records clean within three artifact-health intervals',
});
addAlert({
  id: 'log-ingest-stale', expression: `${metric('log_ingest_backlog')} > 0 and time() - ${metric('log_ingest_last_success_timestamp_seconds')} > 3 * clamp_min(2 * ${metric('configured_retry_max_backoff_seconds')}, 60)`,
  severity: 'critical', missingSeries: 'firing', recoveryCondition: 'a complete redacted log chunk becomes ready while backlog exists',
});
addAlert({
  id: 'orphan-gc-stale', expression: `${metric('orphan_resources_current')} > 0 and on() (time() - ${metric('orphan_gc_last_success_timestamp_seconds')} > 3 * ${metric('configured_orphan_safety_window_seconds')})`,
  severity: 'critical', dedupeKey: ['resource_lifecycle'], missingSeries: 'firing', recoveryCondition: 'an enabled bounded orphan scan reaches EOF and all claims settle',
});
addAlert({
  id: 'evidence-reconcile-stale', expression: `${metric('evidence_write_pending_current')} > 0 and time() - ${metric('evidence_reconcile_last_success_timestamp_seconds')} > 3 * clamp_min(2 * ${metric('configured_retry_max_backoff_seconds')}, 60)`,
  severity: 'critical', missingSeries: 'firing', recoveryCondition: 'an enabled bounded evidence reconcile reaches EOF and all claims settle',
});
addAlert({
  id: 'status-relay-stale', expression: `time() - ${metric('status_relay_last_success_timestamp_seconds')} > clamp_min(2 * ${metric('configured_retry_max_backoff_seconds')}, 60)`,
  severity: 'warning', missingSeries: 'unknown', recoveryCondition: 'status relay succeeds while an active task depends on it',
});
addAlert({
  id: 'status-relay-rejections-warning', expression: `increase(${metric('status_relay_rejections_total')}[5m]) >= 5`, severity: 'warning',
  thresholdSource: 'contract_default', dedupeKey: ['metric_result', 'failure_category'], missingSeries: 'healthy_zero', recoveryCondition: 'the five-minute window contains fewer than five relay rejections',
});
addAlert({
  id: 'status-relay-rejections-critical', expression: `increase(${metric('status_relay_rejections_total')}[5m]) >= 20`, severity: 'critical',
  thresholdSource: 'contract_default', dedupeKey: ['metric_result', 'failure_category'], missingSeries: 'healthy_zero', recoveryCondition: 'the five-minute window contains fewer than twenty relay rejections',
});

function buildRegistry() {
  const plan = readFileSync(planPath, 'utf8');
  const names = planMetricNames(plan);
  const metrics = names.map((name) => {
    const type = metricType(name);
    const aggregate = aggregation(name, type);
    return {
      name: `${prefix}${name}`,
      type,
      help: help(name, type),
      labels: labelSets[name] ?? [],
      aggregation: aggregate,
      no_data: noData(name, type, aggregate),
      buckets: metricBuckets(name, type),
    };
  });
  return {
    registry_version: 'system-backup-metrics-alerts.v1',
    contract_version: 'system-backup-plan.v12',
    status: 'draft',
    source: {
      plan: 'docs/system-backup-restore-division-plan.md',
      section: '15',
      metric_count: metrics.length,
      alert_count: alerts.length,
    },
    metrics,
    alerts,
  };
}

const rendered = `${JSON.stringify(buildRegistry(), null, 2)}\n`;
if (process.argv.includes('--write')) {
  writeFileSync(outputPath, rendered, 'utf8');
} else if (process.argv.includes('--check')) {
  const current = readFileSync(outputPath, 'utf8');
  if (current !== rendered) {
    console.error('metrics-alert-registry.json is stale; run node scripts/system-backup-metrics-registry.mjs --write');
    process.exitCode = 1;
  }
} else {
  process.stdout.write(rendered);
}
