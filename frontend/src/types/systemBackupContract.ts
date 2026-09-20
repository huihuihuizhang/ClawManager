// Wire-only DTO snapshot for the draft system-backup-plan.v12 contract.
// Runtime behavior must not be implemented in this module.

export const taskTypes = ["backup", "drill", "preflight", "artifact_verify"] as const;
export const backupStatuses = ["pending", "preparing", "ready_for_capture", "acquiring_gate", "capturing", "validating", "publishing", "finalization_unknown", "canceling", "succeeded", "failed", "canceled"] as const;
export const drillStatuses = ["pending", "preflighting", "provisioning", "restoring", "normalizing", "verifying", "canceling", "succeeded", "failed", "canceled"] as const;
export const simpleTaskStatuses = ["pending", "running", "canceling", "succeeded", "failed", "canceled"] as const;
export const operationStatuses = ["pending", "running", "succeeded", "failed"] as const;
export const operationTypes = ["cancel", "cleanup", "ownership_resolution", "provider_proof_register", "finalization_resolution", "manual_hold_update", "config_update", "promotion_create", "promotion_revoke", "catalog_scan", "catalog_import", "prune_execute", "prune_retry", "artifact_health_reconcile", "orphan_gc", "control_metadata_gc", "evidence_gc"] as const;
export const failureCategories = ["none", "canceled_by_actor", "canceled_by_shutdown", "validation_failed", "permission_denied", "not_found", "not_ready", "conflict_active_job", "unsupported_runner_p1", "unsupported_profile_p1", "unsupported_datasource_p1", "unsupported_schema", "backup_target_risk_rejected", "isolation_invalid", "writer_registry_drift", "quiesce_timeout", "quiesce_resume_failed", "capacity_exceeded", "deadline_exceeded", "preflight_failed", "normalization_failed", "control_evidence_invalid", "artifact_unavailable", "artifact_conflict", "checksum_mismatch", "signature_invalid", "encryption_key_unavailable", "kek_permission_denied", "signing_key_unavailable", "finalizer_request_unavailable", "catalog_unavailable", "catalog_conflict", "catalog_tombstone_failed", "secret_bundle_failed", "redaction_failed", "audit_failed", "evidence_incomplete", "staging_cleanup_failed", "cleanup_unsafe_target", "confirmation_invalid", "fencing_token_lost", "coordination_invalid", "artifact_delete_failed", "runner_failed", "internal_error"] as const;

export type TaskType = (typeof taskTypes)[number];
export type TaskStatus = (typeof backupStatuses)[number] | (typeof drillStatuses)[number] | (typeof simpleTaskStatuses)[number];
export type OperationStatus = (typeof operationStatuses)[number];
export type OperationType = (typeof operationTypes)[number];
export type FailureCategory = (typeof failureCategories)[number];

export interface SystemBackupTask {
  schema_version: "system-backup-task.v1";
  public_id: string;
  origin_installation_id: string;
  task_type: TaskType;
  actor_type: "admin" | "system";
  actor_id: string;
  endpoint: string;
  idempotency_key: string;
  request_hash: string;
  request_id: string;
  retry_of_public_id: string | null;
  status: TaskStatus;
  pending_reason: "none" | "global_capture_queue" | "kill_switch" | "dependency_backoff";
  attention_reason: "none" | "external_result_unknown";
  can_cancel: boolean;
  config_version: number;
  retryable: boolean;
  failure_category: FailureCategory;
  failure_message: string | null;
  heartbeat_at: string | null;
  row_version: number;
  next_reconcile_at: string | null;
  deadline_at: string;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface SystemBackupOperation {
  schema_version: "system-backup-operation.v1";
  public_id: string;
  origin_installation_id: string;
  operation_type: OperationType;
  target_type: "backup" | "backup_staging" | "external_action" | "drill" | "restore_resource" | "preflight" | "artifact_verify" | "catalog_scan" | "catalog_import" | "prune_run" | "promotion" | "matrix" | "system";
  target_public_id: string;
  actor_type: "admin" | "system";
  actor_id: string;
  endpoint: string;
  idempotency_key: string;
  request_hash: string;
  status: OperationStatus;
  result_resource_public_id: string | null;
  result_config_version: number | null;
  retryable: boolean;
  failure_category: FailureCategory;
  failure_message: string | null;
  http_status: number | null;
  row_version: number;
  deadline_at: string;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface TaskList {
  items: SystemBackupTask[];
  next_cursor: string | null;
  consistency: "stable_cutoff" | "eventual";
}

export interface OperationList {
  items: SystemBackupOperation[];
  next_cursor: string | null;
  consistency: "stable_cutoff" | "eventual";
}

// D-owned business request fields. A-owned authentication transport such as
// strong_auth_proof is intentionally not represented or request-hashed here.
export interface CancelRequest {
}

export interface CleanupRequest {
  retry_of_operation_public_id: string | null;
}

export interface ConfigRollbackRequest {
  rollback_from_version: number;
  expected_version: number;
  change_reason: string | null;
}

export interface FinalizationResolutionRequest {
  external_action_public_id: string;
  expected_backup_row_version: number;
  provider_proof_evidence_public_id: string;
}

export interface OwnershipResolutionRequest {
  expected_resource_row_version: number;
  provider_proof_evidence_public_id: string;
}

export interface ManualHoldUpdateRequest {
  manual_hold: boolean;
  expected_backup_row_version: number;
  reason: string | null;
}

export interface PromotionCreateRequest {
  backup_public_id: string;
  drill_public_id: string;
  expected_backup_row_version: number;
  expected_drill_row_version: number;
  expected_prune_guard_version: number;
  expected_active_promotion_public_id: string | null;
  expected_active_promotion_row_version: number | null;
}

export interface PromotionRevokeRequest {
  expected_promotion_public_id: string;
  expected_promotion_row_version: number;
  reason: string;
}

export interface PruneConfirmationRequest {
  expected_prune_run_row_version: number;
}

export interface PruneExecuteRequest {
  prune_run_public_id: string;
  confirmation_id: string;
  expected_prune_run_row_version: number;
}

export interface PruneRetryRequest {
  expected_prune_run_row_version: number;
}

// D-owned control-plane projections. External provider and security-owner
// configuration is represented only by redacted identity hashes and versions.
export interface ConfigReference {
  purpose: "artifact_write" | "artifact_read" | "artifact_delete" | "artifact_upload_issuer" | "artifact_ca" | "evidence_store" | "evidence_write" | "evidence_read" | "evidence_delete" | "evidence_ca" | "evidence_kek" | "kek" | "capture_signing" | "acceptance_signing" | "catalog_signing" | "catalog_read" | "catalog_append" | "catalog_snapshot" | "nonce_hmac" | "status_relay";
  identity_hash: string;
  version: string;
}

export interface RegistryReference {
  registry_kind: "parts" | "redis_sources" | "failure_domains" | "disaster_identity_mapping" | "source_writers" | "rbac_bindings" | "secret_allowlist" | "strong_auth_issuers" | "provider_proof_issuers";
  version: string;
  sha256: string;
}

export interface DurationConfig {
  controller_claim_ttl_seconds: number;
  controller_claim_heartbeat_seconds: number;
  controller_reconcile_interval_seconds: number;
  mutation_lease_ttl_seconds: number;
  mutation_lease_heartbeat_seconds: number;
  artifact_lease_ttl_seconds: number;
  artifact_lease_heartbeat_seconds: number;
  gate_acquisition_timeout_seconds: number;
  quiesce_max_hold_seconds: number;
  maintenance_lock_ttl_seconds: number;
  watchdog_db_unavailable_grace_seconds: number;
  watchdog_safety_margin_seconds: number;
  staging_retention_seconds: number;
  retention_seconds: number;
  prune_candidate_ttl_seconds: number;
  confirmation_ttl_seconds: number;
  logs_retention_seconds: number;
  evidence_retention_seconds: number;
  promotion_health_max_age_seconds: number;
  task_cancel_deadline_seconds: number;
  cleanup_deadline_seconds: number;
  retry_initial_backoff_seconds: number;
  retry_max_backoff_seconds: number;
  orphan_safety_window_seconds: number;
  artifact_health_interval_seconds: number;
  catalog_scan_interval_seconds: number;
  catalog_scan_deadline_seconds: number;
  provider_consistency_window_seconds: number;
  redis_clock_skew_seconds: number;
  strong_auth_max_age_seconds: number;
  strong_auth_clock_skew_seconds: number;
  provider_proof_max_age_seconds: number;
  capture_certificate_ttl_seconds: number;
  finalization_resolution_grace_seconds: number;
  recovery_point_objective_seconds: number;
  first_enable_recovery_alert_grace_seconds: number;
  control_metadata_retention_seconds: number;
  backup_task_deadline_seconds: number;
  drill_task_deadline_seconds: number;
  preflight_task_deadline_seconds: number;
  artifact_verify_task_deadline_seconds: number;
  operation_deadline_seconds: number;
  finalization_resolution_deadline_seconds: number;
  prune_operation_deadline_seconds: number;
}

export interface CapacityConfig {
  control_metadata_capacity_bytes: number;
  staging_capacity_bytes: number;
  max_artifact_bytes: number;
  max_index_bytes: number;
  max_plaintext_buffer_bytes: number;
  max_source_items: number;
  minimum_capture_throughput_bytes_per_second: number;
  source_size_safety_factor: number;
  max_log_bytes: number;
  max_log_lines: number;
  log_chunk_bytes: number;
  log_chunk_lines: number;
}

export interface ConcurrencyConfig {
  max_concurrent_drills: number;
  max_concurrent_preflights: number;
  max_concurrent_artifact_verifications: number;
  max_pending_tasks: number;
  max_auto_attempts: number;
}

export interface PreflightLimits {
  query_timeout_seconds: number;
  provider_qps: number;
  max_scan_bytes: number;
  max_scan_items: number;
}

export interface ConfigValues {
  enabled: boolean;
  alert_profile: "production" | "development";
  minimum_recovery_points: number;
  durations: DurationConfig;
  capacity: CapacityConfig;
  concurrency: ConcurrencyConfig;
  preflight_limits: PreflightLimits;
  registries: RegistryReference[];
  references: ConfigReference[];
}

export interface ConfigUpdateRequest {
  expected_version: number;
  change_reason: string | null;
  config: ConfigValues;
}

export interface ConfigResource {
  schema_version: "system-backup-config.v1";
  origin_installation_id: string;
  version: number;
  row_version: number;
  active: boolean;
  effective_enabled: boolean;
  config: ConfigValues;
  created_by: string;
  change_reason: string | null;
  created_at: string;
}

export interface FailureDomainShortage {
  target_failure_domain_id: string;
  minimum_recovery_points: number;
  eligible_usable_recovery_points: number;
}

export interface OverviewResource {
  schema_version: "system-backup-overview.v1";
  origin_installation_id: string;
  config_version: number;
  effective_enabled: boolean;
  monitoring_armed: boolean;
  monitoring_armed_reason: "none" | "deployment_required" | "previously_enabled";
  matrix: "k8s-cluster" | "k3s-cluster" | "k8s-single-node" | "k3s-single-node";
  backup_recovery_readiness: boolean;
  baseline_present: boolean;
  controller_health: "healthy" | "degraded" | "unknown" | "stale";
  database_health: "healthy" | "degraded" | "unknown" | "stale";
  artifact_target_health: "healthy" | "degraded" | "unknown" | "stale";
  evidence_store_health: "healthy" | "degraded" | "unknown" | "stale";
  catalog_health: "healthy" | "degraded" | "unknown" | "stale";
  source_writer_state: "clean" | "drift" | "unknown";
  active_task_count: number;
  active_operation_count: number;
  finalization_unknown_count: number;
  cleanup_backlog_count: number;
  ownership_resolution_backlog_count: number;
  shortage_failure_domains: FailureDomainShortage[];
  observed_at: string;
}

export interface PruneRunResource {
  schema_version: "system-backup-prune-run.v1";
  public_id: string;
  status: "planning" | "dry_run_created" | "executing" | "partial_failed" | "succeeded" | "failed" | "expired";
  retryable: boolean;
  config_version: number;
  older_than: string;
  candidate_hash: string | null;
  candidate_count: number | null;
  candidate_bytes: number | null;
  candidate_expires_at: string | null;
  confirmation_status: "none" | "issued" | "consumed" | "expired";
  confirmation_expires_at: string | null;
  planned_items: number;
  blocked_items: number;
  deleting_items: number;
  deleted_items: number;
  delete_failed_items: number;
  failure_category: FailureCategory;
  row_version: number;
  started_at: string;
  execution_started_at: string | null;
  execution_finished_at: string | null;
  finished_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface PruneConfirmationResource {
  schema_version: "system-backup-prune-confirmation.v1";
  prune_run_public_id: string;
  confirmation_id: string;
  status: "issued" | "consumed" | "expired";
  candidate_hash: string;
  candidate_count: number;
  candidate_bytes: number;
  cutoff_at: string;
  config_version: number;
  expires_at: string;
  consumed_at: string | null;
  prune_run_row_version: number;
}

export interface EventDetails {
  previous_status: string | null;
  current_status: string | null;
  reason: string | null;
  attempt_number: number | null;
  operation_public_id: string | null;
  evidence_public_id: string | null;
  truncated: boolean;
  original_size: number | null;
  content_hash: string | null;
}

export interface EventResource {
  schema_version: "system-backup-event.v1";
  target_type: "backup" | "drill" | "preflight" | "artifact_verify" | "catalog_import" | "promotion" | "cleanup" | "prune_run" | "catalog_scan" | "catalog_record" | "operation" | "system";
  target_public_id: string;
  event_type: string;
  level: "info" | "warning" | "error" | "critical";
  task_status: TaskStatus | null;
  message: string;
  details: EventDetails | null;
  request_id: string | null;
  created_at: string;
}

export interface EventResourceList {
  items: EventResource[];
  next_cursor: string | null;
  consistency: "stable_cutoff" | "eventual";
}

export interface LogEntryResource {
  schema_version: "system-backup-log-entry.v1";
  task_type: TaskType;
  task_public_id: string;
  attempt_number: number;
  phase: "capture" | "secret_capture" | "publish" | "restore" | "normalize" | "verify" | "preflight";
  job_generation: number;
  chunk_sequence: number;
  line_index: number;
  timestamp: string;
  stream: "stdout" | "stderr";
  level: "info" | "warning" | "error" | "unknown";
  message: string;
}

export interface LogEntryResourceList {
  items: LogEntryResource[];
  next_cursor: string | null;
  consistency: "stable_cutoff" | "eventual";
}

export interface PruneItemResource {
  schema_version: "system-backup-prune-item.v1";
  public_id: string;
  prune_run_public_id: string;
  artifact_public_id: string;
  item_type: "object_version" | "delete_marker" | "catalog_tombstone";
  status: "planned" | "blocked_by_delete" | "deleting" | "deleted" | "delete_failed";
  locator_hash: string | null;
  immutable_version: string | null;
  catalog_record_hash: string | null;
  bytes: number;
  last_operation_public_id: string | null;
  attempt: number;
  item_failure_code: "none" | "deadline_exceeded" | "provider_unavailable" | "permission_denied" | "identity_mismatch" | "checksum_mismatch" | "catalog_conflict" | "internal";
  external_action_public_id: string | null;
  row_version: number;
  created_at: string;
  updated_at: string;
}

export interface PruneItemResourceList {
  items: PruneItemResource[];
  next_cursor: string | null;
  consistency: "stable_cutoff" | "eventual";
}

export interface PromotionHealth {
  artifact: "healthy" | "degraded" | "unknown" | "stale";
  artifact_access: "healthy" | "degraded" | "unknown" | "stale";
  kek: "healthy" | "degraded" | "unknown" | "stale";
  signature: "healthy" | "degraded" | "unknown" | "stale";
  catalog: "healthy" | "degraded" | "unknown" | "stale";
  evidence: "healthy" | "degraded" | "unknown" | "stale";
  attestation: "healthy" | "degraded" | "unknown" | "stale";
  current_health: "healthy" | "degraded" | "unknown";
  observed_at: string;
}

export interface PromotionResource {
  schema_version: "system-backup-promotion.v1";
  public_id: string;
  origin_installation_id: string;
  matrix: "k8s-cluster" | "k3s-cluster" | "k8s-single-node" | "k3s-single-node";
  record_status: "active" | "superseded" | "revoked";
  backup_public_id: string;
  drill_public_id: string;
  manifest_checksum: string;
  acceptance_checksum: string;
  artifact_registration_id: string;
  artifact_registration_hash: string;
  eligibility_decision_hash: string;
  drill_evidence_public_id: string;
  drill_evidence_hash: string;
  health: PromotionHealth;
  created_by: string;
  created_at: string;
  superseded_by_public_id: string | null;
  superseded_at: string | null;
  revoked_by: string | null;
  revoked_reason: string | null;
  revoked_at: string | null;
  row_version: number;
}

export interface PromotionResourceList {
  items: PromotionResource[];
  next_cursor: string | null;
  consistency: "stable_cutoff" | "eventual";
}

// D-owned task detail projections. Owner payloads stay behind typed evidence,
// source and immutable config-hash references.
export interface EvidenceReference {
  public_id: string;
  sha256: string;
}

export interface SourceArtifactReference {
  source_artifact_type: "backup" | "catalog_import";
  source_public_id: string;
}

export interface ExecutionProjection {
  current_attempt_number: number | null;
  current_phase: "capture" | "secret_capture" | "publish" | "restore" | "normalize" | "verify" | "preflight" | null;
  job_generation: number | null;
  last_business_progress_at: string | null;
}

export interface VerifierSummary {
  aggregate_status: "passed" | "warning" | "failed" | "skipped";
  passed: number;
  warning: number;
  failed: number;
  skipped: number;
  report_evidence: EvidenceReference | null;
}

export interface NullableArtifactChecksumSet {
  manifest: string | null;
  index: string | null;
  marker: string | null;
  acceptance: string | null;
  catalog: string | null;
}

export interface BackupDetailResource {
  schema_version: "system-backup-backup-detail.v1";
  task: SystemBackupTask;
  execution: ExecutionProjection;
  task_purpose: "acceptance" | "functional_test";
  source_orchestrator: "kubernetes" | "k3s";
  source_profile: "cluster" | "single-node";
  matrix: "k8s-cluster" | "k3s-cluster" | "k8s-single-node" | "k3s-single-node";
  datasource_topology: "in_cluster";
  runner: "k8s" | "k3s";
  requested_parts: Array<"mysql" | "redis" | "object_storage" | "workspace" | "deployment_resources" | "secret_bundle">;
  artifact_state: "staging" | "committed" | "deleting" | "delete_failed" | "deleted" | "corrupt";
  artifact_usable: boolean;
  artifact_unusable_reason: "none" | "not_committed" | "finalization_pending" | "deleting" | "delete_failed" | "deleted" | "corrupt" | "provider_unavailable" | "credential_unavailable" | "kek_unavailable" | "evidence_unavailable" | "verification_inconclusive";
  artifact_committed_at: string | null;
  acceptance_ready: boolean;
  acceptance_eligible: boolean;
  eligibility_reason_codes: string[];
  eligibility_decision_hash: string | null;
  target_class: "dr-ready-external" | "same-cluster-copy";
  target_risks: string[];
  target_failure_domain_id: string;
  consistency: "strong" | "bounded" | "weak";
  checksums: NullableArtifactChecksumSet;
  artifact_registration_id: string | null;
  artifact_registration_hash: string | null;
  verifier_summary: VerifierSummary;
  manual_hold: boolean;
  manual_hold_reason: string | null;
  manual_hold_actor: string | null;
  manual_hold_at: string | null;
  promotion_hold: boolean;
  bytes: number | null;
  prune_guard_version: number;
}

export interface DrillDetailResource {
  schema_version: "system-backup-drill-detail.v1";
  task: SystemBackupTask;
  execution: ExecutionProjection;
  source: SourceArtifactReference;
  source_checksums: NullableArtifactChecksumSet;
  task_purpose: "acceptance" | "functional_test";
  target_profile: "cluster" | "single-node";
  restore_target_config_hash: string;
  cleanup_policy: "delete-on-success" | "retain-always";
  cleanup_status: "not_started" | "pending" | "running" | "succeeded" | "failed" | "partial_failed" | "retained";
  cleanup_failure_code: "none" | "deadline_exceeded" | "provider_unavailable" | "permission_denied" | "identity_mismatch" | "checksum_mismatch" | "ownership_unknown" | "residual_data" | "internal";
  preflight_evidence: EvidenceReference | null;
  diff_evidence: EvidenceReference | null;
  verifier_summary: VerifierSummary;
  consistency: "strong" | "bounded" | "weak" | null;
  acceptance_eligible: boolean;
  eligibility_reason_codes: string[];
  eligibility_decision_hash: string | null;
}

export interface PreflightDetailResource {
  schema_version: "system-backup-preflight-detail.v1";
  task: SystemBackupTask;
  execution: ExecutionProjection;
  source: SourceArtifactReference;
  source_checksums: NullableArtifactChecksumSet;
  preflight_mode: "production_readonly" | "functional_test";
  target_profile: "cluster" | "single-node";
  restore_target_config_hash: string;
  artifact_compatibility: "supported" | "compatible_with_warnings" | "unsupported";
  report_evidence: EvidenceReference | null;
  diff_evidence: EvidenceReference | null;
  report_validity_reason: "pending" | "valid" | "functional_test_only" | "source_changed" | "dependency_unhealthy" | "report_expired" | "evidence_unavailable" | "incomplete";
  verifier_summary: VerifierSummary;
}

export interface ArtifactVerificationDetailResource {
  schema_version: "system-backup-artifact-verification-detail.v1";
  task: SystemBackupTask;
  execution: ExecutionProjection;
  verification_scope: "health" | "full";
  source: SourceArtifactReference;
  observed_checksums: NullableArtifactChecksumSet;
  health_report_evidence: EvidenceReference | null;
  artifact_state_before: "staging" | "committed" | "deleting" | "delete_failed" | "deleted" | "corrupt" | null;
  artifact_state_after: "staging" | "committed" | "deleting" | "delete_failed" | "deleted" | "corrupt" | null;
  usable_before: boolean;
  usable_after: boolean;
  unusable_reason_before: string;
  unusable_reason_after: string;
  decision_reason: "pending" | "unchanged" | "restored_usable" | "marked_unusable" | "marked_corrupt" | "catalog_tombstoned" | "verification_inconclusive";
  verifier_summary: VerifierSummary;
}
