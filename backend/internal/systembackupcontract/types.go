// Package systembackupcontract contains wire-only DTO snapshots for the draft
// system-backup-plan.v12 contract. Runtime behavior must not be implemented in
// this package.
package systembackupcontract

var TaskTypes = []string{"backup", "drill", "preflight", "artifact_verify"}
var BackupStatuses = []string{"pending", "preparing", "ready_for_capture", "acquiring_gate", "capturing", "validating", "publishing", "finalization_unknown", "canceling", "succeeded", "failed", "canceled"}
var DrillStatuses = []string{"pending", "preflighting", "provisioning", "restoring", "normalizing", "verifying", "canceling", "succeeded", "failed", "canceled"}
var SimpleTaskStatuses = []string{"pending", "running", "canceling", "succeeded", "failed", "canceled"}
var OperationStatuses = []string{"pending", "running", "succeeded", "failed"}
var OperationTypes = []string{"cancel", "cleanup", "ownership_resolution", "provider_proof_register", "finalization_resolution", "manual_hold_update", "config_update", "promotion_create", "promotion_revoke", "catalog_scan", "catalog_import", "prune_execute", "prune_retry", "artifact_health_reconcile", "orphan_gc", "control_metadata_gc", "evidence_gc"}
var FailureCategories = []string{"none", "canceled_by_actor", "canceled_by_shutdown", "validation_failed", "permission_denied", "not_found", "not_ready", "conflict_active_job", "unsupported_runner_p1", "unsupported_profile_p1", "unsupported_datasource_p1", "unsupported_schema", "backup_target_risk_rejected", "isolation_invalid", "writer_registry_drift", "quiesce_timeout", "quiesce_resume_failed", "capacity_exceeded", "deadline_exceeded", "preflight_failed", "normalization_failed", "control_evidence_invalid", "artifact_unavailable", "artifact_conflict", "checksum_mismatch", "signature_invalid", "encryption_key_unavailable", "kek_permission_denied", "signing_key_unavailable", "finalizer_request_unavailable", "catalog_unavailable", "catalog_conflict", "catalog_tombstone_failed", "secret_bundle_failed", "redaction_failed", "audit_failed", "evidence_incomplete", "staging_cleanup_failed", "cleanup_unsafe_target", "confirmation_invalid", "fencing_token_lost", "coordination_invalid", "artifact_delete_failed", "runner_failed", "internal_error"}

// Task is the public task envelope shared by backup, drill, preflight and
// artifact-verification resources.
type Task struct {
	SchemaVersion        string  `json:"schema_version"`
	PublicID             string  `json:"public_id"`
	OriginInstallationID string  `json:"origin_installation_id"`
	TaskType             string  `json:"task_type"`
	ActorType            string  `json:"actor_type"`
	ActorID              string  `json:"actor_id"`
	Endpoint             string  `json:"endpoint"`
	IdempotencyKey       string  `json:"idempotency_key"`
	RequestHash          string  `json:"request_hash"`
	RequestID            string  `json:"request_id"`
	RetryOfPublicID      *string `json:"retry_of_public_id"`
	Status               string  `json:"status"`
	PendingReason        string  `json:"pending_reason"`
	AttentionReason      string  `json:"attention_reason"`
	CanCancel            bool    `json:"can_cancel"`
	ConfigVersion        int64   `json:"config_version"`
	Retryable            bool    `json:"retryable"`
	FailureCategory      string  `json:"failure_category"`
	FailureMessage       *string `json:"failure_message"`
	HeartbeatAt          *string `json:"heartbeat_at"`
	RowVersion           int64   `json:"row_version"`
	NextReconcileAt      *string `json:"next_reconcile_at"`
	DeadlineAt           string  `json:"deadline_at"`
	StartedAt            *string `json:"started_at"`
	FinishedAt           *string `json:"finished_at"`
	CreatedAt            string  `json:"created_at"`
	UpdatedAt            string  `json:"updated_at"`
}

// Operation is the public idempotent mutation ledger envelope.
type Operation struct {
	SchemaVersion          string  `json:"schema_version"`
	PublicID               string  `json:"public_id"`
	OriginInstallationID   string  `json:"origin_installation_id"`
	OperationType          string  `json:"operation_type"`
	TargetType             string  `json:"target_type"`
	TargetPublicID         string  `json:"target_public_id"`
	ActorType              string  `json:"actor_type"`
	ActorID                string  `json:"actor_id"`
	Endpoint               string  `json:"endpoint"`
	IdempotencyKey         string  `json:"idempotency_key"`
	RequestHash            string  `json:"request_hash"`
	Status                 string  `json:"status"`
	ResultResourcePublicID *string `json:"result_resource_public_id"`
	ResultConfigVersion    *int64  `json:"result_config_version"`
	Retryable              bool    `json:"retryable"`
	FailureCategory        string  `json:"failure_category"`
	FailureMessage         *string `json:"failure_message"`
	HTTPStatus             *int    `json:"http_status"`
	RowVersion             int64   `json:"row_version"`
	DeadlineAt             string  `json:"deadline_at"`
	StartedAt              *string `json:"started_at"`
	FinishedAt             *string `json:"finished_at"`
	CreatedAt              string  `json:"created_at"`
	UpdatedAt              string  `json:"updated_at"`
}

type TaskList struct {
	Items       []Task  `json:"items"`
	NextCursor  *string `json:"next_cursor"`
	Consistency string  `json:"consistency"`
}

type OperationList struct {
	Items       []Operation `json:"items"`
	NextCursor  *string     `json:"next_cursor"`
	Consistency string      `json:"consistency"`
}

// The request DTOs below contain D-owned business fields only. Authentication
// transport fields such as strong_auth_proof remain in the A-owned boundary and
// are deliberately excluded from request hashing and these structs.
type CancelRequest struct {
}

type CleanupRequest struct {
	RetryOfOperationPublicID *string `json:"retry_of_operation_public_id"`
}

type ConfigRollbackRequest struct {
	RollbackFromVersion int64   `json:"rollback_from_version"`
	ExpectedVersion     int64   `json:"expected_version"`
	ChangeReason        *string `json:"change_reason"`
}

type FinalizationResolutionRequest struct {
	ExternalActionPublicID        string `json:"external_action_public_id"`
	ExpectedBackupRowVersion      int64  `json:"expected_backup_row_version"`
	ProviderProofEvidencePublicID string `json:"provider_proof_evidence_public_id"`
}

type OwnershipResolutionRequest struct {
	ExpectedResourceRowVersion    int64  `json:"expected_resource_row_version"`
	ProviderProofEvidencePublicID string `json:"provider_proof_evidence_public_id"`
}

type ManualHoldUpdateRequest struct {
	ManualHold               bool    `json:"manual_hold"`
	ExpectedBackupRowVersion int64   `json:"expected_backup_row_version"`
	Reason                   *string `json:"reason"`
}

type PromotionCreateRequest struct {
	BackupPublicID                    string  `json:"backup_public_id"`
	DrillPublicID                     string  `json:"drill_public_id"`
	ExpectedBackupRowVersion          int64   `json:"expected_backup_row_version"`
	ExpectedDrillRowVersion           int64   `json:"expected_drill_row_version"`
	ExpectedPruneGuardVersion         int64   `json:"expected_prune_guard_version"`
	ExpectedActivePromotionPublicID   *string `json:"expected_active_promotion_public_id"`
	ExpectedActivePromotionRowVersion *int64  `json:"expected_active_promotion_row_version"`
}

type PromotionRevokeRequest struct {
	ExpectedPromotionPublicID   string `json:"expected_promotion_public_id"`
	ExpectedPromotionRowVersion int64  `json:"expected_promotion_row_version"`
	Reason                      string `json:"reason"`
}

type PruneConfirmationRequest struct {
	ExpectedPruneRunRowVersion int64 `json:"expected_prune_run_row_version"`
}

type PruneExecuteRequest struct {
	PruneRunPublicID           string `json:"prune_run_public_id"`
	ConfirmationID             string `json:"confirmation_id"`
	ExpectedPruneRunRowVersion int64  `json:"expected_prune_run_row_version"`
}

type PruneRetryRequest struct {
	ExpectedPruneRunRowVersion int64 `json:"expected_prune_run_row_version"`
}

// The control resource DTOs below are D-owned projections. Provider and
// security-owner configuration is represented only by redacted identity hashes
// and immutable versions; no replayable credential material is part of the wire.
type ConfigReference struct {
	Purpose      string `json:"purpose"`
	IdentityHash string `json:"identity_hash"`
	Version      string `json:"version"`
}

type RegistryReference struct {
	RegistryKind string `json:"registry_kind"`
	Version      string `json:"version"`
	SHA256       string `json:"sha256"`
}

type DurationConfig struct {
	ControllerClaimTTLSeconds             int64 `json:"controller_claim_ttl_seconds"`
	ControllerClaimHeartbeatSeconds       int64 `json:"controller_claim_heartbeat_seconds"`
	ControllerReconcileIntervalSeconds    int64 `json:"controller_reconcile_interval_seconds"`
	MutationLeaseTTLSeconds               int64 `json:"mutation_lease_ttl_seconds"`
	MutationLeaseHeartbeatSeconds         int64 `json:"mutation_lease_heartbeat_seconds"`
	ArtifactLeaseTTLSeconds               int64 `json:"artifact_lease_ttl_seconds"`
	ArtifactLeaseHeartbeatSeconds         int64 `json:"artifact_lease_heartbeat_seconds"`
	GateAcquisitionTimeoutSeconds         int64 `json:"gate_acquisition_timeout_seconds"`
	QuiesceMaxHoldSeconds                 int64 `json:"quiesce_max_hold_seconds"`
	MaintenanceLockTTLSeconds             int64 `json:"maintenance_lock_ttl_seconds"`
	WatchdogDBUnavailableGraceSeconds     int64 `json:"watchdog_db_unavailable_grace_seconds"`
	WatchdogSafetyMarginSeconds           int64 `json:"watchdog_safety_margin_seconds"`
	StagingRetentionSeconds               int64 `json:"staging_retention_seconds"`
	RetentionSeconds                      int64 `json:"retention_seconds"`
	PruneCandidateTTLSeconds              int64 `json:"prune_candidate_ttl_seconds"`
	ConfirmationTTLSeconds                int64 `json:"confirmation_ttl_seconds"`
	LogsRetentionSeconds                  int64 `json:"logs_retention_seconds"`
	EvidenceRetentionSeconds              int64 `json:"evidence_retention_seconds"`
	PromotionHealthMaxAgeSeconds          int64 `json:"promotion_health_max_age_seconds"`
	TaskCancelDeadlineSeconds             int64 `json:"task_cancel_deadline_seconds"`
	CleanupDeadlineSeconds                int64 `json:"cleanup_deadline_seconds"`
	RetryInitialBackoffSeconds            int64 `json:"retry_initial_backoff_seconds"`
	RetryMaxBackoffSeconds                int64 `json:"retry_max_backoff_seconds"`
	OrphanSafetyWindowSeconds             int64 `json:"orphan_safety_window_seconds"`
	ArtifactHealthIntervalSeconds         int64 `json:"artifact_health_interval_seconds"`
	CatalogScanIntervalSeconds            int64 `json:"catalog_scan_interval_seconds"`
	CatalogScanDeadlineSeconds            int64 `json:"catalog_scan_deadline_seconds"`
	ProviderConsistencyWindowSeconds      int64 `json:"provider_consistency_window_seconds"`
	RedisClockSkewSeconds                 int64 `json:"redis_clock_skew_seconds"`
	StrongAuthMaxAgeSeconds               int64 `json:"strong_auth_max_age_seconds"`
	StrongAuthClockSkewSeconds            int64 `json:"strong_auth_clock_skew_seconds"`
	ProviderProofMaxAgeSeconds            int64 `json:"provider_proof_max_age_seconds"`
	CaptureCertificateTTLSeconds          int64 `json:"capture_certificate_ttl_seconds"`
	FinalizationResolutionGraceSeconds    int64 `json:"finalization_resolution_grace_seconds"`
	RecoveryPointObjectiveSeconds         int64 `json:"recovery_point_objective_seconds"`
	FirstEnableRecoveryAlertGraceSeconds  int64 `json:"first_enable_recovery_alert_grace_seconds"`
	ControlMetadataRetentionSeconds       int64 `json:"control_metadata_retention_seconds"`
	BackupTaskDeadlineSeconds             int64 `json:"backup_task_deadline_seconds"`
	DrillTaskDeadlineSeconds              int64 `json:"drill_task_deadline_seconds"`
	PreflightTaskDeadlineSeconds          int64 `json:"preflight_task_deadline_seconds"`
	ArtifactVerifyTaskDeadlineSeconds     int64 `json:"artifact_verify_task_deadline_seconds"`
	OperationDeadlineSeconds              int64 `json:"operation_deadline_seconds"`
	FinalizationResolutionDeadlineSeconds int64 `json:"finalization_resolution_deadline_seconds"`
	PruneOperationDeadlineSeconds         int64 `json:"prune_operation_deadline_seconds"`
}

type CapacityConfig struct {
	ControlMetadataCapacityBytes           int64   `json:"control_metadata_capacity_bytes"`
	StagingCapacityBytes                   int64   `json:"staging_capacity_bytes"`
	MaxArtifactBytes                       int64   `json:"max_artifact_bytes"`
	MaxIndexBytes                          int64   `json:"max_index_bytes"`
	MaxPlaintextBufferBytes                int64   `json:"max_plaintext_buffer_bytes"`
	MaxSourceItems                         int64   `json:"max_source_items"`
	MinimumCaptureThroughputBytesPerSecond int64   `json:"minimum_capture_throughput_bytes_per_second"`
	SourceSizeSafetyFactor                 float64 `json:"source_size_safety_factor"`
	MaxLogBytes                            int64   `json:"max_log_bytes"`
	MaxLogLines                            int64   `json:"max_log_lines"`
	LogChunkBytes                          int64   `json:"log_chunk_bytes"`
	LogChunkLines                          int64   `json:"log_chunk_lines"`
}

type ConcurrencyConfig struct {
	MaxConcurrentDrills                int64 `json:"max_concurrent_drills"`
	MaxConcurrentPreflights            int64 `json:"max_concurrent_preflights"`
	MaxConcurrentArtifactVerifications int64 `json:"max_concurrent_artifact_verifications"`
	MaxPendingTasks                    int64 `json:"max_pending_tasks"`
	MaxAutoAttempts                    int64 `json:"max_auto_attempts"`
}

type PreflightLimits struct {
	QueryTimeoutSeconds int64 `json:"query_timeout_seconds"`
	ProviderQPS         int64 `json:"provider_qps"`
	MaxScanBytes        int64 `json:"max_scan_bytes"`
	MaxScanItems        int64 `json:"max_scan_items"`
}

type ConfigValues struct {
	Enabled               bool                `json:"enabled"`
	AlertProfile          string              `json:"alert_profile"`
	MinimumRecoveryPoints int64               `json:"minimum_recovery_points"`
	Durations             DurationConfig      `json:"durations"`
	Capacity              CapacityConfig      `json:"capacity"`
	Concurrency           ConcurrencyConfig   `json:"concurrency"`
	PreflightLimits       PreflightLimits     `json:"preflight_limits"`
	Registries            []RegistryReference `json:"registries"`
	References            []ConfigReference   `json:"references"`
}

type ConfigUpdateRequest struct {
	ExpectedVersion int64        `json:"expected_version"`
	ChangeReason    *string      `json:"change_reason"`
	Config          ConfigValues `json:"config"`
}

type ConfigResource struct {
	SchemaVersion        string       `json:"schema_version"`
	OriginInstallationID string       `json:"origin_installation_id"`
	Version              int64        `json:"version"`
	RowVersion           int64        `json:"row_version"`
	Active               bool         `json:"active"`
	EffectiveEnabled     bool         `json:"effective_enabled"`
	Config               ConfigValues `json:"config"`
	CreatedBy            string       `json:"created_by"`
	ChangeReason         *string      `json:"change_reason"`
	CreatedAt            string       `json:"created_at"`
}

type FailureDomainShortage struct {
	TargetFailureDomainID        string `json:"target_failure_domain_id"`
	MinimumRecoveryPoints        int64  `json:"minimum_recovery_points"`
	EligibleUsableRecoveryPoints int64  `json:"eligible_usable_recovery_points"`
}

type OverviewResource struct {
	SchemaVersion                   string                  `json:"schema_version"`
	OriginInstallationID            string                  `json:"origin_installation_id"`
	ConfigVersion                   int64                   `json:"config_version"`
	EffectiveEnabled                bool                    `json:"effective_enabled"`
	MonitoringArmed                 bool                    `json:"monitoring_armed"`
	MonitoringArmedReason           string                  `json:"monitoring_armed_reason"`
	Matrix                          string                  `json:"matrix"`
	BackupRecoveryReadiness         bool                    `json:"backup_recovery_readiness"`
	BaselinePresent                 bool                    `json:"baseline_present"`
	ControllerHealth                string                  `json:"controller_health"`
	DatabaseHealth                  string                  `json:"database_health"`
	ArtifactTargetHealth            string                  `json:"artifact_target_health"`
	EvidenceStoreHealth             string                  `json:"evidence_store_health"`
	CatalogHealth                   string                  `json:"catalog_health"`
	SourceWriterState               string                  `json:"source_writer_state"`
	ActiveTaskCount                 int64                   `json:"active_task_count"`
	ActiveOperationCount            int64                   `json:"active_operation_count"`
	FinalizationUnknownCount        int64                   `json:"finalization_unknown_count"`
	CleanupBacklogCount             int64                   `json:"cleanup_backlog_count"`
	OwnershipResolutionBacklogCount int64                   `json:"ownership_resolution_backlog_count"`
	ShortageFailureDomains          []FailureDomainShortage `json:"shortage_failure_domains"`
	ObservedAt                      string                  `json:"observed_at"`
}

type PruneRunResource struct {
	SchemaVersion         string  `json:"schema_version"`
	PublicID              string  `json:"public_id"`
	Status                string  `json:"status"`
	Retryable             bool    `json:"retryable"`
	ConfigVersion         int64   `json:"config_version"`
	OlderThan             string  `json:"older_than"`
	CandidateHash         *string `json:"candidate_hash"`
	CandidateCount        *int64  `json:"candidate_count"`
	CandidateBytes        *int64  `json:"candidate_bytes"`
	CandidateExpiresAt    *string `json:"candidate_expires_at"`
	ConfirmationStatus    string  `json:"confirmation_status"`
	ConfirmationExpiresAt *string `json:"confirmation_expires_at"`
	PlannedItems          int64   `json:"planned_items"`
	BlockedItems          int64   `json:"blocked_items"`
	DeletingItems         int64   `json:"deleting_items"`
	DeletedItems          int64   `json:"deleted_items"`
	DeleteFailedItems     int64   `json:"delete_failed_items"`
	FailureCategory       string  `json:"failure_category"`
	RowVersion            int64   `json:"row_version"`
	StartedAt             string  `json:"started_at"`
	ExecutionStartedAt    *string `json:"execution_started_at"`
	ExecutionFinishedAt   *string `json:"execution_finished_at"`
	FinishedAt            *string `json:"finished_at"`
	CreatedAt             string  `json:"created_at"`
	UpdatedAt             string  `json:"updated_at"`
}

type PruneConfirmationResource struct {
	SchemaVersion      string  `json:"schema_version"`
	PruneRunPublicID   string  `json:"prune_run_public_id"`
	ConfirmationID     string  `json:"confirmation_id"`
	Status             string  `json:"status"`
	CandidateHash      string  `json:"candidate_hash"`
	CandidateCount     int64   `json:"candidate_count"`
	CandidateBytes     int64   `json:"candidate_bytes"`
	CutoffAt           string  `json:"cutoff_at"`
	ConfigVersion      int64   `json:"config_version"`
	ExpiresAt          string  `json:"expires_at"`
	ConsumedAt         *string `json:"consumed_at"`
	PruneRunRowVersion int64   `json:"prune_run_row_version"`
}

type EventDetails struct {
	PreviousStatus    *string `json:"previous_status"`
	CurrentStatus     *string `json:"current_status"`
	Reason            *string `json:"reason"`
	AttemptNumber     *int64  `json:"attempt_number"`
	OperationPublicID *string `json:"operation_public_id"`
	EvidencePublicID  *string `json:"evidence_public_id"`
	Truncated         bool    `json:"truncated"`
	OriginalSize      *int64  `json:"original_size"`
	ContentHash       *string `json:"content_hash"`
}

type EventResource struct {
	SchemaVersion  string        `json:"schema_version"`
	TargetType     string        `json:"target_type"`
	TargetPublicID string        `json:"target_public_id"`
	EventType      string        `json:"event_type"`
	Level          string        `json:"level"`
	TaskStatus     *string       `json:"task_status"`
	Message        string        `json:"message"`
	Details        *EventDetails `json:"details"`
	RequestID      *string       `json:"request_id"`
	CreatedAt      string        `json:"created_at"`
}

type EventResourceList struct {
	Items       []EventResource `json:"items"`
	NextCursor  *string         `json:"next_cursor"`
	Consistency string          `json:"consistency"`
}

type LogEntryResource struct {
	SchemaVersion string `json:"schema_version"`
	TaskType      string `json:"task_type"`
	TaskPublicID  string `json:"task_public_id"`
	AttemptNumber int64  `json:"attempt_number"`
	Phase         string `json:"phase"`
	JobGeneration int64  `json:"job_generation"`
	ChunkSequence int64  `json:"chunk_sequence"`
	LineIndex     int64  `json:"line_index"`
	Timestamp     string `json:"timestamp"`
	Stream        string `json:"stream"`
	Level         string `json:"level"`
	Message       string `json:"message"`
}

type LogEntryResourceList struct {
	Items       []LogEntryResource `json:"items"`
	NextCursor  *string            `json:"next_cursor"`
	Consistency string             `json:"consistency"`
}

type PruneItemResource struct {
	SchemaVersion          string  `json:"schema_version"`
	PublicID               string  `json:"public_id"`
	PruneRunPublicID       string  `json:"prune_run_public_id"`
	ArtifactPublicID       string  `json:"artifact_public_id"`
	ItemType               string  `json:"item_type"`
	Status                 string  `json:"status"`
	LocatorHash            *string `json:"locator_hash"`
	ImmutableVersion       *string `json:"immutable_version"`
	CatalogRecordHash      *string `json:"catalog_record_hash"`
	Bytes                  int64   `json:"bytes"`
	LastOperationPublicID  *string `json:"last_operation_public_id"`
	Attempt                int64   `json:"attempt"`
	ItemFailureCode        string  `json:"item_failure_code"`
	ExternalActionPublicID *string `json:"external_action_public_id"`
	RowVersion             int64   `json:"row_version"`
	CreatedAt              string  `json:"created_at"`
	UpdatedAt              string  `json:"updated_at"`
}

type PruneItemResourceList struct {
	Items       []PruneItemResource `json:"items"`
	NextCursor  *string             `json:"next_cursor"`
	Consistency string              `json:"consistency"`
}

type PromotionHealth struct {
	Artifact       string `json:"artifact"`
	ArtifactAccess string `json:"artifact_access"`
	KEK            string `json:"kek"`
	Signature      string `json:"signature"`
	Catalog        string `json:"catalog"`
	Evidence       string `json:"evidence"`
	Attestation    string `json:"attestation"`
	CurrentHealth  string `json:"current_health"`
	ObservedAt     string `json:"observed_at"`
}

type PromotionResource struct {
	SchemaVersion            string          `json:"schema_version"`
	PublicID                 string          `json:"public_id"`
	OriginInstallationID     string          `json:"origin_installation_id"`
	Matrix                   string          `json:"matrix"`
	RecordStatus             string          `json:"record_status"`
	BackupPublicID           string          `json:"backup_public_id"`
	DrillPublicID            string          `json:"drill_public_id"`
	ManifestChecksum         string          `json:"manifest_checksum"`
	AcceptanceChecksum       string          `json:"acceptance_checksum"`
	ArtifactRegistrationID   string          `json:"artifact_registration_id"`
	ArtifactRegistrationHash string          `json:"artifact_registration_hash"`
	EligibilityDecisionHash  string          `json:"eligibility_decision_hash"`
	DrillEvidencePublicID    string          `json:"drill_evidence_public_id"`
	DrillEvidenceHash        string          `json:"drill_evidence_hash"`
	Health                   PromotionHealth `json:"health"`
	CreatedBy                string          `json:"created_by"`
	CreatedAt                string          `json:"created_at"`
	SupersededByPublicID     *string         `json:"superseded_by_public_id"`
	SupersededAt             *string         `json:"superseded_at"`
	RevokedBy                *string         `json:"revoked_by"`
	RevokedReason            *string         `json:"revoked_reason"`
	RevokedAt                *string         `json:"revoked_at"`
	RowVersion               int64           `json:"row_version"`
}

type PromotionResourceList struct {
	Items       []PromotionResource `json:"items"`
	NextCursor  *string             `json:"next_cursor"`
	Consistency string              `json:"consistency"`
}

type EvidenceReference struct {
	PublicID string `json:"public_id"`
	SHA256   string `json:"sha256"`
}

type SourceArtifactReference struct {
	SourceArtifactType string `json:"source_artifact_type"`
	SourcePublicID     string `json:"source_public_id"`
}

type ExecutionProjection struct {
	CurrentAttemptNumber   *int64  `json:"current_attempt_number"`
	CurrentPhase           *string `json:"current_phase"`
	JobGeneration          *int64  `json:"job_generation"`
	LastBusinessProgressAt *string `json:"last_business_progress_at"`
}

type VerifierSummary struct {
	AggregateStatus string             `json:"aggregate_status"`
	Passed          int64              `json:"passed"`
	Warning         int64              `json:"warning"`
	Failed          int64              `json:"failed"`
	Skipped         int64              `json:"skipped"`
	ReportEvidence  *EvidenceReference `json:"report_evidence"`
}

type NullableArtifactChecksumSet struct {
	Manifest   *string `json:"manifest"`
	Index      *string `json:"index"`
	Marker     *string `json:"marker"`
	Acceptance *string `json:"acceptance"`
	Catalog    *string `json:"catalog"`
}

type BackupDetailResource struct {
	SchemaVersion            string                      `json:"schema_version"`
	Task                     Task                        `json:"task"`
	Execution                ExecutionProjection         `json:"execution"`
	TaskPurpose              string                      `json:"task_purpose"`
	SourceOrchestrator       string                      `json:"source_orchestrator"`
	SourceProfile            string                      `json:"source_profile"`
	Matrix                   string                      `json:"matrix"`
	DatasourceTopology       string                      `json:"datasource_topology"`
	Runner                   string                      `json:"runner"`
	RequestedParts           []string                    `json:"requested_parts"`
	ArtifactState            string                      `json:"artifact_state"`
	ArtifactUsable           bool                        `json:"artifact_usable"`
	ArtifactUnusableReason   string                      `json:"artifact_unusable_reason"`
	ArtifactCommittedAt      *string                     `json:"artifact_committed_at"`
	AcceptanceReady          bool                        `json:"acceptance_ready"`
	AcceptanceEligible       bool                        `json:"acceptance_eligible"`
	EligibilityReasonCodes   []string                    `json:"eligibility_reason_codes"`
	EligibilityDecisionHash  *string                     `json:"eligibility_decision_hash"`
	TargetClass              string                      `json:"target_class"`
	TargetRisks              []string                    `json:"target_risks"`
	TargetFailureDomainID    string                      `json:"target_failure_domain_id"`
	Consistency              string                      `json:"consistency"`
	Checksums                NullableArtifactChecksumSet `json:"checksums"`
	ArtifactRegistrationID   *string                     `json:"artifact_registration_id"`
	ArtifactRegistrationHash *string                     `json:"artifact_registration_hash"`
	VerifierSummary          VerifierSummary             `json:"verifier_summary"`
	ManualHold               bool                        `json:"manual_hold"`
	ManualHoldReason         *string                     `json:"manual_hold_reason"`
	ManualHoldActor          *string                     `json:"manual_hold_actor"`
	ManualHoldAt             *string                     `json:"manual_hold_at"`
	PromotionHold            bool                        `json:"promotion_hold"`
	Bytes                    *int64                      `json:"bytes"`
	PruneGuardVersion        int64                       `json:"prune_guard_version"`
}

type DrillDetailResource struct {
	SchemaVersion           string                      `json:"schema_version"`
	Task                    Task                        `json:"task"`
	Execution               ExecutionProjection         `json:"execution"`
	Source                  SourceArtifactReference     `json:"source"`
	SourceChecksums         NullableArtifactChecksumSet `json:"source_checksums"`
	TaskPurpose             string                      `json:"task_purpose"`
	TargetProfile           string                      `json:"target_profile"`
	RestoreTargetConfigHash string                      `json:"restore_target_config_hash"`
	CleanupPolicy           string                      `json:"cleanup_policy"`
	CleanupStatus           string                      `json:"cleanup_status"`
	CleanupFailureCode      string                      `json:"cleanup_failure_code"`
	PreflightEvidence       *EvidenceReference          `json:"preflight_evidence"`
	DiffEvidence            *EvidenceReference          `json:"diff_evidence"`
	VerifierSummary         VerifierSummary             `json:"verifier_summary"`
	Consistency             *string                     `json:"consistency"`
	AcceptanceEligible      bool                        `json:"acceptance_eligible"`
	EligibilityReasonCodes  []string                    `json:"eligibility_reason_codes"`
	EligibilityDecisionHash *string                     `json:"eligibility_decision_hash"`
}

type PreflightDetailResource struct {
	SchemaVersion           string                      `json:"schema_version"`
	Task                    Task                        `json:"task"`
	Execution               ExecutionProjection         `json:"execution"`
	Source                  SourceArtifactReference     `json:"source"`
	SourceChecksums         NullableArtifactChecksumSet `json:"source_checksums"`
	PreflightMode           string                      `json:"preflight_mode"`
	TargetProfile           string                      `json:"target_profile"`
	RestoreTargetConfigHash string                      `json:"restore_target_config_hash"`
	ArtifactCompatibility   string                      `json:"artifact_compatibility"`
	ReportEvidence          *EvidenceReference          `json:"report_evidence"`
	DiffEvidence            *EvidenceReference          `json:"diff_evidence"`
	ReportValidityReason    string                      `json:"report_validity_reason"`
	VerifierSummary         VerifierSummary             `json:"verifier_summary"`
}

type ArtifactVerificationDetailResource struct {
	SchemaVersion        string                      `json:"schema_version"`
	Task                 Task                        `json:"task"`
	Execution            ExecutionProjection         `json:"execution"`
	VerificationScope    string                      `json:"verification_scope"`
	Source               SourceArtifactReference     `json:"source"`
	ObservedChecksums    NullableArtifactChecksumSet `json:"observed_checksums"`
	HealthReportEvidence *EvidenceReference          `json:"health_report_evidence"`
	ArtifactStateBefore  *string                     `json:"artifact_state_before"`
	ArtifactStateAfter   *string                     `json:"artifact_state_after"`
	UsableBefore         bool                        `json:"usable_before"`
	UsableAfter          bool                        `json:"usable_after"`
	UnusableReasonBefore string                      `json:"unusable_reason_before"`
	UnusableReasonAfter  string                      `json:"unusable_reason_after"`
	DecisionReason       string                      `json:"decision_reason"`
	VerifierSummary      VerifierSummary             `json:"verifier_summary"`
}
