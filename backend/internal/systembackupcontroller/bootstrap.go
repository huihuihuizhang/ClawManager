package systembackupcontroller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"clawreef/internal/migrationcatalog"
)

const (
	ContractMigrationCatalogHash      = "b3fe27c26b2917b2b17a8c20b0af24b5c375188a5478fbe43c4fd15cd1375991"
	ContractMigrationCatalogFileCount = 91
	MinBootstrapCheckInterval         = time.Second
	DefaultBootstrapCheckInterval     = 10 * time.Second
	MaxBootstrapCheckInterval         = 60 * time.Second
)

type BootstrapFailureCode string

const (
	BootstrapInvalidRequirement BootstrapFailureCode = "invalid_requirement"
	BootstrapCatalogMismatch    BootstrapFailureCode = "catalog_mismatch"
	BootstrapMigrationQuery     BootstrapFailureCode = "migration_query_failed"
	BootstrapMigrationsMissing  BootstrapFailureCode = "migrations_missing"
	BootstrapInstallationQuery  BootstrapFailureCode = "installation_query_failed"
	BootstrapInstallationAbsent BootstrapFailureCode = "installation_missing"
	BootstrapActiveConfigAbsent BootstrapFailureCode = "active_config_missing"
	BootstrapStateInvalid       BootstrapFailureCode = "state_invalid"
	BootstrapStateUpdate        BootstrapFailureCode = "state_update_failed"
	BootstrapStateCASConflict   BootstrapFailureCode = "state_cas_conflict"
	BootstrapRuntimeRestarting  BootstrapFailureCode = "runtime_restarting"
	BootstrapWorkerExited       BootstrapFailureCode = "worker_exited"
	BootstrapWorkerStopTimeout  BootstrapFailureCode = "worker_stop_timeout"
)

type BootstrapFailure struct {
	Code BootstrapFailureCode
	Err  error
}

func (e *BootstrapFailure) Error() string {
	if e == nil || e.Err == nil {
		return string(e.Code)
	}
	return fmt.Sprintf("%s: %v", e.Code, e.Err)
}

func (e *BootstrapFailure) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func bootstrapFailure(code BootstrapFailureCode, err error) error {
	return &BootstrapFailure{Code: code, Err: err}
}

func BootstrapFailureCodeOf(err error) BootstrapFailureCode {
	var failure *BootstrapFailure
	if errors.As(err, &failure) {
		return failure.Code
	}
	return BootstrapStateInvalid
}

type BootstrapRequirements struct {
	InstallationID       string
	EnvironmentEnabled   bool
	SystemBackupRequired bool
	Catalog              migrationcatalog.Catalog
}

func (r BootstrapRequirements) Validate() error {
	if !installationIDPattern.MatchString(r.InstallationID) {
		return bootstrapFailure(BootstrapInvalidRequirement, errors.New("origin installation ID must match the v12 installation ID pattern"))
	}
	if r.Catalog.Algorithm != migrationcatalog.Algorithm || r.Catalog.Hash != ContractMigrationCatalogHash || len(r.Catalog.Filenames) != ContractMigrationCatalogFileCount {
		return bootstrapFailure(BootstrapCatalogMismatch, fmt.Errorf("embedded migration catalog is not the v12 contract catalog (algorithm=%s files=%d hash=%s)", r.Catalog.Algorithm, len(r.Catalog.Filenames), r.Catalog.Hash))
	}
	for index, filename := range r.Catalog.Filenames {
		if filename == "" || !strings.HasSuffix(filename, ".sql") || strings.ContainsAny(filename, `/\\`) {
			return bootstrapFailure(BootstrapCatalogMismatch, fmt.Errorf("invalid migration filename at index %d", index))
		}
		if index > 0 && r.Catalog.Filenames[index-1] >= filename {
			return bootstrapFailure(BootstrapCatalogMismatch, errors.New("migration filenames must be unique and sorted"))
		}
	}
	return nil
}

type BootstrapSnapshot struct {
	InstallationID          string
	ConfigVersion           uint64
	ConfigEnabled           bool
	EnvironmentEnabled      bool
	EffectiveEnabled        bool
	FirstEnabled            bool
	LastEffectiveEnabled    bool
	MonitoringArmed         bool
	MonitoringArmedReason   string
	MatrixKey               string
	Policy                  LeasePolicy
	GatePolicy              GatePolicy
	MutationPolicy          MutationLeasePolicy
	MigrationCatalogHash    string
	AppliedMigrationCount   int
	StateRowVersion         uint64
	StateTransitionRequired bool
	SetFirstEnabled         bool
}

type BootstrapChecker interface {
	Check(context.Context, BootstrapRequirements) (BootstrapSnapshot, error)
}

type bootstrapQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type bootstrapExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

type SQLBootstrapChecker struct {
	DB bootstrapQueryer
}

func (c SQLBootstrapChecker) Check(ctx context.Context, requirements BootstrapRequirements) (BootstrapSnapshot, error) {
	var snapshot BootstrapSnapshot
	if err := requirements.Validate(); err != nil {
		return snapshot, err
	}
	if err := ctx.Err(); err != nil {
		return snapshot, err
	}
	if c.DB == nil {
		return snapshot, bootstrapFailure(BootstrapInvalidRequirement, errors.New("nil bootstrap database"))
	}

	rows, err := c.DB.QueryContext(ctx, "SELECT filename FROM schema_migrations ORDER BY filename")
	if err != nil {
		return snapshot, bootstrapFailure(BootstrapMigrationQuery, err)
	}
	applied := make(map[string]struct{})
	for rows.Next() {
		var filename string
		if err := rows.Scan(&filename); err != nil {
			_ = rows.Close()
			return snapshot, bootstrapFailure(BootstrapMigrationQuery, err)
		}
		applied[filename] = struct{}{}
	}
	iterationErr := rows.Err()
	closeErr := rows.Close()
	if iterationErr != nil {
		return snapshot, bootstrapFailure(BootstrapMigrationQuery, iterationErr)
	}
	if closeErr != nil {
		return snapshot, bootstrapFailure(BootstrapMigrationQuery, closeErr)
	}
	missing := make([]string, 0)
	for _, filename := range requirements.Catalog.Filenames {
		if _, ok := applied[filename]; !ok {
			missing = append(missing, filename)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return snapshot, bootstrapFailure(BootstrapMigrationsMissing, fmt.Errorf("%d embedded migrations are not applied; first missing migration is %s", len(missing), missing[0]))
	}

	row := bootstrapRow{}
	err = c.DB.QueryRowContext(ctx, `SELECT
  installation.schema_version,
  installation.origin_installation_id,
  installation.active_config_version,
  installation.first_enabled_at IS NOT NULL,
  installation.last_effective_enabled,
  installation.monitoring_armed,
  installation.monitoring_armed_reason,
  installation.matrix_key,
  installation.row_version,
  active_config.schema_version,
  active_config.version,
  active_config.enabled,
  active_config.controller_claim_ttl_seconds,
  active_config.controller_claim_heartbeat_seconds,
  active_config.controller_reconcile_interval_seconds,
  active_config.mutation_lease_ttl_seconds,
  active_config.mutation_lease_heartbeat_seconds,
  active_config.gate_acquisition_timeout_seconds,
  active_config.quiesce_max_hold_seconds,
  active_config.maintenance_lock_ttl_seconds
FROM system_backup_installation_state AS installation
LEFT JOIN system_backup_configs AS active_config
  ON active_config.origin_installation_id = installation.origin_installation_id
 AND active_config.version = installation.active_config_version
WHERE installation.origin_installation_id = ?`, requirements.InstallationID).Scan(
		&row.StateSchemaVersion,
		&row.InstallationID,
		&row.ActiveConfigVersion,
		&row.FirstEnabled,
		&row.LastEffectiveEnabled,
		&row.MonitoringArmed,
		&row.MonitoringArmedReason,
		&row.MatrixKey,
		&row.StateRowVersion,
		&row.ConfigSchemaVersion,
		&row.ConfigVersion,
		&row.ConfigEnabled,
		&row.ClaimTTLSeconds,
		&row.ClaimHeartbeatSeconds,
		&row.ReconcileIntervalSeconds,
		&row.MutationLeaseTTLSeconds,
		&row.MutationLeaseHeartbeatSeconds,
		&row.GateAcquisitionTimeoutSeconds,
		&row.QuiesceMaxHoldSeconds,
		&row.MaintenanceLockTTLSeconds,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return snapshot, bootstrapFailure(BootstrapInstallationAbsent, errors.New("installation state row does not exist"))
	}
	if err != nil {
		return snapshot, bootstrapFailure(BootstrapInstallationQuery, err)
	}
	snapshot, _, err = row.snapshot(requirements, len(applied))
	if err != nil {
		return BootstrapSnapshot{}, err
	}
	return snapshot, nil
}

type SQLInstallationStateReconciler struct {
	DB bootstrapExecutor
}

// Reconcile is called only after this replica acquires the Kubernetes leader
// lease. Standby replicas remain read-only, preventing old/new rollout pods
// with different deployment gates from fighting over effective state.
func (r SQLInstallationStateReconciler) Reconcile(ctx context.Context, requirements BootstrapRequirements, snapshot BootstrapSnapshot) error {
	if err := requirements.Validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.DB == nil {
		return bootstrapFailure(BootstrapInvalidRequirement, errors.New("nil installation state database"))
	}
	if snapshot.InstallationID != requirements.InstallationID || snapshot.ConfigVersion < 1 || snapshot.StateRowVersion < 1 {
		return bootstrapFailure(BootstrapStateInvalid, errors.New("installation state reconciliation snapshot is invalid"))
	}
	expectedEffective := requirements.EnvironmentEnabled && snapshot.ConfigEnabled
	expectedMonitoring := requirements.SystemBackupRequired || snapshot.FirstEnabled
	expectedReason := "none"
	if snapshot.FirstEnabled {
		expectedReason = "previously_enabled"
	} else if requirements.SystemBackupRequired {
		expectedReason = "deployment_required"
	}
	if snapshot.EnvironmentEnabled != requirements.EnvironmentEnabled ||
		snapshot.EffectiveEnabled != expectedEffective ||
		snapshot.LastEffectiveEnabled != expectedEffective ||
		snapshot.MonitoringArmed != expectedMonitoring ||
		snapshot.MonitoringArmedReason != expectedReason ||
		(snapshot.SetFirstEnabled && !snapshot.FirstEnabled) {
		return bootstrapFailure(BootstrapStateInvalid, errors.New("installation state reconciliation snapshot violates effective-enable invariants"))
	}
	if !snapshot.StateTransitionRequired {
		return nil
	}
	result, updateErr := r.DB.ExecContext(ctx, `UPDATE system_backup_installation_state SET
  first_enabled_at = CASE WHEN ? THEN COALESCE(first_enabled_at, UTC_TIMESTAMP(6)) ELSE first_enabled_at END,
  last_effective_enabled_transition_at = CASE WHEN last_effective_enabled <> ? THEN UTC_TIMESTAMP(6) ELSE last_effective_enabled_transition_at END,
  last_effective_enabled = ?,
  monitoring_armed = ?,
  monitoring_armed_reason = ?,
  row_version = row_version + 1
WHERE origin_installation_id = ?
  AND active_config_version = ?
  AND row_version = ?`,
		snapshot.SetFirstEnabled,
		snapshot.EffectiveEnabled,
		snapshot.EffectiveEnabled,
		snapshot.MonitoringArmed,
		snapshot.MonitoringArmedReason,
		requirements.InstallationID,
		snapshot.ConfigVersion,
		snapshot.StateRowVersion,
	)
	if updateErr != nil {
		return bootstrapFailure(BootstrapStateUpdate, updateErr)
	}
	rowsAffected, affectedErr := result.RowsAffected()
	if affectedErr != nil {
		return bootstrapFailure(BootstrapStateUpdate, affectedErr)
	}
	if rowsAffected != 1 {
		return bootstrapFailure(BootstrapStateCASConflict, errors.New("installation state changed during leader reconciliation"))
	}
	return nil
}

type bootstrapRow struct {
	StateSchemaVersion            string
	InstallationID                string
	ActiveConfigVersion           uint64
	FirstEnabled                  bool
	LastEffectiveEnabled          bool
	MonitoringArmed               bool
	MonitoringArmedReason         string
	MatrixKey                     string
	StateRowVersion               uint64
	ConfigSchemaVersion           sql.NullString
	ConfigVersion                 sql.NullInt64
	ConfigEnabled                 sql.NullBool
	ClaimTTLSeconds               sql.NullInt64
	ClaimHeartbeatSeconds         sql.NullInt64
	ReconcileIntervalSeconds      sql.NullInt64
	MutationLeaseTTLSeconds       sql.NullInt64
	MutationLeaseHeartbeatSeconds sql.NullInt64
	GateAcquisitionTimeoutSeconds sql.NullInt64
	QuiesceMaxHoldSeconds         sql.NullInt64
	MaintenanceLockTTLSeconds     sql.NullInt64
}

func (r bootstrapRow) snapshot(requirements BootstrapRequirements, appliedCount int) (BootstrapSnapshot, bool, error) {
	if !r.ConfigSchemaVersion.Valid || !r.ConfigVersion.Valid || !r.ConfigEnabled.Valid ||
		!r.ClaimTTLSeconds.Valid || !r.ClaimHeartbeatSeconds.Valid || !r.ReconcileIntervalSeconds.Valid ||
		!r.MutationLeaseTTLSeconds.Valid || !r.MutationLeaseHeartbeatSeconds.Valid ||
		!r.GateAcquisitionTimeoutSeconds.Valid || !r.QuiesceMaxHoldSeconds.Valid || !r.MaintenanceLockTTLSeconds.Valid {
		return BootstrapSnapshot{}, false, bootstrapFailure(BootstrapActiveConfigAbsent, errors.New("installation active config row does not exist"))
	}
	if r.StateSchemaVersion != "system-backup-installation-state.v1" || r.ConfigSchemaVersion.String != "system-backup-config.v1" {
		return BootstrapSnapshot{}, false, bootstrapFailure(BootstrapStateInvalid, errors.New("installation or active config schema version is unsupported"))
	}
	if r.InstallationID != requirements.InstallationID || r.ActiveConfigVersion < 1 || r.ConfigVersion.Int64 < 1 || uint64(r.ConfigVersion.Int64) != r.ActiveConfigVersion || r.StateRowVersion < 1 {
		return BootstrapSnapshot{}, false, bootstrapFailure(BootstrapStateInvalid, errors.New("installation and active config identity do not match"))
	}
	switch r.MatrixKey {
	case "k8s-cluster", "k3s-cluster", "k8s-single-node", "k3s-single-node":
	default:
		return BootstrapSnapshot{}, false, bootstrapFailure(BootstrapStateInvalid, errors.New("installation matrix key is unsupported"))
	}
	if (!r.MonitoringArmed && (r.MonitoringArmedReason != "none" || r.FirstEnabled)) ||
		(r.MonitoringArmed && r.MonitoringArmedReason == "none") ||
		(r.MonitoringArmedReason == "previously_enabled" && !r.FirstEnabled) ||
		(r.MonitoringArmedReason != "none" && r.MonitoringArmedReason != "deployment_required" && r.MonitoringArmedReason != "previously_enabled") {
		return BootstrapSnapshot{}, false, bootstrapFailure(BootstrapStateInvalid, errors.New("installation monitoring state is inconsistent"))
	}
	if r.ClaimTTLSeconds.Int64 < 0 || r.ClaimHeartbeatSeconds.Int64 < 0 || r.ReconcileIntervalSeconds.Int64 < 0 ||
		r.MutationLeaseTTLSeconds.Int64 < 0 || r.MutationLeaseHeartbeatSeconds.Int64 < 0 ||
		r.GateAcquisitionTimeoutSeconds.Int64 < 0 || r.QuiesceMaxHoldSeconds.Int64 < 0 || r.MaintenanceLockTTLSeconds.Int64 < 0 {
		return BootstrapSnapshot{}, false, bootstrapFailure(BootstrapStateInvalid, errors.New("active config contains a negative controller duration"))
	}
	policy := LeasePolicy{
		TTL:               time.Duration(r.ClaimTTLSeconds.Int64) * time.Second,
		HeartbeatInterval: time.Duration(r.ClaimHeartbeatSeconds.Int64) * time.Second,
		ReconcileInterval: time.Duration(r.ReconcileIntervalSeconds.Int64) * time.Second,
	}
	if err := policy.Validate(); err != nil {
		return BootstrapSnapshot{}, false, bootstrapFailure(BootstrapStateInvalid, fmt.Errorf("active config controller policy: %w", err))
	}
	gatePolicy := GatePolicy{
		LockTTL:            time.Duration(r.MaintenanceLockTTLSeconds.Int64) * time.Second,
		AcquisitionTimeout: time.Duration(r.GateAcquisitionTimeoutSeconds.Int64) * time.Second,
		MaxHold:            time.Duration(r.QuiesceMaxHoldSeconds.Int64) * time.Second,
	}
	if err := gatePolicy.Validate(); err != nil {
		return BootstrapSnapshot{}, false, bootstrapFailure(BootstrapStateInvalid, fmt.Errorf("active config maintenance gate policy: %w", err))
	}
	mutationPolicy := MutationLeasePolicy{
		TTL:               time.Duration(r.MutationLeaseTTLSeconds.Int64) * time.Second,
		HeartbeatInterval: time.Duration(r.MutationLeaseHeartbeatSeconds.Int64) * time.Second,
	}
	if err := mutationPolicy.Validate(); err != nil {
		return BootstrapSnapshot{}, false, bootstrapFailure(BootstrapStateInvalid, fmt.Errorf("active config mutation lease policy: %w", err))
	}
	effectiveEnabled := requirements.EnvironmentEnabled && r.ConfigEnabled.Bool
	firstEnabled := r.FirstEnabled || effectiveEnabled
	monitoringArmed := requirements.SystemBackupRequired || firstEnabled
	monitoringReason := "none"
	if firstEnabled {
		monitoringReason = "previously_enabled"
	} else if requirements.SystemBackupRequired {
		monitoringReason = "deployment_required"
	}
	snapshot := BootstrapSnapshot{
		InstallationID:        r.InstallationID,
		ConfigVersion:         r.ActiveConfigVersion,
		ConfigEnabled:         r.ConfigEnabled.Bool,
		EnvironmentEnabled:    requirements.EnvironmentEnabled,
		EffectiveEnabled:      effectiveEnabled,
		FirstEnabled:          firstEnabled,
		LastEffectiveEnabled:  effectiveEnabled,
		MonitoringArmed:       monitoringArmed,
		MonitoringArmedReason: monitoringReason,
		MatrixKey:             r.MatrixKey,
		Policy:                policy,
		GatePolicy:            gatePolicy,
		MutationPolicy:        mutationPolicy,
		MigrationCatalogHash:  requirements.Catalog.Hash,
		AppliedMigrationCount: appliedCount,
		StateRowVersion:       r.StateRowVersion,
	}
	transitionNeeded := r.FirstEnabled != firstEnabled ||
		r.LastEffectiveEnabled != effectiveEnabled ||
		r.MonitoringArmed != monitoringArmed ||
		r.MonitoringArmedReason != monitoringReason
	snapshot.StateTransitionRequired = transitionNeeded
	snapshot.SetFirstEnabled = firstEnabled && !r.FirstEnabled
	return snapshot, transitionNeeded, nil
}

type BootstrapCheckResult struct {
	Snapshot BootstrapSnapshot
	Err      error
}

// WaitForBootstrap retries only external database state. Invalid local
// requirements fail immediately; no leader election or reconciliation should
// start until this function returns a snapshot.
func WaitForBootstrap(ctx context.Context, checker BootstrapChecker, requirements BootstrapRequirements, interval time.Duration, onResult func(BootstrapCheckResult)) (BootstrapSnapshot, error) {
	if checker == nil {
		return BootstrapSnapshot{}, bootstrapFailure(BootstrapInvalidRequirement, errors.New("nil bootstrap checker"))
	}
	if err := requirements.Validate(); err != nil {
		return BootstrapSnapshot{}, err
	}
	if interval < MinBootstrapCheckInterval || interval > MaxBootstrapCheckInterval {
		return BootstrapSnapshot{}, bootstrapFailure(BootstrapInvalidRequirement, fmt.Errorf("bootstrap check interval must be between %s and %s", MinBootstrapCheckInterval, MaxBootstrapCheckInterval))
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return BootstrapSnapshot{}, err
		}
		checkCtx, cancelCheck := context.WithTimeout(ctx, interval)
		snapshot, err := checker.Check(checkCtx, requirements)
		cancelCheck()
		if onResult != nil {
			onResult(BootstrapCheckResult{Snapshot: snapshot, Err: err})
		}
		if err == nil {
			return snapshot, nil
		}
		select {
		case <-ctx.Done():
			return BootstrapSnapshot{}, ctx.Err()
		case <-ticker.C:
		}
	}
}
