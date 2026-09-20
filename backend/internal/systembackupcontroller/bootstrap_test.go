package systembackupcontroller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"clawreef/internal/migrationcatalog"
)

type fixedSQLResult struct {
	rows int64
}

func (r fixedSQLResult) LastInsertId() (int64, error) { return 0, nil }
func (r fixedSQLResult) RowsAffected() (int64, error) { return r.rows, nil }

type recordedBootstrapExecutor struct {
	query string
	args  []any
	rows  int64
	err   error
}

func (e *recordedBootstrapExecutor) ExecContext(_ context.Context, query string, args ...any) (sql.Result, error) {
	e.query = query
	e.args = append([]any(nil), args...)
	return fixedSQLResult{rows: e.rows}, e.err
}

func validBootstrapRequirements() BootstrapRequirements {
	filenames := make([]string, ContractMigrationCatalogFileCount)
	for index := range filenames {
		filenames[index] = fmt.Sprintf("%03d.sql", index)
	}
	return BootstrapRequirements{
		InstallationID:       "installation_primary",
		EnvironmentEnabled:   true,
		SystemBackupRequired: false,
		Catalog: migrationcatalog.Catalog{
			Algorithm: migrationcatalog.Algorithm,
			Filenames: filenames,
			Hash:      ContractMigrationCatalogHash,
		},
	}
}

func validBootstrapRow() bootstrapRow {
	return bootstrapRow{
		StateSchemaVersion:            "system-backup-installation-state.v1",
		InstallationID:                "installation_primary",
		ActiveConfigVersion:           3,
		FirstEnabled:                  true,
		LastEffectiveEnabled:          true,
		MonitoringArmed:               true,
		MonitoringArmedReason:         "previously_enabled",
		MatrixKey:                     "k8s-cluster",
		StateRowVersion:               4,
		ConfigSchemaVersion:           sql.NullString{String: "system-backup-config.v1", Valid: true},
		ConfigVersion:                 sql.NullInt64{Int64: 3, Valid: true},
		ConfigEnabled:                 sql.NullBool{Bool: true, Valid: true},
		ClaimTTLSeconds:               sql.NullInt64{Int64: 30, Valid: true},
		ClaimHeartbeatSeconds:         sql.NullInt64{Int64: 10, Valid: true},
		ReconcileIntervalSeconds:      sql.NullInt64{Int64: 10, Valid: true},
		MutationLeaseTTLSeconds:       sql.NullInt64{Int64: 30, Valid: true},
		MutationLeaseHeartbeatSeconds: sql.NullInt64{Int64: 10, Valid: true},
		GateAcquisitionTimeoutSeconds: sql.NullInt64{Int64: 60, Valid: true},
		QuiesceMaxHoldSeconds:         sql.NullInt64{Int64: 600, Valid: true},
		MaintenanceLockTTLSeconds:     sql.NullInt64{Int64: 900, Valid: true},
	}
}

func TestRepositoryMigrationCatalogMatchesControllerAdmission(t *testing.T) {
	catalog, err := migrationcatalog.Compute(os.DirFS("../.."), "internal/db/migrations")
	if err != nil {
		t.Fatalf("compute repository migration catalog: %v", err)
	}
	if len(catalog.Filenames) != ContractMigrationCatalogFileCount || catalog.Hash != ContractMigrationCatalogHash {
		t.Fatalf("controller catalog guard is stale: files=%d hash=%s, want files=%d hash=%s", len(catalog.Filenames), catalog.Hash, ContractMigrationCatalogFileCount, ContractMigrationCatalogHash)
	}
}

func TestBootstrapRequirementsAreClosedToContractCatalog(t *testing.T) {
	requirements := validBootstrapRequirements()
	if err := requirements.Validate(); err != nil {
		t.Fatalf("valid requirements: %v", err)
	}

	invalidInstallation := requirements
	invalidInstallation.InstallationID = "primary"
	if code := BootstrapFailureCodeOf(invalidInstallation.Validate()); code != BootstrapInvalidRequirement {
		t.Fatalf("invalid installation code = %q", code)
	}

	invalidHash := requirements
	first := "0"
	if invalidHash.Catalog.Hash[0] == '0' {
		first = "1"
	}
	invalidHash.Catalog.Hash = first + invalidHash.Catalog.Hash[1:]
	if code := BootstrapFailureCodeOf(invalidHash.Validate()); code != BootstrapCatalogMismatch {
		t.Fatalf("invalid catalog code = %q", code)
	}

	unsorted := requirements
	unsorted.Catalog.Filenames = append([]string(nil), requirements.Catalog.Filenames...)
	unsorted.Catalog.Filenames[0], unsorted.Catalog.Filenames[1] = unsorted.Catalog.Filenames[1], unsorted.Catalog.Filenames[0]
	if code := BootstrapFailureCodeOf(unsorted.Validate()); code != BootstrapCatalogMismatch {
		t.Fatalf("unsorted catalog code = %q", code)
	}
}

func TestBootstrapRowUsesActiveConfigAsControllerPolicy(t *testing.T) {
	snapshot, transitionNeeded, err := validBootstrapRow().snapshot(validBootstrapRequirements(), 88)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if transitionNeeded || snapshot.ConfigVersion != 3 || !snapshot.ConfigEnabled || !snapshot.EffectiveEnabled || !snapshot.FirstEnabled || snapshot.MonitoringArmedReason != "previously_enabled" || snapshot.Policy.TTL != 30*time.Second || snapshot.Policy.HeartbeatInterval != 10*time.Second || snapshot.Policy.ReconcileInterval != 10*time.Second || snapshot.GatePolicy != validGatePolicy() || snapshot.MutationPolicy != validMutationPolicy() {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	if snapshot.AppliedMigrationCount != 88 {
		t.Fatalf("applied count = %d", snapshot.AppliedMigrationCount)
	}
}

func TestBootstrapRowFailsClosedForMissingOrInvalidConfig(t *testing.T) {
	missing := validBootstrapRow()
	missing.ConfigVersion.Valid = false
	if _, _, err := missing.snapshot(validBootstrapRequirements(), 85); BootstrapFailureCodeOf(err) != BootstrapActiveConfigAbsent {
		t.Fatalf("missing config error = %v", err)
	}

	invalidPolicy := validBootstrapRow()
	invalidPolicy.ClaimHeartbeatSeconds.Int64 = 11
	if _, _, err := invalidPolicy.snapshot(validBootstrapRequirements(), 85); BootstrapFailureCodeOf(err) != BootstrapStateInvalid {
		t.Fatalf("invalid policy error = %v", err)
	}

	invalidGatePolicy := validBootstrapRow()
	invalidGatePolicy.MaintenanceLockTTLSeconds.Int64 = invalidGatePolicy.QuiesceMaxHoldSeconds.Int64
	if _, _, err := invalidGatePolicy.snapshot(validBootstrapRequirements(), 85); BootstrapFailureCodeOf(err) != BootstrapStateInvalid {
		t.Fatalf("invalid gate policy error = %v", err)
	}

	invalidMutationPolicy := validBootstrapRow()
	invalidMutationPolicy.MutationLeaseHeartbeatSeconds.Int64 = 11
	if _, _, err := invalidMutationPolicy.snapshot(validBootstrapRequirements(), 85); BootstrapFailureCodeOf(err) != BootstrapStateInvalid {
		t.Fatalf("invalid mutation policy error = %v", err)
	}

	invalidMatrix := validBootstrapRow()
	invalidMatrix.MatrixKey = "unknown"
	if _, _, err := invalidMatrix.snapshot(validBootstrapRequirements(), 85); BootstrapFailureCodeOf(err) != BootstrapStateInvalid {
		t.Fatalf("invalid matrix error = %v", err)
	}
}

func TestBootstrapRowReconcilesEffectiveEnableAndMonitoringState(t *testing.T) {
	row := validBootstrapRow()
	row.FirstEnabled = false
	row.LastEffectiveEnabled = false
	row.MonitoringArmed = false
	row.MonitoringArmedReason = "none"

	snapshot, transitionNeeded, err := row.snapshot(validBootstrapRequirements(), 85)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if !transitionNeeded || !snapshot.EffectiveEnabled || !snapshot.FirstEnabled || !snapshot.MonitoringArmed || snapshot.MonitoringArmedReason != "previously_enabled" {
		t.Fatalf("first-enable snapshot = %#v transition=%t", snapshot, transitionNeeded)
	}

	required := validBootstrapRequirements()
	required.EnvironmentEnabled = false
	required.SystemBackupRequired = true
	row.ConfigEnabled.Bool = false
	snapshot, transitionNeeded, err = row.snapshot(required, 85)
	if err != nil {
		t.Fatalf("required snapshot: %v", err)
	}
	if !transitionNeeded || snapshot.EffectiveEnabled || snapshot.FirstEnabled || !snapshot.MonitoringArmed || snapshot.MonitoringArmedReason != "deployment_required" {
		t.Fatalf("required snapshot = %#v transition=%t", snapshot, transitionNeeded)
	}
}

func TestInstallationStateReconcileUsesDatabaseTimeAndRowVersionCAS(t *testing.T) {
	row := validBootstrapRow()
	row.FirstEnabled = false
	row.LastEffectiveEnabled = false
	row.MonitoringArmed = false
	row.MonitoringArmedReason = "none"
	snapshot, transitionNeeded, err := row.snapshot(validBootstrapRequirements(), 85)
	if err != nil || !transitionNeeded {
		t.Fatalf("snapshot transition=%t err=%v", transitionNeeded, err)
	}
	executor := &recordedBootstrapExecutor{rows: 1}
	reconciler := SQLInstallationStateReconciler{DB: executor}
	if err := reconciler.Reconcile(context.Background(), validBootstrapRequirements(), snapshot); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	for _, required := range []string{"COALESCE(first_enabled_at, UTC_TIMESTAMP(6))", "last_effective_enabled_transition_at", "row_version = row_version + 1", "AND row_version = ?"} {
		if !strings.Contains(executor.query, required) {
			t.Fatalf("reconcile query missing %q: %s", required, executor.query)
		}
	}
	if len(executor.args) != 8 || executor.args[0] != true || executor.args[5] != "installation_primary" || executor.args[6] != uint64(3) || executor.args[7] != uint64(4) {
		t.Fatalf("reconcile args = %#v", executor.args)
	}
}

func TestInstallationStateReconcileFailsClosedOnCASConflict(t *testing.T) {
	row := validBootstrapRow()
	row.LastEffectiveEnabled = false
	snapshot, _, err := row.snapshot(validBootstrapRequirements(), 85)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	executor := &recordedBootstrapExecutor{rows: 0}
	err = (SQLInstallationStateReconciler{DB: executor}).Reconcile(context.Background(), validBootstrapRequirements(), snapshot)
	if BootstrapFailureCodeOf(err) != BootstrapStateCASConflict {
		t.Fatalf("CAS conflict error = %v", err)
	}
}

type recordedBootstrapChecker struct {
	results []BootstrapCheckResult
	calls   int
}

func (c *recordedBootstrapChecker) Check(context.Context, BootstrapRequirements) (BootstrapSnapshot, error) {
	index := c.calls
	c.calls++
	if index >= len(c.results) {
		return BootstrapSnapshot{}, errors.New("unexpected bootstrap check")
	}
	return c.results[index].Snapshot, c.results[index].Err
}

func TestWaitForBootstrapRetriesDatabaseStateThenReturnsSnapshot(t *testing.T) {
	want := BootstrapSnapshot{InstallationID: "installation_primary", ConfigVersion: 3}
	checker := &recordedBootstrapChecker{results: []BootstrapCheckResult{
		{Err: bootstrapFailure(BootstrapMigrationsMissing, errors.New("pending"))},
		{Snapshot: want},
	}}
	var observed []BootstrapFailureCode
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	snapshot, err := WaitForBootstrap(ctx, checker, validBootstrapRequirements(), MinBootstrapCheckInterval, func(result BootstrapCheckResult) {
		if result.Err != nil {
			observed = append(observed, BootstrapFailureCodeOf(result.Err))
		}
	})
	if err != nil {
		t.Fatalf("WaitForBootstrap: %v", err)
	}
	if snapshot != want || checker.calls != 2 || len(observed) != 1 || observed[0] != BootstrapMigrationsMissing {
		t.Fatalf("snapshot=%#v calls=%d observed=%#v", snapshot, checker.calls, observed)
	}
}

func TestWaitForBootstrapRejectsLocalConfigurationWithoutCheckingDatabase(t *testing.T) {
	checker := &recordedBootstrapChecker{}
	requirements := validBootstrapRequirements()
	requirements.InstallationID = "invalid"
	_, err := WaitForBootstrap(context.Background(), checker, requirements, DefaultBootstrapCheckInterval, nil)
	if BootstrapFailureCodeOf(err) != BootstrapInvalidRequirement || checker.calls != 0 {
		t.Fatalf("error=%v calls=%d", err, checker.calls)
	}
}
