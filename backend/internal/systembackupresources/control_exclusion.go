package systembackupresources

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// These are the v12 control tables whose source rows must never be imported
// into a drill database. schema_migrations is target-local metadata and is
// deliberately outside this source-row exclusion check.
var controlExclusionTables = map[string]struct{}{
	"system_artifact_lease_states": {}, "system_artifact_leases": {},
	"system_backup_alert_states": {}, "system_backup_artifact_verifications": {},
	"system_backup_attempts": {}, "system_backup_check_results": {},
	"system_backup_compact_tombstones": {}, "system_backup_configs": {},
	"system_backup_dependency_health": {}, "system_backup_events": {},
	"system_backup_evidence": {}, "system_backup_evidence_chunks": {},
	"system_backup_external_actions": {}, "system_backup_installation_state": {},
	"system_backup_job_observations": {}, "system_backup_log_chunks": {},
	"system_backup_operations": {}, "system_backup_preflights": {},
	"system_backup_promotions": {}, "system_backup_provider_capabilities": {},
	"system_backup_prune_items": {}, "system_backup_prune_runs": {},
	"system_backup_source_writer_check_states": {}, "system_backup_staging_resources": {},
	"system_backup_strong_auth_nonces": {}, "system_backups": {},
	"system_maintenance_locks": {}, "system_maintenance_mutation_leases": {},
	"system_maintenance_participants": {}, "system_restore_drill_resources": {},
	"system_restore_drills": {},
}

// ControlExclusionAllowlist is closed against the frozen schema registry. Any
// newly registered control table requires an explicit policy decision here.
func ControlExclusionAllowlist(registryJSON []byte) ([]string, error) {
	if _, err := CaptureTableAllowlist(registryJSON); err != nil {
		return nil, err
	}
	var document registry
	if err := json.Unmarshal(registryJSON, &document); err != nil {
		return nil, fmt.Errorf("decode control exclusion registry: %w", err)
	}
	seen := make(map[string]struct{}, len(controlExclusionTables))
	sawMigrations := false
	for _, object := range document.Objects {
		_, required := controlExclusionTables[object.Name]
		if object.Category != "system_backup" && !required && !looksLikeControlTable(object.Name) && object.Name != "schema_migrations" {
			continue
		}
		if object.Name == "schema_migrations" {
			if object.ObjectType != "table" || object.Category != "system_backup" || object.Owner != "D" || object.BackupStrategy != "metadata_only" || object.RestoreStrategy != "reference_only" {
				return nil, errors.New("schema_migrations target-local policy mismatch")
			}
			sawMigrations = true
			continue
		}
		if !required || object.ObjectType != "table" || object.Category != "system_backup" || object.Owner != "D" || object.BackupStrategy != "metadata_only" || object.RestoreStrategy != "reference_only" {
			return nil, fmt.Errorf("control exclusion policy mismatch at %s", object.Name)
		}
		seen[object.Name] = struct{}{}
	}
	if !sawMigrations || len(seen) != len(controlExclusionTables) {
		return nil, fmt.Errorf("control exclusion scope incomplete: got %d of %d tables", len(seen), len(controlExclusionTables))
	}
	tables := make([]string, 0, len(seen))
	for table := range seen {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	return tables, nil
}

func looksLikeControlTable(name string) bool {
	return strings.HasPrefix(name, "system_backup_") || strings.HasPrefix(name, "system_artifact_lease") ||
		strings.HasPrefix(name, "system_maintenance_") || name == "system_backups" ||
		name == "system_restore_drills" || name == "system_restore_drill_resources"
}

// TargetReadProofVerifier is supplied by B's isolated restore target. It must
// establish target identity on this exact transaction, the completed
// normalization boundary, and a new SELECT-only credential with no reachable
// restore-write credential.
type TargetReadProofVerifier interface {
	VerifyReadOnlyTarget(ctx context.Context, tx *sql.Tx) error
}

type SQLControlExclusionVerifier struct {
	DB    *sql.DB
	Proof TargetReadProofVerifier
}

// VerifyRestoreTarget checks that the control table structures exist and that
// none contains imported source control rows. It produces no partial result.
func (v SQLControlExclusionVerifier) VerifyRestoreTarget(ctx context.Context, registryJSON []byte, evidenceRef string) ([]ResourcesCheck, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tables, err := ControlExclusionAllowlist(registryJSON)
	if err != nil {
		return nil, err
	}
	if !evidenceIDPattern.MatchString(evidenceRef) || v.DB == nil || v.Proof == nil {
		return nil, errors.New("control exclusion requires evidence, target proof and database")
	}
	tx, err := v.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, fmt.Errorf("begin control exclusion read-only snapshot: %w", err)
	}
	defer tx.Rollback()
	if err := v.Proof.VerifyReadOnlyTarget(ctx, tx); err != nil {
		return nil, fmt.Errorf("control exclusion target proof: %w", err)
	}
	checks := make([]ResourcesCheck, 0, len(tables))
	for _, table := range tables {
		var engine string
		if err := tx.QueryRowContext(ctx, `SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND TABLE_TYPE = 'BASE TABLE'`, table).Scan(&engine); err != nil {
			return nil, fmt.Errorf("inspect control table %s: %w", table, err)
		}
		if !strings.EqualFold(engine, "InnoDB") {
			return nil, fmt.Errorf("control table %s is not transactional InnoDB", table)
		}
		// table is selected only from the closed, frozen allowlist.
		var rows int64
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM `"+table+"`").Scan(&rows); err != nil {
			return nil, fmt.Errorf("count control table %s: %w", table, err)
		}
		if rows < 0 {
			return nil, fmt.Errorf("negative control table count for %s", table)
		}
		checks = append(checks, resourcesCheck("control_plane.empty."+table, "rows", int64(0), rows, evidenceRef))
		if rows != 0 {
			checks[len(checks)-1].FailureCategory = "normalization_failed"
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit control exclusion snapshot: %w", err)
	}
	return checks, nil
}
