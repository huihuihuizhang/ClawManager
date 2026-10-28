package systembackup

import (
	"context"
	"database/sql"
	"errors"
)

var ErrEngineConflict = errors.New("engine_conflict")

const LegacyEngine = "legacy"
const VersionedEngine = "v2"

// An application DB has one installation authority; gate scopes remain separate.
const engineSelectionScope = "installation"

// EngineSelection is installation-local control state, not a task or artifact
// format. Existing tasks keep their original reader and runner.
type EngineSelection struct {
	Engine  string `json:"engine"`
	Version uint64 `json:"row_version"`
}

func validEngine(engine string) bool { return engine == LegacyEngine || engine == VersionedEngine }

func lockEngine(ctx context.Context, tx *sql.Tx, scope, engine string) error {
	var actual string
	if err := tx.QueryRowContext(ctx, "SELECT engine FROM system_backup_v2_engine_bindings WHERE scope=? FOR UPDATE", engineSelectionScope).Scan(&actual); err != nil {
		return err
	}
	if !validEngine(engine) || actual != engine {
		return ErrEngineConflict
	}
	return nil
}

func (g Gate) Engine(ctx context.Context, scope string) (EngineSelection, error) {
	var result EngineSelection
	err := g.DB.QueryRowContext(ctx, "SELECT engine,row_version FROM system_backup_v2_engine_bindings WHERE scope=?", engineSelectionScope).Scan(&result.Engine, &result.Version)
	return result, err
}

// SwitchEngine takes the same authority row used by BeginForEngine before the
// gate row. It cannot switch while a prior task can still send or finish work.
// It is an internal operation; HTTP handlers must separately check configure
// authority and readiness before offering it. There is no force switch.
func (g Gate) SwitchEngine(ctx context.Context, scope string, expected EngineSelection, next string) (EngineSelection, error) {
	if !validEngine(next) || !validEngine(expected.Engine) || expected.Version == 0 {
		return EngineSelection{}, errors.New("validation_failed")
	}
	tx, err := g.DB.BeginTx(ctx, nil)
	if err != nil {
		return EngineSelection{}, err
	}
	defer tx.Rollback()
	var actual EngineSelection
	if err = tx.QueryRowContext(ctx, "SELECT engine,row_version FROM system_backup_v2_engine_bindings WHERE scope=? FOR UPDATE", engineSelectionScope).Scan(&actual.Engine, &actual.Version); err != nil {
		return actual, err
	}
	if actual != expected {
		return actual, errors.New("version_conflict")
	}
	var phase string
	if err = tx.QueryRowContext(ctx, "SELECT phase FROM system_backup_gate WHERE scope=? FOR UPDATE NOWAIT", scope).Scan(&phase); err != nil {
		return actual, err
	}
	if phase != "idle" {
		return actual, ErrMaintenance
	}
	var admission sql.NullString
	if err = tx.QueryRowContext(ctx, "SELECT owner FROM system_backup_gate_admissions WHERE scope=? FOR UPDATE", scope).Scan(&admission); err != nil {
		return actual, err
	}
	if admission.Valid {
		return actual, ErrMaintenance
	}
	var pending int
	// Scope is the source maintenance domain. Conservatively exclude *all*
	// nonterminal installation work: a queued or finalization-unknown task is
	// not evidence that its old runner has stopped.
	queries := []string{
		"SELECT COUNT(*) FROM system_backup_tasks WHERE status NOT IN ('succeeded','failed','canceled')",
		"SELECT COUNT(*) FROM system_backup_external_actions WHERE state IN ('request_sent','provider_unreachable','conflict')",
		"SELECT COUNT(*) FROM system_backup_capture_plans WHERE source_resumed_at IS NULL",
		"SELECT COUNT(*) FROM system_backup_attempts WHERE status='running'",
		"SELECT COUNT(*) FROM system_backup_restore_jobs WHERE create_sent=1 AND stopped_at IS NULL",
		"SELECT COUNT(*) FROM system_backup_v2_backups WHERE status NOT IN ('succeeded','failed','canceled')",
		"SELECT COUNT(*) FROM system_backup_v2_restore_drills WHERE status NOT IN ('succeeded','failed','canceled')",
		"SELECT COUNT(*) FROM system_backup_v2_preflights WHERE status NOT IN ('succeeded','failed','canceled')",
		"SELECT COUNT(*) FROM system_backup_v2_artifact_verifications WHERE status NOT IN ('succeeded','failed','canceled')",
		"SELECT COUNT(*) FROM system_backup_v2_external_actions WHERE state IN ('request_sent','provider_unreachable','conflict')",
		"SELECT COUNT(*) FROM system_backup_v2_maintenance_locks WHERE gate_state<>'idle'",
		"SELECT COUNT(*) FROM system_backup_v2_maintenance_mutation_leases",
		"SELECT COUNT(*) FROM system_backup_v2_maintenance_participants WHERE desired_state<>'running' OR observed_state<>'running'",
		"SELECT COUNT(*) FROM system_backup_mutation_leases WHERE released_at IS NULL",
		"SELECT COUNT(*) FROM system_backup_participants WHERE (state<>'running' OR resume_result NOT IN ('none','succeeded','forced'))",
	}
	queries = append(queries, "SELECT COUNT(*) FROM system_backup_gate WHERE phase<>'idle'", "SELECT COUNT(*) FROM system_backup_gate_admissions WHERE owner IS NOT NULL")
	for _, query := range queries {
		if err = tx.QueryRowContext(ctx, query).Scan(&pending); err != nil {
			return actual, err
		}
		if pending != 0 {
			return actual, errors.New("conflict_active_job")
		}
	}
	if next == actual.Engine {
		return actual, tx.Commit()
	}
	if _, err = tx.ExecContext(ctx, "UPDATE system_backup_v2_engine_bindings SET engine=?,row_version=row_version+1,updated_at=UTC_TIMESTAMP(6) WHERE scope=? AND row_version=?", next, engineSelectionScope, expected.Version); err != nil {
		return actual, err
	}
	actual.Engine, actual.Version = next, actual.Version+1
	return actual, tx.Commit()
}
