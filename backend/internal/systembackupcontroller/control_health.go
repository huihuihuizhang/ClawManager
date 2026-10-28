package systembackupcontroller

import (
	"context"
	"database/sql"
	"errors"
)

// ControlHealthStore is a candidate for the separately reviewed control-health
// schema. It is deliberately not enabled by the production controller until
// its migration, least-privilege grants and leader-start integration are ready.
// It creates no tables, changes no installation projection and reads no B/C data.
// A *sql.DB is required so each statement is autocommitted. Accepting an
// Executor would also admit *sql.Tx and could issue a token before COMMIT.
type ControlHealthStore struct{ DB *sql.DB }

const maxHealthVersion = uint64(9007199254740991)

var ErrControlHealthFence = errors.New("control health writer fence rejected")

// ControlHealthWriter is a single successful leader-start/observation receipt.
// A lost SQL reply returns no next token; the old token cannot authorize a
// repeated write after an observation actually committed.
type ControlHealthWriter struct {
	database     *sql.DB
	installation string
	config       uint64
	owner        string
	epoch        uint64
	sequence     uint64
}

func (ControlHealthWriter) MarshalJSON() ([]byte, error) { return nil, ErrControlHealthFence }

const controlHealthInitialSQL = `INSERT INTO system_backup_v2_control_health
(origin_installation_id,schema_version,config_version,writer_epoch,writer_owner,observation_sequence,controller_health,database_health,observed_at,expires_at)
SELECT s.origin_installation_id,'system-backup-control-health.v1',c.version,1,?,0,'unknown','unknown',UTC_TIMESTAMP(6),
TIMESTAMPADD(SECOND,3*c.controller_reconcile_interval_seconds,UTC_TIMESTAMP(6))
FROM system_backup_v2_installation_state s JOIN system_backup_v2_configs c
ON c.origin_installation_id=s.origin_installation_id AND c.version=s.active_config_version
WHERE s.origin_installation_id=? AND c.version=? AND s.schema_version='system-backup-installation-state.v1'
AND c.schema_version='system-backup-config.v1' AND c.controller_reconcile_interval_seconds BETWEEN 1 AND 60
AND TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))=0`

const controlHealthTakeoverSQL = `UPDATE system_backup_v2_control_health h
JOIN system_backup_v2_installation_state s ON s.origin_installation_id=h.origin_installation_id
JOIN system_backup_v2_configs c ON c.origin_installation_id=s.origin_installation_id AND c.version=s.active_config_version
SET h.config_version=c.version,h.writer_epoch=h.writer_epoch+1,h.writer_owner=?,h.observation_sequence=0,
h.controller_health='unknown',h.database_health='unknown',h.observed_at=UTC_TIMESTAMP(6),
h.expires_at=TIMESTAMPADD(SECOND,3*c.controller_reconcile_interval_seconds,UTC_TIMESTAMP(6))
WHERE h.origin_installation_id=? AND c.version=? AND h.writer_epoch=?
AND h.schema_version='system-backup-control-health.v1' AND s.schema_version='system-backup-installation-state.v1'
AND c.schema_version='system-backup-config.v1' AND c.controller_reconcile_interval_seconds BETWEEN 1 AND 60
AND TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))=0 AND UTC_TIMESTAMP(6)>=h.observed_at`

// BeginWriter must only be called once by a trusted new-leader callback with
// the current persisted epoch. SQL epoch CAS fences all older writers. Merely
// obtaining a token records unknown, never healthy. The callback must also
// carry the existing leader context and readiness/bootstrap admission.
func (s ControlHealthStore) BeginWriter(ctx context.Context, installation string, configVersion uint64, owner string, previousEpoch uint64) (ControlHealthWriter, error) {
	var zero ControlHealthWriter
	if ctx == nil || ctx.Err() != nil || s.DB == nil || !installationIDPattern.MatchString(installation) ||
		!controllerOwnerPattern.MatchString(owner) || configVersion == 0 || configVersion > maxHealthVersion || previousEpoch >= maxHealthVersion {
		return zero, ErrControlHealthFence
	}
	query := controlHealthInitialSQL
	args := []any{owner, installation, configVersion}
	if previousEpoch != 0 {
		query = controlHealthTakeoverSQL
		args = append(args, previousEpoch)
	}
	if err := controlHealthExec(ctx, s.DB, query, args...); err != nil {
		return zero, err
	}
	return ControlHealthWriter{database: s.DB, installation: installation, config: configVersion, owner: owner, epoch: previousEpoch + 1}, nil
}

const controlHealthRecordSQL = `UPDATE system_backup_v2_control_health h
JOIN system_backup_v2_installation_state s ON s.origin_installation_id=h.origin_installation_id
JOIN system_backup_v2_configs c ON c.origin_installation_id=s.origin_installation_id AND c.version=s.active_config_version
SET h.observation_sequence=h.observation_sequence+1,h.controller_health=?,h.database_health=?,h.observed_at=UTC_TIMESTAMP(6),
h.expires_at=TIMESTAMPADD(SECOND,3*c.controller_reconcile_interval_seconds,UTC_TIMESTAMP(6))
WHERE h.origin_installation_id=? AND h.config_version=? AND c.version=h.config_version
AND h.writer_owner=? AND h.writer_epoch=? AND h.observation_sequence=?
AND h.schema_version='system-backup-control-health.v1' AND s.schema_version='system-backup-installation-state.v1'
AND c.schema_version='system-backup-config.v1' AND c.controller_reconcile_interval_seconds BETWEEN 1 AND 60
AND TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))=0
AND UTC_TIMESTAMP(6)>=h.observed_at AND UTC_TIMESTAMP(6)<h.expires_at`

// Observe records the actual control-pass result and executes a distinct DB
// readiness probe. Ping/SELECT alone is not a suitable production probe: use
// the existing UTC, exact-grant, claim and alert SQL readiness set. A failed
// DB write leaves only the prior observation to expire; it cannot report fresh
// health. External artifact failures and kill-switch state are not inputs.
func (s ControlHealthStore) Observe(ctx context.Context, writer ControlHealthWriter, result ControlLoopResult, database ReadinessProbe) (ControlHealthWriter, error) {
	var zero ControlHealthWriter
	if ctx == nil || ctx.Err() != nil || s.DB == nil || writer.database != s.DB || database == nil || writer.epoch == 0 ||
		writer.sequence >= maxHealthVersion || !installationIDPattern.MatchString(writer.installation) ||
		!controllerOwnerPattern.MatchString(writer.owner) || writer.config == 0 || writer.config > maxHealthVersion || writer.epoch > maxHealthVersion {
		return zero, ErrControlHealthFence
	}
	controllerState, databaseState := "healthy", "healthy"
	if result.Err != nil {
		controllerState = "degraded"
	}
	if err := database.Check(ctx); err != nil {
		databaseState = "degraded"
	}
	if ctx.Err() != nil {
		return zero, ErrControlHealthFence
	}
	if err := controlHealthExec(ctx, s.DB, controlHealthRecordSQL, controllerState, databaseState,
		writer.installation, writer.config, writer.owner, writer.epoch, writer.sequence); err != nil {
		return zero, err
	}
	writer.sequence++
	return writer, nil
}

func controlHealthExec(ctx context.Context, db Executor, query string, args ...any) error {
	result, err := db.ExecContext(ctx, query, args...)
	if err != nil || result == nil {
		return ErrControlHealthFence
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 || ctx.Err() != nil {
		return ErrControlHealthFence
	}
	return nil
}
