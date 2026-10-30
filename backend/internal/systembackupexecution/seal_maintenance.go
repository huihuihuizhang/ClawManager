package systembackupexecution

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"clawreef/internal/systembackup/staging"
	d "clawreef/internal/systembackupdispatch"
)

// SealMaintenance only removes local unreferenced staging versions. It never
// changes task state, SQL history, evidence, or a referenced/published artifact.
// The administrative CLI pins deployment config and uses a table-SELECT account.
type SealMaintenance struct {
	DB                                 *sql.DB
	Installation, ServerUUID, Database string
}

// Preflight checks the exact control database and columns required by cleanup.
// It only executes SELECT statements and does not touch the staging volume.
func (m SealMaintenance) Preflight(ctx context.Context) error {
	if m.DB == nil || m.Installation == "" || m.ServerUUID == "" || m.Database == "" {
		return errors.New("seal maintenance scope invalid")
	}
	var server, database string
	if err := m.DB.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE()").Scan(&server, &database); err != nil || server != m.ServerUUID || database != m.Database {
		return errors.New("seal maintenance database mismatch")
	}
	for _, query := range []string{
		"SELECT origin_installation_id,public_id,status,config_version,config_snapshot_sha256,finished_at FROM system_backup_v2_backups LIMIT 0",
		"SELECT task_public_id,resource_kind,namespace_name,resource_name,observed_uid,revoked,result_sha256,binding_json,attempt_no FROM system_backup_v2_runtime_resources LIMIT 0",
		"SELECT public_id,owner_target_type,owner_target_public_id FROM system_backup_v2_evidence LIMIT 0",
	} {
		rows, err := m.DB.QueryContext(ctx, query)
		if err != nil {
			return errors.New("seal maintenance schema or SELECT grant unavailable")
		}
		if err = rows.Close(); err != nil {
			return errors.New("seal maintenance schema check failed")
		}
	}
	return nil
}

func (m SealMaintenance) WithUnreferencedSeal(ctx context.Context, intent staging.SealIntent, reference string, remove func() error) (bool, error) {
	s := intent.Scope
	if m.DB == nil || s.Installation != m.Installation || m.ServerUUID == "" || m.Database == "" || remove == nil {
		return false, errors.New("seal maintenance scope invalid")
	}
	expected, err := staging.SealReferenceForIntent(intent)
	if err != nil || reference != expected {
		return false, errors.New("seal maintenance reference mismatch")
	}
	tx, err := m.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var server, database string
	if err = tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE()").Scan(&server, &database); err != nil || server != m.ServerUUID || database != m.Database {
		return false, errors.New("seal maintenance database mismatch")
	}
	// A missing/purged Job is unknown, never proof of an orphan. Lock task first
	// and original Job second, as the result writer does, before checking refs.
	var status, configSHA string
	var version uint64
	var finished sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT status,config_version,config_snapshot_sha256,finished_at FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=? FOR SHARE`, m.Installation, s.Task).Scan(&status, &version, &configSHA, &finished)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if (status != "failed" && status != "canceled" && status != "succeeded") || !finished.Valid || version != s.ConfigVersion || configSHA != s.ConfigSHA256 {
		return false, nil
	}
	var revoked bool
	var result sql.NullString
	var bindingRaw []byte
	var attempt uint64
	err = tx.QueryRowContext(ctx, `SELECT revoked,result_sha256,binding_json,attempt_no FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND namespace_name=? AND resource_name=? AND observed_uid=? FOR SHARE`, s.Task, s.Namespace, s.JobName, s.JobUID).Scan(&revoked, &result, &bindingRaw, &attempt)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var job d.JobBinding
	if !revoked || result.Valid || attempt != s.Attempt || json.Unmarshal(bindingRaw, &job) != nil || job.UID != s.JobUID || job.Namespace != s.Namespace || job.Name != s.JobName || job.JobUnitKey != s.Unit || job.Generation != s.Generation {
		return false, nil
	}
	// Deliberately retain any evidence for this task, even expired/error records.
	// This conservative query does not have to guess encrypted or external refs.
	var evidenceID string
	err = tx.QueryRowContext(ctx, `SELECT public_id FROM system_backup_v2_evidence WHERE owner_target_type='backup' AND owner_target_public_id=? LIMIT 1 FOR SHARE`, s.Task).Scan(&evidenceID)
	if err == nil {
		return false, nil
	}
	if err != sql.ErrNoRows {
		return false, err
	}
	var now time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || !finished.Time.Before(now.Add(-time.Hour)) {
		return false, nil
	}
	// SQL locks stay held through the precise filesystem removal; terminal and
	// revoked rows cannot be changed by a concurrent result/retry transaction.
	if err = remove(); err != nil {
		return false, err
	}
	return true, nil
}
