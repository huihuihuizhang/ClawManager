package systembackupexecution

import (
	"context"
	"database/sql"
	"errors"
	"time"

	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
)

// This is a user-visible projection of authenticated original execution, never
// a second execution authority. Heartbeats are observations, not business
// progress. Only an independently opened sealed result advances progress.
func recordPublicObservation(ctx context.Context, tx *sql.Tx, a d.Authority, b d.JobBinding, status, digest string) error {
	if (status != "running" && status != "sealed") || len(digest) != 64 || a.AttemptNo == 0 || a.Phase != "capture" {
		return c.ErrExecutionRecord
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil {
		return err
	}
	bound, expires := b.RelayBoundAt.UTC().Truncate(time.Microsecond), b.RelayExpiresAt.UTC().Truncate(time.Microsecond)
	if now.Before(bound) || !expires.After(bound) {
		return c.ErrExecutionRecord
	}
	var uid, ref, version string
	var generation, sequence uint64
	var oldStatus, oldDigest sql.NullString
	var oldBound, oldExpires time.Time
	err := tx.QueryRowContext(ctx, "SELECT job_uid,job_generation,relay_identity_ref,relay_identity_version,relay_identity_bound_at,relay_identity_expires_at,last_accepted_sequence,last_observed_status,last_accepted_body_sha256 FROM system_backup_v2_job_observations WHERE origin_installation_id=? AND target_type='backup' AND target_public_id=? AND attempt_no=? AND phase=? AND job_unit_key=? FOR UPDATE", a.InstallationID, a.TaskPublicID, a.AttemptNo, a.Phase, b.JobUnitKey).Scan(&uid, &generation, &ref, &version, &oldBound, &oldExpires, &sequence, &oldStatus, &oldDigest)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = tx.ExecContext(ctx, "INSERT INTO system_backup_v2_job_observations(origin_installation_id,target_type,target_public_id,attempt_no,phase,job_unit_key,job_uid,job_generation,relay_identity_ref,relay_identity_version,relay_identity_bound_at,relay_identity_expires_at,last_accepted_sequence,last_accepted_body_sha256,last_observed_status,last_observed_at,progress_sequence,progress_digest_sha256,last_business_progress_at,created_at) VALUES(?,'backup',?,?,?,?,?,?,?,?,?,?,1,?,?,?,IF(?='sealed',1,0),IF(?='sealed',?,NULL),IF(?='sealed',?,NULL),?)", a.InstallationID, a.TaskPublicID, a.AttemptNo, a.Phase, b.JobUnitKey, b.UID, b.Generation, b.RelayIdentityRef, b.RelayIdentityVersion, bound, expires, digest, status, now, status, status, digest, status, now, bound)
		return err
	}
	if err != nil {
		return err
	}
	if uid != b.UID || generation != b.Generation || ref != b.RelayIdentityRef || version != b.RelayIdentityVersion || !oldBound.Equal(bound) || !oldExpires.Equal(expires) || !oldStatus.Valid || !oldDigest.Valid {
		return c.ErrExecutionRecord
	}
	change, err := observationAdvance(oldStatus.String, oldDigest.String, sequence, status, digest)
	if err != nil {
		return err
	}
	if !change {
		if oldStatus.String == "running" && status == "running" {
			// Current Pod/process was independently checked by Authorize.
			// Refresh observation time without inventing content progress.
			_, err = tx.ExecContext(ctx, "UPDATE system_backup_v2_job_observations SET last_observed_at=?,row_version=row_version+1 WHERE origin_installation_id=? AND target_type='backup' AND target_public_id=? AND attempt_no=? AND phase=? AND job_unit_key=? AND job_uid=? AND last_observed_status='running'", now, a.InstallationID, a.TaskPublicID, a.AttemptNo, a.Phase, b.JobUnitKey, b.UID)
		}
		return err
	}
	result, err := tx.ExecContext(ctx, "UPDATE system_backup_v2_job_observations SET last_accepted_sequence=last_accepted_sequence+1,last_accepted_body_sha256=?,last_observed_status=?,last_observed_at=?,progress_sequence=IF(?='sealed',last_accepted_sequence,progress_sequence),progress_digest_sha256=IF(?='sealed',?,progress_digest_sha256),last_business_progress_at=IF(?='sealed',?,last_business_progress_at),row_version=row_version+1 WHERE origin_installation_id=? AND target_type='backup' AND target_public_id=? AND attempt_no=? AND phase=? AND job_unit_key=? AND job_uid=? AND last_accepted_sequence=?", digest, status, now, status, status, digest, status, now, a.InstallationID, a.TaskPublicID, a.AttemptNo, a.Phase, b.JobUnitKey, b.UID, sequence)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return c.ErrExecutionRecord
	}
	return nil
}

func observationAdvance(oldStatus, oldDigest string, sequence uint64, status, digest string) (bool, error) {
	if sequence == 0 || sequence >= 1<<53-1 || (oldStatus != "running" && oldStatus != "sealed") || (status != "running" && status != "sealed") {
		return false, c.ErrExecutionRecord
	}
	if oldStatus == "sealed" {
		if status == "sealed" && oldDigest != digest {
			return false, c.ErrExecutionRecord
		}
		return false, nil // A late heartbeat cannot reopen a sealed result.
	}
	return oldStatus != status || oldDigest != digest, nil
}
