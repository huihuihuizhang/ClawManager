package systembackup

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Retry is a durable new attempt of the existing engine, never a second task
// authority. Partial restore copies are cleaned by their existing owned cleanup
// path before a new restore can be queued. The immutable source is retained.
type TeamDataRetry struct {
	Of       string `json:"retry_of_public_id"`
	Next     string `json:"continue_operation,omitempty"`
	Followup string `json:"followup_public_id,omitempty"`
}

func teamDataRetry(j TeamDataJob) *TeamDataRetry {
	var r struct {
		Retry *TeamDataRetry `json:"retry"`
	}
	if json.Unmarshal(j.Report, &r) != nil {
		return nil
	}
	return r.Retry
}

func (s *TeamDataService) Retry(ctx context.Context, actor int, id, key string) (TeamDataJob, error) {
	if actor < 1 || !publicIDPattern.MatchString(id) || !idemPattern.MatchString(key) {
		return TeamDataJob{}, errors.New("validation_failed")
	}
	previous, e := scanTeamDataJob(s.db.QueryRowContext(ctx, "SELECT "+teamDataColumns+" FROM system_team_data_backup_jobs WHERE actor_id=? AND idempotency_key=?", actor, key))
	if e == nil {
		r := teamDataRetry(previous)
		if r == nil || r.Of != id {
			return TeamDataJob{}, errors.New("idempotency_conflict")
		}
		return previous, nil
	}
	if e.Error() != "not_found" {
		return TeamDataJob{}, e
	}
	original, e := s.Get(ctx, id)
	if e != nil {
		return TeamDataJob{}, e
	}
	operation, source := original.Operation, original.SourceID
	retry := &TeamDataRetry{Of: id}
	if original.Status != "failed" && original.Status != "canceled" && !(operation == "restore" && original.Status == "cleaned") && !(operation == "cleanup" && original.Status == "succeeded" && (original.Phase == "retry_blocked" || original.Phase == "retry_stopped")) {
		return TeamDataJob{}, errors.New("state_conflict")
	}
	switch operation {
	case "backup":
		phase := original.Phase
		if phase == "interrupted" {
			var report TeamDataReport
			_ = json.Unmarshal(original.Report, &report)
			phase = report.InterruptedPhase
		}
		// A publication may already exist after an uncertain reply. Reuse it for
		// verification; never overwrite/recollect that same artifact identity.
		if phase == "publishing" || phase == "verifying_backup" || (original.Phase == "interrupted" && phase == "") {
			if s.store.Client == nil {
				return TeamDataJob{}, errors.New("backup_result_unconfirmed")
			}
			artifact, z := OpenPublishedArtifact(ctx, s.store, s.cfg.InstallationID, id, s.catalog().PublicKey, s.cfg.KeyVersion)
			if z != nil {
				return TeamDataJob{}, errors.New("backup_result_unconfirmed")
			}
			if z = s.catalog().Import(ctx, artifact, actor, false); z != nil {
				return TeamDataJob{}, z
			}
			operation, source = "verify", id
		}
	case "restore":
		if original.Status != "cleaned" {
			operation, source, retry.Next = "cleanup", id, "restore"
		} else {
			// The cleanup handoff is not an active SQL slot. Do not let another
			// click queue a competing restore in this small continuation window.
			var waiting int
			if e := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_team_data_backup_jobs WHERE operation='cleanup' AND source_backup_id=? AND status='succeeded' AND phase='retry_pending'", id).Scan(&waiting); e != nil {
				return TeamDataJob{}, e
			}
			if waiting > 0 {
				return TeamDataJob{}, errors.New("conflict_active_job")
			}
		}
	case "cleanup":
		if r := teamDataRetry(original); r != nil && r.Next == "restore" {
			if original.Status == "succeeded" {
				restored, z := s.Get(ctx, original.SourceID)
				if z != nil || restored.Status != "cleaned" {
					return TeamDataJob{}, errors.New("state_conflict")
				}
				operation, source = "restore", restored.SourceID
			} else {
				retry.Next = "restore"
			}
		}
	case "verify", "delete":
	default:
		return TeamDataJob{}, errors.New("state_conflict")
	}
	return s.createWithRetry(ctx, actor, key, operation, source, retry)
}

// The connection-owned worker mutex already serializes this loop. A stable
// child key makes crash/reply-loss recovery idempotent; no source action occurs
// before the queued child is later claimed by the normal executor.
func (s *TeamDataService) continueQueuedRetry(ctx context.Context) error {
	var id string
	e := s.db.QueryRowContext(ctx, "SELECT public_id FROM system_team_data_backup_jobs WHERE operation='cleanup' AND status='succeeded' AND phase='retry_pending' ORDER BY created_at LIMIT 1").Scan(&id)
	if errors.Is(e, sql.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	job, e := s.Get(ctx, id)
	if e != nil {
		return e
	}
	retry := teamDataRetry(job)
	if retry == nil || retry.Next != "restore" || !publicIDPattern.MatchString(retry.Of) {
		return s.blockQueuedRetry(ctx, id, "state_conflict")
	}
	original, e := s.Get(ctx, job.SourceID)
	if e != nil {
		if e.Error() == "not_found" {
			return s.blockQueuedRetry(ctx, id, "state_conflict")
		}
		return e
	}
	if original.Operation != "restore" || original.Status != "cleaned" {
		return s.blockQueuedRetry(ctx, id, "state_conflict")
	}
	var actor int
	if e = s.db.QueryRowContext(ctx, "SELECT actor_id FROM system_team_data_backup_jobs WHERE public_id=?", id).Scan(&actor); e != nil {
		return e
	}
	key := "retry-followup-" + id
	// Reconcile an accepted child before applying the wait deadline: a lost
	// acknowledgement never authorizes creating a replacement child.
	child, e := scanTeamDataJob(s.db.QueryRowContext(ctx, "SELECT "+teamDataColumns+" FROM system_team_data_backup_jobs WHERE actor_id=? AND idempotency_key=?", actor, key))
	if e != nil && e.Error() != "not_found" {
		return e
	}
	if e == nil {
		bound := teamDataRetry(child)
		if child.Operation != "restore" || child.SourceID != original.SourceID || bound == nil || bound.Of != original.ID || bound.Next != "" {
			return s.blockQueuedRetry(ctx, id, "idempotency_conflict")
		}
	}
	if e != nil {
		started := job.CreatedAt
		if job.FinishedAt != nil {
			started = *job.FinishedAt
		}
		wait := s.cfg.DeadlineSeconds
		if wait < 1 {
			wait = 600
		}
		if time.Since(started) > time.Duration(wait)*time.Second {
			return s.blockQueuedRetry(ctx, id, "retry_deadline_exceeded")
		}
		child, e = s.createWithRetry(ctx, actor, key, "restore", original.SourceID, &TeamDataRetry{Of: original.ID})
	}
	if e != nil {
		if e.Error() == "conflict_active_job" {
			return nil
		}
		// An uncertain commit/connection result stays pending: re-read the stable
		// original child key next time. Only explicit domain denials are terminal.
		switch e.Error() {
		case "feature_disabled", "configuration_changed", "artifact_unavailable", "backup_deleting", "state_conflict", "idempotency_conflict":
			return s.blockQueuedRetry(ctx, id, teamDataFailure(e))
		}
		return e
	}
	_, e = s.db.ExecContext(ctx, "UPDATE system_team_data_backup_jobs SET phase='retry_started',error_code='',report_json=JSON_SET(report_json,'$.retry.followup_public_id',?),updated_at=UTC_TIMESTAMP(6) WHERE public_id=? AND status='succeeded' AND phase='retry_pending'", child.ID, id)
	return e
}

func (s *TeamDataService) blockQueuedRetry(ctx context.Context, id, reason string) error {
	_, e := s.db.ExecContext(ctx, "UPDATE system_team_data_backup_jobs SET phase='retry_blocked',error_code=?,updated_at=UTC_TIMESTAMP(6) WHERE public_id=? AND status='succeeded' AND phase='retry_pending'", reason, id)
	return e
}
