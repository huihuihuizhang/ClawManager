package systembackupcontroller

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

var ErrExecutionInput = errors.New("backup execution input invalid")

// ClaimedBackup carries immutable admitted inputs, not current configuration.
// RecoveryRequired forbids blindly rerunning an old operation after a lease
// takeover, including a pending task whose prior owner may have sent work.
type ClaimedBackup struct {
	Claim                             ClaimToken
	InstallationID, Status, RequestID string
	ConfigVersion                     uint64
	ConfigSHA256, ProfileSHA256       string
	Config, Profile, Request          json.RawMessage
	Deadline                          time.Time
	RecoveryRequired                  bool
}

// SQLExecutionQueue uses the public task as its sole state authority. It does
// not create a legacy shadow task or call providers inside its SQL transaction.
type SQLExecutionQueue struct {
	DB                    *sql.DB
	InstallationID, Owner string
	Policy                LeasePolicy
	// Public execution additionally authorizes and records both phase units in
	// the acquisition transaction. The historical reader remains compatible.
	Authorization    ExecutionAuthorization
	ApplicationScope string
	Recovery         *SQLRecoveryAuthority
}

func (q SQLExecutionQueue) validate() error {
	if q.DB == nil || !installationIDPattern.MatchString(q.InstallationID) || !controllerOwnerPattern.MatchString(q.Owner) {
		return ErrExecutionInput
	}
	return q.Policy.Validate()
}

// TakeBackup admits one installation-wide backup at a time. An active or
// uncertain older backup must be reconciled before a newer capture can start.
// Preflight/verification scheduling is independent of this capture queue.
func (q SQLExecutionQueue) TakeBackup(ctx context.Context) (ClaimedBackup, error) {
	var out ClaimedBackup
	if err := q.validate(); err != nil {
		return out, err
	}
	tx, err := q.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var engine string
	if err = tx.QueryRowContext(ctx, "SELECT engine FROM system_backup_v2_engine_bindings WHERE scope='installation' FOR UPDATE").Scan(&engine); err != nil {
		return out, err
	}
	if engine != "v2" {
		return out, ErrClaimNotAcquired
	}
	var enabled bool
	if err = tx.QueryRowContext(ctx, "SELECT last_effective_enabled FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR UPDATE", q.InstallationID).Scan(&enabled); err != nil {
		return out, err
	}
	var id string
	var version uint64
	var previous sql.NullString
	var due, available bool
	err = tx.QueryRowContext(ctx, `SELECT public_id,row_version,controller_owner,
(next_reconcile_at IS NULL OR next_reconcile_at<=UTC_TIMESTAMP(6)),
(controller_owner IS NULL OR controller_lease_expires_at<=UTC_TIMESTAMP(6))
FROM system_backup_v2_backups WHERE origin_installation_id=?
AND status NOT IN ('succeeded','failed','canceled')
AND NOT (status IN ('validating','publishing','finalization_unknown') AND EXISTS(SELECT 1 FROM system_backup_v2_runtime_captures c WHERE c.task_public_id=system_backup_v2_backups.public_id AND c.collectors_stopped_at IS NOT NULL AND c.source_resumed_at IS NOT NULL))
ORDER BY created_at,id LIMIT 1 FOR UPDATE`, q.InstallationID).Scan(&id, &version, &previous, &due, &available)
	if errors.Is(err, sql.ErrNoRows) {
		return out, ErrClaimNotAcquired
	}
	if err != nil {
		return out, err
	}
	// Even the same owner string cannot start two concurrent local executions.
	if !due || !available {
		return out, ErrClaimNotAcquired
	}
	desc, _ := (Target{Kind: TargetBackup, PublicID: id}).descriptor()
	claim, err := stageTaskClaimWithReceipt(ctx, tx, q.InstallationID, Target{Kind: TargetBackup, PublicID: id}, q.Owner, version, q.Policy, desc, nil)
	if err != nil {
		return out, err
	}
	out, err = readClaimedBackup(ctx, tx, q.InstallationID, claim)
	if err != nil {
		return ClaimedBackup{}, err
	}
	var effects int
	err = tx.QueryRowContext(ctx, `SELECT
(SELECT COUNT(*) FROM system_backup_v2_attempts WHERE target_type='backup' AND target_public_id=?) +
(SELECT COUNT(*) FROM system_backup_v2_external_actions WHERE target_type='backup' AND target_public_id=?)`, id, id).Scan(&effects)
	if err != nil {
		return ClaimedBackup{}, err
	}
	out.RecoveryRequired = previous.Valid || effects != 0 || out.Status != "pending"
	if !out.RecoveryRequired {
		if !enabled {
			return ClaimedBackup{}, ErrClaimNotAcquired
		}
		out, err = q.startBackupTx(ctx, tx, out)
		if err != nil {
			return ClaimedBackup{}, err
		}
	}
	if q.Authorization != nil {
		input, e := out.ExecutionInput(ctx, tx)
		if e != nil {
			return ClaimedBackup{}, e
		}
		if !out.RecoveryRequired {
			phases := []string{"capture"}
			for _, part := range input.Backup.RequestedParts {
				if part == "secret_bundle" {
					phases = append(phases, "secret_capture")
				}
			}
			for _, phase := range phases {
				if _, err = tx.ExecContext(ctx, "INSERT INTO system_backup_v2_attempts(target_type,target_public_id,attempt_no,phase,status) VALUES('backup',?,1,?,'preparing')", id, phase); err != nil {
					return ClaimedBackup{}, err
				}
			}
			if _, err = tx.ExecContext(ctx, "INSERT INTO system_backup_v2_events(origin_installation_id,target_type,target_public_id,event_type,level,task_status,message,details_present,detail_attempt_number,request_id) VALUES(?,'backup',?,'attempt_started','info','preparing','Execution attempt started.',TRUE,1,?)", q.InstallationID, id, out.RequestID); err != nil {
				return ClaimedBackup{}, err
			}
		}
		if out.RecoveryRequired && q.Recovery != nil {
			if e = q.Recovery.CheckTx(ctx, tx, input.Authority); e != nil {
				return ClaimedBackup{}, e
			}
			if e = tx.Commit(); e != nil {
				return ClaimedBackup{}, ErrExecutionCommitUnknown
			}
			return out, nil
		}
		authority := SQLExecutionAuthority{DB: q.DB, InstallationID: q.InstallationID, Authorization: q.Authorization, DeploymentEnabled: true, ApplicationScope: q.ApplicationScope}
		guard, e := authority.Bind(ctx, tx, input.Authority)
		if e != nil {
			return ClaimedBackup{}, e
		}
		if e = guard.Recheck(ctx, tx); e != nil {
			return ClaimedBackup{}, e
		}
	}
	if err = tx.Commit(); err != nil {
		return ClaimedBackup{}, err
	}
	return out, nil
}

func readClaimedBackup(ctx context.Context, tx *sql.Tx, installation string, claim ClaimToken) (ClaimedBackup, error) {
	var out ClaimedBackup
	out.Claim, out.InstallationID = claim, installation
	var requestHash string
	var size int
	var valid bool
	err := tx.QueryRowContext(ctx, `SELECT b.status,b.request_id,b.config_version,b.config_snapshot_sha256,b.config_snapshot_size_bytes,
b.config_snapshot_json,i.profile_sha256,i.profile_json,i.request_json,b.request_hash,b.deadline_at,
b.controller_owner=? AND b.row_version=? AND b.controller_lease_expires_at>UTC_TIMESTAMP(6)
FROM system_backup_v2_backups b JOIN system_backup_v2_execution_inputs i
ON i.origin_installation_id=b.origin_installation_id AND i.task_public_id=b.public_id AND i.task_type='backup'
WHERE b.origin_installation_id=? AND b.public_id=? FOR SHARE`, claim.Owner, claim.RowVersion, installation, claim.Target.PublicID).Scan(
		&out.Status, &out.RequestID, &out.ConfigVersion, &out.ConfigSHA256, &size, &out.Config, &out.ProfileSHA256, &out.Profile, &out.Request, &requestHash, &out.Deadline, &valid)
	if err != nil {
		return out, err
	}
	if !valid {
		return out, ErrClaimLost
	}
	if size != len(out.Config) || !executionJSONMatches(out.Config, out.ConfigSHA256, 262144) || !executionJSONMatches(out.Profile, out.ProfileSHA256, 16384) || !executionJSONMatches(out.Request, requestHash, 16384) {
		return out, ErrExecutionInput
	}
	var identity struct {
		Installation string `json:"installation_id"`
	}
	if json.Unmarshal(out.Profile, &identity) != nil || identity.Installation != installation {
		return out, ErrExecutionInput
	}
	return out, nil
}

func executionJSONMatches(raw []byte, hash string, max int) bool {
	if len(raw) < 2 || len(raw) > max || !json.Valid(raw) {
		return false
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]) == hash
}

// This transition shares the acquisition transaction and its observation of
// the previous owner. A caller cannot discard RecoveryRequired then start an
// expired claimant's pending operation using a new token.
func (q SQLExecutionQueue) startBackupTx(ctx context.Context, tx *sql.Tx, out ClaimedBackup) (ClaimedBackup, error) {
	claim := out.Claim
	res, err := tx.ExecContext(ctx, `UPDATE system_backup_v2_backups SET status='preparing',pending_reason='none',started_at=UTC_TIMESTAMP(6),row_version=row_version+1
WHERE origin_installation_id=? AND public_id=? AND row_version=? AND controller_owner=? AND controller_lease_expires_at>UTC_TIMESTAMP(6) AND deadline_at>UTC_TIMESTAMP(6)
AND NOT EXISTS(SELECT 1 FROM system_backup_v2_attempts WHERE target_type='backup' AND target_public_id=?)
AND NOT EXISTS(SELECT 1 FROM system_backup_v2_external_actions WHERE target_type='backup' AND target_public_id=?)`, q.InstallationID, claim.Target.PublicID, claim.RowVersion, claim.Owner, claim.Target.PublicID, claim.Target.PublicID)
	if err != nil {
		return out, err
	}
	changed, err := exactlyOneRow(res)
	if err != nil {
		return out, err
	}
	if !changed {
		return out, ErrClaimLost
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO system_backup_v2_events(origin_installation_id,target_type,target_public_id,event_type,level,task_status,message,request_id)
VALUES(?,'backup',?,'task_status_changed','info','preparing','Execution preparation started',?)`, q.InstallationID, claim.Target.PublicID, out.RequestID); err != nil {
		return out, err
	}
	out.Claim.RowVersion++
	out.Status = "preparing"
	return out, nil
}
