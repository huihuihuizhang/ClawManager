package systembackupevidence

import (
	"context"
	"database/sql"
	"time"
)

func taskTable(kind string) string {
	switch kind {
	case "backup":
		return "system_backup_v2_backups"
	case "drill":
		return "system_backup_v2_restore_drills"
	case "preflight":
		return "system_backup_v2_preflights"
	case "artifact_verify":
		return "system_backup_v2_artifact_verifications"
	}
	return ""
}

func taskPhase(kind, phase string) bool {
	switch kind {
	case "backup":
		return oneOf(phase, "capture", "secret_capture", "publish")
	case "drill":
		return oneOf(phase, "restore", "normalize", "verify")
	case "preflight":
		return phase == "preflight"
	case "artifact_verify":
		return phase == "verify"
	}
	return false
}

func taskRunning(kind, phase, status string) bool {
	switch kind {
	case "backup":
		if phase == "publish" {
			return oneOf(status, "publishing", "finalization_unknown")
		}
		return oneOf(status, "preparing", "ready_for_capture", "acquiring_gate", "capturing", "validating")
	case "drill":
		return phase == "restore" && status == "restoring" || phase == "normalize" && status == "normalizing" || phase == "verify" && status == "verifying"
	case "preflight", "artifact_verify":
		return status == "running"
	}
	return false
}

type taskGrant struct {
	identity  Identity
	until     time.Time
	leaseHash string
}

// Every invocation takes fresh locking reads. This never runs inside the
// Registry's transaction and performs no remote I/O while holding DB locks.
// Lock order: all installations (D's common order), config, task, attempts,
// Job, evidence. Registry admission remains D-owned and mandatory.
func (a *SQLTaskAuthority) authorize(ctx context.Context, scope *S3Scope) (taskGrant, error) {
	return a.authorizeKey(ctx, scope, nil)
}

// A preparer additionally binds the current evidence KEK in the same locked
// config transaction. Preparing ciphertext precedes evidence row registration,
// so this path uses the live task/Job lease, not a fabricated evidence claim.
func (a *SQLTaskAuthority) authorizeKey(ctx context.Context, scope *S3Scope, expected *KeyRef) (taskGrant, error) {
	deny := func() (taskGrant, error) { return taskGrant{}, ErrDenied }
	if expected != nil && !expected.valid() {
		return deny()
	}
	until, err := a.peerExpiry(ctx)
	if err != nil {
		return deny()
	}
	c := a.c
	var access evidenceAccess
	if scope != nil {
		var ok bool
		access, ok = ctx.Value(evidenceAccessKey{}).(evidenceAccess)
		if !ok || !idPattern.MatchString(access.ID) {
			return deny()
		}
		if _, ok = evidenceAccessFrom(ctx, "task", access.ID); !ok {
			return deny()
		}
		if scope.Ref.Identity != c.Store.Identity || scope.Ref.Version != c.Store.Version ||
			!scope.Ref.valid(false) || scope.Ref.ImmutableVersion != "" || scope.Offset != 0 || scope.Length != 0 ||
			!(scope.Operation == S3Stat && scope.Object == (ObjectInfo{}) && scope.Deadline.IsZero() ||
				scope.Operation == S3Put && scope.Object.Version == "" && digestPattern.MatchString(scope.Object.SHA256) && scope.Object.Size > 0 && !scope.Deadline.IsZero()) {
			return deny()
		}
	}
	tx, err := c.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return deny()
	}
	defer tx.Rollback()
	var server, database string
	var now time.Time
	var offset int64
	if tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))").Scan(&server, &database, &now, &offset) != nil ||
		server != c.ServerUUID || database != c.Database || offset != 0 || now.IsZero() {
		return deny()
	}
	rows, err := tx.QueryContext(ctx, "SELECT origin_installation_id FROM system_backup_v2_installation_state ORDER BY origin_installation_id FOR UPDATE")
	if err != nil {
		return deny()
	}
	count, found := 0, false
	for rows.Next() {
		var installation string
		if rows.Scan(&installation) != nil {
			rows.Close()
			return deny()
		}
		count++
		if count > 10000 {
			rows.Close()
			return deny()
		}
		found = found || installation == c.Installation
	}
	readErr := rows.Err()
	closeErr := rows.Close()
	if readErr != nil || closeErr != nil || !found {
		return deny()
	}
	var version int64
	var enabled bool
	if tx.QueryRowContext(ctx, "SELECT active_config_version,last_effective_enabled FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR UPDATE", c.Installation).Scan(&version, &enabled) != nil || version != c.ConfigVersion || !enabled {
		return deny()
	}
	var configHash string
	var configSize int64
	var store, write KeyRef
	if tx.QueryRowContext(ctx, `SELECT config_sha256,config_size_bytes,enabled,evidence_store_identity_hash,evidence_store_ref_version,evidence_write_identity_hash,evidence_write_ref_version
FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? FOR UPDATE`, c.Installation, c.ConfigVersion).Scan(&configHash, &configSize, &enabled, &store.Identity, &store.Version, &write.Identity, &write.Version) != nil ||
		configHash != c.ConfigSHA256 || configSize < 2 || configSize > 262144 || !enabled || store != c.Store || write != c.Write {
		return deny()
	}
	var status, snapshotHash string
	if expected != nil {
		var key KeyRef
		if tx.QueryRowContext(ctx, `SELECT evidence_kek_identity_hash,evidence_kek_ref_version
FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? FOR UPDATE`, c.Installation, c.ConfigVersion).Scan(&key.Identity, &key.Version) != nil || key != *expected {
			return deny()
		}
	}
	var snapshot []byte
	var snapshotSize int64
	var controller sql.NullString
	var lease sql.NullTime
	var deadline time.Time
	// Table names come only from the closed taskTable switch, never request SQL.
	if tx.QueryRowContext(ctx, `SELECT config_version,config_snapshot_sha256,config_snapshot_size_bytes,config_snapshot_json,status,controller_owner,controller_lease_expires_at,deadline_at
FROM `+taskTable(c.OwnerType)+` WHERE origin_installation_id=? AND public_id=? FOR UPDATE`, c.Installation, c.OwnerID).Scan(&version, &snapshotHash, &snapshotSize, &snapshot, &status, &controller, &lease, &deadline) != nil {
		return deny()
	}
	defer wipe(snapshot)
	if version != c.ConfigVersion || snapshotHash != c.ConfigSHA256 || snapshotSize != configSize || int64(len(snapshot)) != configSize || hash(snapshot) != snapshotHash ||
		!taskRunning(c.OwnerType, c.Phase, status) || !controller.Valid || controller.String != c.ControllerOwner || !lease.Valid {
		return deny()
	}
	until = earlier(earlier(until, deadline), lease.Time)
	var attempt int64
	if tx.QueryRowContext(ctx, `SELECT attempt_no,status FROM system_backup_v2_attempts
WHERE target_type=? AND target_public_id=? AND phase=? ORDER BY attempt_no DESC LIMIT 1 FOR UPDATE`, c.OwnerType, c.OwnerID, c.Phase).Scan(&attempt, &status) != nil ||
		attempt != c.Attempt || !oneOf(status, "preparing", "running", "sealed") {
		return deny()
	}
	var jobUID, relay, relayVersion string
	var generation int64
	var bound, relayUntil time.Time
	if tx.QueryRowContext(ctx, `SELECT job_uid,job_generation,relay_identity_ref,relay_identity_version,relay_identity_bound_at,relay_identity_expires_at
FROM system_backup_v2_job_observations WHERE origin_installation_id=? AND target_type=? AND target_public_id=? AND attempt_no=? AND phase=? AND job_unit_key=? FOR UPDATE`, c.Installation, c.OwnerType, c.OwnerID, c.Attempt, c.Phase, c.JobUnit).Scan(&jobUID, &generation, &relay, &relayVersion, &bound, &relayUntil) != nil ||
		jobUID != c.JobUID || generation != c.JobGeneration || relay != c.RelayIdentity || relayVersion != c.RelayVersion || bound.IsZero() || !relayUntil.After(bound) {
		return deny()
	}
	until = earlier(until, relayUntil)
	grant := taskGrant{}
	if scope != nil {
		var claimUntil, expires time.Time
		grant.identity, claimUntil, expires, err = a.lockEvidence(ctx, tx, access, *scope, deadline)
		if err != nil {
			return deny()
		}
		until = earlier(earlier(until, claimUntil), expires)
	}
	// A lock wait may consume the complete lease. Database UTC is authoritative;
	// reject local clock drift instead of accidentally extending a grant.
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || !now.Before(until) || now.Before(bound) ||
		time.Since(now) > 5*time.Second || time.Until(now) > 5*time.Second || !time.Now().Before(until) || ctx.Err() != nil {
		return deny()
	}
	grant.until = until
	grant.leaseHash = hash(canonical(struct {
		Principal                                         string
		Access                                            evidenceAccess
		ControllerUntil, Deadline, RelayBound, RelayUntil time.Time
	}{a.principal, access, lease.Time, deadline, bound, relayUntil}))
	if tx.Commit() != nil || ctx.Err() != nil || !time.Now().Before(until) {
		return deny()
	}
	return grant, nil
}

func (a *SQLTaskAuthority) lockEvidence(ctx context.Context, tx *sql.Tx, access evidenceAccess, scope S3Scope, deadline time.Time) (Identity, time.Time, time.Time, error) {
	deny := func() (Identity, time.Time, time.Time, error) { return Identity{}, time.Time{}, time.Time{}, ErrDenied }
	i := Identity{Installation: a.c.Installation, ID: access.ID}
	var ref Ref
	var immutable sql.NullString
	var state, role, keyHash, objectHash, encryption, framing, claim string
	var size, rowVersion int64
	var until, expires time.Time
	if tx.QueryRowContext(ctx, `SELECT owner_target_type,owner_target_public_id,evidence_type,media_type,redaction_classification,content_checksum,content_size_bytes,
storage_state,storage_provider_role,storage_identity_hash,storage_ref_version,storage_relative_key,storage_relative_key_hash,storage_immutable_version,
object_checksum,object_size_bytes,encryption,envelope_framing_version,claim_owner,claim_expires_at,expires_at,row_version
FROM system_backup_v2_evidence WHERE public_id=? FOR UPDATE`, access.ID).Scan(&i.OwnerType, &i.OwnerID, &i.Type, &i.Media, &i.Classification, &i.ContentHash, &i.ContentSize,
		&state, &role, &ref.Identity, &ref.Version, &ref.RelativeKey, &keyHash, &immutable, &objectHash, &size, &encryption, &framing, &claim, &until, &expires, &rowVersion) != nil {
		return deny()
	}
	ref.ImmutableVersion = immutable.String
	key, err := keyFor(a.c.Root, i)
	if err != nil || !a.accepts(i) || ref != scope.Ref || ref.RelativeKey != key || keyHash != hash([]byte(key)) || role != "evidence" ||
		!oneOf(state, "pending", "write_unknown") || encryption != "envelope_v1" || framing != Framing || !digestPattern.MatchString(objectHash) || size <= 0 || size > maxS3EvidenceObject ||
		claim != access.Claim || rowVersion != access.RowVersion ||
		scope.Operation == S3Put && (scope.Object != (ObjectInfo{SHA256: objectHash, Size: size}) || !scope.Deadline.Equal(deadline)) {
		return deny()
	}
	return i, until, expires, nil
}
