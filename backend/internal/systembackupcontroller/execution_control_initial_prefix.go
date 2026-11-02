package systembackupcontroller

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"time"

	d "clawreef/internal/systembackupdispatch"
)

// CANDIDATE R2, NOT YET DISPATCHED BY snapshotObserved. Every derived block is
// nonmergeable (LIMIT on an original unique point lookup), CURRENT locking and
// its PRIMARY KEY address depends on a NON-KEY value read from its predecessor.
// R1's mere lateral filter dependency was insufficient: MySQL read an inner
// const table before evaluating its correlated non-key filter, locking later
// maintenance/task rows early. Here the required address itself is unavailable
// until the preceding locking read delivers its non-key column. The chain is:
// e.engine -> g.scope; g.owner -> c.task_public_id;
// c.gate_generation -> m.origin_installation_id;
// m.row_version -> i.origin_installation_id;
// i.active_config_version -> active.version; active.enabled -> b.public_id.
// Non-key values are important: a predecessor key alone can be substituted
// from its equality predicate without reading/locking the predecessor row.
// The CASE guards only reject facts already rejected by the original held path.
// The required original prefix is:
// engine -> application gate -> runtime capture -> maintenance gate -> install
// -> active config -> task. A plain STRAIGHT_JOIN is insufficient: MySQL may
// read const/system tables during optimization before ordinary join execution.
// Root must verify the actual MySQL 8.4 execution/lock plan and differential
// results before enabling this in the original per-RPC read scope.
const originalHeldControlPrefixQuery = `SELECT
e.engine,g.phase,g.owner,g.fencing_token,g.generation,
c.gate_generation,c.acquire_token,c.held_token,c.collectors_stopped_at,c.source_resumed_at,c.acquire_until,c.hold_until,
m.gate_state,m.lock_owner,m.fencing_token,m.row_version,m.lease_expires_at,m.absolute_hold_deadline_at,
i.schema_version,i.row_version,i.active_config_version,active.schema_version,active.enabled,
b.schema_version,b.origin_installation_id,b.task_type,b.request_id,b.status,b.controller_owner,b.row_version,b.controller_lease_expires_at,b.deadline_at,b.config_version,b.config_snapshot_json,b.config_snapshot_size_bytes,b.config_snapshot_sha256
FROM (SELECT engine FROM system_backup_v2_engine_bindings WHERE scope='installation' LIMIT 1 FOR SHARE) e
JOIN LATERAL (
 SELECT phase,COALESCE(owner,'') AS owner,fencing_token,generation,scope
 FROM system_backup_gate
 WHERE scope=CASE WHEN BINARY e.engine=BINARY 'v2' THEN ? ELSE NULL END LIMIT 1 FOR SHARE
) g ON TRUE
JOIN LATERAL (
 SELECT gate_generation,acquire_token,held_token,collectors_stopped_at,source_resumed_at,acquire_until,hold_until
 FROM system_backup_v2_runtime_captures
 WHERE task_public_id=g.owner AND application_scope=g.scope AND BINARY g.owner=BINARY ? AND BINARY g.phase=BINARY 'held' LIMIT 1 FOR SHARE
) c ON TRUE
JOIN LATERAL (
 SELECT origin_installation_id,gate_state,COALESCE(lock_owner,'') AS lock_owner,fencing_token,row_version,lease_expires_at,absolute_hold_deadline_at
 FROM system_backup_v2_maintenance_locks
 WHERE origin_installation_id=CASE WHEN c.gate_generation>0 THEN ? ELSE NULL END
 AND scope=? AND lock_name='system_backup_capture_gate' AND fencing_token=c.gate_generation LIMIT 1 FOR UPDATE
) m ON TRUE
JOIN LATERAL (
 SELECT origin_installation_id,schema_version,row_version,active_config_version
 FROM system_backup_v2_installation_state
 WHERE origin_installation_id=CASE WHEN m.row_version>0 THEN m.origin_installation_id ELSE NULL END LIMIT 1 FOR UPDATE
) i ON TRUE
JOIN LATERAL (
 SELECT origin_installation_id,schema_version,enabled
 FROM system_backup_v2_configs WHERE origin_installation_id=i.origin_installation_id AND version=i.active_config_version LIMIT 1 FOR SHARE
) active ON TRUE
JOIN LATERAL (
 SELECT schema_version,origin_installation_id,task_type,request_id,status,controller_owner,row_version,controller_lease_expires_at,deadline_at,config_version,config_snapshot_json,config_snapshot_size_bytes,config_snapshot_sha256
 FROM system_backup_v2_backups
 WHERE origin_installation_id=active.origin_installation_id
 AND public_id=CASE WHEN active.enabled THEN ? ELSE NULL END LIMIT 1 FOR UPDATE
) b ON TRUE`

type originalHeldControlPrefix struct {
	engine, phase, applicationOwner                      string
	applicationToken, generation, epoch, acquireToken    uint64
	heldToken                                            sql.NullInt64
	stopped, resumed                                     sql.NullTime
	acquiringUntil, acquiringHold                        time.Time
	maintenanceFence                                     uint64
	gateLease, hold                                      sql.NullTime
	stateSchema, configSchema                            string
	enabled                                              bool
	activeVersion                                        uint64
	taskSchema, origin, kind, request, owner, configHash string
	taskVersion, configSize, configVersion               uint64
	deadline                                             time.Time
	snapshot                                             executionSnapshot
}

func (s SQLExecutionAuthority) readOriginalHeldControlPrefix(ctx context.Context, tx *sql.Tx, a d.Authority) (originalHeldControlPrefix, error) {
	var p originalHeldControlPrefix
	v := &p.snapshot
	if tx == nil || !validExecutionInput(a, s.InstallationID) || s.ApplicationScope == "" || a.TaskType != "backup" || a.Phase != "capture" || a.MaintenanceFencingToken == 0 {
		return p, ErrExecutionAuthority
	}
	err := tx.QueryRowContext(ctx, originalHeldControlPrefixQuery, s.ApplicationScope, a.TaskPublicID, s.InstallationID, CaptureGateScope, a.TaskPublicID).Scan(
		&p.engine, &p.phase, &p.applicationOwner, &p.applicationToken, &p.generation,
		&p.epoch, &p.acquireToken, &p.heldToken, &p.stopped, &p.resumed, &p.acquiringUntil, &p.acquiringHold,
		&v.gateState, &v.gateOwner, &p.maintenanceFence, &v.gateVersion, &p.gateLease, &p.hold,
		&p.stateSchema, &v.installationVersion, &p.activeVersion, &p.configSchema, &p.enabled,
		&p.taskSchema, &p.origin, &p.kind, &p.request, &v.status, &p.owner, &p.taskVersion, &v.claimUntil, &p.deadline, &p.configVersion, &v.config, &p.configSize, &p.configHash)
	if err != nil {
		return originalHeldControlPrefix{}, err
	}
	return p, nil
}

// The original held branch's predicates are unchanged. Any acquiring/released
// state refuses this scoped forward source-I/O path; it cannot fall back after
// acquiring a different prefix or adopt a new claim/epoch/expiry.
func (p originalHeldControlPrefix) validated(a d.Authority) (executionSnapshot, error) {
	v := p.snapshot
	if p.engine != "v2" || p.phase != "held" || p.applicationOwner != a.TaskPublicID || p.generation != a.MaintenanceFencingToken || p.epoch != a.MaintenanceFencingToken || !p.heldToken.Valid || p.applicationToken != uint64(p.heldToken.Int64) || v.gateState != "held" || v.gateVersion == 0 || p.activeVersion == 0 || p.stateSchema != "system-backup-installation-state.v1" || p.configSchema != "system-backup-config.v1" || !p.enabled || v.installationVersion == 0 || p.taskSchema != "system-backup-task.v1" || p.origin != a.InstallationID || p.kind != a.TaskType || p.request != a.RequestID || p.owner != a.ClaimOwner || p.taskVersion != a.ClaimRowVersion || !p.deadline.Equal(a.DeadlineAt) || p.configVersion != a.ConfigVersion || p.configHash != a.ConfigSHA256 || p.configSize != uint64(len(v.config)) || p.configSize < 2 || p.configSize > 262144 || !json.Valid(v.config) || v.status != "capturing" {
		return executionSnapshot{}, ErrExecutionAuthority
	}
	sum := sha256.Sum256(v.config)
	if hex.EncodeToString(sum[:]) != a.ConfigSHA256 {
		return executionSnapshot{}, ErrExecutionAuthority
	}
	v.gateUntil, v.holdUntil = p.gateLease.Time, p.hold.Time
	v.heldCapture = true
	return v, nil
}

func (s SQLExecutionAuthority) snapshotOriginalHeldControl(ctx context.Context, tx *sql.Tx, a d.Authority, report func(ExecutionBindDiagnostic)) (executionSnapshot, error) {
	p, err := s.readOriginalHeldControlPrefix(ctx, tx, a)
	if err != nil {
		reportExecutionBindDiagnostic(report, "bind-snapshot-held-current-prefix", err)
		return executionSnapshot{}, ErrExecutionAuthority
	}
	v, err := p.validated(a)
	if err != nil {
		reportExecutionBindDiagnostic(report, "bind-snapshot-held-prefix-facts", err)
		return executionSnapshot{}, err
	}
	// The original remaining facts query and its separate POST-DELIVERY SQL
	// clock remain; owner authorization still runs afterwards in BindObserved.
	return s.completeHeldSnapshot(ctx, tx, a, v, p.maintenanceFence, report)
}
