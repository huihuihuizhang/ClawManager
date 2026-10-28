package systembackupcontroller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"sync"
	"time"

	dispatch "clawreef/internal/systembackupdispatch"
)

var ErrExecutionAuthority = errors.New("public execution authority unavailable")
var executionHash = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ExecutionAuthorization supplies A's current purpose/resource authorization,
// revocation and expiry checks inside this SAME transaction. It must not open
// another SQL connection, commit, or contact a provider. Matching hashes alone
// are not authorization. No missing-owner/default-allow implementation exists.
type ExecutionAuthorization interface {
	AuthorizeExecution(context.Context, *sql.Tx, dispatch.Authority, time.Time) (ExecutionAuthorizationGuard, error)
}

type ExecutionAuthorizationGuard interface {
	RecheckExecution(context.Context, *sql.Tx, dispatch.Authority, time.Time) error
	ValidUntil() time.Time
}

func absentExecutionDependency(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Func, reflect.Map, reflect.Slice, reflect.Chan:
		return r.IsNil()
	}
	return false
}

// SQLExecutionAuthority is the Check implementation for the public B ports.
// It also exposes the original-transaction guard needed by relay/ledger writes.
// It grants only live preparing/capturing backup and running preflight work;
// recovery, sealed data, publication and Job creation need their own guards.
// In particular cancellation/expired authority can never authorize resume.
type SQLExecutionAuthority struct {
	DB                *sql.DB
	InstallationID    string
	Authorization     ExecutionAuthorization
	DeploymentEnabled bool
	// ApplicationScope binds the public metadata fence to the existing Team
	// business gate. Production work stores require this explicit mapping.
	ApplicationScope string
}

type executionSnapshot struct {
	status, attemptStatus, gateState, gateOwner      string
	claimUntil, gateUntil, holdUntil, now            time.Time
	gateVersion, attemptVersion, installationVersion uint64
	config                                           []byte
}

func validExecutionInput(a dispatch.Authority, installation string) bool {
	if !installationIDPattern.MatchString(installation) || a.InstallationID != installation ||
		!controllerOwnerPattern.MatchString(a.RequestID) || !controllerOwnerPattern.MatchString(a.ClaimOwner) ||
		a.ClaimRowVersion == 0 || a.ClaimRowVersion == ^uint64(0) || a.ConfigVersion == 0 ||
		!executionHash.MatchString(a.ConfigSHA256) || a.AttemptNo == 0 || a.AttemptNo > uint64(^uint32(0)) || a.DeadlineAt.IsZero() {
		return false
	}
	t := Target{Kind: TargetKind(a.TaskType), PublicID: a.TaskPublicID}
	if _, err := t.descriptor(); err != nil {
		return false
	}
	switch t.Kind {
	case TargetBackup:
		return a.Phase == "capture" && ((a.MaintenanceOwner == "" && a.MaintenanceFencingToken == 0) ||
			(controllerOwnerPattern.MatchString(a.MaintenanceOwner) && a.MaintenanceFencingToken > 0))
	case TargetPreflight:
		return a.Phase == "preflight" && a.MaintenanceOwner == "" && a.MaintenanceFencingToken == 0
	}
	return false
}

func (s SQLExecutionAuthority) snapshot(ctx context.Context, tx *sql.Tx, a dispatch.Authority) (executionSnapshot, error) {
	var v executionSnapshot
	postCapture := false
	var acquiringUntil, acquiringHold time.Time
	if tx == nil || !validExecutionInput(a, s.InstallationID) {
		return v, ErrExecutionAuthority
	}
	if s.ApplicationScope != "" {
		var engine, phase, owner string
		var token, generation uint64
		if tx.QueryRowContext(ctx, "SELECT engine FROM system_backup_v2_engine_bindings WHERE scope='installation' FOR SHARE").Scan(&engine) != nil || engine != "v2" {
			return v, ErrExecutionAuthority
		}
		if tx.QueryRowContext(ctx, "SELECT phase,COALESCE(owner,''),fencing_token,generation FROM system_backup_gate WHERE scope=? FOR SHARE", s.ApplicationScope).Scan(&phase, &owner, &token, &generation) != nil {
			return v, ErrExecutionAuthority
		}
		if a.MaintenanceFencingToken == 0 {
			if phase != "idle" && !(phase == "acquiring" && owner == a.TaskPublicID) {
				return v, ErrExecutionAuthority
			}
		} else {
			// The public epoch is the acquisition generation. The application's
			// held token is separate and must be checked by Job admission.
			var epoch, acquireToken uint64
			var heldToken sql.NullInt64
			var stopped, resumed sql.NullTime
			if tx.QueryRowContext(ctx, "SELECT gate_generation,acquire_token,held_token,collectors_stopped_at,source_resumed_at,acquire_until,hold_until FROM system_backup_v2_runtime_captures WHERE task_public_id=? AND application_scope=? FOR SHARE", a.TaskPublicID, s.ApplicationScope).Scan(&epoch, &acquireToken, &heldToken, &stopped, &resumed, &acquiringUntil, &acquiringHold) != nil || epoch != a.MaintenanceFencingToken {
				return v, ErrExecutionAuthority
			}
			postCapture = resumed.Valid && stopped.Valid && phase == "idle"
			if !postCapture && (owner != a.TaskPublicID || generation != epoch || (phase != "acquiring" && phase != "held") || (phase == "acquiring" && token != acquireToken) || (phase == "held" && (!heldToken.Valid || token != uint64(heldToken.Int64)))) {
				return v, ErrExecutionAuthority
			}
		}
	}
	// Preserve the common coordination lock order: gate before business rows.
	var gateLease, hold sql.NullTime
	var fence uint64
	err := tx.QueryRowContext(ctx, "SELECT gate_state,COALESCE(lock_owner,''),fencing_token,row_version,lease_expires_at,absolute_hold_deadline_at FROM system_backup_v2_maintenance_locks WHERE origin_installation_id=? AND scope=? AND lock_name='system_backup_capture_gate' FOR UPDATE", s.InstallationID, CaptureGateScope).Scan(&v.gateState, &v.gateOwner, &fence, &v.gateVersion, &gateLease, &hold)
	if err != nil || v.gateVersion == 0 {
		return v, ErrExecutionAuthority
	}
	v.gateUntil, v.holdUntil = gateLease.Time, hold.Time
	if s.ApplicationScope != "" && v.gateState == "acquiring" && a.MaintenanceFencingToken != 0 {
		v.gateUntil = acquiringUntil
		v.holdUntil = acquiringHold
	}
	if postCapture {
		v.gateUntil = a.DeadlineAt
		v.holdUntil = a.DeadlineAt
	}
	var stateSchema, configSchema string
	var enabled bool
	var activeVersion uint64
	err = tx.QueryRowContext(ctx, "SELECT schema_version,row_version,active_config_version FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR UPDATE", s.InstallationID).Scan(&stateSchema, &v.installationVersion, &activeVersion)
	if err != nil || activeVersion == 0 {
		return v, ErrExecutionAuthority
	}
	// Config history is read-only to this role. Do not lock the join with
	// FOR UPDATE (which would demand UPDATE/DELETE/LOCK TABLES on configs).
	err = tx.QueryRowContext(ctx, "SELECT schema_version,enabled FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? FOR SHARE", s.InstallationID, activeVersion).Scan(&configSchema, &enabled)
	if err != nil || stateSchema != "system-backup-installation-state.v1" || configSchema != "system-backup-config.v1" || !enabled || v.installationVersion == 0 {
		return v, ErrExecutionAuthority
	}
	d, _ := (Target{Kind: TargetKind(a.TaskType), PublicID: a.TaskPublicID}).descriptor()
	var schema, request, owner, hash, kind, origin string
	var version, size, configVersion uint64
	var deadline time.Time
	query := "SELECT schema_version,origin_installation_id,task_type,request_id,status,controller_owner,row_version,controller_lease_expires_at,deadline_at,config_version,config_snapshot_json,config_snapshot_size_bytes,config_snapshot_sha256 FROM " + d.table + " WHERE origin_installation_id=? AND public_id=? FOR UPDATE"
	err = tx.QueryRowContext(ctx, query, s.InstallationID, a.TaskPublicID).Scan(&schema, &origin, &kind, &request, &v.status, &owner, &version, &v.claimUntil, &deadline, &configVersion, &v.config, &size, &hash)
	if err != nil || schema != "system-backup-task.v1" || origin != a.InstallationID || kind != a.TaskType || request != a.RequestID || owner != a.ClaimOwner || version != a.ClaimRowVersion || !deadline.Equal(a.DeadlineAt) || configVersion != a.ConfigVersion || hash != a.ConfigSHA256 || size != uint64(len(v.config)) || size < 2 || size > 262144 || !json.Valid(v.config) {
		return v, ErrExecutionAuthority
	}
	digest := sha256.Sum256(v.config)
	if hex.EncodeToString(digest[:]) != a.ConfigSHA256 {
		return v, ErrExecutionAuthority
	}
	var original []byte
	if tx.QueryRowContext(ctx, "SELECT canonical_config_json FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? AND config_sha256=? AND config_size_bytes=? FOR SHARE", a.InstallationID, a.ConfigVersion, a.ConfigSHA256, size).Scan(&original) != nil || !bytes.Equal(original, v.config) {
		return v, ErrExecutionAuthority
	}
	var latest uint64
	if tx.QueryRowContext(ctx, "SELECT attempt_no FROM system_backup_v2_attempts WHERE target_type=? AND target_public_id=? AND phase=? ORDER BY attempt_no DESC LIMIT 1 FOR SHARE", a.TaskType, a.TaskPublicID, a.Phase).Scan(&latest) != nil || latest != a.AttemptNo {
		return v, ErrExecutionAuthority
	}
	err = tx.QueryRowContext(ctx, "SELECT status,row_version FROM system_backup_v2_attempts WHERE target_type=? AND target_public_id=? AND attempt_no=? AND phase=? FOR SHARE", a.TaskType, a.TaskPublicID, a.AttemptNo, a.Phase).Scan(&v.attemptStatus, &v.attemptVersion)
	if err != nil || v.attemptVersion == 0 {
		return v, ErrExecutionAuthority
	}
	if a.TaskType == string(TargetBackup) {
		if s.ApplicationScope != "" {
			requested, err := executionCancelRequested(ctx, tx, a)
			if err != nil || requested {
				return v, ErrExecutionAuthority
			}
		}
		if v.status == "preparing" || v.status == "ready_for_capture" || v.status == "acquiring_gate" {
			if v.attemptStatus != "preparing" || a.MaintenanceOwner != "" || a.MaintenanceFencingToken != 0 {
				return v, ErrExecutionAuthority
			}
		} else if v.status == "capturing" {
			var taskOwner string
			var taskFence uint64
			gateOK := v.gateState == "held"
			if s.ApplicationScope != "" {
				gateOK = v.gateState == "held" || v.gateState == "acquiring" || (postCapture && v.gateState == "idle")
			}
			if tx.QueryRowContext(ctx, "SELECT maintenance_lock_owner,maintenance_fencing_token FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=? FOR UPDATE", a.InstallationID, a.TaskPublicID).Scan(&taskOwner, &taskFence) != nil || v.attemptStatus != "running" || !gateOK || (!postCapture && v.gateOwner != a.MaintenanceOwner) || fence != a.MaintenanceFencingToken || taskOwner != a.MaintenanceOwner || taskFence != fence || fence == 0 {
				return v, ErrExecutionAuthority
			}
		} else {
			return v, ErrExecutionAuthority
		}
	} else if v.status != "running" || v.attemptStatus != "running" {
		return v, ErrExecutionAuthority
	}
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&v.now) != nil || v.now.IsZero() || !v.now.Before(v.claimUntil) || !v.now.Before(a.DeadlineAt) {
		return v, ErrExecutionAuthority
	}
	if v.status == "capturing" && !postCapture && (!v.now.Before(v.gateUntil) || !v.now.Before(v.holdUntil)) {
		return v, ErrExecutionAuthority
	}
	return v, nil
}

// ExecutionAuthorityGuard is transaction-bound and failure-latched. Recheck
// cannot replace an old claim with a newly renewed row version, extend a lease,
// or grant recovery. Callers must make this their final check before commit.
type ExecutionAuthorityGuard struct{ state *executionAuthorityState }
type executionAuthorityState struct {
	mu        sync.Mutex
	store     SQLExecutionAuthority
	ctx       context.Context
	tx        *sql.Tx
	authority dispatch.Authority
	first     executionSnapshot
	owner     ExecutionAuthorizationGuard
	until     time.Time
	floor     time.Time
	failed    bool
}

func (s SQLExecutionAuthority) Bind(ctx context.Context, tx *sql.Tx, a dispatch.Authority) (*ExecutionAuthorityGuard, error) {
	if absentExecutionDependency(ctx) || !reflect.TypeOf(ctx).Comparable() || ctx.Err() != nil || !s.DeploymentEnabled || absentExecutionDependency(s.Authorization) {
		return nil, ErrExecutionAuthority
	}
	v, err := s.snapshot(ctx, tx, a)
	if err != nil {
		return nil, err
	}
	owner, err := s.Authorization.AuthorizeExecution(ctx, tx, a, v.now)
	if err != nil || absentExecutionDependency(owner) {
		return nil, ErrExecutionAuthority
	}
	until := owner.ValidUntil()
	if until.IsZero() || !v.now.Before(until) {
		return nil, ErrExecutionAuthority
	}
	return &ExecutionAuthorityGuard{state: &executionAuthorityState{store: s, ctx: ctx, tx: tx, authority: a, first: v, owner: owner, until: until, floor: v.now}}, nil
}

// ValidUntil is the ORIGINAL shortest bound, not a grant or a renewed lease.
// A transaction adding fixed SQL after Recheck must sample SQL time again and
// remain strictly before this bound immediately before its unique commit.
func (g *ExecutionAuthorityGuard) ValidUntil() time.Time {
	if g == nil || g.state == nil {
		return time.Time{}
	}
	s := g.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return time.Time{}
	}
	until := s.until
	for _, bound := range []time.Time{s.first.claimUntil, s.authority.DeadlineAt} {
		if bound.Before(until) {
			until = bound
		}
	}
	if s.first.status == "capturing" {
		for _, bound := range []time.Time{s.first.gateUntil, s.first.holdUntil} {
			if bound.Before(until) {
				until = bound
			}
		}
	}
	return until
}

// ObservedAt is the last successful SQL clock floor. Later fixed SQL checks
// must preserve it; this detached timestamp conveys no execution authority.
func (g *ExecutionAuthorityGuard) ObservedAt() time.Time {
	if g == nil || g.state == nil {
		return time.Time{}
	}
	s := g.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return time.Time{}
	}
	return s.floor
}

func (g *ExecutionAuthorityGuard) Recheck(ctx context.Context, tx *sql.Tx) error {
	return g.RecheckAfter(ctx, tx, time.Time{})
}

// RecheckAfter preserves a caller's newer SQL clock without renewing any
// original expiry. The bound is checked BEFORE the A owner callback.
func (g *ExecutionAuthorityGuard) RecheckAfter(ctx context.Context, tx *sql.Tx, notBefore time.Time) error {
	if g == nil || g.state == nil {
		return ErrExecutionAuthority
	}
	s := g.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed {
		return ErrExecutionAuthority
	}
	// Copies share this latch and the original context/transaction identity.
	s.failed = true
	if absentExecutionDependency(ctx) || !reflect.TypeOf(ctx).Comparable() || ctx != s.ctx || ctx.Err() != nil || tx == nil || tx != s.tx {
		return ErrExecutionAuthority
	}
	var beforeOwner time.Time
	floor := s.floor
	if notBefore.After(floor) {
		floor = notBefore
	}
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&beforeOwner) != nil || beforeOwner.Before(floor) || !beforeOwner.Before(s.until) {
		return ErrExecutionAuthority
	}
	if s.owner.RecheckExecution(ctx, tx, s.authority, beforeOwner) != nil || !s.owner.ValidUntil().Equal(s.until) {
		return ErrExecutionAuthority
	}
	v, err := s.store.snapshot(ctx, tx, s.authority)
	f := s.first
	if err != nil || v.now.Before(beforeOwner) || !v.now.Before(s.until) || v.status != f.status || v.attemptStatus != f.attemptStatus || v.attemptVersion != f.attemptVersion || v.installationVersion != f.installationVersion || v.gateVersion != f.gateVersion || v.gateState != f.gateState || v.gateOwner != f.gateOwner || !v.claimUntil.Equal(f.claimUntil) || !v.gateUntil.Equal(f.gateUntil) || !v.holdUntil.Equal(f.holdUntil) || !bytes.Equal(v.config, f.config) || ctx.Err() != nil {
		return ErrExecutionAuthority
	}
	s.failed = false
	s.floor = v.now
	return nil
}

func (s SQLExecutionAuthority) Check(ctx context.Context, a dispatch.Authority) error {
	if s.DB == nil || absentExecutionDependency(ctx) || !reflect.TypeOf(ctx).Comparable() || ctx.Err() != nil {
		return ErrExecutionAuthority
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return ErrExecutionAuthority
	}
	defer tx.Rollback()
	g, err := s.Bind(ctx, tx, a)
	if err != nil {
		return err
	}
	return g.Recheck(ctx, tx)
}
