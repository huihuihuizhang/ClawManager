package systembackupcontroller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"
)

const (
	MinMaintenanceLockTTL      = 65 * time.Second
	DefaultMaintenanceLockTTL  = 900 * time.Second
	MaxMaintenanceLockTTL      = 7200 * time.Second
	MinGateAcquisitionTimeout  = 10 * time.Second
	DefaultGateAcquisitionTime = 60 * time.Second
	MaxGateAcquisitionTimeout  = 600 * time.Second
	MinQuiesceMaxHold          = 30 * time.Second
	DefaultQuiesceMaxHold      = 600 * time.Second
	MaxQuiesceMaxHold          = 3600 * time.Second
)

var (
	installationIDPattern    = regexp.MustCompile(`^installation_[A-Za-z0-9._:-]{1,115}$`)
	coordinationScopePattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

	ErrGateTransitionRejected = errors.New("system backup maintenance gate transition rejected")
	ErrGateFenceLost          = errors.New("system backup maintenance gate fence lost")
	ErrGateHoldNotReady       = errors.New("system backup maintenance gate hold not ready")
	ErrGateRecoveryNotReady   = errors.New("system backup maintenance gate recovery not ready")
)

type GateState string

const (
	GateIdle      GateState = "idle"
	GateAcquiring GateState = "acquiring"
	GateHeld      GateState = "held"
	GateReleasing GateState = "releasing"
)

type GateKey struct {
	InstallationID string
	Scope          string
}

func (k GateKey) validate() error {
	if !installationIDPattern.MatchString(k.InstallationID) {
		return errors.New("invalid system backup installation ID")
	}
	if !coordinationScopePattern.MatchString(k.Scope) {
		return errors.New("invalid system backup maintenance scope")
	}
	return nil
}

type GatePolicy struct {
	LockTTL            time.Duration
	AcquisitionTimeout time.Duration
	MaxHold            time.Duration
}

func (p GatePolicy) Validate() error {
	for name, value := range map[string]time.Duration{
		"maintenance lock TTL":     p.LockTTL,
		"gate acquisition timeout": p.AcquisitionTimeout,
		"quiesce maximum hold":     p.MaxHold,
	} {
		if value%time.Second != 0 {
			return fmt.Errorf("%s must be a whole number of seconds", name)
		}
	}
	if p.LockTTL < MinMaintenanceLockTTL || p.LockTTL > MaxMaintenanceLockTTL {
		return fmt.Errorf("maintenance lock TTL must be between %s and %s", MinMaintenanceLockTTL, MaxMaintenanceLockTTL)
	}
	if p.AcquisitionTimeout < MinGateAcquisitionTimeout || p.AcquisitionTimeout > MaxGateAcquisitionTimeout {
		return fmt.Errorf("gate acquisition timeout must be between %s and %s", MinGateAcquisitionTimeout, MaxGateAcquisitionTimeout)
	}
	if p.MaxHold < MinQuiesceMaxHold || p.MaxHold > MaxQuiesceMaxHold {
		return fmt.Errorf("quiesce maximum hold must be between %s and %s", MinQuiesceMaxHold, MaxQuiesceMaxHold)
	}
	if p.LockTTL <= p.MaxHold {
		return errors.New("maintenance lock TTL must exceed quiesce maximum hold")
	}
	return nil
}

type GateSnapshot struct {
	Key          GateKey
	State        GateState
	Generation   uint64
	FencingToken uint64
	Owner        string
	RowVersion   uint64
}

type GateToken struct {
	GateSnapshot
}

func (t GateToken) validate(expected GateState) error {
	if err := t.Key.validate(); err != nil {
		return err
	}
	if t.State != expected || t.Generation < 1 || t.RowVersion < 1 {
		return errors.New("invalid system backup maintenance gate token")
	}
	if !controllerOwnerPattern.MatchString(t.Owner) {
		return errors.New("invalid system backup maintenance gate owner")
	}
	if (expected == GateHeld || expected == GateReleasing) && t.FencingToken < 1 {
		return errors.New("invalid system backup maintenance fence")
	}
	return nil
}

type MutationLeaseSnapshot struct {
	LeaseID    string
	Key        GateKey
	Owner      string
	Generation uint64
	RowVersion uint64
	Live       bool
}

// CoordinationTransaction fixes the mandatory lock order at the persistence
// boundary: gate row first, then lease rows, then any caller-owned business
// row. SQLCoordinationTransaction is the production adapter; tests can use a
// deterministic fake without adding a database driver dependency.
type CoordinationTransaction interface {
	Transaction
	LockGate(context.Context, GateKey) (GateSnapshot, error)
	LockMutationLease(context.Context, string) (MutationLeaseSnapshot, error)
	CountOutstandingMutationLeases(context.Context, GateKey, uint64) (uint64, error)
}

type SQLCoordinationTransaction struct {
	Tx *sql.Tx
}

func (t SQLCoordinationTransaction) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if t.Tx == nil {
		return nil, errors.New("nil system backup coordination SQL transaction")
	}
	return t.Tx.ExecContext(ctx, query, args...)
}

func (t SQLCoordinationTransaction) Commit() error {
	if t.Tx == nil {
		return errors.New("nil system backup coordination SQL transaction")
	}
	return t.Tx.Commit()
}

func (t SQLCoordinationTransaction) Rollback() error {
	if t.Tx == nil {
		return errors.New("nil system backup coordination SQL transaction")
	}
	return t.Tx.Rollback()
}

func (t SQLCoordinationTransaction) LockGate(ctx context.Context, key GateKey) (GateSnapshot, error) {
	if t.Tx == nil {
		return GateSnapshot{}, errors.New("nil system backup coordination SQL transaction")
	}
	if err := key.validate(); err != nil {
		return GateSnapshot{}, err
	}
	var snapshot GateSnapshot
	var state string
	if err := t.Tx.QueryRowContext(ctx,
		"SELECT gate_state, generation, fencing_token, COALESCE(lock_owner, ''), row_version FROM system_maintenance_locks WHERE origin_installation_id = ? AND scope = ? FOR UPDATE",
		key.InstallationID, key.Scope,
	).Scan(&state, &snapshot.Generation, &snapshot.FencingToken, &snapshot.Owner, &snapshot.RowVersion); err != nil {
		return GateSnapshot{}, fmt.Errorf("lock system backup maintenance gate: %w", err)
	}
	snapshot.Key = key
	snapshot.State = GateState(state)
	return snapshot, nil
}

func (t SQLCoordinationTransaction) LockMutationLease(ctx context.Context, leaseID string) (MutationLeaseSnapshot, error) {
	if t.Tx == nil {
		return MutationLeaseSnapshot{}, errors.New("nil system backup coordination SQL transaction")
	}
	if !mutationLeaseIDPattern.MatchString(leaseID) {
		return MutationLeaseSnapshot{}, errors.New("invalid system backup mutation lease ID")
	}
	var snapshot MutationLeaseSnapshot
	if err := t.Tx.QueryRowContext(ctx,
		"SELECT lease_id, origin_installation_id, scope, lease_owner, gate_generation, row_version, expires_at > UTC_TIMESTAMP(6) FROM system_maintenance_mutation_leases WHERE lease_id = ? FOR UPDATE",
		leaseID,
	).Scan(&snapshot.LeaseID, &snapshot.Key.InstallationID, &snapshot.Key.Scope, &snapshot.Owner, &snapshot.Generation, &snapshot.RowVersion, &snapshot.Live); err != nil {
		return MutationLeaseSnapshot{}, fmt.Errorf("lock system backup mutation lease: %w", err)
	}
	return snapshot, nil
}

func (t SQLCoordinationTransaction) CountOutstandingMutationLeases(ctx context.Context, key GateKey, throughGeneration uint64) (uint64, error) {
	if t.Tx == nil {
		return 0, errors.New("nil system backup coordination SQL transaction")
	}
	if err := key.validate(); err != nil {
		return 0, err
	}
	if throughGeneration < 1 {
		return 0, errors.New("mutation lease generation must be at least 1")
	}
	rows, err := t.Tx.QueryContext(ctx,
		"SELECT id FROM system_maintenance_mutation_leases WHERE origin_installation_id = ? AND scope = ? AND gate_generation <= ? ORDER BY id FOR UPDATE",
		key.InstallationID, key.Scope, throughGeneration,
	)
	if err != nil {
		return 0, fmt.Errorf("count outstanding system backup mutation leases: %w", err)
	}
	defer rows.Close()
	var count uint64
	for rows.Next() {
		var id uint64
		if err := rows.Scan(&id); err != nil {
			return 0, fmt.Errorf("scan outstanding system backup mutation lease: %w", err)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate outstanding system backup mutation leases: %w", err)
	}
	return count, nil
}

// GateHoldReadinessVerifier is the explicit B-participant boundary. D never
// invents pause acknowledgements: held/fencing advancement requires a verifier
// to prove the current generation is paused using the same transaction.
type GateHoldReadinessVerifier interface {
	VerifyParticipantsPaused(context.Context, CoordinationTransaction, GateKey, uint64) error
}

// GateRecoveryReadinessVerifier is deliberately separate from hold readiness:
// an expired acquiring generation may return to idle only after the participant
// owner proves every writer is running (normally or forced-resumed).
type GateRecoveryReadinessVerifier interface {
	VerifyParticipantsRunning(context.Context, CoordinationTransaction, GateKey, uint64) error
}

func validateCoordinationMutation(ctx context.Context, tx CoordinationTransaction, key GateKey, owner string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if tx == nil {
		return errors.New("nil system backup coordination transaction")
	}
	if err := key.validate(); err != nil {
		return err
	}
	if !controllerOwnerPattern.MatchString(owner) {
		return errors.New("invalid system backup maintenance gate owner")
	}
	return nil
}

func gateSeconds(value time.Duration) int64 {
	return int64(value / time.Second)
}

func snapshotsEqual(actual, expected GateSnapshot) bool {
	return actual.Key == expected.Key && actual.State == expected.State && actual.Generation == expected.Generation && actual.FencingToken == expected.FencingToken && actual.Owner == expected.Owner && actual.RowVersion == expected.RowVersion
}

func withCoordinationRollback(tx CoordinationTransaction, committed *bool) {
	if !*committed {
		_ = tx.Rollback()
	}
}

// BeginGateAcquisition serializes with mutation-lease creation by locking the
// unique gate row before CASing idle -> acquiring and advancing generation.
func BeginGateAcquisition(ctx context.Context, tx CoordinationTransaction, key GateKey, owner string, expectedRowVersion uint64, policy GatePolicy) (GateToken, error) {
	if err := validateCoordinationMutation(ctx, tx, key, owner); err != nil {
		return GateToken{}, err
	}
	if err := policy.Validate(); err != nil {
		return GateToken{}, err
	}
	if expectedRowVersion < 1 {
		return GateToken{}, errors.New("expected maintenance gate row version must be at least 1")
	}
	committed := false
	defer withCoordinationRollback(tx, &committed)

	snapshot, err := tx.LockGate(ctx, key)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return GateToken{}, ErrGateTransitionRejected
		}
		return GateToken{}, err
	}
	if snapshot.State != GateIdle || snapshot.Owner != "" || snapshot.RowVersion != expectedRowVersion || snapshot.Generation < 1 {
		return GateToken{}, ErrGateTransitionRejected
	}
	result, err := tx.ExecContext(ctx,
		"UPDATE system_maintenance_locks SET gate_state = 'acquiring', generation = generation + 1, lock_owner = ?, heartbeat_at = UTC_TIMESTAMP(6), lock_ttl_seconds = ?, lease_expires_at = LEAST(DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND), DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND)), gate_acquisition_timeout_seconds = ?, quiesce_max_hold_seconds = NULL, acquiring_started_at = UTC_TIMESTAMP(6), held_at = NULL, release_started_at = NULL, acquisition_deadline_at = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND), absolute_hold_deadline_at = NULL, state_changed_at = UTC_TIMESTAMP(6), row_version = row_version + 1 WHERE origin_installation_id = ? AND scope = ? AND gate_state = 'idle' AND generation = ? AND row_version = ?",
		owner, gateSeconds(policy.LockTTL), gateSeconds(policy.LockTTL), gateSeconds(policy.AcquisitionTimeout), gateSeconds(policy.AcquisitionTimeout), gateSeconds(policy.AcquisitionTimeout), key.InstallationID, key.Scope, snapshot.Generation, snapshot.RowVersion,
	)
	if err != nil {
		return GateToken{}, fmt.Errorf("begin system backup gate acquisition: %w", err)
	}
	matched, err := exactlyOneRow(result)
	if err != nil {
		return GateToken{}, err
	}
	if !matched {
		return GateToken{}, ErrGateTransitionRejected
	}
	if err := insertGateTransitionEvent(ctx, tx, key, GateIdle, GateAcquiring, gateReasonCaptureRequested, "Maintenance gate acquisition started."); err != nil {
		return GateToken{}, err
	}
	if err := tx.Commit(); err != nil {
		return GateToken{}, fmt.Errorf("commit system backup gate acquisition: %w", err)
	}
	committed = true
	return GateToken{GateSnapshot: GateSnapshot{Key: key, State: GateAcquiring, Generation: snapshot.Generation + 1, FencingToken: snapshot.FencingToken, Owner: owner, RowVersion: snapshot.RowVersion + 1}}, nil
}

// AdvanceGateHeld refuses to treat TTL expiry as proof that an old writer has
// stopped. Every older-generation lease row must be actively removed, and the
// participant verifier must prove paused acknowledgements before fencing moves.
func AdvanceGateHeld(ctx context.Context, tx CoordinationTransaction, token GateToken, policy GatePolicy, readiness GateHoldReadinessVerifier) (GateToken, error) {
	if err := validateCoordinationMutation(ctx, tx, token.Key, token.Owner); err != nil {
		return GateToken{}, err
	}
	if err := token.validate(GateAcquiring); err != nil {
		return GateToken{}, err
	}
	if err := policy.Validate(); err != nil {
		return GateToken{}, err
	}
	if readiness == nil {
		return GateToken{}, errors.New("nil system backup gate hold readiness verifier")
	}
	committed := false
	defer withCoordinationRollback(tx, &committed)

	snapshot, err := tx.LockGate(ctx, token.Key)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return GateToken{}, ErrGateFenceLost
		}
		return GateToken{}, err
	}
	if !snapshotsEqual(snapshot, token.GateSnapshot) {
		return GateToken{}, ErrGateFenceLost
	}
	outstanding, err := tx.CountOutstandingMutationLeases(ctx, token.Key, token.Generation)
	if err != nil {
		return GateToken{}, err
	}
	if outstanding != 0 {
		return GateToken{}, ErrGateHoldNotReady
	}
	if err := readiness.VerifyParticipantsPaused(ctx, tx, token.Key, token.Generation); err != nil {
		return GateToken{}, fmt.Errorf("verify system backup gate participants paused: %w", errors.Join(ErrGateHoldNotReady, err))
	}
	result, err := tx.ExecContext(ctx,
		"UPDATE system_maintenance_locks SET gate_state = 'held', fencing_token = fencing_token + 1, heartbeat_at = UTC_TIMESTAMP(6), lease_expires_at = LEAST(DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND), DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND)), quiesce_max_hold_seconds = ?, held_at = UTC_TIMESTAMP(6), absolute_hold_deadline_at = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND), state_changed_at = UTC_TIMESTAMP(6), row_version = row_version + 1 WHERE origin_installation_id = ? AND scope = ? AND gate_state = 'acquiring' AND generation = ? AND fencing_token = ? AND lock_owner = ? AND row_version = ? AND lease_expires_at > UTC_TIMESTAMP(6) AND acquisition_deadline_at > UTC_TIMESTAMP(6)",
		gateSeconds(policy.LockTTL), gateSeconds(policy.MaxHold), gateSeconds(policy.MaxHold), gateSeconds(policy.MaxHold), token.Key.InstallationID, token.Key.Scope, token.Generation, token.FencingToken, token.Owner, token.RowVersion,
	)
	if err != nil {
		return GateToken{}, fmt.Errorf("hold system backup maintenance gate: %w", err)
	}
	matched, err := exactlyOneRow(result)
	if err != nil {
		return GateToken{}, err
	}
	if !matched {
		return GateToken{}, ErrGateFenceLost
	}
	if err := insertGateTransitionEvent(ctx, tx, token.Key, GateAcquiring, GateHeld, gateReasonParticipantsPaused, "Maintenance gate entered held state."); err != nil {
		return GateToken{}, err
	}
	if err := tx.Commit(); err != nil {
		return GateToken{}, fmt.Errorf("commit system backup held gate: %w", err)
	}
	committed = true
	token.State = GateHeld
	token.FencingToken++
	token.RowVersion++
	return token, nil
}

// AbortGateAcquisition returns only the caller's still-live acquiring
// generation to idle. It never rolls generation or fencing token backward.
func AbortGateAcquisition(ctx context.Context, executor Executor, token GateToken) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if executor == nil {
		return 0, errors.New("nil system backup maintenance gate executor")
	}
	if err := token.validate(GateAcquiring); err != nil {
		return 0, err
	}
	result, err := executor.ExecContext(ctx,
		"UPDATE system_maintenance_locks SET gate_state = 'idle', lock_owner = NULL, heartbeat_at = NULL, lease_expires_at = NULL, gate_acquisition_timeout_seconds = NULL, quiesce_max_hold_seconds = NULL, acquiring_started_at = NULL, held_at = NULL, release_started_at = NULL, acquisition_deadline_at = NULL, absolute_hold_deadline_at = NULL, state_changed_at = UTC_TIMESTAMP(6), row_version = row_version + 1 WHERE origin_installation_id = ? AND scope = ? AND gate_state = 'acquiring' AND generation = ? AND fencing_token = ? AND lock_owner = ? AND row_version = ? AND lease_expires_at > UTC_TIMESTAMP(6)",
		token.Key.InstallationID, token.Key.Scope, token.Generation, token.FencingToken, token.Owner, token.RowVersion,
	)
	if err != nil {
		return 0, fmt.Errorf("abort system backup gate acquisition: %w", err)
	}
	matched, err := exactlyOneRow(result)
	if err != nil {
		return 0, err
	}
	if !matched {
		return 0, ErrGateFenceLost
	}
	return token.RowVersion + 1, nil
}

// RecoverGateIdle resolves an expired acquiring generation. The gate row is
// locked before participant proof, and the final CAS rechecks database-time
// expiry. No D-owned path can infer running state from TTL expiry alone.
func RecoverGateIdle(ctx context.Context, tx CoordinationTransaction, key GateKey, expectedRowVersion uint64, readiness GateRecoveryReadinessVerifier) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if tx == nil {
		return 0, errors.New("nil system backup coordination transaction")
	}
	if err := key.validate(); err != nil {
		return 0, err
	}
	if expectedRowVersion < 1 {
		return 0, errors.New("expected maintenance gate row version must be at least 1")
	}
	if readiness == nil {
		return 0, errors.New("nil system backup gate recovery readiness verifier")
	}
	committed := false
	defer withCoordinationRollback(tx, &committed)

	snapshot, err := tx.LockGate(ctx, key)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrGateTransitionRejected
		}
		return 0, err
	}
	if snapshot.Key != key || snapshot.State != GateAcquiring || snapshot.RowVersion != expectedRowVersion || snapshot.Generation < 1 || !controllerOwnerPattern.MatchString(snapshot.Owner) {
		return 0, ErrGateTransitionRejected
	}
	if err := readiness.VerifyParticipantsRunning(ctx, tx, key, snapshot.Generation); err != nil {
		return 0, fmt.Errorf("verify system backup gate participants running: %w", errors.Join(ErrGateRecoveryNotReady, err))
	}
	result, err := tx.ExecContext(ctx,
		"UPDATE system_maintenance_locks SET gate_state = 'idle', lock_owner = NULL, heartbeat_at = NULL, lease_expires_at = NULL, gate_acquisition_timeout_seconds = NULL, quiesce_max_hold_seconds = NULL, acquiring_started_at = NULL, held_at = NULL, release_started_at = NULL, acquisition_deadline_at = NULL, absolute_hold_deadline_at = NULL, state_changed_at = UTC_TIMESTAMP(6), row_version = row_version + 1 WHERE origin_installation_id = ? AND scope = ? AND gate_state = 'acquiring' AND generation = ? AND fencing_token = ? AND lock_owner = ? AND row_version = ? AND (lease_expires_at <= UTC_TIMESTAMP(6) OR acquisition_deadline_at <= UTC_TIMESTAMP(6))",
		key.InstallationID, key.Scope, snapshot.Generation, snapshot.FencingToken, snapshot.Owner, snapshot.RowVersion,
	)
	if err != nil {
		return 0, fmt.Errorf("recover system backup acquiring gate: %w", err)
	}
	matched, err := exactlyOneRow(result)
	if err != nil {
		return 0, err
	}
	if !matched {
		return 0, ErrGateTransitionRejected
	}
	if err := insertGateTransitionEvent(ctx, tx, key, GateAcquiring, GateIdle, gateReasonExpiredAcquisitionRecovered, "Expired maintenance gate acquisition recovered to idle."); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit system backup acquiring gate recovery: %w", err)
	}
	committed = true
	return snapshot.RowVersion + 1, nil
}

// RecoverGateRelease fences an expired holder and moves only toward resume.
// A held row may be recovered after either its lease or absolute hold deadline;
// a releasing row is stolen only after lease expiry. Acquiring recovery still
// requires proof that B-owned participants are running and is intentionally not
// guessed by this D-owned primitive.
func RecoverGateRelease(ctx context.Context, tx CoordinationTransaction, key GateKey, owner string, expectedRowVersion uint64, policy GatePolicy) (GateToken, error) {
	if err := validateCoordinationMutation(ctx, tx, key, owner); err != nil {
		return GateToken{}, err
	}
	if err := policy.Validate(); err != nil {
		return GateToken{}, err
	}
	if expectedRowVersion < 1 {
		return GateToken{}, errors.New("expected maintenance gate row version must be at least 1")
	}
	committed := false
	defer withCoordinationRollback(tx, &committed)

	snapshot, err := tx.LockGate(ctx, key)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return GateToken{}, ErrGateTransitionRejected
		}
		return GateToken{}, err
	}
	if snapshot.Key != key || snapshot.RowVersion != expectedRowVersion || snapshot.Generation < 1 || snapshot.FencingToken < 1 || !controllerOwnerPattern.MatchString(snapshot.Owner) || (snapshot.State != GateHeld && snapshot.State != GateReleasing) {
		return GateToken{}, ErrGateTransitionRejected
	}
	expiryPredicate := "lease_expires_at <= UTC_TIMESTAMP(6) OR absolute_hold_deadline_at <= UTC_TIMESTAMP(6)"
	if snapshot.State == GateReleasing {
		expiryPredicate = "lease_expires_at <= UTC_TIMESTAMP(6)"
	}
	query := fmt.Sprintf(
		"UPDATE system_maintenance_locks SET gate_state = 'releasing', fencing_token = fencing_token + 1, lock_owner = ?, heartbeat_at = UTC_TIMESTAMP(6), lock_ttl_seconds = ?, lease_expires_at = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND), release_started_at = COALESCE(release_started_at, UTC_TIMESTAMP(6)), state_changed_at = UTC_TIMESTAMP(6), row_version = row_version + 1 WHERE origin_installation_id = ? AND scope = ? AND gate_state = ? AND generation = ? AND fencing_token = ? AND lock_owner = ? AND row_version = ? AND (%s)",
		expiryPredicate,
	)
	result, err := tx.ExecContext(ctx, query,
		owner, gateSeconds(policy.LockTTL), gateSeconds(policy.LockTTL), key.InstallationID, key.Scope, snapshot.State, snapshot.Generation, snapshot.FencingToken, snapshot.Owner, snapshot.RowVersion,
	)
	if err != nil {
		return GateToken{}, fmt.Errorf("recover system backup gate release: %w", err)
	}
	matched, err := exactlyOneRow(result)
	if err != nil {
		return GateToken{}, err
	}
	if !matched {
		return GateToken{}, ErrGateTransitionRejected
	}
	if err := insertGateTransitionEvent(ctx, tx, key, snapshot.State, GateReleasing, gateReasonExpiredOwnerFenced, "Expired maintenance gate owner fenced for release."); err != nil {
		return GateToken{}, err
	}
	if err := tx.Commit(); err != nil {
		return GateToken{}, fmt.Errorf("commit system backup gate release recovery: %w", err)
	}
	committed = true
	return GateToken{GateSnapshot: GateSnapshot{
		Key: key, State: GateReleasing, Generation: snapshot.Generation, FencingToken: snapshot.FencingToken + 1, Owner: owner, RowVersion: snapshot.RowVersion + 1,
	}}, nil
}

func RenewGate(ctx context.Context, executor Executor, token GateToken, policy GatePolicy) (GateToken, error) {
	if err := ctx.Err(); err != nil {
		return GateToken{}, err
	}
	if executor == nil {
		return GateToken{}, errors.New("nil system backup maintenance gate executor")
	}
	if token.State != GateAcquiring && token.State != GateHeld && token.State != GateReleasing {
		return GateToken{}, errors.New("maintenance gate renewal requires an active token")
	}
	if err := token.validate(token.State); err != nil {
		return GateToken{}, err
	}
	if err := policy.Validate(); err != nil {
		return GateToken{}, err
	}
	leaseExpression := "LEAST(DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND), acquisition_deadline_at)"
	deadlinePredicate := " AND acquisition_deadline_at > UTC_TIMESTAMP(6)"
	if token.State == GateHeld {
		leaseExpression = "LEAST(DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND), absolute_hold_deadline_at)"
		deadlinePredicate = " AND absolute_hold_deadline_at > UTC_TIMESTAMP(6)"
	} else if token.State == GateReleasing {
		leaseExpression = "DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? SECOND)"
		deadlinePredicate = ""
	}
	query := fmt.Sprintf(
		"UPDATE system_maintenance_locks SET heartbeat_at = UTC_TIMESTAMP(6), lease_expires_at = %s, row_version = row_version + 1 WHERE origin_installation_id = ? AND scope = ? AND gate_state = ? AND generation = ? AND fencing_token = ? AND lock_owner = ? AND row_version = ? AND lease_expires_at > UTC_TIMESTAMP(6)%s",
		leaseExpression, deadlinePredicate,
	)
	result, err := executor.ExecContext(ctx, query, gateSeconds(policy.LockTTL), token.Key.InstallationID, token.Key.Scope, token.State, token.Generation, token.FencingToken, token.Owner, token.RowVersion)
	if err != nil {
		return GateToken{}, fmt.Errorf("renew system backup maintenance gate: %w", err)
	}
	matched, err := exactlyOneRow(result)
	if err != nil {
		return GateToken{}, err
	}
	if !matched {
		return GateToken{}, ErrGateFenceLost
	}
	token.RowVersion++
	return token, nil
}

func BeginGateRelease(ctx context.Context, executor Executor, token GateToken) (GateToken, error) {
	if err := ctx.Err(); err != nil {
		return GateToken{}, err
	}
	if executor == nil {
		return GateToken{}, errors.New("nil system backup maintenance gate executor")
	}
	if err := token.validate(GateHeld); err != nil {
		return GateToken{}, err
	}
	result, err := executor.ExecContext(ctx,
		"UPDATE system_maintenance_locks SET gate_state = 'releasing', heartbeat_at = UTC_TIMESTAMP(6), release_started_at = UTC_TIMESTAMP(6), state_changed_at = UTC_TIMESTAMP(6), row_version = row_version + 1 WHERE origin_installation_id = ? AND scope = ? AND gate_state = 'held' AND generation = ? AND fencing_token = ? AND lock_owner = ? AND row_version = ? AND lease_expires_at > UTC_TIMESTAMP(6) AND absolute_hold_deadline_at > UTC_TIMESTAMP(6)",
		token.Key.InstallationID, token.Key.Scope, token.Generation, token.FencingToken, token.Owner, token.RowVersion,
	)
	if err != nil {
		return GateToken{}, fmt.Errorf("begin system backup gate release: %w", err)
	}
	matched, err := exactlyOneRow(result)
	if err != nil {
		return GateToken{}, err
	}
	if !matched {
		return GateToken{}, ErrGateFenceLost
	}
	token.State = GateReleasing
	token.RowVersion++
	return token, nil
}

func FinishGateRelease(ctx context.Context, executor Executor, token GateToken) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if executor == nil {
		return 0, errors.New("nil system backup maintenance gate executor")
	}
	if err := token.validate(GateReleasing); err != nil {
		return 0, err
	}
	result, err := executor.ExecContext(ctx,
		"UPDATE system_maintenance_locks SET gate_state = 'idle', lock_owner = NULL, heartbeat_at = NULL, lease_expires_at = NULL, gate_acquisition_timeout_seconds = NULL, quiesce_max_hold_seconds = NULL, acquiring_started_at = NULL, held_at = NULL, release_started_at = NULL, acquisition_deadline_at = NULL, absolute_hold_deadline_at = NULL, state_changed_at = UTC_TIMESTAMP(6), row_version = row_version + 1 WHERE origin_installation_id = ? AND scope = ? AND gate_state = 'releasing' AND generation = ? AND fencing_token = ? AND lock_owner = ? AND row_version = ? AND lease_expires_at > UTC_TIMESTAMP(6)",
		token.Key.InstallationID, token.Key.Scope, token.Generation, token.FencingToken, token.Owner, token.RowVersion,
	)
	if err != nil {
		return 0, fmt.Errorf("finish system backup gate release: %w", err)
	}
	matched, err := exactlyOneRow(result)
	if err != nil {
		return 0, err
	}
	if !matched {
		return 0, ErrGateFenceLost
	}
	return token.RowVersion + 1, nil
}
