package systembackup

import (
	"context"
	"database/sql"
	"regexp"
	"time"
)

// VersionedGateClaim is the current controller claim, not a second task store.
// It must be refreshed after renewing/changing the public task row version.
type VersionedGateClaim struct {
	InstallationID  string
	TaskID          string
	ControllerOwner string
	RowVersion      uint64
}

type gateQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

var versionedBackupID = regexp.MustCompile(`^sbk_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var versionedInstallationID = regexp.MustCompile(`^installation_[A-Za-z0-9._:-]{1,115}$`)
var versionedControllerOwner = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

func (c VersionedGateClaim) validate() error {
	if !versionedBackupID.MatchString(c.TaskID) || !versionedInstallationID.MatchString(c.InstallationID) || !versionedControllerOwner.MatchString(c.ControllerOwner) || c.RowVersion == 0 {
		return ErrFence
	}
	return nil
}

func (c VersionedGateClaim) authorize(ctx context.Context, q gateQuery) error {
	return c.authorizePhase(ctx, q, false)
}

func (c VersionedGateClaim) authorizePhase(ctx context.Context, q gateQuery, alreadyCapturing bool) error {
	if c.validate() != nil {
		return ErrFence
	}
	// Inputs prove the task came through versioned admission. A timeout or old
	// claim cannot acquire the application's gate even if its owner string fits.
	const query = `SELECT (b.status='acquiring_gate' OR (? AND b.status='capturing')) AND b.controller_owner=? AND b.row_version=?
AND b.controller_lease_expires_at>UTC_TIMESTAMP(6) AND b.deadline_at>UTC_TIMESTAMP(6)
FROM system_backup_v2_backups b
WHERE b.origin_installation_id=? AND b.public_id=? AND EXISTS(
SELECT 1 FROM system_backup_v2_execution_inputs i WHERE i.origin_installation_id=b.origin_installation_id AND i.task_public_id=b.public_id AND i.task_type='backup')`
	suffix := ""
	if _, ok := q.(*sql.Tx); ok {
		suffix = " FOR UPDATE"
	}
	var valid bool
	if err := q.QueryRowContext(ctx, query+suffix, alreadyCapturing, c.ControllerOwner, c.RowVersion, c.InstallationID, c.TaskID).Scan(&valid); err != nil {
		return err
	}
	if !valid {
		return ErrFence
	}
	return nil
}

// ResolveVersionedCapture recovers the original acquisition after a lost
// response. It never acquires a new generation or extends either deadline.
// Expired/releasing gates require the separate stop/resume recovery protocol;
// they cannot be converted into new capture permission by this read.
func (g Gate) ResolveVersionedCapture(ctx context.Context, scope string, claim VersionedGateClaim, registryHash string) (GateOwnership, string, error) {
	var zero GateOwnership
	if g.DB == nil || claim.validate() != nil || len(registryHash) != 64 {
		return zero, "", ErrFence
	}
	tx, err := g.DB.BeginTx(ctx, nil)
	if err != nil {
		return zero, "", err
	}
	defer tx.Rollback()
	if err = lockEngine(ctx, tx, scope, VersionedEngine); err != nil {
		return zero, "", err
	}
	var phase, owner, hash string
	var generation, token uint64
	var timely bool
	err = tx.QueryRowContext(ctx, `SELECT phase,COALESCE(owner,''),COALESCE(registry_hash,''),generation,fencing_token,
COALESCE(UTC_TIMESTAMP(6)<hold_deadline AND (phase<>'acquiring' OR UTC_TIMESTAMP(6)<acquire_deadline),FALSE)
FROM system_backup_gate WHERE scope=? FOR SHARE`, scope).Scan(&phase, &owner, &hash, &generation, &token, &timely)
	if err != nil {
		return zero, "", err
	}
	if owner != claim.TaskID || hash != registryHash || !timely || (phase != "acquiring" && phase != "held") {
		return zero, "", ErrFence
	}
	if err = claim.authorizePhase(ctx, tx, true); err != nil {
		return zero, "", err
	}
	if err = tx.Commit(); err != nil {
		return zero, "", err
	}
	return GateOwnership{Scope: scope, Owner: owner, Generation: generation, Token: token}, phase, nil
}

// BeginVersionedCapture acquires the SAME gate and request admission used by
// Team/legacy writers. It never populates the independent source-v2 gate tables.
// Capture remains disabled until writer inventory/pause, runner and recovery
// adapters are composed; this method is not a readiness publisher.
func (g Gate) BeginVersionedCapture(ctx context.Context, scope string, claim VersionedGateClaim, registryHash string, acquire, hold time.Duration) (GateOwnership, error) {
	if err := claim.validate(); err != nil {
		return GateOwnership{}, err
	}
	return g.beginForEngine(ctx, VersionedEngine, scope, claim.TaskID, registryHash, acquire, hold, claim.authorize)
}

// The public task's original epoch and the physical acquiring transition must
// commit together. journal may only perform SQL using this transaction; no
// source/provider IO, nested transaction or commit is allowed.
func (g Gate) BeginVersionedCaptureJournal(ctx context.Context, scope string, claim VersionedGateClaim, registryHash string, acquire, hold time.Duration, journal func(context.Context, *sql.Tx, GateOwnership) error) (GateOwnership, error) {
	if claim.validate() != nil || journal == nil {
		return GateOwnership{}, ErrFence
	}
	return g.beginForEngineJournal(ctx, VersionedEngine, scope, claim.TaskID, registryHash, acquire, hold, claim.authorize, journal)
}

// HoldVersionedCapture checks the live public task claim in the gate transition
// transaction. Paused participant evidence is still checked by the common Hold.
func (g Gate) HoldVersionedCapture(ctx context.Context, claim VersionedGateClaim, ownership GateOwnership) (GateOwnership, error) {
	if err := claim.validate(); err != nil {
		return ownership, err
	}
	if ownership.Owner != claim.TaskID {
		return ownership, ErrFence
	}
	return g.hold(ctx, ownership, func(ctx context.Context, q gateQuery) error { return claim.authorizePhase(ctx, q, true) })
}
