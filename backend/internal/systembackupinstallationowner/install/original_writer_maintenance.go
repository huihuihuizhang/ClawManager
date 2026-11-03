package install

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"reflect"
	"sync"
	"time"

	"clawreef/internal/migrationcoord"
	"clawreef/internal/systembackup/domain"
	c "clawreef/internal/systembackupcontroller"
)

// OriginalWriterMaintenance is ORIGINAL offline administrator/enrollment
// authority. It is not physical hold, a task, a signer or PreparedCoverage.
// The only lifetime is the original authenticated operator/context lifetime.
type OriginalWriterMaintenance struct {
	gatewayRecoveryMode string
	mu                  sync.Mutex
	origin              *OriginalWriterMaintenance
	ctx                 context.Context
	operator            *authenticatedOperator
	enrollment          EnrollmentPin
	initial             HeadCAS
	operation           string
	until               time.Time
	token               c.GateToken
	policy              c.GatePolicy
	instances           []domain.SourceInstance
	failed              bool
	commitUnknown       bool
}

func (*OriginalWriterMaintenance) MarshalJSON() ([]byte, error) { return nil, ErrInstall }

// PrepareOriginalWriterMaintenance performs real admin/enrollment/head reads
// and captures ALL source instances, including stopped/Pro. It does not take
// the gate or mutate a source. The factory must finish its complete native
// recovery-material preflight before BeginAcquisition.
func (i *Installer) PrepareOriginalWriterMaintenance(ctx context.Context, password []byte, enrollment EnrollmentPin, policy c.GatePolicy) (*OriginalWriterMaintenance, error) {
	s, err := i.authenticate(ctx, password)
	if err != nil || policy.Validate() != nil || s.authority(ctx, enrollment) != nil {
		return nil, ErrInstall
	}
	tx, err := i.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, ErrInstall
	}
	defer tx.Rollback()
	if _, err = s.lockAdmin(ctx, tx); err != nil {
		return nil, ErrInstall
	}
	current, err := s.current(ctx, tx, false)
	if err != nil || current.cas.State == "revoked" {
		return nil, ErrInstall
	}
	instances, err := domain.ReadSourceInstances(ctx, tx)
	if err != nil || tx.Rollback() != nil {
		return nil, ErrInstall
	}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		return nil, ErrInstall
	}
	p := &OriginalWriterMaintenance{ctx: ctx, operator: s, enrollment: enrollment, initial: current.cas, operation: hex.EncodeToString(id[:]), until: s.until, policy: policy, instances: append([]domain.SourceInstance(nil), instances...)}
	p.origin = p
	return p, nil
}

func (p *OriginalWriterMaintenance) check(ctx context.Context) error {
	if p == nil || p.origin != p || p.failed || !consumerSameContext(ctx, p.ctx) || !p.operator.live(ctx) || !time.Now().Before(p.until) || p.operator.authority(ctx, p.enrollment) != nil {
		return ErrInstall
	}
	current, now, err := originalAdoptionAuthoritySnapshot(ctx, p.operator)
	if err != nil || current.cas != p.initial || current.cas.State == "revoked" || !now.Before(p.until) {
		return ErrInstall
	}
	return nil
}

// Recheck the complete original projection; no mode/status filter is allowed.
// This is a fresh transaction, so a snapshot taken before the maintenance gate
// cannot hide a newly registered source.
func (p *OriginalWriterMaintenance) checkInstances(ctx context.Context) error {
	tx, err := p.operator.installer.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return ErrInstall
	}
	defer tx.Rollback()
	instances, err := domain.ReadSourceInstances(ctx, tx)
	if err != nil || !reflect.DeepEqual(instances, p.instances) || tx.Rollback() != nil {
		return ErrInstall
	}
	return nil
}

func (p *OriginalWriterMaintenance) Instances(ctx context.Context) ([]domain.SourceInstance, error) {
	if p == nil {
		return nil, ErrInstall
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.check(ctx) != nil || p.checkInstances(ctx) != nil {
		return nil, ErrInstall
	}
	return append([]domain.SourceInstance(nil), p.instances...), nil
}

func (p *OriginalWriterMaintenance) Identity(ctx context.Context) (string, time.Time, error) {
	if p == nil {
		return "", time.Time{}, ErrInstall
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.check(ctx) != nil {
		return "", time.Time{}, ErrInstall
	}
	return p.operation, p.until, nil
}

// BeginAcquisition uses the existing real gate CAS in the SAME gate/admin/head
// transaction. A commit error is unknown; it is never permission to pause or
// retry another operation. No SQL task or fake worker is inserted.
func (p *OriginalWriterMaintenance) BeginAcquisition(ctx context.Context) (result c.GateToken, resultErr error) {
	if p == nil {
		return c.GateToken{}, ErrInstall
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.check(ctx) != nil || p.checkInstances(ctx) != nil || p.token.Generation != 0 || p.commitUnknown {
		return c.GateToken{}, ErrInstall
	}
	// Use the same advisory exclusion as the existing production coordinator.
	// Do not retain SQL source/admin locks during native operations.
	guard, err := (migrationcoord.SQLLocker{DB: p.operator.installer.db, Timeout: time.Second}).Acquire(ctx)
	if err != nil || guard == nil {
		return c.GateToken{}, ErrInstall
	}
	defer func() {
		releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := guard.Release(releaseCtx); err != nil {
			result = c.GateToken{}
			resultErr = errors.Join(resultErr, ErrInstall)
		}
	}()
	tx, err := p.operator.installer.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return c.GateToken{}, ErrInstall
	}
	defer tx.Rollback()
	key := c.GateKey{InstallationID: p.operator.installer.plan.Target.InstallationID, Scope: c.CaptureGateScope}
	coord := &originalMaintenanceCommit{SQLCoordinationTransaction: c.SQLCoordinationTransaction{Tx: tx}}
	_, err = coord.LockGate(ctx, key)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return c.GateToken{}, ErrInstall
	}
	if _, err = p.operator.lockAdmin(ctx, tx); err != nil {
		return c.GateToken{}, ErrInstall
	}
	current, err := p.operator.current(ctx, tx, false)
	if err != nil || current.cas != p.initial {
		return c.GateToken{}, ErrInstall
	}
	if err = (c.SQLGateInitializer{DB: tx}).Ensure(ctx, key.InstallationID, p.policy); err != nil {
		return c.GateToken{}, ErrInstall
	}
	snapshot, err := coord.LockGate(ctx, key)
	if err != nil {
		return c.GateToken{}, ErrInstall
	}
	token, err := c.BeginGateAcquisition(ctx, coord, key, "adoption:"+p.operation, snapshot.RowVersion, p.policy)
	if err != nil {
		if coord.commitAttempted {
			p.commitUnknown = true
			return c.GateToken{}, ErrCommitUnknown
		}
		return c.GateToken{}, ErrInstall
	}
	p.token = token
	return token, nil
}

// Commit errors are distinguished from rejected CAS/pre-commit failures.
// An ambiguous commit is reconciled by reading this exact operation; callers
// cannot pause sources, reacquire or use a different operation after it.
type originalMaintenanceCommit struct {
	c.SQLCoordinationTransaction
	commitAttempted bool
}

func (t *originalMaintenanceCommit) Commit() error {
	t.commitAttempted = true
	return t.SQLCoordinationTransaction.Commit()
}

func (p *OriginalWriterMaintenance) ReconcileAcquisition(ctx context.Context) (c.GateToken, error) {
	if p == nil {
		return c.GateToken{}, ErrInstall
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.commitUnknown || p.check(ctx) != nil || p.checkInstances(ctx) != nil {
		return c.GateToken{}, ErrInstall
	}
	tx, err := p.operator.installer.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return c.GateToken{}, ErrCommitUnknown
	}
	defer tx.Rollback()
	key := c.GateKey{InstallationID: p.operator.installer.plan.Target.InstallationID, Scope: c.CaptureGateScope}
	var t c.GateToken
	t.Key = key
	var live bool
	err = tx.QueryRowContext(ctx, `SELECT gate_state,generation,fencing_token,COALESCE(lock_owner,''),row_version,lease_expires_at>UTC_TIMESTAMP(6) AND acquisition_deadline_at>UTC_TIMESTAMP(6) FROM system_backup_v2_maintenance_locks WHERE origin_installation_id=? AND scope=? FOR SHARE`, key.InstallationID, key.Scope).Scan(&t.State, &t.Generation, &t.FencingToken, &t.Owner, &t.RowVersion, &live)
	if err != nil || !live || t.State != c.GateAcquiring || t.Owner != "adoption:"+p.operation || t.Generation == 0 || tx.Rollback() != nil {
		return c.GateToken{}, ErrCommitUnknown
	}
	p.token = t
	p.commitUnknown = false
	return t, nil
}

// Native clients remain private. Every actual mutation is executed by the
// concrete internal writer with original ctx, exact UID/RV and a journal.
func (p *OriginalWriterMaintenance) checkCurrentGate(ctx context.Context, phases ...c.GateState) error {
	if p == nil || p.check(ctx) != nil || p.commitUnknown || p.token.Generation == 0 {
		return ErrInstall
	}
	allowed := false
	for _, phase := range phases {
		if p.token.State == phase {
			allowed = true
		}
	}
	if !allowed {
		return ErrInstall
	}
	tx, err := p.operator.installer.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return ErrInstall
	}
	defer tx.Rollback()
	var got c.GateSnapshot
	got.Key = p.token.Key
	var live bool
	err = tx.QueryRowContext(ctx, `SELECT gate_state,generation,fencing_token,COALESCE(lock_owner,''),row_version,lease_expires_at>UTC_TIMESTAMP(6) AND (gate_state='releasing' OR gate_state='acquiring' AND acquisition_deadline_at>UTC_TIMESTAMP(6) OR gate_state='held' AND absolute_hold_deadline_at>UTC_TIMESTAMP(6)) FROM system_backup_v2_maintenance_locks WHERE origin_installation_id=? AND scope=? FOR SHARE`, got.Key.InstallationID, got.Key.Scope).Scan(&got.State, &got.Generation, &got.FencingToken, &got.Owner, &got.RowVersion, &live)
	if err != nil || !live || got != p.token.GateSnapshot || tx.Rollback() != nil {
		return ErrInstall
	}
	return nil
}
