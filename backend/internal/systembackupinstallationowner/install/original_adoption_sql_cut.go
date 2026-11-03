package install

import (
	controller "clawreef/internal/systembackupcontroller"
	adapter "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	"context"
	"database/sql"
	"sync"
	"time"
)

type OriginalAdoptionSQLCutInspection struct {
	Version, State string
	SQL            adapter.OriginalAdoptionSQLCutData
}

// Actual original auth and read observation, with no SQL locks held while the
// independent original source owners produce their17 signed controls. This
// private preparation is context-bound and has one ORIGINAL nonrenewing cap.
// It is NOT a physical proof, PreparedCoverage, task grant or commit handle.
type PreparedOriginalAdoptionSQLCut struct {
	mu          sync.Mutex
	origin      *PreparedOriginalAdoptionSQLCut
	ctx         context.Context
	operator    *authenticatedOperator
	enrollment  EnrollmentPin
	reservation controller.OriginalAdoptionReservation
	database    controller.OriginalAdoptionDatabasePin
	scanner     *adapter.SQLCoverageCensus
	observed    *adapter.UnadmittedSQLCoverageCensus
	until       time.Time
	used        bool
}

func (*PreparedOriginalAdoptionSQLCut) MarshalJSON() ([]byte, error) { return nil, ErrInstall }

// PrepareOriginalAdoptionSQLCut performs real local-admin/enrollment and CURRENT
// original held-gate checks before full original SQL census. No fake future
// task or OfflineBootstrapGrant exists on this route. B/C physical history is
// still a separate mandatory producer before a complete adoption executor.
func (i *Installer) PrepareOriginalAdoptionSQLCut(ctx context.Context, password []byte, enrollment EnrollmentPin, reservation controller.OriginalAdoptionReservation) (*PreparedOriginalAdoptionSQLCut, error) {
	s, e := i.authenticate(ctx, password)
	if e != nil || s.authority(ctx, enrollment) != nil {
		return nil, ErrInstall
	}
	if reservation.Phase != controller.GateHeld || reservation.InstallationID != i.plan.Target.InstallationID || reservation.ServerUUID != i.plan.Target.ServerUUID || reservation.Database != i.plan.Target.Database {
		return nil, ErrInstall
	}
	pin := controller.OriginalAdoptionDatabasePin{ServerUUID: i.plan.Target.ServerUUID, Database: i.plan.Target.Database, Account: i.plan.InstallerDatabaseAccount}
	preflight, e := i.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return nil, ErrInstall
	}
	gate, e := controller.LockOriginalAdoptionReservation(ctx, preflight, pin, reservation)
	if e != nil {
		preflight.Rollback()
		return nil, e
	}
	until := gate.ValidUntil()
	if s.until.Before(until) {
		until = s.until
	}
	if preflight.Rollback() != nil {
		return nil, ErrInstall
	}
	scanner, e := adapter.NewSQLCoverageCensus(i.db, reg.DatabaseIdentity{ServerUUID: i.plan.Target.ServerUUID, Database: i.plan.Target.Database}, i.plan.Target.InstallationID)
	if e != nil {
		return nil, ErrInstall
	}
	observed, e := scanner.Observe(ctx)
	if e != nil {
		return nil, e
	}
	if s.authority(ctx, enrollment) != nil || !time.Now().Before(until) {
		return nil, ErrInstall
	}
	p := &PreparedOriginalAdoptionSQLCut{ctx: ctx, operator: s, enrollment: enrollment, reservation: reservation, database: pin, scanner: scanner, observed: observed, until: until}
	p.origin = p
	return p, nil
}

// The actual opaque census may sign ONLY its own SQL witness using the existing
// original SQL issuer API. This permits the caller to construct the17 evidence
// batch against the exact observation without a self-hashing/time cycle.
func (p *PreparedOriginalAdoptionSQLCut) SQLCensus() (*adapter.UnadmittedSQLCoverageCensus, error) {
	if p == nil {
		return nil, ErrInstall
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.origin != p || p.used || !p.operator.live(p.ctx) || !time.Now().Before(p.until) {
		return nil, ErrInstall
	}
	return p.observed, nil
}

// CheckControls executes the first SQL/evidence segment and ALWAYS rolls back:
// gate -> original admin/head/grant ->17 evidence gaps -> all original source
// ranges -> actual17 signed control INSERTs -> complete exact own-delta/source
// recheck -> confirmed rollback -> current original authority readback. It
// exposes no transaction/Commit, adopts nothing and never authorizes thaw.
func (p *PreparedOriginalAdoptionSQLCut) CheckControls(ctx context.Context, pins adapter.OriginalAdoptionControlPins, records adapter.OriginalAdoptionControlRecords) (OriginalAdoptionSQLCutInspection, error) {
	return p.checkControls(ctx, pins, records, nil)
}

// CheckAuthenticatedControls consumes the independently installed original KEK
// preparation. No witness pins/issuers can be selected from submitted records.
// It executes actual KEK Bind and A authentication in the very same original
// held-gate/admin/source/evidence tx and ALWAYS confirms rollback, never adopt.
func (p *PreparedOriginalAdoptionSQLCut) CheckAuthenticatedControls(ctx context.Context, records adapter.OriginalAdoptionControlRecords, preparation *adapter.SQLBootstrapKEKPreparation) (OriginalAdoptionSQLCutInspection, error) {
	if p == nil || p.operator == nil || p.operator.installer == nil || preparation == nil {
		return OriginalAdoptionSQLCutInspection{}, ErrInstall
	}
	cfg, err := preparation.OriginalConfiguration()
	if err != nil || cfg.InstallationID != p.reservation.InstallationID || cfg.Database != (reg.DatabaseIdentity{ServerUUID: p.database.ServerUUID, Database: p.database.Database}) {
		return OriginalAdoptionSQLCutInspection{}, ErrInstall
	}
	owner, err := adapter.NewSQLCoverageOwnerPreparation(adapter.SQLCoverageOwnerConfig{
		DB: p.operator.installer.db, Database: cfg.Database, InstallationID: cfg.InstallationID,
		Adoption: cfg.Adoption, Witnesses: cfg.Witnesses,
	})
	if err != nil {
		return OriginalAdoptionSQLCutInspection{}, ErrInstall
	}
	pins := adapter.OriginalAdoptionControlPins{Adoption: cfg.Adoption, Witnesses: cfg.Witnesses}
	return p.checkControls(ctx, pins, records, owner)
}

func (p *PreparedOriginalAdoptionSQLCut) checkControls(ctx context.Context, pins adapter.OriginalAdoptionControlPins, records adapter.OriginalAdoptionControlRecords, owner *adapter.SQLCoverageOwnerPreparation) (OriginalAdoptionSQLCutInspection, error) {
	zero := OriginalAdoptionSQLCutInspection{}
	if p == nil {
		return zero, ErrInstall
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.origin != p || p.used || !consumerSameContext(ctx, p.ctx) || !p.operator.live(ctx) || !time.Now().Before(p.until) {
		return zero, ErrInstall
	}
	p.used = true
	s := p.operator
	i := s.installer
	if s.authority(ctx, p.enrollment) != nil {
		return zero, ErrInstall
	}
	original, e := p.scanner.BeginOriginalTransaction(ctx)
	if e != nil {
		return zero, e
	}
	defer original.Tx().Rollback()
	gate, e := controller.LockOriginalAdoptionReservation(ctx, original.Tx(), p.database, p.reservation)
	if e != nil {
		return zero, e
	}
	now, e := s.lockAdmin(ctx, original.Tx())
	if e != nil {
		return zero, e
	}
	current, e := s.current(ctx, original.Tx(), false)
	if e != nil {
		return zero, e
	}
	until := p.until
	if gate.ValidUntil().Before(until) {
		until = gate.ValidUntil()
	}
	if current.cas.HeadRevision != 0 {
		if current.cas.State != "active" || now.Before(current.head.NotBefore) || !now.Before(current.head.Until) {
			return zero, ErrInstall
		}
		if current.head.Until.Before(until) {
			until = current.head.Until
		}
	}
	cut, e := p.scanner.PrepareOriginalAdoptionControlCut(ctx, original, p.observed, pins, until)
	if e != nil {
		return zero, e
	}
	defer cut.Abort()
	if cut.Stage(ctx, records) != nil || cut.Recheck(ctx) != nil {
		return zero, ErrInstall
	}
	var bound *reg.Bound
	var authenticated *adapter.AuthenticatedFirstAdoption
	if owner != nil {
		bound, authenticated, e = owner.BindFirstAdoptionControls(ctx, cut)
		if e != nil || bound == nil || authenticated == nil {
			return zero, ErrInstall
		}
		stamp, err := i.database(ctx, original.Tx(), until)
		if err != nil || authenticated.Recheck(ctx, original.Tx(), bound.Snapshot(), stamp) != nil {
			return zero, ErrInstall
		}
	}
	if _, e = s.lockAdmin(ctx, original.Tx()); e != nil {
		return zero, e
	}
	tail, e := s.current(ctx, original.Tx(), false)
	if e != nil || tail.cas != current.cas {
		return zero, ErrInstall
	}
	stamp, e := i.database(ctx, original.Tx(), until)
	if e != nil || gate.Recheck(ctx, original.Tx(), stamp) != nil || cut.Recheck(ctx) != nil {
		return zero, ErrInstall
	}
	if authenticated != nil && authenticated.Recheck(ctx, original.Tx(), bound.Snapshot(), stamp) != nil {
		return zero, ErrInstall
	}
	data, e := cut.InspectionData()
	if e != nil {
		return zero, e
	}
	if cut.Abort() != nil {
		return zero, ErrInstall
	}
	if s.authority(ctx, p.enrollment) != nil {
		return zero, ErrInstall
	}
	after, stamp, e := originalAdoptionAuthoritySnapshot(ctx, s)
	if e != nil || after.cas != current.cas || stamp.Before(data.CheckedAt) || !stamp.Before(until) || !time.Now().Before(until) {
		return zero, ErrInstall
	}
	state := "sql_source_and_17_controls_rechecked_rolled_back_not_adopted"
	if authenticated != nil {
		state = "sql_source_17_controls_and_same_tx_kek_authentication_rolled_back_not_adopted"
	}
	return OriginalAdoptionSQLCutInspection{Version: "original-adoption-sql-control-cut-inspection.v1", State: state, SQL: data}, nil
}

// MySQL permits FOR SHARE in a read-only RR transaction. This authority
// readback performs no DML and explicitly confirms rollback.
func originalAdoptionAuthoritySnapshot(ctx context.Context, s *authenticatedOperator) (currentAuthority, time.Time, error) {
	tx, e := s.installer.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return currentAuthority{}, time.Time{}, ErrInstall
	}
	defer tx.Rollback()
	before, e := s.lockAdmin(ctx, tx)
	if e != nil {
		return currentAuthority{}, time.Time{}, e
	}
	current, e := s.current(ctx, tx, false)
	if e != nil {
		return currentAuthority{}, time.Time{}, e
	}
	after, e := s.installer.database(ctx, tx, s.until)
	if e != nil || after.Before(before) || tx.Rollback() != nil {
		return currentAuthority{}, time.Time{}, ErrInstall
	}
	return current, after, nil
}
