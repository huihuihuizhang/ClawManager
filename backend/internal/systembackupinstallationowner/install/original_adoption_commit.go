package install

import (
	"context"
	"database/sql"
	"reflect"
	"time"

	c "clawreef/internal/systembackupcontroller"
	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
)

// A source-consuming constructor must supply real classified history and
// references. There is deliberately no DTO-to-PreparedCoverage constructor.
// The current archive copy alone cannot construct this private history source.
type originalClassifiedHistorySource interface {
	references() []reg.Reference
	recheckBeforeOriginalHistorySQL(context.Context) error
	validUntil() time.Time
	recheckOriginalHistory(context.Context, *sql.Tx, reg.LockedSnapshot, time.Time) error
}

type PreparedOriginalAdoptionCoverage struct {
	sourceSet     *originalHistorySourceSet
	sqlMetadata   *originalHistorySQLMetadata
	origin        *PreparedOriginalAdoptionCoverage
	ctx           context.Context
	hold          *OriginalWriterHold
	history       originalClassifiedHistorySource
	cut           *a.OriginalAdoptionControlCut
	authenticated *a.AuthenticatedFirstAdoption
	native        *originalHeldReadiness
	tx            *sql.Tx
	sources       []reg.CoverageSource
	refs          []reg.Reference
	epoch         uint64
	until         time.Time
}

func (*PreparedOriginalAdoptionCoverage) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (p *PreparedOriginalAdoptionCoverage) Sources() []reg.CoverageSource {
	if p == nil || p.origin != p {
		return nil
	}
	return append([]reg.CoverageSource(nil), p.sources...)
}
func (p *PreparedOriginalAdoptionCoverage) References() []reg.Reference {
	if p == nil || p.origin != p || p.refs == nil {
		return nil
	}
	return append(make([]reg.Reference, 0, len(p.refs)), p.refs...)
}
func (p *PreparedOriginalAdoptionCoverage) ExpectedEpoch() uint64 {
	if p == nil || p.origin != p {
		return ^uint64(0)
	}
	return p.epoch
}
func (p *PreparedOriginalAdoptionCoverage) ValidUntil() time.Time {
	if p == nil || p.origin != p {
		return time.Time{}
	}
	return p.until
}

func (p *PreparedOriginalAdoptionCoverage) Recheck(ctx context.Context, view reg.SQLReadView, locked reg.LockedSnapshot, now time.Time) error {
	if p == nil || p.origin != p || p.history == nil || p.hold == nil || p.hold.origin != p.hold || p.hold.closed || p.hold.adoptionUnknown || !consumerSameContext(ctx, p.ctx) || p.cut == nil || p.authenticated == nil || p.native == nil || p.sourceSet == nil || p.sqlMetadata == nil || p.sourceSet.metadata != p.sqlMetadata || !p.sourceSet.local(ctx, true) || now.IsZero() || !now.Before(p.until) {
		return ErrInstall
	}
	tx, ok := view.(*sql.Tx)
	if !ok || tx != p.tx || locked.Facts().Epoch != p.epoch || !reflect.DeepEqual(locked.Facts().References, p.refs) || !reflect.DeepEqual(p.history.references(), p.refs) || !now.Before(p.history.validUntil()) {
		return ErrInstall
	}
	if p.authenticated.Recheck(ctx, tx, locked, now) != nil || p.cut.Recheck(ctx) != nil || p.native.VerifyParticipantsPaused(ctx, c.SQLCoordinationTransaction{Tx: tx}, p.hold.set.owner.token.Key, p.hold.set.owner.token.Generation) != nil {
		return ErrInstall
	}
	return p.history.recheckOriginalHistory(ctx, tx, locked, now)
}

type OriginalAdoptionCommitInspection struct {
	Version, Operation, State, InventorySHA256, ExpectedSHA256 string
	ExpectedEpoch                                              uint64
}
type originalAdoptionCommitExpected struct {
	Bindings                                                                  []reg.BindingFacts
	Version, Operation, InstallationID, ServerUUID, Database, InventorySHA256 string
	OldEpoch, NewEpoch                                                        uint64
	Sources                                                                   []reg.CoverageSource
	References                                                                []reg.Reference
	ControlRows                                                               map[string]string
}

// CommitOriginalAdoption owns the real final SQL prefix and completion. It can
// consume only a genuine complete holder and a private source-consuming
// PreparedCoverage. All B/C I/O is finished BEFORE opening this transaction.
// A's existing authentication does not itself mint the missing history source.
func (p *PreparedOriginalAdoptionSQLCut) CommitOriginalAdoption(ctx context.Context, hold *OriginalWriterHold, records a.OriginalAdoptionControlRecords, preparation *a.SQLBootstrapKEKPreparation, coverage *PreparedOriginalAdoptionCoverage) (OriginalAdoptionCommitInspection, error) {
	if p == nil || p.operator == nil || p.operator.installer == nil || preparation == nil {
		return OriginalAdoptionCommitInspection{}, ErrInstall
	}
	cfg, err := preparation.OriginalConfiguration()
	if err != nil {
		return OriginalAdoptionCommitInspection{}, ErrInstall
	}
	owner, err := a.NewSQLCoverageOwnerPreparation(a.SQLCoverageOwnerConfig{DB: p.operator.installer.db, Database: cfg.Database, InstallationID: cfg.InstallationID, Adoption: cfg.Adoption, Witnesses: cfg.Witnesses})
	if err != nil {
		return OriginalAdoptionCommitInspection{}, ErrInstall
	}
	return p.CommitOriginalOwnerAdoption(ctx, hold, records, owner, coverage)
}

// First adoption authenticates the original coverage owners; it does not
// require later configuration Generate/Unwrap or mapping admission. This is
// the ONE actual transaction body, also used by the compatibility wrapper.
func (p *PreparedOriginalAdoptionSQLCut) CommitOriginalOwnerAdoption(ctx context.Context, hold *OriginalWriterHold, records a.OriginalAdoptionControlRecords, owner *a.SQLCoverageOwnerPreparation, coverage *PreparedOriginalAdoptionCoverage) (OriginalAdoptionCommitInspection, error) {
	var zero OriginalAdoptionCommitInspection
	if p == nil || hold == nil || hold.set == nil || coverage == nil {
		return zero, ErrInstall
	}
	hold.set.mu.Lock()
	defer hold.set.mu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.origin != p || p.used || !consumerSameContext(ctx, p.ctx) || hold.recheckBeforeSQL(ctx) != nil || coverage.origin != coverage || coverage.hold != hold || coverage.history == nil || coverage.sourceSet == nil || coverage.sqlMetadata == nil || coverage.sourceSet.metadata != coverage.sqlMetadata || !coverage.sourceSet.local(ctx, false) || coverage.tx != nil || owner == nil {
		return zero, ErrInstall
	}
	// Read only the independent constructor-fixed17 owner pins from A.
	// The real DB pointer and installation identity remain original production inputs.
	cfg, err := owner.FirstAdoptionConfiguration()
	if err != nil || cfg.DB != p.operator.installer.db || cfg.InstallationID != p.reservation.InstallationID || cfg.Database != (reg.DatabaseIdentity{ServerUUID: p.database.ServerUUID, Database: p.database.Database}) {
		return zero, ErrInstall
	}
	if p.operator.authority(ctx, p.enrollment) != nil || hold.set.owner.operation != p.reservation.OperationID || hold.set.inventorySHA != p.reservation.SourceWritersSHA256 {
		return zero, ErrInstall
	}
	if coverage.history.recheckBeforeOriginalHistorySQL(ctx) != nil {
		return zero, ErrInstall
	}
	proof, err := hold.set.refreshNativeHold(ctx)
	if err != nil {
		return zero, err
	}
	nativeUntil, err := originalAdoptionNativeUntil(proof)
	if err != nil {
		return zero, err
	}
	if nativeUntil.Before(coverage.until) {
		coverage.until = nativeUntil
	}
	original, err := p.scanner.BeginOriginalTransaction(ctx)
	if err != nil {
		return zero, err
	}
	defer original.Tx().Rollback()
	gate, err := c.LockOriginalAdoptionReservation(ctx, original.Tx(), p.database, p.reservation)
	if err != nil {
		return zero, err
	}
	now, err := p.operator.lockAdmin(ctx, original.Tx())
	if err != nil {
		return zero, err
	}
	head, err := p.operator.current(ctx, original.Tx(), false)
	if err != nil || head.cas != hold.set.owner.initial || head.cas.State == "revoked" {
		return zero, ErrInstall
	}
	until := p.until
	if head.cas.HeadRevision != 0 {
		if head.cas.State != "active" || now.Before(head.head.NotBefore) || !now.Before(head.head.Until) {
			return zero, ErrInstall
		}
		if head.head.Until.Before(until) {
			until = head.head.Until
		}
	}
	if gate.ValidUntil().Before(until) {
		until = gate.ValidUntil()
	}
	if coverage.until.Before(until) {
		until = coverage.until
	}
	p.used = true
	cut, err := p.scanner.PrepareOriginalAdoptionControlCut(ctx, original, p.observed, a.OriginalAdoptionControlPins{Adoption: cfg.Adoption, Witnesses: cfg.Witnesses}, until)
	if err != nil {
		return zero, err
	}
	defer cut.Abort()
	if cut.Stage(ctx, records) != nil {
		return zero, ErrInstall
	}
	bound, authenticated, err := owner.BindFirstAdoptionControls(ctx, cut)
	if err != nil || bound == nil || authenticated == nil {
		return zero, ErrInstall
	}
	coverage.ctx = ctx
	coverage.tx = original.Tx()
	coverage.cut = cut
	coverage.authenticated = authenticated
	coverage.native = proof
	coverage.epoch = bound.Snapshot().Facts().Epoch
	coverage.until = until
	if coverage.bindOriginalHistoryControls(ctx, cfg, records) != nil {
		return zero, ErrInstall
	}
	until = coverage.until
	if !reflect.DeepEqual(coverage.refs, bound.Snapshot().Facts().References) {
		return zero, ErrInstall
	} // actual backfill must already be complete
	now, err = p.operator.installer.database(ctx, original.Tx(), until)
	if err != nil || coverage.Recheck(ctx, original.Tx(), bound.Snapshot(), now) != nil {
		return zero, ErrInstall
	}
	if bound.AdoptCoverage(ctx, coverage) != nil {
		return zero, ErrInstall
	}
	// A's actual post-adoption derived-index readback, not Snapshot() (which
	// intentionally still returns the original Bind snapshot).
	if bound.RecheckAdoption(ctx, coverage) != nil {
		return zero, ErrInstall
	}
	stamp, err := p.operator.installer.database(ctx, original.Tx(), until)
	if err != nil || authenticated.Recheck(ctx, original.Tx(), bound.Snapshot(), stamp) != nil || cut.Recheck(ctx) != nil || gate.Recheck(ctx, original.Tx(), stamp) != nil {
		return zero, ErrInstall
	}
	tail, err := p.operator.current(ctx, original.Tx(), false)
	if err != nil || tail.cas != head.cas {
		return zero, ErrInstall
	}
	expected := originalAdoptionCommitExpected{Version: "original-adoption-commit-expectation.v1", Operation: hold.set.owner.operation, InstallationID: p.reservation.InstallationID, ServerUUID: p.database.ServerUUID, Database: p.database.Database, InventorySHA256: hold.set.inventorySHA, OldEpoch: coverage.epoch, NewEpoch: coverage.epoch + 1, Sources: coverage.Sources(), References: coverage.References(), ControlRows: map[string]string{}}
	for id, record := range records {
		expected.ControlRows[id] = originalObjectSHA(record)
	}
	expected.Bindings = bound.Snapshot().Facts().Bindings
	digest := originalObjectSHA(expected)
	if hold.set.journal.append(ctx, "", "adoption_commit_send_unknown", nil, expected) != nil {
		return zero, ErrInstall
	}
	hold.adoptionUnknown = true
	p.used = true
	if original.Tx().Commit() != nil {
		return zero, ErrCommitUnknown
	}
	// The separate exact-operation SQL readback is mandatory even after the
	// driver reported successful COMMIT. It must also be usable after restart.
	if err = readbackOriginalAdoptionCommit(ctx, p.operator.installer.db, expected); err != nil {
		return zero, ErrCommitUnknown
	}
	if hold.set.journal.append(ctx, "", "adoption_commit_readback", nil, expected) != nil {
		return zero, ErrCommitUnknown
	}
	hold.adoptionUnknown = false
	return OriginalAdoptionCommitInspection{Version: "original-adoption-commit-inspection.v1", Operation: expected.Operation, State: "committed_exact_original_readback", InventorySHA256: expected.InventorySHA256, ExpectedSHA256: digest, ExpectedEpoch: expected.NewEpoch}, nil
}
