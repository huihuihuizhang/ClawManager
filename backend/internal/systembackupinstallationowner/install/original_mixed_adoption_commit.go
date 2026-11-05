package install

import (
	c "clawreef/internal/systembackupcontroller"
	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	"context"
	"reflect"
)

// Actual nonempty first-adoption owner. All external I/O finishes before the
// original transaction. No exported callback can replace its concrete sources.
func (p *PreparedOriginalAdoptionSQLCut) commitOriginalMixedOwnerAdoption(ctx context.Context, hold *OriginalWriterHold, records a.OriginalAdoptionControlRecords, owner *a.SQLCoverageOwnerPreparation, coverage *PreparedOriginalMixedAdoptionCoverage) (OriginalAdoptionCommitInspection, error) {
	var zero OriginalAdoptionCommitInspection
	if p == nil || hold == nil || hold.set == nil || coverage == nil {
		return zero, ErrInstall
	}
	hold.set.mu.Lock()
	defer hold.set.mu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.origin != p || p.used || !consumerSameContext(ctx, p.ctx) || hold.recheckBeforeSQL(ctx) != nil || coverage.origin != coverage || coverage.hold != hold || coverage.history == nil || !coverage.history.local(ctx, false) || coverage.history.prep != p || coverage.history.hold != hold || coverage.history.coverage != coverage || coverage.tx != nil || owner == nil {
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
	// Entire genuine business ownership range joins the ORIGINAL source prefix
	// BEFORE existing-F/evidence backfill. Any inserted/changed/deleted blob row
	// refuses; only the actual17 writer may change its own control evidence.
	if coverage.history.business == nil || coverage.history.business.lockOriginalSQL(ctx, original.Tx()) != nil {
		return zero, ErrInstall
	}
	// PrepareOriginalAdoptionControlCut already locks original17 gaps and ALL
	// raw source ranges under the real gate/admin/head prefix. The concrete
	// retained owner then takes the EXISTING original fence X, before its
	// first complete mixed reread and any mapping/backfill operation.
	retained := coverage.history.retained
	if retained.lockOriginalRetainedPrefix(ctx, original) != nil {
		return zero, ErrInstall
	}
	initialBound, _, bindErr := (reg.SQLStore{}).Bind(ctx, original.Tx(), p.reservation.InstallationID)
	if bindErr != nil || initialBound == nil || retained.stageOriginalRetained(ctx, original, initialBound) != nil {
		return zero, ErrInstall
	}
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
	if coverage.bindOriginalMixedHistoryControls(ctx, cfg, records) != nil {
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
	// This private phase changes ONLY after actual AdoptCoverage advanced the
	// original owned fence. RecheckAdoption still supplies the original Bind
	// snapshot, while the source reread must see exactly original epoch + 1.
	coverage.adopted = true
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
