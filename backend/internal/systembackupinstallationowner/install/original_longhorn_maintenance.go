package install

import (
	"context"
	"database/sql"

	q "clawreef/internal/systembackup/quiesce"
	c "clawreef/internal/systembackupcontroller"
)

// forwardLonghorn is only for forward maintenance operations. Recovery must
// use its durable independent recovery fence, including after this owner dies.
// This method journals intent and retains unknown results; it never retries IO.
func (p *OriginalWriterMaintenance) forwardLonghorn(ctx context.Context, client *q.SharedRuntimeNodeClient, journal *originalWriterJournal, reservation c.OriginalAdoptionReservation, request *q.LonghornExt4Request) (*q.VerifiedLonghornExt4Observation, []byte, error) {
	if p == nil || client == nil || journal == nil || request == nil {
		return nil, nil, ErrInstall
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	switch request.Action {
	case "register", "qualify", "acquire", "check-held", "register-client", "sync-client":
	default:
		return nil, nil, ErrInstall
	}
	if p.checkCurrentGate(ctx, c.GateAcquiring, c.GateHeld) != nil ||
		reservation.OperationID != p.operation || reservation.GateOwner != p.token.Owner ||
		reservation.GateGeneration != p.token.Generation || reservation.Phase != p.token.State ||
		reservation.InstallationID != p.operator.installer.plan.Target.InstallationID ||
		journal.operation != p.operation || journal.inventory != reservation.SourceWritersSHA256 ||
		reservation.ExpiresAt.After(p.until) {
		return nil, nil, ErrInstall
	}
	i := p.operator.installer
	tx, err := i.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, nil, ErrInstall
	}
	defer tx.Rollback()
	gate, err := c.LockOriginalAdoptionReservation(ctx, tx, c.OriginalAdoptionDatabasePin{
		ServerUUID: i.plan.Target.ServerUUID, Database: i.plan.Target.Database, Account: i.plan.InstallerDatabaseAccount,
	}, reservation)
	if err != nil {
		return nil, nil, ErrInstall
	}
	if _, err = p.operator.lockAdmin(ctx, tx); err != nil {
		return nil, nil, ErrInstall
	}
	current, err := p.operator.current(ctx, tx, false)
	if err != nil || current.cas != p.initial {
		return nil, nil, ErrInstall
	}
	fresh, err := gate.LonghornClaim(ctx, tx, request.Binding)
	if err != nil {
		return nil, nil, ErrInstall
	}
	request.Claim, err = originalLonghornFrozenClaim(request.Claim, fresh)
	if err != nil {
		return nil, nil, err
	}
	// Release SQL locks before network IO, retaining only the bounded sample.
	if tx.Rollback() != nil {
		return nil, nil, ErrInstall
	}
	if journal.append(ctx, reservation.WriterID, "longhorn_"+request.Action+"_intent", nil, request) != nil {
		return nil, nil, ErrInstall
	}
	proof, raw, err := client.LonghornExt4Transition(ctx, *request)
	if err != nil {
		// The durable intent remains unresolved; do not record a false failure
		// that could authorize another acquire after a lost response.
		return nil, raw, err
	}
	if journal.append(ctx, reservation.WriterID, "longhorn_"+request.Action+"_observed", nil, proof.Response()) != nil {
		return nil, raw, ErrInstall
	}
	return proof, raw, nil
}

// The node journal keys the immutable registration claim. Fresh SQL samples
// revalidate that claim; they must never silently extend its lease or change
// the key between register and acquire/check-held.
func originalLonghornFrozenClaim(original, fresh q.LonghornExt4Claim) (q.LonghornExt4Claim, error) {
	if original == (q.LonghornExt4Claim{}) {
		return fresh, nil
	}
	if original.TaskPublicID != "" || original.OriginalOperationID != fresh.OriginalOperationID ||
		original.OriginalReservationID != fresh.OriginalReservationID || original.Owner != fresh.Owner ||
		original.MaintenanceOwner != fresh.MaintenanceOwner || original.EntryRowVersion != fresh.EntryRowVersion ||
		original.LeaseObservedAt.IsZero() || original.LeaseObservedAt.After(fresh.LeaseObservedAt) ||
		!fresh.LeaseObservedAt.Before(original.LeaseExpiresAt) || original.LeaseExpiresAt.After(fresh.LeaseExpiresAt) {
		return q.LonghornExt4Claim{}, ErrInstall
	}
	return original, nil
}
