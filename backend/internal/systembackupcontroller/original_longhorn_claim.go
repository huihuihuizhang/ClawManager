package systembackupcontroller

import (
	"context"
	"database/sql"
	"time"

	q "clawreef/internal/systembackup/quiesce"
)

// LonghornClaim samples the original SQL reservation again before a native
// forward request. The returned correlation is not a recovery capability or
// permission to reuse the claim after this transaction has ended.
func (p *VerifiedOriginalAdoptionReservation) LonghornClaim(ctx context.Context, tx *sql.Tx, binding q.ObservationBinding) (q.LonghornExt4Claim, error) {
	if p == nil {
		return q.LonghornExt4Claim{}, ErrGateFenceLost
	}
	p.mu.Lock()
	floor := p.floor
	p.mu.Unlock()
	if p.Recheck(ctx, tx, floor) != nil {
		return q.LonghornExt4Claim{}, ErrGateFenceLost
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	r := p.claim
	if p.failed || r.ControlKind != "platform-quiesce" || r.Phase == GateReleasing ||
		binding.Kind != q.LonghornExt4Protocol || binding.InstallationID != r.InstallationID ||
		binding.OperationID != r.OperationID || binding.ReservationID != r.ReservationID ||
		binding.Generation != r.GateGeneration || binding.FenceEpoch != r.AcquisitionEpoch ||
		binding.InventorySHA256 != r.SourceWritersSHA256 || !binding.ExpiresAt.Equal(r.ExpiresAt) ||
		binding.Namespace == "" || binding.NamespaceUID == "" || binding.Node == "" || binding.NodeUID == "" {
		p.failed = true
		return q.LonghornExt4Claim{}, ErrGateFenceLost
	}
	until := p.until
	if cap := p.floor.Add(300 * time.Second); cap.Before(until) {
		until = cap
	}
	if !p.floor.Before(until) {
		p.failed = true
		return q.LonghornExt4Claim{}, ErrGateFenceLost
	}
	return q.LonghornExt4Claim{OriginalOperationID: r.OperationID, OriginalReservationID: r.ReservationID,
		Owner: r.GateOwner, MaintenanceOwner: r.GateOwner, EntryRowVersion: r.AcquisitionRowVersion,
		LeaseObservedAt: p.floor, LeaseExpiresAt: until}, nil
}
