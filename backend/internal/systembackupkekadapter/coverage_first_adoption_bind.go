package systembackupkekadapter

import (
	"context"

	reg "clawreef/internal/systembackupkekregistry"
	sec "clawreef/internal/systembackupsecurity"
)

// BindFirstAdoptionControls acquires the KEK fence using the actual original
// transaction already owned by a staged source cut. Unlike a supplied
// LockedSnapshot (which carries facts only), the snapshot used here is obtained
// directly from this same transaction's SQLStore.Bind call.
//
// Required order: original maintenance/admin locks -> evidence gaps -> complete
// original source locks -> Stage -> this method. All native B/C IO must precede
// that SQL prefix. The returned Bound and authentication handle confer no
// physical/history proof and provide no PreparedCoverage or commit operation.
// D still owns native guards, historical backfill, adoption and final rollback
// or commit. Any error requires rollback of the original transaction, including
// the fence row which Bind may have created.
func (s *SQLCoverageOwnerPreparation) BindFirstAdoptionControls(ctx context.Context, cut *OriginalAdoptionControlCut) (*reg.Bound, *AuthenticatedFirstAdoption, error) {
	if s == nil || cut == nil {
		return nil, nil, sec.ErrRegistrationUnavailable
	}
	var bound *reg.Bound
	var locked reg.LockedSnapshot
	err := func() error {
		cut.mu.Lock()
		defer cut.mu.Unlock()
		if !cut.good(ctx) || !cut.staged || len(cut.rows) != 17 || !sameFirstAdoptionPins(s.cfg, cut.pins) || s.cfg.Database != cut.observed.Database || s.cfg.InstallationID != cut.observed.InstallationID || cut.recheck(ctx) != nil {
			return cut.poison()
		}
		var err error
		bound, locked, err = (reg.SQLStore{}).Bind(ctx, cut.original.tx, s.cfg.InstallationID)
		if err != nil {
			return cut.poison()
		}
		return nil
	}()
	if err != nil {
		return nil, nil, err
	}
	// AuthenticateFirstAdoption locks and rechecks the same cut again. A
	// concurrent abort/failure between Bind and authentication therefore refuses;
	// neither a Bound nor a partially authenticated handle escapes on failure.
	authenticated, err := s.AuthenticateFirstAdoption(ctx, cut, locked)
	if err != nil {
		return nil, nil, err
	}
	return bound, authenticated, nil
}
