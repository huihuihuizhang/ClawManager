package systembackupkekadapter

import (
	"context"
	"database/sql"

	reg "clawreef/internal/systembackupkekregistry"
	sec "clawreef/internal/systembackupsecurity"
)

// BootstrapAdmissionSource is C's original candidate/coverage source. The SQL
// snapshot is supplied by D; C must preserve it exactly and resolve its own
// mapping and coverage records. A separately authenticates those records.
type BootstrapAdmissionSource interface {
	BootstrapAdmissionInput(context.Context, sec.OfflineBootstrapGrant, sec.BootstrapConfig, reg.Snapshot) (reg.AdmissionInput, error)
}

// BootstrapComposition prepares all source and provider observations before
// the original bootstrap owner takes locks. The owner stages and rechecks the
// resulting admission in its own transaction; this object cannot commit.
type BootstrapComposition struct {
	Store     reg.SQLStore
	Source    BootstrapAdmissionSource
	Validator KEKAdmissionValidator
}

var _ sec.BootstrapKEKPreparation = BootstrapComposition{}

func (c BootstrapComposition) PrepareBootstrapKEK(ctx context.Context, db *sql.DB, grant sec.OfflineBootstrapGrant, config sec.BootstrapConfig) (reg.PreparedAdmission, error) {
	if ctx == nil || ctx.Err() != nil || db == nil || nilSource(c.Source) {
		return nil, sec.ErrRegistrationUnavailable
	}
	snapshot, err := c.Store.ReadSnapshot(ctx, db, grant.InstallationID)
	if err != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	in, err := c.Source.BootstrapAdmissionInput(ctx, grant, config, snapshot)
	if err != nil || !reg.SameSnapshotFacts(in.Snapshot, snapshot) || !in.Snapshot.ObservedAt.Equal(snapshot.ObservedAt) {
		return nil, sec.ErrRegistrationUnavailable
	}
	prepared, err := c.Validator.PrepareBootstrapKEK(ctx, grant, config, in)
	if err != nil {
		return nil, err
	}
	if coverage, ok := in.Coverage.(*SQLPreparedOriginalCoverage); ok {
		return &bootstrapOriginalEvidenceAdmission{PreparedAdmission: prepared, coverage: coverage}, nil
	}
	return prepared, nil
}
