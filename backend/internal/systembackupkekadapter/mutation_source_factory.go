package systembackupkekadapter

import (
	"context"
	"database/sql"

	reg "clawreef/internal/systembackupkekregistry"
	sec "clawreef/internal/systembackupsecurity"
)

// Concrete lawful config-mutation preparation, selected from independent
// original source pins. It creates no bootstrap grant and enables no config.
type SQLMutationKEKPreparation struct{ cfg SQLBootstrapKEKConfig }

func NewSQLMutationKEKPreparation(cfg SQLBootstrapKEKConfig) (*SQLMutationKEKPreparation, error) {
	validated, err := NewSQLBootstrapKEKPreparation(cfg)
	if err != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	return &SQLMutationKEKPreparation{cfg: validated.cfg}, nil
}

func (p *SQLMutationKEKPreparation) PrepareConfigMutationKEK(ctx context.Context, db *sql.DB, input sec.ConfigMutationResourceInput) (reg.PreparedAdmission, error) {
	if p == nil || db == nil || nilSource(ctx) || ctx.Err() != nil || input.Slot() != "reference:kek" || input.InstallationID() != p.cfg.InstallationID {
		return nil, sec.ErrRegistrationUnavailable
	}
	cfg := p.cfg
	coverage, err := NewSQLCoverageOwnerPreparation(SQLCoverageOwnerConfig{DB: db, Database: cfg.Database, InstallationID: cfg.InstallationID, Adoption: cfg.Adoption, Witnesses: cfg.Witnesses})
	if err != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	source, err := NewSQLMutationAdmissionSource(SQLMutationSourceConfig{DB: db, Database: cfg.Database, InstallationID: cfg.InstallationID, Mapping: cfg.Mapping, MappingIssuer: cfg.MappingIssuer, Generate: cfg.Generate, Unwrap: cfg.Unwrap, Coverage: coverage})
	if err != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	original, err := NewSQLInstallationPreparation(db, cfg.Database, cfg.InstallationID, cfg.MappingIssuer, cfg.Generate, cfg.Unwrap)
	if err != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	snapshot, err := (reg.SQLStore{}).ReadSnapshot(ctx, db, cfg.InstallationID)
	if err != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	in, err := source.MutationAdmissionInput(ctx, input, snapshot)
	if err != nil || !reg.SameSnapshotFacts(in.Snapshot, snapshot) || !in.Snapshot.ObservedAt.Equal(snapshot.ObservedAt) {
		return nil, sec.ErrRegistrationUnavailable
	}
	prepared, err := (KEKAdmissionValidator{Original: original, Now: original.Now}).PrepareConfigMutationKEK(ctx, input, in)
	if err != nil || nilSource(prepared) {
		return nil, sec.ErrRegistrationUnavailable
	}
	actualCoverage, ok := in.Coverage.(*SQLPreparedOriginalCoverage)
	if !ok || actualCoverage == nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	// Preserve this SAME actual opaque admission and its seventeen original
	// evidence dependencies. D locks that union before its original KEK fence,
	// then calls CompleteScan/StageAdmission/final Recheck in that transaction.
	return &bootstrapOriginalEvidenceAdmission{PreparedAdmission: prepared, coverage: actualCoverage}, nil
}

var _ sec.ConfigMutationKEKPreparation = (*SQLMutationKEKPreparation)(nil)
