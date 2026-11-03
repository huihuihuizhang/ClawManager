package systembackupkekadapter

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"reflect"
	"time"

	admission "clawreef/internal/systembackupkekadmission"
	reg "clawreef/internal/systembackupkekregistry"
	kms "clawreef/internal/systembackupkms"
	sec "clawreef/internal/systembackupsecurity"
)

// Independent original deployment pins, not fields accepted from a config
// mutation request. Coverage must already come from actual historical adoption.
type SQLMutationSourceConfig struct {
	DB             *sql.DB
	Database       reg.DatabaseIdentity
	InstallationID string
	Mapping        reg.ReferencePin
	MappingIssuer  ed25519.PublicKey
	Generate       ProviderCapabilityPin
	Unwrap         ProviderCapabilityPin
	Coverage       *SQLCoverageOwnerPreparation
}

type SQLMutationAdmissionSource struct{ cfg SQLBootstrapSourceConfig }

func NewSQLMutationAdmissionSource(cfg SQLMutationSourceConfig) (*SQLMutationAdmissionSource, error) {
	// Share constructor validation/copying of public original pins only. Never
	// call a bootstrap action or manufacture an OfflineBootstrapGrant.
	validated, err := NewSQLBootstrapAdmissionSource(SQLBootstrapSourceConfig{DB: cfg.DB, Database: cfg.Database, InstallationID: cfg.InstallationID, Mapping: cfg.Mapping, MappingIssuer: cfg.MappingIssuer, Generate: cfg.Generate, Unwrap: cfg.Unwrap, Coverage: cfg.Coverage})
	if err != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	return &SQLMutationAdmissionSource{cfg: validated.cfg}, nil
}

func (s *SQLMutationAdmissionSource) MutationAdmissionInput(ctx context.Context, input sec.ConfigMutationResourceInput, snapshot reg.Snapshot) (reg.AdmissionInput, error) {
	fail := func() (reg.AdmissionInput, error) { return reg.AdmissionInput{}, sec.ErrRegistrationUnavailable }
	if s == nil || nilSource(ctx) || ctx.Err() != nil || input.Slot() != "reference:kek" || input.InstallationID() != s.cfg.InstallationID || snapshot.InstallationID != s.cfg.InstallationID || snapshot.Database != s.cfg.Database || snapshot.ObservedAt.IsZero() || s.cfg.Coverage == nil {
		return fail()
	}
	_, proposed := input.Configs()
	_, reference, ok := input.ReferencePair("kek")
	if !ok || len(proposed.CanonicalJSON()) == 0 || reference.Purpose != "kek" || reference.IdentityHash != s.cfg.Mapping.IdentityHash || reference.Version != s.cfg.Mapping.Version {
		return fail()
	}
	// Read and authenticate actual independently selected records outside the
	// mutation owner's locks. No candidate/config supplies a binding or issuer.
	tx, err := s.cfg.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return fail()
	}
	defer tx.Rollback()
	var database reg.DatabaseIdentity
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6)`).Scan(&database.ServerUUID, &database.Database, &now) != nil || database != s.cfg.Database || now.IsZero() || now.Before(snapshot.ObservedAt) {
		return fail()
	}
	raw, signature, err := readOriginal(ctx, tx, s.cfg.InstallationID, s.cfg.Mapping)
	if err != nil {
		return fail()
	}
	original, err := authenticate(raw, signature, s.cfg.MappingIssuer, now)
	if err != nil || original.Binding.InstallationID != s.cfg.InstallationID || original.Binding.ConfigRef != s.cfg.Mapping {
		return fail()
	}
	coverage, err := s.cfg.Coverage.Prepare(ctx, snapshot)
	if err != nil || coverage.ExpectedEpoch() != snapshot.Epoch || !now.Before(coverage.ValidUntil()) || !reflect.DeepEqual(coverage.Sources(), snapshot.Coverage) || !reflect.DeepEqual(coverage.References(), snapshot.References) {
		return fail()
	}
	start, end := original.NotBefore, original.Until
	if coverage.ValidUntil().Before(end) {
		end = coverage.ValidUntil()
	}
	for _, pair := range []struct {
		pin       ProviderCapabilityPin
		operation kms.Operation
	}{{s.cfg.Generate, kms.Generate}, {s.cfg.Unwrap, kms.Unwrap}} {
		e, err := readCapabilityEvidence(ctx, tx, s.cfg.InstallationID, pair.pin, false)
		if err != nil {
			return fail()
		}
		capability, err := authenticateProviderCapability(e, pair.pin, original.Binding, pair.operation, now)
		if err != nil {
			return fail()
		}
		if capability.NotBefore.After(start) {
			start = capability.NotBefore
		}
		for _, limit := range []time.Time{capability.Until, e.until} {
			if limit.Before(end) {
				end = limit
			}
		}
	}
	in := reg.AdmissionInput{Candidate: original.Binding, Observation: reg.AdmissionObservation{InstallationID: s.cfg.InstallationID, ConfigSHA256: proposed.SHA256(), SourceRevision: original.Revision, MappingSource: original.Source, GenerateCapabilitySource: s.cfg.Generate.Source, UnwrapCapabilitySource: s.cfg.Unwrap.Source, NotBefore: start, ValidUntil: end}, Snapshot: snapshot, Coverage: coverage}
	// Recheck the actual SQL clock AFTER all source reads. This does not renew
	// any source window or replace the caller's later original fenced clock.
	var final time.Time
	if tx.QueryRowContext(ctx, `SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6)`).Scan(&database.ServerUUID, &database.Database, &final) != nil || database != s.cfg.Database || final.Before(now) || admission.CheckUnadmittedInput(in, final) != nil || ctx.Err() != nil {
		return fail()
	}
	return in, nil
}

var _ MutationAdmissionSource = (*SQLMutationAdmissionSource)(nil)
