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

// SQLBootstrapSourceConfig is original installation composition, never config
// request data. The mapping pin and all three owner issuers are independently
// fixed before the candidate is read. Coverage must come from the ORIGINAL
// source owner's completed adoption; this adapter cannot manufacture it from
// an empty KEK index, census counts, a config hash or an approval flag.
type SQLBootstrapSourceConfig struct {
	DB             *sql.DB
	Database       reg.DatabaseIdentity
	InstallationID string
	Mapping        reg.ReferencePin
	MappingIssuer  ed25519.PublicKey
	Generate       ProviderCapabilityPin
	Unwrap         ProviderCapabilityPin
	Coverage       *SQLCoverageOwnerPreparation
}

type SQLBootstrapAdmissionSource struct {
	cfg          SQLBootstrapSourceConfig
	capabilities *SQLProviderCapabilityPreparation
}

func NewSQLBootstrapAdmissionSource(cfg SQLBootstrapSourceConfig) (*SQLBootstrapAdmissionSource, error) {
	if cfg.DB == nil || cfg.InstallationID == "" || !authorityHash.MatchString(cfg.Mapping.IdentityHash) || !authorityExact(cfg.Mapping.Version) || len(cfg.MappingIssuer) != ed25519.PublicKeySize || cfg.Coverage == nil || cfg.Coverage.cfg.DB != cfg.DB || cfg.Coverage.cfg.Database != cfg.Database || cfg.Coverage.cfg.InstallationID != cfg.InstallationID {
		return nil, sec.ErrRegistrationUnavailable
	}
	caps, err := NewSQLProviderCapabilityPreparation(cfg.DB, cfg.Database, cfg.InstallationID, cfg.Generate, cfg.Unwrap)
	if err != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	cfg.MappingIssuer = append(ed25519.PublicKey(nil), cfg.MappingIssuer...)
	cfg.Generate.Issuer = append(ed25519.PublicKey(nil), cfg.Generate.Issuer...)
	cfg.Unwrap.Issuer = append(ed25519.PublicKey(nil), cfg.Unwrap.Issuer...)
	return &SQLBootstrapAdmissionSource{cfg: cfg, capabilities: caps}, nil
}

func (s *SQLBootstrapAdmissionSource) BootstrapAdmissionInput(ctx context.Context, grant sec.OfflineBootstrapGrant, config sec.BootstrapConfig, snapshot reg.Snapshot) (reg.AdmissionInput, error) {
	fail := func() (reg.AdmissionInput, error) { return reg.AdmissionInput{}, sec.ErrRegistrationUnavailable }
	if s == nil || s.capabilities == nil || nilSource(ctx) || ctx.Err() != nil || !sec.ValidOfflineBootstrapGrant(grant) || grant.InstallationID != s.cfg.InstallationID || grant.ServerUUID != s.cfg.Database.ServerUUID || grant.Database != s.cfg.Database.Database || grant.ConfigSHA256 != config.SHA256() || !matchesKEKReference(config.References(), s.cfg.Mapping) || snapshot.InstallationID != s.cfg.InstallationID || snapshot.Database != s.cfg.Database || snapshot.ObservedAt.IsZero() || nilSource(s.cfg.Coverage) {
		return fail()
	}
	// Use one real SQL clock and original authority row from the independently
	// pinned database. The caller-supplied candidate/config never supplies the
	// binding, original mapping revision, issuer or capability evidence pins.
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
	if err != nil {
		return fail()
	}
	if coverage.ExpectedEpoch() != snapshot.Epoch || !now.Before(coverage.ValidUntil()) || !reflect.DeepEqual(coverage.Sources(), snapshot.Coverage) || !reflect.DeepEqual(coverage.References(), snapshot.References) {
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
		// authenticateProviderCapability independently authenticates each exact
		// immutable original evidence row, including its operation/ref binding.
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
	in := reg.AdmissionInput{Candidate: original.Binding, Observation: reg.AdmissionObservation{
		InstallationID: s.cfg.InstallationID, ConfigSHA256: config.SHA256(), SourceRevision: original.Revision,
		MappingSource: original.Source, GenerateCapabilitySource: s.cfg.Generate.Source, UnwrapCapabilitySource: s.cfg.Unwrap.Source,
		NotBefore: start, ValidUntil: end,
	}, Snapshot: snapshot, Coverage: coverage}
	if admission.CheckUnadmittedInput(in, now) != nil || ctx.Err() != nil {
		return fail()
	}
	return in, nil
}

var _ BootstrapAdmissionSource = (*SQLBootstrapAdmissionSource)(nil)
