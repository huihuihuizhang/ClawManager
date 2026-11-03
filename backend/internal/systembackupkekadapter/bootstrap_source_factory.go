package systembackupkekadapter

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"strings"

	reg "clawreef/internal/systembackupkekregistry"
	sec "clawreef/internal/systembackupsecurity"
)

// Constructor-fixed ORIGINAL owner pins. This is not a candidate config or a
// receipt-producing API. The actual database is supplied by the unchanged
// bootstrap transaction owner after its existing controlled DSN opener runs.
type SQLBootstrapKEKConfig struct {
	Database         reg.DatabaseIdentity
	InstallationID   string
	Mapping          reg.ReferencePin
	MappingIssuer    ed25519.PublicKey
	Generate, Unwrap ProviderCapabilityPin
	Adoption         CoverageOwnerPin
	Witnesses        []CoverageWitnessPin
}

type SQLBootstrapKEKPreparation struct{ cfg SQLBootstrapKEKConfig }

func NewSQLBootstrapKEKPreparation(cfg SQLBootstrapKEKConfig) (*SQLBootstrapKEKPreparation, error) {
	if cfg.InstallationID == "" || cfg.Database.ServerUUID == "" || cfg.Database.Database == "" || !authorityHash.MatchString(cfg.Mapping.IdentityHash) || !authorityExact(cfg.Mapping.Version) || len(cfg.MappingIssuer) != ed25519.PublicKeySize || !authoritySource(cfg.Adoption.Source) || !strings.HasPrefix(cfg.Adoption.Source.RecordID, "sev_") || len(cfg.Adoption.Issuer) != ed25519.PublicKeySize || len(cfg.Witnesses) != 16 {
		return nil, sec.ErrRegistrationUnavailable
	}
	for _, pin := range []ProviderCapabilityPin{cfg.Generate, cfg.Unwrap} {
		if !authoritySource(pin.Source) || len(pin.Issuer) != ed25519.PublicKeySize {
			return nil, sec.ErrRegistrationUnavailable
		}
	}
	if cfg.Generate.Source.RecordID == cfg.Unwrap.Source.RecordID {
		return nil, sec.ErrRegistrationUnavailable
	}
	cfg.MappingIssuer = append(ed25519.PublicKey(nil), cfg.MappingIssuer...)
	cfg.Generate.Issuer = append(ed25519.PublicKey(nil), cfg.Generate.Issuer...)
	cfg.Unwrap.Issuer = append(ed25519.PublicKey(nil), cfg.Unwrap.Issuer...)
	cfg.Adoption.Issuer = append(ed25519.PublicKey(nil), cfg.Adoption.Issuer...)
	cfg.Witnesses = append([]CoverageWitnessPin(nil), cfg.Witnesses...)
	seen := map[string]bool{}
	for i, pin := range cfg.Witnesses {
		key := coverageWitnessKey(pin.Partition, pin.Kind)
		if !coveragePartition(pin.Partition) || !coverageWitnessKind(pin.Kind) || seen[key] || !authoritySource(pin.Source) || !authorityHash.MatchString(pin.ScopeSHA256) || len(pin.Issuer) != ed25519.PublicKeySize {
			return nil, sec.ErrRegistrationUnavailable
		}
		seen[key] = true
		cfg.Witnesses[i].Issuer = append(ed25519.PublicKey(nil), pin.Issuer...)
	}
	return &SQLBootstrapKEKPreparation{cfg}, nil
}

func (p *SQLBootstrapKEKPreparation) PrepareBootstrapKEK(ctx context.Context, db *sql.DB, grant sec.OfflineBootstrapGrant, config sec.BootstrapConfig) (reg.PreparedAdmission, error) {
	if p == nil || db == nil || nilSource(ctx) || ctx.Err() != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	cfg := p.cfg
	coverage, err := NewSQLCoverageOwnerPreparation(SQLCoverageOwnerConfig{DB: db, Database: cfg.Database, InstallationID: cfg.InstallationID, Adoption: cfg.Adoption, Witnesses: cfg.Witnesses})
	if err != nil {
		return nil, err
	}
	source, err := NewSQLBootstrapAdmissionSource(SQLBootstrapSourceConfig{DB: db, Database: cfg.Database, InstallationID: cfg.InstallationID, Mapping: cfg.Mapping, MappingIssuer: cfg.MappingIssuer, Generate: cfg.Generate, Unwrap: cfg.Unwrap, Coverage: coverage})
	if err != nil {
		return nil, err
	}
	original, err := NewSQLInstallationPreparation(db, cfg.Database, cfg.InstallationID, cfg.MappingIssuer, cfg.Generate, cfg.Unwrap)
	if err != nil {
		return nil, err
	}
	return (BootstrapComposition{Source: source, Validator: KEKAdmissionValidator{Original: original, Now: original.Now}}).PrepareBootstrapKEK(ctx, db, grant, config)
}

// This optional structural contract is for D's ORIGINAL evidence-lock stage,
// before it takes the KEK fence. It performs no Commit/provider I/O or renewal.
// D can use it without importing this package (and creating a dependency cycle).
type BootstrapOriginalEvidenceAdmission interface {
	reg.PreparedAdmission
	OriginalEvidenceIDs() []string
	LockOriginalEvidence(context.Context, reg.SQLReadView) error
	OriginalCoverage() reg.PreparedCoverage
}

type bootstrapOriginalEvidenceAdmission struct {
	reg.PreparedAdmission
	coverage *SQLPreparedOriginalCoverage
}

func (p *bootstrapOriginalEvidenceAdmission) OriginalCoverage() reg.PreparedCoverage {
	return p.coverage
}
func (p *bootstrapOriginalEvidenceAdmission) OriginalEvidenceIDs() []string {
	if p == nil || p.coverage == nil {
		return nil
	}
	ids := make([]string, 0, len(p.coverage.evidence))
	for _, e := range p.coverage.evidence {
		ids = append(ids, e.pin.Source.RecordID)
	}
	return ids
}
func (p *bootstrapOriginalEvidenceAdmission) LockOriginalEvidence(ctx context.Context, view reg.SQLReadView) error {
	if p == nil || p.coverage == nil {
		return sec.ErrRegistrationUnavailable
	}
	return p.coverage.LockOriginalEvidence(ctx, view)
}

var _ sec.BootstrapKEKPreparation = (*SQLBootstrapKEKPreparation)(nil)
var _ BootstrapOriginalEvidenceAdmission = (*bootstrapOriginalEvidenceAdmission)(nil)
