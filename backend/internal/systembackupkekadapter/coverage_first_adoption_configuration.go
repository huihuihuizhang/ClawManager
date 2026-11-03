package systembackupkekadapter

import (
	"crypto/ed25519"

	sec "clawreef/internal/systembackupsecurity"
)

// FirstAdoptionConfiguration exposes detached constructor-fixed source pins
// for the original transaction owner. It does not read already-adopted
// coverage, authorize a task, or invent KEK mapping/provider capabilities.
func (s *SQLCoverageOwnerPreparation) FirstAdoptionConfiguration() (SQLCoverageOwnerConfig, error) {
	if s == nil {
		return SQLCoverageOwnerConfig{}, sec.ErrRegistrationUnavailable
	}
	cfg := s.cfg
	cfg.Adoption.Issuer = append(ed25519.PublicKey(nil), cfg.Adoption.Issuer...)
	cfg.Witnesses = append([]CoverageWitnessPin(nil), cfg.Witnesses...)
	for i := range cfg.Witnesses {
		cfg.Witnesses[i].Issuer = append(ed25519.PublicKey(nil), cfg.Witnesses[i].Issuer...)
	}
	if _, err := NewSQLCoverageOwnerPreparation(cfg); err != nil {
		return SQLCoverageOwnerConfig{}, err
	}
	return cfg, nil
}
