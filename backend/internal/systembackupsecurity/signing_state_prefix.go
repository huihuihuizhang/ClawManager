package systembackupsecurity

import (
	"context"
	"database/sql"
)

// Acquire this prefix BEFORE any original backup/evidence locks when the
// authenticated SQL signing owner is v1. This orders the enabled-only reader
// with the existing config writer (installation state -> task/evidence).
// It is not a new grant, ready bit, first-enable assertion or lineage proof.
func (a *SQLArtifactSigningAuthority) lockSigningStatePrefix(ctx context.Context, tx *sql.Tx) error {
	if a == nil || ctx == nil || ctx.Err() != nil || tx == nil || a.materialCheck == nil || a.materialCheck(ctx) != nil {
		return ErrRegistrationUnavailable
	}
	if a.grant.ConfigVersion != 1 {
		return nil
	}
	var active uint64
	if tx.QueryRowContext(ctx, "SELECT active_config_version FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR SHARE", a.binding.InstallationID).Scan(&active) != nil || active == 0 {
		return ErrRegistrationUnavailable
	}
	return nil
}

// This all-purpose entry is only for owners that will stage several purposes
// in one original transaction. A prepared record below selects its own owner.
func (s *SQLInstallationArtifactSigners) LockSigningStatePrefix(ctx context.Context, tx *sql.Tx) error {
	if s == nil || ctx == nil || ctx.Err() != nil || tx == nil {
		return ErrRegistrationUnavailable
	}
	var installation string
	var first *SQLArtifactSigningAuthority
	for _, purpose := range []string{"capture_certificate", "acceptance_record", "catalog_record"} {
		a := s.owners[purpose]
		if a == nil || a.binding.Purpose != purpose {
			return ErrRegistrationUnavailable
		}
		if installation != "" && installation != a.binding.InstallationID {
			return ErrRegistrationUnavailable
		}
		installation = a.binding.InstallationID
		if a.grant.ConfigVersion == 1 && first == nil {
			first = a
		}
	}
	if first != nil {
		return first.lockSigningStatePrefix(ctx, tx)
	}
	return nil
}
func (p *PreparedPublicationRecord) LockSigningStatePrefix(ctx context.Context, tx *sql.Tx) error {
	if p == nil || p.owner == nil {
		return ErrRegistrationUnavailable
	}
	a := p.owner.owners[p.binding.Purpose]
	if a == nil || a.task != p.task || a.binding != p.binding {
		return ErrRegistrationUnavailable
	}
	return a.lockSigningStatePrefix(ctx, tx)
}
func (p *SQLPreparedPublicationRecord) SigningInstallationID() (string, error) {
	if p == nil || p.task == nil || p.task.signers == nil || p.record == nil || p.record.owner != p.task.signers {
		return "", ErrRegistrationUnavailable
	}
	a := p.task.signers.owners[p.record.binding.Purpose]
	if a == nil || a.task != p.record.task || a.binding != p.record.binding || a.binding.InstallationID == "" {
		return "", ErrRegistrationUnavailable
	}
	return a.binding.InstallationID, nil
}
func (p *SQLPreparedPublicationRecord) LockSigningStatePrefix(ctx context.Context, tx *sql.Tx) error {
	if _, e := p.SigningInstallationID(); e != nil || p.task.factory == nil || p.task.factory.local() != nil {
		return ErrRegistrationUnavailable
	}
	return p.record.LockSigningStatePrefix(ctx, tx)
}
