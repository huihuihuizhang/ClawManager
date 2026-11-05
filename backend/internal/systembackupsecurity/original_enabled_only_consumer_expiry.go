package systembackupsecurity

import (
	"context"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
)

// Read the actual original response expiry in the same view as this private
// proof. A caller cannot provide an expiry, move the proof or renew it. This
// is a historical comparison bound; original owner/native guards still apply.
func (p *OriginalEnabledOnlyLineage) OriginalDiagnosticUntil(ctx context.Context, view reg.SQLReadView) (time.Time, error) {
	if _, e := p.AuthorizationConfigSHA256(ctx, view); e != nil {
		return time.Time{}, ErrRegistrationUnavailable
	}
	var until, now time.Time
	if view.QueryRowContext(ctx, `SELECT e.expires_at FROM system_backup_v2_operations o JOIN system_backup_v2_evidence e ON e.id=o.redacted_response_evidence_id AND e.content_checksum=o.redacted_response_sha256 WHERE o.origin_installation_id=? AND o.public_id=? AND o.operation_type='config_update' AND o.status='succeeded' AND o.result_config_version=2 AND e.owner_target_type='system' AND e.owner_target_public_id=? AND e.evidence_type='diagnostic' AND e.storage_state='inline' AND e.observed_health='healthy' AND e.encryption='none'`, p.installation, p.operation, p.installation).Scan(&until) != nil || view.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || now.Before(p.checkedAt) || until.IsZero() || !now.Before(until) || !time.Now().Before(until) || ctx.Err() != nil {
		return time.Time{}, ErrRegistrationUnavailable
	}
	return until, nil
}

func signingOwnerEnabledOnlyScope(ctx context.Context, view signingSQLView, installation string, oldVersion uint64, oldSHA string, currentVersion uint64, currentSHA string) (time.Time, error) {
	if oldVersion == currentVersion && oldSHA == currentSHA {
		return time.Time{}, nil
	}
	if oldVersion != 1 || currentVersion != 2 || oldSHA == currentSHA {
		return time.Time{}, ErrRegistrationUnavailable
	}
	actual, ok := view.(reg.SQLReadView)
	if !ok {
		return time.Time{}, ErrRegistrationUnavailable
	}
	proof, e := ReadOriginalEnabledOnlyLineage(ctx, actual, installation, oldSHA, currentVersion, currentSHA)
	if e != nil || !proof.Matches(installation, oldSHA, currentVersion, currentSHA) {
		return time.Time{}, ErrRegistrationUnavailable
	}
	authorized, e := proof.AuthorizationConfigSHA256(ctx, actual)
	if e != nil || authorized != oldSHA {
		return time.Time{}, ErrRegistrationUnavailable
	}
	return proof.OriginalDiagnosticUntil(ctx, actual)
}
