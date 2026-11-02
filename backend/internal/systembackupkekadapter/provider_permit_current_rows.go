package systembackupkekadapter

import (
	"context"
	"database/sql"
	"reflect"

	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	reg "clawreef/internal/systembackupkekregistry"
	kms "clawreef/internal/systembackupkms"
)

// Private proof of ORIGINAL ordered row-lock acquisition, never row data or
// authority. Constructed only after the first complete sequential recheck in
// Stage succeeds. Later reads still fetch CURRENT full rows, including this
// transaction's own changes. No initial lock acquisition uses the joined read.
type heldProviderPermitRows struct {
	ctx        context.Context
	tx         *sql.Tx
	issue      *PreparedProviderPermitIssue
	guard      *c.ExecutionAuthorityGuard
	authority  d.Authority
	capability *sqlPreparedCapability
	source     reg.SourceRecord
	mapping    reg.ReferencePin
}

const heldProviderPermitRowsQuery = `SELECT e.inline_payload,e.content_checksum,e.content_size_bytes,e.expires_at,m.signed_record,m.signature
FROM system_backup_v2_evidence e
JOIN system_backup_installation_kek_authority m ON m.installation_id=? AND m.identity_hash=? AND m.registry_version=?
WHERE e.public_id=? AND e.owner_target_type='system' AND e.owner_target_public_id=? AND e.evidence_type='capability_snapshot' AND e.storage_state='inline' AND e.observed_health='healthy' AND e.encryption='none' FOR SHARE`

func (r *heldProviderPermitRows) read(ctx context.Context, tx *sql.Tx, issue *PreparedProviderPermitIssue, guard *c.ExecutionAuthorityGuard) (capabilityEvidence, []byte, []byte, error) {
	bad := func() (capabilityEvidence, []byte, []byte, error) {
		return capabilityEvidence{}, nil, nil, kms.ErrPermission
	}
	if r == nil || ctx == nil || !reflect.TypeOf(ctx).Comparable() || ctx != r.ctx || ctx.Err() != nil || tx == nil || tx != r.tx || issue == nil || issue != r.issue || issue.issuer == nil || guard == nil || guard != r.guard || issue.scope.Input.Authority != r.authority || issue.capability == nil || issue.capability != r.capability || issue.capability.pin.Source != r.source || issue.issuer.cfg.Binding.ConfigRef != r.mapping {
		return bad()
	}
	var evidence capabilityEvidence
	var checksum string
	var size uint64
	var raw, signature []byte
	// Both exact keys are already locked in THIS tx in the original order.
	// Thus optimizer join order cannot introduce a new earlier lock. Never
	// reuse returned bytes at the next callback or after this transaction.
	err := tx.QueryRowContext(ctx, heldProviderPermitRowsQuery, r.authority.InstallationID, r.mapping.IdentityHash, r.mapping.Version, r.source.RecordID, r.authority.InstallationID).Scan(&evidence.raw, &checksum, &size, &evidence.until, &raw, &signature)
	if err != nil || validateCapabilityEvidenceRow(evidence, checksum, size) != nil {
		return bad()
	}
	return evidence, raw, signature, nil
}
