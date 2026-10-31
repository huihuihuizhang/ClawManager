package systembackupexecution

import (
	"context"
	"reflect"

	c "clawreef/internal/systembackupcontroller"
)

// The issuing native principal never enters the Job. Returned bytes are
// confidential delegated PUT capabilities, to be delivered only through an
// original task-owned immutable Secret. Never store them in public diagnostics.
// Full capture/manifest/Job preparation and independent readback remain separate
// mandatory stages; this does not create/send a Job or advance task state.
func (s *DeploymentService) issuePublicationPutGrants(ctx context.Context, claim c.ClaimToken, attempt uint64, target PublicationTargetMaterials, p PublicationUploadRequest) ([]byte, error) {
	if p.Version != publicationPresignedUploadVersion || !formalCandidateDigest(p.CandidateOwnerHMAC) {
		return nil, c.ErrExecutionAuthority
	}
	intent, err := s.beginPublicationCandidate(ctx, claim, attempt, target, p)
	if err != nil {
		return nil, err
	}
	if intent.MAC != p.CandidateOwnerHMAC {
		return nil, c.ErrExecutionRecord
	}
	access, err := s.publicationAccess(ctx, claim, attempt)
	if err != nil || access.Check(ctx) != nil {
		return nil, c.ErrExecutionAuthority
	}
	store, err := s.publicationStore(ctx)
	if err != nil {
		return nil, err
	}
	defer store.Close()
	if !reflect.DeepEqual(store.config, target) {
		return nil, c.ErrExecutionAuthority
	}
	issuer, err := store.credential(true)
	if err != nil {
		return nil, err
	}
	// Explicit new delegation is bounded by this original current publisher
	// use window. It does not adopt a new claim or renew any old DEK/context.
	bounded := issuer
	if access.ValidUntil().Before(bounded.Until) {
		bounded.Until = access.ValidUntil()
	}
	raw, err := makePublicationPutGrantSet(ctx, p, bounded)
	if err != nil {
		return nil, err
	}
	accepted := false
	defer func() {
		if !accepted {
			clear(raw)
		}
	}()
	current, err := store.credential(true)
	if err != nil || current != issuer {
		return nil, c.ErrExecutionAuthority
	}
	if err = access.Check(ctx); err != nil {
		return nil, err
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	guard, err := access.Bind(ctx, tx)
	if err != nil {
		return nil, err
	}
	if err = s.checkPublicationTargetTx(ctx, tx, guard.Facts(), target); err != nil {
		return nil, err
	}
	var rowVersion uint64
	var mac, checksum, keyVersion, lifecycle string
	var bytes int64
	if err = tx.QueryRowContext(ctx, "SELECT row_version,owner_marker_hmac,candidate_checksum_sha256,candidate_length_bytes,owner_marker_key_version,lifecycle FROM system_backup_v2_staging_resources WHERE public_id=? AND origin_installation_id=? AND backup_public_id=? AND attempt_no=? AND phase='publish' AND phase_uid=? AND resource_type='remote_manifest_candidate' AND location_sha256=? FOR SHARE", intent.owner.Resource, intent.owner.Installation, intent.owner.Task, intent.owner.Attempt, intent.owner.PhaseUID, hash([]byte(intent.owner.Location))).Scan(&rowVersion, &mac, &checksum, &bytes, &keyVersion, &lifecycle); err != nil || rowVersion != intent.RowVersion || mac != intent.MAC || checksum != intent.Checksum || bytes != intent.Bytes || keyVersion != intent.owner.KeyVersion || lifecycle != "creating" {
		return nil, c.ErrExecutionRecord
	}
	if err = guard.RecheckTx(ctx, tx); err != nil {
		return nil, err
	}
	accepted = true
	return raw, nil
}
