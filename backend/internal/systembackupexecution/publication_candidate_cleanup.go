package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"time"

	c "clawreef/internal/systembackupcontroller"
	"github.com/google/uuid"
)

// Private same-flow deletion gate. It binds the acknowledged original104
// deleting state, exact uploaded version and already persisted actual exits.
// A prepared intent or this partial cleanup is never acceptance evidence.
type publicationCandidateCleanup struct {
	exit     *publicationUploadExit
	store    *nativePublicationS3
	resource publicationCandidateIntent
	object   ArtifactReadObject
	deadline time.Time
	deleted  bool
}

func (p *publicationCandidateCleanup) recheckPredecessorsTx(ctx context.Context, tx *sql.Tx) error {
	if p == nil || p.exit == nil || p.store == nil || tx == nil || p.exit.marker.receipt == nil || p.exit.marker.receipt.postManifestMarker == nil {
		return c.ErrExecutionAuthority
	}
	e := p.exit
	parent := e.marker.receipt.postManifestMarker
	completed := parent.completion
	if completed == nil || completed.receipt == nil || completed.receipt.access == nil || e.service == nil || e.marker.receipt.access == nil || completed.service != e.service || completed.claim != e.claim || completed.attempt != e.attempt || completed.target != p.store.config || parent.claim != e.claim || parent.attempt != e.attempt || e.marker.receipt.target != p.store.config || completed.uploaded == nil || completed.uploaded.Candidate != p.object || !originalCandidateDeleteObject(p.store.config, e.claim.Target.PublicID, e.attempt, p.object) || p.store.config.DeleteIdentityHash == "" || p.deadline.IsZero() || p.deadline.After(parent.intent.Deadline) {
		return c.ErrExecutionAuthority
	}
	if err := e.marker.recheckPublicationReceiptTx(ctx, tx, e.claim); err != nil {
		return err
	}
	if err := parent.manifest.recheckPublicationReceiptTx(ctx, tx, e.claim); err != nil {
		return err
	}
	guard, err := e.marker.receipt.access.Bind(ctx, tx)
	if err != nil {
		return err
	}
	if guard.Facts().Status != "publishing" {
		return c.ErrExecutionAuthority
	}
	if err = e.service.checkPublicationTargetTx(ctx, tx, guard.Facts(), p.store.config); err != nil {
		return err
	}
	if err = checkOriginalPublicationReferencesTx(ctx, tx, guard.Facts(), publicationConfigReference{"artifact_delete", p.store.config.DeleteIdentityHash, p.store.config.DeleteRefVersion}); err != nil {
		return err
	}
	limits, err := readPublicationLimitsTx(ctx, tx, guard)
	if err != nil || limits != completed.receipt.limits {
		return c.ErrExecutionAuthority
	}
	known, err := readOriginalCaptureCertificateBytes(ctx, tx, completed.capture)
	if err != nil || !bytes.Equal(known, completed.certificate.bytes) {
		return c.ErrExecutionRecord
	}
	if err = completed.recheckUploadedProvenanceTx(ctx, tx); err != nil {
		return err
	}
	if err = e.readStopProofsTx(ctx, tx, false); err != nil {
		return err
	}
	if err = parent.recheckClockTx(ctx, tx); err != nil {
		return err
	}
	if !completed.clockFloor.Before(p.deadline) {
		return c.ErrExecutionAuthority
	}
	return guard.RecheckTx(ctx, tx)
}

func (p *publicationCandidateCleanup) loadCandidateTx(ctx context.Context, tx *sql.Tx, state string) error {
	e := p.exit
	completed := e.marker.receipt.postManifestMarker.completion
	var resource publicationCandidateIntent
	resource.owner = originalStageOwner{Schema: "system-backup-original-stage-owner.v1", Installation: p.store.config.InstallationID, Task: e.claim.Target.PublicID, Phase: "publish", Attempt: e.attempt, ConfigVersion: completed.capture.Input.ConfigVersion, ConfigSHA256: completed.capture.Input.ConfigSHA256}
	var locationSHA, result, failure string
	var immutable sql.NullString
	var owner sql.NullString
	var expires sql.NullTime
	var observedName, observedUID sql.NullString
	var operation, resolutionOperation, resolutionEvidence sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT public_id,phase_uid,planned_locator,location_sha256,owner_marker_hmac,owner_marker_key_version,candidate_checksum_sha256,candidate_length_bytes,lifecycle,cleanup_result,last_failure_code,immutable_version,row_version,claim_owner,claim_expires_at,observed_name,observed_uid,cleanup_operation_id,ownership_resolution_operation_id,ownership_resolution_evidence_id FROM system_backup_v2_staging_resources WHERE origin_installation_id=? AND backup_public_id=? AND attempt_no=? AND phase='publish' AND resource_type='remote_manifest_candidate' AND public_id=? FOR UPDATE`, p.store.config.InstallationID, e.claim.Target.PublicID, e.attempt, e.material.CandidateResource).Scan(&resource.owner.Resource, &resource.owner.PhaseUID, &resource.owner.Location, &locationSHA, &resource.MAC, &resource.owner.KeyVersion, &resource.Checksum, &resource.Bytes, &resource.Lifecycle, &result, &failure, &immutable, &resource.RowVersion, &owner, &expires, &observedName, &observedUID, &operation, &resolutionOperation, &resolutionEvidence)
	location, _ := json.Marshal(struct{ Endpoint, Bucket, Key string }{p.store.config.Endpoint, p.store.config.Bucket, p.object.Key})
	if err != nil || operation.Valid || resolutionOperation.Valid || resolutionEvidence.Valid || observedUID.Valid || resource.owner.Resource != e.material.CandidateResource || resource.owner.Location != string(location) || locationSHA != hash(location) || resource.Checksum != p.object.SHA256 || resource.Bytes != p.object.Size || resource.MAC != e.material.CandidateOwnerMAC || resource.Lifecycle != state || failure != "none" {
		return c.ErrExecutionRecord
	}
	if _, err = uuid.Parse(resource.owner.KeyVersion); err != nil {
		return c.ErrExecutionRecord
	}
	if err = e.service.verifyPublicationCandidateKey(ctx, resource); err != nil {
		return err
	}
	if state == "creating" {
		// A preexisting dispatch/deletion is query-only; this fresh path cannot
		// adopt it, overwrite its version or send a second DELETE.
		if p.resource.RowVersion != 0 || result != "not_started" || immutable.Valid || owner.Valid || expires.Valid || observedName.Valid {
			return c.ErrExecutionRecord
		}
		p.resource = resource
		return nil
	}
	if state != "deleting" && state != "deleted" || observedName.Valid || p.resource.RowVersion == 0 || resource.owner != p.resource.owner || resource.RowVersion != p.resource.RowVersion || resource.MAC != p.resource.MAC || immutable.String != p.object.Version || !immutable.Valid || !owner.Valid || owner.String != e.claim.Owner || !expires.Valid || !expires.Time.Equal(p.deadline) || state == "deleting" && result != "running" || state == "deleted" && result != "succeeded" {
		return c.ErrExecutionRecord
	}
	return nil
}

func (p *publicationCandidateCleanup) recheckTx(ctx context.Context, tx *sql.Tx, state string) error {
	if err := p.recheckPredecessorsTx(ctx, tx); err != nil {
		return err
	}
	if err := p.loadCandidateTx(ctx, tx, state); err != nil {
		return err
	}
	return p.recheckPredecessorsTx(ctx, tx)
}

func (p *publicationCandidateCleanup) beginDelete(ctx context.Context) error {
	e := p.exit
	if e.marker.receipt.access.Check(ctx) != nil {
		return c.ErrExecutionAuthority
	}
	tx, err := e.service.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return errPublicationUnavailable
	}
	defer tx.Rollback()
	// Original task row serializes claim transitions before resource mutation.
	var version uint64
	if tx.QueryRowContext(ctx, `SELECT row_version FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=? FOR UPDATE`, p.store.config.InstallationID, e.claim.Target.PublicID).Scan(&version) != nil || version != e.claim.RowVersion {
		return c.ErrClaimLost
	}
	if err = p.recheckTx(ctx, tx, "creating"); err != nil {
		return err
	}
	for _, transition := range []struct{ from, to, result string }{{"creating", "sealed", "not_started"}, {"sealed", "deleting", "running"}} {
		result, err := tx.ExecContext(ctx, `UPDATE system_backup_v2_staging_resources SET lifecycle=?,cleanup_result=?,immutable_version=?,claim_owner=?,claim_expires_at=?,row_version=row_version+1 WHERE public_id=? AND origin_installation_id=? AND backup_public_id=? AND attempt_no=? AND phase='publish' AND resource_type='remote_manifest_candidate' AND lifecycle=? AND row_version=?`, transition.to, transition.result, p.object.Version, e.claim.Owner, p.deadline, p.resource.owner.Resource, p.store.config.InstallationID, e.claim.Target.PublicID, e.attempt, transition.from, p.resource.RowVersion)
		if err != nil {
			return errPublicationUnavailable
		}
		if count, err := result.RowsAffected(); err != nil || count != 1 {
			return c.ErrExecutionRecord
		}
		p.resource.RowVersion++
	}
	if err = p.recheckTx(ctx, tx, "deleting"); err != nil {
		return err
	}
	if tx.Commit() != nil || ctx.Err() != nil {
		return c.ErrExecutionCommitUnknown
	}
	return nil
}

func (p *publicationCandidateCleanup) recordDeleted(ctx context.Context) error {
	e := p.exit
	if e.marker.receipt.access.Check(ctx) != nil {
		return c.ErrExecutionAuthority
	}
	tx, err := e.service.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return errPublicationUnavailable
	}
	defer tx.Rollback()
	if err = p.recheckTx(ctx, tx, "deleting"); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE system_backup_v2_staging_resources SET lifecycle='deleted',cleanup_result='succeeded',row_version=row_version+1 WHERE public_id=? AND origin_installation_id=? AND backup_public_id=? AND attempt_no=? AND phase='publish' AND resource_type='remote_manifest_candidate' AND lifecycle='deleting' AND cleanup_result='running' AND row_version=? AND claim_owner=? AND claim_expires_at>UTC_TIMESTAMP(6) AND immutable_version=?`, p.resource.owner.Resource, p.store.config.InstallationID, e.claim.Target.PublicID, e.attempt, p.resource.RowVersion, e.claim.Owner, p.object.Version)
	if err != nil {
		return errPublicationUnavailable
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return c.ErrExecutionRecord
	}
	p.resource.RowVersion++
	if err = p.recheckTx(ctx, tx, "deleted"); err != nil {
		return err
	}
	if tx.Commit() != nil || ctx.Err() != nil {
		return c.ErrExecutionCommitUnknown
	}
	p.deleted = true
	return nil
}

func (s *DeploymentService) cleanupOriginalPublicationCandidate(ctx context.Context, claim c.ClaimToken, attempt uint64, store *nativePublicationS3, exit *publicationUploadExit) (*publicationCandidateCleanup, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || store == nil || exit == nil || exit.service != s || exit.claim != claim || exit.attempt != attempt || exit.marker.receipt == nil || exit.marker.receipt.postManifestMarker == nil || exit.marker.receipt.access == nil || store.config.DeleteIdentityHash == "" {
		return nil, c.ErrExecutionAuthority
	}
	parent := exit.marker.receipt.postManifestMarker
	if parent.completion == nil || parent.completion.uploaded == nil || store.config != parent.target {
		return nil, c.ErrExecutionAuthority
	}
	p := &publicationCandidateCleanup{exit: exit, store: store, object: parent.completion.uploaded.Candidate, deadline: parent.intent.Deadline}
	if !originalCandidateDeleteObject(store.config, claim.Target.PublicID, attempt, p.object) {
		return nil, c.ErrExecutionRecord
	}
	// Pin and validate the independent delete credential BEFORE any ledger change.
	credential, err := loadNativePublicationCredential(store.config.DeleteCredentialFile, store.config.DeleteCredentialSHA256)
	if err != nil {
		return nil, err
	}
	if credential.Until.Before(p.deadline) {
		p.deadline = credential.Until.UTC().Truncate(time.Microsecond)
	}
	if !time.Now().Before(p.deadline) {
		return nil, c.ErrExecutionAuthority
	}
	if err = exit.checkNativeStopped(ctx); err != nil {
		return nil, err
	}
	preflight, err := s.publisherVerifierDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: false})
	if err != nil {
		return nil, errPublicationUnavailable
	}
	err = p.recheckPredecessorsTx(ctx, preflight)
	rollback := preflight.Rollback()
	if err != nil {
		return nil, err
	}
	if rollback != nil {
		return nil, errPublicationUnavailable
	}
	// Full independent fixed-version readback, not the worker's PUT/HEAD hint.
	reader, err := store.candidateReadTransport(claim.Target.PublicID, attempt, p.object)
	if err != nil {
		return nil, err
	}
	action := publicationJournalAction{Key: p.object.Key, ObjectVersion: sql.NullString{String: p.object.Version, Valid: true}, Payload: parent.completion.uploaded.Manifest, PayloadSHA: p.object.SHA256, Size: p.object.Size}
	object, raw, err := readPublicationJSON(ctx, reader, action, p.deadline)
	if err != nil || object.Version != p.object.Version || !bytes.Equal(raw, parent.completion.uploaded.Manifest) {
		return nil, errPublicationUnavailable
	}
	if err = p.beginDelete(ctx); err != nil {
		return nil, err
	}
	if err = exit.checkNativeStopped(ctx); err != nil {
		return nil, err
	}
	if exit.marker.receipt.access.Check(ctx) != nil {
		return nil, c.ErrExecutionAuthority
	}
	// Exactly one request after an acknowledged original deleting intent. If its
	// ACK is lost, only the independent original-version read may resolve it.
	_ = store.deleteFixedPublicationCandidateVersion(ctx, claim.Target.PublicID, attempt, p.object, p.deadline)
	if err = store.publicationCandidateVersionAbsent(ctx, claim.Target.PublicID, attempt, p.object, p.deadline); err != nil {
		return nil, err
	}
	if err = p.recordDeleted(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

func (s *DeploymentService) completeOriginalPublicationThroughCandidateCleanup(ctx context.Context, claim *c.ClaimToken, attempt uint64, policy c.LeasePolicy, store *nativePublicationS3, capture publicationVerifiedCapture) (*publicationCandidateCleanup, error) {
	exit, err := s.completeOriginalPublicationThroughUploadExit(ctx, claim, attempt, policy, store, capture)
	if err != nil {
		return nil, err
	}
	return s.cleanupOriginalPublicationCandidate(ctx, *claim, attempt, store, exit)
}
