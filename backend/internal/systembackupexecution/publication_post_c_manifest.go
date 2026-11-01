package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
)

// Private post-C gate. Public uploaded DATA never constructs a C receipt or
// authorizes 102. The only production constructor below runs the real verifier.
type publicationPostCManifest struct {
	service        *DeploymentService
	claim          c.ClaimToken
	attempt        uint64
	target         PublicationTargetMaterials
	capture        publicationVerifiedCapture
	objects        publicationRemoteContainerObjects
	receipt        *publicationRemoteContainerReceipt
	uploaded       *publicationUploadedCaptureData
	materialSHA256 string
	uploadSnapshot publicationPostCUploadSnapshot
	intent         publicationJSONIntent
	certificate    originalPublicationCaptureCertificate
	clockFloor     time.Time
}

// Inert immutable upload provenance, frozen while its original claim is live.
// It cannot authorize C, claim adoption, a send or reopening private material.
type publicationPostCUploadSnapshot struct {
	claim          c.ClaimToken
	materialSHA256 string
	resultsSHA256  [16]string
	processSHA256  string
}

func originalPostCUploadResultPin(raw []byte, sequence uint64, data *publicationUploadedCaptureData) (string, error) {
	if data == nil || sequence < 1 || sequence > 16 || !formalCandidateDigest(data.ResultBodySHA256[sequence-1]) || hash(raw) != data.ResultBodySHA256[sequence-1] {
		return "", c.ErrExecutionRecord
	}
	return data.ResultBodySHA256[sequence-1], nil
}

func decodeOriginalPostCUploadResult(raw []byte, sequence uint64, snapshot publicationPostCUploadSnapshot) (publicationResultMessage, error) {
	var message publicationResultMessage
	if sequence < 1 || sequence > 16 || !formalCandidateDigest(snapshot.resultsSHA256[sequence-1]) || hash(raw) != snapshot.resultsSHA256[sequence-1] || decodeProviderDeploymentJSON(raw, &message) != nil {
		return message, c.ErrExecutionRecord
	}
	canonical, err := ce.Canonical(message)
	if err != nil || !bytes.Equal(canonical, raw) || message.Sequence != sequence {
		return publicationResultMessage{}, c.ErrExecutionRecord
	}
	return message, nil
}

func (s *DeploymentService) snapshotOriginalPostCUpload(ctx context.Context, claim c.ClaimToken, attempt uint64, target PublicationTargetMaterials, original publicationMaterialIntent, data *publicationUploadedCaptureData) (publicationPostCUploadSnapshot, error) {
	var zero publicationPostCUploadSnapshot
	if original.Claim != claim || data == nil || original.RequestSHA256 != data.RequestSHA256 || !formalCandidateDigest(data.ProcessSHA256) {
		return zero, c.ErrClaimLost
	}
	raw, err := ce.Canonical(original)
	if err != nil {
		return zero, c.ErrExecutionRecord
	}
	snapshot := publicationPostCUploadSnapshot{claim: claim, materialSHA256: hash(raw), processSHA256: data.ProcessSHA256}
	access, err := s.publicationAccess(ctx, claim, attempt)
	if err != nil || access.Check(ctx) != nil {
		return zero, c.ErrExecutionAuthority
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return zero, err
	}
	defer tx.Rollback()
	guard, err := access.Bind(ctx, tx)
	if err != nil {
		return zero, err
	}
	if err = s.checkPublicationTargetTx(ctx, tx, guard.Facts(), target); err != nil {
		return zero, err
	}
	for seq := uint64(1); seq <= 16; seq++ {
		raw, err := loadPublicationMetadata(ctx, tx, claim.Target.PublicID, publicationResultID(original, seq))
		if err != nil {
			return zero, err
		}
		pin, err := originalPostCUploadResultPin(raw, seq, data)
		if err != nil {
			return zero, err
		}
		snapshot.resultsSHA256[seq-1] = pin
	}
	p := &publicationPostCManifest{service: s, claim: claim, attempt: attempt, target: target, uploaded: data, materialSHA256: snapshot.materialSHA256, uploadSnapshot: snapshot}
	if err = p.recheckUploadedTx(ctx, tx); err != nil {
		return zero, err
	}
	if err = guard.RecheckTx(ctx, tx); err != nil {
		return zero, err
	}
	if err = tx.Rollback(); err != nil {
		return zero, err
	}
	return snapshot, nil
}

// Content selection only, with independent copies. This does not authenticate
// the manifest, uploaded results or C; the production owner checks them below.
func originalPostCManifestData(capture publicationVerifiedCapture, target PublicationTargetMaterials, data *publicationUploadedCaptureData) (*publicationUploadedCaptureData, publicationRemoteContainerObjects, error) {
	var zero publicationRemoteContainerObjects
	if data == nil || !capture.checked() || capture.DescriptionSHA256 == "" || len(data.Objects) != 15 || !formalCandidateDigest(data.RequestSHA256) || data.JobUID == "" || data.JobGeneration < 1 || len(data.Manifest) < 2 || len(data.Manifest) > 262144 || len(data.Index) < 2 || int64(len(data.Index)) > MaxPublicationIndexBytes || len(data.Certificate) < 2 || len(data.Certificate) > 16<<10 || len(data.Bootstrap) < 2 || len(data.Bootstrap) > 3*(64<<10)+4096 || target.InstallationID != capture.Input.InstallationID {
		return nil, zero, c.ErrExecutionRecord
	}
	for _, pin := range data.ResultBodySHA256 {
		if !formalCandidateDigest(pin) {
			return nil, zero, c.ErrExecutionRecord
		}
	}
	owned := &publicationUploadedCaptureData{RequestSHA256: data.RequestSHA256, JobUID: data.JobUID, JobGeneration: data.JobGeneration, Manifest: bytes.Clone(data.Manifest), Index: bytes.Clone(data.Index), Certificate: bytes.Clone(data.Certificate), Bootstrap: bytes.Clone(data.Bootstrap), Objects: make(map[string]ArtifactReadObject, 15), Candidate: data.Candidate, ResultBodySHA256: data.ResultBodySHA256}
	owned.ProcessSHA256 = data.ProcessSHA256
	m, err := decodePublicationManifestV12(owned.Manifest)
	if err != nil || m.Installation != capture.Input.InstallationID || m.Backup != capture.Input.TaskPublicID || m.Attempt != capture.Input.CaptureAttemptNo || m.Config.Version != capture.Input.ConfigVersion || m.Config.SHA256 != capture.Input.ConfigSHA256 || m.CaptureContext != capture.CaptureContextSHA256 {
		return nil, zero, c.ErrExecutionRecord
	}
	base := target.Root + m.Backup + "/" + strconv.FormatUint(m.Attempt, 10) + "/"
	objects := publicationRemoteContainerObjects{Containers: map[string]ArtifactReadObject{}, Control: map[string]ArtifactReadObject{}, Metadata: map[string]ArtifactReadObject{}}
	request := PublicationUploadRequest{Version: publicationPresignedUploadVersion, Installation: m.Installation, Backup: m.Backup, Attempt: m.Attempt, ManifestInput: owned.Manifest, IndexBytes: owned.Index, CaptureCertificate: owned.Certificate, CaptureBootstrap: owned.Bootstrap}
	for path, object := range data.Objects {
		if object.Key != base+path || object.Version == "" || object.Version == "null" || object.Version == "latest" || len(object.Version) > 256 || strings.ContainsAny(object.Version, "\x00\r\n") || object.Size < 1 || !formalCandidateDigest(object.SHA256) {
			return nil, zero, c.ErrExecutionRecord
		}
		owned.Objects[path] = object
		request.Objects = append(request.Objects, PublicationUploadInput{Path: path, SHA256: object.SHA256, Bytes: object.Size})
		if isPublicationContainerObject(path) {
			matched := false
			for _, part := range publicationRequestedParts {
				if path == "parts/"+part+"/container.enc" {
					objects.Containers[part] = object
					matched = true
					break
				}
			}
			if !matched {
				return nil, zero, c.ErrExecutionRecord
			}
		} else if path == "artifact-index.json" || path == publicationCaptureCertificatePath || path == remoteCaptureBootstrapPath {
			objects.Metadata[path] = object
		} else {
			objects.Control[path] = object
		}
	}
	if len(objects.Containers) != 6 || len(objects.Control) != 6 || len(objects.Metadata) != 3 || validatePublicationContainerManifestInput(request, owned.Manifest) != nil {
		return nil, zero, c.ErrExecutionRecord
	}
	if owned.Candidate.Key != target.RemoteStagingRoot+m.Backup+"/"+strconv.FormatUint(m.Attempt, 10)+"/manifest-candidate.json" || target.RemoteStagingRoot == "" || owned.Candidate.Version == "" || owned.Candidate.Version == "null" || owned.Candidate.Version == "latest" || len(owned.Candidate.Version) > 256 || strings.ContainsAny(owned.Candidate.Version, "\x00\r\n") || owned.Candidate.SHA256 != hash(owned.Manifest) || owned.Candidate.Size != int64(len(owned.Manifest)) {
		return nil, zero, c.ErrExecutionRecord
	}
	return owned, objects, nil
}

func (r *publicationRemoteContainerReceipt) recheckTx(ctx context.Context, tx *sql.Tx, s *DeploymentService, claim c.ClaimToken, attempt uint64, target PublicationTargetMaterials, capture publicationVerifiedCapture, objects publicationRemoteContainerObjects) error {
	if r == nil || tx == nil || ctx == nil || ctx.Err() != nil || r.service != s || r.access == nil || r.claim != claim || r.attempt != attempt || r.target != target || !r.checked(capture, objects) {
		return c.ErrExecutionAuthority
	}
	guard, err := r.access.Bind(ctx, tx)
	if err != nil {
		return err
	}
	facts := guard.Facts()
	if facts.InstallationID != capture.Input.InstallationID || facts.BackupPublicID != capture.Input.TaskPublicID || facts.ConfigVersion != capture.Input.ConfigVersion || facts.ConfigSHA256 != capture.Input.ConfigSHA256 || facts.CaptureAttemptNo != attempt || facts.CaptureEpoch != capture.Input.CaptureEpoch || facts.CaptureResultSHA256 != capture.CaptureResultSHA256 || s.checkPublicationTargetTx(ctx, tx, facts, target) != nil {
		return c.ErrExecutionAuthority
	}
	limits, err := readPublicationLimitsTx(ctx, tx, guard)
	if err != nil || limits != r.limits {
		return c.ErrExecutionAuthority
	}
	known, err := readOriginalCaptureCertificateBytes(ctx, tx, capture)
	certificate := objects.Metadata[publicationCaptureCertificatePath]
	if err != nil || int64(len(known)) != certificate.Size || hash(known) != certificate.SHA256 {
		return c.ErrExecutionRecord
	}
	original, err := s.readPublicationCertificateFactsTx(ctx, tx, facts, capture, nil)
	if err != nil {
		return err
	}
	// History is independently pinned, bounded local public material. No Kube,
	// provider or nested SQL call occurs inside this transaction.
	history, err := s.PublicationSigningHistory(ctx)
	if err != nil {
		return err
	}
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT UTC_TIMESTAMP(6)`).Scan(&now) != nil {
		return c.ErrExecutionAuthority
	}
	if _, err = validateOriginalPublicationCaptureCertificate(known, capture, original, now, history); err != nil {
		return err
	}
	return guard.RecheckTx(ctx, tx)
}

func postCManifestDeadline(authority time.Time, certificate originalPublicationCaptureCertificate) (time.Time, error) {
	if authority.IsZero() || certificate.expires.IsZero() {
		return time.Time{}, c.ErrExecutionAuthority
	}
	if certificate.expires.Before(authority) {
		authority = certificate.expires
	}
	return authority.UTC().Truncate(time.Microsecond), nil
}

func checkPostCManifestClock(now, floor, deadline, authority time.Time, certificate originalPublicationCaptureCertificate, capture publicationVerifiedCapture) error {
	if now.IsZero() || !floor.IsZero() && now.Before(floor) || deadline.IsZero() || authority.IsZero() || deadline.After(authority) || deadline.After(certificate.expires) || !now.Before(deadline) || !certificate.checked(capture, now) {
		return c.ErrExecutionAuthority
	}
	return nil
}

func checkPostCManifestCertificateHistory(certificate originalPublicationCaptureCertificate, task security.ArtifactSigningTask, history *security.ArtifactSigningKeyHistory) error {
	if history == nil {
		return c.ErrExecutionRecord
	}
	sum, err := history.VerifyPublicationRecord(certificate.bytes, task, "capture_certificate")
	if err != nil || sum != certificate.sha256 {
		return c.ErrExecutionRecord
	}
	return nil
}

// Also called AFTER the original task's publishing transition and immediately
// before commit. The bound pre-transition C authority is never silently rebound
// to a different status: its fixed deadline remains the upper clock bound.
func (p *publicationPostCManifest) recheckClockTx(ctx context.Context, tx *sql.Tx) error {
	if p == nil || tx == nil || p.receipt == nil || p.receipt.access == nil {
		return c.ErrExecutionAuthority
	}
	history, err := p.service.PublicationSigningHistory(ctx)
	if err != nil {
		return err
	}
	if err = checkPostCManifestCertificateHistory(p.certificate, security.ArtifactSigningTask{BackupPublicID: p.claim.Target.PublicID, AttemptNo: int64(p.attempt)}, history); err != nil {
		return err
	}
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT UTC_TIMESTAMP(6)`).Scan(&now) != nil {
		return c.ErrExecutionAuthority
	}
	if err = checkPostCManifestClock(now, p.clockFloor, p.intent.Deadline, p.receipt.access.ValidUntil(), p.certificate, p.capture); err != nil {
		return err
	}
	p.clockFloor = now
	return nil
}

// Read ORIGINAL immutable transport provenance in the same 102 transaction.
// The old upload intent is historical DATA here, never a renewed upload grant.
// No Secret/Kube/provider operation and no old deadline refresh occurs here.
func (p *publicationPostCManifest) recheckUploadedProvenanceTx(ctx context.Context, tx *sql.Tx) error {
	raw, err := loadPublicationMetadata(ctx, tx, p.claim.Target.PublicID, publicationMaterialID(p.target.InstallationID, p.claim.Target.PublicID, p.attempt))
	var material publicationMaterialIntent
	if err != nil || hash(raw) != p.materialSHA256 || p.materialSHA256 != p.uploadSnapshot.materialSHA256 || decodeProviderDeploymentJSON(raw, &material) != nil || material.Version != "system-backup-original-publication-materials.v1" || material.Installation != p.target.InstallationID || material.Backup != p.claim.Target.PublicID || material.Attempt != p.attempt || material.Namespace != p.service.Config.Namespace || material.RequestSHA256 != p.uploaded.RequestSHA256 || material.Claim != p.uploadSnapshot.claim || material.Claim.Target != p.claim.Target || material.Claim.Owner != p.claim.Owner || material.Claim.RowVersion == 0 || material.Claim.RowVersion > p.claim.RowVersion {
		return c.ErrExecutionRecord
	}
	activation, err := p.service.loadPublicationActivationTx(ctx, tx, material)
	if err != nil || activation == nil || activation.JobUID != p.uploaded.JobUID || activation.AfterGeneration != p.uploaded.JobGeneration {
		return c.ErrExecutionRecord
	}
	process, processRaw, err := loadPublicationProcessTx(ctx, tx, material, *activation)
	if err != nil || !formalCandidateDigest(p.uploadSnapshot.processSHA256) || hash(processRaw) != p.uploadSnapshot.processSHA256 || p.uploaded.ProcessSHA256 != p.uploadSnapshot.processSHA256 || p.service.Config.PublicationWorker == nil || process.ServiceAccountUID != p.service.Config.PublicationWorker.ServiceAccountUID || process.NodeUID != p.service.Config.Security.NodeUIDs[process.Pod.Node] {
		return c.ErrExecutionRecord
	}
	cursor, err := scanPublicationUploadCursor(tx.QueryRowContext(ctx, `SELECT last_accepted_sequence,last_observed_status,last_accepted_body_sha256 FROM system_backup_v2_job_observations WHERE origin_installation_id=? AND target_type='backup' AND target_public_id=? AND attempt_no=? AND phase='publish' AND job_unit_key='artifact-upload' AND job_uid=? AND job_generation=? FOR SHARE`, material.Installation, material.Backup, material.Attempt, activation.JobUID, activation.AfterGeneration), 16)
	if err != nil || cursor.Sequence != 16 {
		return c.ErrExecutionRecord
	}
	seen := map[string]bool{}
	for sequence := uint64(1); sequence <= 16; sequence++ {
		raw, err := loadPublicationMetadata(ctx, tx, material.Backup, publicationResultID(material, sequence))
		if err != nil {
			return c.ErrExecutionRecord
		}
		message, err := decodeOriginalPostCUploadResult(raw, sequence, p.uploadSnapshot)
		if err != nil || message.Version != publicationResultVersion || message.Installation != material.Installation || message.Backup != material.Backup || message.Attempt != material.Attempt || message.RequestSHA256 != p.uploaded.RequestSHA256 || seen[message.Object.Key] || sequence == 16 && !cursor.matchesLastBody(raw) {
			return c.ErrExecutionRecord
		}
		actual := ArtifactReadObject{Key: message.Object.Key, Version: message.Object.Version, SHA256: message.Object.SHA256, Size: message.Object.Bytes}
		matched := actual == p.uploaded.Candidate && sequence == 16
		if sequence < 16 {
			for _, expected := range p.uploaded.Objects {
				if actual == expected {
					matched = true
					break
				}
			}
		}
		if !matched {
			return c.ErrExecutionRecord
		}
		seen[actual.Key] = true
	}
	return nil
}

func (p *publicationPostCManifest) recheckUploadedTx(ctx context.Context, tx *sql.Tx) error {
	if err := p.recheckUploadedProvenanceTx(ctx, tx); err != nil {
		return err
	}
	raw, err := loadPublicationMetadata(ctx, tx, p.claim.Target.PublicID, publicationMaterialID(p.target.InstallationID, p.claim.Target.PublicID, p.attempt))
	var material publicationMaterialIntent
	if err != nil || hash(raw) != p.materialSHA256 || decodeProviderDeploymentJSON(raw, &material) != nil {
		return c.ErrExecutionRecord
	}
	var locator, checksum, mac, lifecycle string
	var size int64
	err = tx.QueryRowContext(ctx, `SELECT planned_locator,candidate_checksum_sha256,candidate_length_bytes,owner_marker_hmac,lifecycle FROM system_backup_v2_staging_resources WHERE origin_installation_id=? AND backup_public_id=? AND attempt_no=? AND phase='publish' AND resource_type='remote_manifest_candidate' AND public_id=? FOR SHARE`, material.Installation, material.Backup, material.Attempt, material.CandidateResource).Scan(&locator, &checksum, &size, &mac, &lifecycle)
	location, locationErr := json.Marshal(struct{ Endpoint, Bucket, Key string }{p.target.Endpoint, p.target.Bucket, p.uploaded.Candidate.Key})
	if err != nil || locationErr != nil || locator != string(location) || checksum != hash(p.uploaded.Manifest) || size != int64(len(p.uploaded.Manifest)) || mac != material.CandidateOwnerMAC || !formalCandidateDigest(mac) || lifecycle != "creating" {
		return c.ErrExecutionRecord
	}
	return nil
}

func (p *publicationPostCManifest) recheckTx(ctx context.Context, tx *sql.Tx, s *DeploymentService, claim c.ClaimToken, attempt uint64, target PublicationTargetMaterials, intent publicationJSONIntent) error {
	if p == nil || p.service != s || p.claim != claim || p.attempt != attempt || p.target != target || p.uploaded == nil || intent.Kind != "manifest_put" || intent.Key != p.intent.Key || !intent.Deadline.Equal(p.intent.Deadline) || !bytes.Equal(intent.Payload, p.intent.Payload) || !bytes.Equal(intent.Payload, p.uploaded.Manifest) {
		return c.ErrExecutionAuthority
	}
	if err := p.receipt.recheckTx(ctx, tx, s, claim, attempt, target, p.capture, p.objects); err != nil {
		return err
	}
	if err := p.recheckUploadedTx(ctx, tx); err != nil {
		return err
	}
	if err := p.receipt.recheckTx(ctx, tx, s, claim, attempt, target, p.capture, p.objects); err != nil {
		return err
	}
	return p.recheckClockTx(ctx, tx)
}

// A's caller supplies uploaded DATA and the real independent verifier's private
// receipt. This production segment consumes it in 102's original one-send
// transaction, with current authority and original registered input rechecks.
// It stops at confirmed manifest; marker/cleanup/acceptance/catalog are later.
func (s *DeploymentService) publishOriginalManifestAfterRemoteCapture(ctx context.Context, claim c.ClaimToken, attempt uint64, store *nativePublicationS3, capture publicationVerifiedCapture, objects publicationRemoteContainerObjects, receipt *publicationRemoteContainerReceipt, data *publicationUploadedCaptureData, snapshot publicationPostCUploadSnapshot) (nativePublicationObject, error) {
	var zero nativePublicationObject
	if s == nil || store == nil || ctx == nil || ctx.Err() != nil || receipt == nil || receipt.service != s || receipt.claim != claim || receipt.attempt != attempt || receipt.target != store.config || receipt.access == nil || !receipt.checked(capture, objects) || !formalCandidateDigest(snapshot.materialSHA256) {
		return zero, c.ErrExecutionAuthority
	}
	owned, selected, err := originalPostCManifestData(capture, store.config, data)
	if err != nil {
		return zero, err
	}
	if !receipt.checked(capture, selected) || receipt.access.Check(ctx) != nil {
		return zero, c.ErrExecutionAuthority
	}
	certificate, known, err := s.loadOriginalPublicationCaptureCertificate(ctx, claim, attempt, capture)
	if err != nil || !known || certificate.sha256 != hash(owned.Certificate) || !bytes.Equal(certificate.bytes, owned.Certificate) {
		return zero, c.ErrExecutionRecord
	}
	// The final 102 deadline is bounded by THIS C authority, not by reissuing
	// or extending any old upload/provider/DEK permission.
	until, err := postCManifestDeadline(receipt.access.ValidUntil(), certificate)
	if err != nil {
		return zero, err
	}
	p := &publicationPostCManifest{service: s, claim: claim, attempt: attempt, target: store.config, capture: capture, objects: selected, receipt: receipt, uploaded: owned, materialSHA256: snapshot.materialSHA256, uploadSnapshot: snapshot, certificate: certificate, intent: publicationJSONIntent{Kind: "manifest_put", Key: store.config.Root + claim.Target.PublicID + "/" + strconv.FormatUint(attempt, 10) + "/manifest.json", Payload: bytes.Clone(owned.Manifest), Deadline: until}}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return zero, err
	}
	defer tx.Rollback()
	if err = receipt.recheckTx(ctx, tx, s, claim, attempt, store.config, capture, selected); err != nil {
		return zero, err
	}
	// Immutable evidence is historical upload provenance, not permission to
	// reopen/renew old material. Current receipt authority guards this read.
	materialRaw, err := loadPublicationMetadata(ctx, tx, claim.Target.PublicID, publicationMaterialID(s.Config.InstallationID, claim.Target.PublicID, attempt))
	if err != nil || hash(materialRaw) != p.materialSHA256 {
		return zero, c.ErrExecutionRecord
	}
	if err = p.recheckTx(ctx, tx, s, claim, attempt, store.config, p.intent); err != nil {
		return zero, err
	}
	if err = tx.Rollback(); err != nil {
		return zero, err
	}
	object, err := s.publishOriginalJSONWithProof(ctx, claim, attempt, store, p.intent, nil, p)
	if err != nil {
		return zero, err
	}
	if object.receipt == nil {
		return zero, c.ErrExecutionRecord
	}
	object.receipt.postCManifest = p
	return object, nil
}

// Production bridge immediately after the original upload has completed. Read
// A's original material/results before any explicit C-stage Renew; no expired
// upload grant can be regenerated or adopted. A reopened path must independently
// rebuild its private capture facts, then perform the same complete remote C.
func (s *DeploymentService) completeOriginalPublicationUploadedManifest(ctx context.Context, claim *c.ClaimToken, attempt uint64, policy c.LeasePolicy, store *nativePublicationS3, capture publicationVerifiedCapture) (nativePublicationObject, error) {
	var zero nativePublicationObject
	if s == nil || claim == nil || store == nil || ctx == nil || ctx.Err() != nil || policy.Validate() != nil {
		return zero, c.ErrExecutionAuthority
	}
	data, err := s.readOriginalPublicationUploadedData(ctx, *claim, attempt, store.config)
	if err != nil {
		return zero, err
	}
	original, err := s.loadPublicationMaterialIntent(ctx, *claim, attempt)
	if err != nil {
		return zero, err
	}
	if original.Claim != *claim || original.RequestSHA256 != data.RequestSHA256 {
		return zero, c.ErrClaimLost
	}
	snapshot, err := s.snapshotOriginalPostCUpload(ctx, *claim, attempt, store.config, original, data)
	if err != nil {
		return zero, err
	}
	if !capture.checked() {
		capture, err = s.verifyOriginalPublicationCapture(ctx, claim, attempt, policy)
		if err != nil {
			return zero, err
		}
	}
	owned, objects, err := originalPostCManifestData(capture, store.config, data)
	if err != nil {
		return zero, err
	}
	receipt, err := s.verifyOriginalRemoteContainerCapture(ctx, claim, attempt, policy, store.config, capture, objects)
	if err != nil {
		return zero, err
	}
	return s.publishOriginalManifestAfterRemoteCapture(ctx, *claim, attempt, store, capture, objects, receipt, owned, snapshot)
}
