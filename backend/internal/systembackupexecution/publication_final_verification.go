package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"time"

	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/staging"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	pc "clawreef/internal/systembackuppartcontainer"
	security "clawreef/internal/systembackupsecurity"
)

func finalVerificationFrozenSource(raw []byte, sha string) (b.SourceInventory, error) {
	var source b.SourceInventory
	if len(raw) == 0 || len(raw) > 8<<20 || !formalCandidateDigest(sha) || hash(raw) != sha || decodeMetadataCanonical(raw, &source) != nil || source.Teams == nil || source.Skills == nil {
		return b.SourceInventory{}, c.ErrExecutionRecord
	}
	users, owners := map[int]bool{}, map[int]int{}
	for _, id := range source.Users {
		if id < 1 || users[id] {
			return b.SourceInventory{}, c.ErrExecutionRecord
		}
		users[id] = true
	}
	for _, instance := range source.Instances {
		if instance.ID < 1 || owners[instance.ID] != 0 || !users[instance.UserID] {
			return b.SourceInventory{}, c.ErrExecutionRecord
		}
		owners[instance.ID] = instance.UserID
	}
	if source.Teams.Validate(users, owners) != nil || source.Skills.Validate(users, owners) != nil {
		return b.SourceInventory{}, c.ErrExecutionRecord
	}
	return source, nil
}

// Concrete current record/source joins, not a caller "covered" flag. Existing
// inert domain readers still verify the actual authenticated SQL/object bytes.
func finalVerificationMemberSource(source b.SourceInventory, part publicationVerifiedPart, record c.PublisherCaptureRecord) error {
	if source.Teams == nil || source.Skills == nil {
		return c.ErrExecutionRecord
	}
	r := record.Invocation.Request
	if part.Part == b.UsersInstancesDatabasePart {
		if part.Operation != "capture-database" || r.Database == nil || r.Database.TeamsInventory == nil || r.Database.SkillsInventory == nil || r.Database.TeamsInventory.SHA256() != source.Teams.SHA256() || r.Database.SkillsInventory.SHA256() != source.Skills.SHA256() || r.Database.Name != source.Database || r.Database.ServerUUID != source.ServerUUID {
			return c.ErrExecutionRecord
		}
	} else if r.Database != nil {
		return c.ErrExecutionRecord
	}
	if part.Part == b.SkillObjectsPart {
		s := r.SkillObjects
		if part.Operation != "capture-skill-objects" || s == nil || s.InventorySHA256 != source.Skills.SHA256() || len(s.Blobs) != len(source.Skills.Blobs) {
			return c.ErrExecutionRecord
		}
		seen := map[int]bool{}
		wanted := map[int]struct {
			Key  string
			Size int64
		}{}
		for _, blob := range source.Skills.Blobs {
			if _, exists := wanted[blob.ID]; exists {
				return c.ErrExecutionRecord
			}
			wanted[blob.ID] = struct {
				Key  string
				Size int64
			}{blob.ObjectKey, blob.SizeBytes}
		}
		for _, blob := range s.Blobs {
			if seen[blob.ID] {
				return c.ErrExecutionRecord
			}
			seen[blob.ID] = true
			want, found := wanted[blob.ID]
			if !found || want.Key != blob.ObjectKey || want.Size != blob.SizeBytes {
				return c.ErrExecutionRecord
			}
		}
	} else if r.SkillObjects != nil {
		return c.ErrExecutionRecord
	}
	return nil
}

// Current final verification, not local acceptance, a signature or a terminal
// decision. The original cleanup claim is immutable history. This claim is the
// explicitly acquired/renewed current token and is never installed in cleanup.
type publicationFinalVerification struct {
	service                      *DeploymentService
	cleanup                      *publicationCompleteCleanup
	claim                        c.ClaimToken
	attempt                      uint64
	target                       PublicationTargetMaterials
	access                       *security.SQLPublisherCaptureAuthority
	limits                       ArtifactReadLimits
	originalSHA256               string
	verifiedSHA256               string
	manifest, marker, index      []byte
	manifestObject, markerObject ArtifactReadObject
	source                       b.SourceInventory
	skillParts                   []b.JobPart
	teamRelations                *publicationFinalTeamRelations
	sourceRecovery               *c.PublisherSourceRecovery
	contentSamples               *publicationContentSamples
}

func (p *publicationFinalVerification) contentSHA() (string, error) {
	if p == nil || p.access == nil || p.originalSHA256 == "" || len(p.manifest) == 0 || len(p.marker) == 0 || len(p.index) == 0 || hash(p.manifest) != p.manifestObject.SHA256 || hash(p.marker) != p.markerObject.SHA256 {
		return "", c.ErrExecutionAuthority
	}
	recovered, err := publicationSourceRecoveryFacts(p, p.sourceRecovery)
	if err != nil {
		return "", err
	}
	_, samplesSHA256, err := p.contentSamples.snapshot()
	if err != nil {
		return "", err
	}
	sourceRaw, err := json.Marshal(p.source)
	if err != nil || !p.cleanup.ready() || hash(sourceRaw) != p.cleanup.native.candidate.exit.marker.receipt.postManifestMarker.completion.capture.Input.SourceSHA256 {
		return "", c.ErrExecutionRecord
	}
	raw, err := ce.Canonical(struct {
		Claim                             c.ClaimToken
		Attempt                           uint64
		Target                            PublicationTargetMaterials
		Limits                            ArtifactReadLimits
		Original, Manifest, Marker, Index string
		ManifestObject, MarkerObject      ArtifactReadObject
		Source                            []byte
		Parts                             []b.JobPart
		SourceRecovery                    c.PublisherSourceRecoveryFacts
		ContentSamplesSHA256              string
	}{p.claim, p.attempt, p.target, p.limits, p.originalSHA256, hash(p.manifest), hash(p.marker), hash(p.index), p.manifestObject, p.markerObject, sourceRaw, p.skillParts, recovered, samplesSHA256})
	if err != nil {
		return "", err
	}
	return hash(raw), nil
}

// Signing/terminal consumers use THIS gate, never the pre-verification history
// reader below. The producer stamps only after authenticated Team relations
// and original Skills workspace requirements/coverage have been consumed.
func (p *publicationFinalVerification) recheckVerifiedTx(ctx context.Context, tx *sql.Tx) error {
	if p == nil || !formalCandidateDigest(p.verifiedSHA256) {
		return c.ErrExecutionAuthority
	}
	digest, err := p.contentSHA()
	if err != nil || digest != p.verifiedSHA256 {
		return c.ErrExecutionRecord
	}
	if p.teamRelations == nil || p.teamRelations.complete() != nil || b.ValidateFinalSkillWorkspaceParts(p.source, p.skillParts) != nil {
		return c.ErrExecutionRecord
	}
	if err := p.recheckTx(ctx, tx); err != nil {
		return err
	}
	return recheckPublicationSourceRecoveryTx(ctx, tx, p, p.sourceRecovery)
}

func finalVerificationOriginalSHA(cleanup *publicationCompleteCleanup) (string, error) {
	if !cleanup.ready() || cleanup.intentSHA256 == "" || cleanup.evidence.SHA256 != hash(cleanup.body) {
		return "", c.ErrExecutionAuthority
	}
	n := cleanup.native
	e := n.candidate.exit
	p := e.marker.receipt.postManifestMarker
	if p.completion.uploaded == nil || !p.completion.capture.checked() {
		return "", c.ErrExecutionRecord
	}
	seals, err := publicationLocalSealsHash(cleanup.seals)
	if err != nil || seals != cleanup.intent.SealsSHA256 {
		return "", c.ErrExecutionRecord
	}
	ref, body, err := cleanup.expectedEvidence()
	if err != nil || ref != cleanup.evidence || !bytes.Equal(body, cleanup.body) {
		return "", c.ErrExecutionRecord
	}
	raw, err := ce.Canonical(struct {
		Intent           publicationLocalCleanupIntent
		IntentSHA256     string
		Evidence         ce.EvidenceRef
		Body             []byte
		Native           publicationNativeCleanupIntent
		NativeSHA256     string
		Absent           [3]string
		CaptureSHA256    string
		Manifest, Marker ArtifactReadObject
		Objects          publicationRemoteContainerObjects
	}{cleanup.intent, cleanup.intentSHA256, ref, body, n.intent, n.intentSHA256, n.absentSHA256, p.completion.capture.receipt.sha256, ArtifactReadObject{Key: p.manifest.Key, Version: p.manifest.Version, SHA256: p.manifest.SHA256, Size: p.manifest.Size}, ArtifactReadObject{Key: e.marker.Key, Version: e.marker.Version, SHA256: e.marker.SHA256, Size: e.marker.Size}, p.completion.objects})
	if err != nil {
		return "", err
	}
	return hash(raw), nil
}

// Re-read a confirmed original action as HISTORY under the caller's new
// publisher guard. It deliberately does not invoke its old receipt's Bind.
func readFinalVerificationActionTx(ctx context.Context, tx *sql.Tx, s *DeploymentService, backup string, original nativePublicationObject) error {
	if original.receipt == nil {
		return c.ErrExecutionRecord
	}
	want := original.receipt.action
	got, err := scanPublicationAction(tx.QueryRowContext(ctx, "SELECT "+publicationActionColumns+" FROM system_backup_v2_external_actions WHERE origin_installation_id=? AND target_type='backup' AND target_public_id=? AND public_id=? FOR SHARE", s.Config.InstallationID, backup, want.ID))
	a, _ := ce.Canonical(got)
	b, _ := ce.Canonical(want)
	if err != nil || !bytes.Equal(a, b) || got.State != "confirmed_present" || !got.ObjectVersion.Valid || got.ObjectVersion.String != original.Version || !got.ObjectSHA.Valid || got.ObjectSHA.String != original.SHA256 || got.Key != original.Key || got.Size != original.Size || hash(got.Payload) != original.SHA256 {
		return c.ErrExecutionRecord
	}
	return nil
}

// No old claim authorization, old lease extension, network request or local
// seal open occurs here. The current independent publisher guard owns ALL
// these original-history reads. Expired diagnostic/evidence rows fail closed.
func (p *publicationFinalVerification) recheckTx(ctx context.Context, tx *sql.Tx) error {
	if p == nil || p.service == nil || p.access == nil || tx == nil || ctx == nil || ctx.Err() != nil {
		return c.ErrExecutionAuthority
	}
	digest, err := finalVerificationOriginalSHA(p.cleanup)
	if err != nil || digest != p.originalSHA256 {
		return c.ErrExecutionRecord
	}
	old := p.cleanup
	n := old.native
	e := n.candidate.exit
	completed := e.marker.receipt.postManifestMarker.completion
	capture := completed.capture
	if e.service != p.service || p.claim.Target.Kind != c.TargetBackup || p.claim.Target.PublicID != capture.Input.TaskPublicID || p.attempt != capture.Input.CaptureAttemptNo || p.target != completed.target {
		return c.ErrExecutionAuthority
	}
	guard, err := p.access.Bind(ctx, tx)
	if err != nil {
		return err
	}
	f := guard.Facts()
	if f.InstallationID != capture.Input.InstallationID || f.BackupPublicID != capture.Input.TaskPublicID || f.CaptureAttemptNo != p.attempt || f.CaptureEpoch != capture.Input.CaptureEpoch || f.CaptureResultSHA256 != capture.CaptureResultSHA256 || f.ConfigVersion != capture.Input.ConfigVersion || f.ConfigSHA256 != capture.Input.ConfigSHA256 || f.Status != "publishing" || p.service.checkPublicationTargetTx(ctx, tx, f, p.target) != nil {
		return c.ErrExecutionAuthority
	}
	i := old.intent
	if i.Owner.Installation != f.InstallationID || i.Owner.Task != f.BackupPublicID || i.Owner.Attempt != p.attempt || i.Claim != e.claim || i.CaptureSHA256 != capture.receipt.sha256 || i.NativeSHA256 != n.intentSHA256 || i.ManifestSHA256 != e.marker.receipt.postManifestMarker.manifest.SHA256 || i.MarkerSHA256 != e.marker.SHA256 || i.RowVersion < 1 || i.RowVersion > ^uint64(0)-3 || n.intent.Version != "system-backup-original-native-cleanup.v1" || n.intent.Claim != e.claim || n.intent.Installation != f.InstallationID || n.intent.Backup != f.BackupPublicID || n.intent.Attempt != p.attempt || n.intent.NamespaceUID != p.service.Config.NamespaceUID || n.intent.MaterialSHA256 != completed.materialSHA256 || n.intent.ProcessSHA256 != completed.uploadSnapshot.processSHA256 || n.intent.MarkerSHA256 != e.marker.SHA256 || n.intent.CandidateResource != n.candidate.resource.owner.Resource {
		return c.ErrExecutionRecord
	}
	scope := p.access.Scope()
	if scope.Claim.ControllerOwner != p.claim.Owner || scope.Claim.RowVersion != p.claim.RowVersion {
		return c.ErrClaimLost
	}
	limits, err := readPublicationLimitsTx(ctx, tx, guard)
	if err != nil || limits != p.limits {
		return c.ErrExecutionAuthority
	}
	checkMetadata := func(id string, want []byte, sha string) error {
		got, err := loadPublicationMetadata(ctx, tx, f.BackupPublicID, id)
		if err != nil || hash(got) != sha || !bytes.Equal(got, want) {
			return c.ErrExecutionRecord
		}
		return nil
	}
	raw, _ := ce.Canonical(old.intent)
	if err = checkMetadata(old.id(), raw, old.intentSHA256); err != nil {
		return err
	}
	raw, _ = ce.Canonical(n.intent)
	if err = checkMetadata(n.id(), raw, n.intentSHA256); err != nil {
		return err
	}
	for index, object := range n.intent.Objects {
		sent, _ := ce.Canonical(publicationNativeCleanupEvent{Version: "system-backup-original-native-cleanup-event.v1", IntentSHA256: n.intentSHA256, Stage: "delete_dispatched", Object: object})
		if err = checkMetadata(n.id()+"_"+object.Kind+"_sent", sent, hash(sent)); err != nil {
			return err
		}
		raw, _ = ce.Canonical(publicationNativeCleanupEvent{Version: "system-backup-original-native-cleanup-event.v1", IntentSHA256: n.intentSHA256, Stage: "confirmed_absent", Object: object})
		if err = checkMetadata(n.id()+"_"+object.Kind+"_absent", raw, n.absentSHA256[index]); err != nil {
			return err
		}
	}
	// These two helpers compare only historical rows/keys/process witnesses;
	// neither binds the old authority or adopts the new claim into old structs.
	if err = n.candidate.loadCandidateTx(ctx, tx, "deleted"); err != nil {
		return err
	}
	if err = e.readStopProofsTx(ctx, tx, false); err != nil {
		return err
	}
	if err = completed.recheckUploadedProvenanceTx(ctx, tx); err != nil {
		return err
	}
	if err = readFinalVerificationActionTx(ctx, tx, p.service, f.BackupPublicID, e.marker); err != nil {
		return err
	}
	if err = readFinalVerificationActionTx(ctx, tx, p.service, f.BackupPublicID, e.marker.receipt.postManifestMarker.manifest); err != nil {
		return err
	}
	var owner, untilOwner, phase, phaseUID, kind, location, locationSHA, mac, key, state, result, failure, name, uid string
	var until time.Time
	var version uint64
	var immutable sql.NullString
	var operation, resolution, resolutionEvidence sql.NullInt64
	// Old claim/deadline below are facts of the committed deletion, not live
	// permission. Current permission comes solely from guard above and below.
	err = tx.QueryRowContext(ctx, `SELECT origin_installation_id,claim_owner,claim_expires_at,phase,phase_uid,resource_type,planned_locator,location_sha256,owner_marker_hmac,owner_marker_key_version,lifecycle,cleanup_result,last_failure_code,observed_name,observed_uid,row_version,immutable_version,cleanup_operation_id,ownership_resolution_operation_id,ownership_resolution_evidence_id FROM system_backup_v2_staging_resources WHERE origin_installation_id=? AND backup_public_id=? AND attempt_no=? AND public_id=? FOR SHARE`, i.Owner.Installation, i.Owner.Task, i.Owner.Attempt, i.Owner.Resource).Scan(&owner, &untilOwner, &until, &phase, &phaseUID, &kind, &location, &locationSHA, &mac, &key, &state, &result, &failure, &name, &uid, &version, &immutable, &operation, &resolution, &resolutionEvidence)
	if err != nil || owner != i.Owner.Installation || untilOwner != i.Claim.Owner || !until.Equal(i.Deadline) || phase != "capture" || phaseUID != i.Owner.PhaseUID || kind != "hostpath" || location != i.Owner.Location || locationSHA != hash([]byte(location)) || mac != i.OwnerMAC || key != i.Owner.KeyVersion || state != "deleted" || result != "succeeded" || failure != "none" || name != i.Owner.Task || uid != i.Owner.Resource || version != i.RowVersion+3 || immutable.Valid || operation.Valid || resolution.Valid || resolutionEvidence.Valid {
		return c.ErrExecutionRecord
	}
	var count int
	if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_staging_resources WHERE origin_installation_id=? AND backup_public_id=? AND attempt_no=? AND phase IN ('capture','secret_capture')`, i.Owner.Installation, i.Owner.Task, i.Owner.Attempt).Scan(&count) != nil || count != 1 {
		return c.ErrExecutionRecord
	}
	var body []byte
	var sha string
	var size int
	if tx.QueryRowContext(ctx, `SELECT inline_payload,content_checksum,content_size_bytes FROM system_backup_v2_evidence WHERE origin_installation_id=? AND public_id=? AND owner_target_type='backup' AND owner_target_public_id=? AND evidence_type='cleanup_result' AND storage_state='inline' AND observed_health='healthy' AND evidence_failure_code='none' AND encryption='none' AND media_type='application/json' AND redaction_classification='internal' AND expires_at>UTC_TIMESTAMP(6) FOR SHARE`, i.Owner.Installation, old.evidence.PublicID, i.Owner.Task).Scan(&body, &sha, &size) != nil || !bytes.Equal(body, old.body) || size != len(body) || sha != old.evidence.SHA256 {
		return c.ErrExecutionRecord
	}
	// Validate the known original certificate from actual original completion,
	// TTL and deleted resource identity, without the old ready-only loader.
	var original publicationCertificateSQLFacts
	var now time.Time
	original.stage = originalStageResource{owner: i.Owner, mac: i.OwnerMAC, lifecycle: "deleted", version: version}
	original.locationHash = hash([]byte(i.Owner.Location))
	if tx.QueryRowContext(ctx, `SELECT a.finished_at,cfg.capture_certificate_ttl_seconds,UTC_TIMESTAMP(6) FROM system_backup_v2_attempts a JOIN system_backup_v2_configs cfg ON cfg.origin_installation_id=? AND cfg.version=? AND cfg.config_sha256=? WHERE a.target_type='backup' AND a.target_public_id=? AND a.attempt_no=? AND a.phase='capture' AND a.status='sealed'`, f.InstallationID, f.ConfigVersion, f.ConfigSHA256, f.BackupPublicID, p.attempt).Scan(&original.completed, &original.ttl, &now) != nil {
		return c.ErrExecutionRecord
	}
	certificate, err := readOriginalCaptureCertificateBytes(ctx, tx, capture)
	if err != nil || !bytes.Equal(certificate, completed.certificate.bytes) {
		return c.ErrExecutionRecord
	}
	history, err := p.service.PublicationSigningHistory(ctx)
	if err != nil {
		return err
	}
	validated, err := validateOriginalPublicationCaptureCertificate(certificate, capture, original, now, history)
	if err != nil || validated.sha256 != completed.certificate.sha256 {
		return c.ErrExecutionRecord
	}
	return guard.RecheckTx(ctx, tx)
}

func (p *publicationFinalVerification) checkHistory(ctx context.Context, claim c.ClaimToken) error {
	access, err := p.service.publicationAccess(ctx, claim, p.attempt)
	if err != nil {
		return err
	}
	if err = access.Check(ctx); err != nil {
		return err
	}
	p.claim, p.access = claim, access
	tx, err := p.service.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	return p.recheckTx(ctx, tx)
}

func (p *publicationFinalVerification) checkAbsence(ctx context.Context) error {
	if p == nil || !p.cleanup.ready() || p.cleanup.checkKey() != nil || p.access == nil || p.access.Check(ctx) != nil {
		return c.ErrExecutionAuthority
	}
	root := p.service.Runtime.Owner.Staging
	custody, err := openPublicationLocalCustody(root)
	if err != nil {
		return err
	}
	defer custody.Close()
	files := &publicationLocalFiles{parent: root, custody: custody}
	return staging.WithCustodyLock(ctx, custody, func() error { return p.cleanup.observeAbsent(files) })
}

// Producer for D's first-forward caller: after real local cleanup, verify the
// SAME immutable artifact under explicit current token(s). No PUT/sign/capture,
// source read, sealed-file open, readiness change or terminal update occurs.
func (s *DeploymentService) verifyOriginalPublicationFinalization(ctx context.Context, claim *c.ClaimToken, policy c.LeasePolicy, cleanup *publicationCompleteCleanup) (*publicationFinalVerification, error) {
	digest, err := finalVerificationOriginalSHA(cleanup)
	if err != nil || s == nil || claim == nil || ctx == nil || ctx.Err() != nil || policy.Validate() != nil {
		return nil, c.ErrExecutionAuthority
	}
	e := cleanup.native.candidate.exit
	completed := e.marker.receipt.postManifestMarker.completion
	capture := completed.capture
	if e.service != s || claim.Owner != s.PublisherOwner || claim.Target != e.claim.Target || claim.RowVersion <= e.claim.RowVersion {
		return nil, c.ErrExecutionAuthority
	}
	data, objects, err := originalPostCManifestData(capture, completed.target, completed.uploaded)
	if err != nil {
		return nil, err
	}
	source, err := finalVerificationFrozenSource(capture.Input.SourceSnapshot, capture.Input.SourceSHA256)
	if err != nil {
		return nil, err
	}
	teamRelations, err := newPublicationFinalTeamRelations(source)
	if err != nil {
		return nil, err
	}
	p := &publicationFinalVerification{service: s, cleanup: cleanup, claim: *claim, attempt: e.attempt, target: completed.target, originalSHA256: digest, manifest: bytes.Clone(data.Manifest), index: bytes.Clone(data.Index), manifestObject: ArtifactReadObject{Key: e.marker.receipt.postManifestMarker.manifest.Key, Version: e.marker.receipt.postManifestMarker.manifest.Version, SHA256: e.marker.receipt.postManifestMarker.manifest.SHA256, Size: e.marker.receipt.postManifestMarker.manifest.Size}, markerObject: ArtifactReadObject{Key: e.marker.Key, Version: e.marker.Version, SHA256: e.marker.SHA256, Size: e.marker.Size}}
	p.source, p.teamRelations = source, teamRelations
	p.contentSamples, err = newPublicationContentSamples(capture, source, p.target, p.manifestObject)
	if err != nil {
		return nil, err
	}
	samplesComplete := false
	defer func() {
		if !samplesComplete {
			p.contentSamples.clear()
		}
	}()
	p.limits, err = s.publicationContainerLimits(ctx, *claim, p.attempt)
	if err != nil {
		return nil, err
	}
	if err = p.checkHistory(ctx, *claim); err != nil {
		return nil, err
	}
	if err = p.checkAbsence(ctx); err != nil {
		return nil, err
	}
	reader, err := NewArtifactReadOnlyS3(artifactReadMaterials(p.target), p.limits)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	renew := func() error {
		fresh, err := (c.ClaimCoordinator{Executor: s.publisherVerifierDB, InstallationID: s.Config.InstallationID}).Renew(ctx, *claim, policy)
		if err != nil {
			return err
		}
		*claim = fresh
		// Each stage gets a NEW current authority through the real factory.
		// Original cleanup/history is immutable comparison data, checked in full
		// before and after all remote reads; it never caches authorization.
		access, err := s.remoteContainerReadScope(ctx, fresh, p.attempt, p.target, p.limits)
		if err != nil {
			return err
		}
		p.claim, p.access = fresh, access
		return nil
	}
	readExact := func(object ArtifactReadObject, want []byte) error {
		got, observed, err := reader.readVersionedBytes(ctx, object.Key, object.Version, object.SHA256, object.Size, p.access.ValidUntil())
		if err != nil || observed != object || !bytes.Equal(got, want) {
			return c.ErrExecutionRecord
		}
		return p.access.Check(ctx)
	}
	readPublic := func() error {
		if err := renew(); err != nil {
			return err
		}
		if err := readExact(p.manifestObject, p.manifest); err != nil {
			return err
		}
		marker, err := originalCommittedMarkerData(p.manifest, p.manifestObject, p.target.InstallationID, claim.Target.PublicID, p.attempt, p.target.Root)
		if err != nil {
			return err
		}
		p.marker = marker
		if err := readExact(p.markerObject, marker); err != nil {
			return err
		}
		expectedIndex, err := originalRemoteContainerIndex(capture, objects, data.Bootstrap)
		if err != nil || !bytes.Equal(expectedIndex, data.Index) {
			return c.ErrExecutionRecord
		}
		for _, member := range []struct {
			path string
			raw  []byte
		}{{"artifact-index.json", data.Index}, {publicationCaptureCertificatePath, data.Certificate}, {remoteCaptureBootstrapPath, data.Bootstrap}} {
			if err := renew(); err != nil {
				return err
			}
			object, ok := data.Objects[member.path]
			if !ok {
				return c.ErrExecutionRecord
			}
			if err := readExact(object, member.raw); err != nil {
				return err
			}
		}
		return nil
	}
	if err = readPublic(); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	sqlVerified, skillsObjectsVerified := false, false
	for _, requested := range publicationRequestedParts {
		if err = renew(); err != nil {
			return nil, err
		}
		object, ok := objects.Containers[requested]
		if !ok {
			return nil, c.ErrExecutionRecord
		}
		checkpoints := map[string]string{}
		parts := map[string]publicationVerifiedPart{}
		for _, part := range capture.Parts {
			if part.RequestedPart == requested {
				sum, err := pcCheckpointSHA(part.Checkpoint)
				if err != nil || parts[part.Part].Part != "" {
					return nil, c.ErrExecutionRecord
				}
				checkpoints[part.Part] = sum
				parts[part.Part] = part
			}
		}
		facts, err := reader.InspectPartContainer(ctx, object, pc.Scope{Installation: capture.Input.InstallationID, Backup: capture.Input.TaskPublicID, Attempt: p.attempt, ConfigVersion: capture.Input.ConfigVersion, ConfigSHA256: capture.Input.ConfigSHA256, CaptureContextSHA256: capture.CaptureContextSHA256, Part: requested}, checkpoints, p.access.ValidUntil())
		if err != nil || facts.Header.SourceInventorySHA256 != capture.Input.SourceSHA256 || len(facts.Header.Members) != len(parts) || p.access.Check(ctx) != nil {
			return nil, c.ErrExecutionRecord
		}
		for index, member := range facts.Header.Members {
			part, ok := parts[member.Part]
			if !ok || seen[member.Part] {
				return nil, c.ErrExecutionRecord
			}
			if err = renew(); err != nil {
				return nil, err
			}
			record, err := s.inspectOriginalRemoteContainerMemberSamples(ctx, *claim, p.attempt, reader, object, capture, part, member, facts.Locations[index], teamRelations, p.contentSamples)
			if err != nil {
				return nil, err
			}
			expected, _, err := publicationContainerMember(capture, part, record)
			if err != nil || !sameOriginalContainerMember(expected, member) || finalVerificationMemberSource(source, part, record) != nil {
				return nil, c.ErrExecutionRecord
			}
			invocationRaw, err := json.Marshal(record.Invocation)
			if err != nil {
				return nil, err
			}
			p.skillParts = append(p.skillParts, b.JobPart{Part: part.Part, Category: part.Category, InvocationJSON: invocationRaw, InvocationSHA256: part.InvocationSHA256})
			seen[member.Part] = true
			if part.Part == b.UsersInstancesDatabasePart {
				sqlVerified = true
			}
			if part.Part == b.SkillObjectsPart {
				skillsObjectsVerified = true
			}
		}
	}
	var sidecar, proofs []byte
	defer func() { clear(sidecar); clear(proofs) }()
	for _, part := range capture.Parts {
		if part.Part != ce.Part && part.Part != ce.ProofPart && part.Part != remoteCaptureDescriptionPart {
			continue
		}
		if seen[part.Part] {
			return nil, c.ErrExecutionRecord
		}
		if err = renew(); err != nil {
			return nil, err
		}
		plain, err := s.readOriginalRemoteContainerControl(ctx, *claim, p.attempt, reader, capture, part, objects.Control)
		if err != nil {
			return nil, err
		}
		if part.Part == ce.Part {
			sidecar = plain
		} else if part.Part == ce.ProofPart {
			proofs = plain
		} else {
			clear(plain)
		}
		seen[part.Part] = true
	}
	if len(seen) != len(capture.Parts) || !sqlVerified || !skillsObjectsVerified {
		return nil, c.ErrExecutionRecord
	}
	prepared, err := ce.VerifyFinalizedBytes(ctx, capture.ControlSeed, sidecar, proofs)
	if err != nil {
		return nil, err
	}
	defer clear(prepared.SidecarJSON)
	defer clear(prepared.ProofsJSON)
	got, _ := ce.Canonical(prepared.Locator)
	want, _ := ce.Canonical(capture.Control)
	if !bytes.Equal(got, want) {
		return nil, c.ErrExecutionRecord
	}
	if err = readPublic(); err != nil {
		return nil, err
	}
	if err = p.checkAbsence(ctx); err != nil {
		return nil, err
	}
	if err = teamRelations.complete(); err != nil {
		return nil, err
	}
	if err = b.ValidateFinalSkillWorkspaceParts(source, p.skillParts); err != nil {
		return nil, err
	}
	if err = p.checkHistory(ctx, *claim); err != nil {
		return nil, err
	}
	if err = p.openSourceRecovery(ctx); err != nil {
		return nil, err
	}
	stamp, err := p.contentSHA()
	if err != nil {
		return nil, err
	}
	p.verifiedSHA256 = stamp
	tx, err := s.publisherVerifierDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: false, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = p.recheckVerifiedTx(ctx, tx); err != nil {
		return nil, err
	}
	samplesComplete = true
	return p, nil
}

// Concrete first-forward producer for D's two existing caller sites. It
// consumes only the result of REAL cleanup, explicitly renews the task token,
// and runs current remote reads plus actual cross-member predicates. It never
// modifies the cleanup token, signs, opens readiness or updates terminal state.
func (s *DeploymentService) completeOriginalPublicationThroughFinalVerification(ctx context.Context, claim *c.ClaimToken, attempt uint64, policy c.LeasePolicy, store *nativePublicationS3, capture publicationVerifiedCapture) (*publicationFinalVerification, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || claim == nil || store == nil || policy.Validate() != nil {
		return nil, c.ErrExecutionAuthority
	}
	cleanup, err := s.completeOriginalPublicationThroughNativeCleanup(ctx, claim, attempt, policy, store, capture)
	if err != nil {
		return nil, err
	}
	fresh, err := (c.ClaimCoordinator{Executor: s.publisherVerifierDB, InstallationID: s.Config.InstallationID}).Renew(ctx, *claim, policy)
	if err != nil {
		return nil, err
	}
	*claim = fresh
	return s.verifyOriginalPublicationFinalization(ctx, claim, policy, cleanup)
}
