package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/hmac"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"sort"
	"time"

	"clawreef/internal/systembackup/staging"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
	"github.com/google/uuid"
)

type publicationLocalCleanupIntent struct {
	Version, NativeSHA256, CaptureSHA256, ManifestSHA256, MarkerSHA256 string
	Owner                                                              originalStageOwner
	OwnerMAC, InventorySHA256, SealsSHA256                             string
	RowVersion                                                         uint64
	Claim                                                              c.ClaimToken
	Deadline                                                           time.Time
}

// Only this private producer, after actual absence and committed cleanup_result
// evidence, can construct the next signing stage's complete cleanup receipt.
// It is not artifact acceptance or permission to change the task terminal state.
type publicationCompleteCleanup struct {
	native       *publicationNativeCleanup
	intent       publicationLocalCleanupIntent
	intentSHA256 string
	seals        []publicationLocalSeal
	evidence     ce.EvidenceRef
	body         []byte
}

type publicationCleanupEvidenceBody struct {
	Version, Installation, Backup                                                                  string
	Attempt                                                                                        uint64
	Claim                                                                                          c.ClaimToken
	IntentSHA256, NativeSHA256, ManifestSHA256, MarkerSHA256, InventorySHA256, SealsSHA256, Result string
}

func (p *publicationCompleteCleanup) expectedEvidence() (ce.EvidenceRef, []byte, error) {
	if !p.ready() || !formalCandidateDigest(p.intentSHA256) {
		return ce.EvidenceRef{}, nil, c.ErrExecutionAuthority
	}
	i := p.intent
	body, err := ce.Canonical(publicationCleanupEvidenceBody{Version: "system-backup-original-complete-cleanup.v1", Installation: i.Owner.Installation, Backup: i.Owner.Task, Attempt: i.Owner.Attempt, Claim: i.Claim, IntentSHA256: p.intentSHA256, NativeSHA256: i.NativeSHA256, ManifestSHA256: i.ManifestSHA256, MarkerSHA256: i.MarkerSHA256, InventorySHA256: i.InventorySHA256, SealsSHA256: i.SealsSHA256, Result: "confirmed_absent"})
	return ce.EvidenceRef{PublicID: "sev_" + uuid.NewSHA1(uuid.NameSpaceOID, []byte(p.id()+"_complete")).String(), SHA256: hash(body)}, body, err
}

func (p *publicationCompleteCleanup) id() string { return p.native.id() + "_local" }

func (p *publicationCompleteCleanup) ready() bool {
	return p != nil && p.native != nil && p.native.done && p.native.candidate != nil && p.native.candidate.exit != nil && p.native.candidate.exit.service != nil && p.native.candidate.exit.service.publisherVerifierDB != nil && p.native.candidate.exit.service.Runtime != nil && p.native.candidate.exit.service.Runtime.Owner != nil && p.native.candidate.exit.service.Runtime.Owner.Staging != nil && p.native.candidate.exit.marker.receipt != nil && p.native.candidate.exit.marker.receipt.access != nil && p.native.candidate.exit.marker.receipt.postManifestMarker != nil && p.native.candidate.exit.marker.receipt.postManifestMarker.completion != nil
}

// Includes every original member, even C/envelope pairs packed inside a
// container and never mounted in the upload Job. No current source is read.
func (p *publicationCompleteCleanup) readSeals(ctx context.Context) error {
	if !p.ready() {
		return c.ErrExecutionAuthority
	}
	e := p.native.candidate.exit
	capture := e.marker.receipt.postManifestMarker.completion.capture
	if !capture.checked() || len(capture.Parts) < 8 || len(capture.Parts) > 64 {
		return c.ErrExecutionRecord
	}
	seen := map[string]bool{}
	for _, part := range capture.Parts {
		v, err := e.service.PublisherVerifierForPart(ctx, e.claim, e.attempt, part.Part)
		if err != nil {
			return err
		}
		record, err := v.CapturedRecord(ctx)
		v.Close()
		if err != nil {
			return err
		}
		raw, err := json.Marshal(record.PartResult)
		if err != nil || hash(raw) != part.ResultSHA256 || record.CandidateSHA256 != part.CandidateSHA256 || record.CaptureResultSHA256 != capture.CaptureResultSHA256 || record.Input.InstallationID != capture.Input.InstallationID || record.Input.TaskPublicID != capture.Input.TaskPublicID || record.Input.CaptureAttemptNo != capture.Input.CaptureAttemptNo || record.Input.ConfigVersion != capture.Input.ConfigVersion || record.Input.ConfigSHA256 != capture.Input.ConfigSHA256 || record.Input.SourceSHA256 != capture.Input.SourceSHA256 {
			return c.ErrExecutionRecord
		}
		pair, err := publicationRecordSeals(record)
		if err != nil || record.SealScope.InvocationSHA256 != part.InvocationSHA256 || pair[0].Intent.Original.SHA256 != part.CipherSHA256 || pair[0].Intent.Original.Size != part.CipherBytes || pair[1].Intent.Original.SHA256 != part.EnvelopeSHA256 || pair[1].Intent.Original.Size != part.EnvelopeBytes {
			return c.ErrExecutionRecord
		}
		for _, seal := range pair {
			if seen[seal.Name] {
				return c.ErrExecutionRecord
			}
			seen[seal.Name] = true
			p.seals = append(p.seals, seal)
		}
	}
	sort.Slice(p.seals, func(i, j int) bool { return p.seals[i].Name < p.seals[j].Name })
	_, err := publicationLocalSealsHash(p.seals)
	return err
}

// Authenticate the retained original key even after its owned directory is
// absent. The key is not deleted here; no missing key can be recreated.
func (p *publicationCompleteCleanup) checkKey() error {
	if !p.ready() {
		return c.ErrExecutionAuthority
	}
	if _, err := uuid.Parse(p.intent.Owner.KeyVersion); err != nil {
		return c.ErrExecutionRecord
	}
	root, err := stageKeyRoot(p.native.candidate.exit.service.Runtime.Owner.Staging, false)
	if err != nil {
		return err
	}
	defer root.Close()
	key, err := readStageFile(root, p.intent.Owner.KeyVersion+".key", 32)
	if err != nil {
		return err
	}
	defer clear(key)
	if len(key) != 32 || !hmac.Equal([]byte(stageMAC(p.intent.Owner, key)), []byte(p.intent.OwnerMAC)) {
		return c.ErrExecutionRecord
	}
	return nil
}

func (p *publicationCompleteCleanup) checkTx(ctx context.Context, tx *sql.Tx, state string) error {
	if !p.ready() || tx == nil {
		return c.ErrExecutionAuthority
	}
	e := p.native.candidate.exit
	completed := e.marker.receipt.postManifestMarker.completion
	if err := p.native.recheckCompleteTx(ctx, tx); err != nil {
		return err
	}
	i := p.intent
	sealsSHA, err := publicationLocalSealsHash(p.seals)
	if err != nil || i.Version != "system-backup-original-local-cleanup.v1" || i.NativeSHA256 != p.native.intentSHA256 || i.Claim != e.claim || !completed.capture.checked() || i.CaptureSHA256 != completed.capture.receipt.sha256 || i.ManifestSHA256 != e.marker.receipt.postManifestMarker.manifest.SHA256 || i.MarkerSHA256 != e.marker.SHA256 || i.Owner.Installation != e.service.Config.InstallationID || i.Owner.Task != e.claim.Target.PublicID || i.Owner.Attempt != e.attempt || i.SealsSHA256 != sealsSHA || !formalCandidateDigest(i.InventorySHA256) || i.RowVersion < 1 || i.RowVersion > ^uint64(0)-3 || !i.Deadline.Equal(p.native.intent.Deadline) {
		return c.ErrExecutionRecord
	}
	var raw []byte
	if p.intentSHA256 != "" {
		raw, err = loadPublicationMetadata(ctx, tx, i.Owner.Task, p.id())
		want, _ := ce.Canonical(i)
		if err != nil || hash(raw) != p.intentSHA256 || !bytes.Equal(raw, want) {
			return c.ErrExecutionRecord
		}
	}
	// Reopen the immutable ORIGINAL container plan on every stage. A journal
	// cannot substitute its own path/key/resource or shrink the capture set.
	var plan publicationContainerPlan
	raw, err = loadPublicationMetadata(ctx, tx, i.Owner.Task, publicationContainerPlanID(i.Owner.Installation, i.Owner.Task, i.Owner.Attempt))
	if err != nil || decodePublicationCanonical(raw, &plan) != nil || plan.Version != "system-backup-original-publication-container-plan.v1" || plan.Installation != i.Owner.Installation || plan.Backup != i.Owner.Task || plan.Attempt != i.Owner.Attempt || plan.ConfigVersion != completed.capture.Input.ConfigVersion || plan.ConfigSHA256 != completed.capture.Input.ConfigSHA256 || plan.CaptureSHA256 != i.CaptureSHA256 || plan.CaptureResultSHA256 != completed.capture.CaptureResultSHA256 || plan.CertificateSHA256 != completed.certificate.sha256 || plan.CaptureContextSHA256 != completed.capture.CaptureContextSHA256 || plan.ParentResource != i.Owner.Resource || plan.ParentKeyVersion != i.Owner.KeyVersion || plan.ParentOwnerMAC != i.OwnerMAC || plan.ParentRowVersion != i.RowVersion {
		return c.ErrExecutionRecord
	}
	owner := originalStageOwner{Schema: "system-backup-original-stage-owner.v1", Installation: plan.Installation, Task: plan.Backup, Phase: "capture", Attempt: plan.Attempt, ConfigVersion: plan.ConfigVersion, ConfigSHA256: plan.ConfigSHA256, Location: filepath.Join(e.service.Runtime.Owner.Staging.Name(), plan.Backup)}
	base, _ := json.Marshal(owner)
	owner.PhaseUID = "capture-" + hash(base)
	owner.Resource = plan.ParentResource
	owner.KeyVersion = plan.ParentKeyVersion
	if owner != i.Owner {
		return c.ErrExecutionRecord
	}
	var phase, uid, kind, location, locationSHA, mac, key, lifecycle, result, failure string
	var name, observed, claimOwner, immutable sql.NullString
	var until sql.NullTime
	var version uint64
	var operation, resolution, evidence sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT phase,phase_uid,resource_type,planned_locator,location_sha256,owner_marker_hmac,owner_marker_key_version,lifecycle,cleanup_result,last_failure_code,row_version,observed_name,observed_uid,claim_owner,claim_expires_at,immutable_version,cleanup_operation_id,ownership_resolution_operation_id,ownership_resolution_evidence_id FROM system_backup_v2_staging_resources WHERE origin_installation_id=? AND backup_public_id=? AND attempt_no=? AND public_id=? FOR UPDATE`, i.Owner.Installation, i.Owner.Task, i.Owner.Attempt, i.Owner.Resource).Scan(&phase, &uid, &kind, &location, &locationSHA, &mac, &key, &lifecycle, &result, &failure, &version, &name, &observed, &claimOwner, &until, &immutable, &operation, &resolution, &evidence)
	expectedVersion := i.RowVersion
	expectedResult := "not_started"
	if state == "deleting" {
		expectedVersion += 2
		expectedResult = "running"
	} else if state == "deleted" {
		expectedVersion += 3
		expectedResult = "succeeded"
	} else if state != "ready" {
		return c.ErrExecutionRecord
	}
	if err != nil || phase != "capture" || uid != i.Owner.PhaseUID || kind != "hostpath" || location != i.Owner.Location || locationSHA != hash([]byte(location)) || mac != i.OwnerMAC || key != i.Owner.KeyVersion || lifecycle != state || result != expectedResult || failure != "none" || version != expectedVersion || !name.Valid || name.String != i.Owner.Task || !observed.Valid || observed.String != i.Owner.Resource || immutable.Valid || operation.Valid || resolution.Valid || evidence.Valid {
		return c.ErrExecutionRecord
	}
	if state == "ready" {
		if claimOwner.Valid || until.Valid {
			return c.ErrExecutionRecord
		}
	} else if !claimOwner.Valid || claimOwner.String != i.Claim.Owner || !until.Valid || !until.Time.Equal(i.Deadline) {
		return c.ErrExecutionRecord
	}
	var count int
	if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_staging_resources WHERE origin_installation_id=? AND backup_public_id=? AND attempt_no=? AND phase IN ('capture','secret_capture')`, i.Owner.Installation, i.Owner.Task, i.Owner.Attempt).Scan(&count) != nil || count != 1 {
		return c.ErrExecutionRecord
	}
	return p.native.recheckCompleteTx(ctx, tx)
}

func (p *publicationCompleteCleanup) transaction(ctx context.Context, state string, fn func(*sql.Tx) error) error {
	if !p.ready() || ctx == nil || ctx.Err() != nil || p.checkKey() != nil {
		return c.ErrExecutionAuthority
	}
	e := p.native.candidate.exit
	if e.marker.receipt.access.Check(ctx) != nil {
		return c.ErrExecutionAuthority
	}
	tx, err := e.service.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version uint64
	if tx.QueryRowContext(ctx, `SELECT row_version FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=? FOR UPDATE`, p.intent.Owner.Installation, p.intent.Owner.Task).Scan(&version) != nil || version != e.claim.RowVersion {
		return c.ErrClaimLost
	}
	if err = p.checkTx(ctx, tx, state); err != nil {
		return err
	}
	if fn != nil {
		if err = fn(tx); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil || ctx.Err() != nil {
		return c.ErrExecutionCommitUnknown
	}
	return nil
}

// Dispatch and original104 transitions commit atomically BEFORE removal.
func (p *publicationCompleteCleanup) begin(ctx context.Context) error {
	return p.transaction(ctx, "ready", func(tx *sql.Tx) error {
		body, err := ce.Canonical(p.intent)
		if err != nil || len(body) > 8192 {
			return c.ErrExecutionRecord
		}
		if err = p.reserve(ctx, tx, len(body)); err != nil {
			return err
		}
		until, err := p.retentionTx(ctx, tx)
		if err != nil {
			return err
		}
		if err = registerPublicationMetadata(ctx, tx, p.intent.Owner.Installation, p.intent.Owner.Task, p.id(), body, until); err != nil {
			return err
		}
		p.intentSHA256 = hash(body)
		for offset, step := range []struct{ from, to, result string }{{"ready", "sealed", "not_started"}, {"sealed", "deleting", "running"}} {
			r, err := tx.ExecContext(ctx, `UPDATE system_backup_v2_staging_resources SET lifecycle=?,cleanup_result=?,claim_owner=?,claim_expires_at=?,row_version=row_version+1 WHERE public_id=? AND origin_installation_id=? AND backup_public_id=? AND attempt_no=? AND phase='capture' AND resource_type='hostpath' AND lifecycle=? AND row_version=?`, step.to, step.result, p.intent.Claim.Owner, p.intent.Deadline, p.intent.Owner.Resource, p.intent.Owner.Installation, p.intent.Owner.Task, p.intent.Owner.Attempt, step.from, p.intent.RowVersion+uint64(offset))
			if err != nil {
				return err
			}
			if n, err := r.RowsAffected(); err != nil || n != 1 {
				return c.ErrExecutionRecord
			}
		}
		return p.checkTx(ctx, tx, "deleting")
	})
}

func (p *publicationCompleteCleanup) retentionTx(ctx context.Context, tx *sql.Tx) (time.Time, error) {
	var seconds int64
	var now time.Time
	i := p.intent
	if tx.QueryRowContext(ctx, `SELECT evidence_retention_seconds,UTC_TIMESTAMP(6) FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? AND config_sha256=? FOR SHARE`, i.Owner.Installation, i.Owner.ConfigVersion, i.Owner.ConfigSHA256).Scan(&seconds, &now) != nil || seconds < 60 || seconds > 10*365*86400 {
		return time.Time{}, c.ErrExecutionAuthority
	}
	until := now.Add(time.Duration(seconds) * time.Second)
	if !until.After(p.native.candidate.exit.marker.receipt.postManifestMarker.completion.capture.Input.Deadline) {
		return time.Time{}, c.ErrExecutionAuthority
	}
	return until, nil
}

func (p *publicationCompleteCleanup) reserve(ctx context.Context, tx *sql.Tx, size int) error {
	var capacity int64
	i := p.intent
	if tx.QueryRowContext(ctx, `SELECT control_metadata_capacity_bytes FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? AND config_sha256=? FOR SHARE`, i.Owner.Installation, i.Owner.ConfigVersion, i.Owner.ConfigSHA256).Scan(&capacity) != nil {
		return c.ErrExecutionAuthority
	}
	return (security.RegistrationCapacity{ReportFile: p.native.candidate.exit.service.Config.CapacityFile}).Reserve(ctx, tx, capacity, size)
}

func (p *publicationCompleteCleanup) absent(custody *publicationLocalFiles) bool {
	return custody != nil && publicationLocalFilesAbsent(custody.parent, custody.custody, p.intent.Owner.Task, p.seals)
}

// A query resolving a lost sync/commit ACK must flush the surviving parent
// directories too. Absence alone does not prove durable local cleanup.
func (p *publicationCompleteCleanup) observeAbsent(files *publicationLocalFiles) error {
	if !p.absent(files) {
		return c.ErrExecutionRecord
	}
	if err := staging.SyncDirectory(files.custody); err != nil {
		return err
	}
	if err := staging.SyncDirectory(files.parent); err != nil {
		return err
	}
	if !p.absent(files) {
		return c.ErrExecutionRecord
	}
	return nil
}

func (p *publicationCompleteCleanup) finish(ctx context.Context, files *publicationLocalFiles) error {
	return p.transaction(ctx, "deleting", func(tx *sql.Tx) error {
		if !p.absent(files) {
			return c.ErrExecutionRecord
		}
		r, err := tx.ExecContext(ctx, `UPDATE system_backup_v2_staging_resources SET lifecycle='deleted',cleanup_result='succeeded',row_version=row_version+1 WHERE public_id=? AND origin_installation_id=? AND backup_public_id=? AND attempt_no=? AND lifecycle='deleting' AND cleanup_result='running' AND row_version=? AND claim_owner=? AND claim_expires_at>UTC_TIMESTAMP(6)`, p.intent.Owner.Resource, p.intent.Owner.Installation, p.intent.Owner.Task, p.intent.Owner.Attempt, p.intent.RowVersion+2, p.intent.Claim.Owner)
		if err != nil {
			return err
		}
		if n, err := r.RowsAffected(); err != nil || n != 1 {
			return c.ErrExecutionRecord
		}
		if err = p.checkTx(ctx, tx, "deleted"); err != nil {
			return err
		}
		ref, body, err := p.expectedEvidence()
		if err != nil {
			return err
		}
		if err = p.reserve(ctx, tx, len(body)); err != nil {
			return err
		}
		until, err := p.retentionTx(ctx, tx)
		if err != nil {
			return err
		}
		// Unlike dispatch metadata, this row is actual cleanup_result evidence.
		_, err = tx.ExecContext(ctx, `INSERT INTO system_backup_v2_evidence(origin_installation_id,public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,inline_payload,content_checksum,content_size_bytes,media_type,encryption,redaction_classification,observed_health,expires_at) VALUES(?,?,'backup',?,'cleanup_result','inline',?,?,?,'application/json','none','internal','healthy',?)`, p.intent.Owner.Installation, ref.PublicID, p.intent.Owner.Task, body, ref.SHA256, len(body), until)
		if err != nil {
			return err
		}
		p.evidence = ref
		p.body = body
		return p.recheckCompleteTx(ctx, tx)
	})
}

func (p *publicationCompleteCleanup) recheckCompleteTx(ctx context.Context, tx *sql.Tx) error {
	if !p.ready() || p.intentSHA256 == "" || len(p.body) == 0 || p.evidence.SHA256 != hash(p.body) {
		return c.ErrExecutionAuthority
	}
	ref, want, err := p.expectedEvidence()
	if err != nil || ref != p.evidence || !bytes.Equal(want, p.body) {
		return c.ErrExecutionRecord
	}
	if err := p.checkTx(ctx, tx, "deleted"); err != nil {
		return err
	}
	var body []byte
	var digest string
	var size int
	if tx.QueryRowContext(ctx, `SELECT inline_payload,content_checksum,content_size_bytes FROM system_backup_v2_evidence WHERE origin_installation_id=? AND public_id=? AND owner_target_type='backup' AND owner_target_public_id=? AND evidence_type='cleanup_result' AND storage_state='inline' AND observed_health='healthy' AND evidence_failure_code='none' AND encryption='none' AND expires_at>UTC_TIMESTAMP(6) FOR SHARE`, p.intent.Owner.Installation, p.evidence.PublicID, p.intent.Owner.Task).Scan(&body, &digest, &size) != nil || !bytes.Equal(body, p.body) || len(body) != size || digest != p.evidence.SHA256 {
		return c.ErrExecutionRecord
	}
	return nil
}

func (s *DeploymentService) cleanupOriginalPublicationLocal(ctx context.Context, native *publicationNativeCleanup) (*publicationCompleteCleanup, error) {
	p := &publicationCompleteCleanup{native: native}
	if !p.ready() || native.candidate.exit.service != s || ctx == nil || ctx.Err() != nil {
		return nil, c.ErrExecutionAuthority
	}
	ctx, cancel := context.WithDeadline(ctx, native.intent.Deadline)
	defer cancel()
	if err := p.readSeals(ctx); err != nil {
		return nil, err
	}
	e := native.candidate.exit
	tx, err := s.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = native.recheckCompleteTx(ctx, tx); err != nil {
		return nil, err
	}
	raw, err := loadPublicationMetadata(ctx, tx, e.claim.Target.PublicID, p.id())
	fresh := errors.Is(err, sql.ErrNoRows)
	var files *publicationLocalFiles
	if fresh {
		guard, err := e.marker.receipt.access.Bind(ctx, tx)
		if err != nil {
			return nil, err
		}
		plan, _, stage, err := readPublicationContainerJobInputsTx(ctx, tx, guard, s)
		if err != nil {
			return nil, err
		}
		completed := e.marker.receipt.postManifestMarker.completion
		if plan.CaptureSHA256 != completed.capture.receipt.sha256 || plan.CertificateSHA256 != completed.certificate.sha256 {
			return nil, c.ErrExecutionRecord
		}
		if err = tx.Rollback(); err != nil {
			return nil, err
		}
		files, err = preparePublicationLocalFiles(ctx, s.Runtime.Owner, stage, p.seals)
		if err != nil {
			return nil, err
		}
		defer files.close()
		p.intent = publicationLocalCleanupIntent{Version: "system-backup-original-local-cleanup.v1", NativeSHA256: native.intentSHA256, CaptureSHA256: completed.capture.receipt.sha256, ManifestSHA256: e.marker.receipt.postManifestMarker.manifest.SHA256, MarkerSHA256: e.marker.SHA256, Owner: stage.owner, OwnerMAC: stage.mac, InventorySHA256: files.taskSHA256, SealsSHA256: files.sealsSHA256, RowVersion: stage.version, Claim: e.claim, Deadline: native.intent.Deadline}
		if err = p.begin(ctx); err != nil {
			return nil, err
		}
		// The custody lock covers the repeated inventory, committed deleting
		// gate and removal. The exact SQL task/resource locks cover each action.
		if err = staging.WithCustodyLock(ctx, files.custody, func() error {
			return files.removeLocked(ctx, func(remove func() error) error {
				return p.transaction(ctx, "deleting", func(tx *sql.Tx) error {
					if err := remove(); err != nil {
						return err
					}
					return p.checkTx(ctx, tx, "deleting")
				})
			})
		}); err != nil {
			return nil, err
		}
	} else {
		if err != nil || decodePublicationCanonical(raw, &p.intent) != nil {
			return nil, c.ErrExecutionRecord
		}
		p.intentSHA256 = hash(raw)
		if err = tx.Rollback(); err != nil {
			return nil, err
		}
		custody, err := openPublicationLocalCustody(s.Runtime.Owner.Staging)
		if err != nil {
			return nil, err
		}
		files = &publicationLocalFiles{parent: s.Runtime.Owner.Staging, custody: custody}
		defer files.close()
		// Original dispatch, including lost commit ACK, is QUERY ONLY. A
		// surviving directory or one surviving seal cannot cause another remove.
		var state string
		if err = s.publisherVerifierDB.QueryRowContext(ctx, `SELECT lifecycle FROM system_backup_v2_staging_resources WHERE public_id=? AND origin_installation_id=? AND backup_public_id=? AND attempt_no=?`, p.intent.Owner.Resource, p.intent.Owner.Installation, p.intent.Owner.Task, p.intent.Owner.Attempt).Scan(&state); err != nil {
			return nil, err
		}
		if state == "deleted" {
			p.evidence, p.body, err = p.expectedEvidence()
			if err != nil {
				return nil, err
			}
			if err = staging.WithCustodyLock(ctx, files.custody, func() error {
				if err := p.observeAbsent(files); err != nil {
					return err
				}
				return p.transaction(ctx, "deleted", func(tx *sql.Tx) error { return p.recheckCompleteTx(ctx, tx) })
			}); err != nil {
				return nil, err
			}
			return p, nil
		}
		if err = p.transaction(ctx, "deleting", nil); err != nil {
			return nil, err
		}
	}
	if err = staging.WithCustodyLock(ctx, files.custody, func() error {
		if err := p.observeAbsent(files); err != nil {
			return err
		}
		return p.finish(ctx, files)
	}); err != nil {
		return nil, err
	}
	return p, nil
}
