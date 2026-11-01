package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
)

var (
	ErrPublicationUploadFailed         = errors.New("original publication upload Job failed")
	ErrPublicationUploadMissingResults = errors.New("original publication upload Job exited without complete registered results")
	ErrPublicationUploadWindowClosed   = errors.New("original publication upload claim or material window closed")
)

type publicationUploadCursor struct {
	Sequence        uint64
	Status, LastSHA sql.NullString
}

// Scan the actual 107 SQL nullability; empty strings are not substitutes for
// its required NULL initial state. This returns inert cursor DATA only.
func scanPublicationUploadCursor(row interface{ Scan(...any) error }, max uint64) (publicationUploadCursor, error) {
	var cursor publicationUploadCursor
	if row == nil || max < 1 || row.Scan(&cursor.Sequence, &cursor.Status, &cursor.LastSHA) != nil || cursor.Sequence > max {
		return publicationUploadCursor{}, c.ErrExecutionRecord
	}
	if cursor.Sequence == 0 {
		if cursor.Status.Valid || cursor.LastSHA.Valid {
			return publicationUploadCursor{}, c.ErrExecutionRecord
		}
	} else {
		if !cursor.Status.Valid || !cursor.LastSHA.Valid || !formalCandidateDigest(cursor.LastSHA.String) {
			return publicationUploadCursor{}, c.ErrExecutionRecord
		}
		expected := "upload_objects"
		if cursor.Sequence == max {
			expected = "upload_candidate"
		}
		if cursor.Status.String != expected {
			return publicationUploadCursor{}, c.ErrExecutionRecord
		}
	}
	return cursor, nil
}

func (cursor publicationUploadCursor) matchesLastBody(raw []byte) bool {
	return cursor.Sequence > 0 && cursor.LastSHA.Valid && hash(raw) == cursor.LastSHA.String
}

// Result hints remain DATA, never native-content or C verification receipts.
// This closed consistency check cannot create authority or register a result.
func publicationUploadCompletion(request PublicationUploadRequest, requestSHA, uid string, generation int64, job *batchv1.Job, sequence uint64, status string, messages []publicationResultMessage) (bool, error) {
	raw, marshalErr := json.Marshal(request)
	if _, _, err := request.validate(); err != nil || marshalErr != nil || hash(raw) != requestSHA {
		return false, c.ErrExecutionRecord
	}
	if job == nil || uid == "" || string(job.UID) != uid || generation < 1 || job.Generation != generation || job.DeletionTimestamp != nil || job.Spec.Suspend == nil || *job.Spec.Suspend || !formalCandidateDigest(requestSHA) || sequence > uint64(len(request.Objects)+1) || uint64(len(messages)) != sequence {
		return false, c.ErrExecutionRecord
	}
	for i, message := range messages {
		if message.Sequence != uint64(i+1) || message.validate(request, requestSHA) != nil {
			return false, c.ErrExecutionRecord
		}
	}
	expectedStatus := ""
	if sequence > 0 {
		expectedStatus = "upload_objects"
	}
	if sequence == uint64(len(request.Objects)+1) {
		expectedStatus = "upload_candidate"
	}
	if status != expectedStatus {
		return false, c.ErrExecutionRecord
	}
	complete, failed := false, job.Status.Failed > 0
	for _, condition := range job.Status.Conditions {
		if condition.Status != corev1.ConditionTrue {
			continue
		}
		if condition.Type == batchv1.JobComplete {
			complete = true
		}
		if condition.Type == batchv1.JobFailed {
			failed = true
		}
	}
	if failed {
		return false, ErrPublicationUploadFailed
	}
	if complete && job.Status.Succeeded != 1 {
		return false, c.ErrExecutionRecord
	}
	if complete && sequence != uint64(len(request.Objects)+1) {
		return false, ErrPublicationUploadMissingResults
	}
	return complete && sequence == uint64(len(request.Objects)+1), nil
}

func originalPublicationUploadDeadline(request PublicationUploadRequest, material, claim time.Time) (time.Time, error) {
	if material.IsZero() || claim.IsZero() || request.Deadline.IsZero() {
		return time.Time{}, c.ErrExecutionRecord
	}
	envelope, closed := decodeOriginalCaptureCertificateEnvelope(request.CaptureCertificate)
	var certificate publicationCaptureCertificatePayload
	if !closed || decodePublicationCanonical(envelope.Payload, &certificate) != nil || certificate.Installation != request.Installation || certificate.Backup != request.Backup || certificate.Attempt != request.Attempt || certificate.ExpiresAt.IsZero() {
		return time.Time{}, c.ErrExecutionRecord
	}
	until := material
	for _, deadline := range []time.Time{claim, request.Deadline, certificate.ExpiresAt} {
		if deadline.Before(until) {
			until = deadline
		}
	}
	return until, nil
}

func (s *DeploymentService) readOriginalPublicationUploadCompletion(ctx context.Context, claim c.ClaimToken, m *publicationJobMaterials, job *batchv1.Job) (bool, error) {
	if m == nil || m.intent.Claim != claim {
		return false, c.ErrClaimLost
	}
	if s == nil || s.publicationTarget == nil {
		return false, c.ErrExecutionAuthority
	}
	access, err := s.publicationAccess(ctx, claim, m.intent.Attempt)
	if err != nil || access.Check(ctx) != nil {
		return false, c.ErrClaimLost
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	guard, err := access.Bind(ctx, tx)
	if err != nil {
		return false, err
	}
	activation, err := s.loadPublicationActivationTx(ctx, tx, m.intent)
	if err != nil {
		return false, err
	}
	if activation == nil {
		return false, ErrJobUncertain
	}
	if s.checkPublicationTargetTx(ctx, tx, guard.Facts(), *s.publicationTarget) != nil {
		return false, c.ErrExecutionAuthority
	}
	cursor, err := scanPublicationUploadCursor(tx.QueryRowContext(ctx, `SELECT last_accepted_sequence,last_observed_status,last_accepted_body_sha256 FROM system_backup_v2_job_observations WHERE origin_installation_id=? AND target_type='backup' AND target_public_id=? AND attempt_no=? AND phase='publish' AND job_unit_key='artifact-upload' AND job_uid=? AND job_generation=? FOR SHARE`, m.intent.Installation, m.intent.Backup, m.intent.Attempt, activation.JobUID, activation.AfterGeneration), uint64(len(m.request.Objects)+1))
	if err != nil {
		return false, err
	}
	sequence := cursor.Sequence
	messages := make([]publicationResultMessage, 0, sequence)
	for i := uint64(1); i <= sequence; i++ {
		raw, err := loadPublicationMetadata(ctx, tx, m.intent.Backup, publicationResultID(m.intent, i))
		if err != nil {
			return false, err
		}
		var message publicationResultMessage
		if decodeProviderDeploymentJSON(raw, &message) != nil {
			return false, c.ErrExecutionRecord
		}
		canonical, err := ce.Canonical(message)
		if err != nil || !bytes.Equal(canonical, raw) || i == sequence && !cursor.matchesLastBody(raw) {
			return false, c.ErrExecutionRecord
		}
		messages = append(messages, message)
	}
	complete, err := publicationUploadCompletion(m.request, m.intent.RequestSHA256, activation.JobUID, activation.AfterGeneration, job, sequence, cursor.Status.String, messages)
	if err != nil {
		return false, err
	}
	if guard.RecheckTx(ctx, tx) != nil {
		return false, c.ErrClaimLost
	}
	return complete, nil
}

// Keep the exact claim alive by retaining it, not by extending/replacing it.
// Every poll uses current original SQL and the already bound native Job; no
// Create/Patch, new grant, signer, claim Renew or new task is reachable here.
// Cancellation/claim loss stops immediately. Native exit alone is insufficient.
func (s *DeploymentService) awaitOriginalPublicationUpload(ctx context.Context, claim c.ClaimToken, attempt uint64, target PublicationTargetMaterials, interval time.Duration) error {
	if ctx == nil || ctx.Err() != nil {
		if ctx != nil {
			return ctx.Err()
		}
		return c.ErrExecutionAuthority
	}
	m, err := s.preparePublicationJobMaterials(ctx, claim, attempt, target, PublicationUploadRequest{})
	if err != nil {
		return err
	}
	defer m.Close()
	access, err := s.publicationAccess(ctx, claim, attempt)
	if err != nil || access.Check(ctx) != nil {
		return c.ErrClaimLost
	}
	until, err := originalPublicationUploadDeadline(m.request, m.intent.Deadline, access.ValidUntil())
	if err != nil {
		return err
	}
	if !time.Now().Before(until) {
		return errors.Join(ErrJobUncertain, ErrPublicationUploadWindowClosed)
	}
	bounded, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	if interval < 100*time.Millisecond || interval > 5*time.Second {
		interval = time.Second
	}
	for {
		if bounded.Err() != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return errors.Join(ErrJobUncertain, ErrPublicationUploadWindowClosed)
		}
		if access.Check(bounded) != nil {
			return c.ErrClaimLost
		}
		job, _, err := s.readBoundPublicationJob(bounded, claim, attempt, m)
		if err != nil {
			return err
		}
		complete, err := s.readOriginalPublicationUploadCompletion(bounded, claim, m, job)
		if err != nil {
			return err
		}
		if complete {
			return nil
		}
		timer := time.NewTimer(interval)
		select {
		case <-bounded.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}

func (s *DeploymentService) startAndAwaitOriginalPublicationUpload(ctx context.Context, claim c.ClaimToken, attempt uint64, target PublicationTargetMaterials, request PublicationUploadRequest, interval time.Duration) error {
	if original, err := s.loadPublicationMaterialIntent(ctx, claim, attempt); err == nil {
		if original.Claim != claim {
			return c.ErrClaimLost
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, sendErr := s.ensureStartedPublicationJob(ctx, claim, attempt, target, request)
	if sendErr != nil && !errors.Is(sendErr, ErrJobUncertain) {
		return sendErr
	}
	// A lost activation ACK permits observation only. If original immutable
	// records prove actual completion, no resend is needed; otherwise preserve
	// uncertainty and leave finalization to its independent current authority.
	err := s.awaitOriginalPublicationUpload(ctx, claim, attempt, target, interval)
	if err == nil {
		return nil
	}
	return errors.Join(sendErr, err)
}
