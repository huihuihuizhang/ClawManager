package systembackupexecution

import (
	"bytes"
	"context"
	"time"

	c "clawreef/internal/systembackupcontroller"
)

// An existing prepared/dispatch/unknown certificate intent is never fresh.
// load/prepare/Stage/commit/SignCommitted use the already installed original
// one-send protocol; only acknowledged fresh preparation reaches a signer.
func (s *DeploymentService) ensureOriginalForwardCertificate(ctx context.Context, claim c.ClaimToken, attempt uint64, capture publicationVerifiedCapture) (originalPublicationCaptureCertificate, error) {
	known, found, err := s.loadOriginalPublicationCaptureCertificate(ctx, claim, attempt, capture)
	if err != nil || found {
		return known, err
	}
	signers, err := s.PublicationSignersForTask(ctx, claim)
	if err != nil {
		return originalPublicationCaptureCertificate{}, err
	}
	prepared, err := s.prepareOriginalCaptureCertificate(ctx, claim, attempt, capture, signers)
	if err != nil {
		return originalPublicationCaptureCertificate{}, err
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return originalPublicationCaptureCertificate{}, err
	}
	defer tx.Rollback()
	if err = prepared.Stage(ctx, tx); err != nil {
		return originalPublicationCaptureCertificate{}, err
	}
	if tx.Commit() != nil || ctx.Err() != nil {
		return originalPublicationCaptureCertificate{}, c.ErrExecutionCommitUnknown
	}
	raw, sum, err := prepared.SignCommitted(ctx)
	if err != nil {
		return originalPublicationCaptureCertificate{}, err
	}
	known, found, err = s.loadOriginalPublicationCaptureCertificate(ctx, claim, attempt, capture)
	if err != nil || !found || known.sha256 != sum || !bytes.Equal(known.bytes, raw) {
		return originalPublicationCaptureCertificate{}, c.ErrExecutionCommitUnknown
	}
	return known, nil
}

func (s *DeploymentService) prepareOriginalForwardRequest(ctx context.Context, claim *c.ClaimToken, attempt uint64, policy c.LeasePolicy, capture publicationVerifiedCapture, target PublicationTargetMaterials) (PublicationUploadRequest, error) {
	var zero PublicationUploadRequest
	if claim == nil || !capture.checked() {
		return zero, c.ErrExecutionRecord
	}
	guard := &publicationContainerGuard{service: s, claim: claim, attempt: attempt, policy: policy, freshPreparation: true}
	if err := guard.current(ctx, true); err != nil {
		return zero, err
	}
	if _, err := s.ensureOriginalForwardCertificate(ctx, *claim, attempt, capture); err != nil {
		return zero, err
	}
	files, err := s.preparePublicationContainerFilesMode(ctx, claim, attempt, policy, capture, true)
	if err != nil {
		return zero, err
	}
	bootstrap, err := s.prepareOriginalPublicationBootstrapMode(ctx, claim, attempt, policy, capture, true)
	if err != nil {
		return zero, err
	}
	if err = guard.current(ctx, true); err != nil {
		return zero, err
	}
	limits, err := s.publicationContainerLimits(ctx, *claim, attempt)
	if err != nil {
		return zero, err
	}
	recovery, err := s.preparePublicationRecoveryFacts(ctx, *claim, attempt, capture, target)
	if err != nil {
		return zero, err
	}
	certificate, found, err := s.loadOriginalPublicationCaptureCertificate(ctx, *claim, attempt, capture)
	if err != nil || !found {
		return zero, c.ErrExecutionRecord
	}
	assembled, err := assembleOriginalPublicationManifest(capture, certificate, files, bootstrap, recovery, target, limits, time.Now())
	if err != nil {
		return zero, err
	}
	deadline := capture.Input.Deadline
	if certificate.expires.Before(deadline) {
		deadline = certificate.expires
	}
	if !time.Now().Before(deadline) {
		return zero, c.ErrExecutionAuthority
	}
	request := PublicationUploadRequest{Version: publicationPresignedUploadVersion, Installation: capture.Input.InstallationID, Backup: capture.Input.TaskPublicID, Attempt: attempt, Endpoint: target.Endpoint, Region: target.Region, Bucket: target.Bucket, ArtifactRoot: target.Root, RemoteStagingRoot: target.RemoteStagingRoot, CAHash: target.CASHA256, Deadline: deadline, Objects: assembled.Objects, ManifestInput: assembled.Manifest, IndexBytes: assembled.Index, CaptureCertificate: bytes.Clone(certificate.bytes), CaptureBootstrap: bytes.Clone(bootstrap)}
	if _, _, err = request.validate(); err != nil {
		return zero, err
	}
	if err = guard.check(ctx); err != nil {
		return zero, err
	}
	return request, nil
}
