package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	cd "clawreef/internal/systembackupcapturedescription"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	a "clawreef/internal/systembackupkekadapter"
	w "clawreef/internal/systembackupwire"
)

// Private publisher input, never a business verifier/acceptance receipt. Only
// the actual current service can open it from the original authenticated plan,
// stopped Job history and controller-private observed C copies. Its logical C
// AAD paths remain the ORIGINAL worker names when objects are later relocated.
type publicationCaptureFiles struct {
	record             c.PublisherCaptureRecord
	candidate          worker.FormalCaptureResult
	files              staging.FormalFiles
	envelope           []byte
	stream             w.StreamVerification
	verifier           *a.PublisherVerifier
	until              time.Time
	domainVerified     bool
	counts             ownedPayloadCounts
	controlPlain       []byte
	descriptionRelease func()
}

func (p *publicationCaptureFiles) Close() {
	if p == nil {
		return
	}
	p.files.Close()
	clear(p.envelope)
	p.envelope = nil
	clear(p.controlPlain)
	p.controlPlain = nil
	if p.descriptionRelease != nil {
		p.descriptionRelease()
		p.descriptionRelease = nil
	}
	p.counts = ownedPayloadCounts{}
	if p.verifier != nil {
		p.verifier.Close()
		p.verifier = nil
	}
}

func (p *publicationCaptureFiles) check(ctx context.Context) error {
	if p == nil || p.verifier == nil || ctx == nil || ctx.Err() != nil || !time.Now().Before(p.until) || !p.verifier.ValidUntil().Equal(p.until) || p.verifier.Recheck(ctx) != nil {
		return c.ErrExecutionAuthority
	}
	return nil
}

// This independently authenticates and inertly reads complete original business
// C bytes. Control parts remain bounded in-memory inputs for the paired final
// source verification; neither individual part grants artifact acceptance.
func (s *DeploymentService) openPublicationCaptureFiles(ctx context.Context, claim c.ClaimToken, attempt uint64, part string) (out *publicationCaptureFiles, resultErr error) {
	stage := "service readiness"
	defer func() {
		if resultErr != nil {
			resultErr = fmt.Errorf("original publication files %s: %w", stage, resultErr)
		}
	}()
	if s == nil || s.staging == nil || ctx == nil || ctx.Err() != nil {
		return nil, c.ErrExecutionAuthority
	}
	stage = "current part verifier"
	verifier, err := s.PublisherVerifierForPart(ctx, claim, attempt, part)
	if err != nil {
		return nil, err
	}
	p := &publicationCaptureFiles{verifier: verifier, until: verifier.ValidUntil()}
	defer func() {
		if resultErr != nil {
			p.Close()
		}
	}()
	bounded, cancel := context.WithDeadline(ctx, p.until)
	defer cancel()
	stage = "original captured record"
	record, err := verifier.CapturedRecord(bounded)
	if err != nil {
		return nil, err
	}
	stage = "original candidate"
	var original FormalCandidateRecord
	if decodeProviderDeploymentJSON(record.CandidateJSON, &original) != nil || hash(record.CandidateJSON) != record.CandidateSHA256 || !worker.ValidateFormalCaptureResult(record.Invocation, &original.Candidate) || record.Invocation.ProviderKey == nil || record.Invocation.FormalCapture == nil || record.Invocation.Request.Binding.Path != part {
		return nil, c.ErrExecutionRecord
	}
	stage = "sealed file custody"
	custody, err := staging.OpenSealCustody(s.staging)
	if err != nil {
		return nil, err
	}
	defer custody.Close()
	stage = "original observed files"
	files, observed, err := staging.OpenFormalObserved(bounded, custody, record.SealScope, original.Candidate.Ciphertext, original.Candidate.Envelope)
	if err != nil {
		return nil, err
	}
	p.files = files
	stage = "original checkpoint"
	var checkpoint b.Checkpoint
	if json.Unmarshal(record.PartResult.Checkpoint, &checkpoint) != nil || checkpoint.SealedRef != observed.Reference() || checkpoint.ContentSHA256 != original.Candidate.Ciphertext.SHA256 {
		return nil, c.ErrExecutionRecord
	}
	stage = "original envelope bytes"
	envelope, err := io.ReadAll(io.LimitReader(files.Envelope, (32<<20)+1))
	p.envelope = envelope
	if err != nil || int64(len(envelope)) != original.Candidate.Envelope.Size || len(envelope) > 32<<20 || hash(envelope) != original.Candidate.Envelope.SHA256 {
		return nil, c.ErrExecutionRecord
	}
	stage = "current envelope binding"
	bound, err := verifier.ForEnvelope(bounded, envelope)
	if err != nil {
		return nil, err
	}
	i := record.Invocation
	if i.Request.CaptureDescription != nil && (s.publisherVerifier == nil || s.publisherVerifier.DescriptionMaxPlaintextBytes < i.Request.MaxArchiveBytes || s.publisherVerifier.validateDescriptionMemoryDeclaration() != nil) {
		return nil, cd.ErrMemoryDeclaration
	}
	spec := w.StreamSpec{Request: i.ProviderKey.Request, Path: i.Request.ArtifactName, MaxPlaintextBytes: i.Request.MaxCompressedBytes, MaxFrames: i.FormalCapture.MaxFrames}
	stage = "whole authenticated stream and payload"
	verified, err := w.InspectWrappedStream(bounded, spec, envelope, files.Ciphertext, bound, func(plaintext io.Reader) error {
		if i.Request.CaptureDescription != nil {
			p.descriptionRelease, err = cd.AdmitDecodeMemory(*i.Request.CaptureDescription)
			if err != nil {
				return err
			}
			p.controlPlain, err = io.ReadAll(io.LimitReader(plaintext, i.Request.MaxArchiveBytes+1))
			if err != nil || int64(len(p.controlPlain)) > i.Request.MaxArchiveBytes || part != cd.Part {
				return c.ErrExecutionRecord
			}
			return inspectOriginalDescriptionPartAdmitted(bounded, bytes.NewReader(p.controlPlain), i, nil, cd.Scope{InstallationID: record.Input.InstallationID, TaskPublicID: record.Input.TaskPublicID, ConfigVersion: record.Input.ConfigVersion, ConfigSHA256: record.Input.ConfigSHA256, AttemptNo: record.Input.CaptureAttemptNo, CaptureContextSHA256: i.Request.Binding.CaptureContextHash})
		}
		if i.Request.ControlEvidence == nil {
			if err := inspectOwnedBusinessPayloadCounts(bounded, i, original.Candidate, plaintext, &p.counts); err != nil {
				return err
			}
			p.domainVerified = true
			return nil
		}
		limit := int64(ce.MaxBytes)
		if part == ce.ProofPart {
			limit = ce.MaxProofBytes
		} else if part != ce.Part {
			return c.ErrExecutionRecord
		}
		p.controlPlain, err = io.ReadAll(io.LimitReader(plaintext, limit+1))
		if err != nil || int64(len(p.controlPlain)) > limit {
			return c.ErrExecutionRecord
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	stage = "stream totals and final authority"
	if verified.CiphertextBytes() != original.Candidate.Ciphertext.Size || verified.CiphertextSHA256() != original.Candidate.Ciphertext.SHA256 || p.check(bounded) != nil {
		return nil, c.ErrExecutionRecord
	}
	// Retain the SAME authenticated private file descriptors, not reopened
	// mutable worker paths. Any upload must still hash bytes through EOF and
	// independently GET the immutable remote version before it can be trusted.
	stage = "retained file rewind"
	if _, err = files.Ciphertext.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	if _, err = files.Envelope.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	p.record, p.candidate, p.stream = record, original.Candidate, verified
	return p, nil
}
