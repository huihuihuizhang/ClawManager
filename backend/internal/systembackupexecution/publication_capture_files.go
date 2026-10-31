package systembackupexecution

import (
	"context"
	"encoding/json"
	"io"
	"time"

	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
	a "clawreef/internal/systembackupkekadapter"
	w "clawreef/internal/systembackupwire"
)

// Private publisher input, never a business verifier/acceptance receipt. Only
// the actual current service can open it from the original authenticated plan,
// stopped Job history and controller-private observed C copies. Its logical C
// AAD paths remain the ORIGINAL worker names when objects are later relocated.
type publicationCaptureFiles struct {
	record    c.PublisherCaptureRecord
	candidate worker.FormalCaptureResult
	files     staging.FormalFiles
	envelope  []byte
	stream    w.StreamVerification
	verifier  *a.PublisherVerifier
	until     time.Time
}

func (p *publicationCaptureFiles) Close() {
	if p == nil {
		return
	}
	p.files.Close()
	clear(p.envelope)
	p.envelope = nil
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

// This authenticates complete C bytes, not their domain semantics. The final
// assembler must additionally run the actual inert domain readers and require
// complete owned reports before publishing a manifest or claiming success.
func (s *DeploymentService) openPublicationCaptureFiles(ctx context.Context, claim c.ClaimToken, attempt uint64, part string) (out *publicationCaptureFiles, resultErr error) {
	if s == nil || s.staging == nil || ctx == nil || ctx.Err() != nil {
		return nil, c.ErrExecutionAuthority
	}
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
	record, err := verifier.CapturedRecord(bounded)
	if err != nil {
		return nil, err
	}
	var original FormalCandidateRecord
	if decodeProviderDeploymentJSON(record.CandidateJSON, &original) != nil || hash(record.CandidateJSON) != record.CandidateSHA256 || !worker.ValidateFormalCaptureResult(record.Invocation, &original.Candidate) || record.Invocation.ProviderKey == nil || record.Invocation.FormalCapture == nil || record.Invocation.Request.Binding.Path != part {
		return nil, c.ErrExecutionRecord
	}
	custody, err := staging.OpenSealCustody(s.staging)
	if err != nil {
		return nil, err
	}
	defer custody.Close()
	files, observed, err := staging.OpenFormalObserved(bounded, custody, record.SealScope, original.Candidate.Ciphertext, original.Candidate.Envelope)
	if err != nil {
		return nil, err
	}
	p.files = files
	var checkpoint b.Checkpoint
	if json.Unmarshal(record.PartResult.Checkpoint, &checkpoint) != nil || checkpoint.SealedRef != observed.Reference() || checkpoint.ContentSHA256 != original.Candidate.Ciphertext.SHA256 {
		return nil, c.ErrExecutionRecord
	}
	envelope, err := io.ReadAll(io.LimitReader(files.Envelope, (32<<20)+1))
	p.envelope = envelope
	if err != nil || int64(len(envelope)) != original.Candidate.Envelope.Size || len(envelope) > 32<<20 || hash(envelope) != original.Candidate.Envelope.SHA256 {
		return nil, c.ErrExecutionRecord
	}
	bound, err := verifier.ForEnvelope(bounded, envelope)
	if err != nil {
		return nil, err
	}
	i := record.Invocation
	spec := w.StreamSpec{Request: i.ProviderKey.Request, Path: i.Request.ArtifactName, MaxPlaintextBytes: i.Request.MaxCompressedBytes, MaxFrames: i.FormalCapture.MaxFrames}
	verified, err := w.VerifyWrappedStream(bounded, spec, envelope, files.Ciphertext, bound)
	if err != nil {
		return nil, err
	}
	if verified.CiphertextBytes() != original.Candidate.Ciphertext.Size || verified.CiphertextSHA256() != original.Candidate.Ciphertext.SHA256 || p.check(bounded) != nil {
		return nil, c.ErrExecutionRecord
	}
	// Retain the SAME authenticated private file descriptors, not reopened
	// mutable worker paths. Any upload must still hash bytes through EOF and
	// independently GET the immutable remote version before it can be trusted.
	if _, err = files.Ciphertext.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	if _, err = files.Envelope.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	p.record, p.candidate, p.stream = record, original.Candidate, verified
	return p, nil
}
