package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"time"

	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	pc "clawreef/internal/systembackuppartcontainer"
	security "clawreef/internal/systembackupsecurity"
	w "clawreef/internal/systembackupwire"
)

// This guard may renew ONLY the publisher task claim while copying original
// ciphertext. It owns no DEK, source permission, provider session or Job intent.
// It must never surround Unwrap, Sign or an already issued upload delegation.
type publicationContainerGuard struct {
	service *DeploymentService
	claim   *c.ClaimToken
	attempt uint64
	policy  c.LeasePolicy
	access  *security.SQLPublisherCaptureAuthority
	last    time.Time
}

func (g *publicationContainerGuard) check(ctx context.Context) error { return g.current(ctx, false) }
func (g *publicationContainerGuard) current(ctx context.Context, force bool) error {
	if ctx == nil || ctx.Err() != nil || g == nil || g.service == nil || g.claim == nil || g.policy.Validate() != nil {
		return c.ErrExecutionAuthority
	}
	now := time.Now()
	if !force && !g.last.IsZero() && now.Sub(g.last) < 250*time.Millisecond && g.access != nil && now.Before(g.access.ValidUntil()) {
		return nil
	}
	if g.access != nil && time.Until(g.access.ValidUntil()) < 2*g.policy.HeartbeatInterval {
		fresh, err := (c.ClaimCoordinator{Executor: g.service.publisherVerifierDB, InstallationID: g.service.Config.InstallationID}).Renew(ctx, *g.claim, g.policy)
		if err != nil {
			return err
		}
		*g.claim = fresh
		g.access = nil
	}
	if g.access == nil {
		access, err := g.service.publicationAccess(ctx, *g.claim, g.attempt)
		if err != nil {
			return err
		}
		g.access = access
	}
	if err := g.access.Check(ctx); err != nil {
		return err
	}
	g.last = now
	return nil
}

type publicationContainerReader struct {
	ctx   context.Context
	src   io.ReadCloser
	check func(context.Context) error
}

func (r *publicationContainerReader) Read(dst []byte) (int, error) {
	if err := r.check(r.ctx); err != nil {
		return 0, err
	}
	n, err := r.src.Read(dst)
	if current := r.check(r.ctx); current != nil {
		return 0, current
	}
	return n, err
}
func (r *publicationContainerReader) Close() error { return r.src.Close() }

// Write actual physical bytes from original private C copies. No source GET,
// Unwrap, re-encryption, direct artifact PUT or fake capture authority occurs.
// The caller owns an unpublished destination and must persist its byte receipt
// before making it an input to the actual upload-only Job.
func (s *DeploymentService) writeOriginalPublicationContainer(ctx context.Context, claim *c.ClaimToken, attempt uint64, policy c.LeasePolicy, capture publicationVerifiedCapture, requested string, dst io.Writer) (pc.Facts, error) {
	var zero pc.Facts
	if s == nil || s.staging == nil || claim == nil || dst == nil || !capture.checked() || claim.Target.PublicID != capture.Input.TaskPublicID || attempt != capture.Input.CaptureAttemptNo || policy.Validate() != nil {
		return zero, c.ErrExecutionAuthority
	}
	guard := &publicationContainerGuard{service: s, claim: claim, attempt: attempt, policy: policy}
	if err := guard.current(ctx, true); err != nil {
		return zero, err
	}
	certificate, known, err := s.loadOriginalPublicationCaptureCertificate(ctx, *claim, attempt, capture)
	if err != nil || !known || !certificate.checked(capture, time.Now()) {
		return zero, c.ErrExecutionRecord
	}
	limits, err := s.publicationContainerLimits(ctx, *claim, attempt)
	if err != nil {
		return zero, err
	}
	envelope, closed := decodeOriginalCaptureCertificateEnvelope(certificate.bytes)
	var certified publicationCaptureCertificatePayload
	if !closed || decodeProviderDeploymentJSON(envelope.Payload, &certified) != nil {
		return zero, c.ErrExecutionRecord
	}
	allCheckpoints := map[string]string{}
	for _, checkpoint := range certified.Checkpoints {
		if allCheckpoints[checkpoint.Part] != "" {
			return zero, c.ErrExecutionRecord
		}
		allCheckpoints[checkpoint.Part] = checkpoint.SHA256
	}
	inputs := []pc.Input{}
	checkpoints := map[string]string{}
	for _, part := range capture.Parts {
		if part.RequestedPart != requested {
			continue
		}
		if err = guard.current(ctx, true); err != nil {
			return zero, err
		}
		verifier, err := s.PublisherVerifierForPart(ctx, *claim, attempt, part.Part)
		if err != nil {
			return zero, err
		}
		record, err := verifier.CapturedRecord(ctx)
		verifier.Close()
		if err != nil {
			return zero, err
		}
		member, candidate, err := publicationContainerMember(capture, part, record)
		if err != nil {
			return zero, err
		}
		checkpoint, err := pcCheckpointSHA(part.Checkpoint)
		if err != nil || checkpoint != allCheckpoints[part.Part] {
			return zero, c.ErrExecutionRecord
		}
		checkpoints[part.Part] = checkpoint
		sealScope := record.SealScope
		inputs = append(inputs, pc.Input{Member: member, Open: func(openCtx context.Context) (io.ReadCloser, []byte, error) {
			if err := guard.current(openCtx, true); err != nil {
				return nil, nil, err
			}
			custody, err := staging.OpenSealCustody(s.staging)
			if err != nil {
				return nil, nil, err
			}
			defer custody.Close()
			files, _, err := staging.OpenFormalObservedGuarded(openCtx, custody, sealScope, candidate.Ciphertext, candidate.Envelope, guard.check)
			if err != nil {
				return nil, nil, err
			}
			accepted := false
			defer func() {
				if !accepted {
					files.Close()
				}
			}()
			raw, err := io.ReadAll(io.LimitReader(&publicationContainerReader{ctx: openCtx, src: files.Envelope, check: guard.check}, (32<<20)+1))
			if err != nil || int64(len(raw)) != candidate.Envelope.Size || hash(raw) != candidate.Envelope.SHA256 || files.Envelope.Close() != nil {
				return nil, nil, c.ErrExecutionRecord
			}
			accepted = true
			return &publicationContainerReader{ctx: openCtx, src: files.Ciphertext, check: guard.check}, raw, nil
		}})
	}
	if len(inputs) == 0 || len(inputs) > pc.MaxMembers {
		return zero, c.ErrExecutionRecord
	}
	scope := pc.Scope{Installation: capture.Input.InstallationID, Backup: capture.Input.TaskPublicID, Attempt: attempt, ConfigVersion: capture.Input.ConfigVersion, ConfigSHA256: capture.Input.ConfigSHA256, CaptureContextSHA256: capture.CaptureContextSHA256, Part: requested}
	facts, err := pc.Write(ctx, dst, scope, capture.Input.SourceSHA256, inputs, checkpoints, limits.MaxArtifactBytes, limits.MaxIndexBytes)
	if err != nil {
		return zero, err
	}
	if err = guard.current(ctx, true); err != nil {
		return zero, err
	}
	again, known, err := s.loadOriginalPublicationCaptureCertificate(ctx, *claim, attempt, capture)
	if err != nil || !known || again.sha256 != certificate.sha256 || !again.checked(capture, time.Now()) {
		return zero, c.ErrExecutionRecord
	}
	currentLimits, err := s.publicationContainerLimits(ctx, *claim, attempt)
	if err != nil || currentLimits != limits {
		return zero, c.ErrExecutionAuthority
	}
	return facts, nil
}

func pcCheckpointSHA(raw []byte) (string, error) {
	canonical, err := ce.Canonical(json.RawMessage(raw))
	if err != nil {
		return "", err
	}
	return hash(canonical), nil
}

func (s *DeploymentService) publicationContainerLimits(ctx context.Context, claim c.ClaimToken, attempt uint64) (ArtifactReadLimits, error) {
	access, err := s.publicationAccess(ctx, claim, attempt)
	if err != nil {
		return ArtifactReadLimits{}, err
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return ArtifactReadLimits{}, err
	}
	defer tx.Rollback()
	guard, err := access.Bind(ctx, tx)
	if err != nil {
		return ArtifactReadLimits{}, err
	}
	return readPublicationLimitsTx(ctx, tx, guard)
}

func publicationContainerMember(capture publicationVerifiedCapture, part publicationVerifiedPart, record c.PublisherCaptureRecord) (pc.Member, worker.FormalCaptureResult, error) {
	var zero pc.Member
	var original FormalCandidateRecord
	input, err := json.Marshal(record.Input)
	expected, inputErr := json.Marshal(capture.Input)
	i := record.Invocation
	invocationSHA, invErr := i.Hash()
	result, resultErr := json.Marshal(record.PartResult)
	if err != nil || inputErr != nil || !bytes.Equal(input, expected) || record.Plan.SHA256 != capture.PlanSHA256 || record.CaptureResultSHA256 != capture.CaptureResultSHA256 || record.CandidateSHA256 != part.CandidateSHA256 || hash(record.CandidateJSON) != part.CandidateSHA256 || decodeProviderDeploymentJSON(record.CandidateJSON, &original) != nil || i.ProviderKey == nil || i.FormalCapture == nil || invErr != nil || invocationSHA != part.InvocationSHA256 || invocationSHA != original.Candidate.InvocationSHA256 || resultErr != nil || hash(result) != part.ResultSHA256 || !bytes.Equal(record.PartResult.Checkpoint, part.Checkpoint) || i.Request.Operation != part.Operation || i.Request.Binding.Path != part.Part || i.Request.Binding.PartIndex != part.Index || publicationRequestedPart(part.Operation) != part.RequestedPart || !worker.ValidateFormalCaptureResult(i, &original.Candidate) {
		return zero, worker.FormalCaptureResult{}, c.ErrExecutionRecord
	}
	if original.Candidate.Ciphertext.Size != part.CipherBytes || original.Candidate.Ciphertext.SHA256 != part.CipherSHA256 || original.Candidate.Envelope.Size != part.EnvelopeBytes || original.Candidate.Envelope.SHA256 != part.EnvelopeSHA256 {
		return zero, worker.FormalCaptureResult{}, c.ErrExecutionRecord
	}
	cipherPath, envelopePath := publicationPartPaths(part.Part, part.Index, invocationSHA)
	if cipherPath != part.CipherPath || envelopePath != part.EnvelopePath {
		return zero, worker.FormalCaptureResult{}, c.ErrExecutionRecord
	}
	member := pc.Member{Part: part.Part, Operation: part.Operation, Index: part.Index, CipherPath: cipherPath, EnvelopePath: envelopePath, CipherBytes: part.CipherBytes, CipherSHA256: part.CipherSHA256, CipherFraming: w.FramingVersion, EnvelopeBytes: part.EnvelopeBytes, EnvelopeSHA256: part.EnvelopeSHA256, EnvelopeFraming: w.EnvelopeVersion, Stream: w.StreamSpec{Request: i.ProviderKey.Request, Path: i.Request.ArtifactName, MaxPlaintextBytes: i.Request.MaxCompressedBytes, MaxFrames: i.FormalCapture.MaxFrames}, Checkpoint: bytes.Clone(part.Checkpoint)}
	return member, original.Candidate, nil
}
