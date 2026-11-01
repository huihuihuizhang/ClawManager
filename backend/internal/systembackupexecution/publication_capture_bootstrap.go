package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"

	cd "clawreef/internal/systembackupcapturedescription"
	c "clawreef/internal/systembackupcontroller"
	w "clawreef/internal/systembackupwire"
)

// Build public administrative bootstrap from independently checked ORIGINAL
// C records and the known original signed certificate. It creates no new
// capture, signature, key use, native version, artifact send or acceptance.
func (s *DeploymentService) prepareOriginalPublicationBootstrap(ctx context.Context, claim *c.ClaimToken, attempt uint64, policy c.LeasePolicy, capture publicationVerifiedCapture) ([]byte, error) {
	return s.prepareOriginalPublicationBootstrapMode(ctx, claim, attempt, policy, capture, false)
}

func (s *DeploymentService) prepareOriginalPublicationBootstrapMode(ctx context.Context, claim *c.ClaimToken, attempt uint64, policy c.LeasePolicy, capture publicationVerifiedCapture, freshPreparation bool) ([]byte, error) {
	if s == nil || claim == nil || !capture.checked() || !formalCandidateDigest(capture.DescriptionSHA256) {
		return nil, c.ErrExecutionRecord
	}
	guard := &publicationContainerGuard{service: s, claim: claim, attempt: attempt, policy: policy, freshPreparation: freshPreparation}
	if err := guard.current(ctx, true); err != nil {
		return nil, err
	}
	certificate, known, err := s.loadOriginalPublicationCaptureCertificate(ctx, *claim, attempt, capture)
	if err != nil || !known {
		return nil, c.ErrExecutionRecord
	}
	envelope, closed := decodeOriginalCaptureCertificateEnvelope(certificate.bytes)
	var payload publicationCaptureCertificatePayload
	if !closed || decodeProviderDeploymentJSON(envelope.Payload, &payload) != nil || len(payload.Checkpoints) != len(capture.Parts) {
		return nil, c.ErrExecutionRecord
	}
	pins := map[string]string{}
	for _, p := range payload.Checkpoints {
		if _, exists := pins[p.Part]; exists {
			return nil, c.ErrExecutionRecord
		}
		pins[p.Part] = p.SHA256
	}
	bootstrap := cd.Bootstrap{Version: cd.BootstrapVersion, Scope: cd.Scope{InstallationID: capture.Input.InstallationID, TaskPublicID: capture.Input.TaskPublicID, ConfigVersion: capture.Input.ConfigVersion, ConfigSHA256: capture.Input.ConfigSHA256, AttemptNo: attempt, CaptureContextSHA256: capture.CaptureContextSHA256}, SourceInventorySHA256: capture.Input.SourceSHA256, Members: []cd.AdministrativeMember{}}
	byName := map[string]publicationVerifiedPart{}
	for _, p := range capture.Parts {
		byName[p.Part] = p
	}
	for _, name := range []string{cd.Part, cd.ControlPart, cd.ProofPart} {
		expected, exists := byName[name]
		if !exists || expected.RequestedPart != "" {
			return nil, c.ErrExecutionRecord
		}
		if err = guard.current(ctx, true); err != nil {
			return nil, err
		}
		verifier, err := s.PublisherVerifierForPart(ctx, *claim, attempt, name)
		if err != nil {
			return nil, err
		}
		record, err := verifier.CapturedRecord(ctx)
		verifier.Close()
		if err != nil {
			return nil, err
		}
		inv := record.Invocation
		var original FormalCandidateRecord
		sha, err := inv.Hash()
		resultRaw, marshalErr := json.Marshal(record.PartResult)
		if err != nil || marshalErr != nil || sha != expected.InvocationSHA256 || decodeProviderDeploymentJSON(record.CandidateJSON, &original) != nil || hash(record.CandidateJSON) != expected.CandidateSHA256 || record.CandidateSHA256 != expected.CandidateSHA256 || hash(resultRaw) != expected.ResultSHA256 || !bytes.Equal(record.PartResult.Checkpoint, expected.Checkpoint) || record.Plan.SHA256 != capture.PlanSHA256 || record.CaptureResultSHA256 != capture.CaptureResultSHA256 || inv.ProviderKey == nil || inv.FormalCapture == nil || original.Candidate.Ciphertext.SHA256 != expected.CipherSHA256 || original.Candidate.Ciphertext.Size != expected.CipherBytes || original.Candidate.Envelope.SHA256 != expected.EnvelopeSHA256 || original.Candidate.Envelope.Size != expected.EnvelopeBytes {
			return nil, c.ErrExecutionRecord
		}
		bootstrap.Members = append(bootstrap.Members, cd.AdministrativeMember{Selection: cd.Selection{Part: name, Operation: expected.Operation, PartIndex: expected.Index}, CipherPath: expected.CipherPath, EnvelopePath: expected.EnvelopePath, CipherBytes: expected.CipherBytes, CipherSHA256: expected.CipherSHA256, EnvelopeBytes: expected.EnvelopeBytes, EnvelopeSHA256: expected.EnvelopeSHA256, Stream: w.StreamSpec{Request: inv.ProviderKey.Request, Path: inv.Request.ArtifactName, MaxPlaintextBytes: inv.Request.MaxCompressedBytes, MaxFrames: inv.FormalCapture.MaxFrames}, CheckpointJSON: bytes.Clone(expected.Checkpoint)})
	}
	raw, err := cd.EncodeBootstrap(bootstrap, pins)
	if err != nil {
		return nil, err
	}
	if err = guard.current(ctx, true); err != nil {
		return nil, err
	}
	return raw, nil
}
