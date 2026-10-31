package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"strconv"

	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	w "clawreef/internal/systembackupwire"
)

// Observation-only: unlike beginPublicationPayload, missing metadata never
// reserves a send. A stored nonempty immutable version is required here.
func (s *DeploymentService) originalPublishedPayload(ctx context.Context, claim c.ClaimToken, attempt uint64, store *nativePublicationS3, expected publicationPayloadIntent) (publicationPayloadIntent, string, error) {
	access, err := s.publicationAccess(ctx, claim, attempt)
	if err != nil || access.Check(ctx) != nil {
		return publicationPayloadIntent{}, "", c.ErrExecutionAuthority
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return publicationPayloadIntent{}, "", err
	}
	defer tx.Rollback()
	guard, err := access.Bind(ctx, tx)
	if err != nil || s.checkPublicationTargetTx(ctx, tx, guard.Facts(), store.config) != nil {
		return publicationPayloadIntent{}, "", c.ErrExecutionAuthority
	}
	raw, err := loadPublicationMetadata(ctx, tx, expected.Backup, expected.id())
	var actual publicationPayloadIntent
	if err != nil || decodeProviderDeploymentJSON(raw, &actual) != nil || actual.Deadline.IsZero() {
		return publicationPayloadIntent{}, "", c.ErrExecutionRecord
	}
	expected.Deadline = actual.Deadline
	want, _ := ce.Canonical(expected)
	if !bytes.Equal(raw, want) {
		return publicationPayloadIntent{}, "", c.ErrExecutionRecord
	}
	observedRaw, err := loadPublicationMetadata(ctx, tx, actual.Backup, actual.id()+"_observed")
	var observation publicationPayloadObservation
	if err != nil || decodeProviderDeploymentJSON(observedRaw, &observation) != nil || observation.Version != "system-backup-original-binary-observation.v1" || observation.IntentSHA256 != hash(raw) || observation.ObjectSHA256 != actual.SHA256 || observation.Size != actual.Size || observation.ObjectVersion == "" || observation.ObjectVersion == "null" || len(observation.ObjectVersion) > 256 || guard.RecheckTx(ctx, tx) != nil {
		return publicationPayloadIntent{}, "", c.ErrExecutionRecord
	}
	return actual, observation.ObjectVersion, nil
}

// Reopen ORIGINAL history/current independent publisher Unwrap, but read only
// native immutable artifact objects. This never opens controller-private C FDs
// or a worker staging path, and cannot repair the paired proof bytes from SQL.
func (s *DeploymentService) readRemotePublicationPart(ctx context.Context, claim c.ClaimToken, attempt uint64, store *nativePublicationS3, expected publicationVerifiedPart) (plain []byte, resultErr error) {
	verifier, err := s.PublisherVerifierForPart(ctx, claim, attempt, expected.Part)
	if err != nil {
		return nil, err
	}
	defer verifier.Close()
	bounded, cancel := context.WithDeadline(ctx, verifier.ValidUntil())
	defer cancel()
	record, err := verifier.CapturedRecord(bounded)
	if err != nil {
		return nil, err
	}
	var original FormalCandidateRecord
	if decodeProviderDeploymentJSON(record.CandidateJSON, &original) != nil || record.CandidateSHA256 != expected.CandidateSHA256 || hash(record.CandidateJSON) != record.CandidateSHA256 || !worker.ValidateFormalCaptureResult(record.Invocation, &original.Candidate) || original.Candidate.InvocationSHA256 != expected.InvocationSHA256 || original.Candidate.Ciphertext.SHA256 != expected.CipherSHA256 || original.Candidate.Ciphertext.Size != expected.CipherBytes || original.Candidate.Envelope.SHA256 != expected.EnvelopeSHA256 || original.Candidate.Envelope.Size != expected.EnvelopeBytes {
		return nil, c.ErrExecutionRecord
	}
	resultRaw, err := json.Marshal(record.PartResult)
	if err != nil || hash(resultRaw) != expected.ResultSHA256 || record.Invocation.Request.Operation != expected.Operation {
		return nil, c.ErrExecutionRecord
	}
	i := record.Invocation
	cipherPath, envelopePath := publicationPartPaths(expected.Part, i.Request.Binding.PartIndex, expected.InvocationSHA256)
	if cipherPath != expected.CipherPath || envelopePath != expected.EnvelopePath || i.Request.Binding.PartIndex != expected.Index {
		return nil, c.ErrExecutionRecord
	}
	intent := func(path, sha string, size int64) publicationPayloadIntent {
		return publicationPayloadIntent{Version: "system-backup-original-binary-upload.v1", Installation: record.Input.InstallationID, Backup: record.Input.TaskPublicID, Attempt: attempt, Part: expected.Part, InvocationSHA256: expected.InvocationSHA256, Path: path, Key: store.config.Root + record.Input.TaskPublicID + "/" + strconv.FormatUint(attempt, 10) + "/" + path, SHA256: sha, Size: size}
	}
	envelopeIntent, envelopeVersion, err := s.originalPublishedPayload(bounded, claim, attempt, store, intent(envelopePath, expected.EnvelopeSHA256, expected.EnvelopeBytes))
	if err != nil || expected.EnvelopeBytes > 32<<20 {
		return nil, c.ErrExecutionRecord
	}
	var envelope bytes.Buffer
	var controlPlain []byte
	defer func() {
		clear(envelope.Bytes())
		if resultErr != nil {
			clear(controlPlain)
			plain = nil
		}
	}()
	if _, err = readPublicationPayloadTo(bounded, store, envelopeIntent, envelopeVersion, verifier.ValidUntil(), &envelope); err != nil {
		return nil, err
	}
	bound, err := verifier.ForEnvelope(bounded, envelope.Bytes())
	if err != nil {
		return nil, err
	}
	cipherIntent, cipherVersion, err := s.originalPublishedPayload(bounded, claim, attempt, store, intent(cipherPath, expected.CipherSHA256, expected.CipherBytes))
	if err != nil {
		return nil, err
	}
	object, err := store.stat(bounded, cipherIntent.Key, cipherVersion, verifier.ValidUntil())
	if err != nil || object.Size != expected.CipherBytes {
		return nil, c.ErrExecutionRecord
	}
	reader, err := store.open(bounded, object, verifier.ValidUntil())
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	verified, err := w.InspectWrappedStream(bounded, w.StreamSpec{Request: i.ProviderKey.Request, Path: i.Request.ArtifactName, MaxPlaintextBytes: i.Request.MaxCompressedBytes, MaxFrames: i.FormalCapture.MaxFrames}, envelope.Bytes(), reader, bound, func(payload io.Reader) error {
		if i.Request.ControlEvidence == nil {
			return inspectOwnedBusinessPayload(bounded, i, original.Candidate, payload)
		}
		limit := int64(ce.MaxBytes)
		if expected.Part == ce.ProofPart {
			limit = ce.MaxProofBytes
		} else if expected.Part != ce.Part {
			return c.ErrExecutionRecord
		}
		controlPlain, err = io.ReadAll(io.LimitReader(payload, limit+1))
		if err != nil || int64(len(controlPlain)) > limit {
			return c.ErrExecutionRecord
		}
		return nil
	})
	closeErr := reader.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil || verified.CiphertextSHA256() != expected.CipherSHA256 || verified.CiphertextBytes() != expected.CipherBytes || verifier.Recheck(bounded) != nil {
		return nil, c.ErrExecutionRecord
	}
	current, err := s.publicationStore(bounded)
	if err != nil {
		return nil, err
	}
	defer current.Close()
	if current.config != store.config {
		return nil, c.ErrExecutionAuthority
	}
	if _, err = current.credential(false); err != nil {
		return nil, err
	}
	return controlPlain, nil
}

func (s *DeploymentService) verifyRemotePublicationCapture(ctx context.Context, claim *c.ClaimToken, attempt uint64, policy c.LeasePolicy, store *nativePublicationS3, capture publicationVerifiedCapture) error {
	if claim == nil || !capture.checked() {
		return c.ErrExecutionRecord
	}
	var sidecar, proofs []byte
	defer func() { clear(sidecar); clear(proofs) }()
	for _, part := range capture.Parts {
		fresh, err := (c.ClaimCoordinator{Executor: s.publisherVerifierDB, InstallationID: s.Config.InstallationID}).Renew(ctx, *claim, policy)
		if err != nil {
			return err
		}
		*claim = fresh
		plain, err := s.readRemotePublicationPart(ctx, *claim, attempt, store, part)
		if err != nil {
			return err
		}
		if part.Part == ce.Part {
			sidecar = plain
		} else if part.Part == ce.ProofPart {
			proofs = plain
		} else {
			clear(plain)
		}
	}
	prepared, err := ce.VerifyFinalizedBytes(ctx, capture.ControlSeed, sidecar, proofs)
	if err != nil {
		return err
	}
	defer clear(prepared.SidecarJSON)
	defer clear(prepared.ProofsJSON)
	got, _ := ce.Canonical(prepared.Locator)
	want, _ := ce.Canonical(capture.Control)
	if !bytes.Equal(got, want) {
		return c.ErrExecutionRecord
	}
	return nil
}
