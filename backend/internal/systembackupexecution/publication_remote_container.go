package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"io"

	cd "clawreef/internal/systembackupcapturedescription"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	pc "clawreef/internal/systembackuppartcontainer"
	security "clawreef/internal/systembackupsecurity"
	w "clawreef/internal/systembackupwire"
)

// These locators are inert input. The private receipt below is minted only
// after independently reading and decrypting EVERY original remote C payload.
// This is current publication verification, never historical DR authority.
type publicationRemoteContainerObjects struct {
	Containers map[string]ArtifactReadObject
	Control    map[string]ArtifactReadObject
	Metadata   map[string]ArtifactReadObject
}

type publicationRemoteContainerReceipt struct {
	captureSHA256, objectsSHA256 string
	service                      *DeploymentService
	access                       *security.SQLPublisherCaptureAuthority
	claim                        c.ClaimToken
	attempt                      uint64
	target                       PublicationTargetMaterials
	limits                       ArtifactReadLimits
}

func (p *publicationRemoteContainerReceipt) checked(capture publicationVerifiedCapture, objects publicationRemoteContainerObjects) bool {
	if p == nil || !capture.checked() || p.captureSHA256 != publicationVerifiedCaptureHash(capture) {
		return false
	}
	raw, err := ce.Canonical(objects)
	return err == nil && p.objectsSHA256 == hash(raw)
}

// No Kube/provider/network operation occurs inside the returned guard's TX.
// Each explicit Renew discards previous access/verifier scopes first.
func (s *DeploymentService) remoteContainerReadScope(ctx context.Context, claim c.ClaimToken, attempt uint64, target PublicationTargetMaterials, limits ArtifactReadLimits) (*security.SQLPublisherCaptureAuthority, error) {
	current, err := s.publicationStore(ctx)
	if err != nil {
		return nil, err
	}
	current.Close()
	if current.config != target || current.catalog != nil {
		return nil, c.ErrExecutionAuthority
	}
	access, err := s.publicationAccess(ctx, claim, attempt)
	if err != nil || access.Check(ctx) != nil {
		return nil, c.ErrExecutionAuthority
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	guard, err := access.Bind(ctx, tx)
	if err != nil || s.checkPublicationTargetTx(ctx, tx, guard.Facts(), target) != nil {
		return nil, c.ErrExecutionAuthority
	}
	actual, err := readPublicationLimitsTx(ctx, tx, guard)
	if err != nil || actual != limits || guard.RecheckTx(ctx, tx) != nil {
		return nil, c.ErrExecutionAuthority
	}
	if err := tx.Rollback(); err != nil {
		return nil, err
	}
	return access, nil
}

func sameOriginalContainerMember(expected, actual pc.Member) bool {
	// Offsets are physical framing, checked by the complete container reader.
	// All original stream/checkpoint/path/hash/size fields must still match.
	expected.CipherOffset, expected.EnvelopeOffset = actual.CipherOffset, actual.EnvelopeOffset
	a, err := ce.Canonical(expected)
	b, otherErr := ce.Canonical(actual)
	return err == nil && otherErr == nil && bytes.Equal(a, b)
}

func (s *DeploymentService) inspectOriginalRemoteContainerMember(ctx context.Context, claim c.ClaimToken, attempt uint64, reader *ArtifactReadOnlyS3, object ArtifactReadObject, capture publicationVerifiedCapture, part publicationVerifiedPart, member pc.Member, location pc.MemberLocation) error {
	_, err := s.inspectOriginalRemoteContainerMemberRelations(ctx, claim, attempt, reader, object, capture, part, member, location, nil)
	return err
}

// Keep the SAME current verifier, envelope, authenticated stream and final
// Recheck. Only the finalizer selects the enhanced concrete content parser;
// ordinary callers keep their existing parser and receive no mutable hook.
// A record escapes only AFTER the full cipher/EOF and current recheck succeed.
func (s *DeploymentService) inspectOriginalRemoteContainerMemberRelations(ctx context.Context, claim c.ClaimToken, attempt uint64, reader *ArtifactReadOnlyS3, object ArtifactReadObject, capture publicationVerifiedCapture, part publicationVerifiedPart, member pc.Member, location pc.MemberLocation, relations *publicationFinalTeamRelations) (c.PublisherCaptureRecord, error) {
	return s.inspectOriginalRemoteContainerMemberSamples(ctx, claim, attempt, reader, object, capture, part, member, location, relations, nil)
}

func (s *DeploymentService) inspectOriginalRemoteContainerMemberSamples(ctx context.Context, claim c.ClaimToken, attempt uint64, reader *ArtifactReadOnlyS3, object ArtifactReadObject, capture publicationVerifiedCapture, part publicationVerifiedPart, member pc.Member, location pc.MemberLocation, relations *publicationFinalTeamRelations, samples *publicationContentSamples) (_ c.PublisherCaptureRecord, resultErr error) {
	// Authentication/provider/recheck failures occur outside the inert parser.
	// Invalidate this same round there too; a caller must not reuse prior facts.
	defer func() {
		if resultErr != nil {
			if relations != nil {
				relations.failed = true
			}
			if samples != nil {
				samples.clear()
			}
		}
	}()
	var zero c.PublisherCaptureRecord
	verifier, err := s.PublisherVerifierForPart(ctx, claim, attempt, part.Part)
	if err != nil {
		return zero, err
	}
	defer verifier.Close()
	bounded, cancel := context.WithDeadline(ctx, verifier.ValidUntil())
	defer cancel()
	record, err := verifier.CapturedRecord(bounded)
	if err != nil {
		return zero, err
	}
	original, candidate, err := publicationContainerMember(capture, part, record)
	if err != nil || !sameOriginalContainerMember(original, member) {
		return zero, c.ErrExecutionRecord
	}
	envelope, err := reader.ReadContainerEnvelope(bounded, object, member, location, verifier.ValidUntil())
	if err != nil {
		return zero, err
	}
	defer clear(envelope)
	bound, err := verifier.ForEnvelope(bounded, envelope)
	if err != nil {
		return zero, err
	}
	var observed ownedPayloadCounts
	_, err = reader.InspectContainerCipher(bounded, object, member, location, envelope, bound, func(plain io.Reader) error {
		if relations != nil {
			return inspectOwnedBusinessPayloadRelations(bounded, record.Invocation, candidate, plain, relations, &observed)
		}
		return inspectOwnedBusinessPayload(bounded, record.Invocation, candidate, plain)
	}, verifier.ValidUntil())
	if err != nil {
		return zero, err
	}
	if err = verifier.Recheck(bounded); err != nil {
		return zero, err
	}
	if relations != nil {
		if err = relations.confirmPart(record.Invocation); err != nil {
			return zero, err
		}
	}
	if samples != nil {
		if err = samples.confirm(record.Invocation, object, member, location, observed); err != nil {
			return zero, err
		}
	}
	return record, nil
}

func (s *DeploymentService) readOriginalRemoteContainerControl(ctx context.Context, claim c.ClaimToken, attempt uint64, reader *ArtifactReadOnlyS3, capture publicationVerifiedCapture, part publicationVerifiedPart, objects map[string]ArtifactReadObject) (_ []byte, resultErr error) {
	verifier, err := s.PublisherVerifierForPart(ctx, claim, attempt, part.Part)
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
	member, _, err := publicationContainerMember(capture, part, record)
	if err != nil || part.Part != remoteCaptureDescriptionPart && record.Invocation.Request.ControlEvidence == nil || part.Part == remoteCaptureDescriptionPart && record.Invocation.Request.Operation != remoteCaptureDescriptionOperation {
		return nil, c.ErrExecutionRecord
	}
	if part.Part == remoteCaptureDescriptionPart {
		if record.Invocation.Request.CaptureDescription == nil || s.publisherVerifier == nil || s.publisherVerifier.DescriptionMaxPlaintextBytes < record.Invocation.Request.MaxArchiveBytes || s.publisherVerifier.validateDescriptionMemoryDeclaration() != nil {
			return nil, cd.ErrMemoryDeclaration
		}
		release, err := cd.AdmitDecodeMemory(*record.Invocation.Request.CaptureDescription)
		if err != nil {
			return nil, err
		}
		defer release()
	}
	cipherObject, cipherOK := objects[part.CipherPath]
	envelopeObject, envelopeOK := objects[part.EnvelopePath]
	base := reader.store.config.Root + capture.Input.TaskPublicID + "/" + record.Invocation.ProviderKey.Request.Context.AttemptNo + "/"
	if !cipherOK || !envelopeOK || !fixedPublicationReadVersion(cipherObject.Version) || !fixedPublicationReadVersion(envelopeObject.Version) || cipherObject.Key != base+part.CipherPath || envelopeObject.Key != base+part.EnvelopePath || cipherObject.Size != part.CipherBytes || cipherObject.SHA256 != part.CipherSHA256 || envelopeObject.Size != part.EnvelopeBytes || envelopeObject.SHA256 != part.EnvelopeSHA256 || envelopeObject.Size > 32<<20 {
		return nil, c.ErrExecutionRecord
	}
	envelopeMetadata, err := reader.store.stat(bounded, envelopeObject.Key, envelopeObject.Version, verifier.ValidUntil())
	if err != nil || envelopeObject.Version == "" || envelopeMetadata.Size != envelopeObject.Size {
		return nil, c.ErrExecutionRecord
	}
	envelopeBody, err := reader.store.open(bounded, envelopeMetadata, verifier.ValidUntil())
	if err != nil {
		return nil, err
	}
	defer envelopeBody.Close()
	envelope, err := io.ReadAll(io.LimitReader(envelopeBody, envelopeObject.Size+1))
	envelopeCloseErr := envelopeBody.Close()
	if err != nil || envelopeCloseErr != nil || int64(len(envelope)) != envelopeObject.Size || hash(envelope) != envelopeObject.SHA256 {
		clear(envelope)
		return nil, c.ErrExecutionRecord
	}
	defer clear(envelope)
	bound, err := verifier.ForEnvelope(bounded, envelope)
	if err != nil {
		return nil, err
	}
	observed, err := reader.store.stat(bounded, cipherObject.Key, cipherObject.Version, verifier.ValidUntil())
	if err != nil || observed.Size != cipherObject.Size || cipherObject.Version == "" {
		return nil, c.ErrExecutionRecord
	}
	body, err := reader.store.open(bounded, observed, verifier.ValidUntil())
	if err != nil {
		return nil, err
	}
	defer body.Close()
	var controlPlain []byte
	defer func() {
		if resultErr != nil {
			clear(controlPlain)
		}
	}()
	verified, err := w.InspectWrappedStream(bounded, member.Stream, envelope, body, bound, func(src io.Reader) error {
		if part.Part == remoteCaptureDescriptionPart {
			return inspectOriginalRemoteDescription(bounded, src, capture, record.Invocation)
		}
		limit := int64(ce.MaxBytes)
		if part.Part == ce.ProofPart {
			limit = ce.MaxProofBytes
		} else if part.Part != ce.Part {
			return c.ErrExecutionRecord
		}
		controlPlain, err = io.ReadAll(io.LimitReader(src, limit+1))
		if err != nil || int64(len(controlPlain)) > limit {
			return c.ErrExecutionRecord
		}
		return nil
	})
	closeErr := body.Close()
	if err != nil || closeErr != nil || verified.CiphertextSHA256() != part.CipherSHA256 || verified.CiphertextBytes() != part.CipherBytes || verifier.Recheck(bounded) != nil {
		return nil, c.ErrExecutionRecord
	}
	if _, err := reader.store.credential(false); err != nil {
		return nil, err
	}
	return controlPlain, nil
}

// This mints only a private complete-remote-C receipt. Manifest/certificate
// semantics, independent cleanup and acceptance/catalog signing are additional
// mandatory inputs to the future finalization gate; this receipt grants none.
func (s *DeploymentService) verifyOriginalRemoteContainerCapture(ctx context.Context, claim *c.ClaimToken, attempt uint64, policy c.LeasePolicy, target PublicationTargetMaterials, capture publicationVerifiedCapture, objects publicationRemoteContainerObjects) (*publicationRemoteContainerReceipt, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || claim == nil || !capture.checked() || claim.Target.Kind != c.TargetBackup || claim.Target.PublicID != capture.Input.TaskPublicID || attempt != capture.Input.CaptureAttemptNo || policy.Validate() != nil || len(objects.Containers) != 6 {
		return nil, c.ErrExecutionAuthority
	}
	description, err := originalRemoteCaptureHasDescription(capture)
	if err != nil || !description && (len(objects.Control) != 4 || len(objects.Metadata) != 0) || description && (len(objects.Control) != 6 || len(objects.Metadata) != 3) {
		return nil, c.ErrExecutionRecord
	}
	encodedObjects, err := ce.Canonical(objects)
	if err != nil {
		return nil, c.ErrExecutionRecord
	}
	limits, err := s.publicationContainerLimits(ctx, *claim, attempt)
	if err != nil {
		return nil, err
	}
	reader, err := NewArtifactReadOnlyS3(artifactReadMaterials(target), limits)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	renew := func() (*security.SQLPublisherCaptureAuthority, error) {
		fresh, err := (c.ClaimCoordinator{Executor: s.publisherVerifierDB, InstallationID: s.Config.InstallationID}).Renew(ctx, *claim, policy)
		if err != nil {
			return nil, err
		}
		*claim = fresh
		return s.remoteContainerReadScope(ctx, *claim, attempt, target, limits)
	}
	if description {
		if err := s.verifyOriginalRemoteCaptureMetadata(ctx, claim, attempt, policy, capture, objects, reader, renew); err != nil {
			return nil, err
		}
	}
	seen := map[string]bool{}
	var total int64
	for _, object := range objects.Control {
		if object.Size < 1 || object.Size > limits.MaxArtifactBytes-total {
			return nil, c.ErrExecutionRecord
		}
		total += object.Size
	}
	for _, requested := range []string{"mysql", "redis", "object_storage", "workspace", "deployment_resources", "secret_bundle"} {
		object, ok := objects.Containers[requested]
		if !ok || object.Size < 1 || object.Size > limits.MaxArtifactBytes-total {
			return nil, c.ErrExecutionRecord
		}
		total += object.Size
		access, err := renew()
		if err != nil {
			return nil, err
		}
		checkpoints := map[string]string{}
		parts := map[string]publicationVerifiedPart{}
		for _, part := range capture.Parts {
			if part.RequestedPart == requested {
				sum, err := pcCheckpointSHA(part.Checkpoint)
				if err != nil || parts[part.Part].Part != "" {
					return nil, c.ErrExecutionRecord
				}
				checkpoints[part.Part], parts[part.Part] = sum, part
			}
		}
		scope := pc.Scope{Installation: capture.Input.InstallationID, Backup: capture.Input.TaskPublicID, Attempt: attempt, ConfigVersion: capture.Input.ConfigVersion, ConfigSHA256: capture.Input.ConfigSHA256, CaptureContextSHA256: capture.CaptureContextSHA256, Part: requested}
		facts, err := reader.InspectPartContainer(ctx, object, scope, checkpoints, access.ValidUntil())
		if err != nil || facts.Header.SourceInventorySHA256 != capture.Input.SourceSHA256 || len(facts.Header.Members) != len(parts) || access.Check(ctx) != nil {
			return nil, c.ErrExecutionRecord
		}
		for index, member := range facts.Header.Members {
			part, ok := parts[member.Part]
			if !ok || seen[member.Part] {
				return nil, c.ErrExecutionRecord
			}
			if _, err := renew(); err != nil {
				return nil, err
			}
			if err := s.inspectOriginalRemoteContainerMember(ctx, *claim, attempt, reader, object, capture, part, member, facts.Locations[index]); err != nil {
				return nil, err
			}
			seen[member.Part] = true
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
		if _, err := renew(); err != nil {
			return nil, err
		}
		plain, err := s.readOriginalRemoteContainerControl(ctx, *claim, attempt, reader, capture, part, objects.Control)
		if err != nil {
			return nil, err
		}
		if part.Part == remoteCaptureDescriptionPart {
			clear(plain)
		} else if part.Part == ce.Part {
			sidecar = plain
		} else {
			proofs = plain
		}
		seen[part.Part] = true
	}
	if len(seen) != len(capture.Parts) {
		return nil, c.ErrExecutionRecord
	}
	prepared, err := ce.VerifyFinalizedBytes(ctx, capture.ControlSeed, sidecar, proofs)
	if err != nil {
		return nil, err
	}
	defer clear(prepared.SidecarJSON)
	defer clear(prepared.ProofsJSON)
	got, err := ce.Canonical(prepared.Locator)
	want, wantErr := ce.Canonical(capture.Control)
	currentObjects, objectErr := ce.Canonical(objects)
	if err != nil || wantErr != nil || objectErr != nil || !bytes.Equal(got, want) || !bytes.Equal(encodedObjects, currentObjects) {
		return nil, c.ErrExecutionRecord
	}
	if _, err := s.remoteContainerReadScope(ctx, *claim, attempt, target, limits); err != nil {
		return nil, err
	}
	if description {
		// Re-read the same certificate/bootstrap/index after all C semantics,
		// under the final current claim/config before minting the private receipt.
		if err := s.verifyOriginalRemoteCaptureMetadata(ctx, claim, attempt, policy, capture, objects, reader, renew); err != nil {
			return nil, err
		}
	}
	// Keep the exact final authority; a later Renew cannot adopt this receipt.
	access, err := s.remoteContainerReadScope(ctx, *claim, attempt, target, limits)
	if err != nil {
		return nil, err
	}
	return &publicationRemoteContainerReceipt{captureSHA256: publicationVerifiedCaptureHash(capture), objectsSHA256: hash(encodedObjects), service: s, access: access, claim: *claim, attempt: attempt, target: target, limits: limits}, nil
}
