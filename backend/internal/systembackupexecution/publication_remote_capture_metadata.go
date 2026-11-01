package systembackupexecution

import (
	"bytes"
	"context"
	"io"
	"sort"
	"time"

	"clawreef/internal/systembackup/worker"
	cd "clawreef/internal/systembackupcapturedescription"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	pc "clawreef/internal/systembackuppartcontainer"
	security "clawreef/internal/systembackupsecurity"
	w "clawreef/internal/systembackupwire"
)

const remoteCaptureDescriptionPart = cd.Part
const remoteCaptureDescriptionOperation = cd.Operation
const remoteCaptureBootstrapPath = cd.BootstrapPath
const remoteCaptureBootstrapVersion = cd.BootstrapVersion

// The authenticated original capture determines the layout. Object counts or
// an untrusted remote declaration cannot opt an old capture into new semantics
// or downgrade a description-bearing original to the legacy ten-object path.
func originalRemoteCaptureHasDescription(capture publicationVerifiedCapture) (bool, error) {
	if !capture.checked() {
		return false, c.ErrExecutionRecord
	}
	seen := map[string]bool{}
	description := false
	for _, part := range capture.Parts {
		if seen[part.Part] {
			return false, c.ErrExecutionRecord
		}
		seen[part.Part] = true
		if part.Part == remoteCaptureDescriptionPart {
			if part.Operation != remoteCaptureDescriptionOperation || part.RequestedPart != "" || part.CipherPath != "control/capture-description.json.enc" || part.EnvelopePath != "control/capture-description.envelope.json" {
				return false, c.ErrExecutionRecord
			}
			description = true
		} else if part.Operation == remoteCaptureDescriptionOperation {
			return false, c.ErrExecutionRecord
		}
	}
	if !seen[ce.Part] || !seen[ce.ProofPart] {
		return false, c.ErrExecutionRecord
	}
	if description != formalCandidateDigest(capture.DescriptionSHA256) || !description && capture.DescriptionSHA256 != "" {
		return false, c.ErrExecutionRecord
	}
	return description, nil
}

// Called only inside the independently authenticated remote C stream, while
// the caller holds the original seed's process-memory admission. This parser
// consumes no local staging plaintext and reconstructs no capture authority.
func inspectOriginalRemoteDescription(ctx context.Context, plaintext io.Reader, capture publicationVerifiedCapture, carrier worker.Invocation) error {
	if ctx == nil || ctx.Err() != nil || plaintext == nil || !capture.checked() || carrier.Request.CaptureDescription == nil || carrier.Request.CaptureDescription.Validate() != nil || carrier.Request.MaxArchiveBytes != carrier.Request.CaptureDescription.MaxPlaintextBytes {
		return c.ErrExecutionRecord
	}
	raw, err := io.ReadAll(io.LimitReader(plaintext, carrier.Request.MaxArchiveBytes+1))
	defer clear(raw)
	if err != nil || int64(len(raw)) > carrier.Request.MaxArchiveBytes || hash(raw) != capture.DescriptionSHA256 {
		return c.ErrExecutionRecord
	}
	description, err := cd.Decode(raw, *carrier.Request.CaptureDescription)
	if err != nil {
		return err
	}
	defer description.Clear()
	expectedScope := cd.Scope{InstallationID: capture.Input.InstallationID, TaskPublicID: capture.Input.TaskPublicID, ConfigVersion: capture.Input.ConfigVersion, ConfigSHA256: capture.Input.ConfigSHA256, AttemptNo: capture.Input.CaptureAttemptNo, CaptureContextSHA256: capture.CaptureContextSHA256}
	if description.Scope != expectedScope || validateDescriptionContents(description, carrier) != nil || description.SourceInventorySHA256 != capture.Input.SourceSHA256 || !bytes.Equal(description.SourceInventoryJSON, capture.Input.SourceSnapshot) || len(description.Members)+3 != len(capture.Parts) {
		return c.ErrExecutionRecord
	}
	parts := map[string]publicationVerifiedPart{}
	for _, part := range capture.Parts {
		parts[part.Part] = part
	}
	for _, member := range description.Members {
		part, exists := parts[member.Part]
		if !exists || part.RequestedPart == "" || part.Operation != member.Operation || part.Index != member.PartIndex || part.InvocationSHA256 != member.SHA256 || part.CandidateSHA256 != member.CandidateSHA256 || part.ResultSHA256 != member.ResultSHA256 {
			return c.ErrExecutionRecord
		}
	}
	seed, err := ce.Canonical(capture.ControlSeed)
	if err != nil {
		return err
	}
	for index, inv := range description.AdministrativeInvocations {
		part, exists := parts[inv.Part]
		if !exists || part.RequestedPart != "" || part.Operation != inv.Operation || part.Index != inv.PartIndex || part.InvocationSHA256 != inv.SHA256 {
			return c.ErrExecutionRecord
		}
		if index > 0 {
			var original worker.Invocation
			if decodeProviderDeploymentJSON(inv.JSON, &original) != nil || original.Request.ControlEvidence == nil {
				return c.ErrExecutionRecord
			}
			got, err := ce.Canonical(*original.Request.ControlEvidence)
			if err != nil || !bytes.Equal(got, seed) {
				return c.ErrExecutionRecord
			}
		}
	}
	return ctx.Err()
}

// The container index has thirteen entries, unlike the old per-member index.
// Its hashes still need all remote C/domain checks before a capture receipt.
func originalRemoteContainerIndex(capture publicationVerifiedCapture, objects publicationRemoteContainerObjects, bootstrap []byte) ([]byte, error) {
	description, err := originalRemoteCaptureHasDescription(capture)
	if err != nil || !description || len(bootstrap) == 0 || len(bootstrap) > 3*(64<<10)+4096 {
		return nil, c.ErrExecutionRecord
	}
	index := publicationArtifactIndex{Version: "system-backup-artifact-index.v1", Backup: capture.Input.TaskPublicID, Attempt: capture.Input.CaptureAttemptNo, CaptureContext: capture.CaptureContextSHA256, Entries: []publicationArtifactEntry{}}
	for _, name := range []string{"mysql", "redis", "object_storage", "workspace", "deployment_resources", "secret_bundle"} {
		object, exists := objects.Containers[name]
		if !exists {
			return nil, c.ErrExecutionRecord
		}
		index.Entries = append(index.Entries, publicationArtifactEntry{Path: "parts/" + name + "/container.enc", Role: "encrypted_payload", Size: object.Size, SHA256: object.SHA256, Framing: pc.Version})
	}
	admin := 0
	for _, part := range capture.Parts {
		if part.Part != remoteCaptureDescriptionPart && part.Part != ce.Part && part.Part != ce.ProofPart {
			continue
		}
		admin++
		index.Entries = append(index.Entries, publicationArtifactEntry{Path: part.CipherPath, Role: "control_evidence", Size: part.CipherBytes, SHA256: part.CipherSHA256, Framing: w.FramingVersion}, publicationArtifactEntry{Path: part.EnvelopePath, Role: "envelope", Size: part.EnvelopeBytes, SHA256: part.EnvelopeSHA256, Framing: w.EnvelopeVersion})
	}
	if admin != 3 {
		return nil, c.ErrExecutionRecord
	}
	index.Entries = append(index.Entries, publicationArtifactEntry{Path: remoteCaptureBootstrapPath, Role: "control_evidence", Size: int64(len(bootstrap)), SHA256: hash(bootstrap), Framing: remoteCaptureBootstrapVersion})
	sort.Slice(index.Entries, func(i, j int) bool { return index.Entries[i].Path < index.Entries[j].Path })
	return ce.Canonical(index)
}

func (s *DeploymentService) verifyOriginalRemoteCaptureMetadata(ctx context.Context, claim *c.ClaimToken, attempt uint64, policy c.LeasePolicy, capture publicationVerifiedCapture, objects publicationRemoteContainerObjects, reader *ArtifactReadOnlyS3, renew func() (*security.SQLPublisherCaptureAuthority, error)) error {
	if _, err := renew(); err != nil {
		return err
	}
	certificate, known, err := s.loadOriginalPublicationCaptureCertificate(ctx, *claim, attempt, capture)
	if err != nil || !known || !certificate.checked(capture, time.Now()) {
		return c.ErrExecutionRecord
	}
	bootstrap, err := s.prepareOriginalPublicationBootstrap(ctx, claim, attempt, policy, capture)
	if err != nil {
		return err
	}
	index, err := originalRemoteContainerIndex(capture, objects, bootstrap)
	if err != nil {
		return err
	}
	all := make(map[string]ArtifactReadObject, 15)
	for part, object := range objects.Containers {
		all["parts/"+part+"/container.enc"] = object
	}
	for path, object := range objects.Control {
		all[path] = object
	}
	for path, object := range objects.Metadata {
		if _, exists := all[path]; exists {
			return c.ErrExecutionRecord
		}
		all[path] = object
	}
	set, err := selectPublicationRemoteCaptureSet(capture.Input.InstallationID, capture.Input.TaskPublicID, attempt, reader.store.config.Root, capture.CaptureContextSHA256, index, hash(index), all, reader.limits)
	if err != nil {
		return err
	}
	for _, entry := range []struct {
		path     string
		expected []byte
	}{{"artifact-index.json", index}, {"control/capture-certificate.json", certificate.bytes}, {remoteCaptureBootstrapPath, bootstrap}} {
		object := set.objects[entry.path]
		if object.SHA256 != hash(entry.expected) || object.Size != int64(len(entry.expected)) {
			return c.ErrExecutionRecord
		}
		access, err := renew()
		if err != nil {
			return err
		}
		raw, observed, err := reader.readVersionedBytes(ctx, object.Key, object.Version, object.SHA256, object.Size, access.ValidUntil())
		matches := err == nil && observed == object && bytes.Equal(raw, entry.expected) && access.Check(ctx) == nil
		clear(raw)
		if !matches {
			return c.ErrExecutionRecord
		}
	}
	// Current signed history and original SQL are rechecked after native I/O.
	again, known, err := s.loadOriginalPublicationCaptureCertificate(ctx, *claim, attempt, capture)
	if err != nil || !known || !again.checked(capture, time.Now()) || again.sha256 != certificate.sha256 || !bytes.Equal(again.bytes, certificate.bytes) {
		return c.ErrExecutionRecord
	}
	// Renewal independently rechecks the caller's full original target and
	// configured budgets; the narrowed read-only transport DTO is not authority.
	_, err = renew()
	return err
}
