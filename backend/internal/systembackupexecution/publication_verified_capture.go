package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
	w "clawreef/internal/systembackupwire"
)

// Private, inert assembly facts. They carry no old claim, DEK or live verifier.
// Every remote upload/readback still needs its own current original authority.
type publicationVerifiedPart struct {
	Part, Category, Operation, RequestedPart               string
	Index                                                  uint32
	InvocationSHA256, CandidateSHA256, ResultSHA256        string
	CipherPath, EnvelopePath, CipherSHA256, EnvelopeSHA256 string
	CipherBytes, EnvelopeBytes                             int64
	ResultEvidenceIDs                                      []string
	Checkpoint                                             json.RawMessage
	ResultEvidenceRef                                      string
}

type publicationVerifiedCapture struct {
	Input                                                 c.HistoricalCaptureInput
	PlanSHA256, CaptureResultSHA256, CaptureContextSHA256 string
	Parts                                                 []publicationVerifiedPart
	Control                                               ce.CaptureLocator
	ControlSeed                                           ce.CaptureLocator
	SourceFacts                                           productionPublicationSourceFacts
	receipt                                               *publicationVerifiedCaptureReceipt
}

type publicationVerifiedCaptureReceipt struct{ sha256 string }

func (capture publicationVerifiedCapture) checked() bool {
	if capture.receipt == nil {
		return false
	}
	return publicationVerifiedCaptureHash(capture) == capture.receipt.sha256
}

func publicationVerifiedCaptureHash(capture publicationVerifiedCapture) string {
	// RawMessage compaction must not hide changes to the exact frozen bytes.
	checkpoints := make([][]byte, 0, len(capture.Parts))
	for _, part := range capture.Parts {
		checkpoints = append(checkpoints, []byte(part.Checkpoint))
	}
	raw, err := json.Marshal(struct {
		Capture        publicationVerifiedCapture
		Config, Source []byte
		Checkpoints    [][]byte
	}{capture, capture.Input.ConfigSnapshot, capture.Input.SourceSnapshot, checkpoints})
	if err != nil {
		return ""
	}
	return hash(raw)
}

func publicationRequestedPart(operation string) string {
	switch operation {
	case "capture-database":
		return "mysql"
	case "capture-source-redis", "capture-team-redis":
		return "redis"
	case "capture-skill-objects", "capture-team-objects":
		return "object_storage"
	case "capture-workspace":
		return "workspace"
	case "capture-deployment-resources":
		return "deployment_resources"
	case "capture-secret-bundle":
		return "secret_bundle"
	}
	return ""
}

// The complete locator list is independently loaded from the ORIGINAL sealed
// encrypted plan. Every part then opens its own current publisher Unwrap and
// complete inert reader. Explicit claim renewal happens only after closing the
// previous verifier/files; no old object or DEK adopts the renewed claim.
func (s *DeploymentService) verifyOriginalPublicationCapture(ctx context.Context, claim *c.ClaimToken, attempt uint64, policy c.LeasePolicy) (publicationVerifiedCapture, error) {
	var zero publicationVerifiedCapture
	if s == nil || claim == nil || policy.Validate() != nil || s.checkPublisherVerifierBinding(ctx) != nil || claim.Owner != s.PublisherOwner {
		return zero, c.ErrExecutionAuthority
	}
	scope := security.PublisherCaptureScope{BackupPublicID: claim.Target.PublicID, Claim: security.SQLSigningClaim{ControllerOwner: claim.Owner, RowVersion: claim.RowVersion}, CaptureAttemptNo: attempt}
	names, err := s.publisherVerifierFactory.CaptureParts(ctx, scope)
	if err != nil {
		return zero, err
	}
	if len(names) < 8 || len(names) > 10000 {
		return zero, c.ErrExecutionRecord
	}
	seen := map[string]bool{}
	for _, name := range names {
		seen[name] = true
	}
	if !seen[ce.Part] || !seen[ce.ProofPart] {
		return zero, c.ErrExecutionRecord
	}
	var result publicationVerifiedCapture
	var sidecar, proofs []byte
	defer func() { clear(sidecar); clear(proofs) }()
	var originalInput []byte
	indices := map[uint32]bool{}
	requests := map[string]bool{}
	for index, name := range names {
		if index != 0 {
			fresh, err := (c.ClaimCoordinator{Executor: s.publisherVerifierDB, InstallationID: s.Config.InstallationID}).Renew(ctx, *claim, policy)
			if err != nil {
				return zero, err
			}
			*claim = fresh
		}
		part, err := s.openPublicationCaptureFiles(ctx, *claim, attempt, name)
		if err != nil {
			return zero, err
		}
		err = func() error {
			defer part.Close()
			record, invocation := part.record, part.record.Invocation
			input, err := json.Marshal(record.Input)
			if err != nil || invocation.ProviderKey == nil || record.Input.CaptureAttemptNo != attempt || indices[invocation.Request.Binding.PartIndex] {
				return c.ErrExecutionRecord
			}
			indices[invocation.Request.Binding.PartIndex] = true
			if index == 0 {
				originalInput = input
				result.Input, result.PlanSHA256, result.CaptureResultSHA256, result.CaptureContextSHA256 = record.Input, record.Plan.SHA256, record.CaptureResultSHA256, invocation.Request.Binding.CaptureContextHash
			} else if !bytes.Equal(input, originalInput) || record.Plan.SHA256 != result.PlanSHA256 || record.CaptureResultSHA256 != result.CaptureResultSHA256 || invocation.Request.Binding.CaptureContextHash != result.CaptureContextSHA256 {
				return c.ErrExecutionRecord
			}
			invSHA, err := invocation.Hash()
			if err != nil || invSHA != part.candidate.InvocationSHA256 {
				return c.ErrExecutionRecord
			}
			resultRaw, err := json.Marshal(record.PartResult)
			if err != nil {
				return c.ErrExecutionRecord
			}
			requested := publicationRequestedPart(invocation.Request.Operation)
			if requested == "" {
				seed := invocation.Request.ControlEvidence
				if seed == nil || seed.Finalization == nil || seed.Validate() != nil || seed.Finalization.CaptureContextSHA256 != result.CaptureContextSHA256 || name != ce.Part && name != ce.ProofPart {
					return c.ErrExecutionRecord
				}
				seedRaw, _ := ce.Canonical(*seed)
				if result.ControlSeed.Finalization == nil {
					result.ControlSeed = *seed
				} else {
					expected, _ := ce.Canonical(result.ControlSeed)
					if !bytes.Equal(seedRaw, expected) {
						return c.ErrExecutionRecord
					}
				}
				if name == ce.Part {
					sidecar = bytes.Clone(part.controlPlain)
				} else {
					proofs = bytes.Clone(part.controlPlain)
				}
			} else {
				if !part.domainVerified || invocation.Request.ControlEvidence != nil {
					return c.ErrExecutionRecord
				}
				requests[requested] = true
			}
			cipherPath, envelopePath := publicationPartPaths(name, invocation.Request.Binding.PartIndex, invSHA)
			result.Parts = append(result.Parts, publicationVerifiedPart{Part: name, Category: record.PartResult.Category, Operation: invocation.Request.Operation, RequestedPart: requested, Index: invocation.Request.Binding.PartIndex, InvocationSHA256: invSHA, CandidateSHA256: record.CandidateSHA256, ResultSHA256: hash(resultRaw), CipherPath: cipherPath, EnvelopePath: envelopePath, CipherSHA256: part.stream.CiphertextSHA256(), EnvelopeSHA256: hash(part.envelope), CipherBytes: part.stream.CiphertextBytes(), EnvelopeBytes: int64(len(part.envelope)), ResultEvidenceIDs: append([]string{}, record.PartResult.EvidenceIDs...), Checkpoint: bytes.Clone(record.PartResult.Checkpoint)})
			result.Parts[len(result.Parts)-1].ResultEvidenceRef = resultEvidenceCoordinates(record.Input.InstallationID, record.Input.TaskPublicID, record.Input.CaptureAttemptNo, "capture", record.Job, hash(resultRaw)).PublicID
			return part.check(ctx)
		}()
		if err != nil {
			return zero, err
		}
	}
	if len(requests) != 6 || len(result.Input.Backup.RequestedParts) != 6 {
		return zero, c.ErrExecutionRecord
	}
	for _, name := range result.Input.Backup.RequestedParts {
		if !requests[name] {
			return zero, c.ErrExecutionRecord
		}
		delete(requests, name)
	}
	if len(requests) != 0 {
		return zero, c.ErrExecutionRecord
	}
	prepared, err := ce.VerifyFinalizedBytes(ctx, result.ControlSeed, sidecar, proofs)
	if err != nil {
		return zero, err
	}
	defer clear(prepared.SidecarJSON)
	defer clear(prepared.ProofsJSON)
	basis, err := ce.OriginalOwnedBasis(ctx, result.ControlSeed, prepared)
	if err != nil || len(basis.Parts) != len(result.Parts)-2 {
		return zero, c.ErrExecutionRecord
	}
	byPart := map[string]publicationVerifiedPart{}
	for _, part := range result.Parts {
		byPart[part.Part] = part
	}
	for _, expected := range basis.Parts {
		actual, ok := byPart[expected.Part]
		if !ok || actual.RequestedPart == "" || actual.Operation != expected.Operation || actual.InvocationSHA256 != expected.InvocationSHA256 || actual.CandidateSHA256 != expected.CandidateSHA256 || actual.ResultSHA256 != expected.ResultSHA256 || actual.ResultEvidenceRef != expected.ResultEvidenceRef || actual.CipherSHA256 != expected.CiphertextSHA256 || actual.EnvelopeSHA256 != expected.EnvelopeSHA256 || actual.CipherBytes != expected.CiphertextBytes {
			return zero, c.ErrExecutionRecord
		}
	}
	result.Control = prepared.Locator
	result.SourceFacts, err = publicationSourceFacts(result.Input, result.Control)
	if err != nil {
		return zero, err
	}
	sort.Slice(result.Parts, func(i, j int) bool { return result.Parts[i].Index < result.Parts[j].Index })
	for index, part := range result.Parts {
		if part.Index != uint32(index) {
			return zero, c.ErrExecutionRecord
		}
	}
	digest := publicationVerifiedCaptureHash(result)
	if digest == "" {
		return zero, c.ErrExecutionRecord
	}
	result.receipt = &publicationVerifiedCaptureReceipt{sha256: digest}
	return result, nil
}

type publicationArtifactIndex struct {
	Version        string                     `json:"schema_version"`
	Backup         string                     `json:"backup_public_id"`
	Attempt        uint64                     `json:"attempt_no"`
	CaptureContext string                     `json:"capture_context_hash"`
	Entries        []publicationArtifactEntry `json:"entries"`
}
type publicationArtifactEntry struct {
	Path    string `json:"path"`
	Role    string `json:"content_role"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
	Framing string `json:"framing_version"`
}

func (capture publicationVerifiedCapture) artifactIndex(maxBytes int64) ([]byte, error) {
	index := publicationArtifactIndex{Version: "system-backup-artifact-index.v1", Backup: capture.Input.TaskPublicID, Attempt: capture.Input.CaptureAttemptNo, CaptureContext: capture.CaptureContextSHA256, Entries: []publicationArtifactEntry{}}
	if !capture.checked() || maxBytes < 1<<20 || maxBytes > 8<<30 || len(capture.Parts) < 8 || capture.Control.Validate() != nil || capture.Control.Finalization != nil {
		return nil, c.ErrExecutionRecord
	}
	for _, part := range capture.Parts {
		role := "encrypted_payload"
		if part.Part == ce.Part || part.Part == ce.ProofPart {
			role = "control_evidence"
		}
		index.Entries = append(index.Entries, publicationArtifactEntry{part.CipherPath, role, part.CipherBytes, part.CipherSHA256, w.FramingVersion}, publicationArtifactEntry{part.EnvelopePath, "envelope", part.EnvelopeBytes, part.EnvelopeSHA256, w.EnvelopeVersion})
	}
	sort.Slice(index.Entries, func(i, j int) bool { return index.Entries[i].Path < index.Entries[j].Path })
	last := ""
	for _, entry := range index.Entries {
		if !safePublicationKey(entry.Path) || entry.Path <= last || entry.Size < 1 || !formalCandidateDigest(entry.SHA256) {
			return nil, c.ErrExecutionRecord
		}
		last = entry.Path
	}
	raw, err := ce.Canonical(index)
	if err != nil || int64(len(raw)) > maxBytes {
		return nil, c.ErrExecutionRecord
	}
	return raw, nil
}
