package worker

import (
	"context"
	"io"
	"strconv"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
)

func controlEvidenceOperation(operation string) bool { return operation == ce.Operation }

// Intrinsic shape only. Live deadline/claim/source/key-use checks remain at
// actual execution boundaries, so an expired original worker still has
// authenticated history readable by an independently authorized publisher.
func validControlEvidenceRequest(r Request) bool {
	if !controlEvidenceOperation(r.Operation) || r.Version != Version || r.Deadline.IsZero() || r.ControlEvidence == nil || r.ControlEvidence.Validate() != nil || r.SourceRedis != nil || r.SkillObjects != nil || r.SkillWorkspace != nil || r.Teams != nil || r.Resources != nil || r.Database != nil || r.RuntimePolicy != nil || r.WorkBuddyIdentity != nil || r.TeamWorkspace != nil || r.PolicyVersion != "" || len(r.Files) != 0 || r.MaxFiles != 0 || r.MaxFileBytes != 0 {
		return false
	}
	locator := r.ControlEvidence
	if locator.Expected.Backup != r.Binding.BackupID || r.Binding.Attempt != strconv.FormatUint(locator.Expected.Attempt, 10) {
		return false
	}
	limit := int64(ce.MaxBytes)
	if r.Binding.Path == ce.Part {
		if r.ArtifactName != ce.LogicalCipherName {
			return false
		}
	} else if r.Binding.Path == ce.ProofPart {
		if r.ArtifactName != ce.LogicalProofCipherName {
			return false
		}
		limit = ce.MaxProofBytes
	} else {
		return false
	}
	return r.MaxArchiveBytes == limit && r.MaxCompressedBytes == limit
}

func captureControlEvidence(ctx context.Context, i Invocation, source *ControlEvidenceCaptureSources, dst io.Writer, check func() error) error {
	if source == nil || dst == nil || check == nil || !validControlEvidenceRequest(i.Request) || !time.Now().Before(i.Request.Deadline) || check() != nil || source.Authorize(ctx, i) != nil {
		return ErrNotReady
	}
	prepared, err := source.Read(ctx, i)
	if err != nil {
		return err
	}
	defer clear(prepared.SidecarJSON)
	defer clear(prepared.ProofsJSON)
	payload := prepared.SidecarJSON
	expected := i.Request.ControlEvidence.SidecarSHA256
	if i.Request.Binding.Path == ce.ProofPart {
		payload = prepared.ProofsJSON
		expected = i.Request.ControlEvidence.ProofsSHA256
	}
	if int64(len(payload)) > i.Request.MaxArchiveBytes || ce.SHA256(payload) != expected {
		return ErrExecution
	}
	// Canonical JSON goes directly into the ORIGINAL C frame writer. No
	// plaintext tar/gzip/temp file, environment variable or ConfigMap is made.
	for offset := 0; offset < len(payload); {
		if ctx.Err() != nil || check() != nil || source.Authorize(ctx, i) != nil {
			return ErrNotReady
		}
		end := offset + (64 << 10)
		if end > len(payload) {
			end = len(payload)
		}
		n, err := dst.Write(payload[offset:end])
		if err != nil || n != end-offset {
			return ErrExecution
		}
		offset = end
	}
	if check() != nil || source.Authorize(ctx, i) != nil {
		return ErrNotReady
	}
	return nil
}
