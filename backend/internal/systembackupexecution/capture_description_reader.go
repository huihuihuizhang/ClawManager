package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strconv"

	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/worker"
	cd "clawreef/internal/systembackupcapturedescription"
	c "clawreef/internal/systembackupcontroller"
)

// Pure historical semantics, never a current Authority/claim/permit resolver.
// The caller supplies independent original-plan/AEAD/checkpoint authentication.
func validateDescriptionContents(description cd.Description, carrier worker.Invocation) error {
	if description.Validate() != nil || carrier.Request.CaptureDescription == nil || carrier.ProviderKey == nil || carrier.FormalCapture == nil {
		return c.ErrExecutionRecord
	}
	sha, err := carrier.Hash()
	if err != nil || description.AdministrativeInvocations[0].SHA256 != sha {
		return c.ErrExecutionRecord
	}
	scope := description.Scope
	if scope.InstallationID != carrier.ProviderKey.Request.Context.InstallationID || scope.TaskPublicID != carrier.Request.Binding.BackupID || strconv.FormatUint(scope.AttemptNo, 10) != carrier.Request.Binding.Attempt || scope.CaptureContextSHA256 != carrier.Request.Binding.CaptureContextHash || scope.ConfigSHA256 != carrier.FormalCapture.SourceConfigSHA256 {
		return c.ErrExecutionRecord
	}
	validateInvocation := func(v cd.Invocation) (worker.Invocation, error) {
		var inv worker.Invocation
		if decodeProviderDeploymentJSON(v.JSON, &inv) != nil || !worker.ValidateRecordedInvocation(inv) || inv.ProviderKey == nil || inv.FormalCapture == nil {
			return inv, c.ErrExecutionRecord
		}
		got, err := inv.Hash()
		b := inv.Request.Binding
		k := inv.ProviderKey.Request.Context
		if err != nil || got != v.SHA256 || v.Part != b.Path || v.PartIndex != b.PartIndex || v.Operation != inv.Request.Operation || b.BackupID != scope.TaskPublicID || b.Attempt != strconv.FormatUint(scope.AttemptNo, 10) || b.CaptureContextHash != scope.CaptureContextSHA256 || k.InstallationID != scope.InstallationID || k.BackupPublicID != scope.TaskPublicID || k.AttemptNo != b.Attempt || k.Part != b.Path || k.PartIndex != strconv.FormatUint(uint64(b.PartIndex), 10) || k.CaptureContextHash != scope.CaptureContextSHA256 || k.Phase != "capture" {
			return inv, c.ErrExecutionRecord
		}
		return inv, nil
	}
	for _, m := range description.Members {
		inv, err := validateInvocation(m.Invocation)
		if err != nil {
			return err
		}
		var wrapper FormalCandidateRecord
		if decodeProviderDeploymentJSON(m.CandidateJSON, &wrapper) != nil || wrapper.Version != "public-formal-candidate-record.v1" || wrapper.InvocationSHA256 != m.SHA256 || !worker.ValidateFormalCaptureResult(inv, &wrapper.Candidate) || wrapper.Authority.InstallationID != scope.InstallationID || wrapper.Authority.TaskPublicID != scope.TaskPublicID || wrapper.Authority.ConfigVersion != scope.ConfigVersion || wrapper.Authority.ConfigSHA256 != scope.ConfigSHA256 || wrapper.Authority.AttemptNo != scope.AttemptNo || wrapper.Authority.Phase != "capture" || wrapper.Authority.TaskType != "backup" || wrapper.Job.UID == "" || wrapper.Job.Generation < 1 || wrapper.Pod.Namespace != wrapper.Job.Namespace || wrapper.Pod.UID == "" || wrapper.Pod.Name == "" || wrapper.Pod.ServiceAccountUID == "" || len(wrapper.KeyUseNonce) != 32 || !formalCandidateDigest(wrapper.ExecutionGrantSHA256) {
			return c.ErrExecutionRecord
		}
	}
	var controlSeed []byte
	for index, v := range description.AdministrativeInvocations {
		inv, err := validateInvocation(v)
		if err != nil {
			return err
		}
		if index == 0 {
			left, _ := json.Marshal(inv.Request.CaptureDescription)
			right, _ := json.Marshal(carrier.Request.CaptureDescription)
			if !bytes.Equal(left, right) {
				return c.ErrExecutionRecord
			}
			continue
		}
		seed := inv.Request.ControlEvidence
		if seed == nil || seed.Finalization == nil || seed.Finalization.CaptureContextSHA256 != scope.CaptureContextSHA256 || len(seed.Finalization.Parts) != len(description.Members) || seed.Expected.Installation != scope.InstallationID || seed.Expected.Backup != scope.TaskPublicID || seed.Expected.Attempt != scope.AttemptNo || seed.Expected.ConfigSHA256 != scope.ConfigSHA256 {
			return c.ErrExecutionRecord
		}
		for i, p := range seed.Finalization.Parts {
			m := description.Members[i]
			if p.Part != m.Part || p.Operation != m.Operation || p.InvocationSHA256 != m.SHA256 {
				return c.ErrExecutionRecord
			}
		}
		raw, _ := json.Marshal(seed)
		if index == 1 {
			controlSeed = raw
		} else if !bytes.Equal(raw, controlSeed) {
			return c.ErrExecutionRecord
		}
	}
	return nil
}

func inspectOriginalDescriptionPart(ctx context.Context, plaintext io.Reader, carrier worker.Invocation, original *b.Discovery, expected cd.Scope) error {
	if carrier.Request.CaptureDescription == nil {
		return c.ErrExecutionRecord
	}
	release, err := cd.AdmitDecodeMemory(*carrier.Request.CaptureDescription)
	if err != nil {
		return err
	}
	defer release()
	return inspectOriginalDescriptionPartAdmitted(ctx, plaintext, carrier, original, expected)
}

// Caller retains the shared memory admission through all decoded buffers.
func inspectOriginalDescriptionPartAdmitted(ctx context.Context, plaintext io.Reader, carrier worker.Invocation, original *b.Discovery, expected cd.Scope) error {
	if ctx == nil || ctx.Err() != nil || plaintext == nil || carrier.Request.CaptureDescription == nil {
		return c.ErrExecutionRecord
	}
	raw, err := io.ReadAll(io.LimitReader(plaintext, carrier.Request.MaxArchiveBytes+1))
	defer clear(raw)
	if err != nil || int64(len(raw)) > carrier.Request.MaxArchiveBytes {
		return c.ErrExecutionRecord
	}
	description, err := cd.Decode(raw, *carrier.Request.CaptureDescription)
	if err != nil {
		return err
	}
	defer description.Clear()
	if description.Scope != expected || validateDescriptionContents(description, carrier) != nil {
		return c.ErrExecutionRecord
	}
	if original != nil {
		admin, err := descriptionPlan(description.Seed, original.Parts)
		if err != nil || !bytes.Equal(description.SourceInventoryJSON, original.Source) || description.SourceInventorySHA256 != original.SourceSHA256 {
			return c.ErrExecutionRecord
		}
		for index, inv := range admin {
			if !bytes.Equal(inv.JSON, description.AdministrativeInvocations[index].JSON) || inv.SHA256 != description.AdministrativeInvocations[index].SHA256 {
				return c.ErrExecutionRecord
			}
		}
		parts := map[string]b.JobPart{}
		for _, p := range original.Parts {
			parts[p.Part] = p
		}
		for _, m := range description.Members {
			p := parts[m.Part]
			if !bytes.Equal(p.InvocationJSON, m.JSON) || p.InvocationSHA256 != m.SHA256 {
				return c.ErrExecutionRecord
			}
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}
