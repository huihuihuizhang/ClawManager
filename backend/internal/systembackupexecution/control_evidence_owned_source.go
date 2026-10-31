package systembackupexecution

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"sort"
	"time"

	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	w "clawreef/internal/systembackupwire"
)

type originalOwnedPart struct {
	basis  ce.OwnedPartBasis
	job    d.JobBinding
	actual map[string]json.RawMessage
}

// This is the concrete original owner producer. Every comparison originates
// in the authenticated original plan/result/candidate, controller-private C
// copies and independent current controller Unwrap plus an inert domain reader.
// No report/expected count/passed flag arrives from the HTTP request.
func (s *DeploymentService) deriveOriginalOwnedReports(ctx context.Context, in d.Input, seed ce.CaptureLocator) ([]ce.OwnedReports, []originalOwnedPart, error) {
	if s == nil || s.Runtime == nil || s.Runtime.Owner == nil || seed.Validate() != nil || seed.Finalization == nil || in.Authority.TaskType != "backup" || in.Authority.Phase != "capture" || in.Authority.MaintenanceFencingToken == 0 || seed.Expected.Backup != in.Authority.TaskPublicID || seed.Expected.Attempt != in.Authority.AttemptNo || seed.Expected.ConfigSHA256 != in.Authority.ConfigSHA256 || s.checkProductionCaptureMaterials() != nil {
		return nil, nil, c.ErrExecutionAuthority
	}
	o := s.Runtime.Owner
	if o.FormalKeys == nil || o.Gate.Check(ctx, in.Authority) != nil {
		return nil, nil, c.ErrExecutionAuthority
	}
	_, _, discovery, err := o.input(ctx, in.Authority, false)
	if err != nil {
		return nil, nil, err
	}
	planned := map[string]b.JobPart{}
	for _, part := range discovery.Parts {
		if part.Part != ce.Part && part.Part != ce.ProofPart {
			planned[part.Part] = part
		}
	}
	if len(planned) != len(seed.Finalization.Parts) {
		return nil, nil, c.ErrExecutionRecord
	}
	custody, err := staging.OpenSealCustody(o.Staging)
	if err != nil {
		return nil, nil, err
	}
	defer custody.Close()
	parts := make([]originalOwnedPart, 0, len(planned))
	basis := ce.OwnedReportBasis{CaptureContextSHA256: seed.Finalization.CaptureContextSHA256, Parts: []ce.OwnedPartBasis{}}
	for _, selection := range seed.Finalization.Parts {
		part, ok := planned[selection.Part]
		var inv worker.Invocation
		if !ok || json.Unmarshal(part.InvocationJSON, &inv) != nil || part.InvocationSHA256 != selection.InvocationSHA256 || hash(part.InvocationJSON) != selection.InvocationSHA256 || inv.Request.Operation != selection.Operation || inv.ProviderKey == nil || inv.ProviderKey.Request.Context.CaptureContextHash != basis.CaptureContextSHA256 {
			return nil, nil, c.ErrExecutionRecord
		}
		var bindingRaw, keyUseRaw []byte
		var candidateSHA, resultSHA string
		if o.Gate.Authority.DB.QueryRowContext(ctx, `SELECT binding_json,key_use_json,candidate_sha256,result_sha256 FROM system_backup_v2_runtime_resources WHERE target_type='backup' AND task_public_id=? AND attempt_no=? AND phase='capture' AND resource_kind='Job' AND namespace_name=? AND resource_name=? AND lifecycle='ready' AND create_dispatched=TRUE AND revoked=FALSE AND stopped_at IS NULL`, in.Authority.TaskPublicID, in.Authority.AttemptNo, part.Intent.Namespace, part.Intent.Name).Scan(&bindingRaw, &keyUseRaw, &candidateSHA, &resultSHA) != nil {
			return nil, nil, c.ErrExecutionRecord
		}
		var job d.JobBinding
		var keyUse worker.KeyUseLease
		if decodeProviderDeploymentJSON(bindingRaw, &job) != nil || decodeProviderDeploymentJSON(keyUseRaw, &keyUse) != nil || keyUse.State != "finished" || keyUse.Identity.JobUID != job.UID || keyUse.Identity.InvocationSHA256 != part.InvocationSHA256 {
			return nil, nil, c.ErrExecutionRecord
		}
		candidate, err := o.ReadFormalCandidate(ctx, in.Authority, job, false)
		if err != nil {
			return nil, nil, err
		}
		ref := resultEvidenceRef(in.Authority, job, resultSHA)
		registered, err := o.Evidence(ctx, in.Authority, job)
		if err != nil || registered == nil || *registered != ref {
			return nil, nil, c.ErrExecutionRecord
		}
		resultRaw, err := o.ReadResult(ctx, in.Authority, job, ref)
		if err != nil {
			return nil, nil, err
		}
		actualResultSHA := hash(resultRaw)
		var result d.ModuleResult
		var checkpoint b.Checkpoint
		decodeErr := decodeProviderDeploymentJSON(resultRaw, &result)
		clear(resultRaw)
		if decodeErr != nil || json.Unmarshal(result.Checkpoint, &checkpoint) != nil || actualResultSHA != resultSHA {
			return nil, nil, c.ErrExecutionRecord
		}
		files, observed, err := staging.OpenFormalObserved(ctx, custody, workerSealScope(in.Authority, job, inv), candidate.Candidate.Ciphertext, candidate.Candidate.Envelope)
		if err != nil {
			return nil, nil, err
		}
		var verified w.StreamVerification
		var envelopeSHA string
		err = func() error {
			defer files.Close()
			if checkpoint.SealedRef != observed.Reference() || checkpoint.ContentSHA256 != candidate.Candidate.Ciphertext.SHA256 {
				return c.ErrExecutionRecord
			}
			envelope, err := io.ReadAll(io.LimitReader(files.Envelope, (32<<20)+1))
			defer clear(envelope)
			if err != nil || len(envelope) > 32<<20 || int64(len(envelope)) != candidate.Candidate.Envelope.Size || hash(envelope) != candidate.Candidate.Envelope.SHA256 {
				return c.ErrExecutionRecord
			}
			envelopeSHA = hash(envelope)
			keys, err := openFormalCandidateKeys(ctx, o.FormalKeys, FormalCandidateReadScope{Authority: in.Authority, Job: job, Invocation: inv, Candidate: candidate.Candidate, CapturePod: candidate.Pod, CaptureGrantSHA256: candidate.ExecutionGrantSHA256})
			if err != nil {
				return err
			}
			defer keys.Close()
			bounded, cancel := context.WithDeadline(ctx, keys.ValidUntil())
			defer cancel()
			spec := w.StreamSpec{Request: inv.ProviderKey.Request, Path: inv.Request.ArtifactName, MaxPlaintextBytes: inv.Request.MaxCompressedBytes, MaxFrames: inv.FormalCapture.MaxFrames}
			verified, err = w.InspectWrappedStream(bounded, spec, envelope, files.Ciphertext, keys, func(plaintext io.Reader) error {
				return inspectOwnedBusinessPayload(bounded, inv, candidate.Candidate, plaintext)
			})
			if err != nil || verified.CiphertextBytes() != candidate.Candidate.Ciphertext.Size || verified.CiphertextSHA256() != candidate.Candidate.Ciphertext.SHA256 {
				return c.ErrExecutionRecord
			}
			return nil
		}()
		if err != nil {
			return nil, nil, err
		}
		p := ce.OwnedPartBasis{Part: selection.Part, Operation: selection.Operation, InvocationSHA256: part.InvocationSHA256, CandidateSHA256: candidateSHA, ResultSHA256: resultSHA, ResultEvidenceRef: ref.PublicID, CiphertextSHA256: candidate.Candidate.Ciphertext.SHA256, EnvelopeSHA256: candidate.Candidate.Envelope.SHA256, CiphertextBytes: candidate.Candidate.Ciphertext.Size}
		actualInvSHA, err := inv.Hash()
		if err != nil {
			return nil, nil, err
		}
		value := func(key string, v any) json.RawMessage { raw, _ := ce.Canonical(map[string]any{key: v}); return raw }
		category := ownedBusinessCategory(inv)
		if category == "" {
			return nil, nil, c.ErrExecutionRecord
		}
		actual := map[string]json.RawMessage{
			category + "." + p.Part + ".source_binding":      value("hash", actualInvSHA),
			category + "." + p.Part + ".domain_violations":   value("violations", uint64(0)), // only AFTER complete actual inert read and post-Unwrap authorization above
			"artifact." + p.Part + ".ciphertext":             value("hash", verified.CiphertextSHA256()),
			"artifact." + p.Part + ".ciphertext_bytes":       value("bytes", verified.CiphertextBytes()),
			"artifact." + p.Part + ".envelope":               value("hash", envelopeSHA),
			"control_plane." + p.Part + ".capture_context":   value("hash", inv.ProviderKey.Request.Context.CaptureContextHash),
			"control_plane." + p.Part + ".invocation":        value("hash", actualInvSHA),
			"control_plane." + p.Part + ".registered_result": value("hash", actualResultSHA),
		}
		basis.Parts = append(basis.Parts, p)
		parts = append(parts, originalOwnedPart{p, job, actual})
	}
	if o.Gate.Check(ctx, in.Authority) != nil || s.checkProductionCaptureMaterials() != nil {
		return nil, nil, c.ErrExecutionAuthority
	}
	var observedAt time.Time
	if o.Gate.Authority.DB.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&observedAt) != nil {
		return nil, nil, c.ErrExecutionAuthority
	}
	actual := map[string]json.RawMessage{}
	for _, part := range parts {
		for id, value := range part.actual {
			actual[id] = value
		}
	}
	owners := []ce.OwnedReports{}
	for _, owner := range []string{"B", "C", "D"} {
		requirements, err := ce.RequiredOwnerChecks(owner, basis)
		if err != nil {
			return nil, nil, err
		}
		sort.Slice(requirements, func(i, j int) bool { return requirements[i].ID < requirements[j].ID })
		reports := []ce.RegisteredEvidence{}
		for offset := 0; offset < len(requirements); {
			attempt := in.Authority.AttemptNo
			category := requirements[offset].Category
			report := ce.VerifierReport{Version: "system-backup-verifier-result.v1", TargetType: "backup", Target: in.Authority.TaskPublicID, Attempt: &attempt, Category: category, Mode: "backup_validate", Checks: []ce.VerifierCheck{}}
			for offset < len(requirements) && requirements[offset].Category == category && len(report.Checks) < 8 {
				required := requirements[offset]
				computed, ok := actual[required.ID]
				if !ok {
					return nil, nil, c.ErrExecutionRecord
				}
				ref := required.ResultEvidenceRef
				report.Checks = append(report.Checks, ce.VerifierCheck{ID: required.ID, Status: "passed", Expected: required.Expected, Actual: computed, Evidence: &ref, Failure: "none"})
				offset++
			}
			entry, err := ce.ProposedVerifierReport(seed.Expected.Scope, owner, report)
			if err != nil {
				return nil, nil, err
			}
			reports = append(reports, entry)
		}
		owners = append(owners, ce.OwnedReports{Owner: owner, ObservedAt: observedAt, Basis: basis, Reports: reports})
	}
	return owners, parts, nil
}

func ownedBusinessCategory(inv worker.Invocation) string {
	switch inv.Request.Operation {
	case "capture-database", "capture-workspace", "capture-source-redis":
		return "instances"
	case "capture-skill-objects":
		return "skill_hub"
	case "capture-deployment-resources", "capture-secret-bundle":
		return "resources"
	case "capture-team-redis", "capture-team-objects":
		return "teams"
	}
	return ""
}

func recheckOriginalOwnedParts(ctx context.Context, tx *sql.Tx, in d.Input, parts []originalOwnedPart) error {
	for _, part := range parts {
		var candidate, result string
		var keyUse []byte
		if tx.QueryRowContext(ctx, `SELECT candidate_sha256,result_sha256,key_use_json FROM system_backup_v2_runtime_resources WHERE target_type='backup' AND task_public_id=? AND attempt_no=? AND phase='capture' AND resource_kind='Job' AND namespace_name=? AND resource_name=? AND observed_uid=? AND lifecycle='ready' AND create_dispatched=TRUE AND revoked=FALSE AND stopped_at IS NULL FOR SHARE`, in.Authority.TaskPublicID, in.Authority.AttemptNo, part.job.Namespace, part.job.Name, part.job.UID).Scan(&candidate, &result, &keyUse) != nil || candidate != part.basis.CandidateSHA256 || result != part.basis.ResultSHA256 {
			return c.ErrExecutionRecord
		}
		var use worker.KeyUseLease
		if decodeProviderDeploymentJSON(keyUse, &use) != nil || use.State != "finished" || use.Identity.InvocationSHA256 != part.basis.InvocationSHA256 || use.Identity.JobUID != part.job.UID {
			return c.ErrExecutionRecord
		}
	}
	return nil
}
