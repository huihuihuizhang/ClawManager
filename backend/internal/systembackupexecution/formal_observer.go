package systembackupexecution

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"

	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	w "clawreef/internal/systembackupwire"
)

// The normal Job Evidence poll consumes the ORIGINAL encrypted journal and
// original frozen plan. The actual independently supplied Unwrapper rechecks
// its own exact provider operation/current authority before and after AEAD use.
// No capture credential is promoted into read/unwrap authority here.
func (o *PublicJobOwner) observeFormalCandidateResult(ctx context.Context, a d.Authority, j d.JobBinding) (*d.EvidenceRef, error) {
	var digest sql.NullString
	if err := o.Gate.Authority.DB.QueryRowContext(ctx, `SELECT candidate_sha256 FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND attempt_no=? AND phase=? AND resource_kind='Job' AND namespace_name=? AND resource_name=? AND observed_uid=?`, a.TaskPublicID, a.AttemptNo, a.Phase, j.Namespace, j.Name, j.UID).Scan(&digest); err != nil {
		return nil, err
	}
	if !digest.Valid {
		return nil, nil
	}
	if o.FormalKeys == nil {
		return nil, d.ErrNotReady
	}
	record, err := o.ReadFormalCandidate(ctx, a, j, false)
	if err != nil {
		return nil, err
	}
	in, plan, desc, err := o.input(ctx, a, false)
	if err != nil {
		return nil, err
	}
	part, err := partFor(desc, j.JobUnitKey)
	if err != nil {
		return nil, err
	}
	var invocation worker.Invocation
	if json.Unmarshal(part.InvocationJSON, &invocation) != nil || !worker.ValidateFormalCaptureResult(invocation, &record.Candidate) {
		return nil, c.ErrExecutionRecord
	}
	keys, err := openFormalCandidateKeys(ctx, o.FormalKeys, FormalCandidateReadScope{Authority: a, Job: j, Invocation: invocation, Candidate: record.Candidate, CapturePod: record.Pod, CaptureGrantSHA256: record.ExecutionGrantSHA256})
	if err != nil {
		return nil, err
	}
	defer keys.Close()
	ctx, cancel := context.WithDeadline(ctx, keys.ValidUntil())
	defer cancel()
	custody, err := staging.OpenSealCustody(o.Staging)
	if err != nil {
		return nil, err
	}
	defer custody.Close()
	source, err := o.Staging.OpenRoot(a.TaskPublicID)
	if err != nil {
		return nil, err
	}
	defer source.Close()
	if err = o.Gate.Check(ctx, a); err != nil {
		return nil, err
	}
	observed, err := observeOriginalFormalCandidate(ctx, source, custody, staging.CustodyPolicy{Installation: a.InstallationID, MaxBytes: o.SealCustodyMaxBytes}, workerSealScope(a, j, invocation), invocation, record.Candidate, keys)
	if err != nil {
		return nil, err
	}
	if err = o.Gate.Check(ctx, a); err != nil {
		return nil, err
	}
	inner, err := d.UnwrapTaskPlan(in, plan, b.PlanVersion)
	if err != nil {
		return nil, err
	}
	defer clear(inner.CanonicalJSON)
	result, err := b.BuildFormalPartResult(in, inner, j.JobUnitKey, j, record.Candidate, b.SealedPart{Reference: observed.Reference(), ContentSHA256: observed.Ciphertext().SHA256, EvidenceIDs: []string{}})
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(result)
	if err != nil || !inlineResultBody(raw) || b.ValidatePartResult(in, inner, j, raw) != nil {
		return nil, c.ErrExecutionRecord
	}
	if err = o.saveResult(ctx, a, j, raw); err != nil {
		return nil, err
	}
	ref := resultEvidenceRef(a, j, hash(raw))
	return &ref, nil
}

func observeOriginalFormalCandidate(ctx context.Context, source, custody *os.Root, policy staging.CustodyPolicy, scope staging.SealScope, i worker.Invocation, candidate worker.FormalCaptureResult, keys w.Unwrapper) (staging.FormalObservation, error) {
	if !worker.ValidateFormalCaptureResult(i, &candidate) || i.ProviderKey == nil || keys == nil {
		return staging.FormalObservation{}, d.ErrNotReady
	}
	spec := w.StreamSpec{Request: i.ProviderKey.Request, Path: i.Request.ArtifactName, MaxPlaintextBytes: i.Request.MaxCompressedBytes, MaxFrames: i.FormalCapture.MaxFrames}
	return staging.ObserveFormalManaged(ctx, source, custody, policy, scope, candidate.Ciphertext, candidate.Envelope, spec, keys)
}
