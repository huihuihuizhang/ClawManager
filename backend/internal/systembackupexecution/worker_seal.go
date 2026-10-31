package systembackupexecution

import (
	"context"
	"encoding/json"
	"math"

	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
)

func workerSealScope(a d.Authority, j d.JobBinding, i worker.Invocation) staging.SealScope {
	digest, _ := i.Hash()
	return staging.SealScope{Installation: a.InstallationID, Task: a.TaskPublicID, Phase: a.Phase, Unit: j.JobUnitKey, Namespace: j.Namespace, JobName: j.Name, JobUID: j.UID, Attempt: a.AttemptNo, Generation: j.Generation, ConfigVersion: a.ConfigVersion, ConfigSHA256: a.ConfigSHA256, InvocationSHA256: digest, Binding: i.Request.Binding}
}

func (o *PublicJobOwner) observeWorkerSeal(ctx context.Context, a d.Authority, j d.JobBinding, i worker.Invocation, r worker.Result, key []byte) (b.SealedPart, error) {
	if !worker.ValidateResult(i.Request, &r) {
		return b.SealedPart{}, c.ErrExecutionRecord
	}
	custody, err := staging.OpenSealCustody(o.Staging)
	if err != nil {
		return b.SealedPart{}, err
	}
	defer custody.Close()
	source, err := o.Staging.OpenRoot(a.TaskPublicID)
	if err != nil {
		return b.SealedPart{}, err
	}
	defer source.Close()
	observed, err := staging.ObserveManaged(ctx, source, custody, staging.CustodyPolicy{Installation: a.InstallationID, MaxBytes: o.SealCustodyMaxBytes}, workerSealScope(a, j, i), r.Receipt, key, i.Request.MaxCompressedBytes)
	if err != nil {
		return b.SealedPart{}, err
	}
	receipt := observed.Receipt()
	return b.SealedPart{Reference: observed.Reference(), ContentSHA256: receipt.SHA256, EvidenceIDs: []string{}}, nil
}

// A stored report is usable only while its exact controller-owned ciphertext
// version is readable. Never silently switch back to the worker's source file.
func (o *PublicJobOwner) checkWorkerSeal(ctx context.Context, a d.Authority, j d.JobBinding, desc b.Discovery, raw []byte) error {
	var result d.ModuleResult
	var cp b.Checkpoint
	if json.Unmarshal(raw, &result) != nil || json.Unmarshal(result.Checkpoint, &cp) != nil || result.Statistics["sealed_bytes"] > math.MaxInt64 {
		return c.ErrExecutionRecord
	}
	for _, part := range desc.Parts {
		if part.Intent.JobUnitKey == j.JobUnitKey {
			var i worker.Invocation
			if json.Unmarshal(part.InvocationJSON, &i) != nil {
				return c.ErrExecutionRecord
			}
			custody, err := staging.OpenSealCustody(o.Staging)
			if err != nil {
				return err
			}
			defer custody.Close()
			if i.FormalCapture != nil {
				record, err := o.ReadFormalCandidate(ctx, a, j, false)
				if err != nil {
					return err
				}
				if record.Candidate.Ciphertext.SHA256 != cp.ContentSHA256 || uint64(record.Candidate.Ciphertext.Size) != result.Statistics["sealed_bytes"] {
					return c.ErrExecutionRecord
				}
				files, observed, err := staging.OpenFormalObserved(ctx, custody, workerSealScope(a, j, i), record.Candidate.Ciphertext, record.Candidate.Envelope)
				files.Close()
				if err != nil {
					return err
				}
				if observed.Reference() != cp.SealedRef {
					return c.ErrExecutionRecord
				}
				return nil
			}
			original := staging.Receipt{Name: i.Request.ArtifactName, Size: int64(result.Statistics["sealed_bytes"]), SHA256: cp.ContentSHA256}
			file, observed, err := staging.OpenObserved(ctx, custody, workerSealScope(a, j, i), original)
			if err != nil {
				return err
			}
			defer file.Close()
			if observed.Reference() != cp.SealedRef {
				return c.ErrExecutionRecord
			}
			return nil
		}
	}
	return c.ErrExecutionRecord
}
