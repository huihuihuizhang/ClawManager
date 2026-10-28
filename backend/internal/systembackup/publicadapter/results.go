package publicadapter

import (
	"encoding/json"

	"clawreef/internal/systembackup/worker"
	d "clawreef/internal/systembackupdispatch"
)

// SealedPart comes from C's immutable seal observer AFTER A authenticated the
// worker result. A filename, Job success or worker self-report cannot mint it.
// This value is data only; BuildPartResult itself does NOT authenticate/approve.
type SealedPart struct {
	Reference, ContentSHA256 string
	EvidenceIDs              []string
}

// BuildPartResult is the explicit B data-plane -> public module conversion.
// A/D must call it within their authenticated result pipeline and register its
// original bytes before putting that reference in the public Job observation.
// It never signs, publishes, creates evidence or mutates task/attempt state.
func BuildPartResult(in d.Input, plan d.Plan, unitKey string, job d.JobBinding, result worker.Result, seal SealedPart) (d.ModuleResult, error) {
	var zero d.ModuleResult
	f, err := loadPlan(in, plan)
	if err != nil {
		return zero, err
	}
	if in.Authority.TaskType != "backup" || seal.Reference == "" || len(seal.Reference) > 1024 || !hexHash.MatchString(seal.ContentSHA256) || seal.EvidenceIDs == nil || len(seal.EvidenceIDs) > 1000 {
		return zero, d.ErrNotReady
	}
	var part *JobPart
	for i := range f.Discovery.Parts {
		if f.Discovery.Parts[i].Intent.JobUnitKey == unitKey {
			part = &f.Discovery.Parts[i]
			break
		}
	}
	if part == nil || !matchesIntent(job, part.Intent) {
		return zero, d.ErrNotReady
	}
	var invocation worker.Invocation
	if decodeStrict(part.InvocationJSON, &invocation) != nil || !worker.ValidateResult(invocation.Request, &result) || result.Receipt.SHA256 != seal.ContentSHA256 {
		return zero, &Failure{"checksum_mismatch"}
	}
	cp := Checkpoint{SchemaVersion: "system-backup-b-checkpoint.v1", InstallationID: in.Authority.InstallationID, ConfigVersion: in.Authority.ConfigVersion, TaskPublicID: in.Authority.TaskPublicID, AttemptNo: in.Authority.AttemptNo, Phase: in.Authority.Phase, ConfigSHA256: in.Authority.ConfigSHA256, InventorySHA256: f.Discovery.SourceSHA256, Part: part.Part, JobUID: job.UID, JobGeneration: job.Generation, InvocationSHA256: part.InvocationSHA256, SealedRef: seal.Reference, ContentSHA256: seal.ContentSHA256}
	raw, err := json.Marshal(cp)
	if err != nil {
		return zero, d.ErrNotReady
	}
	out := d.ModuleResult{SchemaVersion: "system-backup-part-result.v1", Part: part.Part, Category: part.Category, Status: "completed", Checkpoint: raw, Statistics: map[string]uint64{"files": uint64(result.Files), "bytes": uint64(result.Bytes), "rows": uint64(result.Rows), "tables": uint64(result.Tables), "sealed_bytes": uint64(result.Receipt.Size)}, Warnings: []d.Warning{}, EvidenceIDs: append([]string{}, seal.EvidenceIDs...), FailureCategory: "none"}
	if validateResult(out) != nil || validateCheckpoint(out.Checkpoint, in, *part, job, f.Discovery.SourceSHA256) != nil {
		return zero, d.ErrNotReady
	}
	return out, nil
}
