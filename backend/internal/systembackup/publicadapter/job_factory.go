package publicadapter

import (
	"encoding/json"
	"time"

	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/worker"
	d "clawreef/internal/systembackupdispatch"
	batchv1 "k8s.io/api/batch/v1"
)

// CapturePartRequest is admitted deployment data, not a client create request.
// Generation is supplied by D's original intent journal. Workload contains
// observed mount/ref identities; no builder can attest those identities itself.
type CapturePartRequest struct {
	Part, Category, JobUnitKey string
	Generation                 uint64
	Workload                   kube.JobRequest
	Invocation                 worker.Invocation
}

// BuildCapturePart reuses the actual workspace/database worker Job builders.
// It freezes original invocation/spec bytes without API calls, identity/grant
// issuance or journal writes. D must journal the ConfigMap/ref and Job intent,
// observe the real Job UID, then issue A's UID-bound work identity via its port.
func BuildCapturePart(in d.Input, hold time.Time, req CapturePartRequest) (JobPart, error) {
	var zero JobPart
	w := req.Workload
	if validateInput(in, false) != nil || in.Authority.TaskType != "backup" || w.Identity.Owner != in.Authority.TaskPublicID || w.Restore || w.WorkerControl == nil || len(w.Command) != 0 || req.Generation == 0 || hold.After(in.Authority.DeadlineAt) || !time.Now().Before(hold) || w.DeadlineSeconds <= 0 || w.DeadlineSeconds > 3600 || time.Duration(w.DeadlineSeconds)*time.Second > time.Until(req.Invocation.Request.Deadline) {
		return zero, d.ErrNotReady
	}
	var job *batchv1.Job
	var err error
	switch req.Invocation.Request.Operation {
	case "capture-workspace":
		// Match the real worker's capture contract before stopping sources.
		// Restore-normalization policy is invalid for an archive capture.
		if req.Invocation.Request.PolicyVersion != "" || len(req.Invocation.Request.Files) != 0 || req.Invocation.Request.ArtifactName == "" {
			return zero, d.ErrNotReady
		}
		job, err = kube.Job(w)
	case "capture-database":
		// Database capture has no source filesystem or extra evidence mount.
		if w.Source.Name != "" || w.SourceSubPath != "" {
			return zero, d.ErrNotReady
		}
		job, err = kube.DatabaseJob(kube.DatabaseJobRequest{Identity: w.Identity, Image: w.Image, ServiceAccount: w.ServiceAccount, StagingClaim: w.StagingClaim, NodeName: w.NodeName, DeadlineSeconds: w.DeadlineSeconds, Operation: "capture-database", Control: *w.WorkerControl})
	default:
		return zero, d.ErrNotReady
	}
	if err != nil {
		return zero, d.ErrNotReady
	}
	// Public tasks own separate ciphertext directories on the staging claim.
	// The owner creates this directory only after the immutable plan is saved.
	for i := range job.Spec.Template.Spec.Containers[0].VolumeMounts {
		m := &job.Spec.Template.Spec.Containers[0].VolumeMounts[i]
		if m.Name == "staging" {
			m.SubPath = in.Authority.TaskPublicID
		}
	}
	job.APIVersion, job.Kind = "batch/v1", "Job"
	raw, err := json.Marshal(job)
	if err != nil {
		return zero, d.ErrNotReady
	}
	inv, err := json.Marshal(req.Invocation)
	if err != nil {
		return zero, d.ErrNotReady
	}
	out := JobPart{Part: req.Part, Category: req.Category, InvocationJSON: inv, InvocationSHA256: digest(inv), InvocationConfigMap: w.WorkerControl.InvocationConfigMap, Intent: d.JobIntent{JobUnitKey: req.JobUnitKey, Namespace: job.Namespace, Name: job.Name, Generation: req.Generation, SpecJSON: raw, SpecSHA256: digest(raw)}}
	if !unit.MatchString(out.Part) || !unit.MatchString(out.Category) || !validIntent(out.Intent, in.Authority.TaskPublicID) || !validWorkerPart(in, out, hold) {
		return zero, d.ErrNotReady
	}
	return out, nil
}
