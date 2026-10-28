package publicadapter

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/worker"
	d "clawreef/internal/systembackupdispatch"
	batchv1 "k8s.io/api/batch/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

func validWorkerPart(in d.Input, p JobPart, hold time.Time) bool {
	if len(p.InvocationJSON) == 0 || len(p.InvocationJSON) > 512<<10 || digest(p.InvocationJSON) != p.InvocationSHA256 || len(validation.IsDNS1123Subdomain(p.InvocationConfigMap)) != 0 {
		return false
	}
	var invocation worker.Invocation
	if decodeStrict(p.InvocationJSON, &invocation) != nil || !worker.ValidateRecordedInvocation(invocation) {
		return false
	}
	r := invocation.Request
	if r.Binding.BackupID != in.Authority.TaskPublicID || r.Binding.Attempt != strconv.FormatUint(in.Authority.AttemptNo, 10) || r.Binding.Path != p.Part || r.Binding.EnvelopeID == "" || !hexHash.MatchString(r.Binding.CaptureContextHash) || r.Deadline.After(in.Authority.DeadlineAt) || r.Deadline.After(hold) {
		return false
	}
	if r.Operation != "capture-workspace" && r.Operation != "capture-database" {
		return false
	}
	if _, err := kube.WorkerConfigMap(kube.Identity{Namespace: p.Intent.Namespace, Name: p.InvocationConfigMap, Owner: in.Authority.TaskPublicID}, invocation); err != nil {
		return false
	}
	var job batchv1.Job
	if decodeStrict(p.Intent.SpecJSON, &job) != nil {
		return false
	}
	found := false
	for _, v := range job.Spec.Template.Spec.Volumes {
		if v.ConfigMap != nil && v.ConfigMap.Name == p.InvocationConfigMap {
			found = true
		}
	}
	return found
}

func invocationIndex(p JobPart) (uint32, error) {
	var inv worker.Invocation
	err := decodeStrict(p.InvocationJSON, &inv)
	return inv.Request.Binding.PartIndex, err
}

func validIntent(i d.JobIntent, task string) bool {
	if !unit.MatchString(i.JobUnitKey) || i.Generation == 0 || len(validation.IsDNS1123Label(i.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(i.Name)) != 0 || len(i.SpecJSON) == 0 || len(i.SpecJSON) > 1<<20 || digest(i.SpecJSON) != i.SpecSHA256 {
		return false
	}
	var job batchv1.Job
	if decodeStrict(i.SpecJSON, &job) != nil || job.Kind != "Job" || job.APIVersion != "batch/v1" || job.Name != i.Name || job.Namespace != i.Namespace || job.UID != "" || job.ResourceVersion != "" || job.GenerateName != "" || job.DeletionTimestamp != nil || len(job.OwnerReferences) > 0 || job.Labels[kube.OwnerLabel] != task || job.Spec.Template.Labels[kube.OwnerLabel] != task || job.Spec.Template.Spec.ServiceAccountName == "" || len(job.Spec.Template.Spec.Containers) != 1 || job.Spec.ActiveDeadlineSeconds == nil || *job.Spec.ActiveDeadlineSeconds <= 0 {
		return false
	}
	return immutableImage.MatchString(job.Spec.Template.Spec.Containers[0].Image)
}

func validBinding(b d.JobBinding) bool {
	return unit.MatchString(b.JobUnitKey) && len(validation.IsDNS1123Label(b.Namespace)) == 0 && len(validation.IsDNS1123Subdomain(b.Name)) == 0 && uuid.MatchString(b.UID) && b.Generation > 0 && b.RelayIdentityRef != "" && b.RelayIdentityVersion != "" && !b.RelayBoundAt.IsZero() && b.RelayExpiresAt.After(b.RelayBoundAt)
}
func sameBinding(a, b d.JobBinding) bool {
	return a.JobUnitKey == b.JobUnitKey && a.Namespace == b.Namespace && a.Name == b.Name && a.UID == b.UID && a.Generation == b.Generation && a.RelayIdentityRef == b.RelayIdentityRef && a.RelayIdentityVersion == b.RelayIdentityVersion && a.RelayBoundAt.Equal(b.RelayBoundAt) && a.RelayExpiresAt.Equal(b.RelayExpiresAt)
}
func matchesIntent(b d.JobBinding, i d.JobIntent) bool {
	return validBinding(b) && b.JobUnitKey == i.JobUnitKey && b.Namespace == i.Namespace && b.Name == i.Name && b.Generation == i.Generation
}

type jobCollector struct {
	in              d.Input
	spec            JobPart
	sourceSHA       string
	ports           d.Ports
	reader          Results
	ensureAttempted bool
	binding         *d.JobBinding
	result          *d.ModuleResult
	failure         error
	sealedReuse     bool
}

func (c *jobCollector) ID() string { return c.spec.Part }

// Prepare is read-only. EnsureJob can start a Pod immediately, so dispatch is
// deferred to Capture, after flow has checked ALL writer ACKs and CheckPaused.
// This ABI has no suspended-Job/release primitive; we must not assume one.
func (c *jobCollector) Prepare(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.failure = c.ports.Check(ctx, c.in.Authority)
	return c.failure
}
func (c *jobCollector) dispatch(ctx context.Context) (resultErr error) {
	defer func() {
		if resultErr != nil && c.failure == nil {
			c.failure = resultErr
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.ports.Check(ctx, c.in.Authority); err != nil {
		return err
	}
	c.ensureAttempted = true
	b, err := c.ports.EnsureJob(ctx, c.in.Authority, c.spec.Intent)
	if err != nil {
		return err
	}
	if !matchesIntent(b, c.spec.Intent) || b.RelayExpiresAt.After(c.in.Authority.DeadlineAt) || !time.Now().Before(b.RelayExpiresAt) {
		return &Failure{"control_evidence_invalid"}
	}
	c.binding = &b
	for _, old := range c.in.Jobs {
		if old.JobUnitKey == b.JobUnitKey && !sameBinding(old, b) {
			return &Failure{"coordination_invalid"}
		}
	}
	return nil
}
func (c *jobCollector) Capture(ctx context.Context) (_ flow.Part, resultErr error) {
	defer func() {
		if resultErr != nil && c.failure == nil {
			c.failure = resultErr
		}
	}()
	if c.binding == nil {
		if c.sealedReuse {
			return flow.Part{}, d.ErrNotReady
		}
		if err := c.dispatch(ctx); err != nil {
			return flow.Part{}, err
		}
	}
	for {
		if err := ctx.Err(); err != nil {
			return flow.Part{}, err
		}
		if !c.sealedReuse && !time.Now().Before(c.binding.RelayExpiresAt) {
			return flow.Part{}, &Failure{"deadline_exceeded"}
		}
		if err := c.ports.Check(ctx, c.in.Authority); err != nil {
			return flow.Part{}, err
		}
		obs, err := c.ports.ObserveJob(ctx, c.in.Authority, *c.binding)
		if err != nil {
			return flow.Part{}, err
		}
		if !sameBinding(obs.Binding, *c.binding) {
			return flow.Part{}, &Failure{"control_evidence_invalid"}
		}
		if c.sealedReuse && (!obs.Complete || obs.ResultEvidence == nil) {
			return flow.Part{}, &Failure{"control_evidence_invalid"}
		}
		if obs.Complete && obs.ResultEvidence != nil {
			e := *obs.ResultEvidence
			if !evidenceID.MatchString(e.PublicID) || !hexHash.MatchString(e.SHA256) {
				return flow.Part{}, &Failure{"control_evidence_invalid"}
			}
			raw, err := c.reader.Read(ctx, c.in.Authority, *c.binding, e)
			if err != nil {
				return flow.Part{}, err
			}
			if len(raw) == 0 || len(raw) > 1<<20 || digest(raw) != e.SHA256 {
				return flow.Part{}, &Failure{"checksum_mismatch"}
			}
			var result d.ModuleResult
			if decodeRequiredObject(raw, &result) != nil || result.Part != c.spec.Part || result.Category != c.spec.Category || validateResult(result) != nil || validateCheckpoint(result.Checkpoint, c.in, c.spec, *c.binding, c.sourceSHA) != nil {
				return flow.Part{}, &Failure{"control_evidence_invalid"}
			}
			if err := ctx.Err(); err != nil {
				return flow.Part{}, err
			}
			if err := c.ports.Check(ctx, c.in.Authority); err != nil {
				return flow.Part{}, err
			}
			c.result = &result
			// Preserve authenticated fields/bytes. The OUTER report ref already
			// lives in D's Job observation; appending it to its own signed payload
			// would change the report while retaining the old checksum.
			return flow.Part{ID: c.ID(), Checkpoint: digest(result.Checkpoint), SealedRef: string(raw)}, nil
		}
		// A completed Job without authenticated evidence, or evidence without
		// Kubernetes completion, remains pending within the ORIGINAL deadline.
		timer := time.NewTimer(200 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return flow.Part{}, ctx.Err()
		case <-timer.C:
		}
	}
}

func freshInvocations(x Discovery) bool {
	if !time.Now().Before(x.HoldUntil) {
		return false
	}
	for _, part := range x.Parts {
		var inv worker.Invocation
		if decodeStrict(part.InvocationJSON, &inv) != nil || !time.Now().Before(inv.Request.Deadline) {
			return false
		}
	}
	return true
}
func (c *jobCollector) Stop(ctx context.Context) error {
	if !c.ensureAttempted {
		return nil
	}
	if c.binding == nil {
		return &Failure{"coordination_invalid"}
	} // unknown create needs D intent recovery
	return c.ports.StopJob(ctx, c.in.Authority, *c.binding)
}

func validateResult(r d.ModuleResult) error {
	if r.SchemaVersion != "system-backup-part-result.v1" || !unit.MatchString(r.Part) || !unit.MatchString(r.Category) || r.Status != "completed" || r.FailureCategory != "none" || r.Statistics == nil || r.Warnings == nil || r.EvidenceIDs == nil || len(r.EvidenceIDs) > 1000 || len(r.Checkpoint) == 0 || !json.Valid(r.Checkpoint) {
		return d.ErrNotReady
	}
	var checkpoint map[string]json.RawMessage
	if json.Unmarshal(r.Checkpoint, &checkpoint) != nil || checkpoint == nil {
		return d.ErrNotReady
	}
	seen := map[string]bool{}
	for _, id := range r.EvidenceIDs {
		if !evidenceID.MatchString(id) || seen[id] {
			return d.ErrNotReady
		}
		seen[id] = true
	}
	// Disqualifying warnings need the original owner policy, not an implicit
	// acceptance claim. This adapter's first supported path accepts none.
	if len(r.Warnings) != 0 {
		return d.ErrNotReady
	}
	return nil
}

func validateRecoveryJobs(jobs []d.JobBinding, in d.Input, x Discovery) error {
	expected := map[string]d.JobIntent{}
	for _, p := range x.Parts {
		expected[p.Intent.JobUnitKey] = p.Intent
	}
	seen := map[string]bool{}
	uids := map[string]bool{}
	for _, b := range jobs {
		i, ok := expected[b.JobUnitKey]
		if !ok || seen[b.JobUnitKey] || uids[b.UID] || !matchesIntent(b, i) || b.RelayExpiresAt.After(in.Authority.DeadlineAt) {
			return d.ErrNotReady
		}
		seen[b.JobUnitKey] = true
		uids[b.UID] = true
	}
	return nil
}

func validateRecoveryScope(s RecoverySnapshot, in d.Input, x Discovery) error {
	if err := validateRecoveryJobs(s.Jobs, in, x); err != nil {
		return err
	}
	remaining := map[string]bool{}
	for _, p := range x.Parts {
		remaining[p.Intent.JobUnitKey] = true
	}
	for _, b := range s.Jobs {
		delete(remaining, b.JobUnitKey)
	}
	for _, key := range s.Undispatched {
		if !remaining[key] {
			return d.ErrNotReady
		}
		delete(remaining, key)
	}
	if len(remaining) != 0 {
		return d.ErrNotReady
	}
	return nil
}
