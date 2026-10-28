package systembackupcontroller

import (
	"bytes"
	"context"
	"encoding/json"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/worker"
	d "clawreef/internal/systembackupdispatch"
	batchv1 "k8s.io/api/batch/v1"
)

// ExecutionJobOwner binds each operation to the public journal and current
// authority. Admit must check the complete shared pause barrier, exact frozen
// plan and current registry, including external writers. Bind persists the
// actual UID and A's worker grant atomically; it cannot invent relay identity.
type ExecutionJobOwner interface {
	Admit(context.Context, d.Authority, d.JobIntent) (d.Input, d.Plan, kube.Runner, error)
	Bind(context.Context, d.Authority, d.JobIntent, kube.ResourceRecord) (d.JobBinding, error)
	Read(context.Context, d.Authority, d.JobBinding, bool) (kube.Runner, kube.ResourceRecord, error)
	Evidence(context.Context, d.Authority, d.JobBinding) (*d.EvidenceRef, error)
	Revoke(context.Context, d.Authority, d.JobBinding) error
	// Stopped proves worker/Pod termination even if a Job was externally
	// orphan-deleted. A missing Job alone must never release source writers.
	Stopped(context.Context, d.Authority, d.JobBinding) error
}

// ExecutionJobPorts delegates writer operations to the public maintenance
// owner and implements Job operations using B's actual Kubernetes runner.
type ExecutionJobPorts struct {
	d.Ports
	Jobs ExecutionJobOwner
}

func NewExecutionJobPorts(writers d.Ports, jobs ExecutionJobOwner) (*ExecutionJobPorts, error) {
	if absentExecutionDependency(writers) || absentExecutionDependency(jobs) {
		return nil, d.ErrNotReady
	}
	return &ExecutionJobPorts{Ports: writers, Jobs: jobs}, nil
}

func (p ExecutionJobPorts) EnsureJob(ctx context.Context, a d.Authority, intent d.JobIntent) (d.JobBinding, error) {
	if absentExecutionDependency(p.Ports) || absentExecutionDependency(p.Jobs) {
		return d.JobBinding{}, d.ErrNotReady
	}
	intent.SpecJSON = bytes.Clone(intent.SpecJSON)
	in, plan, runner, err := p.Jobs.Admit(ctx, a, intent)
	if err != nil {
		return d.JobBinding{}, err
	}
	if in.Authority != a {
		return d.JobBinding{}, ErrExecutionAuthority
	}
	inner, err := d.UnwrapTaskPlan(in, plan, b.PlanVersion)
	if err != nil {
		return d.JobBinding{}, err
	}
	desc, err := b.DescribePlan(in, inner)
	if err != nil {
		return d.JobBinding{}, err
	}
	var part *b.JobPart
	for i := range desc.Parts {
		v := &desc.Parts[i]
		if v.Intent.JobUnitKey == intent.JobUnitKey {
			if part != nil || v.Intent.Namespace != intent.Namespace || v.Intent.Name != intent.Name || v.Intent.Generation != intent.Generation || v.Intent.SpecSHA256 != intent.SpecSHA256 || !bytes.Equal(v.Intent.SpecJSON, intent.SpecJSON) {
				return d.JobBinding{}, ErrExecutionAuthority
			}
			part = v
		}
	}
	if part == nil {
		return d.JobBinding{}, ErrExecutionAuthority
	}
	var invocation worker.Invocation
	var job batchv1.Job
	if json.Unmarshal(part.InvocationJSON, &invocation) != nil || json.Unmarshal(intent.SpecJSON, &job) != nil {
		return d.JobBinding{}, d.ErrNotReady
	}
	cm, err := kube.WorkerConfigMap(kube.Identity{Namespace: intent.Namespace, Name: part.InvocationConfigMap, Owner: a.TaskPublicID}, invocation)
	if err != nil {
		return d.JobBinding{}, err
	}
	// Keep the original JSON bytes (including whitespace) from custody.
	cm.Data["invocation.json"] = string(part.InvocationJSON)
	if _, err = runner.Ensure(ctx, "ConfigMap", cm); err != nil {
		return d.JobBinding{}, err
	}
	record, err := runner.Ensure(ctx, "Job", &job)
	if err != nil {
		return d.JobBinding{}, err
	}
	binding, err := p.Jobs.Bind(ctx, a, intent, record)
	if err != nil {
		return d.JobBinding{}, err
	}
	if !executionJobMatches(binding, record) || binding.JobUnitKey != intent.JobUnitKey || binding.Generation != intent.Generation || binding.RelayIdentityRef == "" || binding.RelayIdentityVersion == "" || binding.RelayBoundAt.IsZero() || !binding.RelayExpiresAt.After(binding.RelayBoundAt) || binding.RelayExpiresAt.After(a.DeadlineAt) {
		return d.JobBinding{}, ErrExecutionAuthority
	}
	return binding, nil
}

func executionJobMatches(binding d.JobBinding, record kube.ResourceRecord) bool {
	return record.Intent.Kind == "Job" && record.UID != "" && binding.UID == record.UID && binding.Namespace == record.Intent.Identity.Namespace && binding.Name == record.Intent.Identity.Name
}

func (p ExecutionJobPorts) ObserveJob(ctx context.Context, a d.Authority, binding d.JobBinding) (d.JobObservation, error) {
	if absentExecutionDependency(p.Jobs) {
		return d.JobObservation{}, d.ErrNotReady
	}
	runner, record, err := p.Jobs.Read(ctx, a, binding, false)
	if err != nil {
		return d.JobObservation{}, err
	}
	if !executionJobMatches(binding, record) {
		return d.JobObservation{}, ErrExecutionAuthority
	}
	complete, err := runner.JobComplete(ctx, record)
	if err != nil {
		return d.JobObservation{}, err
	}
	obs := d.JobObservation{Binding: binding, Complete: complete}
	if complete {
		obs.ResultEvidence, err = p.Jobs.Evidence(ctx, a, binding)
	}
	return obs, err
}

func (p ExecutionJobPorts) StopJob(ctx context.Context, a d.Authority, binding d.JobBinding) error {
	if absentExecutionDependency(p.Jobs) {
		return d.ErrNotReady
	}
	// Read uses current recovery authority; an expired forward grant cannot
	// authorize cleanup. Revoke must finish before Kubernetes deletion.
	runner, record, err := p.Jobs.Read(ctx, a, binding, true)
	if err != nil {
		return err
	}
	if !executionJobMatches(binding, record) {
		return ErrExecutionAuthority
	}
	if err = p.Jobs.Revoke(ctx, a, binding); err != nil {
		return err
	}
	stopped, err := runner.Cleanup(ctx, record)
	if err != nil {
		return err
	}
	if !stopped {
		return kube.ErrPending
	}
	return p.Jobs.Stopped(ctx, a, binding)
}

var _ d.Ports = ExecutionJobPorts{}
