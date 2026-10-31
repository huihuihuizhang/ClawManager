package publicadapter

import (
	"clawreef/internal/systembackup/worker"
	"encoding/json"
	"strconv"
	"time"

	d "clawreef/internal/systembackupdispatch"
)

type ResourceCaptureModuleConfig struct {
	Revision            string
	Deployment, Secrets CapturePartRequest
}

// NewResourceCaptureModule contributes the two actual GET-only D operations.
// Requests come from the original task/namespace/selection/writer inventory.
// This pure constructor neither discovers an empty replacement nor issues keys.
func NewResourceCaptureModule(cfg ResourceCaptureModuleConfig) (CaptureModuleRegistration, error) {
	var zero CaptureModuleRegistration
	raw, err := json.Marshal(cfg)
	var frozen ResourceCaptureModuleConfig
	if err != nil || len(raw) > 4<<20 || json.Unmarshal(raw, &frozen) != nil {
		return zero, d.ErrNotReady
	}
	cfg = frozen
	requests := map[string]CapturePartRequest{"deployment_resources": cfg.Deployment, "secret_bundle": cfg.Secrets}
	for part, r := range requests {
		s := r.Invocation.Request.Resources
		if r.Part != part || r.Category != part || s == nil || s.Part != part || r.Invocation.FormalCapture == nil || r.Invocation.ProviderKey == nil || r.Workload.FormalMaterials == nil || s.Namespace != r.Workload.Identity.Namespace || !workerResourceInvocation(r) {
			return zero, d.ErrNotReady
		}
	}
	a, b := cfg.Deployment.Invocation.Request.Resources, cfg.Secrets.Invocation.Request.Resources
	if a.Namespace != b.Namespace || a.NamespaceUID != b.NamespaceUID || a.ServiceAccountUID == b.ServiceAccountUID || cfg.Deployment.Workload.FormalMaterials.ConfigMap == cfg.Secrets.Workload.FormalMaterials.ConfigMap {
		return zero, d.ErrNotReady
	}
	registration := CaptureModuleRegistration{Descriptor: CaptureModuleDescriptor{ID: "deployment_and_secrets", Owner: "D", Revision: cfg.Revision, Required: true, Parts: []CaptureModulePart{{"deployment_resources", "deployment_resources", "deployment_resources", "capture-deployment-resources"}, {"secret_bundle", "secret_bundle", "secret_bundle", "capture-secret-bundle"}}}}
	registration.Build = func(input CaptureModuleInput) ([]CapturePartRequest, error) {
		if len(input.Parts) != 2 {
			return nil, d.ErrNotReady
		}
		out := make([]CapturePartRequest, 0, 2)
		for _, selection := range input.Parts {
			r, ok := requests[selection.Part]
			if !ok || selection.Category != r.Category || selection.Operation != r.Invocation.Request.Operation {
				return nil, d.ErrNotReady
			}
			bound := r.Invocation.Request.Binding
			if bound.BackupID != input.Input.Authority.TaskPublicID || bound.Attempt != strconv.FormatUint(input.Input.Authority.AttemptNo, 10) || bound.Path != selection.Part || bound.CaptureContextHash != input.Context.CaptureContextSHA256 || !r.Invocation.Request.Deadline.Equal(input.Context.HoldUntil) || r.Invocation.ProviderKey.Request.Context.PartIndex != strconv.FormatUint(uint64(selection.PartIndex), 10) {
				return nil, d.ErrNotReady
			}
			var copy CapturePartRequest
			raw, _ := json.Marshal(r)
			if json.Unmarshal(raw, &copy) != nil {
				return nil, d.ErrNotReady
			}
			copy.Invocation.Request.Binding.PartIndex = selection.PartIndex
			out = append(out, copy)
		}
		return out, nil
	}
	if _, err = NewCaptureModules([]CaptureModuleRegistration{registration}, func(d.Input, SourceInventory, time.Time, string) (ModuleCaptureContext, error) {
		return ModuleCaptureContext{}, d.ErrNotReady
	}); err != nil {
		return zero, err
	}
	return registration, nil
}

func workerResourceInvocation(r CapturePartRequest) bool {
	return worker.ValidateRecordedInvocation(r.Invocation)
}
