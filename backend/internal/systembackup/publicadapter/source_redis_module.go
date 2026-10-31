package publicadapter

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	c "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/worker"
	d "clawreef/internal/systembackupdispatch"
)

const SourceRedisPart = "source_redis"

type SourceRedisModuleConfig struct {
	Revision string
	Source   SourceInventory
	Request  CapturePartRequest
}

// NewSourceRedisModule captures an original finite Redis source independently
// of Team existence. Teams may depend on this shared export, like shared SQL.
// Empty scopes still run the real source collector and produce a real header.
func NewSourceRedisModule(cfg SourceRedisModuleConfig) (CaptureModuleRegistration, error) {
	var zero CaptureModuleRegistration
	raw, err := json.Marshal(cfg)
	var frozen SourceRedisModuleConfig
	if err != nil || len(raw) > 16<<20 || json.Unmarshal(raw, &frozen) != nil {
		return zero, d.ErrNotReady
	}
	cfg = frozen
	r := cfg.Request
	s := r.Invocation.Request.SourceRedis
	if cfg.Source.Database == "" || cfg.Source.ServerUUID == "" || cfg.Source.Teams == nil || r.Part != SourceRedisPart || r.Category != "source" || r.Invocation.Request.Operation != "capture-source-redis" || s == nil || s.Validate() != nil || r.Invocation.FormalCapture == nil || r.Invocation.ProviderKey == nil || r.Workload.FormalMaterials == nil || r.Workload.Source.Name != "" || r.Workload.SourceSubPath != "" || !worker.ValidateRecordedInvocation(r.Invocation) || validateSharedTeamRedis(cfg.Source, *s) != nil {
		return zero, d.ErrNotReady
	}
	registration := CaptureModuleRegistration{Descriptor: CaptureModuleDescriptor{ID: SourceRedisPart, Owner: "D", Revision: cfg.Revision, Required: true, Parts: []CaptureModulePart{{Part: SourceRedisPart, Category: "source", RequestedPart: "redis", Operation: "capture-source-redis"}}}}
	sourceRaw, _ := json.Marshal(cfg.Source)
	registration.Build = func(input CaptureModuleInput) ([]CapturePartRequest, error) {
		actual, _ := json.Marshal(input.Source)
		if string(actual) != string(sourceRaw) || len(input.Parts) != 1 || input.Parts[0].Part != SourceRedisPart || r.Invocation.Request.SourceRedis.Policy.Purpose != input.Input.Backup.TaskPurpose {
			return nil, d.ErrNotReady
		}
		bound := r.Invocation.Request.Binding
		if bound.BackupID != input.Input.Authority.TaskPublicID || bound.Attempt != strconv.FormatUint(input.Input.Authority.AttemptNo, 10) || bound.Path != SourceRedisPart || bound.CaptureContextHash != input.Context.CaptureContextSHA256 || !r.Invocation.Request.Deadline.Equal(input.Context.HoldUntil) || r.Invocation.ProviderKey.Request.Context.PartIndex != strconv.FormatUint(uint64(input.Parts[0].PartIndex), 10) {
			return nil, d.ErrNotReady
		}
		var copy CapturePartRequest
		raw, _ := json.Marshal(r)
		if json.Unmarshal(raw, &copy) != nil {
			return nil, d.ErrNotReady
		}
		copy.Invocation.Request.Binding.PartIndex = input.Parts[0].PartIndex
		return []CapturePartRequest{copy}, nil
	}
	if _, err := NewCaptureModules([]CaptureModuleRegistration{registration}, func(d.Input, SourceInventory, time.Time, string) (ModuleCaptureContext, error) {
		return ModuleCaptureContext{}, d.ErrNotReady
	}); err != nil {
		return zero, err
	}
	return registration, nil
}

func validateSharedTeamRedis(source SourceInventory, policy c.RedisCapturePolicy) error {
	if source.Teams == nil || policy.Validate() != nil {
		return d.ErrNotReady
	}
	for _, scope := range source.Teams.Redis {
		if scope.ID != policy.Policy.Source.ID || scope.ServerID != policy.ServerID || scope.Database != policy.Policy.DB {
			return d.ErrNotReady
		}
		for _, id := range scope.TeamIDs {
			prefix := "claw:team:" + strconv.Itoa(id) + ":"
			covered := false
			for _, allowed := range policy.Policy.Prefixes {
				if strings.HasPrefix(prefix, allowed) {
					covered = true
				}
			}
			if !covered {
				return d.ErrNotReady
			}
			for _, excluded := range policy.ExcludePrefixes {
				if strings.HasPrefix(prefix, excluded) || strings.HasPrefix(excluded, prefix) {
					return d.ErrNotReady
				}
			}
		}
	}
	return nil
}
