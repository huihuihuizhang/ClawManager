package profile

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"clawreef/internal/systembackup/artifact"
	"clawreef/internal/systembackup/assets"
	"clawreef/internal/systembackup/control"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/staging"
)

func (d *Driver) contract() *artifact.DomainContract {
	policies := map[string]string{}
	for _, i := range d.Config.Instances {
		policies[fmt.Sprintf("instance-%d", i.ID)] = kube.ContentHash(d.Config.RuntimePolicies[i.Policy])
	}
	return &artifact.DomainContract{Version: "users-instances-contribution.v2", PolicySHA256: kube.ContentHash([]any{d.Config.Configs, d.Config.WorkBuddy, d.Config.Dependencies}), RuntimePolicies: policies, Dependencies: []string{"ai_gateway", "skill_hub", "teams", "resources"}, Assets: true}
}

type assetCollector struct {
	d *Driver
	t control.Task
	p plan
	w work
}

func (c *assetCollector) ID() string                        { return c.w.ID }
func (c *assetCollector) Prepare(ctx context.Context) error { return c.d.fence(ctx, c.t, false) }
func (c *assetCollector) Stop(ctx context.Context) error    { return c.d.fence(ctx, c.t, true) }
func (c *assetCollector) Capture(ctx context.Context) (flow.Part, error) {
	if c.t.Request.Kind != "backup" {
		return flow.Part{}, ErrProfile
	}
	writers, j, e := c.d.writers(c.t, c.p)
	if e != nil {
		return flow.Part{}, e
	}
	records, e := j.PendingPauses(ctx, c.p.Identity)
	if e != nil || len(records) != len(writers) {
		return flow.Part{}, ErrProfile
	}
	paused := map[string]flow.PauseRecord{}
	for _, record := range records {
		if _, exists := paused[record.WriterID]; exists {
			return flow.Part{}, ErrProfile
		}
		paused[record.WriterID] = record
	}
	for _, w := range writers {
		record, ok := paused[w.ID()]
		if !ok || w.CheckPaused(ctx, record.Original) != nil {
			return flow.Part{}, ErrProfile
		}
	}
	snapshot, e := domain.CaptureSource(ctx, c.d.Source, domain.Limits{MaxRows: c.d.Config.Source.MaxRows, MaxBytes: c.d.Config.Source.MaxMemoryBytes}, c.d.Config.Source.Name, c.d.Config.Source.ServerUUID)
	if e != nil || c.d.Config.Assets.CheckReferences(snapshot) != nil {
		return flow.Part{}, ErrProfile
	}
	set, e := assets.Capture(ctx, c.d.Client, c.d.Config.Assets, c.d.OpenObject)
	if e != nil {
		return flow.Part{}, ErrProfile
	}
	defer set.Clear()
	root, e := c.d.Staging.OpenRoot(c.t.ID)
	if e != nil {
		return flow.Part{}, e
	}
	defer root.Close()
	key, e := c.d.Keys.Unwrap(ctx, c.w.Invocation.Request.Binding, c.w.Key)
	if e != nil {
		return flow.Part{}, e
	}
	defer clear(key)
	receipt, e := staging.SealFile(ctx, root, c.w.Invocation.Request.ArtifactName, key, c.w.Invocation.Request.Binding, func(out io.Writer) error { return json.NewEncoder(out).Encode(set) })
	if e != nil {
		return flow.Part{}, e
	}
	if e = c.d.checkApplications(ctx, c.t, c.p, "capture"); e != nil {
		return flow.Part{}, e
	}
	raw, _ := json.Marshal(receipt)
	return flow.Part{ID: c.ID(), Checkpoint: kube.ContentHash(c.w), SealedRef: string(raw)}, nil
}
