package profile

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"clawreef/internal/systembackup/artifact"
	"clawreef/internal/systembackup/control"
	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/staging"
)

var _ control.ProfileDriver = (*Driver)(nil)

func (d *Driver) Bind(ctx context.Context, t control.Task, raw json.RawMessage) (*control.Execution, error) {
	var p plan
	if json.Unmarshal(raw, &p) != nil || p.Version != "kubernetes-linux.v1" || p.Task != t.ID || p.Revision != t.ProfileRevision || p.Revision != d.Metadata().Revision || p.Deadline != t.Deadline {
		return nil, ErrProfile
	}
	owner, e := d.bindSix(t, p)
	if e != nil {
		return nil, e
	}
	x := &control.Execution{Identity: p.Identity, HoldUntil: time.UnixMilli(p.Deadline), ResumeTimeout: 5 * time.Minute}
	x.PrepareResources = func(ctx context.Context) error {
		if e := d.fence(ctx, t, false); e != nil {
			return e
		}
		if e := d.prepareDirectories(t); e != nil {
			return e
		}
		if t.Request.Kind != "backup" {
			return d.stageInput(ctx, t, p)
		}
		if owner != nil {
			return owner.Prepare(ctx)
		}
		return nil
	}
	x.Cleanup = func(ctx context.Context) error {
		var e error
		if owner != nil {
			e = owner.Cleanup(ctx)
		}
		return errors.Join(e, d.cleanup(ctx, t, p))
	}
	if t.Request.Kind == "backup" {
		var e error
		x.Writers, _, e = d.writers(t, p)
		if e != nil {
			return nil, e
		}
		x.CheckSource = func(ctx context.Context) error {
			return d.checkSource(ctx, t, p)
		}
		x.ResolveMutations = func(ctx context.Context) error {
			var e error
			if owner != nil {
				e = owner.ResolveMutations(ctx)
			}
			return errors.Join(e, d.resolveMutations(ctx, t, p))
		}
		x.ValidateCapture = func(ctx context.Context, parts []flow.Part) error {
			base := parts
			if owner != nil {
				if e := owner.Validate(ctx, parts); e != nil {
					return e
				}
				base = ownParts(p, parts)
			}
			b, e := d.bundle(ctx, t, p, base)
			if e != nil {
				return e
			}
			if d.Config.SixDomainModule != nil {
				return d.prepareSixDomain(ctx, t, b, parts)
			}
			return nil
		}
		x.Publish = func(ctx context.Context, parts []flow.Part) error {
			if d.Config.SixDomainModule != nil {
				return d.publishSixDomain(ctx, t, false)
			}
			b, e := d.bundle(ctx, t, p, parts)
			if e != nil {
				return e
			}
			root, e := d.Staging.OpenRoot(t.ID)
			if e != nil {
				return e
			}
			defer root.Close()
			return d.Publisher.Publish(ctx, t, control.Publication{Bundle: b, KeyID: d.Config.SignerID}, func(part artifact.Part) (io.ReadCloser, error) { return staging.OpenFile(ctx, root, part.Receipt) })
		}
	} else {
		x.Preflight = func(ctx context.Context) error { return d.blankTarget(ctx, t, p) }
		x.CheckTargetStopped = func(ctx context.Context) error { return d.checkTarget(ctx, t, p) }
	}
	for _, w := range p.Work {
		if w.LocalAssets {
			if t.Request.Kind != "backup" || w.PartID != "assets" || w.Invocation.Request.Operation != "capture-assets" {
				return nil, ErrProfile
			}
			c := &assetCollector{d: d, t: t, p: p, w: w}
			x.Capture = append(x.Capture, c)
			continue
		}
		c := &collector{d: d, t: t, p: p, w: w}
		switch {
		case strings.HasPrefix(w.Invocation.Request.Operation, "capture-"):
			x.Capture = append(x.Capture, c)
		case strings.HasPrefix(w.Invocation.Request.Operation, "restore-"):
			x.Restore = append(x.Restore, c)
		case strings.HasPrefix(w.Invocation.Request.Operation, "verify-"):
			x.Verify = append(x.Verify, c)
		default:
			return nil, ErrProfile
		}
	}
	if owner != nil {
		x.Capture = append(x.Capture, owner.Collectors...)
	}
	return x, nil
}

func (d *Driver) bundle(ctx context.Context, t control.Task, p plan, parts []flow.Part) (artifact.Bundle, error) {
	b := artifact.Bundle{Version: artifact.Version, ID: t.ID, Purpose: "functional_test", Scope: []string{"users", "instances"}, PolicyVersion: d.Config.PolicyVersion, Users: p.Users, Instances: len(p.Instances)}
	b.Contract = d.contract()
	if len(parts) != len(p.Work) || len(parts) != b.Instances+2 {
		return b, ErrProfile
	}
	root, e := d.Staging.OpenRoot(t.ID)
	if e != nil {
		return b, ErrProfile
	}
	defer root.Close()
	results := map[string]flow.Part{}
	for _, part := range parts {
		if _, exists := results[part.ID]; exists {
			return b, ErrProfile
		}
		results[part.ID] = part
	}
	for _, w := range p.Work {
		result, ok := results[w.ID]
		hash, e := w.Invocation.Hash()
		if w.LocalAssets {
			hash = kube.ContentHash(w)
			e = nil
		}
		if !ok || e != nil || result.Checkpoint != hash {
			return b, ErrProfile
		}
		var receipt staging.Receipt
		if json.Unmarshal([]byte(result.SealedRef), &receipt) != nil || receipt.Name != w.Invocation.Request.ArtifactName {
			return b, ErrProfile
		}
		f, e := staging.OpenFile(ctx, root, receipt)
		if e != nil {
			return b, e
		}
		key, e := d.Keys.Unwrap(ctx, w.Invocation.Request.Binding, w.Key)
		if e != nil {
			f.Close()
			return b, e
		}
		e = staging.Open(ctx, f, io.Discard, key, w.Invocation.Request.Binding, w.Invocation.Request.MaxCompressedBytes)
		clear(key)
		f.Close()
		if e != nil {
			return b, e
		}
		b.Parts = append(b.Parts, artifact.Part{ID: w.PartID, Receipt: receipt, Binding: w.Invocation.Request.Binding, Key: w.Key})
	}
	if e = d.validateWorkBuddyCapture(ctx, root, b, p); e != nil {
		return b, e
	}
	_, e = artifact.PublishedBundle(b)
	return b, e
}

func (d *Driver) cleanup(ctx context.Context, t control.Task, p plan) error {
	runner, e := d.runner(t, true)
	if e != nil {
		return e
	}
	// Jobs have already been stopped and proved by Pipeline.Recover. Delete only
	// resources from the authoritative ledger, retaining isolated restored PVCs.
	rows, e := d.Store.DB.QueryContext(ctx, "SELECT kind,namespace_name,resource_name,owner_marker,request_sha256,request_json FROM system_backup_resources WHERE task_id=? ORDER BY CASE kind WHEN 'Job' THEN 0 WHEN 'PersistentVolumeClaim' THEN 2 WHEN 'VolumeSnapshot' THEN 3 ELSE 1 END", t.ID)
	if e != nil {
		return ErrProfile
	}
	var intents []kube.ResourceIntent
	for rows.Next() {
		var i kube.ResourceIntent
		if e = rows.Scan(&i.Kind, &i.Identity.Namespace, &i.Identity.Name, &i.Identity.Owner, &i.RequestSHA256, &i.RequestJSON); e != nil {
			rows.Close()
			return ErrProfile
		}
		intents = append(intents, i)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return ErrProfile
	}
	for _, i := range intents {
		keep := false
		for _, w := range p.Work {
			if i.Kind == "PersistentVolumeClaim" && w.RestoreClaim == i.Identity.Name && w.Namespace == i.Identity.Namespace {
				keep = true
			}
		}
		if keep {
			continue
		}
		r, e := runner.Journal.Prepare(ctx, i)
		if e != nil {
			return e
		}
		for {
			done, e := runner.Cleanup(ctx, r)
			if e != nil {
				return e
			}
			if done {
				break
			}
			if !poll(ctx) {
				return ctx.Err()
			}
			r, e = runner.Journal.Prepare(ctx, i)
			if e != nil {
				return e
			}
		}
	}
	for _, w := range p.Work {
		if w.LocalAssets {
			continue
		}
		c := collector{d: d, t: t, p: p, w: w}
		if e = c.revokeIfPresent(ctx); e != nil {
			return e
		}
		name := c.identity("-identity").Name
		raw, e := d.Vault.Get(ctx, t, name, "worker-identity")
		if errors.Is(e, control.ErrNotFound) {
			continue
		}
		if e != nil {
			return e
		}
		var identity control.TaskIdentity
		e = json.Unmarshal(raw, &identity)
		clear(raw)
		if e != nil {
			return ErrProfile
		}
		uri := identity.SPIFFE
		identity.Clear()
		idx := strings.LastIndex(uri, "/")
		if idx < 0 {
			return ErrProfile
		}
		if e = d.Identities.Delete(ctx, t, w.Namespace, name, uri[idx+1:]); e != nil {
			return e
		}
	}
	return nil
}
