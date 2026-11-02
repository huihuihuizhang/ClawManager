package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/team"
	d "clawreef/internal/systembackupdispatch"
)

type productionSourceBinding struct {
	service        *DeploymentService
	owner          *PublicJobOwner
	plan           *productionCapturePlan
	materialSHA256 string
}

func (s *DeploymentService) attachProductionSources(owner *PublicJobOwner, profile b.LinuxProfileConfig) (b.LinuxProfileConfig, func(d.Input, b.SourceInventory, time.Time, []b.FrozenWriter) (*b.CaptureModules, error), error) {
	if s.Config.CaptureScope != "six-part" {
		return profile, nil, nil
	}
	if owner == nil || s.Config.RuntimeSources == nil || s.RuntimeControl == nil {
		return b.LinuxProfileConfig{}, nil, d.ErrNotReady
	}
	binding := &productionSourceBinding{service: s, owner: owner}
	if !s.ForwardEnabled {
		owner.productionSource = binding
		return profile, nil, nil
	}
	if s.checkProductionCaptureMaterials() != nil || s.captureMaterials.Discovery == nil || s.captureMaterials.Discovery.validate() != nil || s.captureMaterials.ControlEvidence == nil || s.captureMaterials.ControlEvidenceSource == nil {
		return b.LinuxProfileConfig{}, nil, d.ErrNotReady
	}
	for _, operation := range s.captureMaterials.Operations {
		if !validProductionOperationMounts(operation) {
			return b.LinuxProfileConfig{}, nil, d.ErrNotReady
		}
	}
	plan, err := newProductionCapturePlan(s.captureMaterials.Operations, s.captureMaterials.Revision)
	if err != nil {
		return b.LinuxProfileConfig{}, nil, err
	}
	binding.plan, binding.materialSHA256 = plan, s.captureInput.SHA256
	profile = b.WithSkillCaptureInventory(b.WithTeamsSourceFacts(profile))
	profile.BuildParts = nil
	profile.FreezeSourcesWithWriters = func(ctx context.Context, in d.Input, source b.SourceInventory, writers []b.FrozenWriter) (*team.Inventory, json.RawMessage, error) {
		if s.Config.StagingLocation != nil && s.checkStagingLocation(ctx, owner.Client) != nil {
			return nil, nil, d.ErrNotReady
		}
		return s.freezeProductionSource(ctx, owner, in, source, writers, nil)
	}
	profile.CheckFrozenSources = func(ctx context.Context, in d.Input, current, frozen b.SourceInventory, writers []b.FrozenWriter) error {
		if s.Config.StagingLocation != nil && s.checkStagingLocation(ctx, owner.Client) != nil {
			return d.ErrNotReady
		}
		var saved productionCaptureMetadata
		if decodeMetadataCanonical(frozen.CaptureMetadata, &saved) != nil {
			return d.ErrNotReady
		}
		teams, metadata, err := s.freezeProductionSource(ctx, owner, in, current, writers, &saved)
		if err != nil {
			return err
		}
		originalTeams, _ := json.Marshal(frozen.Teams)
		actualTeams, _ := json.Marshal(teams)
		if !bytes.Equal(originalTeams, actualTeams) || !bytes.Equal(frozen.CaptureMetadata, metadata) {
			return d.ErrNotReady
		}
		return nil
	}
	// The factory is PURE and consumes the exact post-writer source metadata.
	// Original files/source grants are rechecked by the freeze/check hooks.
	factory := binding.moduleFactory()
	owner.productionSource = binding
	return profile, factory, nil
}

func (x *productionSourceBinding) matchesCapturePlan() bool {
	return x != nil && x.service != nil && x.owner != nil && x.owner.productionSource == x && x.service.ForwardEnabled && x.service.captureMaterials != nil && x.service.captureInput != nil && x.materialSHA256 != "" && x.materialSHA256 == x.service.captureInput.SHA256 && x.plan.matches(x.service.captureMaterials.Operations, x.service.captureMaterials.Revision)
}

func (x *productionSourceBinding) moduleFactory() func(d.Input, b.SourceInventory, time.Time, []b.FrozenWriter) (*b.CaptureModules, error) {
	plan := x.plan
	return func(in d.Input, source b.SourceInventory, hold time.Time, writers []b.FrozenWriter) (*b.CaptureModules, error) {
		if !x.matchesCapturePlan() || x.plan != plan {
			return nil, d.ErrNotReady
		}
		cfg := x.service.Config
		node := cfg.Workspace.Node
		if cfg.StagingLocation != nil {
			if cfg.StagingLocation.validate(cfg) != nil {
				return nil, d.ErrNotReady
			}
			node = cfg.StagingLocation.Node
		}
		if node == "" || node != cfg.Workspace.Node || cfg.Security.NodeUIDs[node] == "" {
			return nil, d.ErrNotReady
		}
		return plan.build(in, source, hold, writers, node)
	}
}

func (o *PublicJobOwner) supportsCapture(in d.Input) error {
	if o == nil {
		return d.ErrNotReady
	}
	if supportedPublicCapture(in) == nil {
		return nil
	}
	binding := o.productionSource
	if binding == nil || binding.owner != o || binding.service == nil || binding.service.Config.CaptureScope != "six-part" || in.Authority.InstallationID != binding.service.Config.InstallationID {
		return d.ErrNotReady
	}
	if in.Authority.TaskType == "preflight" && in.Backup == nil {
		return nil
	}
	if !completeProductionCaptureInput(in) {
		return d.ErrNotReady
	}
	return nil
}

// This is only the admitted task shape. Original authority, config, grants,
// materials and source-window checks still run at their existing boundaries.
func completeProductionCaptureInput(in d.Input) bool {
	return in.Authority.TaskType == "backup" && d.ValidateBackupSpec(in.Backup) == nil && len(in.Backup.RequestedParts) == 6
}
