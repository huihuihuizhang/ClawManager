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
	service *DeploymentService
	owner   *PublicJobOwner
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
	profile = b.WithSkillCaptureInventory(b.WithTeamsSourceFacts(profile))
	profile.BuildParts = nil
	profile.FreezeSourcesWithWriters = func(ctx context.Context, in d.Input, source b.SourceInventory, writers []b.FrozenWriter) (*team.Inventory, json.RawMessage, error) {
		return s.freezeProductionSource(ctx, owner, in, source, writers, nil)
	}
	profile.CheckFrozenSources = func(ctx context.Context, in d.Input, current, frozen b.SourceInventory, writers []b.FrozenWriter) error {
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
	factory := func(in d.Input, source b.SourceInventory, hold time.Time, writers []b.FrozenWriter) (*b.CaptureModules, error) {
		return productionCaptureModules(in, source, hold, writers, s.captureMaterials.Operations, s.captureMaterials.Revision)
	}
	owner.productionSource = binding
	return profile, factory, nil
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
	if in.Authority.TaskType != "backup" || in.Backup == nil || in.Backup.TaskPurpose != "acceptance" || d.ValidateBackupSpec(in.Backup) != nil {
		return d.ErrNotReady
	}
	return nil
}
