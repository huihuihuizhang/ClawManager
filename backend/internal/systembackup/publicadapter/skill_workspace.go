package publicadapter

import (
	"encoding/json"
	"strings"

	"clawreef/internal/systembackup/worker"
	d "clawreef/internal/systembackupdispatch"
	sh "clawreef/internal/systembackupskillhub"
)

func validateOriginalSkillWorkspace(source SourceInventory, r CapturePartRequest) error {
	s := r.Invocation.Request.SkillWorkspace
	if source.Skills == nil || s == nil || s.Validate() != nil || s.InventorySHA256 != source.Skills.SHA256() || s.MountID != "workspace" || r.Part != instanceMountPart(s.InstanceID, s.MountID) || r.Category != "instances" || r.Invocation.Request.Operation != "capture-workspace" || r.Invocation.FormalCapture == nil || r.Invocation.ProviderKey == nil || r.Invocation.Request.RuntimePolicy == nil || s.Runtime != r.Invocation.Request.RuntimePolicy.Runtime {
		return d.ErrNotReady
	}
	var instance *InstanceIdentity
	for n := range source.Instances {
		if source.Instances[n].ID == s.InstanceID {
			instance = &source.Instances[n]
		}
	}
	if instance == nil || s.Runtime.Type != instance.Type || s.Runtime.Mode != instance.Mode || s.Runtime.Backend != instance.Backend || s.Runtime.Variant != instance.Variant || s.Runtime.OS != instance.OS {
		return d.ErrNotReady
	}
	// An OpenCode Pro selected project is not in the old instance projection.
	// Keep it closed until its original SQL project mapping is independently
	// frozen; a caller-provided path cannot choose a different source directory.
	if strings.EqualFold(instance.Type, "opencode") && strings.EqualFold(instance.Mode, "pro") {
		return d.ErrNotReady
	}
	original, err := source.Skills.WorkspaceRequirements()
	if err != nil {
		return err
	}
	allowed := map[sh.WorkspaceCaptureRequirement]bool{}
	for _, requirement := range original {
		allowed[requirement] = true
	}
	for _, requirement := range s.Requirements {
		if !allowed[requirement] {
			return d.ErrNotReady
		}
	}
	return nil
}

// Required Skills dependencies are checked against the ACTUAL assembled
// original invocations, not a parallel "workspace covered" boolean. Each such
// formal workspace observer must authenticate its archive's original MD5.
func validateSkillWorkspaceParts(source SourceInventory, parts []JobPart) error {
	covered := map[int]bool{}
	for _, part := range parts {
		var inv worker.Invocation
		if json.Unmarshal(part.InvocationJSON, &inv) != nil {
			return d.ErrNotReady
		}
		if inv.Request.SkillWorkspace == nil {
			continue
		}
		if validateOriginalSkillWorkspace(source, CapturePartRequest{Part: part.Part, Category: part.Category, Invocation: inv}) != nil {
			return d.ErrNotReady
		}
		for _, requirement := range inv.Request.SkillWorkspace.Requirements {
			covered[requirement.BlobID] = true
		}
	}
	if source.Skills != nil {
		for _, blob := range source.Skills.Blobs {
			if blob.ObjectKey == "" && !covered[blob.ID] {
				return d.ErrNotReady
			}
		}
	}
	return nil
}
