package systembackupskillhub

import (
	"context"
	"errors"
	"io"
	"sort"

	"clawreef/internal/models"
)

// RestoreSampleInput contains original frozen projections and the complete
// captured object index. The coordinator must authenticate every input against
// ONE task/attempt/manifest before calling; no field here grants that authority.
type RestoreSampleInput struct {
	Inventory      CaptureInventory
	Users          map[int]bool
	InstanceOwners map[int]int
	Objects        []FrozenObject
	Captured       []CapturedObject
	ObjectLimits   ObjectCaptureLimits
}

// RestoreSample is a deterministic selection, never a verification receipt.
// It retains all original versions, bindings and jobs of one skill, their blob
// closure and every available location for its unpackaged blobs. SQL raw rows,
// objects and workspace bytes still require the existing independent verifiers.
// Keep this task-bound projection private; it contains original paths and keys.
type RestoreSample struct {
	InventorySHA256   string
	ObjectIndexSHA256 string
	Skill             CaptureSkill
	Versions          []CaptureVersion
	Blobs             []CaptureBlob
	Bindings          []CaptureBinding
	Jobs              []CaptureMaterializeJob
	Objects           []CapturedObject
	Workspaces        []WorkspaceCaptureRequirement
}

var ErrRestoreSampleUnavailable = errors.New("skill hub nonempty restore sample unavailable")

// SelectRestoreSample chooses the lowest skill ID having at least one version.
// No source/target I/O, decryption, writes or caller-provided coverage flags are
// involved. Empty or incomplete inputs return no partial selection. An absent
// binding/job remains absent; the selector never invents a relationship.
func SelectRestoreSample(ctx context.Context, input RestoreSampleInput) (RestoreSample, error) {
	var empty RestoreSample
	if err := checkContext(ctx); err != nil {
		return empty, err
	}
	if err := input.Inventory.Validate(input.Users, input.InstanceOwners); err != nil {
		return empty, err
	}
	inventory := CloneCaptureInventory(&input.Inventory)
	if inventory == nil {
		return empty, ErrRows
	}
	requirements, err := inventory.WorkspaceRequirements()
	if err != nil {
		return empty, err
	}
	blobs := make([]models.SkillBlob, 0, len(inventory.Blobs))
	for _, blob := range inventory.Blobs {
		blobs = append(blobs, models.SkillBlob{ID: blob.ID, ObjectKey: blob.ObjectKey, SizeBytes: blob.SizeBytes})
	}
	plan, err := PrepareObjectCapture(ctx, blobs, input.Objects, input.ObjectLimits)
	if err != nil {
		return empty, err
	}
	index, err := WriteCapturedObjectIndex(ctx, io.Discard, plan, input.Captured, input.ObjectLimits.MaxIndexBytes)
	if err != nil {
		return empty, err
	}
	if index.ObjectsWithOmittedMetadata != 0 {
		return empty, ErrObjectMetadata
	}
	versioned := map[int]bool{}
	for _, version := range inventory.Versions {
		versioned[version.SkillID] = true
	}
	var selected CaptureSkill
	for _, skill := range inventory.Skills {
		if versioned[skill.ID] && (selected.ID == 0 || skill.ID < selected.ID) {
			selected = skill
		}
	}
	if selected.ID == 0 {
		return empty, ErrRestoreSampleUnavailable
	}
	out := RestoreSample{InventorySHA256: inventory.SHA256(), ObjectIndexSHA256: index.SHA256, Skill: selected}
	requiredBlobs := map[int]bool{}
	for _, version := range inventory.Versions {
		if version.SkillID == selected.ID {
			out.Versions = append(out.Versions, version)
			requiredBlobs[version.BlobID] = true
		}
	}
	for _, binding := range inventory.Bindings {
		if binding.SkillID == selected.ID {
			out.Bindings = append(out.Bindings, binding)
		}
	}
	for _, job := range inventory.Jobs {
		if job.SkillID == selected.ID {
			out.Jobs = append(out.Jobs, job)
			requiredBlobs[job.BlobID] = true
		}
	}
	requiredKeys := map[string]bool{}
	for _, blob := range inventory.Blobs {
		if requiredBlobs[blob.ID] {
			out.Blobs = append(out.Blobs, blob)
			if blob.ObjectKey != "" {
				requiredKeys[blob.ObjectKey] = true
			}
		}
	}
	for _, object := range input.Captured {
		if requiredKeys[object.Object.Key] {
			object.Digest.Properties = cloneProperties(object.Digest.Properties)
			if object.Object.Metadata != nil {
				metadata := cloneMetadata(*object.Object.Metadata)
				object.Object.Metadata = &metadata
			}
			out.Objects = append(out.Objects, object)
		}
	}
	for _, requirement := range requirements {
		if requiredBlobs[requirement.BlobID] {
			out.Workspaces = append(out.Workspaces, requirement)
		}
	}
	sort.Slice(out.Versions, func(i, j int) bool { return out.Versions[i].ID < out.Versions[j].ID })
	sort.Slice(out.Blobs, func(i, j int) bool { return out.Blobs[i].ID < out.Blobs[j].ID })
	sort.Slice(out.Bindings, func(i, j int) bool { return out.Bindings[i].ID < out.Bindings[j].ID })
	sort.Slice(out.Jobs, func(i, j int) bool { return out.Jobs[i].ID < out.Jobs[j].ID })
	sort.Slice(out.Objects, func(i, j int) bool { return out.Objects[i].Object.Key < out.Objects[j].Object.Key })
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	return out, nil
}
