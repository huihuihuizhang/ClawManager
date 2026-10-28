package systembackupskillhub

import (
	"context"
	"io"

	"clawreef/internal/models"
)

// RestoredObjectLocation is supplied by the shared restore coordinator after
// verifying its target upload receipt, isolated root and exact version. It is
// not a source URL or an authorization claim this module can authenticate.
type RestoredObjectLocation struct {
	Key       string
	VersionID string
}

type ObjectRestorePlan struct {
	Objects                    []FrozenObject
	ObjectsWithOmittedMetadata int
	UnpackagedBlobIDs          []int
}

// PrepareObjectRestore ties authenticated capture results and target receipts
// to the SQL RestoreMapping.ObjectKeys. Referenced keys must match SQL exactly;
// unreferenced inventory objects also require unique target locations. Pending
// workspace proofs and metadata warnings remain explicit in the returned plan.
// This is a pure local preparation step, not a public Runner or permission
// adapter. The caller must authenticate all inputs against one sealed artifact
// and isolated target before using the plan.
func PrepareObjectRestore(ctx context.Context, blobs []models.SkillBlob, objectKeys map[string]string, inventory []FrozenObject, captured []CapturedObject, targets map[string]RestoredObjectLocation, limits ObjectCaptureLimits) (ObjectRestorePlan, error) {
	var empty ObjectRestorePlan
	plan, err := PrepareObjectCapture(ctx, blobs, inventory, limits)
	if err != nil {
		return empty, err
	}
	if len(targets) != len(plan.Objects) {
		return empty, ErrObjectCoverage
	}
	// Reuse the closed full-index validation without publishing or buffering it.
	index, err := WriteCapturedObjectIndex(ctx, io.Discard, plan, captured, limits.MaxIndexBytes)
	if err != nil {
		return empty, err
	}
	refs := map[string]bool{}
	for _, blob := range blobs {
		if blob.ObjectKey != "" {
			refs[blob.ObjectKey] = true
		}
	}
	if len(objectKeys) != len(refs) {
		return empty, ErrMapping
	}
	byKey := make(map[string]CapturedObject, len(captured))
	for _, item := range captured {
		byKey[item.Object.Key] = item
	}
	seen := map[string]bool{}
	checks := make([]FrozenObject, 0, len(plan.Objects))
	for _, source := range plan.Objects {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		target, ok := targets[source.Key]
		if !ok || !validObjectKey(target.Key) || seen[target.Key] {
			return empty, ErrMapping
		}
		seen[target.Key] = true
		if refs[source.Key] {
			key, ok := objectKeys[source.Key]
			if !ok || key != target.Key {
				return empty, ErrMapping
			}
		}
		item := byKey[source.Key]
		metadata := cloneMetadata(item.Digest.Properties.Metadata)
		checks = append(checks, FrozenObject{Key: target.Key, VersionID: target.VersionID,
			Size: source.Size, SHA256: item.Digest.SHA256, Metadata: &metadata})
	}
	// Target names/versions may be longer than source names; bound them again.
	targetPlan, err := PrepareObjectCapture(ctx, nil, checks, limits)
	if err != nil {
		return empty, err
	}
	return ObjectRestorePlan{Objects: targetPlan.Objects,
		ObjectsWithOmittedMetadata: index.ObjectsWithOmittedMetadata,
		UnpackagedBlobIDs:          append([]int(nil), plan.UnpackagedBlobIDs...)}, nil
}

// VerifyObjectRestorePlan reads only target versions using independently scoped
// credentials. It validates every selector before any I/O and never substitutes
// a current version or computes expected digests from the target. Success covers
// only object bytes/metadata, NOT SQL, workspace proofs, source metadata warnings
// or whole-domain acceptance. Public integration must consume those separately.
func VerifyObjectRestorePlan(ctx context.Context, reader VersionReader, plan ObjectRestorePlan, limits ObjectCaptureLimits) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if nilObjectAdapter(reader) {
		return ErrObject
	}
	frozen, err := PrepareObjectCapture(ctx, nil, plan.Objects, limits)
	if err != nil {
		return err
	}
	for _, object := range frozen.Objects {
		if !validSHA256(object.SHA256) {
			return ErrObject
		}
		if object.Metadata == nil {
			return ErrObjectMetadata
		}
	}
	for _, object := range frozen.Objects {
		if err := VerifyRestoredObject(ctx, reader, object, limits.MaxObjectBytes); err != nil {
			return err
		}
	}
	return ctx.Err()
}
