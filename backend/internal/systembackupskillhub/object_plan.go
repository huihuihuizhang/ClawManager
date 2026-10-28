package systembackupskillhub

import (
	"context"
	"errors"
	"io"
	"math"
	"sort"
	"strings"

	"clawreef/internal/models"
)

var ErrObjectCoverage = errors.New("skill hub object inventory does not cover blob references")

type ObjectCaptureLimits struct {
	MaxObjects     int
	MaxObjectBytes int64
	MaxTotalBytes  int64
	MaxIndexBytes  int64
}

// ObjectCapturePlan retains every frozen inventory object, including objects
// not currently referenced by a blob. UnpackagedBlobIDs are unresolved B
// workspace-proof requirements, NOT successful or skippable object captures.
type ObjectCapturePlan struct {
	Objects           []FrozenObject
	TotalBytes        int64
	FrozenIndexBytes  int64
	UnpackagedBlobIDs []int
}

// PrepareObjectCapture reconciles blob references against the entire supplied
// frozen prefix inventory, and returns nothing on error. The caller must prove
// this inventory's completeness and checkpoint/gate binding before calling.
// MaxIndexBytes bounds the frozen list; the final enriched index must be bounded
// again by WriteCapturedObjectIndex. This plan cannot upgrade capture to strong.
func PrepareObjectCapture(ctx context.Context, blobs []models.SkillBlob, inventory []FrozenObject, limits ObjectCaptureLimits) (ObjectCapturePlan, error) {
	var empty ObjectCapturePlan
	if err := checkContext(ctx); err != nil {
		return empty, err
	}
	if limits.MaxObjects < 0 || limits.MaxObjectBytes < 0 || limits.MaxTotalBytes < 0 || limits.MaxIndexBytes < 2 || len(inventory) > limits.MaxObjects {
		return empty, ErrCapacity
	}
	plan := ObjectCapturePlan{FrozenIndexBytes: 2}
	byKey := map[string]FrozenObject{}
	for i, item := range inventory {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		if !validObjectKey(item.Key) || strings.TrimSpace(item.VersionID) == "" || item.VersionID == "null" || item.Size < 0 || (item.SHA256 != "" && !validSHA256(item.SHA256)) {
			return empty, ErrObject
		}
		if _, exists := byKey[item.Key]; exists {
			return empty, ErrObjectCoverage
		}
		if item.Size == math.MaxInt64 || item.Size > limits.MaxObjectBytes || item.Size > limits.MaxTotalBytes-plan.TotalBytes {
			return empty, ErrCapacity
		}
		if item.Metadata != nil {
			if _, err := CanonicalObjectMetadata(ctx, *item.Metadata); err != nil {
				return empty, err
			}
		}
		value := map[string]any{"key": item.Key, "size": item.Size, "version_id": item.VersionID}
		if item.Metadata != nil {
			value["metadata"] = metadataValue(*item.Metadata)
		}
		if i > 0 {
			plan.FrozenIndexBytes++
		}
		n, err := canonicalObjectJSON(ctx, io.Discard, value, limits.MaxIndexBytes-plan.FrozenIndexBytes)
		if err != nil {
			return empty, err
		}
		plan.FrozenIndexBytes += n
		plan.TotalBytes += item.Size
		byKey[item.Key] = item
	}
	plan.Objects = append([]FrozenObject(nil), inventory...)
	for i := range plan.Objects {
		if plan.Objects[i].Metadata != nil {
			m := cloneMetadata(*plan.Objects[i].Metadata)
			plan.Objects[i].Metadata = &m
		}
	}
	ids := map[int]bool{}
	for _, blob := range blobs {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		if !validID(blob.ID) || ids[blob.ID] || blob.SizeBytes < 0 {
			return empty, ErrObjectCoverage
		}
		ids[blob.ID] = true
		if blob.ObjectKey == "" {
			plan.UnpackagedBlobIDs = append(plan.UnpackagedBlobIDs, blob.ID)
			continue
		}
		item, exists := byKey[blob.ObjectKey]
		if !exists || item.Size != blob.SizeBytes {
			return empty, ErrObjectCoverage
		}
	}
	sort.Slice(plan.Objects, func(i, j int) bool { return plan.Objects[i].Key < plan.Objects[j].Key })
	sort.Ints(plan.UnpackagedBlobIDs)
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	return plan, nil
}
