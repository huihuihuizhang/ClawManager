package systembackupskillhub

import (
	"context"
	"errors"
	"math"
	"reflect"
	"testing"

	"clawreef/internal/models"
)

func TestObjectCapturePlanIncludesUnreferencedAndSharedObjects(t *testing.T) {
	blobs := []models.SkillBlob{{ID: 1, ObjectKey: "shared.zip", SizeBytes: 5}, {ID: 2, ObjectKey: "shared.zip", SizeBytes: 5}, {ID: 3, ObjectKey: ""}}
	inventory := []FrozenObject{{Key: "unreferenced.zip", VersionID: "v2", Size: 8}, {Key: "shared.zip", VersionID: "v1", Size: 5}}
	plan, err := PrepareObjectCapture(context.Background(), blobs, inventory, ObjectCaptureLimits{MaxObjects: 2, MaxObjectBytes: 8, MaxTotalBytes: 13, MaxIndexBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Objects) != 2 || plan.TotalBytes != 13 || plan.Objects[0].Key != "shared.zip" || !reflect.DeepEqual(plan.UnpackagedBlobIDs, []int{3}) {
		t.Fatalf("lost objects/workspace requirement: %#v", plan)
	}
	plan.Objects[0].VersionID = "mutated"
	if inventory[1].VersionID != "v1" {
		t.Fatal("plan aliases input")
	}
}
func TestObjectCapturePlanRejectsIncompleteOrOversizedInventory(t *testing.T) {
	for _, name := range []string{"missing", "wrong_size", "duplicate", "unversioned", "unsafe_key", "item_capacity", "byte_capacity", "object_capacity", "overflow_total"} {
		t.Run(name, func(t *testing.T) {
			blobs := []models.SkillBlob{{ID: 1, ObjectKey: "key", SizeBytes: 5}}
			inventory := []FrozenObject{{Key: "key", VersionID: "v1", Size: 5}}
			limits := ObjectCaptureLimits{MaxObjects: 5, MaxObjectBytes: 10, MaxTotalBytes: 20, MaxIndexBytes: 1 << 20}
			switch name {
			case "missing":
				inventory = nil
			case "wrong_size":
				inventory[0].Size = 6
			case "duplicate":
				inventory = append(inventory, inventory[0])
			case "unversioned":
				inventory[0].VersionID = ""
			case "unsafe_key":
				inventory[0].Key = "../escape"
			case "item_capacity":
				limits.MaxObjects = 0
			case "byte_capacity":
				limits.MaxTotalBytes = 4
			case "object_capacity":
				limits.MaxObjectBytes = 4
			case "overflow_total":
				limits.MaxTotalBytes = math.MaxInt64
				limits.MaxObjectBytes = math.MaxInt64
				inventory = append(inventory, FrozenObject{Key: "large", VersionID: "v2", Size: math.MaxInt64 - 1})
			}
			got, err := PrepareObjectCapture(context.Background(), blobs, inventory, limits)
			if err == nil || !reflect.DeepEqual(got, ObjectCapturePlan{}) {
				t.Fatalf("partial/invalid plan: %#v %v", got, err)
			}
			if name == "overflow_total" && !errors.Is(err, ErrCapacity) {
				t.Fatalf("overflow error=%v", err)
			}
		})
	}
}
