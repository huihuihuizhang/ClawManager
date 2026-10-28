package systembackupresources

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func imageNormalizeFixture() restoreImageInput {
	key := restoreImageKey{"workbuddy", "desktop", "linux"}
	return restoreImageInput{Source: restoreFieldTable{Name: "system_image_settings", Columns: restoreFieldColumns()["system_image_settings"], Rows: []restoreFieldRow{{
		"id": fieldString("1"), "instance_type": fieldString(key.InstanceType), "runtime_type": fieldString(key.RuntimeType), "runtime_variant": fieldString(key.Variant),
		"display_name": fieldString("private-secret"), "image": fieldString("private-secret"), "is_enabled": fieldString("1"), "created_at": fieldString("2026-10-22 01:02:03"), "updated_at": fieldString("2026-10-22 01:02:03.000001"),
	}}}, Targets: []restoreImageTarget{{SourceID: 1, SourceKey: key, LogicalKeySHA256: strings.Repeat("a", 64), Image: "registry.example/runtime@sha256:" + strings.Repeat("b", 64), DisplayName: "Target Runtime"}}, OccupiedIDs: []int64{2}, OccupiedLogicalKeys: []string{strings.Repeat("c", 64)}, Budget: fieldTestBudget}
}
func TestNormalizeRestoreImagesCompleteDisabledCandidate(t *testing.T) {
	i := imageNormalizeFixture()
	got, err := normalizeRestoreImages(context.Background(), i)
	if err != nil {
		t.Fatal(err)
	}
	row := got.Rows[0]
	if len(row) != 9 || !reflect.DeepEqual(got.Columns, i.Source.Columns) || *row["is_enabled"] != "0" || *row["image"] != i.Targets[0].Image || *row["display_name"] != "Target Runtime" {
		t.Fatal("incomplete target-only candidate")
	}
	for _, column := range []string{"id", "instance_type", "runtime_type", "runtime_variant", "created_at", "updated_at"} {
		if *row[column] != *i.Source.Rows[0][column] {
			t.Fatal("historical key/time changed")
		}
	}
	for _, value := range row {
		if value != nil && strings.Contains(*value, "private-secret") {
			t.Fatal("source image/name leaked")
		}
	}
	*row["image"] = "changed"
	*row["created_at"] = "changed"
	got.Columns[0] = "changed"
	if i.Targets[0].Image == "changed" || *i.Source.Rows[0]["created_at"] != "2026-10-22 01:02:03" || *i.Source.Rows[0]["is_enabled"] != "1" || i.Source.Columns[0] != "id" {
		t.Fatal("input aliased")
	}
}
func TestNormalizeRestoreImagesFailuresDiscardCandidate(t *testing.T) {
	cases := map[string]func(*restoreImageInput){
		"missing_mapping":   func(i *restoreImageInput) { i.Targets = nil },
		"extra_mapping":     func(i *restoreImageInput) { i.Targets = append(i.Targets, i.Targets[0]) },
		"wrong_source_id":   func(i *restoreImageInput) { i.Targets[0].SourceID = 3 },
		"invalid_source_id": func(i *restoreImageInput) { i.Targets[0].SourceID = 0 },
		"wrong_source_key":  func(i *restoreImageInput) { i.Targets[0].SourceKey.Variant = "windows" },
		"missing_identity":  func(i *restoreImageInput) { i.Targets[0].LogicalKeySHA256 = "" },
		"occupied_key":      func(i *restoreImageInput) { i.OccupiedLogicalKeys = []string{i.Targets[0].LogicalKeySHA256} },
		"duplicate_occupied_key": func(i *restoreImageInput) {
			i.OccupiedLogicalKeys = append(i.OccupiedLogicalKeys, i.OccupiedLogicalKeys[0])
		},
		"invalid_occupied_key":  func(i *restoreImageInput) { i.OccupiedLogicalKeys = []string{"bad"} },
		"occupied_id":           func(i *restoreImageInput) { i.OccupiedIDs = []int64{1} },
		"duplicate_occupied_id": func(i *restoreImageInput) { i.OccupiedIDs = []int64{2, 2} },
		"invalid_occupied_id":   func(i *restoreImageInput) { i.OccupiedIDs = []int64{-1} },
		"missing_image":         func(i *restoreImageInput) { i.Targets[0].Image = "" },
		"missing_name":          func(i *restoreImageInput) { i.Targets[0].DisplayName = "" },
		"image_URL":             func(i *restoreImageInput) { i.Targets[0].Image = "https://private-secret/" },
		"image_space":           func(i *restoreImageInput) { i.Targets[0].Image = "registry.example/runtime:bad tag" },
		"name_control":          func(i *restoreImageInput) { i.Targets[0].DisplayName = "private-secret\n" },
		"long_name":             func(i *restoreImageInput) { i.Targets[0].DisplayName = strings.Repeat("界", 256) },
		"invalid_utf8":          func(i *restoreImageInput) { i.Targets[0].DisplayName = string([]byte{255}) },
		"source_null_image":     func(i *restoreImageInput) { i.Source.Rows[0]["image"] = nil },
		"source_null_variant":   func(i *restoreImageInput) { i.Source.Rows[0]["runtime_variant"] = nil },
		"runtime_alias":         func(i *restoreImageInput) { i.Source.Rows[0]["runtime_type"] = fieldString("Desktop") },
		"invalid_source_switch": func(i *restoreImageInput) { i.Source.Rows[0]["is_enabled"] = fieldString("true") },
		"invalid_source_time":   func(i *restoreImageInput) { i.Source.Rows[0]["created_at"] = fieldString("2026-02-30 00:00:00") },
		"missing_column":        func(i *restoreImageInput) { delete(i.Source.Rows[0], "display_name") },
		"extra_column":          func(i *restoreImageInput) { i.Source.Rows[0]["extra"] = nil },
		"wrong_table":           func(i *restoreImageInput) { i.Source.Name = "instances" },
		"byte_budget":           func(i *restoreImageInput) { i.Budget.Bytes = 1 },
		"invalid_budget":        func(i *restoreImageInput) { i.Budget.Rows = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			i := imageNormalizeFixture()
			mutate(&i)
			got, err := normalizeRestoreImages(context.Background(), i)
			if err == nil || !reflect.DeepEqual(got, restoreFieldTable{}) || strings.Contains(err.Error(), "private-secret") {
				t.Fatalf("unsafe candidate %v", err)
			}
		})
	}
}
func TestNormalizeRestoreImagesDuplicateLogicalIdentity(t *testing.T) {
	for _, mode := range []string{"raw_key", "B_equivalent_key", "duplicate_mapping_id"} {
		t.Run(mode, func(t *testing.T) {
			i := imageNormalizeFixture()
			i.OccupiedIDs = nil
			i.OccupiedLogicalKeys = nil
			row := cloneRestoreAuditRow(i.Source.Rows[0])
			row["id"] = fieldString("2")
			i.Source.Rows = append(i.Source.Rows, row)
			target := i.Targets[0]
			target.SourceID = 2
			if mode == "raw_key" {
				target.LogicalKeySHA256 = strings.Repeat("d", 64)
			} else {
				row["instance_type"] = fieldString("WORKBUDDY")
				target.SourceKey.InstanceType = "WORKBUDDY"
			}
			if mode == "duplicate_mapping_id" {
				target.SourceID = 1
				target.LogicalKeySHA256 = strings.Repeat("d", 64)
			}
			i.Targets = append(i.Targets, target)
			if got, err := normalizeRestoreImages(context.Background(), i); err == nil || !reflect.DeepEqual(got, restoreFieldTable{}) {
				t.Fatal("duplicate identity accepted")
			}
		})
	}
}
func TestNormalizeRestoreImagesEmptyNullBudgetAndCancellation(t *testing.T) {
	i := imageNormalizeFixture()
	i.Source.Rows[0]["runtime_variant"] = fieldString("")
	i.Targets[0].SourceKey.Variant = ""
	i.Source.Rows[0]["created_at"] = nil
	i.Source.Rows[0]["updated_at"] = nil
	got, err := normalizeRestoreImages(context.Background(), i)
	if err != nil || got.Rows[0]["created_at"] != nil || *got.Rows[0]["runtime_variant"] != "" {
		t.Fatal("SQL NULL or empty variant lost")
	}
	i = imageNormalizeFixture()
	i.Source.Rows = nil
	i.Targets = nil
	got, err = normalizeRestoreImages(context.Background(), i)
	if err != nil || len(got.Rows) != 0 || len(got.Columns) != 9 {
		t.Fatal("empty source synthesized a default")
	}
	i = imageNormalizeFixture()
	var size int64
	for _, v := range i.Source.Rows[0] {
		if v != nil {
			size += int64(len(*v))
		}
	}
	i.Budget.Bytes = size
	if got, err = normalizeRestoreImages(context.Background(), i); err == nil || !reflect.DeepEqual(got, restoreFieldTable{}) {
		t.Fatal("target image growth escaped budget")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err = normalizeRestoreImages(ctx, imageNormalizeFixture()); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(got, restoreFieldTable{}) {
		t.Fatal("cancellation lost")
	}
}
