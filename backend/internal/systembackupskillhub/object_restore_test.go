package systembackupskillhub

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"clawreef/internal/models"
)

func objectRestoreFixture(t *testing.T) ([]models.SkillBlob, map[string]string, ObjectCapturePlan, []CapturedObject, map[string]RestoredObjectLocation, ObjectCaptureLimits) {
	t.Helper()
	plan, captured := indexFixture(t)
	blobs := []models.SkillBlob{{ID: 1, ObjectKey: "a-shared", SizeBytes: 5}, {ID: 2, ObjectKey: "a-shared", SizeBytes: 5}, {ID: 3}}
	keys := map[string]string{"a-shared": "target/shared"}
	targets := map[string]RestoredObjectLocation{"a-shared": {Key: "target/shared", VersionID: "target-v1"}, "z-unreferenced": {Key: "target/orphan", VersionID: "target-v2"}}
	limits := ObjectCaptureLimits{MaxObjects: 2, MaxObjectBytes: 5, MaxTotalBytes: 10, MaxIndexBytes: 4096}
	return blobs, keys, plan, captured, targets, limits
}

func TestObjectRestorePlanConnectsSQLAndAllFrozenObjects(t *testing.T) {
	blobs, keys, source, captured, targets, limits := objectRestoreFixture(t)
	plan, err := PrepareObjectRestore(context.Background(), blobs, keys, source.Objects, captured, targets, limits)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Objects) != 2 || plan.ObjectsWithOmittedMetadata != 1 || !reflect.DeepEqual(plan.UnpackagedBlobIDs, []int{3}) {
		t.Fatalf("lost evidence requirements: %+v", plan)
	}
	// Returned metadata and target selectors must survive caller mutation.
	captured[0].Digest.Properties.Metadata.UserMetadata["owner"] = "mutated"
	targets["a-shared"] = RestoredObjectLocation{Key: "wrong", VersionID: "wrong"}
	calls := 0
	reader := objectReaderFunc(func(_ context.Context, key, version string) (ObjectVersion, error) {
		calls++
		if key != "target/shared" && key != "target/orphan" || !strings.HasPrefix(version, "target-v") {
			t.Fatal("source or current object read")
		}
		return ObjectVersion{Body: io.NopCloser(strings.NewReader("hello")), VersionID: version, Size: 5, Properties: &ObjectProperties{
			Metadata: ObjectMetadata{ContentType: "application/zip", UserMetadata: map[string]string{"owner": "value"}},
		}}, nil
	})
	if err := VerifyObjectRestorePlan(context.Background(), reader, plan, limits); err != nil || calls != 2 {
		t.Fatalf("verify=%v calls=%d", err, calls)
	}
}

func TestObjectRestorePlanRejectsIncompleteOrInconsistentMappings(t *testing.T) {
	for _, mode := range []string{"missing_orphan", "extra_target", "collision", "SQL_drift", "missing_SQL", "extra_SQL", "null_version", "unsafe_target", "missing_capture", "wrong_digest", "long_target", "metadata_missing", "missing_source"} {
		t.Run(mode, func(t *testing.T) {
			blobs, keys, source, captured, targets, limits := objectRestoreFixture(t)
			switch mode {
			case "missing_orphan":
				delete(targets, "z-unreferenced")
			case "extra_target":
				targets["extra"] = targets["a-shared"]
			case "collision":
				targets["z-unreferenced"] = targets["a-shared"]
			case "SQL_drift":
				keys["a-shared"] = "other/key"
			case "missing_SQL":
				delete(keys, "a-shared")
			case "extra_SQL":
				keys["unused"] = "other/key"
			case "null_version":
				targets["a-shared"] = RestoredObjectLocation{Key: "target/shared", VersionID: "null"}
			case "unsafe_target":
				targets["z-unreferenced"] = RestoredObjectLocation{Key: "../escape", VersionID: "v"}
			case "missing_capture":
				captured = captured[:1]
			case "wrong_digest":
				source.Objects[0].SHA256 = hashText("wrong")
			case "long_target":
				targets["z-unreferenced"] = RestoredObjectLocation{Key: strings.Repeat("x", 4096), VersionID: "v"}
			case "metadata_missing":
				captured[0].Digest.Properties = nil
			case "missing_source":
				blobs[0].ObjectKey = "missing"
			}
			got, err := PrepareObjectRestore(context.Background(), blobs, keys, source.Objects, captured, targets, limits)
			if err == nil || !reflect.DeepEqual(got, ObjectRestorePlan{}) {
				t.Fatalf("partial/invalid plan: %+v %v", got, err)
			}
		})
	}
}

func TestObjectRestoreVerifierPreflightsWholeSetAndRejectsTargetDrift(t *testing.T) {
	for _, mode := range []string{"late_invalid", "late_missing_metadata", "late_missing_digest", "byte_drift", "metadata_drift", "wrong_version", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			blobs, keys, source, captured, targets, limits := objectRestoreFixture(t)
			plan, err := PrepareObjectRestore(context.Background(), blobs, keys, source.Objects, captured, targets, limits)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "late_invalid":
				plan.Objects[1].VersionID = "null"
			case "late_missing_metadata":
				plan.Objects[1].Metadata = nil
			case "late_missing_digest":
				plan.Objects[1].SHA256 = ""
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "canceled" {
				cancel()
			}
			calls := 0
			reader := objectReaderFunc(func(_ context.Context, _ string, version string) (ObjectVersion, error) {
				calls++
				body := "hello"
				metadata := ObjectMetadata{ContentType: "application/zip", UserMetadata: map[string]string{"owner": "value"}}
				if mode == "byte_drift" {
					body = "wrong"
				}
				if mode == "metadata_drift" {
					metadata.ContentType = "text/plain"
				}
				if mode == "wrong_version" {
					version = "source-v1"
				}
				return ObjectVersion{Body: io.NopCloser(strings.NewReader(body)), VersionID: version, Size: 5, Properties: &ObjectProperties{Metadata: metadata}}, nil
			})
			if err := VerifyObjectRestorePlan(ctx, reader, plan, limits); err == nil {
				t.Fatal("accepted invalid restore")
			}
			if (strings.HasPrefix(mode, "late_") || mode == "canceled") && calls != 0 {
				t.Fatal("invalid plan performed target I/O")
			}
			if mode == "canceled" && !errors.Is(ctx.Err(), context.Canceled) {
				t.Fatal("lost cancellation")
			}
		})
	}
}
