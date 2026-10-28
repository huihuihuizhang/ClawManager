package systembackupskillhub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func indexFixture(t *testing.T) (ObjectCapturePlan, []CapturedObject) {
	t.Helper()
	inventory := []FrozenObject{{Key: "z-unreferenced", VersionID: "v2", Size: 5}, {Key: "a-shared", VersionID: "v1", Size: 5}}
	plan, err := PrepareObjectCapture(context.Background(), nil, inventory, ObjectCaptureLimits{MaxObjects: 2, MaxObjectBytes: 5, MaxTotalBytes: 10, MaxIndexBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	var captured []CapturedObject
	for _, entry := range inventory {
		captured = append(captured, CapturedObject{Object: entry, Digest: ObjectDigest{Size: 5, SHA256: hashText("hello"), Properties: &ObjectProperties{
			ETag: "etag", LastModified: "2026-10-22T04:05:06Z", Metadata: ObjectMetadata{ContentType: "application/zip", UserMetadata: map[string]string{"owner": "value"}},
		}}})
	}
	captured[0].Digest.Properties.OmittedUserMetadata = 1
	return plan, captured
}

type indexWriterFunc func([]byte) (int, error)

func (f indexWriterFunc) Write(p []byte) (int, error) { return f(p) }

func TestObjectIndexFreezesBeforeWriterCallback(t *testing.T) {
	plan, items := indexFixture(t)
	var expected, actual bytes.Buffer
	if _, err := WriteCapturedObjectIndex(context.Background(), &expected, plan, items, 4096); err != nil {
		t.Fatal(err)
	}
	writer := indexWriterFunc(func(p []byte) (int, error) {
		items[0].Digest.Properties.Metadata.UserMetadata["owner"] = "SECRET changed during write"
		plan.Objects[0].Key = "changed"
		return actual.Write(p)
	})
	if _, err := WriteCapturedObjectIndex(context.Background(), writer, plan, items, 4096); err != nil || !bytes.Equal(actual.Bytes(), expected.Bytes()) {
		t.Fatalf("writer changed frozen index: %v", err)
	}
}

func TestObjectIndexTenThousandObjectsStreamsBoundedWrites(t *testing.T) {
	const count = 10000
	inventory := make([]FrozenObject, count)
	items := make([]CapturedObject, count)
	for i := range inventory {
		inventory[i] = FrozenObject{Key: "skills/" + strconv.Itoa(i), VersionID: "v1"}
		items[i] = CapturedObject{Object: inventory[i], Digest: ObjectDigest{SHA256: hashText(""), Properties: &ObjectProperties{ETag: "etag", LastModified: "2026-10-22T04:05:06Z"}}}
	}
	plan, err := PrepareObjectCapture(context.Background(), nil, inventory, ObjectCaptureLimits{MaxObjects: count, MaxIndexBytes: 8 << 20})
	if err != nil {
		t.Fatal(err)
	}
	var written int64
	writer := indexWriterFunc(func(p []byte) (int, error) {
		if len(p) > 64*1024 {
			t.Fatal("unbounded write chunk")
		}
		written += int64(len(p))
		return len(p), nil
	})
	got, err := WriteCapturedObjectIndex(context.Background(), writer, plan, items, 8<<20)
	if err != nil || got.Size != written || written < count*100 {
		t.Fatalf("large index=%+v error=%v", got, err)
	}
}

func TestCapturedObjectIndexCompleteSortedBounded(t *testing.T) {
	plan, captured := indexFixture(t)
	var dst bytes.Buffer
	got, err := WriteCapturedObjectIndex(context.Background(), &dst, plan, captured, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if got.Size != int64(dst.Len()) || got.SHA256 != hashText(dst.String()) || got.ObjectsWithOmittedMetadata != 1 {
		t.Fatalf("digest=%+v", got)
	}
	var entries []map[string]any
	if err := json.Unmarshal(dst.Bytes(), &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0]["key"] != "a-shared" || entries[1]["key"] != "z-unreferenced" {
		t.Fatal("lost order or unreferenced entry")
	}
	var exact bytes.Buffer
	if _, err := WriteCapturedObjectIndex(context.Background(), &exact, plan, captured, got.Size); err != nil || !bytes.Equal(exact.Bytes(), dst.Bytes()) {
		t.Fatal("exact index limit failed")
	}
	var short bytes.Buffer
	if _, err := WriteCapturedObjectIndex(context.Background(), &short, plan, captured, got.Size-1); !errors.Is(err, ErrCapacity) || short.Len() != 0 {
		t.Fatalf("capacity preflight failed: %v", err)
	}
	if _, err := PrepareObjectCapture(context.Background(), nil, plan.Objects, ObjectCaptureLimits{MaxObjects: 2, MaxObjectBytes: 5, MaxTotalBytes: 10, MaxIndexBytes: plan.FrozenIndexBytes - 1}); !errors.Is(err, ErrCapacity) {
		t.Fatal("frozen index was not bounded")
	}
}

func TestCapturedObjectIndexRejectsIncompleteEvidenceBeforeWrite(t *testing.T) {
	for _, mode := range []string{"missing", "extra", "duplicate", "key", "version", "size", "digest", "properties", "etag", "modified", "metadata", "expected_digest", "expected_metadata", "total", "oversized_metadata"} {
		t.Run(mode, func(t *testing.T) {
			plan, items := indexFixture(t)
			switch mode {
			case "missing":
				items = items[:1]
			case "extra":
				items = append(items, items[0])
			case "duplicate":
				items[1] = items[0]
			case "key":
				items[0].Object.Key = "unknown"
			case "version":
				items[0].Object.VersionID = "other"
			case "size":
				items[0].Digest.Size = 6
			case "digest":
				items[0].Digest.SHA256 = ""
			case "properties":
				items[0].Digest.Properties = nil
			case "etag":
				items[0].Digest.Properties.ETag = ""
			case "modified":
				items[0].Digest.Properties.LastModified = "invalid"
			case "metadata":
				items[0].Digest.Properties.Metadata.ContentType = "bad\r\nheader"
			case "expected_digest":
				plan.Objects[0].SHA256 = hashText("other")
			case "expected_metadata":
				plan.Objects[0].Metadata = &ObjectMetadata{ContentType: "other"}
			case "total":
				plan.TotalBytes++
			case "oversized_metadata":
				items[0].Digest.Properties.Metadata.ContentType = strings.Repeat("x", MaxObjectMetadataBytes)
			}
			var dst bytes.Buffer
			got, err := WriteCapturedObjectIndex(context.Background(), &dst, plan, items, 4096)
			if err == nil || got != (ObjectIndexDigest{}) || dst.Len() != 0 {
				t.Fatalf("partial/invalid index: %v", err)
			}
		})
	}
}

type indexCancelWriter struct{ cancel context.CancelFunc }

func (w indexCancelWriter) Write(p []byte) (int, error) { w.cancel(); return len(p), nil }
func TestObjectIndexIOCancellationEmptyAndCopies(t *testing.T) {
	plan, items := indexFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got, err := WriteCapturedObjectIndex(ctx, indexCancelWriter{cancel}, plan, items, 4096)
	if !errors.Is(err, context.Canceled) || got != (ObjectIndexDigest{}) {
		t.Fatal("cancel produced successful index")
	}
	got, err = WriteCapturedObjectIndex(context.Background(), writerFailure{errors.New("SECRET")}, plan, items, 4096)
	if !errors.Is(err, ErrObjectIO) || got != (ObjectIndexDigest{}) || strings.Contains(err.Error(), "SECRET") {
		t.Fatal("write failure leaked or succeeded")
	}
	var dst bytes.Buffer
	if _, err := WriteCapturedObjectIndex(context.Background(), &dst, ObjectCapturePlan{}, nil, 2); err != nil || dst.String() != "[]" {
		t.Fatal("empty prefix not represented")
	}
	m := &ObjectMetadata{UserMetadata: map[string]string{"owner": "expected"}}
	inventory := []FrozenObject{{Key: "key", VersionID: "v1", Metadata: m}}
	frozen, err := PrepareObjectCapture(context.Background(), nil, inventory, ObjectCaptureLimits{MaxObjects: 1, MaxIndexBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	m.UserMetadata["owner"] = "changed"
	if reflect.DeepEqual(frozen.Objects[0].Metadata, m) {
		t.Fatal("frozen metadata aliases caller")
	}
	if _, err := canonicalObjectJSON(context.Background(), io.Discard, map[string]any{"size": int64(9007199254740992)}, 4096); !errors.Is(err, ErrObject) {
		t.Fatal("non-exact JCS integer accepted")
	}
}
