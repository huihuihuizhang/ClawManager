package install

import (
	backup "clawreef/internal/systembackup"
	"context"
	"strings"
	"testing"
	"time"
)

// Classification MODEL only. This does not construct a real held SQL/native
// owner and cannot qualify original17, ownership, source recovery or a task.
func TestOriginalSQLSkillHistoryClassifiesExactOldVersionsAndOwnedMarkers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	row := originalSkillArchiveRow{ID: 7, ObjectKey: "original.zip", ArchiveSHA256: strings.Repeat("a", 64), Size: 31}
	s := &originalMinIOBusinessHistorySource{ctx: ctx, prep: &PreparedOriginalAdoptionSQLCut{}, hold: &OriginalWriterHold{set: &PreparedOriginalWriterSet{owner: &OriginalWriterMaintenance{}}}, bucket: "actual-business", prefix: "actual-root/", rows: []originalSkillArchiveRow{row}, byKey: map[string][]originalSkillArchiveRow{"actual-root/original.zip": {row}}, until: time.Now().Add(time.Minute), revision: "actual-source-revision-model"}
	s.origin = s
	s.rowsSHA256 = originalObjectSHA(s.rows)
	base := backup.OriginalProtectedMinIOObject{Bucket: s.bucket, Key: "actual-root/original.zip", VersionID: "actual-old-version", Size: 31, BodySHA256: row.ArchiveSHA256, Latest: false}
	cases := []struct {
		name   string
		object backup.OriginalProtectedMinIOObject
		want   bool
	}{
		{"exact-old-not-latest", base, true},
		{"wrong-body", func() backup.OriginalProtectedMinIOObject {
			x := base
			x.BodySHA256 = strings.Repeat("b", 64)
			return x
		}(), false},
		{"wrong-size", func() backup.OriginalProtectedMinIOObject { x := base; x.Size++; return x }(), false},
		{"unreferenced-same-prefix", func() backup.OriginalProtectedMinIOObject { x := base; x.Key = "actual-root/orphan.zip"; return x }(), false},
		{"wrong-bucket", func() backup.OriginalProtectedMinIOObject { x := base; x.Bucket = "other"; return x }(), false},
		{"owned-delete-marker", func() backup.OriginalProtectedMinIOObject {
			x := base
			x.DeleteMarker = true
			x.Size = 0
			x.BodySHA256 = ""
			return x
		}(), true},
		{"marker-with-body", func() backup.OriginalProtectedMinIOObject { x := base; x.DeleteMarker = true; x.Size = 0; return x }(), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := s.classifyNativeObject(ctx, c.object)
			if ok != c.want {
				t.Fatalf("classify=%v want=%v", ok, c.want)
			}
			if ok && (got.VersionID != c.object.VersionID || got.Key != c.object.Key || got.SourceSHA256 == "") {
				t.Fatal("original exact native version/SQL owner omitted")
			}
		})
	}
	foreign, stop := context.WithTimeout(context.Background(), time.Minute)
	defer stop()
	if _, ok := s.classifyNativeObject(foreign, base); ok {
		t.Fatal("foreign context accepted")
	}
	s.until = time.Now().Add(-time.Second)
	if _, ok := s.classifyNativeObject(ctx, base); ok {
		t.Fatal("expired original source accepted")
	}
}
