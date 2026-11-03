package systembackupexecution

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/worker"
	sh "clawreef/internal/systembackupskillhub"
)

func finalSkillReportInput(t *testing.T) (*publicationFinalSkillReport, worker.Invocation, []byte) {
	t.Helper()
	inventory := sh.CaptureInventory{Version: sh.CaptureInventoryVersion, Skills: []sh.CaptureSkill{{ID: 1, UserID: 7, CurrentVersionID: 3}}, Blobs: []sh.CaptureBlob{{ID: 2, ObjectKey: "original.zip", ContentHash: strings.Repeat("a", 32), SizeBytes: 5}}, Versions: []sh.CaptureVersion{{ID: 3, SkillID: 1, BlobID: 2}}}
	for _, name := range sh.CaptureTableNames() {
		keys := sh.CaptureTableKeys{Name: name, SchemaSHA256: strings.Repeat("b", 64), IDs: []int{}}
		switch name {
		case "skills":
			keys.IDs = []int{1}
		case "skill_blobs":
			keys.IDs = []int{2}
		case "skill_versions":
			keys.IDs = []int{3}
		}
		inventory.Tables = append(inventory.Tables, keys)
	}
	source := b.SourceInventory{Skills: &inventory, Users: []int{7}}
	s := newPublicationFinalSkillReport(source)
	objects := []sh.FrozenObject{{Key: "original.zip", VersionID: "immutable-v1", Size: 5}}
	limits := sh.ObjectCaptureLimits{MaxObjects: 10, MaxObjectBytes: 1024, MaxTotalBytes: 4096, MaxIndexBytes: 8192}
	spec := worker.SkillObjectCaptureSpec{Version: worker.SkillObjectCaptureVersion, InventorySHA256: inventory.SHA256(), Bucket: "skill-bucket", Prefix: "packages", Objects: objects, Blobs: []worker.SkillObjectBlobRef{{ID: 2, ObjectKey: "original.zip", SizeBytes: 5}}, MaxObjects: limits.MaxObjects, MaxObjectBytes: limits.MaxObjectBytes, MaxTotalBytes: limits.MaxTotalBytes, MaxIndexBytes: limits.MaxIndexBytes}
	i := worker.Invocation{Request: worker.Request{Operation: "capture-skill-objects", SkillObjects: &spec, MaxArchiveBytes: 1 << 20}}
	invocation, err := i.Hash()
	if err != nil {
		t.Fatal(err)
	}
	header, _ := json.Marshal(struct {
		Version, InvocationSHA256 string
		Spec                      worker.SkillObjectCaptureSpec
	}{worker.SkillObjectCaptureVersion, invocation, spec})
	plan, err := sh.PrepareObjectCapture(context.Background(), nil, objects, limits)
	if err != nil {
		t.Fatal(err)
	}
	captured := []sh.CapturedObject{{Object: objects[0], Digest: sh.ObjectDigest{Size: 5, SHA256: hash([]byte("hello")), Properties: &sh.ObjectProperties{ETag: "original-etag", LastModified: "2026-11-02T06:00:00Z"}}}}
	var index bytes.Buffer
	if _, err = sh.WriteCapturedObjectIndex(context.Background(), &index, plan, captured, limits.MaxIndexBytes); err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	tw := tar.NewWriter(&body)
	for _, v := range []struct {
		name string
		raw  []byte
	}{{"skill-hub/header.json", header}, {"skill-hub/objects/0.bin", []byte("hello")}, {"skill-hub/index.json", index.Bytes()}} {
		if err = tw.WriteHeader(&tar.Header{Name: v.name, Typeflag: tar.TypeReg, Mode: 0600, Size: int64(len(v.raw)), Format: tar.FormatPAX}); err != nil {
			t.Fatal(err)
		}
		if _, err = tw.Write(v.raw); err != nil {
			t.Fatal(err)
		}
	}
	if err = tw.Close(); err != nil {
		t.Fatal(err)
	}
	return s, i, body.Bytes()
}
func TestPublicationSkillReportWaitsForOuterAuthentication(t *testing.T) {
	s, i, body := finalSkillReportInput(t)
	var counts ownedPayloadCounts
	if err := s.read(context.Background(), i, bytes.NewReader(body), &counts); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.snapshot(); err == nil {
		t.Fatal("tentative parser data escaped before AEAD/current confirmation")
	}
	if err := s.confirm(context.Background()); err != nil {
		t.Fatal(err)
	}
	report, digest, err := s.snapshot()
	if err != nil || !formalCandidateDigest(digest) || !report.SampleAvailable || report.Sample == nil || report.Sample.Skill.ID != 1 || report.Sample.Objects[0].Object.VersionID != "immutable-v1" || report.Sample.Objects[0].Digest.SHA256 != hash([]byte("hello")) || counts.Items != 1 || counts.ContentBytes != 5 {
		t.Fatal("lost authenticated sample binding", err)
	}
	report.Sample.Objects[0].Object.Key = "changed"
	again, _, err := s.snapshot()
	if err != nil || again.Sample.Objects[0].Object.Key != "original.zip" {
		t.Fatal("report aliases internal state")
	}
	p := &publicationContentSamples{skills: s}
	p.clear()
	if _, _, err = s.snapshot(); err == nil {
		t.Fatal("outer authentication failure preserved sample")
	}
}
func TestPublicationSkillReportRejectsForeignAndCorruptArchive(t *testing.T) {
	for _, mode := range []string{"foreign", "body", "tail"} {
		t.Run(mode, func(t *testing.T) {
			s, i, body := finalSkillReportInput(t)
			switch mode {
			case "foreign":
				i.Request.SkillObjects.InventorySHA256 = strings.Repeat("f", 64)
			case "body":
				body = bytes.Replace(body, []byte("hello"), []byte("world"), 1)
			case "tail":
				body = append(body, 'x')
			}
			var count ownedPayloadCounts
			if err := s.read(context.Background(), i, bytes.NewReader(body), &count); err == nil {
				t.Fatal("invalid final archive accepted")
			}
			if _, _, err := s.snapshot(); err == nil {
				t.Fatal("failed input reportable")
			}
		})
	}
}
func TestPublicationBusinessReportRequiresTypedCurrentReady(t *testing.T) {
	var dst bytes.Buffer
	for _, ready := range []*publicationTerminalReady{nil, {}} {
		if ready.WriteBusinessContentReport(context.Background(), &dst) == nil || dst.Len() != 0 {
			t.Fatal("forged Ready emitted private metadata")
		}
	}
}
