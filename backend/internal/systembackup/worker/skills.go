package worker

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"

	"clawreef/internal/models"
	sh "clawreef/internal/systembackupskillhub"
)

const SkillObjectCaptureVersion = "skill-hub-versioned-capture.v1"

type SkillObjectBlobRef struct {
	ID        int
	ObjectKey string
	SizeBytes int64
}
type SkillObjectCaptureSpec struct {
	Version                                      string `json:"schema_version"`
	InventorySHA256                              string `json:"inventory_sha256"`
	Bucket, Prefix                               string
	Blobs                                        []SkillObjectBlobRef
	Objects                                      []sh.FrozenObject
	WorkspaceRequiredBlobIDs                     []int
	UserMetadataAllowlist                        []string
	MaxObjects                                   int
	MaxObjectBytes, MaxTotalBytes, MaxIndexBytes int64
}
type SkillObjectCaptureSources struct {
	Reader    sh.VersionReader
	Authorize func(context.Context, Invocation) error
}

func skillObjectOperation(op string) bool { return op == "capture-skill-objects" }
func validSkillObjectRequest(r Request) bool {
	s := r.SkillObjects
	if r.Version != Version || !skillObjectOperation(r.Operation) || s == nil || s.Version != SkillObjectCaptureVersion || !keyUseHash.MatchString(s.InventorySHA256) || s.Bucket == "" || strings.ContainsAny(s.Bucket, "/\\\r\n\x00") || s.Prefix == "" || path.IsAbs(s.Prefix) || path.Clean(s.Prefix) != s.Prefix || s.Prefix == "." || s.Prefix == ".." || strings.HasPrefix(s.Prefix, "../") || strings.ContainsAny(s.Prefix, "\\\r\n\x00") || r.Database != nil || r.Teams != nil || r.TeamWorkspace != nil || r.Resources != nil || r.RuntimePolicy != nil || r.WorkBuddyIdentity != nil || r.MaxFiles != 0 || r.MaxFileBytes != 0 || len(r.Files) != 0 || r.PolicyVersion != "" || r.MaxArchiveBytes <= 0 || r.MaxArchiveBytes > 64<<20 || r.MaxCompressedBytes <= 0 || r.MaxCompressedBytes > 64<<20 || s.MaxObjects < 0 || s.MaxObjects > 10000 || len(s.Blobs) > 100000 || s.MaxIndexBytes < 2 || s.MaxIndexBytes > 4<<20 || s.MaxTotalBytes > r.MaxArchiveBytes || s.MaxObjectBytes > r.MaxArchiveBytes {
		return false
	}
	plan, err := skillObjectPlan(context.Background(), *s)
	if err != nil || len(plan.UnpackagedBlobIDs) != len(s.WorkspaceRequiredBlobIDs) {
		return false
	}
	for n, id := range plan.UnpackagedBlobIDs {
		if id != s.WorkspaceRequiredBlobIDs[n] {
			return false
		}
	}
	return true
}
func skillObjectPlan(ctx context.Context, s SkillObjectCaptureSpec) (sh.ObjectCapturePlan, error) {
	blobs := make([]models.SkillBlob, len(s.Blobs))
	for n, blob := range s.Blobs {
		blobs[n] = models.SkillBlob{ID: blob.ID, ObjectKey: blob.ObjectKey, SizeBytes: blob.SizeBytes}
	}
	return sh.PrepareObjectCapture(ctx, blobs, s.Objects, sh.ObjectCaptureLimits{MaxObjects: s.MaxObjects, MaxObjectBytes: s.MaxObjectBytes, MaxTotalBytes: s.MaxTotalBytes, MaxIndexBytes: s.MaxIndexBytes})
}
func authorizeSkillObjects(ctx context.Context, source *SkillObjectCaptureSources, i Invocation) error {
	if source == nil || source.Reader == nil || source.Authorize == nil {
		return ErrNotReady
	}
	raw, err := json.Marshal(i)
	var frozen Invocation
	if err != nil || json.Unmarshal(raw, &frozen) != nil {
		return ErrRequest
	}
	return source.Authorize(ctx, frozen)
}

func captureSkillObjects(ctx context.Context, source *SkillObjectCaptureSources, i Invocation, dst io.Writer, check func() error) error {
	if !validSkillObjectRequest(i.Request) || source == nil || source.Reader == nil || check == nil {
		return ErrRequest
	}
	guard := func() error {
		if ctx.Err() != nil || check() != nil || authorizeSkillObjects(ctx, source, i) != nil {
			return ErrNotReady
		}
		return nil
	}
	if guard() != nil {
		return ErrNotReady
	}
	s := *i.Request.SkillObjects
	plan, err := skillObjectPlan(ctx, s)
	if err != nil {
		return ErrExecution
	}
	header := struct {
		Version, InvocationSHA256 string
		Spec                      SkillObjectCaptureSpec
	}{Version: SkillObjectCaptureVersion, Spec: s}
	header.InvocationSHA256, _ = i.Hash()
	headerRaw, err := json.Marshal(header)
	if err != nil || len(headerRaw) > 4<<20 {
		return ErrRequest
	}
	tw := tar.NewWriter(dst)
	writeBytes := func(name string, raw []byte) error {
		if guard() != nil {
			return ErrNotReady
		}
		if tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0600, Size: int64(len(raw)), Format: tar.FormatPAX}) != nil {
			return ErrExecution
		}
		_, err := tw.Write(raw)
		if err != nil {
			return ErrExecution
		}
		return guard()
	}
	if writeBytes("skill-hub/header.json", headerRaw) != nil {
		return ErrExecution
	}
	captured := make([]sh.CapturedObject, 0, len(plan.Objects))
	reader := guardedSkillVersionReader{reader: source.Reader, check: guard}
	for n, object := range plan.Objects {
		if guard() != nil {
			return ErrNotReady
		}
		name := "skill-hub/objects/" + strconv.Itoa(n) + ".bin"
		if tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0600, Size: object.Size, Format: tar.FormatPAX}) != nil {
			return ErrExecution
		}
		digest, err := sh.CopyFrozenObject(ctx, reader, tw, object, s.MaxObjectBytes)
		if err != nil {
			return ErrExecution
		}
		captured = append(captured, sh.CapturedObject{Object: object, Digest: digest})
	}
	var index bytes.Buffer
	indexDigest, err := sh.WriteCapturedObjectIndex(ctx, &index, plan, captured, s.MaxIndexBytes)
	if err != nil || indexDigest.ObjectsWithOmittedMetadata != 0 {
		return ErrExecution
	}
	if writeBytes("skill-hub/index.json", index.Bytes()) != nil {
		return ErrExecution
	}
	if tw.Close() != nil || guard() != nil {
		return ErrExecution
	}
	return nil
}

type guardedSkillVersionReader struct {
	reader sh.VersionReader
	check  func() error
}

func (r guardedSkillVersionReader) OpenVersion(ctx context.Context, key, version string) (sh.ObjectVersion, error) {
	if r.check() != nil {
		return sh.ObjectVersion{}, ErrNotReady
	}
	object, err := r.reader.OpenVersion(ctx, key, version)
	if err != nil {
		return object, err
	}
	if object.Body == nil || r.check() != nil {
		if object.Body != nil {
			object.Body.Close()
		}
		return sh.ObjectVersion{}, ErrNotReady
	}
	object.Body = &guardedSkillBody{ReadCloser: object.Body, check: r.check}
	return object, nil
}

type guardedSkillBody struct {
	io.ReadCloser
	check func() error
}

func (r *guardedSkillBody) Read(raw []byte) (int, error) {
	if r.check() != nil {
		return 0, ErrNotReady
	}
	n, err := r.ReadCloser.Read(raw)
	if r.check() != nil {
		return 0, ErrNotReady
	}
	return n, err
}

// SkillObjectArchiveNames is deterministic for independent payload readers.
// The header contains unresolved workspace requirements, never a success flag.
func SkillObjectArchiveNames(spec SkillObjectCaptureSpec) []string {
	objects := append([]sh.FrozenObject(nil), spec.Objects...)
	sort.Slice(objects, func(i, j int) bool { return objects[i].Key < objects[j].Key })
	names := []string{"skill-hub/header.json"}
	for n := range objects {
		names = append(names, "skill-hub/objects/"+strconv.Itoa(n)+".bin")
	}
	return append(names, "skill-hub/index.json")
}
