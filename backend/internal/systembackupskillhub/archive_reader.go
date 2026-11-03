package systembackupskillhub

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"

	"clawreef/internal/models"
)

// SkillArchiveReadSpec must come from the same authenticated original worker
// invocation and SQL projection. ExpectedHeaderJSON is exactly json.Marshal of
// {Version, InvocationSHA256, Spec} emitted by worker.captureSkillObjects. This
// package deliberately does not import worker (worker imports this package).
type SkillArchiveReadSpec struct {
	ExpectedHeaderJSON []byte
	Inventory          CaptureInventory
	Users              map[int]bool
	InstanceOwners     map[int]int
	Objects            []FrozenObject
	Limits             ObjectCaptureLimits
	MaxArchiveBytes    int64
}

// SkillArchivePayload is bounded preparation data, not an authentication or
// restore receipt. Bodies and Captured follow Plan.Objects' sorted key order.
// No target writes occur here. The caller must complete the outer authenticated
// stream (AEAD/gzip/EOF/current authority) before consuming any returned data.
// SQL restoration belongs to the common domain transaction, never this reader.
type SkillArchivePayload struct {
	Plan        ObjectCapturePlan
	Captured    []CapturedObject
	Bodies      [][]byte
	IndexSHA256 string
}

func (p *SkillArchivePayload) Clear() {
	for _, body := range p.Bodies {
		clear(body)
	}
	*p = SkillArchivePayload{}
}

// The finite header projection is checked against independent original inputs;
// exact header byte equality also retains the original bucket/prefix/policies.
type skillArchiveHeader struct {
	Version, InvocationSHA256 string
	Spec                      struct {
		InventorySHA256 string `json:"inventory_sha256"`
		Version         string `json:"schema_version"`
		Blobs           []struct {
			ID        int
			ObjectKey string
			SizeBytes int64
		}
		Objects                                      []FrozenObject
		WorkspaceRequiredBlobIDs                     []int
		MaxObjects                                   int
		MaxObjectBytes, MaxTotalBytes, MaxIndexBytes int64
	}
}

// ReadSkillObjectArchive consumes the uncompressed formal Skills tar, not the
// ordinary ReadObjectSnapshot format. Limits include the complete tar and tail.
// Partial bodies are cleared on every failure; errors contain no source data.
func ReadSkillObjectArchive(ctx context.Context, src io.Reader, spec SkillArchiveReadSpec) (_ SkillArchivePayload, resultErr error) {
	var empty, payload SkillArchivePayload
	defer func() {
		if resultErr != nil {
			payload.Clear()
		}
	}()
	if err := checkContext(ctx); err != nil {
		return empty, err
	}
	if src == nil || spec.MaxArchiveBytes < 1024 || spec.MaxArchiveBytes > 64<<20 || len(spec.ExpectedHeaderJSON) < 2 || len(spec.ExpectedHeaderJSON) > 4<<20 || spec.Limits.MaxObjects > 10000 || spec.Limits.MaxIndexBytes > 4<<20 {
		return empty, ErrCapacity
	}
	if err := spec.Inventory.Validate(spec.Users, spec.InstanceOwners); err != nil {
		return empty, err
	}
	expectedHeaderJSON := bytes.Clone(spec.ExpectedHeaderJSON)
	defer clear(expectedHeaderJSON)
	var expected skillArchiveHeader
	if json.Unmarshal(expectedHeaderJSON, &expected) != nil || expected.Version != "skill-hub-versioned-capture.v1" || expected.Spec.Version != expected.Version || !validSHA256(expected.InvocationSHA256) || expected.Spec.InventorySHA256 != spec.Inventory.SHA256() || expected.Spec.MaxObjects != spec.Limits.MaxObjects || expected.Spec.MaxObjectBytes != spec.Limits.MaxObjectBytes || expected.Spec.MaxTotalBytes != spec.Limits.MaxTotalBytes || expected.Spec.MaxIndexBytes != spec.Limits.MaxIndexBytes || len(expected.Spec.Blobs) != len(spec.Inventory.Blobs) {
		return empty, ErrObjectCoverage
	}
	objectsJSON, err := json.Marshal(spec.Objects)
	if err != nil {
		return empty, ErrObjectCoverage
	}
	headerObjectsJSON, err := json.Marshal(expected.Spec.Objects)
	if err != nil || !bytes.Equal(objectsJSON, headerObjectsJSON) {
		return empty, ErrObjectCoverage
	}
	refs := map[int]CaptureBlob{}
	for _, blob := range spec.Inventory.Blobs {
		refs[blob.ID] = blob
	}
	seen := map[int]bool{}
	blobs := make([]models.SkillBlob, 0, len(expected.Spec.Blobs))
	for _, blob := range expected.Spec.Blobs {
		original, ok := refs[blob.ID]
		if !ok || seen[blob.ID] || blob.ObjectKey != original.ObjectKey || blob.SizeBytes != original.SizeBytes {
			return empty, ErrObjectCoverage
		}
		seen[blob.ID] = true
		blobs = append(blobs, models.SkillBlob{ID: blob.ID, ObjectKey: blob.ObjectKey, SizeBytes: blob.SizeBytes})
	}
	plan, err := PrepareObjectCapture(ctx, blobs, spec.Objects, spec.Limits)
	if err != nil || len(plan.UnpackagedBlobIDs) != len(expected.Spec.WorkspaceRequiredBlobIDs) {
		return empty, ErrObjectCoverage
	}
	for n, id := range plan.UnpackagedBlobIDs {
		if expected.Spec.WorkspaceRequiredBlobIDs[n] != id {
			return empty, ErrObjectCoverage
		}
	}
	if _, err := spec.Inventory.WorkspaceRequirements(); err != nil {
		return empty, err
	}
	payload.Plan = plan
	limited := &io.LimitedReader{R: &objectContextReader{ctx: ctx, reader: src}, N: spec.MaxArchiveBytes + 1}
	reader := tar.NewReader(limited)
	var lastMemberSize int64
	readMember := func(name string, max int64) ([]byte, error) {
		header, err := reader.Next()
		if err != nil || header.Name != name || header.Typeflag != tar.TypeReg || header.Mode != 0600 || header.Size < 0 || header.Size > max || header.Linkname != "" || len(header.Xattrs) != 0 || len(header.PAXRecords) != 0 {
			return nil, ErrObject
		}
		raw, err := io.ReadAll(io.LimitReader(reader, header.Size+1))
		if err != nil || int64(len(raw)) != header.Size {
			clear(raw)
			return nil, ErrObjectIO
		}
		lastMemberSize = header.Size
		return raw, nil
	}
	headerRaw, err := readMember("skill-hub/header.json", 4<<20)
	if err != nil {
		return empty, err
	}
	headerMatches := bytes.Equal(headerRaw, expectedHeaderJSON)
	clear(headerRaw)
	if !headerMatches {
		return empty, ErrObjectCoverage
	}
	for n, object := range plan.Objects {
		raw, err := readMember("skill-hub/objects/"+strconv.Itoa(n)+".bin", object.Size)
		if err != nil {
			return empty, err
		}
		payload.Bodies = append(payload.Bodies, raw)
		digest := sha256.Sum256(raw)
		sha := hex.EncodeToString(digest[:])
		if int64(len(raw)) != object.Size || object.SHA256 != "" && object.SHA256 != sha {
			return empty, ErrObject
		}
		payload.Captured = append(payload.Captured, CapturedObject{Object: object, Digest: ObjectDigest{Size: int64(len(raw)), SHA256: sha}})
	}
	indexRaw, err := readMember("skill-hub/index.json", spec.Limits.MaxIndexBytes)
	if err != nil {
		return empty, err
	}
	defer clear(indexRaw)
	var index []struct {
		Key      string `json:"key"`
		Version  string `json:"version_id"`
		Size     int64  `json:"size"`
		SHA      string `json:"sha256"`
		ETag     string `json:"etag"`
		Modified string `json:"last_modified"`
		Omitted  int    `json:"omitted_user_metadata_count"`
		Metadata struct {
			ContentType        string            `json:"content_type"`
			ContentEncoding    string            `json:"content_encoding"`
			ContentDisposition string            `json:"content_disposition"`
			ContentLanguage    string            `json:"content_language"`
			CacheControl       string            `json:"cache_control"`
			Expires            string            `json:"expires"`
			User               map[string]string `json:"user_metadata_allowlist"`
		} `json:"metadata"`
	}
	if json.Unmarshal(indexRaw, &index) != nil || len(index) != len(payload.Captured) {
		return empty, ErrObjectCoverage
	}
	for n, entry := range index {
		item := &payload.Captured[n]
		if entry.Key != item.Object.Key || entry.Version != item.Object.VersionID || entry.Size != item.Digest.Size || entry.SHA != item.Digest.SHA256 || entry.Omitted != 0 {
			return empty, ErrObjectCoverage
		}
		item.Digest.Properties = &ObjectProperties{ETag: entry.ETag, LastModified: entry.Modified, Metadata: ObjectMetadata{ContentType: entry.Metadata.ContentType, ContentEncoding: entry.Metadata.ContentEncoding, ContentDisposition: entry.Metadata.ContentDisposition, ContentLanguage: entry.Metadata.ContentLanguage, CacheControl: entry.Metadata.CacheControl, Expires: entry.Metadata.Expires, UserMetadata: entry.Metadata.User}}
	}
	var canonical bytes.Buffer
	indexDigest, err := WriteCapturedObjectIndex(ctx, &canonical, plan, payload.Captured, spec.Limits.MaxIndexBytes)
	defer clear(canonical.Bytes())
	if err != nil || !bytes.Equal(canonical.Bytes(), indexRaw) {
		return empty, ErrObjectCoverage
	}
	beforeTrailer := limited.N
	if _, err := reader.Next(); err != io.EOF || beforeTrailer-limited.N != (512-lastMemberSize%512)%512+1024 {
		return empty, ErrObject
	}
	var padding [4096]byte
	var paddingBytes int64
	for {
		n, err := limited.Read(padding[:])
		paddingBytes += int64(n)
		if paddingBytes > 1<<20 || limited.N <= 0 {
			return empty, ErrCapacity
		}
		for _, b := range padding[:n] {
			if b != 0 {
				return empty, ErrObject
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil || n == 0 {
			return empty, ErrObjectIO
		}
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	payload.IndexSHA256 = indexDigest.SHA256
	return payload, nil
}
