package systembackupexecution

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
	"strings"

	"clawreef/internal/models"
	source "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/worker"
	"clawreef/internal/systembackup/workspace"
	d "clawreef/internal/systembackupdispatch"
	sh "clawreef/internal/systembackupskillhub"
)

// An inert parser for the ORIGINAL frozen operation. Its caller must surround
// it with the independent current C Unwrap and complete AEAD/EOF verification.
// It reads no current source/restore target and never extracts an archive.
func inspectOwnedBusinessPayload(ctx context.Context, i worker.Invocation, candidate worker.FormalCaptureResult, plaintext io.Reader) error {
	if ctx == nil || ctx.Err() != nil || plaintext == nil || !worker.ValidateFormalCaptureResult(i, &candidate) || i.Request.ControlEvidence != nil {
		return d.ErrNotReady
	}
	z, err := gzip.NewReader(plaintext)
	if err != nil {
		return d.ErrNotReady
	}
	defer z.Close()
	limited := &io.LimitedReader{R: z, N: i.Request.MaxArchiveBytes + 1}
	r := i.Request
	switch {
	case r.Database != nil:
		spec := r.Database
		snapshot, err := domain.Decode(limited, domain.Limits{MaxRows: spec.MaxRows, MaxBytes: r.MaxArchiveBytes})
		if err != nil {
			return d.ErrNotReady
		}
		defer func() {
			for _, table := range snapshot.Tables {
				for _, row := range table.Rows {
					for _, cell := range row {
						clear(cell.Bytes)
					}
				}
			}
		}()
		var rows, memory int64
		for _, table := range snapshot.Tables {
			rows += int64(len(table.Rows))
			for _, row := range table.Rows {
				for column, cell := range row {
					memory += int64(len(column) + len(cell.Bytes) + 128)
				}
			}
		}
		if rows != candidate.Rows || len(snapshot.Tables) != candidate.Tables || memory > spec.MaxMemoryBytes || spec.SourceScope != domain.BusinessTableSourceScope || spec.CaptureSchema == nil || domain.VerifyBusinessCapturedSnapshot(snapshot, *spec.CaptureSchema) != nil {
			return d.ErrNotReady
		}
		if spec.TeamsInventory != nil && domain.VerifyTeamCapture(snapshot, *spec.TeamsInventory) != nil {
			return d.ErrNotReady
		}
		if spec.SkillsInventory != nil && domain.VerifySkillCapture(snapshot, *spec.SkillsInventory) != nil {
			return d.ErrNotReady
		}
	case r.SourceRedis != nil:
		snapshot, err := source.ReadSourceRedisSnapshot(ctx, limited, *r.SourceRedis)
		if err != nil {
			return d.ErrNotReady
		}
		source.ClearSourceRedisSnapshot(snapshot)
	case r.Resources != nil:
		if err = worker.ReadResourceCaptureArchive(ctx, limited, *r.Resources, r.MaxArchiveBytes, nil); err != nil {
			return d.ErrNotReady
		}
	case r.SkillObjects != nil:
		if inspectOwnedSkillObjects(ctx, i, limited) != nil {
			return d.ErrNotReady
		}
	case r.SkillWorkspace != nil:
		if sh.VerifyWorkspaceCapture(ctx, limited, *r.SkillWorkspace) != nil {
			return d.ErrNotReady
		}
	case r.Teams != nil && r.Teams.Redis != nil:
		reader := bufio.NewReaderSize(limited, 64<<10)
		headerRaw, headerErr := reader.ReadSlice('\n')
		var header source.RedisRecord
		if headerErr != nil || decodeProviderDeploymentJSON(headerRaw, &header) != nil || header.Kind != "redis_dump_v1" || header.ServerID != r.Teams.Redis.ServerID || header.CapturedAtMillis <= 0 {
			return d.ErrNotReady
		}
		headerRaw = bytes.Clone(headerRaw)
		allowed := map[string]bool{}
		for _, id := range r.Teams.Redis.TeamIDs {
			allowed["claw:team:"+strconv.Itoa(id)+":"] = true
		}
		if source.ReadRedisSnapshot(io.MultiReader(bytes.NewReader(headerRaw), reader), source.RedisBudget{MaxItems: r.Teams.MaxItems, MaxBytes: r.MaxArchiveBytes, MaxInventoryBytes: r.MaxArchiveBytes}, func(record source.RedisRecord) error {
			defer clear(record.Dump)
			if record.ExpiresAtMillis != 0 && record.ExpiresAtMillis < header.CapturedAtMillis {
				return d.ErrNotReady
			}
			for prefix := range allowed {
				if strings.HasPrefix(string(record.Key), prefix) {
					return nil
				}
			}
			return d.ErrNotReady
		}) != nil {
			return d.ErrNotReady
		}
	case r.Teams != nil && r.Operation == "capture-team-objects":
		if inspectOwnedTeamObjects(ctx, i, limited) != nil {
			return d.ErrNotReady
		}
	case r.Operation == "capture-workspace":
		if inspectOwnedWorkspace(ctx, i, candidate, limited) != nil {
			return d.ErrNotReady
		}
	default:
		return d.ErrNotReady
	}
	var extra [1]byte
	n, tailErr := limited.Read(extra[:])
	if n != 0 || tailErr != io.EOF || limited.N <= 0 || z.Close() != nil || ctx.Err() != nil {
		return d.ErrNotReady
	}
	return nil
}

func zeroArchiveTail(r io.Reader) error {
	var buffer [32768]byte
	for {
		n, err := r.Read(buffer[:])
		for _, value := range buffer[:n] {
			if value != 0 {
				return d.ErrNotReady
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return d.ErrNotReady
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
}

func inspectOwnedWorkspace(ctx context.Context, i worker.Invocation, candidate worker.FormalCaptureResult, src io.Reader) error {
	r := i.Request
	layout := workspace.Layout("")
	if r.RuntimePolicy != nil {
		if r.RuntimePolicy.Validate() != nil {
			return d.ErrNotReady
		}
		layout = r.RuntimePolicy.WorkspaceLayout
	}
	validator, err := workspace.NewCapturedArchiveValidator(layout)
	if err != nil {
		return d.ErrNotReady
	}
	reader := tar.NewReader(src)
	var files, total int64
	marker, home := false, false
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil || validator.Observe(header) != nil {
			return d.ErrNotReady
		}
		files++
		if files > r.MaxFiles || header.Size > r.MaxFileBytes-total {
			return d.ErrNotReady
		}
		total += header.Size
		if want := r.WorkBuddyIdentity; want != nil {
			if header.Name == "home" {
				if header.Typeflag != tar.TypeDir || header.Uid != want.UID || header.Gid != want.GID {
					return d.ErrNotReady
				}
				home = true
			}
			if header.Name == ".workbuddy-identity.json" {
				if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA || header.Size > 4096 {
					return d.ErrNotReady
				}
				raw, readErr := io.ReadAll(io.LimitReader(reader, 4097))
				var actual domain.WorkBuddyUIDIdentity
				decodeErr := decodeProviderDeploymentJSON(raw, &actual)
				clear(raw)
				if readErr != nil || decodeErr != nil || actual != *want {
					return d.ErrNotReady
				}
				marker = true
				continue
			}
		}
		if _, err = io.Copy(io.Discard, reader); err != nil {
			return d.ErrNotReady
		}
	}
	if validator.Finish() != nil || files != candidate.Files || total != candidate.Bytes || r.WorkBuddyIdentity != nil && (!marker || !home) || zeroArchiveTail(src) != nil {
		return d.ErrNotReady
	}
	return nil
}

func inspectOwnedTeamObjects(ctx context.Context, i worker.Invocation, src io.Reader) error {
	expected := map[string]struct {
		version, sha string
		size         int64
	}{}
	for _, ref := range i.Request.Teams.Objects {
		key := ref.Bucket + "\x00" + ref.Key
		if _, exists := expected[key]; exists {
			return d.ErrNotReady
		}
		expected[key] = struct {
			version, sha string
			size         int64
		}{ref.Version, ref.SHA256, ref.Size}
	}
	err := source.ReadObjectSnapshot(ctx, src, source.ObjectBudget{MaxItems: i.Request.Teams.MaxItems, MaxBytes: i.Request.MaxArchiveBytes}, func(meta source.ObjectMetadata) (io.WriteCloser, error) {
		key := meta.Bucket + "\x00" + meta.Key
		want, ok := expected[key]
		if !ok || meta.Version != want.version || meta.Size != want.size {
			return nil, d.ErrNotReady
		}
		delete(expected, key)
		digest := sha256.New()
		var size int64
		return &ownedCountedObjectSink{digest: digest, count: &size, expectedSize: want.size, expectedSHA: want.sha}, nil
	})
	if err != nil || len(expected) != 0 {
		return d.ErrNotReady
	}
	return nil
}

type ownedCountedObjectSink struct {
	digest interface {
		io.Writer
		Sum([]byte) []byte
	}
	count        *int64
	expectedSize int64
	expectedSHA  string
}

func (s *ownedCountedObjectSink) Write(raw []byte) (int, error) {
	n, err := s.digest.Write(raw)
	*s.count += int64(n)
	if *s.count > s.expectedSize {
		return n, d.ErrNotReady
	}
	return n, err
}
func (s *ownedCountedObjectSink) Close() error {
	if *s.count != s.expectedSize || hex.EncodeToString(s.digest.Sum(nil)) != s.expectedSHA {
		return d.ErrNotReady
	}
	return nil
}

func inspectOwnedSkillObjects(ctx context.Context, i worker.Invocation, src io.Reader) error {
	spec := *i.Request.SkillObjects
	blobs := make([]models.SkillBlob, len(spec.Blobs))
	for index, blob := range spec.Blobs {
		blobs[index] = models.SkillBlob{ID: blob.ID, ObjectKey: blob.ObjectKey, SizeBytes: blob.SizeBytes}
	}
	plan, err := sh.PrepareObjectCapture(ctx, blobs, spec.Objects, sh.ObjectCaptureLimits{MaxObjects: spec.MaxObjects, MaxObjectBytes: spec.MaxObjectBytes, MaxTotalBytes: spec.MaxTotalBytes, MaxIndexBytes: spec.MaxIndexBytes})
	if err != nil || len(plan.UnpackagedBlobIDs) != len(spec.WorkspaceRequiredBlobIDs) {
		return d.ErrNotReady
	}
	for index, id := range plan.UnpackagedBlobIDs {
		if id != spec.WorkspaceRequiredBlobIDs[index] {
			return d.ErrNotReady
		}
	}
	reader := tar.NewReader(src)
	readHeader := func(name string, max int64) (*tar.Header, error) {
		header, err := reader.Next()
		if err != nil || header.Name != name || header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > max || header.Mode != 0600 || header.Linkname != "" || len(header.Xattrs) != 0 {
			return nil, d.ErrNotReady
		}
		return header, nil
	}
	if _, err = readHeader("skill-hub/header.json", 4<<20); err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(reader, (4<<20)+1))
	if err != nil {
		return d.ErrNotReady
	}
	defer clear(raw)
	invocationSHA, _ := i.Hash()
	expectedHeader, _ := json.Marshal(struct {
		Version, InvocationSHA256 string
		Spec                      worker.SkillObjectCaptureSpec
	}{worker.SkillObjectCaptureVersion, invocationSHA, spec})
	if !bytes.Equal(raw, expectedHeader) {
		return d.ErrNotReady
	}
	actual := make([]sh.CapturedObject, 0, len(plan.Objects))
	for index, object := range plan.Objects {
		header, err := readHeader("skill-hub/objects/"+strconv.Itoa(index)+".bin", spec.MaxObjectBytes)
		if err != nil || header.Size != object.Size {
			return d.ErrNotReady
		}
		digest := sha256.New()
		size, err := io.Copy(digest, reader)
		if err != nil || size != object.Size {
			return d.ErrNotReady
		}
		sha := hex.EncodeToString(digest.Sum(nil))
		if object.SHA256 != "" && object.SHA256 != sha {
			return d.ErrNotReady
		}
		actual = append(actual, sh.CapturedObject{Object: object, Digest: sh.ObjectDigest{Size: size, SHA256: sha}})
	}
	if _, err = readHeader("skill-hub/index.json", spec.MaxIndexBytes); err != nil {
		return err
	}
	indexRaw, err := io.ReadAll(io.LimitReader(reader, spec.MaxIndexBytes+1))
	if err != nil || int64(len(indexRaw)) > spec.MaxIndexBytes {
		return d.ErrNotReady
	}
	defer clear(indexRaw)
	type metadata struct {
		CacheControl       string            `json:"cache_control"`
		ContentDisposition string            `json:"content_disposition"`
		ContentEncoding    string            `json:"content_encoding"`
		ContentLanguage    string            `json:"content_language"`
		ContentType        string            `json:"content_type"`
		Expires            string            `json:"expires"`
		User               map[string]string `json:"user_metadata_allowlist"`
	}
	type entry struct {
		ETag     string   `json:"etag"`
		Key      string   `json:"key"`
		Modified string   `json:"last_modified"`
		Metadata metadata `json:"metadata"`
		Omitted  int      `json:"omitted_user_metadata_count"`
		SHA      string   `json:"sha256"`
		Size     int64    `json:"size"`
		Version  string   `json:"version_id"`
	}
	var index []entry
	if decodeProviderDeploymentJSON(indexRaw, &index) != nil || len(index) != len(actual) {
		return d.ErrNotReady
	}
	for position, entry := range index {
		item := &actual[position]
		if entry.Key != item.Object.Key || entry.Version != item.Object.VersionID || entry.Size != item.Digest.Size || entry.SHA != item.Digest.SHA256 || entry.Omitted != 0 {
			return d.ErrNotReady
		}
		item.Digest.Properties = &sh.ObjectProperties{ETag: entry.ETag, LastModified: entry.Modified, Metadata: sh.ObjectMetadata{ContentType: entry.Metadata.ContentType, ContentEncoding: entry.Metadata.ContentEncoding, ContentDisposition: entry.Metadata.ContentDisposition, ContentLanguage: entry.Metadata.ContentLanguage, CacheControl: entry.Metadata.CacheControl, Expires: entry.Metadata.Expires, UserMetadata: entry.Metadata.User}, OmittedUserMetadata: entry.Omitted}
	}
	var canonical bytes.Buffer
	if _, err = sh.WriteCapturedObjectIndex(ctx, &canonical, plan, actual, spec.MaxIndexBytes); err != nil || !bytes.Equal(canonical.Bytes(), indexRaw) {
		return d.ErrNotReady
	}
	if _, err = reader.Next(); err != io.EOF || zeroArchiveTail(src) != nil {
		return d.ErrNotReady
	}
	return nil
}
