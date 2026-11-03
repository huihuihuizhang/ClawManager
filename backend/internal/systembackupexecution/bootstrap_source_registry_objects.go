package systembackupexecution

import (
	"context"
	"sort"
	"strings"

	"clawreef/internal/models"
	"clawreef/internal/systembackup/worker"
	"clawreef/internal/systembackupinstallationowner/install"
	sh "clawreef/internal/systembackupskillhub"
	"github.com/minio/minio-go/v7"
)

func (x *bootstrapSourceRegistryReader) readSkillObjectMetadata(ctx context.Context, clients *productionMetadataClients, skills *sh.CaptureInventory) (worker.SkillObjectCaptureSpec, error) {
	var zero worker.SkillObjectCaptureSpec
	if skills == nil || clients == nil || clients.Objects == nil || x.checkPhysical(ctx) != nil {
		return zero, install.ErrInstall
	}
	m := &x.materials
	// The current application-owned provider root is Skill packages. A broader
	// delegated root cannot be silently narrowed to only SQL-referenced objects.
	if len(m.Objects.ObjectPrefixes) != 1 || m.Objects.ObjectPrefixes[0].Bucket != m.SkillBucket || m.Objects.ObjectPrefixes[0].Prefix != m.SkillPrefix+"/" {
		return zero, install.ErrInstall
	}
	if _, err := sh.NewS3VersionReaderWithMetadata(clients.Objects, m.SkillBucket, m.SkillPrefix, m.UserMetadataAllowlist); err != nil {
		return zero, install.ErrInstall
	}
	versioning, err := clients.Objects.GetBucketVersioning(ctx, m.SkillBucket)
	if err != nil || !versioning.Enabled() || x.checkPhysical(ctx) != nil {
		return zero, install.ErrInstall
	}
	objects := []sh.FrozenObject{}
	seen := map[string]bool{}
	versions := 0
	var bytes int64
	listCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	for object := range clients.Objects.ListObjects(listCtx, m.SkillBucket, minio.ListObjectsOptions{Prefix: m.SkillPrefix + "/", Recursive: true, WithVersions: true}) {
		versions++
		if object.Err != nil || versions > 100000 || !strings.HasPrefix(object.Key, m.SkillPrefix+"/") || object.VersionID == "" || object.VersionID == "null" || x.checkPhysical(ctx) != nil {
			return zero, install.ErrInstall
		}
		if !object.IsLatest {
			continue
		}
		key := strings.TrimPrefix(object.Key, m.SkillPrefix+"/")
		if seen[key] {
			return zero, install.ErrInstall
		}
		seen[key] = true
		if object.IsDeleteMarker {
			continue
		}
		if len(objects) >= m.MaxObjects || object.Size < 0 || object.Size > m.MaxObjectBytes || object.Size > m.MaxObjectTotalBytes-bytes {
			return zero, install.ErrInstall
		}
		bytes += object.Size
		// This freezes an immutable original version. The original worker
		// computes its content SHA/metadata from that exact version in C.
		objects = append(objects, sh.FrozenObject{Key: key, VersionID: object.VersionID, Size: object.Size})
	}
	if listCtx.Err() != nil || x.checkPhysical(ctx) != nil {
		return zero, install.ErrInstall
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].Key < objects[j].Key })
	spec := worker.SkillObjectCaptureSpec{Version: worker.SkillObjectCaptureVersion, InventorySHA256: skills.SHA256(), Bucket: m.SkillBucket, Prefix: m.SkillPrefix, Objects: objects, Blobs: []worker.SkillObjectBlobRef{}, UserMetadataAllowlist: append([]string{}, m.UserMetadataAllowlist...), MaxObjects: m.MaxObjects, MaxObjectBytes: m.MaxObjectBytes, MaxTotalBytes: m.MaxObjectTotalBytes, MaxIndexBytes: 4 << 20}
	var blobs []models.SkillBlob
	for _, blob := range skills.Blobs {
		spec.Blobs = append(spec.Blobs, worker.SkillObjectBlobRef{ID: blob.ID, ObjectKey: blob.ObjectKey, SizeBytes: blob.SizeBytes})
		blobs = append(blobs, models.SkillBlob{ID: blob.ID, ObjectKey: blob.ObjectKey, SizeBytes: blob.SizeBytes})
	}
	plan, err := sh.PrepareObjectCapture(ctx, blobs, objects, sh.ObjectCaptureLimits{MaxObjects: spec.MaxObjects, MaxObjectBytes: spec.MaxObjectBytes, MaxTotalBytes: spec.MaxTotalBytes, MaxIndexBytes: spec.MaxIndexBytes})
	if err != nil {
		return zero, install.ErrInstall
	}
	spec.WorkspaceRequiredBlobIDs = append([]int{}, plan.UnpackagedBlobIDs...)
	return spec, nil
}
