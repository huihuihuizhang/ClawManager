package systembackup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
)

// Actual complete native read under ONE original source gate. This is not
// immutable-history authority, a physical cut, a backfill or PreparedCoverage.
// The installer must independently bind the same physical source/cold archive.
type OriginalProtectedMinIOHistory struct {
	origin *OriginalProtectedMinIOHistory
	ctx    context.Context
	gate   *MinIOReadServiceGate
	facts  OriginalProtectedMinIOHistoryFacts
	failed bool
}

type OriginalProtectedMinIOObject struct {
	Bucket, Key, VersionID, ETag, BodySHA256, MetadataSHA256 string
	Size                                                     int64
	ModifiedAt                                               time.Time
	Latest, DeleteMarker                                     bool
}

type OriginalProtectedMinIOBucket struct {
	Name, VersioningSHA256 string
	CreatedAt              time.Time
	Versions, UploadPages  uint64
}

type OriginalProtectedMinIOHistoryFacts struct {
	Version, Operation, InventorySHA256, OriginalNativeSHA256 string
	Namespace, NamespaceUID, Pod, PodUID, Container, ImageID  string
	Endpoint, Region, DeploymentID, CASHA256, SPKISHA256      string
	Buckets                                                   []OriginalProtectedMinIOBucket
	Objects                                                   []OriginalProtectedMinIOObject
	BodyBytes                                                 int64
	SnapshotSHA256                                            string
	ObservedAt, Until                                         time.Time
}

func (*OriginalProtectedMinIOHistory) MarshalJSON() ([]byte, error) { return nil, ErrMinIOReadGate }

func originalMinIOHistorySameContext(a, b context.Context) bool {
	return a != nil && b != nil && reflect.TypeOf(a).Comparable() && reflect.TypeOf(b).Comparable() && a == b
}

func (g *MinIOReadServiceGate) CollectOriginalProtectedHistory(ctx context.Context) (*OriginalProtectedMinIOHistory, error) {
	if g == nil {
		return nil, ErrMinIOReadGate
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	// Every native bucket must be covered by the actual write fence. An
	// output-only bucket/account is not silently exempt from initial history.
	if g.origin != g || !g.held || g.restored || g.recovering || g.pending != nil || len(g.in.OutputAccounts) != 0 || !reflect.DeepEqual(g.in.BusinessBuckets, g.original.BucketNames) || g.recheckState(ctx, true) != nil {
		return nil, ErrMinIOReadGate
	}
	first, err := g.readOriginalProtectedHistory(ctx)
	if err != nil {
		return nil, err
	}
	second, err := g.readOriginalProtectedHistory(ctx)
	if err != nil || first.SnapshotSHA256 != second.SnapshotSHA256 || g.recheckState(ctx, true) != nil {
		return nil, ErrMinIOReadGate
	}
	h := &OriginalProtectedMinIOHistory{ctx: ctx, gate: g, facts: second}
	h.origin = h
	return h, nil
}

// Recheck while the native server is STILL online, immediately before the
// source owner's warm physical read and original full-cold stop dispatch.
func (h *OriginalProtectedMinIOHistory) RecheckProtectedBeforeCold(ctx context.Context) error {
	if h == nil || h.origin != h || h.failed || !originalMinIOHistorySameContext(ctx, h.ctx) || ctx.Err() != nil || !time.Now().Before(h.facts.Until) {
		return ErrMinIOReadGate
	}
	h.gate.mu.Lock()
	defer h.gate.mu.Unlock()
	if !h.gate.held || h.gate.restored || h.gate.recovering || h.gate.recheckState(ctx, true) != nil {
		h.failed = true
		return ErrMinIOReadGate
	}
	current, err := h.gate.readOriginalProtectedHistory(ctx)
	if err != nil || current.SnapshotSHA256 != h.facts.SnapshotSHA256 || h.gate.recheckState(ctx, true) != nil {
		h.failed = true
		return ErrMinIOReadGate
	}
	return nil
}

// Comparison DATA only. After cold this performs no MinIO/old-Pod request.
// Having this pointer is not a claim that the raw copy matches these objects.
func (h *OriginalProtectedMinIOHistory) OriginalHistoryData(ctx context.Context) (OriginalProtectedMinIOHistoryFacts, error) {
	var zero OriginalProtectedMinIOHistoryFacts
	if h == nil || h.origin != h || h.failed || !originalMinIOHistorySameContext(ctx, h.ctx) || ctx.Err() != nil || !time.Now().Before(h.facts.Until) {
		return zero, ErrMinIOReadGate
	}
	h.gate.mu.Lock()
	defer h.gate.mu.Unlock()
	if h.gate.origin != h.gate || !h.gate.held || h.gate.restored || h.gate.recovering || h.gate.pending != nil {
		return zero, ErrMinIOReadGate
	}
	raw, err := json.Marshal(h.facts)
	if err != nil || json.Unmarshal(raw, &zero) != nil {
		return OriginalProtectedMinIOHistoryFacts{}, ErrMinIOReadGate
	}
	return zero, nil
}

func (g *MinIOReadServiceGate) readOriginalProtectedHistory(ctx context.Context) (OriginalProtectedMinIOHistoryFacts, error) {
	bad := func() (OriginalProtectedMinIOHistoryFacts, error) {
		return OriginalProtectedMinIOHistoryFacts{}, ErrMinIOReadGate
	}
	if ctx == nil || ctx.Err() != nil || g.reader == nil || !time.Now().Before(g.until) {
		return bad()
	}
	f := OriginalProtectedMinIOHistoryFacts{Version: "original-protected-whole-minio-history.v1", Operation: g.in.Operation, InventorySHA256: g.in.InventorySHA256, OriginalNativeSHA256: minioGateHash(g.original), Namespace: g.in.Namespace, NamespaceUID: g.in.NamespaceUID, Pod: g.in.Pod, PodUID: g.in.PodUID, Container: g.in.Container, ImageID: g.in.ImageID, Endpoint: g.in.Endpoint, Region: g.in.Region, DeploymentID: g.in.DeploymentID, CASHA256: g.in.CASHA256, SPKISHA256: g.in.SPKISHA256, Buckets: []OriginalProtectedMinIOBucket{}, Objects: []OriginalProtectedMinIOObject{}, ObservedAt: time.Now().UTC(), Until: g.until}
	buckets, err := g.reader.ListBuckets(ctx)
	if err != nil || len(buckets) == 0 || len(buckets) > 64 {
		return bad()
	}
	sort.Slice(buckets, func(i, j int) bool { return buckets[i].Name < buckets[j].Name })
	names := []string{}
	for _, bucket := range buckets {
		names = append(names, bucket.Name)
	}
	if !reflect.DeepEqual(names, g.original.BucketNames) {
		return bad()
	}
	seen := map[string]bool{}
	for _, bucket := range buckets {
		versioning, err := g.reader.GetBucketVersioning(ctx, bucket.Name)
		if err != nil {
			return bad()
		}
		bf := OriginalProtectedMinIOBucket{Name: bucket.Name, CreatedAt: bucket.CreationDate.UTC(), VersioningSHA256: minioGateHash(versioning)}
		child, cancel := context.WithCancel(ctx)
		for object := range g.reader.ListObjects(child, bucket.Name, minio.ListObjectsOptions{WithVersions: true, Recursive: true}) {
			id := bucket.Name + "\x00" + object.Key + "\x00" + object.VersionID
			if object.Err != nil || object.Key == "" || strings.ContainsRune(object.Key, '\x00') || object.Size < 0 || seen[id] || len(seen) >= 100000 || object.LastModified.IsZero() || ctx.Err() != nil {
				cancel()
				return bad()
			}
			seen[id] = true
			item := OriginalProtectedMinIOObject{Bucket: bucket.Name, Key: object.Key, VersionID: object.VersionID, ETag: object.ETag, Size: object.Size, ModifiedAt: object.LastModified.UTC(), Latest: object.IsLatest, DeleteMarker: object.IsDeleteMarker}
			if !object.IsDeleteMarker {
				if object.Size > 1<<40 || f.BodyBytes > (1<<40)-object.Size {
					cancel()
					return bad()
				}
				body, err := g.reader.GetObject(child, bucket.Name, object.Key, minio.GetObjectOptions{VersionID: object.VersionID})
				if err != nil {
					cancel()
					return bad()
				}
				stat, err := body.Stat()
				if err != nil || stat.Size != object.Size || stat.VersionID != object.VersionID || stat.ETag != object.ETag || !stat.LastModified.Equal(object.LastModified) || stat.Metadata.Get("X-Amz-Server-Side-Encryption") != "" || stat.Metadata.Get("X-Amz-Server-Side-Encryption-Customer-Algorithm") != "" {
					_ = body.Close()
					cancel()
					return bad()
				}
				h := sha256.New()
				n, readErr := io.Copy(h, io.LimitReader(body, object.Size+1))
				closeErr := body.Close()
				if readErr != nil || closeErr != nil || n != object.Size {
					cancel()
					return bad()
				}
				item.BodySHA256 = hex.EncodeToString(h.Sum(nil))
				item.MetadataSHA256 = minioGateHash(struct {
					Metadata     any
					UserMetadata any
				}{stat.Metadata, stat.UserMetadata})
				f.BodyBytes += n
			}
			f.Objects = append(f.Objects, item)
			bf.Versions++
		}
		cancel()
		if ctx.Err() != nil {
			return bad()
		}
		// Whole-bucket, empty-prefix native EOF, deliberately separate from the
		// older nonempty-prefix census. Multipart bodies have no read-part S3
		// API: this closed profile refuses any actual pending upload instead of
		// omitting it or treating an upload/part list as a complete body proof.
		core := minio.Core{Client: g.reader}
		page, err := core.ListMultipartUploads(ctx, bucket.Name, "", "", "", "", 1000)
		if err != nil || page.Bucket != bucket.Name || page.Prefix != "" || page.KeyMarker != "" || page.UploadIDMarker != "" || page.Delimiter != "" || page.IsTruncated || len(page.CommonPrefixes) != 0 || len(page.Uploads) != 0 || page.NextKeyMarker != "" || page.NextUploadIDMarker != "" {
			return bad()
		}
		bf.UploadPages = 1
		f.Buckets = append(f.Buckets, bf)
	}
	sort.Slice(f.Objects, func(i, j int) bool {
		a, b := f.Objects[i], f.Objects[j]
		if a.Bucket != b.Bucket {
			return a.Bucket < b.Bucket
		}
		if a.Key != b.Key {
			return a.Key < b.Key
		}
		return a.VersionID < b.VersionID
	})
	projection := f
	projection.ObservedAt, projection.Until = time.Time{}, time.Time{}
	projection.SnapshotSHA256 = ""
	f.SnapshotSHA256 = minioGateHash(projection)
	if !time.Now().Before(f.Until) {
		return bad()
	}
	return f, nil
}
