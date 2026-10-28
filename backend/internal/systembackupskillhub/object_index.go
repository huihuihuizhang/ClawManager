package systembackupskillhub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math"
	"time"
)

// CapturedObject binds a completed CopyFrozenObject result to its frozen input.
// It is a local staging record, not a public Runner DTO or authenticated proof.
type CapturedObject struct {
	Object FrozenObject
	Digest ObjectDigest
}

type ObjectIndexDigest struct {
	Size   int64
	SHA256 string
	// Public integration must emit a disqualifying warning when non-zero.
	ObjectsWithOmittedMetadata int
}

func capturedIndexValue(ctx context.Context, item CapturedObject) (map[string]any, error) {
	p := item.Digest.Properties
	if p == nil || p.ETag == "" || !metadataText(p.ETag) || len(p.ETag) > MaxObjectMetadataBytes || p.OmittedUserMetadata < 0 {
		return nil, ErrObjectMetadata
	}
	modified, err := time.Parse(time.RFC3339Nano, p.LastModified)
	if err != nil || modified.IsZero() || modified.UTC().Format(time.RFC3339Nano) != p.LastModified {
		return nil, ErrObjectMetadata
	}
	if _, err := CanonicalObjectMetadata(ctx, p.Metadata); err != nil {
		return nil, err
	}
	return map[string]any{"etag": p.ETag, "key": item.Object.Key, "last_modified": p.LastModified,
		"metadata": metadataValue(p.Metadata), "omitted_user_metadata_count": int64(p.OmittedUserMetadata),
		"sha256": item.Digest.SHA256, "size": item.Digest.Size, "version_id": item.Object.VersionID}, nil
}

// WriteCapturedObjectIndex writes a sorted, closed local JSON index into
// caller-owned candidate staging. It covers the complete frozen prefix,
// including unreferenced objects. Missing properties or digests are errors.
// All records and the total JCS/UTF-8 size are checked before writing. Output
// streams with bounded chunks; on I/O/cancellation failure discard staging.
// This does not prove source quiescence, copy objects to the failure domain,
// encrypt staging, discharge workspace proofs or confer public eligibility.
func WriteCapturedObjectIndex(ctx context.Context, dst io.Writer, plan ObjectCapturePlan, captured []CapturedObject, maxBytes int64) (ObjectIndexDigest, error) {
	var empty ObjectIndexDigest
	if err := checkContext(ctx); err != nil {
		return empty, err
	}
	if nilObjectAdapter(dst) {
		return empty, ErrObjectIO
	}
	if len(captured) != len(plan.Objects) {
		return empty, ErrObjectCoverage
	}
	frozen, err := PrepareObjectCapture(ctx, nil, plan.Objects, ObjectCaptureLimits{
		MaxObjects: len(plan.Objects), MaxObjectBytes: math.MaxInt64, MaxTotalBytes: math.MaxInt64, MaxIndexBytes: maxBytes,
	})
	if err != nil {
		return empty, err
	}
	if frozen.TotalBytes != plan.TotalBytes {
		return empty, ErrObjectCoverage
	}
	byKey := make(map[string]CapturedObject, len(captured))
	for _, item := range captured {
		if _, exists := byKey[item.Object.Key]; exists {
			return empty, ErrObjectCoverage
		}
		if !validSHA256(item.Digest.SHA256) || item.Digest.Size != item.Object.Size {
			return empty, ErrObject
		}
		// Validate before cloning an adapter-supplied metadata map.
		if _, err := capturedIndexValue(ctx, item); err != nil {
			return empty, err
		}
		byKey[item.Object.Key] = item
	}
	size := int64(2)
	omitted := 0
	for i, source := range frozen.Objects {
		item, ok := byKey[source.Key]
		if !ok || item.Object.VersionID != source.VersionID || item.Object.Size != source.Size ||
			(source.SHA256 != "" && source.SHA256 != item.Digest.SHA256) {
			return empty, ErrObjectCoverage
		}
		if source.Metadata != nil && !sameMetadata(*source.Metadata, item.Digest.Properties.Metadata) {
			return empty, ErrObjectMetadata
		}
		value, err := capturedIndexValue(ctx, item)
		if err != nil {
			return empty, err
		}
		if i > 0 {
			size++
		}
		n, err := canonicalObjectJSON(ctx, io.Discard, value, maxBytes-size)
		if err != nil {
			return empty, err
		}
		size += n
		if item.Digest.Properties.OmittedUserMetadata > 0 {
			omitted++
		}
	}
	// Only clone after the aggregate index budget has passed, then freeze before
	// invoking the caller's writer (which may mutate the original input).
	for key, item := range byKey {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		item.Digest.Properties = cloneProperties(item.Digest.Properties)
		byKey[key] = item
	}
	hash := sha256.New()
	out := io.MultiWriter(dst, hash)
	write := func(s string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if n, err := io.WriteString(out, s); err != nil || n != len(s) {
			return objectIOError(ctx)
		}
		return nil
	}
	if err := write("["); err != nil {
		return empty, err
	}
	for i, source := range frozen.Objects {
		if i > 0 {
			if err := write(","); err != nil {
				return empty, err
			}
		}
		value, err := capturedIndexValue(ctx, byKey[source.Key])
		if err != nil {
			return empty, err
		}
		if _, err := canonicalObjectJSON(ctx, out, value, maxBytes); err != nil {
			return empty, err
		}
	}
	if err := write("]"); err != nil {
		return empty, err
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	return ObjectIndexDigest{Size: size, SHA256: hex.EncodeToString(hash.Sum(nil)), ObjectsWithOmittedMetadata: omitted}, nil
}
