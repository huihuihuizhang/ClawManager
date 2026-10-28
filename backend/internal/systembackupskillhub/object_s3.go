package systembackupskillhub

import (
	"context"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/s3utils"
)

// NewS3VersionReader wraps the existing MinIO SDK in a read-only capability.
// The provider owner supplies a client with independently scoped read credentials
// and verified endpoint/TLS policy. This helper does not prove those permissions.
// prefix is a provider root; keys passed to OpenVersion are relative logical
// keys. They are appended exactly once, never cleaned or guessed as full keys.
func NewS3VersionReader(client *minio.Client, bucket, prefix string) (VersionReader, error) {
	return NewS3VersionReaderWithMetadata(client, bucket, prefix, nil)
}

// The allowlist must come from authenticated frozen configuration. It is copied
// at construction and never inferred from the source object's user metadata.
func NewS3VersionReaderWithMetadata(client *minio.Client, bucket, prefix string, userMetadataAllowlist []string) (VersionReader, error) {
	allow := map[string]bool{}
	allowBytes := 0
	if len(userMetadataAllowlist) > MaxObjectMetadataBytes {
		return nil, ErrCapacity
	}
	for _, name := range userMetadataAllowlist {
		if len(name) > MaxObjectMetadataBytes-allowBytes {
			return nil, ErrCapacity
		}
		allowBytes += len(name)
		if !metadataKey(name) || allow[name] {
			return nil, ErrObjectMetadata
		}
		allow[name] = true
	}
	if strings.HasPrefix(prefix, "/") {
		return nil, ErrObject
	}
	prefix = strings.TrimSuffix(prefix, "/")
	if client == nil || s3utils.CheckValidBucketName(bucket) != nil || !safeRelative(prefix, true) {
		return nil, ErrObject
	}
	return s3VersionReader{core: minio.Core{Client: client}, bucket: bucket, prefix: prefix, allow: allow}, nil
}

type s3VersionReader struct {
	core           minio.Core
	bucket, prefix string
	allow          map[string]bool
}

func (r s3VersionReader) OpenVersion(ctx context.Context, key, version string) (ObjectVersion, error) {
	if err := checkContext(ctx); err != nil {
		return ObjectVersion{}, err
	}
	if !validObjectKey(key) || strings.TrimSpace(version) == "" || version == "null" {
		return ObjectVersion{}, ErrObject
	}
	fullKey := key
	if r.prefix != "" {
		fullKey = r.prefix + "/" + key
	}
	// Core.GetObject returns metadata from the SAME GET response as the stream;
	// a separate HEAD could authenticate a different observation.
	body, info, headers, err := r.core.GetObject(ctx, r.bucket, fullKey, minio.GetObjectOptions{VersionID: version})
	if err != nil {
		if body != nil {
			_ = body.Close()
		}
		return ObjectVersion{}, objectIOError(ctx)
	}
	if body == nil || info.VersionID != version || info.Size < 0 {
		if body != nil {
			_ = body.Close()
		}
		return ObjectVersion{}, ErrObject
	}
	metadata, omitted, err := s3Metadata(ctx, headers, r.allow)
	if err != nil {
		_ = body.Close()
		return ObjectVersion{}, err
	}
	modified := ""
	if !info.LastModified.IsZero() {
		modified = info.LastModified.UTC().Format(time.RFC3339Nano)
	}
	return ObjectVersion{Body: body, VersionID: info.VersionID, Size: info.Size, Properties: &ObjectProperties{
		ETag: info.ETag, LastModified: modified, Metadata: metadata, OmittedUserMetadata: omitted,
	}}, nil
}
