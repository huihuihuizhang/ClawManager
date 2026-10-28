package systembackupskillhub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"reflect"
	"strings"
)

var (
	ErrObject   = errors.New("skill hub object version or integrity mismatch")
	ErrObjectIO = errors.New("skill hub object transfer failed")
	ErrCapacity = errors.New("skill hub object exceeds transfer capacity")
)

// FrozenObject must originate in the controller-authenticated frozen keyset.
// This helper cannot establish keyset completeness, writer pause or strong
// consistency. SHA256 is optional during capture, required by the verifier.
type FrozenObject struct {
	Key       string
	VersionID string
	Size      int64
	SHA256    string
	// Optional for byte-only helpers; required when verifying restored metadata.
	Metadata *ObjectMetadata
}

// VersionReader must read the exact requested immutable version, bind Size
// and VersionID to that response, and abort network reads on ctx cancellation.
// It must not fall back to a current object when the version is missing.
type VersionReader interface {
	OpenVersion(context.Context, string, string) (ObjectVersion, error)
}
type ObjectVersion struct {
	Body       io.ReadCloser
	VersionID  string
	Size       int64
	Properties *ObjectProperties
}
type ObjectDigest struct {
	Size       int64
	SHA256     string
	Properties *ObjectProperties
}

// CopyFrozenObject streams into caller-owned candidate staging with a fixed
// buffer. It never publishes an artifact or reports a backup consistency level.
// On ANY error the caller must discard that staging candidate; bytes may have
// already been written. It never deletes an object or retries against production.
func CopyFrozenObject(ctx context.Context, reader VersionReader, dst io.Writer, entry FrozenObject, maxBytes int64) (ObjectDigest, error) {
	var empty ObjectDigest
	if err := checkContext(ctx); err != nil {
		return empty, err
	}
	if nilObjectAdapter(reader) || nilObjectAdapter(dst) || !validObjectKey(entry.Key) || strings.TrimSpace(entry.VersionID) == "" || entry.VersionID == "null" || entry.Size < 0 {
		return empty, ErrObject
	}
	if entry.Size == math.MaxInt64 || maxBytes < 0 || entry.Size > maxBytes {
		return empty, ErrCapacity
	}
	if entry.SHA256 != "" && !validSHA256(entry.SHA256) {
		return empty, ErrObject
	}
	if entry.Metadata != nil {
		if _, err := CanonicalObjectMetadata(ctx, *entry.Metadata); err != nil {
			return empty, err
		}
		frozen := cloneMetadata(*entry.Metadata)
		entry.Metadata = &frozen
	}
	object, err := reader.OpenVersion(ctx, entry.Key, entry.VersionID)
	if err != nil {
		if !nilObjectAdapter(object.Body) {
			_ = object.Body.Close()
		}
		if ctx.Err() == nil {
			if errors.Is(err, ErrCapacity) {
				return empty, ErrCapacity
			}
			if errors.Is(err, ErrObjectMetadata) {
				return empty, ErrObjectMetadata
			}
		}
		return empty, objectIOError(ctx)
	}
	if nilObjectAdapter(object.Body) {
		return empty, ErrObject
	}
	if object.VersionID != entry.VersionID || object.Size != entry.Size {
		_ = object.Body.Close()
		return empty, ErrObject
	}
	if object.Properties != nil {
		if _, err := CanonicalObjectMetadata(ctx, object.Properties.Metadata); err != nil {
			_ = object.Body.Close()
			return empty, err
		}
		if object.Properties.OmittedUserMetadata < 0 {
			_ = object.Body.Close()
			return empty, ErrObjectMetadata
		}
	}
	if entry.Metadata != nil && (object.Properties == nil || !sameMetadata(*entry.Metadata, object.Properties.Metadata)) {
		_ = object.Body.Close()
		return empty, ErrObjectMetadata
	}
	properties := cloneProperties(object.Properties)
	hash := sha256.New()
	// Read at most one byte past the frozen size to detect truncation/extension,
	// but never write that extra byte into candidate staging.
	limited := io.LimitReader(&objectContextReader{ctx: ctx, reader: object.Body}, entry.Size+1)
	writer := &sizedObjectWriter{ctx: ctx, writer: io.MultiWriter(dst, hash), remaining: entry.Size}
	size, copyErr := io.CopyBuffer(writer, limited, make([]byte, 64*1024))
	closeErr := object.Body.Close()
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if copyErr != nil {
		if errors.Is(copyErr, ErrObject) {
			return empty, ErrObject
		}
		return empty, ErrObjectIO
	}
	if closeErr != nil {
		return empty, ErrObjectIO
	}
	if size != entry.Size {
		return empty, ErrObject
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	if entry.SHA256 != "" && digest != entry.SHA256 {
		return empty, ErrObject
	}
	return ObjectDigest{Size: size, SHA256: digest, Properties: properties}, nil
}

// VerifyFrozenObject consumes independently read target bytes, without a write
// capability. Caller supplies the target key/version and authenticated expected
// digest from the captured artifact, never a digest calculated from this target.
// Metadata is compared when supplied; legacy byte-only callers may omit it.
// Restore acceptance must use VerifyRestoredObject, which requires metadata.
func VerifyFrozenObject(ctx context.Context, reader VersionReader, entry FrozenObject, maxBytes int64) error {
	if !validSHA256(entry.SHA256) {
		return ErrObject
	}
	got, err := CopyFrozenObject(ctx, reader, io.Discard, entry, maxBytes)
	if err == nil && got.Properties != nil && got.Properties.OmittedUserMetadata != 0 {
		return ErrObjectMetadata
	}
	return err
}

// Enforce the logical-key boundary even for non-S3 adapters and callers that
// invoke copy/verify without first building a capture plan. Never clean keys:
// normalization could silently select a different object than the frozen one.
func validObjectKey(key string) bool {
	return strings.TrimSpace(key) != "" && safeRelative(key, false)
}

// VerifyRestoredObject requires authenticated expected metadata as well as the
// captured content SHA-256. Source ETag and last-modified are index history,
// not equality requirements for a newly uploaded target object's version.
func VerifyRestoredObject(ctx context.Context, reader VersionReader, entry FrozenObject, maxBytes int64) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if entry.Metadata == nil {
		return ErrObjectMetadata
	}
	return VerifyFrozenObject(ctx, reader, entry, maxBytes)
}

func validSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func nilObjectAdapter(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Func, reflect.Map, reflect.Slice, reflect.Chan:
		return v.IsNil()
	}
	return false
}
func objectIOError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Provider errors may contain signed URLs, credentials and private keys.
	return ErrObjectIO
}

type objectContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *objectContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

type sizedObjectWriter struct {
	ctx       context.Context
	writer    io.Writer
	remaining int64
}

func (w *sizedObjectWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if int64(len(p)) > w.remaining {
		return 0, ErrObject
	}
	n, err := w.writer.Write(p)
	w.remaining -= int64(n)
	return n, err
}
