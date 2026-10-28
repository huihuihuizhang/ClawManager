package systembackupskillhub

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/minio/minio-go/v7"
)

func TestMetadataCanonicalBoundaries(t *testing.T) {
	ctx := context.Background()
	m := ObjectMetadata{UserMetadata: map[string]string{"z": "<>&\u2028\u2029", "a": "tab\tquote\""}}
	raw, err := CanonicalObjectMetadata(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"user_metadata_allowlist":{"a":"tab\tquote\"","z":"<>&`+"\u2028\u2029"+`"}`) {
		t.Fatalf("noncanonical JSON: %s", raw)
	}
	base, _ := CanonicalObjectMetadata(ctx, ObjectMetadata{})
	m = ObjectMetadata{ContentType: strings.Repeat("x", MaxObjectMetadataBytes-len(base))}
	raw, err = CanonicalObjectMetadata(ctx, m)
	if err != nil || len(raw) != MaxObjectMetadataBytes {
		t.Fatalf("boundary: %d %v", len(raw), err)
	}
	m.ContentType += "x"
	if raw, err = CanonicalObjectMetadata(ctx, m); !errors.Is(err, ErrCapacity) || raw != nil {
		t.Fatal("oversized metadata accepted")
	}
	for _, m := range []ObjectMetadata{
		{ContentType: "SECRET\r\nInjected: bad"}, {UserMetadata: map[string]string{"Upper": "x"}},
		{UserMetadata: map[string]string{"a:b": "x"}}, {ContentLanguage: string([]byte{0xff})},
	} {
		if _, err := CanonicalObjectMetadata(ctx, m); !errors.Is(err, ErrObjectMetadata) || strings.Contains(err.Error(), "SECRET") {
			t.Fatalf("invalid metadata: %v", err)
		}
	}
	m = ObjectMetadata{ContentType: strings.Repeat("\"", MaxObjectMetadataBytes/2)}
	if _, err := CanonicalObjectMetadata(ctx, m); !errors.Is(err, ErrCapacity) {
		t.Fatal("escaped size not counted")
	}
}

func TestS3MetadataFromSameGETAndFrozenAllowlist(t *testing.T) {
	for _, mode := range []string{"valid", "oversized", "ambiguous"} {
		t.Run(mode, func(t *testing.T) {
			body := &closeProbe{Reader: strings.NewReader("hello")}
			calls := 0
			transport := s3Transport(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.Method != "GET" || req.URL.Query().Get("versionId") != "v1" {
					t.Fatal("not exact GET")
				}
				h := http.Header{"Content-Length": {"5"}, "Content-Type": {"application/zip"}, "Etag": {`"etag"`},
					"Last-Modified": {"Thu, 22 Oct 2026 04:05:06 GMT"}, "X-Amz-Version-Id": {"v1"},
					"Content-Encoding": {"gzip"}, "Cache-Control": {"private"}, "Content-Disposition": {"attachment"},
					"Content-Language": {"zh-CN"}, "Expires": {"Fri, 23 Oct 2026 04:05:06 GMT"},
					"X-Amz-Meta-Owner": {"allowed"}, "X-Amz-Meta-Secret": {"DO-NOT-RETAIN"}}
				if mode == "oversized" {
					h.Set("Cache-Control", strings.Repeat("x", MaxObjectMetadataBytes))
				}
				if mode == "ambiguous" {
					h["Content-Language"] = []string{"en", "zh"}
				}
				return &http.Response{StatusCode: 200, Header: h, Body: body, ContentLength: 5, Request: req}, nil
			})
			client, err := minio.New("s3.example.invalid", &minio.Options{Secure: true, Region: "us-east-1", Transport: transport})
			if err != nil {
				t.Fatal(err)
			}
			allow := []string{"owner"}
			reader, err := NewS3VersionReaderWithMetadata(client, "fixture-bucket", "root", allow)
			if err != nil {
				t.Fatal(err)
			}
			allow[0] = "secret"
			var dst bytes.Buffer
			got, err := CopyFrozenObject(context.Background(), reader, &dst, FrozenObject{Key: "key", VersionID: "v1", Size: 5}, 5)
			if mode != "valid" {
				if err == nil || got != (ObjectDigest{}) || dst.Len() != 0 || !body.closed {
					t.Fatalf("unsafe metadata streamed: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			p := got.Properties
			if p == nil || p.ETag != "etag" || p.LastModified != "2026-10-22T04:05:06Z" || p.OmittedUserMetadata != 1 {
				t.Fatalf("properties=%+v", p)
			}
			want := ObjectMetadata{ContentType: "application/zip", ContentEncoding: "gzip", CacheControl: "private", ContentDisposition: "attachment", ContentLanguage: "zh-CN", Expires: "Fri, 23 Oct 2026 04:05:06 GMT", UserMetadata: map[string]string{"owner": "allowed"}}
			if !sameMetadata(p.Metadata, want) || calls != 1 || !body.closed {
				t.Fatal("lost metadata or used HEAD")
			}
			raw, _ := CanonicalObjectMetadata(context.Background(), p.Metadata)
			if bytes.Contains(raw, []byte("DO-NOT-RETAIN")) {
				t.Fatal("retained unapproved user metadata")
			}
			entry := FrozenObject{Key: "key", VersionID: "v1", Size: 5}
			plan, err := PrepareObjectCapture(context.Background(), nil, []FrozenObject{entry}, ObjectCaptureLimits{MaxObjects: 1, MaxObjectBytes: 5, MaxTotalBytes: 5, MaxIndexBytes: 4096})
			if err != nil {
				t.Fatal(err)
			}
			var index bytes.Buffer
			indexDigest, err := WriteCapturedObjectIndex(context.Background(), &index, plan, []CapturedObject{{Object: entry, Digest: got}}, 4096)
			if err != nil || indexDigest.ObjectsWithOmittedMetadata != 1 || !bytes.Contains(index.Bytes(), raw) || bytes.Contains(index.Bytes(), []byte("DO-NOT-RETAIN")) {
				t.Fatalf("GET metadata not propagated into index: %v", err)
			}
		})
	}
}

func TestS3MetadataAllowlistRejectedBeforeIO(t *testing.T) {
	client, err := minio.New("s3.example.invalid", &minio.Options{Region: "us-east-1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, allow := range [][]string{{"Owner"}, {"owner", "owner"}, {"bad:key"}, {""}, {strings.Repeat("a", MaxObjectMetadataBytes), "b"}} {
		if _, err := NewS3VersionReaderWithMetadata(client, "fixture-bucket", "root", allow); err == nil {
			t.Fatal("invalid allowlist accepted")
		}
	}
}

func TestRestoredObjectRequiresExpectedMetadataBeforeIO(t *testing.T) {
	reader := objectReaderFunc(func(context.Context, string, string) (ObjectVersion, error) {
		t.Fatal("missing metadata reached provider")
		return ObjectVersion{}, nil
	})
	entry := FrozenObject{Key: "key", VersionID: "v1", SHA256: hashText("")}
	if err := VerifyRestoredObject(context.Background(), reader, entry, 0); !errors.Is(err, ErrObjectMetadata) {
		t.Fatal(err)
	}
}

func TestObjectMetadataVerificationAndDefensiveCopies(t *testing.T) {
	for _, mode := range []string{"match", "drift", "missing", "omitted"} {
		t.Run(mode, func(t *testing.T) {
			m := ObjectMetadata{ContentType: "application/zip", UserMetadata: map[string]string{"owner": "expected"}}
			p := &ObjectProperties{Metadata: cloneMetadata(m)}
			if mode == "drift" {
				p.Metadata.ContentType = "text/plain"
			}
			if mode == "missing" {
				p = nil
			}
			if mode == "omitted" {
				p.OmittedUserMetadata = 1
			}
			body := &closeProbe{Reader: strings.NewReader("hello")}
			reader := objectReaderFunc(func(context.Context, string, string) (ObjectVersion, error) {
				m.UserMetadata["owner"] = "mutated by callback"
				return ObjectVersion{Body: body, Size: 5, VersionID: "v1", Properties: p}, nil
			})
			entry := FrozenObject{Key: "key", VersionID: "v1", Size: 5, SHA256: hashText("hello"), Metadata: &m}
			err := VerifyRestoredObject(context.Background(), reader, entry, 5)
			if mode == "match" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrObjectMetadata) {
				t.Fatalf("metadata accepted: %v", err)
			}
			if !body.closed {
				t.Fatal("body leaked")
			}
		})
	}
	p := &ObjectProperties{Metadata: ObjectMetadata{UserMetadata: map[string]string{"a": "b"}}}
	reader := objectReaderFunc(func(context.Context, string, string) (ObjectVersion, error) {
		return ObjectVersion{Body: io.NopCloser(strings.NewReader("")), VersionID: "v1", Properties: p}, nil
	})
	got, err := CopyFrozenObject(context.Background(), reader, io.Discard, FrozenObject{Key: "key", VersionID: "v1"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	p.Metadata.UserMetadata["a"] = "changed"
	if got.Properties.Metadata.UserMetadata["a"] != "b" {
		t.Fatal("returned properties alias adapter")
	}
}
