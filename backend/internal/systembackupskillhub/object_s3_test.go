package systembackupskillhub

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type s3Transport func(*http.Request) (*http.Response, error)

func (f s3Transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestS3VersionReaderUsesMetadataFromExactGET(t *testing.T) {
	for _, mode := range []string{"valid", "wrong_version", "missing_version", "not_found"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			transport := s3Transport(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.Method != http.MethodGet || req.URL.Path != "/fixture-bucket/provider/root/nested/skill.zip" || req.URL.Query().Get("versionId") != "opaque/version+7" {
					t.Errorf("request lost exact key/version or used separate HEAD: %s %s", req.Method, req.URL.Path)
				}
				if len(req.URL.Query()) != 1 {
					t.Error("unexpected unversioned/auxiliary request")
				}
				headers := http.Header{"Content-Length": {"5"}, "Content-Type": {"application/zip"}, "Etag": {`"opaque-multipart-7"`}, "Last-Modified": {"Thu, 22 Oct 2026 04:05:06 GMT"}}
				if mode != "missing_version" {
					headers.Set("X-Amz-Version-Id", "opaque/version+7")
				}
				if mode == "wrong_version" {
					headers.Set("X-Amz-Version-Id", "different-version")
				}
				if mode == "not_found" {
					xml := "<Error><Code>NoSuchVersion</Code><Message>SECRET SOURCE LOCATION</Message></Error>"
					headers.Set("Content-Length", strconv.Itoa(len(xml)))
					return &http.Response{StatusCode: 404, Status: "404 Not Found", Header: headers, Body: io.NopCloser(strings.NewReader(xml)), ContentLength: int64(len(xml)), Request: req}, nil
				}
				return &http.Response{StatusCode: 200, Status: "200 OK", Header: headers, Body: io.NopCloser(strings.NewReader("hello")), ContentLength: 5, Request: req}, nil
			})
			client, err := minio.New("s3.example.invalid", &minio.Options{Secure: true, Region: "us-east-1", BucketLookup: minio.BucketLookupPath, Creds: credentials.NewStaticV4("fixture-access", "fixture-secret", ""), Transport: transport})
			if err != nil {
				t.Fatal(err)
			}
			reader, err := NewS3VersionReader(client, "fixture-bucket", "provider/root/")
			if err != nil {
				t.Fatal(err)
			}
			var dst bytes.Buffer
			result, err := CopyFrozenObject(context.Background(), reader, &dst, FrozenObject{Key: "nested/skill.zip", VersionID: "opaque/version+7", Size: 5}, 5)
			if mode == "valid" {
				if err != nil || dst.String() != "hello" || result.SHA256 != hashText("hello") {
					t.Fatalf("copy=%v %v", result, err)
				}
			} else if err == nil || result != (ObjectDigest{}) || dst.Len() != 0 {
				t.Fatalf("invalid version returned bytes: %v %v", result, err)
			}
			if err != nil && strings.Contains(err.Error(), "SECRET") {
				t.Fatal("provider error leaked")
			}
			if calls != 1 {
				t.Fatalf("expected one exact GET without fallback, got %d", calls)
			}
		})
	}
}

func TestS3VersionReaderRejectsPathsBeforeNetwork(t *testing.T) {
	client, err := minio.New("s3.example.invalid", &minio.Options{Secure: true, Region: "us-east-1", Transport: s3Transport(func(*http.Request) (*http.Response, error) {
		t.Error("invalid path reached network")
		return nil, errors.New("unexpected request")
	})})
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"/", "../escape", "/absolute", "C:/drive", "nested//root", "root/../escape"} {
		if _, err := NewS3VersionReader(client, "fixture-bucket", prefix); err == nil {
			t.Fatalf("accepted prefix %q", prefix)
		}
	}
	reader, err := NewS3VersionReader(client, "fixture-bucket", "root")
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"../escape", "/absolute", "a/../b", "a\\b", "a//b", "", " ", "\t", "a\x00b", string([]byte{0xff})} {
		if _, err := reader.OpenVersion(context.Background(), key, "v1"); err == nil {
			t.Fatalf("accepted key %q", key)
		}
	}
	for _, version := range []string{"", "null"} {
		if _, err := reader.OpenVersion(context.Background(), "key", version); err == nil {
			t.Fatal("accepted unversioned read")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := reader.OpenVersion(ctx, "key", "v1"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestObjectTransferRejectsTypedNilAdapters(t *testing.T) {
	var reader objectReaderFunc
	var writer *bytes.Buffer
	valid := objectReaderFunc(func(context.Context, string, string) (ObjectVersion, error) {
		var body *closeProbe
		return ObjectVersion{Body: body, VersionID: "v1", Size: 0}, nil
	})
	entry := FrozenObject{Key: "key", VersionID: "v1", Size: 0}
	if _, err := CopyFrozenObject(context.Background(), reader, io.Discard, entry, 1); err == nil {
		t.Fatal("accepted nil reader")
	}
	if _, err := CopyFrozenObject(context.Background(), valid, writer, entry, 1); err == nil {
		t.Fatal("accepted nil writer")
	}
	if _, err := CopyFrozenObject(context.Background(), valid, io.Discard, entry, 1); err == nil {
		t.Fatal("accepted nil body")
	}
}
