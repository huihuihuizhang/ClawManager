package systembackupskillhub

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"clawreef/internal/models"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Opt-in disposable loopback MinIO only. Creates a random versioned bucket;
// cleanup deletes only the exact versions uploaded by this test.
func TestS3MinIORoundTrip(t *testing.T) {
	endpoint := os.Getenv("CLAWMANAGER_SKILLHUB_TEST_MINIO_ENDPOINT")
	if endpoint == "" {
		t.Skip("set CLAWMANAGER_SKILLHUB_TEST_MINIO_ENDPOINT for disposable local MinIO")
	}
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil || (host != "127.0.0.1" && host != "::1") {
		t.Fatal("test endpoint must be a loopback address")
	}
	access, secret := os.Getenv("CLAWMANAGER_SKILLHUB_TEST_MINIO_ACCESS_KEY"), os.Getenv("CLAWMANAGER_SKILLHUB_TEST_MINIO_SECRET_KEY")
	if access == "" || secret == "" {
		t.Fatal("test credentials missing")
	}
	client, err := minio.New(endpoint, &minio.Options{Creds: credentials.NewStaticV4(access, secret, ""), Region: "us-east-1"})
	if err != nil {
		t.Fatal("could not construct test client")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var id [12]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	bucket := "skillhub-test-" + hex.EncodeToString(id[:])
	if err := client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil {
		t.Fatal("could not create isolated bucket")
	}
	type uploaded struct{ key, version string }
	var versions []uploaded
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanCancel()
		for _, v := range versions {
			if err := client.RemoveObject(cleanCtx, bucket, v.key, minio.RemoveObjectOptions{VersionID: v.version}); err != nil {
				t.Error("test version cleanup failed")
			}
		}
		if err := client.RemoveBucket(cleanCtx, bucket); err != nil {
			t.Error("test bucket cleanup failed")
		}
	})
	if err := client.EnableVersioning(ctx, bucket); err != nil {
		t.Fatal("could not enable test bucket versioning")
	}
	put := func(key, body string, options minio.PutObjectOptions) string {
		t.Helper()
		info, err := client.PutObject(ctx, bucket, key, strings.NewReader(body), int64(len(body)), options)
		if err != nil {
			t.Fatal("test upload failed")
		}
		if info.VersionID == "" || info.VersionID == "null" {
			t.Fatal("test upload has no immutable version")
		}
		versions = append(versions, uploaded{key, info.VersionID})
		return info.VersionID
	}
	options := minio.PutObjectOptions{ContentType: "application/zip", ContentEncoding: "identity", ContentLanguage: "zh-CN",
		CacheControl: "private, max-age=60", ContentDisposition: `attachment; filename="skill.zip"`,
		Expires: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC), UserMetadata: map[string]string{"owner": "team", "private-field": "do-not-copy"}}
	inventory := []FrozenObject{{Key: "shared", VersionID: put("source/shared", "hello", options), Size: 5},
		{Key: "orphan", VersionID: put("source/orphan", "", options), Size: 0}}
	// Current contents deliberately differ from the frozen version.
	put("source/shared", "changed", options)
	source, err := NewS3VersionReaderWithMetadata(client, bucket, "source", []string{"owner"})
	if err != nil {
		t.Fatal(err)
	}
	blobs := []models.SkillBlob{{ID: 1, ObjectKey: "shared", SizeBytes: 5}, {ID: 2, ObjectKey: "shared", SizeBytes: 5}, {ID: 3}}
	limits := ObjectCaptureLimits{MaxObjects: 2, MaxObjectBytes: 16, MaxTotalBytes: 32, MaxIndexBytes: 8192}
	capturePlan, err := PrepareObjectCapture(ctx, blobs, inventory, limits)
	if err != nil {
		t.Fatal(err)
	}
	var captured []CapturedObject
	targets := map[string]RestoredObjectLocation{}
	delete(options.UserMetadata, "private-field")
	for _, entry := range capturePlan.Objects {
		var body bytes.Buffer
		digest, err := CopyFrozenObject(ctx, source, &body, entry, limits.MaxObjectBytes)
		if err != nil {
			t.Fatal(err)
		}
		if digest.Properties == nil || digest.Properties.OmittedUserMetadata != 1 || digest.Properties.Metadata.UserMetadata["owner"] != "team" {
			t.Fatal("metadata allowlist lost")
		}
		captured = append(captured, CapturedObject{Object: entry, Digest: digest})
		targets[entry.Key] = RestoredObjectLocation{Key: entry.Key, VersionID: put("target/"+entry.Key, body.String(), options)}
	}
	var index bytes.Buffer
	indexDigest, err := WriteCapturedObjectIndex(ctx, &index, capturePlan, captured, limits.MaxIndexBytes)
	if err != nil || indexDigest.ObjectsWithOmittedMetadata != 2 {
		t.Fatalf("index capture: %v", err)
	}
	if strings.Contains(index.String(), "private-field") || strings.Contains(index.String(), "do-not-copy") {
		t.Fatal("omitted metadata leaked")
	}
	// Anonymous credentials can only read target objects in this owned fixture.
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":["arn:aws:s3:::` + bucket + `/target/*"]}]}`
	if err := client.SetBucketPolicy(ctx, bucket, policy); err != nil {
		t.Fatal("test read-only policy failed")
	}
	readClient, err := minio.New(endpoint, &minio.Options{Creds: credentials.NewStaticV4("", "", ""), Region: "us-east-1"})
	if err != nil {
		t.Fatal("could not create independent reader")
	}
	reader, err := NewS3VersionReaderWithMetadata(readClient, bucket, "target", []string{"owner"})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PrepareObjectRestore(ctx, blobs, map[string]string{"shared": "shared"}, inventory, captured, targets, limits)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.UnpackagedBlobIDs) != 1 || plan.ObjectsWithOmittedMetadata != 2 {
		t.Fatal("restore lost proof or warning requirements")
	}
	if err := VerifyObjectRestorePlan(ctx, reader, plan, limits); err != nil {
		t.Fatal(err)
	}
	wrongVersion := put("target/shared", "wrong", options)
	if err := VerifyObjectRestorePlan(ctx, reader, plan, limits); err != nil {
		t.Fatal("target verification selected current version")
	}
	for _, entry := range plan.Objects {
		if entry.Key != "shared" {
			continue
		}
		entry.VersionID = wrongVersion
		if err := VerifyRestoredObject(ctx, reader, entry, 16); !errors.Is(err, ErrObject) {
			t.Fatalf("accepted changed bytes: %v", err)
		}
		options.ContentType = "text/plain"
		entry.VersionID = put("target/shared", "hello", options)
		if err := VerifyRestoredObject(ctx, reader, entry, 16); !errors.Is(err, ErrObjectMetadata) {
			t.Fatalf("accepted changed metadata: %v", err)
		}
		entry.VersionID = "11111111-1111-4111-8111-111111111111"
		if err := VerifyRestoredObject(ctx, reader, entry, 16); err == nil {
			t.Fatal("missing version fell back to current object")
		}
	}
	info, err := readClient.PutObject(ctx, bucket, "target/forbidden", strings.NewReader("x"), 1, minio.PutObjectOptions{})
	if err == nil {
		versions = append(versions, uploaded{"target/forbidden", info.VersionID})
		t.Fatal("read-only test identity can write")
	}
	if minio.ToErrorResponse(err).Code != "AccessDenied" {
		t.Fatal("write denial was not an authorization rejection")
	}
}
