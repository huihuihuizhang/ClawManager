package domain

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"clawreef/internal/systembackup/staging"
	"github.com/minio/minio-go/v7"
)

func imageObjectBindings() (staging.Binding, staging.Binding, staging.Binding) {
	a := staging.Binding{BackupID: "owned-image-backup", Attempt: "1", Path: "images/source", CaptureContextHash: strings.Repeat("a", 64), EnvelopeID: "owned-image-dek"}
	b, c := a, a
	b.Path = "mysql/expected"
	c.Path = "images/expected"
	return a, b, c
}
func cloneImageTestSnapshot(t *testing.T, s Snapshot) Snapshot {
	t.Helper()
	raw, e := json.Marshal(s)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(raw)
	var out Snapshot
	if json.Unmarshal(raw, &out) != nil {
		t.Fatal("snapshot clone")
	}
	return out
}
func normalizedImageTestSnapshot(t *testing.T, s Snapshot) Snapshot {
	t.Helper()
	out := cloneImageTestSnapshot(t, s)
	for _, table := range out.Tables {
		if isGatewayImageTable(table.Name) {
			for _, row := range table.Rows {
				if normalizeGatewayImageRow(table.Name, row, "2026-11-01T00:00:00Z") != nil {
					t.Fatal("image projection")
				}
			}
		}
	}
	return out
}
func TestGatewayImageActualVersionedSDKReadbackAndEncryptedRestartReceipt(t *testing.T) {
	ctx := context.Background()
	source, raw := imageRestoreFixture()
	id := find(source, "gateway_image_artifacts").Rows[0]["id"].String()
	bucket := "cm-restore-" + strings.Repeat("8", 32)
	s, src, writer, reader := newImageS3Fixture(t, bucket, id, raw)
	root, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	key := bytes.Repeat([]byte{73}, 32)
	a, b, c := imageObjectBindings()
	refs := []GatewayImageObjectRef{{ArtifactID: id, Bucket: "owned-image-source", Key: "gateway-images/" + id, Version: "source-version-1", SHA256: imageHash(raw), Size: int64(len(raw))}}
	before, _ := Digest(source)
	captured, e := CaptureGatewayImageObjects(ctx, src, source, refs, root, "image-source.enc", key, a)
	if e != nil {
		t.Fatal("actual source version capture", e)
	}
	restored, e := RestoreGatewayImageObjects(ctx, source, root, captured, key, a, writer, reader, "cm_drill_image_sdk", "owned-sql-uuid", bucket, "2026-11-01T00:00:00Z")
	if e != nil {
		t.Fatal("actual SDK restore/readback", e)
	}
	if s.puts != 1 || s.fixedReads < 2 {
		t.Fatal("no actual version IO occurred")
	}
	if after, _ := Digest(source); after != before {
		t.Fatal("source archive changed")
	}
	_, _, policy := gatewayRestoreFixture()
	for _, table := range source.Tables {
		if isGatewayImageTable(table.Name) {
			adapter := TableAdapter{SchemaSHA256: SchemaDigest(table), Normalizer: GatewayImage074Normalizer, InterruptedAt: "2026-11-01T00:00:00Z", Columns: map[string]string{}}
			for _, column := range table.Columns {
				adapter.Columns[column.Name] = "preserve"
			}
			policy.Dependencies[table.Name] = adapter
		}
	}
	if _, e := Normalize(ctx, source, source.Tables, policy); e == nil {
		t.Fatal("missing concrete image receipt accepted")
	}
	policy.GatewayImages = restored
	plan, e := Normalize(ctx, source, source.Tables, policy)
	if e != nil {
		t.Fatal("actual common Normalize with image receipt", e)
	}
	normalized := plan.Data
	if restored.quarantineMatches(ctx, normalized) != nil || verifyGatewayImageExpected(ctx, normalized, restored, "cm_drill_image_sdk", "owned-sql-uuid") == nil {
		t.Fatal("source receipt reused as independent persisted expected evidence")
	}
	sqlExpected, e := staging.SealFile(ctx, root, "sql-expected.enc", key, b, func(w io.Writer) error { return Encode(w, normalized) })
	if e != nil {
		t.Fatal(e)
	}
	metadata, e := SealGatewayImageReceipt(ctx, restored, normalized, sqlExpected, b, root, "image-expected.enc", key, c)
	if e != nil {
		t.Fatal("encrypted actual receipt seal", e)
	}
	// Drop the process-local original; a fresh reader must open authenticated
	// metadata and repeat fixed-version GET/hash/GCM/length/extra-version checks.
	restored = nil
	s.mu.Lock()
	s.roles["writer-access"] = ""
	priorReads := s.fixedReads
	s.mu.Unlock()
	_, _, _, freshReader := newImageS3Fixture(t, "cm-restore-"+strings.Repeat("9", 32), id, raw)
	if _, e := OpenGatewayImageReceipt(ctx, root, metadata, key, c, freshReader, normalized, sqlExpected, b, "cm_drill_image_sdk", "owned-sql-uuid"); e == nil {
		t.Fatal("other TLS location accepted")
	}
	restartedReader := s.freshReader()
	opened, e := OpenGatewayImageReceipt(ctx, root, metadata, key, c, restartedReader, normalized, sqlExpected, b, "cm_drill_image_sdk", "owned-sql-uuid")
	if e != nil || opened == nil || s.fixedReads <= priorReads {
		t.Fatal("persisted actual readback", e)
	}
	if _, e := reader.client.PutObject(ctx, bucket, "unauthorized", bytes.NewReader([]byte("x")), 1, minio.PutObjectOptions{DisableMultipart: true, SendContentMd5: true}); minio.ToErrorResponse(e).Code != "AccessDenied" {
		t.Fatal("real fixture reader write was not denied")
	}
	if _, e := writer.client.PutObject(ctx, bucket, "revoked", bytes.NewReader([]byte("x")), 1, minio.PutObjectOptions{DisableMultipart: true, SendContentMd5: true}); minio.ToErrorResponse(e).Code != "SignatureDoesNotMatch" {
		t.Fatal("actual fixture writer revocation not observed")
	}
	wrong := cloneImageTestSnapshot(t, normalized)
	find(wrong, "users").Rows[0]["username"] = Text("changed-non-image-owner")
	if _, e := OpenGatewayImageReceipt(ctx, root, metadata, key, c, reader, wrong, sqlExpected, b, "cm_drill_image_sdk", "owned-sql-uuid"); e == nil {
		t.Fatal("receipt did not bind complete expected SQL")
	}
	wrongRef := sqlExpected
	wrongRef.SHA256 = strings.Repeat("b", 64)
	if _, e := OpenGatewayImageReceipt(ctx, root, metadata, key, c, reader, normalized, wrongRef, b, "cm_drill_image_sdk", "owned-sql-uuid"); e == nil {
		t.Fatal("receipt did not bind exact SQL evidence reference")
	}
	// Even when the pinned version still matches, an extra target version is
	// unexpected data. Do not silently compare only latest or ignore history.
	s.mu.Lock()
	s.versions[bucket]["gateway-images/"+id]["unexpected-version"] = append([]byte(nil), raw...)
	s.mu.Unlock()
	if _, e := OpenGatewayImageReceipt(ctx, root, metadata, key, c, reader, normalized, sqlExpected, b, "cm_drill_image_sdk", "owned-sql-uuid"); e == nil {
		t.Fatal("extra actual object version accepted")
	}
	t.Log("TLS/SigV4 protocol fixture: source immutable v1 despite newer v2; actual SDK PUT/version/readback; encrypted receipt restart and full SQL/binding/DB/UUID/TLS-location correspondence; read-only write denial and writer revocation; extra version refusal PASS (not native MinIO qualification)")
}

func TestGatewayImageBadMaterialRejectsBeforeAnyTargetPUT(t *testing.T) {
	for _, mode := range []string{"latest", "null-version", "etag-observation", "missing-version", "wrong-hash", "wrong-key-path", "wrong-AAD", "wrong-DEK", "wrong-size", "wrong-SQL-snapshot", "wrong-staging-binding"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			source, raw := imageRestoreFixture()
			id := find(source, "gateway_image_artifacts").Rows[0]["id"].String()
			bucket := "cm-restore-" + strings.Repeat("7", 32)
			s, src, writer, reader := newImageS3Fixture(t, bucket, id, raw)
			root, e := os.OpenRoot(t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			defer root.Close()
			key := bytes.Repeat([]byte{74}, 32)
			a, _, _ := imageObjectBindings()
			ref := GatewayImageObjectRef{ArtifactID: id, Bucket: "owned-image-source", Key: "gateway-images/" + id, Version: "source-version-1", SHA256: imageHash(raw), Size: int64(len(raw))}
			switch mode {
			case "latest":
				ref.Version = ""
			case "null-version":
				ref.Version = "null"
			case "etag-observation":
				ref.Version = "etag:observed"
			case "missing-version":
				ref.Version = "not-present"
			case "wrong-hash":
				ref.SHA256 = strings.Repeat("0", 64)
			case "wrong-key-path":
				ref.Key = "other/" + id
			case "wrong-DEK":
				find(source, "gateway_image_artifacts").Rows[0]["encryption_key"] = Text(strings.Repeat("z", 32))
			case "wrong-size":
				find(source, "gateway_image_artifacts").Rows[0]["byte_size"] = Text("5")
			case "wrong-AAD":
				s.mu.Lock()
				s.versions["owned-image-source"][ref.Key][ref.Version] = imageTestCipher(find(source, "gateway_image_artifacts").Rows[0], []byte("PNG!"), []byte("img_"+strings.Repeat("d", 32)))
				ref.SHA256 = imageHash(s.versions["owned-image-source"][ref.Key][ref.Version])
				s.mu.Unlock()
			}
			captured, e := CaptureGatewayImageObjects(ctx, src, source, []GatewayImageObjectRef{ref}, root, "source.enc", key, a)
			if mode == "wrong-SQL-snapshot" || mode == "wrong-staging-binding" {
				if e != nil {
					t.Fatal("positive capture control", e)
				}
				if mode == "wrong-SQL-snapshot" {
					find(source, "users").Rows[0]["username"] = Text("different-snapshot")
				} else {
					a.Attempt = "2"
				}
				_, e = RestoreGatewayImageObjects(ctx, source, root, captured, key, a, writer, reader, "cm_drill_image_sdk", "owned-sql-uuid", bucket, "2026-11-01T00:00:00Z")
			}
			if e == nil || s.puts != 0 {
				t.Fatal("bad material allowed target write", mode, e)
			}
		})
	}
}
