package domain

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"testing"

	"clawreef/internal/systembackup/staging"
	"github.com/minio/minio-go/v7"
)

func imageTestPolicy(s Snapshot) Policy {
	_, _, p := gatewayRestoreFixture()
	for _, table := range s.Tables {
		if isGatewayImageTable(table.Name) {
			a := TableAdapter{SchemaSHA256: SchemaDigest(table), Normalizer: GatewayImage074Normalizer, InterruptedAt: "2026-11-01T00:00:00Z", Columns: map[string]string{}}
			for _, c := range table.Columns {
				a.Columns[c.Name] = "preserve"
			}
			p.Dependencies[table.Name] = a
		}
	}
	return p
}

// This file only exports real test drivers/fixtures to package domain_test.
// None of these symbols is present in a production binary or mints authority.
func NewTestGatewayImageSQLFixture(mode string) *TestSQLFixture {
	s, _ := imageRestoreFixture()
	if mode == "empty-orphan-hold" || mode == "empty-no-hold" {
		for n := range s.Tables {
			if isGatewayImageTable(s.Tables[n].Name) {
				s.Tables[n].Rows = nil
			}
		}
	}
	if mode == "job-only-emptyobjects" {
		imageFixtureTable(&s, "gateway_image_artifacts").Rows = nil
		job := find(s, "gateway_image_jobs").Rows[0]
		job["gateway_key_id"], job["reservation_id"] = Cell{Null: true}, Cell{Null: true}
		find(s, "gateway_key_budget_reservations").Rows[0]["settlement_status"] = Text("reserved")
	}
	if mode == "empty-no-hold" {
		find(s, "gateway_key_budget_reservations").Rows[0]["settlement_status"] = Text("reserved")
	}
	source := &memoryDB{tables: copyTables(s.Tables), name: "source", uuid: "fixture-server", grants: "GRANT SELECT ON `source`.* TO 'capture'@'localhost'"}
	target := isolatedTarget(s.Tables)
	// Named SQL-driver JSON renderer, not a MySQL observation. Only this
	// fixture's gateway string-array column is supported; native tests use SQL.
	target.castJSON = func(ctx context.Context, raw string) (string, error) {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		var groups []string
		if strictJSON([]byte(raw)) != nil || json.Unmarshal([]byte(raw), &groups) != nil || groups == nil {
			return "", ErrData
		}
		encoded, e := json.Marshal(groups)
		return string(encoded), e
	}
	return &TestSQLFixture{Source: database(source), Target: database(target), Policy: imageTestPolicy(s), source: source, target: target}
}
func GatewayImageNativeSeedForTest() (Snapshot, Policy, []byte) {
	s, raw := imageRestoreFixture()
	return s, imageTestPolicy(s), raw
}

type GatewayImageProtocolFixture struct {
	Source, Writer, Reader *GatewayImageObjectClient
	Ref                    GatewayImageObjectRef
	FreshReader            func() *GatewayImageObjectClient
	ReaderSettings         GatewayImageReaderTestSettings
	Puts                   func() int
	RevokeWriter           func() error
	SourceStorage          *imageTestObjectStorage
	SourceOperatorStorage  *imageTestObjectStorage
	SourceDeletes          func() int
}
type GatewayImageReaderTestSettings struct {
	Endpoint, TLSServerName, Region string
	CA                              []byte
	Access, Secret                  string
}

func GatewayImageProtocolForTest(t *testing.T, bucket, id string, raw []byte) GatewayImageProtocolFixture {
	t.Helper()
	s, src, writer, reader := newImageS3Fixture(t, bucket, id, raw)
	return GatewayImageProtocolFixture{Source: src, Writer: writer, Reader: reader, Ref: GatewayImageObjectRef{ArtifactID: id, Bucket: "owned-image-source", Key: "gateway-images/" + id, Version: "source-version-1", SHA256: imageHash(raw), Size: int64(len(raw))}, ReaderSettings: GatewayImageReaderTestSettings{Endpoint: reader.realm.Endpoint, TLSServerName: reader.realm.TLSServerName, Region: reader.realm.Region, CA: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.server.Certificate().Raw}), Access: "reader-access", Secret: s.secret}, SourceStorage: &imageTestObjectStorage{client: src, bucket: "owned-image-source", versions: map[string]string{"gateway-images/" + id: "source-version-1"}}, SourceOperatorStorage: &imageTestObjectStorage{client: s.sourceOperator, bucket: "owned-image-source", versions: map[string]string{}}, SourceDeletes: func() int { s.mu.Lock(); defer s.mu.Unlock(); return s.sourceDeletes }, Puts: func() int { s.mu.Lock(); defer s.mu.Unlock(); return s.puts }, RevokeWriter: func() error {
		s.mu.Lock()
		s.roles["writer-access"] = ""
		s.mu.Unlock()
		_, e := writer.client.PutObject(context.Background(), bucket, "revoked-writer-probe", bytes.NewReader([]byte("x")), 1, minio.PutObjectOptions{DisableMultipart: true, SendContentMd5: true})
		if minio.ToErrorResponse(e).Code != "SignatureDoesNotMatch" {
			return ErrIsolation
		}
		return nil
	}, FreshReader: func() *GatewayImageObjectClient {
		return s.freshReader()
	}}
}

type imageTestObjectStorage struct {
	client   *GatewayImageObjectClient
	bucket   string
	versions map[string]string
}

func (s *imageTestObjectStorage) PutObject(ctx context.Context, key string, body []byte, contentType string) error {
	info, e := s.client.client.PutObject(ctx, s.bucket, key, bytes.NewReader(body), int64(len(body)), minio.PutObjectOptions{ContentType: contentType, DisableMultipart: true, SendContentMd5: true})
	if e == nil {
		s.versions[key] = info.VersionID
	}
	return e
}
func (s *imageTestObjectStorage) GetObject(ctx context.Context, key string) ([]byte, error) {
	return s.GetObjectLimited(ctx, key, 16<<20+64)
}
func (s *imageTestObjectStorage) GetObjectLimited(ctx context.Context, key string, max int64) ([]byte, error) {
	version := s.versions[key]
	if version == "" {
		return nil, ErrData
	}
	object, e := s.client.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{VersionID: version})
	if e != nil {
		return nil, e
	}
	defer object.Close()
	raw, e := io.ReadAll(io.LimitReader(object, max+1))
	if e != nil || int64(len(raw)) > max {
		return nil, ErrData
	}
	return raw, nil
}
func (s *imageTestObjectStorage) DeleteObject(ctx context.Context, key string) error {
	return s.client.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{})
}
func GatewayImageTargetStorageForTest(r *GatewayImageReceipt) *imageTestObjectStorage {
	versions := map[string]string{}
	for _, o := range r.data.Objects {
		versions[o.Source.Key] = o.TargetVersion
	}
	return &imageTestObjectStorage{client: r.reader, bucket: r.data.Bucket, versions: versions}
}
func GatewayImageCipherForTest(s Snapshot, plain []byte, aad string) []byte {
	row := find(s, "gateway_image_artifacts").Rows[0]
	return imageTestCipher(row, plain, []byte(aad))
}

// Deliberately mutate only the SQL reference, preserving the complete expected
// SQL digest. Public verify must reject a changed non-image SQL entity even
// after terminal AEAD/receipt/binding checks pass for both actual files.
func ForgeGatewayImageSQLReferenceForTest(ctx context.Context, root *os.Root, original staging.Receipt, key []byte, binding staging.Binding, replacement staging.Receipt, name string) (staging.Receipt, error) {
	var data imageReceiptData
	if e := openImageMaterial(ctx, root, original, key, binding, &data); e != nil {
		return staging.Receipt{}, e
	}
	data.ExpectedSQLReceipt = replacement
	return staging.SealFile(ctx, root, name, key, binding, func(w io.Writer) error { return json.NewEncoder(w).Encode(data) })
}
