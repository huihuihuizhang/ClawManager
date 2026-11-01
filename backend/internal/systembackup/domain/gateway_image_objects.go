package domain

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"clawreef/internal/systembackup/staging"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

const imageObjectBudget = 32 << 20

var imageArtifactID = regexp.MustCompile(`^img_[a-f0-9]{32}$`)
var imageTargetBucket = regexp.MustCompile(`^cm-restore-[a-f0-9]{32}$`)

// GatewayImageObjectRef is an inventory input, never evidence by itself. Every
// source GET must name a real immutable version and match size/hash and SQL AEAD.
type GatewayImageObjectRef struct {
	ArtifactID, Bucket, Key, Version, SHA256 string
	Size                                     int64
}
type capturedImageObject struct {
	Ref        GatewayImageObjectRef
	Ciphertext []byte
}
type capturedImageObjects struct {
	Version, SourceSQLSHA256 string
	SourceRealm              imageObjectRealm
	Objects                  []capturedImageObject
}
type restoredImageObject struct {
	Source                         GatewayImageObjectRef
	TargetVersion, PlaintextSHA256 string
}
type imageReceiptData struct {
	Version, SourceSQLSHA256, ImageSQLSHA256    string
	Database, ServerUUID, Bucket, InterruptedAt string
	TargetRealm                                 imageObjectRealm
	SourceRealm                                 imageObjectRealm
	SourceImageBinding                          staging.Binding
	ExpectedSQLSHA256                           string
	ExpectedSQLReceipt                          staging.Receipt
	ExpectedSQLBinding                          staging.Binding
	Objects                                     []restoredImageObject
}

// GatewayImageReceipt has no public fields or DTO constructor. It is minted
// only after real fixed-version object readback. It proves data correspondence,
// not fullC authentication, account permissions or physical target isolation.
type GatewayImageReceipt struct {
	data   imageReceiptData
	reader *GatewayImageObjectClient
}

type imageObjectRealm struct{ Endpoint, TLSServerName, RootCASHA256, Region string }

// GatewayImageObjectClient freezes the TLS location and CA of actual SDK IO.
// A TLS location is not proof of physical realm UID or read-only IAM policy.
type GatewayImageObjectClient struct {
	client    *minio.Client
	realm     imageObjectRealm
	transport *http.Transport
}

func NewGatewayImageObjectClient(endpoint, tlsName, region string, ca []byte, access, secret, session string) (*GatewayImageObjectClient, error) {
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || tlsName == "" || region == "" || len(ca) == 0 || len(ca) > 64<<10 || access == "" || secret == "" {
		return nil, ErrIsolation
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, ErrIsolation
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: tlsName, MinVersion: tls.VersionTLS12}, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
	client, e := minio.New(u.Host, &minio.Options{Secure: true, Region: region, Transport: transport, Creds: credentials.NewStaticV4(access, secret, session), BucketLookup: minio.BucketLookupPath})
	if e != nil {
		transport.CloseIdleConnections()
		return nil, ErrIsolation
	}
	return &GatewayImageObjectClient{client: client, transport: transport, realm: imageObjectRealm{Endpoint: endpoint, TLSServerName: tlsName, RootCASHA256: imageHash(ca), Region: region}}, nil
}
func (c *GatewayImageObjectClient) Close() {
	if c != nil && c.transport != nil {
		c.transport.CloseIdleConnections()
	}
}
func imageTLSClient(c *GatewayImageObjectClient) bool {
	return c != nil && c.client != nil && c.client.EndpointURL().Scheme == "https"
}
func imageVersion(s string) bool {
	return s != "" && s != "null" && !strings.HasPrefix(s, "etag:") && len(s) <= 1024 && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\x00\r\n")
}
func imageHash(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func imageValidHash(s string) bool {
	raw, e := hex.DecodeString(s)
	return e == nil && len(raw) == 32 && strings.ToLower(s) == s
}
func imageArtifactRows(s Snapshot) map[string]Row {
	out := map[string]Row{}
	for _, table := range s.Tables {
		if table.Name == "gateway_image_artifacts" {
			for _, row := range table.Rows {
				out[row["id"].String()] = row
			}
		}
	}
	return out
}
func imagePlaintext(row Row, raw []byte) ([]byte, error) {
	if !imageArtifactID.Match(row["id"].Bytes) || row["encryption_key"].Null || len(row["encryption_key"].Bytes) != 32 {
		return nil, ErrData
	}
	block, e := aes.NewCipher(row["encryption_key"].Bytes)
	if e != nil {
		return nil, ErrData
	}
	gcm, e := cipher.NewGCM(block)
	if e != nil || len(raw) < gcm.NonceSize()+gcm.Overhead() {
		return nil, ErrData
	}
	plain, e := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], row["id"].Bytes)
	if e != nil {
		return nil, ErrData
	}
	if gatewayNumber(row["byte_size"], 16<<20, false) != nil || Text(stringInt(int64(len(plain)))).String() != row["byte_size"].String() {
		clear(plain)
		return nil, ErrData
	}
	return plain, nil
}
func readImageVersion(ctx context.Context, c *GatewayImageObjectClient, bucket, key, version, hash string, size int64) ([]byte, error) {
	if !imageTLSClient(c) || bucket == "" || !imageVersion(version) || !imageValidHash(hash) || size <= 0 || size > 16<<20+64 {
		return nil, ErrData
	}
	obj, e := c.client.GetObject(ctx, bucket, key, minio.GetObjectOptions{VersionID: version})
	if e != nil {
		return nil, ErrData
	}
	defer obj.Close()
	info, e := obj.Stat()
	if e != nil || info.VersionID != version || info.Size != size || info.IsDeleteMarker {
		return nil, ErrData
	}
	raw, e := io.ReadAll(io.LimitReader(obj, size+1))
	if e != nil || int64(len(raw)) != size || imageHash(raw) != hash {
		clear(raw)
		return nil, ErrData
	}
	return raw, nil
}

// CaptureGatewayImageObjects seals a bounded local data-plane artifact using
// existing staging AEAD. This is explicitly not the published fullC format.
func CaptureGatewayImageObjects(ctx context.Context, c *GatewayImageObjectClient, source Snapshot, refs []GatewayImageObjectRef, root *os.Root, name string, key []byte, binding staging.Binding) (staging.Receipt, error) {
	if validateSnapshot(source) != nil || validateImageRows(ctx, source, false) != nil || validateGatewayBudgetData(ctx, source, false) != nil || len(refs) > 64 || len(refs) != len(imageArtifactRows(source)) {
		return staging.Receipt{}, ErrData
	}
	if !imageTLSClient(c) {
		return staging.Receipt{}, ErrIsolation
	}
	data := capturedImageObjects{Version: "gateway-image-objects.074.v1", SourceRealm: c.realm}
	data.SourceSQLSHA256, _ = Digest(source)
	rows := imageArtifactRows(source)
	seen := map[string]bool{}
	total := int64(0)
	defer func() {
		for _, o := range data.Objects {
			clear(o.Ciphertext)
		}
	}()
	for _, ref := range refs {
		row, ok := rows[ref.ArtifactID]
		if !ok || seen[ref.ArtifactID] || ref.Key != "gateway-images/"+ref.ArtifactID {
			return staging.Receipt{}, ErrData
		}
		seen[ref.ArtifactID] = true
		total += ref.Size
		if total > imageObjectBudget {
			return staging.Receipt{}, ErrCapacity
		}
		raw, e := readImageVersion(ctx, c, ref.Bucket, ref.Key, ref.Version, ref.SHA256, ref.Size)
		if e != nil {
			return staging.Receipt{}, e
		}
		plain, e := imagePlaintext(row, raw)
		clear(plain)
		if e != nil {
			clear(raw)
			return staging.Receipt{}, e
		}
		data.Objects = append(data.Objects, capturedImageObject{ref, raw})
	}
	return staging.SealFile(ctx, root, name, key, binding, func(w io.Writer) error { return json.NewEncoder(w).Encode(data) })
}

func openImageMaterial(ctx context.Context, root *os.Root, receipt staging.Receipt, key []byte, binding staging.Binding, out any) error {
	clearImageMaterial(out)
	file, e := staging.OpenFile(ctx, root, receipt)
	if e != nil {
		return ErrData
	}
	defer file.Close()
	var plain bytes.Buffer
	if staging.Open(ctx, file, &plain, key, binding, 48<<20) != nil {
		clear(plain.Bytes())
		return ErrData
	}
	defer clear(plain.Bytes())
	return decodeImageMaterial(ctx, plain.Bytes(), out)
}

// RestoreGatewayImageObjects authenticates the complete local artifact and all
// SQL/object relationships before the first PUT. Target must be preprovisioned,
// versioned and empty. Failures leave owned residues for controller custody;
// this function never deletes a bucket/object or infers writer revocation.
func RestoreGatewayImageObjects(ctx context.Context, source Snapshot, root *os.Root, receipt staging.Receipt, key []byte, binding staging.Binding, writer, reader *GatewayImageObjectClient, database, uuid, bucket, frozen string) (*GatewayImageReceipt, error) {
	if !imageTLSClient(writer) || !imageTLSClient(reader) || writer == reader || writer.realm != reader.realm || !imageTargetBucket.MatchString(bucket) || !identifier.MatchString(database) || !strings.HasPrefix(database, "cm_drill_") || uuid == "" {
		return nil, ErrIsolation
	}
	if validateSnapshot(source) != nil || validateImageRows(ctx, source, false) != nil || validateGatewayBudgetData(ctx, source, false) != nil {
		return nil, ErrData
	}
	var data capturedImageObjects
	if openImageMaterial(ctx, root, receipt, key, binding, &data) != nil {
		return nil, ErrData
	}
	defer func() {
		for _, o := range data.Objects {
			clear(o.Ciphertext)
		}
	}()
	digest, _ := Digest(source)
	rows := imageArtifactRows(source)
	if data.Version != "gateway-image-objects.074.v1" || data.SourceSQLSHA256 != digest || len(data.Objects) != len(rows) || len(data.Objects) > 64 {
		return nil, ErrData
	}
	result := &GatewayImageReceipt{data: imageReceiptData{Version: "gateway-image-readback.074.v1", SourceSQLSHA256: digest, Database: database, ServerUUID: uuid, Bucket: bucket, InterruptedAt: frozen, TargetRealm: reader.realm, SourceRealm: data.SourceRealm, SourceImageBinding: binding}, reader: reader}
	seen := map[string]bool{}
	total := int64(0)
	for _, o := range data.Objects {
		row, ok := rows[o.Ref.ArtifactID]
		total += int64(len(o.Ciphertext))
		if !ok || seen[o.Ref.ArtifactID] || o.Ref.Bucket == bucket || o.Ref.Key != "gateway-images/"+o.Ref.ArtifactID || !imageVersion(o.Ref.Version) || int64(len(o.Ciphertext)) != o.Ref.Size || imageHash(o.Ciphertext) != o.Ref.SHA256 || total > imageObjectBudget {
			return nil, ErrData
		}
		seen[o.Ref.ArtifactID] = true
		plain, e := imagePlaintext(row, o.Ciphertext)
		if e != nil {
			return nil, e
		}
		hash := imageHash(plain)
		clear(plain)
		result.data.Objects = append(result.data.Objects, restoredImageObject{Source: o.Ref, PlaintextSHA256: hash})
	}
	projected, e := imageProjection(source, frozen)
	if e != nil {
		return nil, e
	}
	result.data.ImageSQLSHA256 = projected
	versioning, e := reader.client.GetBucketVersioning(ctx, bucket)
	if e != nil || versioning.Status != "Enabled" {
		return nil, ErrIsolation
	}
	for o := range reader.client.ListObjects(ctx, bucket, minio.ListObjectsOptions{Recursive: true, WithVersions: true}) {
		if o.Err != nil {
			return nil, ErrIsolation
		}
		return nil, ErrNotEmpty
	}
	for n, o := range data.Objects {
		info, e := writer.client.PutObject(ctx, bucket, o.Ref.Key, bytes.NewReader(o.Ciphertext), o.Ref.Size, minio.PutObjectOptions{ContentType: "application/octet-stream", DisableMultipart: true, SendContentMd5: true})
		if e != nil || !imageVersion(info.VersionID) || info.Size != o.Ref.Size {
			return nil, ErrData
		}
		result.data.Objects[n].TargetVersion = info.VersionID
	}
	if result.verify(ctx, source, false, database, uuid) != nil {
		return nil, ErrData
	}
	return result, nil
}

func (r *GatewayImageReceipt) verify(ctx context.Context, s Snapshot, normalized bool, database, uuid string) error {
	if r == nil || !imageTLSClient(r.reader) || r.reader.realm != r.data.TargetRealm || r.data.Version != "gateway-image-readback.074.v1" || r.data.Database != database || r.data.ServerUUID != uuid || !imageTargetBucket.MatchString(r.data.Bucket) || len(r.data.Objects) > 64 {
		return ErrIsolation
	}
	if !normalized {
		digest, _ := Digest(s)
		if digest != r.data.SourceSQLSHA256 {
			return ErrData
		}
	}
	projected, e := imageProjection(s, r.data.InterruptedAt)
	if e != nil || projected != r.data.ImageSQLSHA256 {
		return ErrData
	}
	rows := imageArtifactRows(s)
	if len(rows) != len(r.data.Objects) {
		return ErrData
	}
	expected := map[string]bool{}
	versioning, e := r.reader.client.GetBucketVersioning(ctx, r.data.Bucket)
	if e != nil || versioning.Status != "Enabled" {
		return ErrIsolation
	}
	for _, o := range r.data.Objects {
		row, ok := rows[o.Source.ArtifactID]
		if !ok || !imageVersion(o.Source.Version) || o.Source.Bucket == "" || o.Source.Bucket == r.data.Bucket || o.Source.Key != "gateway-images/"+o.Source.ArtifactID || expected[o.Source.Key+"\x00"+o.TargetVersion] {
			return ErrData
		}
		raw, e := readImageVersion(ctx, r.reader, r.data.Bucket, o.Source.Key, o.TargetVersion, o.Source.SHA256, o.Source.Size)
		if e != nil {
			return e
		}
		plain, e := imagePlaintext(row, raw)
		clear(raw)
		if e != nil {
			return e
		}
		hash := imageHash(plain)
		clear(plain)
		if hash != o.PlaintextSHA256 {
			return ErrData
		}
		expected[o.Source.Key+"\x00"+o.TargetVersion] = true
	}
	for item := range r.reader.client.ListObjects(ctx, r.data.Bucket, minio.ListObjectsOptions{Recursive: true, WithVersions: true}) {
		id := item.Key + "\x00" + item.VersionID
		if item.Err != nil || item.IsDeleteMarker || !expected[id] {
			return ErrData
		}
		delete(expected, id)
	}
	if len(expected) != 0 {
		return ErrData
	}
	return ctx.Err()
}

// SealGatewayImageReceipt preserves actual target versions in encrypted local
// evidence. Opening it always repeats real object readback; JSON cannot mint r.
// The controlled worker supplies normalized and sqlExpected from its actual
// completed SQL evidence seal; these helper arguments alone are not SQL proof.
func SealGatewayImageReceipt(ctx context.Context, r *GatewayImageReceipt, normalized Snapshot, sqlExpected staging.Receipt, sqlBinding staging.Binding, root *os.Root, name string, key []byte, binding staging.Binding) (staging.Receipt, error) {
	if r == nil || r.reader == nil {
		return staging.Receipt{}, ErrData
	}
	if sqlExpected.Name == "" || sqlExpected.Size <= 0 || !imageValidHash(sqlExpected.SHA256) || sqlBinding == binding || r.verify(ctx, normalized, true, r.data.Database, r.data.ServerUUID) != nil {
		return staging.Receipt{}, ErrData
	}
	data := r.data
	data.ExpectedSQLSHA256, _ = Digest(normalized)
	data.ExpectedSQLReceipt = sqlExpected
	data.ExpectedSQLBinding = sqlBinding
	return staging.SealFile(ctx, root, name, key, binding, func(w io.Writer) error { return json.NewEncoder(w).Encode(data) })
}

// OpenGatewayImageReceipt requires normalized to be the actual SQL entity just
// authenticated through sqlExpected/sqlBinding by RunDatabase. Independent
// metadata/DTO callers do not thereby obtain SQL verification or authority.
func OpenGatewayImageReceipt(ctx context.Context, root *os.Root, receipt staging.Receipt, key []byte, binding staging.Binding, reader *GatewayImageObjectClient, normalized Snapshot, sqlExpected staging.Receipt, sqlBinding staging.Binding, database, uuid string) (*GatewayImageReceipt, error) {
	r := &GatewayImageReceipt{reader: reader}
	if openImageMaterial(ctx, root, receipt, key, binding, &r.data) != nil || r.data.ExpectedSQLReceipt != sqlExpected || r.data.ExpectedSQLBinding != sqlBinding {
		return nil, ErrData
	}
	digest, _ := Digest(normalized)
	if digest != r.data.ExpectedSQLSHA256 || r.verify(ctx, normalized, true, database, uuid) != nil {
		return nil, ErrData
	}
	return r, nil
}
