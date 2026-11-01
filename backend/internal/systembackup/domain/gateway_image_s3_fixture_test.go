package domain

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// An owned TLS/SigV4 protocol fixture, NOT a native MinIO/S3 deployment. The
// real SDK performs all IO; the fixture checks signatures and role permissions,
// stores immutable version bytes, and never supplies a receipt/proof callback.
type imageS3Fixture struct {
	mu                        sync.Mutex
	server                    *httptest.Server
	versions                  map[string]map[string]map[string][]byte
	roles                     map[string]string
	secret                    string
	puts, fixedReads          int
	sourcePuts, sourceDeletes int
	deletedKeys               map[string]bool
	sourceOperator            *GatewayImageObjectClient
	freshReader               func() *GatewayImageObjectClient
}

func imageHM(key []byte, message string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return h.Sum(nil)
}
func (s *imageS3Fixture) signedRole(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
		return ""
	}
	fields := map[string]string{}
	for _, field := range strings.Split(strings.TrimPrefix(auth, "AWS4-HMAC-SHA256 "), ",") {
		kv := strings.SplitN(strings.TrimSpace(field), "=", 2)
		if len(kv) != 2 {
			return ""
		}
		fields[kv[0]] = kv[1]
	}
	scope := strings.Split(fields["Credential"], "/")
	if len(scope) != 5 || scope[2] != "us-east-1" || scope[3] != "s3" || scope[4] != "aws4_request" {
		return ""
	}
	role := s.roles[scope[0]]
	if role == "" {
		return ""
	}
	date := r.Header.Get("X-Amz-Date")
	if len(date) != 16 || date[:8] != scope[1] {
		return ""
	}
	var canonicalHeaders strings.Builder
	for _, name := range strings.Split(fields["SignedHeaders"], ";") {
		value := r.Header.Get(name)
		if name == "host" {
			value = r.Host
		}
		canonicalHeaders.WriteString(name + ":" + strings.Join(strings.Fields(value), " ") + "\n")
	}
	query := strings.ReplaceAll(r.URL.Query().Encode(), "+", "%20")
	canonical := strings.Join([]string{r.Method, r.URL.EscapedPath(), query, canonicalHeaders.String(), fields["SignedHeaders"], r.Header.Get("X-Amz-Content-Sha256")}, "\n")
	stringToSign := "AWS4-HMAC-SHA256\n" + date + "\n" + strings.Join(scope[1:], "/") + "\n" + imageHash([]byte(canonical))
	key := imageHM([]byte("AWS4"+s.secret), scope[1])
	key = imageHM(key, scope[2])
	key = imageHM(key, "s3")
	key = imageHM(key, "aws4_request")
	actual := hex.EncodeToString(imageHM(key, stringToSign))
	if subtle.ConstantTimeCompare([]byte(actual), []byte(fields["Signature"])) != 1 {
		return ""
	}
	return role
}
func (s *imageS3Fixture) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fail := func(status int, code string) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(status)
		fmt.Fprintf(w, "<Error><Code>%s</Code><Message>owned fixture rejection</Message></Error>", code)
	}
	role := s.signedRole(r)
	if role == "" {
		fail(403, "SignatureDoesNotMatch")
		return
	}
	parts := strings.SplitN(strings.Trim(r.URL.Path, "/"), "/", 2)
	bucket := parts[0]
	key := ""
	if len(parts) == 2 {
		key = parts[1]
	}
	objects, exists := s.versions[bucket]
	if !exists {
		fail(404, "NoSuchBucket")
		return
	}
	source := bucket == "owned-image-source"
	if source && role != "source" && role != "source-operator" || !source && (role == "source" || role == "source-operator") || r.Method == "DELETE" && !(source && role == "source-operator") || r.Method == "PUT" && role != "writer" && role != "source-operator" || r.Method != "PUT" && role == "writer" {
		fail(403, "AccessDenied")
		return
	}
	if r.Method == "DELETE" {
		if key == "" || r.URL.Query().Get("versionId") != "" {
			fail(400, "InvalidArgument")
			return
		}
		s.deletedKeys[key] = true
		s.sourceDeletes++
		w.Header().Set("X-Amz-Delete-Marker", "true")
		w.Header().Set("X-Amz-Version-Id", "source-delete-marker")
		w.WriteHeader(204)
		return
	}
	if key == "" {
		if r.Method != "GET" {
			fail(403, "AccessDenied")
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		if r.URL.Query().Has("versioning") {
			io.WriteString(w, `<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>`)
			return
		}
		if !r.URL.Query().Has("versions") {
			fail(400, "InvalidArgument")
			return
		}
		io.WriteString(w, `<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>`+bucket+`</Name><IsTruncated>false</IsTruncated>`)
		var keys []string
		for k := range objects {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if source && s.deletedKeys[k] {
				io.WriteString(w, "<DeleteMarker><Key>")
				xml.EscapeText(w, []byte(k))
				io.WriteString(w, "</Key><VersionId>source-delete-marker</VersionId><IsLatest>true</IsLatest><LastModified>2026-01-01T00:00:00.000Z</LastModified></DeleteMarker>")
			}
			var versions []string
			for v := range objects[k] {
				versions = append(versions, v)
			}
			sort.Strings(versions)
			for _, v := range versions {
				io.WriteString(w, "<Version><Key>")
				xml.EscapeText(w, []byte(k))
				io.WriteString(w, "</Key><VersionId>")
				xml.EscapeText(w, []byte(v))
				fmt.Fprintf(w, "</VersionId><IsLatest>true</IsLatest><LastModified>2026-01-01T00:00:00.000Z</LastModified><Size>%d</Size><ETag>\"owned\"</ETag><StorageClass>STANDARD</StorageClass></Version>", len(objects[k][v]))
			}
		}
		io.WriteString(w, "</ListVersionsResult>")
		return
	}
	if r.Method == "PUT" {
		body, e := io.ReadAll(io.LimitReader(r.Body, 16<<20+65))
		if e != nil || len(body) > 16<<20+64 {
			fail(400, "InvalidRequest")
			return
		}
		md := md5.Sum(body)
		if r.Header.Get("Content-Md5") != base64.StdEncoding.EncodeToString(md[:]) {
			fail(400, "BadDigest")
			return
		}
		if objects[key] == nil {
			objects[key] = map[string][]byte{}
		}
		version := fmt.Sprintf("target-version-%d", s.puts+1)
		if source {
			version = fmt.Sprintf("source-upload-%d", s.sourcePuts+1)
			s.sourcePuts++
		} else {
			s.puts++
		}
		objects[key][version] = body
		w.Header().Set("X-Amz-Version-Id", version)
		w.Header().Set("ETag", "\""+hex.EncodeToString(md[:])+"\"")
		w.WriteHeader(200)
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		fail(405, "MethodNotAllowed")
		return
	}
	version := r.URL.Query().Get("versionId")
	if version == "" {
		fail(400, "InvalidArgument")
		return
	}
	body, ok := objects[key][version]
	if !ok {
		fail(404, "NoSuchVersion")
		return
	}
	s.fixedReads++
	md := md5.Sum(body)
	w.Header().Set("X-Amz-Version-Id", version)
	w.Header().Set("ETag", "\""+hex.EncodeToString(md[:])+"\"")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Last-Modified", "Thu, 01 Jan 2026 00:00:00 GMT")
	w.Header().Set("Content-Type", "application/octet-stream")
	if r.Method == "GET" {
		w.Write(body)
	}
}
func newImageS3Fixture(t *testing.T, bucket, id string, body []byte) (*imageS3Fixture, *GatewayImageObjectClient, *GatewayImageObjectClient, *GatewayImageObjectClient) {
	t.Helper()
	s := &imageS3Fixture{versions: map[string]map[string]map[string][]byte{"owned-image-source": {"gateway-images/" + id: {"source-version-1": append([]byte(nil), body...), "source-version-2": []byte("newer unrelated object bytes")}}, bucket: {}}, roles: map[string]string{"source-access": "source", "source-operator-access": "source-operator", "writer-access": "writer", "reader-access": "reader"}, secret: "owned-fixture-sigv4-secret", deletedKeys: map[string]bool{}}
	s.server = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	if id == "" {
		s.versions["owned-image-source"] = map[string]map[string][]byte{}
	}
	t.Cleanup(s.server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.server.Certificate().Raw})
	client := func(access string) *GatewayImageObjectClient {
		u, _ := url.Parse(s.server.URL)
		c, e := NewGatewayImageObjectClient(s.server.URL, u.Hostname(), "us-east-1", ca, access, s.secret, "")
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(c.Close)
		return c
	}
	s.freshReader = func() *GatewayImageObjectClient { return client("reader-access") }
	s.sourceOperator = client("source-operator-access")
	return s, client("source-access"), client("writer-access"), client("reader-access")
}
