package systembackupevidence

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type s3CredentialFunc func(context.Context, S3Scope) (S3Credential, error)

func (f s3CredentialFunc) Resolve(ctx context.Context, scope S3Scope) (S3Credential, error) {
	return f(ctx, scope)
}

type s3AbsenceFunc func(context.Context, S3AbsenceRequest) (S3AbsenceProof, error)

func (f s3AbsenceFunc) VerifyAbsent(ctx context.Context, r S3AbsenceRequest) (S3AbsenceProof, error) {
	return f(ctx, r)
}

const s3TestAccess = "test-access-key"
const s3TestSecret = "synthetic-secret-key-0123456789"
const s3TestSession = "synthetic-sts-session-0123456789"

// Independent server-side SigV4 verification checks the actual wire request,
// including Go's handling of Content-Length. It does not call the signer under
// test. No synthetic credentials or URLs are logged on failures.
func verifyS3Wire(r *http.Request) bool {
	q := r.URL.Query()
	for _, v := range q {
		if len(v) != 1 {
			return false
		}
	}
	credential := strings.Split(q.Get("X-Amz-Credential"), "/")
	date, e := time.Parse("20060102T150405Z", q.Get("X-Amz-Date"))
	expires, ee := strconv.ParseInt(q.Get("X-Amz-Expires"), 10, 64)
	if e != nil || ee != nil || expires < 1 || expires > 60 || time.Now().After(date.Add(time.Duration(expires)*time.Second)) ||
		len(credential) != 5 || credential[0] != s3TestAccess || credential[1] != date.Format("20060102") || credential[2] != "us-east-1" || credential[3] != "s3" || credential[4] != "aws4_request" ||
		q.Get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256" || q.Get("X-Amz-Security-Token") != s3TestSession {
		return false
	}
	names := q.Get("X-Amz-SignedHeaders")
	required := []string{"host", "x-amz-content-sha256"}
	if r.Method == "PUT" {
		required = append(required, "content-length", "content-type", "if-none-match", "x-amz-checksum-sha256")
	}
	if r.Method == "GET" {
		required = append(required, "range", "x-amz-checksum-mode")
	}
	if r.Method == "HEAD" {
		required = append(required, "x-amz-checksum-mode")
	}
	for _, name := range required {
		if !strings.Contains(";"+names+";", ";"+name+";") {
			return false
		}
	}
	var headers strings.Builder
	for _, name := range strings.Split(names, ";") {
		value := r.Header.Get(name)
		if name == "host" {
			value = r.Host
		}
		headers.WriteString(name + ":" + value + "\n")
	}
	signature := q.Get("X-Amz-Signature")
	q.Del("X-Amz-Signature")
	canonical := strings.Join([]string{r.Method, r.URL.EscapedPath(), strings.ReplaceAll(q.Encode(), "+", "%20"), headers.String(), names, r.Header.Get("X-Amz-Content-Sha256")}, "\n")
	scope := strings.Join(credential[1:], "/")
	input := "AWS4-HMAC-SHA256\n" + date.Format("20060102T150405Z") + "\n" + scope + "\n" + hash([]byte(canonical))
	key := []byte("AWS4" + s3TestSecret)
	for _, part := range credential[1:] {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(part))
		key = mac.Sum(nil)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(input))
	return hmac.Equal([]byte(signature), []byte(hex.EncodeToString(mac.Sum(nil))))
}

type s3TestServer struct {
	mu                   sync.Mutex
	mode                 string
	data                 []byte
	present              bool
	calls, puts, deletes int
	version              string
	owned                [][]byte
	lastScope            S3Scope
}

func (f *s3TestServer) callCount() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }
func (f *s3TestServer) exists() bool   { f.mu.Lock(); defer f.mu.Unlock(); return f.present }

func newS3Fixture(t *testing.T, mode string) (*S3Store, *s3TestServer, Ref) {
	t.Helper()
	f := &s3TestServer{mode: mode, version: "immutable-v1+/=?"}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls++
		if !verifyS3Wire(r) || !strings.HasPrefix(r.URL.Path, "/test-bucket/evidence/installation_test/") {
			t.Error("S3 signature or route did not bind the wire request")
			w.WriteHeader(403)
			return
		}
		if !f.lastScope.Deadline.IsZero() {
			signed, _ := time.Parse("20060102T150405Z", r.URL.Query().Get("X-Amz-Date"))
			expires, _ := strconv.ParseInt(r.URL.Query().Get("X-Amz-Expires"), 10, 64)
			if signed.Add(time.Duration(expires) * time.Second).After(f.lastScope.Deadline) {
				t.Error("signature outlived owner deadline")
				w.WriteHeader(403)
				return
			}
		}
		if f.mode == "redirect" {
			w.Header().Set("Location", "https://invalid.example/credential-sink")
			w.WriteHeader(307)
			return
		}
		if f.mode == "denied" {
			http.Error(w, "PRIVATE provider credentials", 403)
			return
		}
		if f.mode == "not-found" {
			w.WriteHeader(404)
			return
		}
		if f.mode == "encoding" {
			w.Header().Set("Content-Encoding", "gzip")
		}
		version := f.version
		if f.mode == "wrong-version" {
			version = "wrong-version"
		}
		if r.Method == "PUT" {
			f.puts++
			if r.Header.Get("Expect") != "100-continue" {
				t.Error("upload lacks early rejection negotiation")
				w.WriteHeader(400)
				return
			}
			if r.URL.Query().Get("versionId") != "" || r.Header.Get("If-None-Match") != "*" {
				t.Error("unconditional or versioned PUT")
				w.WriteHeader(400)
				return
			}
			if f.present {
				w.WriteHeader(412)
				return
			}
			body, e := io.ReadAll(io.LimitReader(r.Body, 2*ChunkSize))
			checksum, _ := hex.DecodeString(hash(body))
			if e != nil || int64(len(body)) != r.ContentLength || hash(body) != r.Header.Get("X-Amz-Content-Sha256") || base64.StdEncoding.EncodeToString(checksum) != r.Header.Get("X-Amz-Checksum-Sha256") {
				w.WriteHeader(400)
				return
			}
			f.data, f.present = body, true
			if f.mode == "lost-put" {
				w.WriteHeader(500)
				return
			}
		} else {
			if !f.present {
				w.WriteHeader(404)
				return
			}
			if r.Method != "HEAD" && r.URL.Query().Get("versionId") != f.version {
				t.Error("missing exact version")
				w.WriteHeader(400)
				return
			}
			if v := r.URL.Query().Get("versionId"); v != "" && v != f.version {
				w.WriteHeader(404)
				return
			}
		}
		w.Header().Set("X-Amz-Version-Id", version)
		w.Header().Set("X-Amz-Delete-Marker", "false")
		if f.mode == "duplicate-marker" {
			w.Header().Add("X-Amz-Delete-Marker", "false")
		}
		if f.mode == "invalid-marker" {
			w.Header().Set("X-Amz-Delete-Marker", "invalid")
		}
		if f.mode == "duplicate-version" {
			w.Header().Add("X-Amz-Version-Id", version)
		}
		checksum, _ := hex.DecodeString(hash(f.data))
		if f.mode == "wrong-checksum" {
			checksum[0] ^= 1
		}
		w.Header().Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(checksum))
		w.Header().Set("X-Amz-Checksum-Type", "FULL_OBJECT")
		if f.mode == "etag-only" {
			w.Header().Del("X-Amz-Checksum-Sha256")
			w.Header().Set("ETag", hash(f.data))
		}
		if f.mode == "composite" {
			w.Header().Set("X-Amz-Checksum-Type", "COMPOSITE")
		}
		if f.mode == "delete-marker" {
			w.Header().Set("X-Amz-Delete-Marker", "true")
		}
		switch r.Method {
		case "PUT":
			w.WriteHeader(200)
		case "HEAD":
			w.Header().Set("Content-Length", strconv.Itoa(len(f.data)))
			w.WriteHeader(200)
		case "GET":
			var start, end int64
			if _, e := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end); e != nil || start < 0 || end < start || end >= int64(len(f.data)) {
				w.WriteHeader(416)
				return
			}
			w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(f.data)))
			if f.mode == "wrong-range" {
				w.Header().Set("Content-Range", "bytes 0-0/1")
			}
			if f.mode == "full-body" {
				w.WriteHeader(200)
				return
			}
			w.WriteHeader(206)
			if f.mode == "short-body" {
				return
			}
			w.Write(f.data[start : end+1])
		case "DELETE":
			f.deletes++
			f.present = false
			w.WriteHeader(204)
		default:
			t.Error("unexpected S3 method")
			w.WriteHeader(405)
		}
	}))
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	credentials := s3CredentialFunc(func(_ context.Context, scope S3Scope) (S3Credential, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		grant := S3Credential{Scope: scope, AccessKey: []byte(s3TestAccess), SecretKey: []byte(s3TestSecret), SessionToken: []byte(s3TestSession), ExpiresAt: time.Now().Add(time.Minute)}
		if f.mode == "static-grant" {
			wipe(grant.SessionToken)
			grant.SessionToken = nil
		}
		f.owned = append(f.owned, grant.AccessKey, grant.SecretKey, grant.SessionToken)
		f.lastScope = scope
		switch f.mode {
		case "expired-grant":
			grant.ExpiresAt = time.Now().Add(-time.Second)
		case "wrong-grant":
			grant.Scope.Ref.Identity = strings.Repeat("c", 64)
		case "resolver-failure":
			return grant, errors.New("PRIVATE credential resolver")
		}
		return grant, nil
	})
	absence := s3AbsenceFunc(func(_ context.Context, r S3AbsenceRequest) (S3AbsenceProof, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.present || f.mode == "unknown-absence" {
			return S3AbsenceProof{}, ErrUnavailable
		}
		return S3AbsenceProof{Request: r, ObservedAt: time.Now(), ExpiresAt: time.Now().Add(10 * time.Second)}, nil
	})
	config := S3Config{Endpoint: server.URL, Region: "us-east-1", Bucket: "test-bucket", Root: "evidence", Installation: "installation_test", Identity: strings.Repeat("a", 64), Version: "v1", CAPEM: ca, CASHA256: hash(ca)}
	s, e := NewS3Store(config, credentials, absence)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Close)
	return s, f, Ref{Identity: config.Identity, Version: config.Version, RelativeKey: "evidence/installation_test/test.bin"}
}

func TestS3EvidenceLifecycle(t *testing.T) {
	store, f, ref := newS3Fixture(t, "lost-put")
	p, plain, object, keys := fixture(t, int(ChunkSize)+131)
	now := time.Now().UTC()
	registry := &memoryRegistry{now: now}
	s := Service{Registry: registry, Store: store, Keys: keys}
	if e := s.Register(context.Background(), p, "evidence", Ref{Identity: ref.Identity, Version: ref.Version}, now, now.Add(time.Hour), now.Add(2*time.Hour), now.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	if e := s.Publish(context.Background(), p.manifest.Identity.ID, source(object)); e != nil || registry.r.State != "ready" {
		t.Fatal("lost PUT response did not converge", e)
	}
	got, e := OpenRange(context.Background(), registry.r.Manifest, registry.r.Ref, store, keys, ChunkSize-3, ChunkSize+3)
	if e != nil || !bytes.Equal(got, plain[ChunkSize-3:ChunkSize+4]) {
		t.Fatal("HTTP exact range failed", e)
	}
	if e := store.Put(context.Background(), registry.r.Ref, bytes.NewReader(object), ObjectInfo{SHA256: hash(object), Size: int64(len(object))}, now.Add(time.Minute)); e != ErrInvalid {
		t.Fatal("published ref reused for PUT")
	}
	unpublished := registry.r.Ref
	unpublished.ImmutableVersion = ""
	if e := store.Put(context.Background(), unpublished, bytes.NewReader(object), ObjectInfo{SHA256: hash(object), Size: int64(len(object))}, now.Add(time.Minute)); e != ErrConflict {
		t.Fatal("conditional conflict not preserved", e)
	}
	registry.now = now.Add(3 * time.Hour)
	f.mu.Lock()
	f.mode = "unknown-absence"
	f.mu.Unlock()
	if e := s.GC(context.Background(), []string{p.manifest.Identity.ID})[0]; e == nil || registry.r.State != "delete_failed" || registry.r.Ref.ImmutableVersion == "" {
		t.Fatal("DELETE ack substituted for absence proof")
	}
	f.mu.Lock()
	f.mode = "valid"
	f.mu.Unlock()
	if e := s.GC(context.Background(), []string{p.manifest.Identity.ID})[0]; e != nil || registry.r.State != "deleted" {
		t.Fatal("verified absence did not converge", e)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deletes != 1 || f.puts != 2 {
		t.Fatal("unexpected operation replay")
	}
	for _, secret := range f.owned {
		if !bytes.Equal(secret, make([]byte, len(secret))) {
			t.Fatal("owned credential was retained")
		}
	}
}

func TestS3EvidenceResponseRejection(t *testing.T) {
	for _, mode := range []string{"wrong-version", "duplicate-version", "etag-only", "composite", "delete-marker", "duplicate-marker", "invalid-marker", "redirect", "denied", "not-found", "encoding"} {
		t.Run("stat-"+mode, func(t *testing.T) {
			s, f, ref := newS3Fixture(t, mode)
			f.mu.Lock()
			f.present = true
			f.data = bytes.Repeat([]byte{1}, 9000)
			ref.ImmutableVersion = f.version
			f.mu.Unlock()
			if _, e := s.Stat(context.Background(), ref); e == nil {
				t.Fatal("invalid Stat accepted")
			}
			if f.callCount() != 1 {
				t.Fatal("request replayed")
			}
		})
	}
	for _, mode := range []string{"wrong-version", "duplicate-version", "wrong-range", "full-body", "short-body", "encoding"} {
		t.Run("range-"+mode, func(t *testing.T) {
			s, f, ref := newS3Fixture(t, mode)
			f.mu.Lock()
			f.present = true
			f.data = bytes.Repeat([]byte{1}, 9000)
			ref.ImmutableVersion = f.version
			f.mu.Unlock()
			if body, e := s.Range(context.Background(), ref, 7, 31); e == nil || body != nil {
				t.Fatal("unverified response body exposed")
			}
		})
	}
	for _, mode := range []string{"wrong-checksum", "duplicate-version", "etag-only", "composite", "redirect"} {
		t.Run("put-"+mode, func(t *testing.T) {
			s, f, ref := newS3Fixture(t, mode)
			b := bytes.Repeat([]byte{1}, 9000)
			if e := s.Put(context.Background(), ref, bytes.NewReader(b), ObjectInfo{SHA256: hash(b), Size: int64(len(b))}, time.Now().Add(10*time.Second)); e == nil {
				t.Fatal("bad PUT acknowledgement accepted")
			}
			if f.callCount() != 1 {
				t.Fatal("PUT replayed")
			}
		})
	}
}

func TestS3EvidenceScopeAndBodyBinding(t *testing.T) {
	for _, mode := range []string{"expired-grant", "wrong-grant", "resolver-failure", "static-grant"} {
		t.Run(mode, func(t *testing.T) {
			s, f, ref := newS3Fixture(t, mode)
			if _, e := s.Stat(context.Background(), ref); e != ErrDenied || f.callCount() != 0 {
				t.Fatal("invalid grant reached provider", e)
			}
			for _, secret := range f.owned {
				if !bytes.Equal(secret, make([]byte, len(secret))) {
					t.Fatal("credential retained")
				}
			}
		})
	}
	s, f, ref := newS3Fixture(t, "valid")
	for _, key := range []string{"evidence/installation_other/test", "evidence/installation_test/../test", "evidence/installation_test2/test"} {
		bad := ref
		bad.RelativeKey = key
		if _, e := s.Stat(context.Background(), bad); e != ErrInvalid {
			t.Fatal("foreign prefix accepted")
		}
	}
	if _, e := s.Range(context.Background(), ref, 0, 1); e != ErrInvalid {
		t.Fatal("unversioned read accepted")
	}
	if e := s.Delete(context.Background(), ref, ObjectInfo{}); e != ErrInvalid {
		t.Fatal("unversioned delete accepted")
	}
	if f.callCount() != 0 {
		t.Fatal("invalid scope reached provider")
	}
	b := bytes.Repeat([]byte{1}, 9000)
	info := ObjectInfo{SHA256: hash(b), Size: int64(len(b))}
	badBody := append([]byte(nil), b...)
	badBody[0] ^= 1
	if e := s.Put(context.Background(), ref, bytes.NewReader(badBody), info, time.Now().Add(10*time.Second)); e == nil || f.exists() {
		t.Fatal("server accepted body not matching signed digest")
	}
	if e := s.Put(context.Background(), ref, bytes.NewReader(b[:8999]), info, time.Now().Add(10*time.Second)); e == nil || f.exists() {
		t.Fatal("server accepted wrong content length")
	}
	if e := s.Put(context.Background(), ref, bytes.NewReader(b), info, time.Now().Add(-time.Second)); e != ErrInvalid {
		t.Fatal("expired owner deadline accepted")
	}
}

func TestS3EvidenceAbsenceProofBinding(t *testing.T) {
	s, _, ref := newS3Fixture(t, "valid")
	for _, mode := range []string{"wrong-key", "wrong-version", "wrong-challenge", "stale", "future", "expired", "long-lived", "verifier-error"} {
		t.Run(mode, func(t *testing.T) {
			s.absence = s3AbsenceFunc(func(_ context.Context, request S3AbsenceRequest) (S3AbsenceProof, error) {
				p := S3AbsenceProof{Request: request, ObservedAt: time.Now(), ExpiresAt: time.Now().Add(time.Second)}
				switch mode {
				case "wrong-key":
					p.Request.Ref.RelativeKey += ".other"
				case "wrong-version":
					p.Request.Ref.ImmutableVersion = "other"
				case "wrong-challenge":
					p.Request.Challenge = strings.Repeat("0", 64)
				case "stale":
					p.ObservedAt = time.Now().Add(-time.Minute)
				case "future":
					p.ObservedAt = time.Now().Add(time.Second)
				case "expired":
					p.ExpiresAt = time.Now().Add(-time.Second)
				case "long-lived":
					p.ExpiresAt = time.Now().Add(time.Hour)
				case "verifier-error":
					return p, errors.New("PRIVATE issuer response")
				}
				return p, nil
			})
			if proof, e := s.Absent(context.Background(), ref); e == nil || proof.Authoritative {
				t.Fatal("unbound absence proof accepted")
			}
		})
	}
}

func TestS3EvidenceDeleteAndRangeLimits(t *testing.T) {
	s, f, ref := newS3Fixture(t, "valid")
	f.mu.Lock()
	f.present = true
	f.data = bytes.Repeat([]byte{7}, 9000)
	ref.ImmutableVersion = f.version
	f.mu.Unlock()
	wrong := ObjectInfo{Version: ref.ImmutableVersion, Size: 9000, SHA256: strings.Repeat("0", 64)}
	if e := s.Delete(context.Background(), ref, wrong); e != ErrIntegrity {
		t.Fatal("mismatched object authorized for deletion", e)
	}
	for _, bounds := range [][2]int64{{-1, 1}, {0, 0}, {0, ChunkSize + 29}, {1 << 62, 1}} {
		if body, e := s.Range(context.Background(), ref, bounds[0], bounds[1]); e != ErrRange || body != nil {
			t.Fatal("invalid range accepted")
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deletes != 0 || f.calls != 1 {
		t.Fatal("invalid delete/range reached provider")
	}
}

func TestS3EvidenceTLSAndConfiguration(t *testing.T) {
	s, f, ref := newS3Fixture(t, "valid")
	s.client.Transport.(*http.Transport).TLSClientConfig.ServerName = "wrong-host.invalid"
	if _, e := s.Stat(context.Background(), ref); e == nil || f.callCount() != 0 {
		t.Fatal("TLS hostname validation bypassed")
	}
	s.Close()
	s.client.Transport.(*http.Transport).TLSClientConfig.ServerName = ""
	s.client.Transport.(*http.Transport).TLSClientConfig.RootCAs = nil
	if _, e := s.Stat(context.Background(), ref); e == nil || f.callCount() != 0 {
		t.Fatal("TLS CA validation bypassed")
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	base := s.config
	base.Endpoint = server.URL
	base.CAPEM = ca
	base.CASHA256 = hash(ca)
	valid, e := NewS3Store(base, s.credentials, s.absence)
	if e != nil {
		t.Fatal(e)
	}
	valid.Close()
	for _, mutate := range []func(*S3Config){
		func(c *S3Config) { c.Endpoint = "http://example.com" },
		func(c *S3Config) { c.Endpoint = "https://user:secret@example.com" },
		func(c *S3Config) { c.Endpoint += "/path" },
		func(c *S3Config) { c.Endpoint += "?" },
		func(c *S3Config) { c.Root = "../escape" },
		func(c *S3Config) { c.Bucket = "bucket/key" },
		func(c *S3Config) { c.CASHA256 = strings.Repeat("0", 64) },
	} {
		bad := base
		mutate(&bad)
		if _, e := NewS3Store(bad, s.credentials, s.absence); e != ErrInvalid {
			t.Fatal("invalid configuration accepted")
		}
	}
	if _, e := NewS3Store(base, nil, s.absence); e != ErrInvalid {
		t.Fatal("missing live credentials accepted")
	}
	if _, e := NewS3Store(base, s.credentials, nil); e != ErrInvalid {
		t.Fatal("missing absence verifier accepted")
	}
}
