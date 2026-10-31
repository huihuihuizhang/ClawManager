package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type aNativePublicationServer struct {
	mu                    sync.Mutex
	objects               map[string][]byte
	puts, gets, heads     int
	lostACK, wrongVersion bool
	getUnavailable        bool
	delay                 time.Duration
	deadline              time.Time
	read, write           nativePublicationCredential
	onGet                 func()
}

func aHMAC(key []byte, message string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return h.Sum(nil)
}

// Independent S3-compatible verifier for actual native PUTs: changed method,
// path, body, condition, length, checksum, expiry or signed headers reject.
func aValidPublicationSignature(r *http.Request, key nativePublicationCredential, deadline time.Time) bool {
	q := r.URL.Query()
	credential := strings.Split(q.Get("X-Amz-Credential"), "/")
	if len(credential) != 5 || credential[0] != key.AccessKey || credential[2] != "local-1" || credential[3] != "s3" || credential[4] != "aws4_request" || q.Get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256" {
		return false
	}
	signed := q.Get("X-Amz-SignedHeaders")
	var headers strings.Builder
	for _, name := range strings.Split(signed, ";") {
		value := r.Header.Get(name)
		if name == "host" {
			value = r.Host
		}
		if name == "content-length" {
			value = strconv.FormatInt(r.ContentLength, 10)
		}
		if value == "" {
			return false
		}
		headers.WriteString(name + ":" + strings.Join(strings.Fields(value), " ") + "\n")
	}
	date, err := time.Parse("20060102T150405Z", q.Get("X-Amz-Date"))
	if err != nil {
		return false
	}
	seconds, err := strconv.ParseInt(q.Get("X-Amz-Expires"), 10, 64)
	if err != nil || seconds < 1 || !time.Now().Before(date.Add(time.Duration(seconds)*time.Second)) || date.Add(time.Duration(seconds)*time.Second).After(deadline) {
		return false
	}
	signature := q.Get("X-Amz-Signature")
	q.Del("X-Amz-Signature")
	canonical := r.Method + "\n" + r.URL.EscapedPath() + "\n" + strings.ReplaceAll(q.Encode(), "+", "%20") + "\n" + headers.String() + "\n" + signed + "\n" + r.Header.Get("X-Amz-Content-Sha256")
	scope := strings.Join(credential[1:], "/")
	keyDate := aHMAC([]byte("AWS4"+key.SecretKey), credential[1])
	keyRegion := aHMAC(keyDate, credential[2])
	keyService := aHMAC(keyRegion, "s3")
	keySigning := aHMAC(keyService, "aws4_request")
	expected := hex.EncodeToString(aHMAC(keySigning, "AWS4-HMAC-SHA256\n"+q.Get("X-Amz-Date")+"\n"+scope+"\n"+hash([]byte(canonical))))
	return hmac.Equal([]byte(expected), []byte(signature))
}

func (s *aNativePublicationServer) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Method == "PUT" {
		s.puts++
		raw, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err != nil || !aValidPublicationSignature(r, s.write, s.deadline) || r.Header.Get("If-None-Match") != "*" || int64(len(raw)) != r.ContentLength || hash(raw) != r.Header.Get("X-Amz-Content-Sha256") {
			http.Error(w, "denied", 403)
			return
		}
		if _, ok := s.objects[r.URL.Path]; ok {
			w.WriteHeader(412)
			return
		}
		s.objects[r.URL.Path] = bytes.Clone(raw)
		if s.lostACK {
			w.WriteHeader(503)
			return
		}
		w.Header().Set("x-amz-version-id", "original-v1")
		w.WriteHeader(200)
		return
	}
	if !strings.Contains(r.Header.Get("Authorization"), "Credential="+s.read.AccessKey+"/") || r.URL.Query().Get("X-Amz-Credential") != "" {
		http.Error(w, "read denied", 403)
		return
	}
	raw, ok := s.objects[r.URL.Path]
	if !ok {
		w.WriteHeader(404)
		return
	}
	if r.URL.Query().Get("versionId") != "" && r.URL.Query().Get("versionId") != "original-v1" {
		w.WriteHeader(404)
		return
	}
	w.Header().Set("x-amz-version-id", "original-v1")
	if s.wrongVersion {
		w.Header().Set("x-amz-version-id", "substitute-v2")
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
	if r.Method == "HEAD" {
		s.heads++
		return
	}
	if r.Method != "GET" || r.URL.Query().Get("versionId") != "original-v1" {
		http.Error(w, "version required", 403)
		return
	}
	s.gets++
	if s.getUnavailable {
		w.WriteHeader(503)
		return
	}
	if s.onGet != nil {
		s.onGet()
	}
	w.WriteHeader(200)
	if s.delay > 0 {
		w.(http.Flusher).Flush()
		timer := time.NewTimer(s.delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-r.Context().Done():
			return
		}
	}
	_, _ = w.Write(raw)
}

func newANativePublicationStore(t *testing.T, window time.Duration) (*nativePublicationS3, *aNativePublicationServer) {
	t.Helper()
	now := time.Now().UTC()
	state := &aNativePublicationServer{objects: map[string][]byte{}, deadline: now.Add(window), read: nativePublicationCredential{AccessKey: "read-only-local", SecretKey: strings.Repeat("r", 32), NotBefore: now.Add(-time.Minute), Until: now.Add(window + time.Minute)}, write: nativePublicationCredential{AccessKey: "immutable-write-local", SecretKey: strings.Repeat("w", 32), NotBefore: now.Add(-time.Minute), Until: now.Add(window + time.Minute)}}
	server := httptest.NewTLSServer(http.HandlerFunc(state.serve))
	t.Cleanup(server.Close)
	root := t.TempDir()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	material := PublicationTargetMaterials{Version: publicationTargetVersion, InstallationID: "installation_native_local", Endpoint: server.URL, Region: "local-1", Bucket: "formal-local", Root: "installation_native_local/", ReadIdentityHash: hash([]byte("read")), ReadRefVersion: "read-r1", WriteIdentityHash: hash([]byte("write")), WriteRefVersion: "write-r1", CAIdentityHash: hash([]byte("ca")), CARefVersion: "ca-r1", CAFile: filepath.Join(root, "ca.pem"), CASHA256: hash(ca), ReadCredentialFile: filepath.Join(root, "read.json"), WriteCredentialFile: filepath.Join(root, "write.json")}
	read, _ := json.Marshal(state.read)
	write, _ := json.Marshal(state.write)
	material.ReadCredentialSHA256 = hash(read)
	material.WriteCredentialSHA256 = hash(write)
	for file, raw := range map[string][]byte{material.CAFile: ca, material.ReadCredentialFile: read, material.WriteCredentialFile: write} {
		if err := os.WriteFile(file, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	store, err := newNativePublicationS3(material)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	return store, state
}

func TestAPublicationNativeImmutablePutIndependentVersionReadback(t *testing.T) {
	store, state := newANativePublicationStore(t, time.Minute)
	ctx := context.Background()
	payload := []byte(`{"schema_version":"system-backup-committed.v1"}`)
	key := store.config.Root + "sbk_original/1/_COMMITTED"
	object, err := store.create(ctx, key, bytes.NewReader(payload), int64(len(payload)), hash(payload), state.deadline)
	if err != nil || object.Version != "original-v1" {
		t.Fatal("actual signed conditional PUT", err)
	}
	if _, err = store.create(ctx, key, bytes.NewReader(payload), int64(len(payload)), hash(payload), state.deadline); err != errPublicationConflict {
		t.Fatal("overwrite allowed", err)
	}
	action := publicationJournalAction{Key: key, Payload: payload, PayloadSHA: hash(payload), Size: int64(len(payload))}
	observed, raw, err := readPublicationJSON(ctx, store, action, state.deadline)
	if err != nil || !bytes.Equal(raw, payload) || observed.Version != "original-v1" || state.puts != 2 || state.heads != 1 || state.gets != 1 {
		t.Fatal("independent complete readback", err)
	}
	state.wrongVersion = true
	if _, err = store.open(ctx, observed, state.deadline); err == nil {
		t.Fatal("substituted version accepted")
	}
}

func TestAPublicationNativeLostACKQueriesOriginalWithoutSend(t *testing.T) {
	store, state := newANativePublicationStore(t, time.Minute)
	state.lostACK = true
	ctx := context.Background()
	payload := []byte(`{"original":"request"}`)
	key := store.config.Root + "sbk_original/1/manifest.json"
	if _, err := store.create(ctx, key, bytes.NewReader(payload), int64(len(payload)), hash(payload), state.deadline); err == nil {
		t.Fatal("lost ACK reported success")
	}
	action := publicationJournalAction{Key: key, Payload: payload, PayloadSHA: hash(payload), Size: int64(len(payload))}
	if _, _, err := readPublicationJSON(ctx, store, action, state.deadline); err != nil || state.puts != 1 {
		t.Fatal("original readback", err)
	}
	action.Key = store.config.Root + "missing"
	if _, _, err := readPublicationJSON(ctx, store, action, state.deadline); err != errPublicationUnavailable {
		t.Fatal("404 became absence", err)
	}
}

func TestAPublicationNativeLongReadHonorsOriginalWindow(t *testing.T) {
	if os.Getenv("A_PUBLICATION_LONG_STREAM_TEST") != "1" {
		t.Skip("explicit 31-second local TLS stream")
	}
	store, state := newANativePublicationStore(t, 40*time.Second)
	state.delay = 31 * time.Second
	payload := bytes.Repeat([]byte("q"), 1<<20)
	key := store.config.Root + "payload.enc"
	if _, err := store.create(context.Background(), key, bytes.NewReader(payload), int64(len(payload)), hash(payload), state.deadline); err != nil {
		t.Fatal(err)
	}
	object, err := store.stat(context.Background(), key, "original-v1", state.deadline)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	reader, err := store.open(context.Background(), object, state.deadline)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(reader)
	closeErr := reader.Close()
	if err != nil || closeErr != nil || !bytes.Equal(raw, payload) || time.Since(start) < 30*time.Second {
		t.Fatal("legal stream failed past 30s", err, closeErr)
	}
	// The same client cannot extend a caller's ORIGINAL shorter use deadline.
	state.delay = 2 * time.Second
	until := time.Now().Add(200 * time.Millisecond)
	reader, err = store.open(context.Background(), object, until)
	if err == nil {
		_, err = io.ReadAll(reader)
		reader.Close()
	}
	if err == nil {
		t.Fatal("original deadline extended")
	}
}
