package systembackupevidence

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type testKeys struct {
	key  []byte
	fail bool
}

func (k testKeys) Wrap(_ context.Context, ref KeyRef, b []byte) ([]byte, error) {
	if k.fail {
		return nil, errors.New("private KMS credential")
	}
	a, _ := aes.NewCipher(k.key)
	g, _ := cipher.NewGCM(a)
	n := make([]byte, 12)
	rand.Read(n)
	return append(n, g.Seal(nil, n, b, canonical(ref))...), nil
}
func (k testKeys) Unwrap(_ context.Context, ref KeyRef, b []byte) ([]byte, error) {
	if k.fail || len(b) < 28 {
		return nil, errors.New("private KMS credential")
	}
	a, _ := aes.NewCipher(k.key)
	g, _ := cipher.NewGCM(a)
	return g.Open(nil, b[:12], b[12:], canonical(ref))
}

type testRedactor struct{ reject bool }

func (r testRedactor) Validate(_ context.Context, _ Identity, b io.Reader) error {
	if r.reject {
		return errors.New("private rejected text")
	}
	_, e := io.Copy(io.Discard, b)
	return e
}
func source(b []byte) Source {
	return func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
}

type testStore struct {
	data                                                      []byte
	info                                                      ObjectInfo
	puts, deletes, reads                                      int
	present, authoritative, putUnknown, deleteUnknown, tamper bool
	onRead                                                    func()
}

func (s *testStore) Stat(context.Context, Ref) (ObjectInfo, error) {
	if !s.present {
		return ObjectInfo{}, ErrUnavailable
	}
	return s.info, nil
}
func (s *testStore) Put(_ context.Context, _ Ref, r io.Reader, want ObjectInfo, _ time.Time) error {
	s.puts++
	if s.present {
		return ErrConflict
	}
	b, e := io.ReadAll(io.LimitReader(r, want.Size+1))
	if e != nil || int64(len(b)) != want.Size || hash(b) != want.SHA256 {
		return ErrIntegrity
	}
	s.data = b
	s.info = ObjectInfo{"immutable-v1", hash(b), int64(len(b))}
	s.present = true
	if s.putUnknown {
		return ErrUnavailable
	}
	return nil
}
func (s *testStore) Range(_ context.Context, ref Ref, offset, length int64) (io.ReadCloser, error) {
	s.reads++
	if s.onRead != nil {
		s.onRead()
	}
	if !s.present || ref.ImmutableVersion != s.info.Version || offset < 0 || offset+length > int64(len(s.data)) {
		return nil, ErrUnavailable
	}
	b := append([]byte(nil), s.data[offset:offset+length]...)
	if s.tamper && offset > 0 {
		b[len(b)-1] ^= 1
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}
func (s *testStore) Delete(_ context.Context, _ Ref, _ ObjectInfo) error {
	s.deletes++
	if s.deleteUnknown {
		return ErrUnavailable
	}
	s.present = false
	return nil
}
func (s *testStore) Absent(_ context.Context, ref Ref) (Absence, error) {
	return Absence{Authoritative: s.authoritative && !s.present, Version: ref.ImmutableVersion}, nil
}

type memoryRegistry struct {
	mu                            sync.Mutex
	r                             Record
	now                           time.Time
	denied, referenced, failAudit bool
	audits                        []Audit
	authorizations                int
}
type memLocked struct {
	m      *memoryRegistry
	r      Record
	audits []Audit
}

func (m *memoryRegistry) PersistPending(_ context.Context, r Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.r.Manifest.Identity.ID != "" {
		return ErrConflict
	}
	m.r = r
	return nil
}
func (m *memoryRegistry) WithLocked(_ context.Context, id string, fn func(Locked) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.r.Manifest.Identity.ID != id {
		return ErrNotFound
	}
	tx := &memLocked{m: m, r: m.r}
	if e := fn(tx); e != nil {
		return e
	}
	m.r = tx.r
	m.audits = append(m.audits, tx.audits...)
	return nil
}
func (t *memLocked) Record() Record  { return t.r }
func (t *memLocked) Time() time.Time { return t.m.now }
func (t *memLocked) Authorize(_ context.Context, a Actor, p []string) error {
	t.m.authorizations++
	if t.m.denied || a.ID != "admin" || len(p) != 2 || p[1] != "system_backup.security_configure" {
		return ErrDenied
	}
	return nil
}
func (t *memLocked) Audit(_ context.Context, a Audit) error {
	if t.m.failAudit {
		return errors.New("private DB error")
	}
	t.audits = append(t.audits, a)
	return nil
}
func (t *memLocked) Save(_ context.Context, r Record) error {
	if r.RowVersion != t.r.RowVersion+1 {
		return ErrConflict
	}
	t.r = r
	return nil
}
func (t *memLocked) Deletable(context.Context) error {
	if t.m.referenced {
		return ErrConflict
	}
	return nil
}

type testAuth struct{}

func (testAuth) Authenticate(*http.Request) (Actor, error) { return Actor{"admin", "session"}, nil }
func (testAuth) AuthorizeSensitiveDownload(context.Context, *http.Request, Actor, Record, int64, int64, Locked) error {
	return nil
}

type unsteppedTestAuth struct{}

func (unsteppedTestAuth) Authenticate(*http.Request) (Actor, error) {
	return Actor{"admin", "session"}, nil
}

func fixture(t *testing.T, size int) (Prepared, []byte, []byte, testKeys) {
	t.Helper()
	plain := bytes.Repeat([]byte("abcdefgh"), (size+7)/8)[:size]
	i := Identity{Installation: "installation_test", ID: "sev_11111111-2222-4333-8444-555555555555", OwnerType: "backup", OwnerID: "sbk_11111111-2222-4333-8444-555555555555", Type: "verifier_report", Media: "text/plain", Classification: "sensitive", ContentHash: hash(plain), ContentSize: int64(size)}
	keys := testKeys{key: bytes.Repeat([]byte{7}, 32)}
	var object bytes.Buffer
	p, e := Prepare(context.Background(), i, KeyRef{strings.Repeat("b", 64), "v1"}, source(plain), testRedactor{}, keys, &object)
	if e != nil {
		t.Fatal(e)
	}
	return p, plain, object.Bytes(), keys
}
func serviceFixture(t *testing.T) (Service, *memoryRegistry, *testStore, []byte, []byte) {
	p, plain, object, keys := fixture(t, int(ChunkSize)+131)
	now := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	m := &memoryRegistry{now: now}
	store := &testStore{authoritative: true}
	s := Service{Registry: m, Store: store, Keys: keys, Failure: func(context.Context, string, string) {}}
	if e := s.Register(context.Background(), p, "evidence", Ref{Identity: strings.Repeat("a", 64), Version: "v1"}, now, now.Add(time.Hour), now.Add(2*time.Hour), now.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	if e := s.Publish(context.Background(), p.manifest.Identity.ID, source(object)); e != nil {
		t.Fatal(e)
	}
	return s, m, store, plain, object
}

func TestEnvelopeChunkRangesAndTampering(t *testing.T) {
	s, m, store, plain, _ := serviceFixture(t)
	r := m.r
	for _, bounds := range [][2]int64{{0, r.Manifest.Identity.ContentSize - 1}, {ChunkSize - 8, ChunkSize + 8}, {3, 99}} {
		got, e := OpenRange(context.Background(), r.Manifest, r.Ref, store, s.Keys, bounds[0], bounds[1])
		if e != nil || !bytes.Equal(got, plain[bounds[0]:bounds[1]+1]) {
			t.Fatal("range roundtrip", e)
		}
	}
	store.tamper = true
	if got, e := OpenRange(context.Background(), r.Manifest, r.Ref, store, s.Keys, 0, r.Manifest.Identity.ContentSize-1); e != ErrIntegrity || got != nil {
		t.Fatal("tampering leaked body", e)
	}
	store.tamper = false
	bad := r.Manifest
	bad.Chunks = append([]Chunk(nil), bad.Chunks...)
	bad.Chunks[1].FrameOffset++
	if _, e := OpenRange(context.Background(), bad, r.Ref, store, s.Keys, 0, 99); e != ErrIntegrity {
		t.Fatal("bad chunk index accepted")
	}
	bad = r.Manifest
	bad.Identity.Classification = "internal"
	if _, e := OpenRange(context.Background(), bad, r.Ref, store, s.Keys, 0, 99); e != ErrIntegrity {
		t.Fatal("classification substitution accepted")
	}
	if _, e := OpenRange(context.Background(), r.Manifest, r.Ref, store, testKeys{fail: true}, 0, 99); e != ErrKey {
		t.Fatal("KMS failure not closed", e)
	}
}

func TestPrepareRejectsDriftSizeAndRedaction(t *testing.T) {
	p, plain, _, keys := fixture(t, 9000)
	i := p.manifest.Identity
	var dst bytes.Buffer
	if _, e := Prepare(context.Background(), i, p.manifest.Key, source(plain), testRedactor{reject: true}, keys, &dst); e != ErrRedaction || dst.Len() != 0 {
		t.Fatal("redaction failure wrote ciphertext")
	}
	n := 0
	drift := func() (io.ReadCloser, error) {
		n++
		b := append([]byte(nil), plain...)
		if n > 1 {
			b[0] ^= 1
		}
		return io.NopCloser(bytes.NewReader(b)), nil
	}
	if _, e := Prepare(context.Background(), i, p.manifest.Key, drift, testRedactor{}, keys, &dst); e != ErrIntegrity {
		t.Fatal("source changed", e)
	}
	i.ContentSize = MaxContent + 1
	if _, e := Prepare(context.Background(), i, p.manifest.Key, source(nil), testRedactor{}, keys, &dst); e != ErrCapacity {
		t.Fatal("size limit", e)
	}
	i = p.manifest.Identity
	i.ContentSize = 8192
	if _, e := Prepare(context.Background(), i, p.manifest.Key, source(plain), testRedactor{}, keys, &dst); e != ErrInvalid {
		t.Fatal("inline boundary", e)
	}
}

func TestPublishUnknownAndRetentionGC(t *testing.T) {
	s, m, store, _, object := serviceFixture(t)
	id := m.r.Manifest.Identity.ID
	if store.puts != 1 || m.r.State != "ready" {
		t.Fatal("not ready")
	}
	if e := s.GC(context.Background(), []string{id})[0]; e != ErrConflict || store.deletes != 0 {
		t.Fatal("retained object deleted")
	}
	m.now = m.now.Add(3 * time.Hour)
	m.referenced = true
	if e := s.GC(context.Background(), []string{id})[0]; e != ErrConflict || store.deletes != 0 {
		t.Fatal("referenced object deleted")
	}
	m.referenced = false
	store.deleteUnknown = true
	if e := s.GC(context.Background(), []string{id})[0]; e == nil || m.r.State != "delete_failed" || m.r.Ref.ImmutableVersion == "" {
		t.Fatal("uncertain deletion lost record")
	}
	store.deleteUnknown = false
	store.authoritative = false
	if e := s.GC(context.Background(), []string{id})[0]; e == nil || m.r.State != "delete_failed" {
		t.Fatal("ordinary absence accepted")
	}
	store.authoritative = true
	if e := s.GC(context.Background(), []string{id})[0]; e != nil || m.r.State != "deleted" || m.r.Ref.RelativeKey != "" || len(m.r.Manifest.Chunks) != 0 {
		t.Fatal("GC did not converge", e)
	}
	beforeDelete := store.deletes
	if e := s.GC(context.Background(), []string{id})[0]; e != nil || store.deletes != beforeDelete {
		t.Fatal("tombstone replay dispatched remote delete", e)
	}
	// A lost PUT response is resolved by exact Stat without a second write.
	s, m, store, _, _ = serviceFixture(t)
	m.r.State = "write_unknown"
	m.r.Ref.ImmutableVersion = ""
	before := store.puts
	if e := s.Publish(context.Background(), id, source(object)); e != nil || store.puts != before || m.r.State != "ready" {
		t.Fatal("reconcile resent committed write", e)
	}
}

func TestDownloadAuthAuditRangeAndNoPartialBody(t *testing.T) {
	for _, name := range []string{"success", "denied", "late-revoke", "tamper", "audit-failure", "multi-range", "duplicate-range", "oversize", "forwarded-http", "missing-step-up"} {
		t.Run(name, func(t *testing.T) {
			s, m, store, plain, _ := serviceFixture(t)
			original := m.r
			originalAudits := len(m.audits)
			h := Handler{Service: s, Auth: testAuth{}}
			r := httptest.NewRequest("GET", Path+m.r.Manifest.Identity.ID, nil)
			r.TLS = &tls.ConnectionState{}
			r.Header.Set("Range", "bytes=1048570-1048590")
			want := 206
			switch name {
			case "denied":
				m.denied = true
				want = 403
			case "late-revoke":
				store.onRead = func() { m.denied = true }
				want = 403
			case "tamper":
				store.tamper = true
				want = 409
			case "audit-failure":
				m.failAudit = true
				want = 500
			case "multi-range":
				r.Header.Set("Range", "bytes=0-1,4-5")
				want = 416
			case "duplicate-range":
				r.Header.Add("Range", "bytes=0-1")
				want = 416
			case "oversize":
				r.Header.Set("Range", "bytes=-0")
				want = 416
			case "forwarded-http":
				r.TLS = nil
				r.Header.Set("X-Forwarded-Proto", "https")
				want = 401
			case "missing-step-up":
				h.Auth = unsteppedTestAuth{}
				want = 401
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != want {
				t.Fatal(w.Code, w.Body.String())
			}
			if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("unsafe response headers")
			}
			if want == 206 {
				if !bytes.Equal(w.Body.Bytes(), plain[1048570:1048591]) || m.authorizations != 2 || len(m.audits) != 2 || m.audits[1].Outcome != "sent" {
					t.Fatal("successful download checks")
				}
			} else if bytes.Contains(w.Body.Bytes(), plain[:32]) {
				t.Fatal("plaintext leaked before final validation")
			}
			if oneOf(name, "denied", "audit-failure", "multi-range", "duplicate-range", "oversize") && store.reads != 0 {
				t.Fatal("unauthorized provider read")
			}
			if name == "missing-step-up" && (m.r.RowVersion != original.RowVersion || m.r.Claim != original.Claim || len(m.audits) != originalAudits || store.reads != 0) {
				t.Fatal("failed second factor committed claim, audit or provider read")
			}
		})
	}
}

func TestRetentionSnapshotAndLogSeparation(t *testing.T) {
	p := Retention{Artifact: 24 * time.Hour, Evidence: 48 * time.Hour, Logs: time.Hour, Control: 30 * 24 * time.Hour}
	r := Record{CreatedAt: time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)}
	r.ExpiresAt = r.CreatedAt.Add(p.Evidence)
	if p.Check(r, true) != nil {
		t.Fatal("valid retention rejected")
	}
	r.ExpiresAt = r.ExpiresAt.Add(-time.Second)
	if p.Check(r, false) != ErrInvalid {
		t.Fatal("short retention accepted")
	}
	r.Manifest.Identity.Type = "job_log_chunk"
	r.Manifest.Identity.ContentSize = ChunkSize
	r.ExpiresAt = r.CreatedAt.Add(p.Logs)
	if p.Check(r, false) != nil || p.Check(r, true) != ErrInvalid {
		t.Fatal("log policy")
	}
	r.ExpiresAt = r.ExpiresAt.Add(time.Second)
	if p.Check(r, false) != ErrInvalid {
		t.Fatal("log expiry extended")
	}
	cutoff, e := p.TombstoneUntil(r.CreatedAt)
	if e != nil || !cutoff.Equal(r.CreatedAt.Add(p.Control)) {
		t.Fatal("tombstone cutoff")
	}
	p.Control = time.Hour
	if _, e := p.TombstoneUntil(r.CreatedAt); e != ErrInvalid {
		t.Fatal("short control retention")
	}
}

func TestRangeAndKeyBoundaries(t *testing.T) {
	for _, value := range []string{"bytes=0-8388608", "bytes=0-1,4-5", "bytes=+0-1", "bytes=-0", "bytes=999999999999999999999-", "items=0-1"} {
		if _, _, _, e := parseRange(value, MaxContent); e != ErrRange {
			t.Fatal(value)
		}
	}
	if _, _, _, e := parseRange("", MaxResponse+1); e != ErrRange {
		t.Fatal("unbounded full response")
	}
	start, end, partial, e := parseRange("bytes=-10", 9000)
	if e != nil || !partial || start != 8990 || end != 8999 {
		t.Fatal("suffix")
	}
	for _, key := range []string{"https://x/a", "../escape", "a/../b", "/root", "a//b"} {
		if safeKey(key) {
			t.Fatal("unsafe key", key)
		}
	}
}
