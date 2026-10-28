package systembackupevidence

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

type systemPublishTestProof struct {
	request SystemPublicationProofRequest
	calls   int
	mutate  func(*SystemPublicationProof)
	hook    func()
	err     error
}

func (v *systemPublishTestProof) VerifySystemPublication(_ context.Context, q SystemPublicationProofRequest) (SystemPublicationProof, error) {
	v.calls++
	v.request = q
	p := SystemPublicationProof{Request: q, State: "write_unknown", ProofHash: strings.Repeat("e", 64), ObservedAt: time.Now().UTC().Truncate(time.Microsecond), ExpiresAt: q.Deadline}
	if q.Observation == "match" {
		p.State = "ready"
		p.Object = q.Observed
	}
	if v.mutate != nil {
		v.mutate(&p)
	}
	if v.hook != nil {
		v.hook()
	}
	return p, v.err
}

type systemPublishTestFinish struct {
	calls   int
	request pd.FinishRequest
	err     error
}

func (f *systemPublishTestFinish) FinishPublication(_ context.Context, _ *pd.PublicationClaim, r pd.FinishRequest) (pd.FinishResult, error) {
	f.calls++
	f.request = r
	if f.err != nil {
		return pd.FinishResult{}, f.err
	}
	return pd.FinishResult{State: r.State, ImmutableVersion: r.ImmutableVersion, EvidenceVersion: "3"}, nil
}

type systemPublishFixture struct {
	x                   *systemSTSTestFixture
	p                   *SystemPublisher
	proof               *systemPublishTestProof
	finish              *systemPublishTestFinish
	body                []byte
	mu                  sync.Mutex
	heads, puts, absent int
	present             bool
	absenceDenied       bool
	absenceHook         func()
	absenceUntil        time.Time
	mode                string
}

func (f *systemPublishFixture) VerifyAbsent(_ context.Context, q S3AbsenceRequest) (S3AbsenceProof, error) {
	f.absent++
	if f.absenceHook != nil {
		f.absenceHook()
	}
	if f.absenceDenied {
		return S3AbsenceProof{}, ErrDenied
	}
	lifetime := 10 * time.Second
	if f.mode == "absence_expired_during_staging" {
		// Leave enough time for the real profile/authority checks to accept
		// the proof and enter Source. Source waits for THIS original expiry.
		lifetime = 2 * time.Second
	} else if f.mode == "absence_expired_before_staging" {
		lifetime = time.Millisecond
	}
	observed := time.Now().UTC()
	p := S3AbsenceProof{Request: q, ObservedAt: observed, ExpiresAt: observed.Add(lifetime)}
	f.mu.Lock()
	f.absenceUntil = p.ExpiresAt
	f.mu.Unlock()
	if f.mode == "absence_expired_before_staging" {
		time.Sleep(time.Until(p.ExpiresAt) + time.Millisecond)
	}
	return p, nil
}
func newSystemPublishFixture(t *testing.T, mode string) *systemPublishFixture {
	t.Helper()
	x := newSystemSTSTestFixture(t, "")
	i, body, a, keys := smallSystemFixture(t)
	var dst bytes.Buffer
	p, err := PrepareSystemCapability(context.Background(), i, KeyRef{strings.Repeat("b", 64), "v1"}, source(body), a, keys, &dst)
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.PendingProducerBinding(x.c.Channel)
	if err != nil {
		t.Fatal(err)
	}
	key, err := keyFor(x.c.Channel.Root, i)
	if err != nil {
		t.Fatal(err)
	}
	x.c.History.Evidence = b
	x.c.History.RelativeKey = pd.RelativeKey(key)
	x.f.prepared = p
	f := &systemPublishFixture{x: x, body: append([]byte(nil), dst.Bytes()...), mode: mode, proof: &systemPublishTestProof{}, finish: &systemPublishTestFinish{}}
	f.present = mode == "existing" || mode == "mismatch"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if !verifyS3Wire(r) || r.URL.Path != "/test-bucket/"+key || r.URL.Query().Get("versionId") != "" {
			t.Error("wrong signed publication request")
			w.WriteHeader(403)
			return
		}
		m := p.Manifest()
		setHeaders := func() {
			digest, _ := hex.DecodeString(m.ObjectHash)
			if mode == "mismatch" {
				digest = make([]byte, 32)
			}
			w.Header().Set("X-Amz-Version-Id", "Exact-Version-1")
			w.Header().Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(digest))
		}
		switch r.Method {
		case "HEAD":
			f.heads++
			if mode == "revoke_stat" {
				x.calls.revoked.Store(true)
			}
			if !f.present || mode == "unknown" {
				w.WriteHeader(404)
				return
			}
			setHeaders()
			w.Header().Set("Content-Length", strconv.Itoa(len(f.body)))
		case "PUT":
			f.puts++
			signedAt, parseErr := time.Parse("20060102T150405Z", r.URL.Query().Get("X-Amz-Date"))
			expires, expiryErr := strconv.ParseInt(r.URL.Query().Get("X-Amz-Expires"), 10, 64)
			if parseErr != nil || expiryErr != nil || signedAt.Add(time.Duration(expires)*time.Second).After(f.absenceUntil) {
				t.Error("signed PUT exceeds original absence proof expiry")
				w.WriteHeader(403)
				return
			}
			raw, e := io.ReadAll(io.LimitReader(r.Body, int64(len(f.body)+1)))
			if e != nil || !bytes.Equal(raw, f.body) || r.Header.Get("If-None-Match") != "*" {
				t.Error("not exact original conditional body")
				w.WriteHeader(400)
				return
			}
			f.present = true
			if mode == "revoke_put" {
				x.calls.revoked.Store(true)
			}
			if mode == "lost" || mode == "unknown" {
				w.WriteHeader(503)
				return
			}
			if mode == "conflict" {
				w.WriteHeader(412)
				return
			}
			setHeaders()
		default:
			t.Error("forbidden storage operation")
			w.WriteHeader(403)
		}
	}))
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	x.c.STS.Store.Endpoint = server.URL
	x.c.STS.Store.CAPEM = ca
	x.c.STS.Store.CASHA256 = hash(ca)
	x.calls.c = x.c
	x.start(t)
	absence := &systemPublicationAbsence{sts: x.s, verifier: f}
	store, err := NewS3Store(x.c.STS.Store, x.s, absence)
	if err != nil {
		t.Fatal(err)
	}
	f.p = &SystemPublisher{sts: x.s, store: store, finalizer: f.finish, verifier: f.proof, absence: absence}
	t.Cleanup(f.p.Close)
	return f
}
func (f *systemPublishFixture) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.heads, f.puts
}

func TestSystemPublisherWireAndConvergence(t *testing.T) {
	for _, mode := range []string{"existing", "create", "lost", "conflict", "unknown", "mismatch", "absence_denied"} {
		t.Run(mode, func(t *testing.T) {
			f := newSystemPublishFixture(t, mode)
			if mode == "absence_denied" {
				f.absenceDenied = true
			}
			opens := 0
			r, e := f.p.Publish(context.Background(), func() (io.ReadCloser, error) { opens++; return io.NopCloser(bytes.NewReader(f.body)), nil })
			want := "ready"
			if mode == "unknown" || mode == "mismatch" || mode == "absence_denied" {
				want = "write_unknown"
			}
			if e != nil || r.State != want || f.finish.calls != 1 || f.proof.calls != 1 {
				t.Fatal("publication result", e, r.State)
			}
			heads, puts := f.counts()
			write := mode != "existing" && mode != "mismatch" && mode != "absence_denied"
			if write && (heads != 2 || puts != 1 || opens != 1 || f.absent != 1) || !write && (heads != 1 || puts != 0 || opens != 0) {
				t.Fatal("unexpected retry or staging read", heads, puts, opens)
			}
			q := f.proof.request
			if q.PutAttempted != write || len(q.Challenge) != 64 || q.Ref != f.x.s.original.record.Ref || q.Expected.SHA256 != hash(f.body) || q.PolicyHash != f.x.s.policy || q.Claim != *f.x.s.views[0].Binding.Claim {
				t.Fatal("incomplete proof binding")
			}
			if want == "ready" && (r.ImmutableVersion == nil || *r.ImmutableVersion != "Exact-Version-1") || want == "write_unknown" && r.ImmutableVersion != nil {
				t.Fatal("wrong immutable version")
			}
			if _, e = f.p.Publish(context.Background(), source(f.body)); e == nil {
				t.Fatal("claim attempt reused")
			}
			_, again := f.counts()
			if again != puts {
				t.Fatal("duplicate PUT")
			}
		})
	}
}

func TestSystemPublisherRejectsProof(t *testing.T) {
	cases := map[string]func(*SystemPublicationProof){
		"challenge":      func(p *SystemPublicationProof) { p.Request.Challenge = strings.Repeat("0", 64) },
		"claim":          func(p *SystemPublicationProof) { p.Request.Claim.Owner = pd.ID(strings.Repeat("0", 64)) },
		"key":            func(p *SystemPublicationProof) { p.Request.Ref.RelativeKey += "x" },
		"profile":        func(p *SystemPublicationProof) { p.Request.ProviderProfileHash = strings.Repeat("0", 64) },
		"manifest":       func(p *SystemPublicationProof) { p.Request.ManifestHash = strings.Repeat("0", 64) },
		"hash":           func(p *SystemPublicationProof) { p.ProofHash = "invalid" },
		"stale":          func(p *SystemPublicationProof) { p.ObservedAt = time.Now().Add(-time.Minute) },
		"future":         func(p *SystemPublicationProof) { p.ObservedAt = time.Now().Add(time.Second) },
		"expired":        func(p *SystemPublicationProof) { p.ExpiresAt = time.Now().Add(-time.Second) },
		"extended":       func(p *SystemPublicationProof) { p.ExpiresAt = p.Request.Deadline.Add(time.Second) },
		"state":          func(p *SystemPublicationProof) { p.State = "write_failed" },
		"version":        func(p *SystemPublicationProof) { p.Object.Version = "another" },
		"checksum":       func(p *SystemPublicationProof) { p.Object.SHA256 = strings.Repeat("0", 64) },
		"size":           func(p *SystemPublicationProof) { p.Object.Size++ },
		"unknown_object": func(p *SystemPublicationProof) { p.State = "write_unknown" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newSystemPublishFixture(t, "existing")
			f.proof.mutate = mutate
			if _, e := f.p.Publish(context.Background(), nil); e == nil || f.finish.calls != 0 {
				t.Fatal("invalid proof finalized")
			}
		})
	}
	for _, mode := range []string{"mismatch", "absence_denied"} {
		t.Run("ready_without_matching_stat_"+mode, func(t *testing.T) {
			f := newSystemPublishFixture(t, mode)
			f.absenceDenied = true
			f.proof.mutate = func(p *SystemPublicationProof) {
				p.State = "ready"
				p.Object = ObjectInfo{Version: "invented", SHA256: p.Request.Expected.SHA256, Size: p.Request.Expected.Size}
			}
			if _, e := f.p.Publish(context.Background(), nil); e == nil || f.finish.calls != 0 {
				t.Fatal("invented ready")
			}
		})
	}
}

type systemPublishReader struct {
	io.Reader
	close func() error
}

func (r systemPublishReader) Close() error { return r.close() }
func TestSystemPublisherStagingAndRevocation(t *testing.T) {
	for _, mode := range []string{"short", "long", "changed", "open_error", "close_error", "revoke_open", "revoke_read", "revoke_absence", "revoke_stat", "revoke_put", "revoke_proof", "proof_error", "finish_error", "absence_expired_during_staging"} {
		t.Run(mode, func(t *testing.T) {
			f := newSystemPublishFixture(t, mode)
			if mode == "revoke_absence" {
				f.absenceHook = func() { f.x.calls.revoked.Store(true) }
			}
			if mode == "revoke_proof" {
				f.proof.hook = func() { f.x.calls.revoked.Store(true) }
			}
			if mode == "proof_error" {
				f.proof.err = errors.New("private provider error")
			}
			if mode == "finish_error" {
				f.finish.err = pd.ErrGuardRequired
			}
			closed := 0
			opened := 0
			var originalAbsenceUntil time.Time
			src := func() (io.ReadCloser, error) {
				opened++
				if mode == "absence_expired_during_staging" {
					f.mu.Lock()
					originalAbsenceUntil = f.absenceUntil
					f.mu.Unlock()
					if originalAbsenceUntil.IsZero() || !time.Now().Before(originalAbsenceUntil) || !originalAbsenceUntil.Add(time.Second).Before(f.p.sts.until) {
						t.Fatal("absence fixture did not enter staging with a live independent absence budget")
					}
					time.Sleep(time.Until(originalAbsenceUntil) + 50*time.Millisecond)
					if time.Now().Before(originalAbsenceUntil) || !time.Now().Before(f.p.sts.until) {
						t.Fatal("fixture did not expire only the original absence proof")
					}
				}
				raw := append([]byte(nil), f.body...)
				switch mode {
				case "short":
					raw = raw[:len(raw)-1]
				case "long":
					raw = append(raw, 0)
				case "changed":
					raw[0] ^= 1
				case "revoke_open":
					f.x.calls.revoked.Store(true)
				}
				r := systemPublishReader{Reader: bytes.NewReader(raw), close: func() error {
					closed++
					if mode == "revoke_read" {
						f.x.calls.revoked.Store(true)
					}
					if mode == "close_error" {
						return errors.New("private staging error")
					}
					return nil
				}}
				if mode == "open_error" {
					return r, errors.New("private open error")
				}
				return r, nil
			}
			_, err := f.p.Publish(context.Background(), src)
			if err == nil || strings.Contains(err.Error(), "private") {
				heads, puts := f.counts()
				t.Fatal("lost rejection or leaked private error", "rejected", err != nil, "opens", opened, "heads", heads, "puts", puts, "absence", f.absent, "finish", f.finish.calls)
			}
			if mode == "absence_expired_during_staging" && (opened != 1 || f.absent != 1 || originalAbsenceUntil.IsZero() || !f.p.absence.until.Equal(originalAbsenceUntil)) {
				t.Fatal("expiry case skipped staging or renewed the absence proof")
			}
			_, puts := f.counts()
			postPut := mode == "revoke_put" || mode == "revoke_proof" || mode == "proof_error" || mode == "finish_error"
			if !postPut && puts != 0 {
				t.Fatal("write after staging/authority failure")
			}
			if mode != "finish_error" && f.finish.calls != 0 {
				t.Fatal("finalized despite revoked authority")
			}
			if mode != "revoke_absence" && mode != "revoke_stat" && closed != 1 {
				t.Fatal("staging not closed")
			}
		})
	}
}

// Failure to obtain a still-live absence proof is a different path from a
// previously accepted proof expiring during staging. It may converge to
// write_unknown without opening ciphertext or attempting a PUT.
func TestSystemPublisherAbsenceExpiredBeforeStagingConvergesUnknown(t *testing.T) {
	f := newSystemPublishFixture(t, "absence_expired_before_staging")
	opens := 0
	result, err := f.p.Publish(context.Background(), func() (io.ReadCloser, error) {
		opens++
		return io.NopCloser(bytes.NewReader(f.body)), nil
	})
	heads, puts := f.counts()
	if err != nil || result.State != "write_unknown" || result.ImmutableVersion != nil || opens != 0 || heads != 1 || puts != 0 || f.absent != 1 || f.proof.calls != 1 || f.finish.calls != 1 || f.proof.request.PutAttempted || f.p.absence.until != (time.Time{}) {
		t.Fatal("expired unaccepted absence proof was confused with expired staging authority", "error", err != nil, "state", result.State, "opens", opens, "heads", heads, "puts", puts, "absence", f.absent)
	}
}

func TestSystemPublisherConstructionAndClose(t *testing.T) {
	if _, e := NewSystemPublisher(context.Background(), nil, nil, nil, Prepared{}, SystemSTSPolicy{}, nil, nil, nil, nil); e == nil {
		t.Fatal("empty authority accepted")
	}
	var zero *SystemPublisher
	if _, e := zero.Publish(context.Background(), nil); e == nil {
		t.Fatal("nil publisher")
	}
	for _, mode := range []string{"closed", "cancelled", "nil_context", "expired", "nil_verifier"} {
		t.Run(mode, func(t *testing.T) {
			f := newSystemPublishFixture(t, "existing")
			ctx := context.Background()
			switch mode {
			case "closed":
				f.p.Close()
				f.p.Close()
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "nil_context":
				ctx = nil
			case "expired":
				f.x.s.until = time.Now().Add(-time.Second)
			case "nil_verifier":
				f.p.verifier = nil
			}
			if _, e := f.p.Publish(ctx, nil); e == nil {
				t.Fatal("invalid runtime accepted")
			}
			h, p := f.counts()
			if h+p+f.finish.calls+f.proof.calls != 0 {
				t.Fatal("side effect on denied runtime")
			}
		})
	}
}
