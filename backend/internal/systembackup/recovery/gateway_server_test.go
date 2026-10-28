package recovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type nativeFixture struct {
	mu                                      sync.Mutex
	data                                    map[string][]byte
	creates, observes                       int
	missingExpiry, weak, lostReply, badPage bool
}

func (*nativeFixture) Identity() Reference { return ref("provider") }
func (*nativeFixture) Location() Locator   { return Locator{"s3", "fixture", "root", "isolated-site"} }
func (n *nativeFixture) Capabilities(context.Context) ([]Capability, error) {
	out := gatewayCapabilities()
	for _, code := range []string{"conditional_create", "checksum_bound_request", "content_length_bound_request", "scoped_append_credential", "native_deadline_enforced"} {
		if n.missingExpiry && code == "native_deadline_enforced" {
			continue
		}
		out = append(out, Capability{"catalog", code, "supported", n.Identity(), time.Now().Add(-time.Second).UnixMilli(), time.Now().Add(time.Minute).UnixMilli()})
	}
	return out, nil
}
func (n *nativeFixture) observation(key string) Observation {
	o := Observation{State: "absent", Key: key, Strong: !n.weak, Proof: ref("proof"), ValidUntil: time.Now().Add(time.Minute).UnixMilli()}
	if data, ok := n.data[key]; ok {
		o.State = "present"
		o.Object = Object{key, "immutable-v1", int64(len(data)), Hash(data)}
	}
	return o
}
func (n *nativeFixture) Observe(_ context.Context, key string) (Observation, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.observes++
	return n.observation(key), nil
}
func (n *nativeFixture) Create(_ context.Context, r Request) (Observation, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.creates++
	if _, ok := n.data[r.Key]; !ok {
		n.data[r.Key] = append([]byte(nil), r.Payload...)
	}
	if n.lostReply {
		return Observation{}, ErrUnavailable
	}
	return n.observation(r.Key), nil
}
func (n *nativeFixture) Open(_ context.Context, o Object) (io.ReadCloser, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	data := n.data[o.Key]
	if Hash(data) != o.SHA256 || o.Version != "immutable-v1" {
		return nil, ErrUnavailable
	}
	return io.NopCloser(bytes.NewReader(append([]byte(nil), data...))), nil
}
func (n *nativeFixture) Begin(_ context.Context, deadline int64) (Snapshot, error) {
	return Snapshot{"frozen-snapshot", "inventory_manifest", n.Identity(), 0, emptyRolling(), deadline + 1000}, nil
}
func (n *nativeFixture) Page(_ context.Context, s Snapshot, c string, i int64) (Page, error) {
	p := Page{SnapshotID: s.ID, Number: i, Cursor: c, Objects: []Object{}}
	if n.badPage {
		p.SnapshotID = "other"
	}
	return p, nil
}

type memoryGatewayJournal struct {
	mu       sync.Mutex
	requests map[string][]byte
	lost     bool
	calls    int
}

func (j *memoryGatewayJournal) Reserve(_ context.Context, _ Locator, r Request) (bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.calls++
	b, _ := Marshal(r)
	if prior, ok := j.requests[r.Key]; ok {
		if !bytes.Equal(prior, b) {
			return false, ErrConflict
		}
		return false, nil
	}
	j.requests[r.Key] = append([]byte(nil), b...)
	if j.lost {
		j.lost = false
		return false, ErrUnavailable
	}
	return true, nil
}

func nativeServerFixture(t *testing.T, ops []string) (*Gateway, *GatewayServer, *nativeFixture, *memoryGatewayJournal, context.Context) {
	t.Helper()
	_, caKey, _ := ed25519.GenerateKey(rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, e := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if e != nil {
		t.Fatal(e)
	}
	ca, _ := x509.ParseCertificate(caDER)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	issue := func(serial int64, usage x509.ExtKeyUsage) ([]byte, []byte) {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		c := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		der, e := x509.CreateCertificate(rand.Reader, c, ca, key.Public(), caKey)
		if e != nil {
			t.Fatal(e)
		}
		pk, _ := x509.MarshalPKCS8PrivateKey(key)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})
	}
	serverCert, serverKey := issue(2, x509.ExtKeyUsageServerAuth)
	clientCert, clientKey := issue(3, x509.ExtKeyUsageClientAuth)
	block, _ := pem.Decode(clientCert)
	backend := &nativeFixture{data: map[string][]byte{}}
	journal := &memoryGatewayJournal{requests: map[string][]byte{}}
	if ops == nil {
		ops = []string{"capabilities", "observe", "open", "conditional_create", "begin_snapshot", "snapshot_page"}
	}
	handler, e := NewGatewayServer(GatewayServerConfig{backend.Identity(), backend.Location(), "inventory_manifest", true, map[string][]string{Hash(block.Bytes): ops}, 10000}, backend, journal)
	if e != nil {
		t.Fatal(e)
	}
	s := httptest.NewUnstartedServer(handler)
	pair, _ := tls.X509KeyPair(serverCert, serverKey)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	s.StartTLS()
	t.Cleanup(s.Close)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	g, e := NewGateway(GatewayConfig{s.URL, backend.Identity(), backend.Location(), "inventory_manifest", true}, caPEM, clientCert, clientKey)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(g.Close)
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(stop)
	return g, handler, backend, journal, ctx
}

func TestNativeGatewayRoundTripAndRepeatedWritesAreObserveOnly(t *testing.T) {
	g, _, backend, journal, ctx := nativeServerFixture(t, nil)
	r := requestFor("isolated-action", "manifest.json", []byte(`{"fixture":true}`), time.Now().Add(time.Minute).UnixMilli())
	r.Target = g.Identity()
	for i := 0; i < 2; i++ {
		if _, e := g.Create(ctx, r); e != nil {
			t.Fatal(e)
		}
	}
	if backend.creates != 1 || journal.calls != 2 || backend.observes != 1 {
		t.Fatal("write replayed")
	}
	o, e := g.Observe(ctx, r.Key)
	if e != nil {
		t.Fatal(e)
	}
	stream, e := g.Open(ctx, o.Object)
	if e != nil {
		t.Fatal(e)
	}
	data, e := io.ReadAll(stream)
	stream.Close()
	if e != nil || !bytes.Equal(data, r.Payload) {
		t.Fatal("incorrect exact-version stream", e)
	}
	s, e := g.Begin(ctx, time.Now().Add(time.Minute).UnixMilli())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = g.Page(ctx, s, "", 0); e != nil {
		t.Fatal(e)
	}
	backend.badPage = true
	if _, e = g.Page(ctx, s, "", 0); e == nil {
		t.Fatal("wrong snapshot accepted")
	}
	backend.weak = true
	if _, e = g.Observe(ctx, r.Key); e == nil {
		t.Fatal("weak native observation accepted")
	}
	backend.weak = false
	r.Payload = []byte(`{"fixture":false}`)
	r.Size = int64(len(r.Payload))
	r.SHA256 = Hash(r.Payload)
	if _, e = g.Create(ctx, r); e == nil || backend.creates != 1 {
		t.Fatal("immutable claim replaced")
	}
}
func TestNativeGatewayDoesNotReplayUncertainDispatch(t *testing.T) {
	for _, scenario := range []string{"commit-lost", "provider-reply-lost", "missing-expiry", "read-only-role"} {
		t.Run(scenario, func(t *testing.T) {
			var ops []string
			if scenario == "read-only-role" {
				ops = []string{"capabilities", "observe", "open"}
			}
			g, _, b, j, ctx := nativeServerFixture(t, ops)
			j.lost = scenario == "commit-lost"
			b.lostReply = scenario == "provider-reply-lost"
			b.missingExpiry = scenario == "missing-expiry"
			r := requestFor("action", "manifest.json", []byte(`{}`), time.Now().Add(time.Minute).UnixMilli())
			r.Target = g.Identity()
			if _, e := g.Create(ctx, r); e == nil {
				t.Fatal("uncertain operation reported success")
			}
			_, _ = g.Create(ctx, r)
			want := 0
			if scenario == "provider-reply-lost" {
				want = 1
			}
			if b.creates != want {
				t.Fatal("native send count", b.creates)
			}
			if (scenario == "missing-expiry" || scenario == "read-only-role") && j.calls != 0 {
				t.Fatal("unauthorized dispatch reservation")
			}
		})
	}
}
func TestNativeGatewayRejectsUnverifiedTransportAndMalformedInput(t *testing.T) {
	_, handler, b, j, _ := nativeServerFixture(t, nil)
	args, _ := Marshal(struct{}{})
	q := GatewayRequest{GatewayProtocol, strings.Repeat("a", 64), b.Identity(), b.Location(), "capabilities", args}
	raw, _ := Marshal(q)
	for _, scenario := range []string{"plaintext", "unverified", "wrong-identity", "unknown-field", "duplicate-field", "noncanonical", "traversal", "oversized", "write-expired"} {
		t.Run(scenario, func(t *testing.T) {
			body := raw
			request := q
			switch scenario {
			case "wrong-identity":
				request.Identity = ref("other")
				body, _ = Marshal(request)
			case "unknown-field":
				body = append([]byte(`{"unknown":true,`), raw[1:]...)
			case "duplicate-field":
				body = append([]byte(`{"Nonce":"different",`), raw[1:]...)
			case "noncanonical":
				body = append([]byte(" "), raw...)
			case "traversal":
				request.Operation = "observe"
				request.Arguments, _ = Marshal(struct{ Key string }{"../escape"})
				body, _ = Marshal(request)
			case "oversized":
				body = bytes.Repeat([]byte("x"), MaxDocument+1)
			case "write-expired":
				r := requestFor("expired", "manifest.json", []byte(`{}`), 1)
				r.Target = b.Identity()
				request.Operation = "conditional_create"
				request.Arguments, _ = Marshal(r)
				body, _ = Marshal(request)
			}
			r := httptest.NewRequest("POST", "https://isolated/recovery/v1", bytes.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			if scenario != "plaintext" {
				// Unit transport state only; the integration tests above use real mTLS.
				cert := &x509.Certificate{Raw: []byte("unit-certificate")}
				handler.config.Clients[Hash(cert.Raw)] = []string{"capabilities", "observe", "conditional_create"}
				r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{cert}}
				if scenario != "unverified" {
					r.TLS.VerifiedChains = [][]*x509.Certificate{{cert}}
				}
			} else {
				r.TLS = nil
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code == 200 || b.creates != 0 || j.calls != 0 || strings.Contains(w.Body.String(), "unknown") || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("unsafe request accepted", w.Code)
			}
		})
	}
}
func TestNativeGatewayConcurrentDuplicatesHaveOneSender(t *testing.T) {
	g, _, b, _, ctx := nativeServerFixture(t, nil)
	r := requestFor("concurrent", "manifest.json", []byte(`{}`), time.Now().Add(time.Minute).UnixMilli())
	r.Target = g.Identity()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = g.Create(ctx, r) }()
	}
	wg.Wait()
	if b.creates != 1 {
		t.Fatal("duplicate sends", b.creates)
	}
}
