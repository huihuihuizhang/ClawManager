package recovery

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GatewayProtocol is an explicit provider-owner protocol, not the S3 API.
// The service must implement native expiry/conditional-write/snapshot proofs.
const GatewayProtocol = "clawmanager-recovery-provider.v1"

type GatewayConfig struct {
	Endpoint      string
	Identity      Reference
	Location      Locator
	DiscoveryMode string
	AllowAppend   bool
}

func (c GatewayConfig) Validate() error {
	u, e := url.Parse(c.Endpoint)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || !c.Identity.valid() || !c.Location.valid() {
		return ErrContract
	}
	if c.DiscoveryMode != "known_record_only" && c.DiscoveryMode != "inventory_manifest" && c.DiscoveryMode != "provider_snapshot" {
		return ErrContract
	}
	return nil
}

type GatewayRequest struct {
	Schema    string
	Nonce     string
	Identity  Reference
	Location  Locator
	Operation string
	Arguments json.RawMessage
}
type GatewayResponse struct {
	Schema        string
	Nonce         string
	RequestSHA256 string
	Identity      Reference
	ValidUntil    int64
	Payload       json.RawMessage
}
type Gateway struct {
	config    GatewayConfig
	client    *http.Client
	transport *http.Transport
	now       func() int64
}

func NewGateway(c GatewayConfig, ca, certificate, key []byte) (*Gateway, error) {
	if c.Validate() != nil {
		return nil, ErrContract
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, ErrContract
	}
	pair, e := tls.X509KeyPair(certificate, key)
	if e != nil {
		return nil, ErrContract
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{pair}}, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second, DisableCompression: true}
	return &Gateway{c, &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, transport, func() int64 { return time.Now().UnixMilli() }}, nil
}
func (g *Gateway) Close()              { g.transport.CloseIdleConnections() }
func (g *Gateway) Identity() Reference { return g.config.Identity }
func (g *Gateway) Location() Locator   { return g.config.Location }
func (g *Gateway) send(ctx context.Context, operation string, args any) (*http.Response, GatewayRequest, []byte, error) {
	if g == nil || g.client == nil || ctx.Err() != nil {
		return nil, GatewayRequest{}, nil, ErrUnavailable
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, GatewayRequest{}, nil, ErrContract
	}
	var nonce [32]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return nil, GatewayRequest{}, nil, ErrUnavailable
	}
	a, e := Marshal(args)
	if e != nil {
		return nil, GatewayRequest{}, nil, e
	}
	r := GatewayRequest{GatewayProtocol, hex.EncodeToString(nonce[:]), g.config.Identity, g.config.Location, operation, a}
	b, e := Marshal(r)
	if e != nil {
		return nil, r, nil, e
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(g.config.Endpoint, "/")+"/recovery/v1", bytes.NewReader(b))
	if e != nil {
		return nil, r, nil, ErrContract
	}
	req.Header.Set("Content-Type", "application/json")
	// No retries, including an uncertain native create; Finalizer owns recovery.
	response, e := g.client.Do(req)
	if e != nil {
		return nil, r, nil, ErrUnavailable
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		return nil, r, nil, ErrUnavailable
	}
	return response, r, b, nil
}
func (g *Gateway) response(raw []byte, request GatewayRequest, sent []byte, out any) error {
	var response GatewayResponse
	if decode(raw, &response) != nil || response.Schema != GatewayProtocol || response.Nonce != request.Nonce || response.RequestSHA256 != Hash(sent) || response.Identity != g.config.Identity || response.ValidUntil <= g.now() || response.ValidUntil > g.now()+60000 || decode(response.Payload, out) != nil {
		return ErrUnavailable
	}
	return nil
}
func (g *Gateway) call(ctx context.Context, op string, args, out any) error {
	r, q, b, e := g.send(ctx, op, args)
	if e != nil {
		return e
	}
	defer r.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(r.Body, MaxDocument+1))
	if e != nil || len(raw) > MaxDocument {
		return ErrUnavailable
	}
	return g.response(raw, q, b, out)
}
func (g *Gateway) Probe(ctx context.Context, appendWrite, fullScan bool) error {
	if appendWrite && !g.config.AllowAppend || fullScan && g.config.DiscoveryMode == "known_record_only" {
		return ErrUnavailable
	}
	var capabilities []Capability
	if e := g.call(ctx, "capabilities", struct{}{}, &capabilities); e != nil {
		return e
	}
	return RequireCapabilities(capabilities, g.config.Identity, g.now(), appendWrite, fullScan)
}
func (g *Gateway) Observe(ctx context.Context, key string) (Observation, error) {
	if !safeKey(key) {
		return Observation{}, ErrContract
	}
	var o Observation
	if e := g.Probe(ctx, false, false); e != nil {
		return o, e
	}
	if e := g.call(ctx, "observe", struct{ Key string }{key}, &o); e != nil {
		return o, e
	}
	if !o.decisive(key, g.now()) {
		return Observation{}, ErrUnavailable
	}
	return o, nil
}
func (g *Gateway) Open(ctx context.Context, o Object) (io.ReadCloser, error) {
	if !o.valid() {
		return nil, ErrContract
	}
	r, q, b, e := g.send(ctx, "open", o)
	if e != nil {
		return nil, e
	}
	// Receipt authenticates the exact immutable object before streaming bytes.
	var actual Object
	if g.response([]byte(r.Header.Get("X-Recovery-Receipt")), q, b, &actual) != nil || actual != o || r.ContentLength != o.Size {
		r.Body.Close()
		return nil, ErrUnavailable
	}
	return r.Body, nil // caller must verify size/hash and every encrypted frame
}
func (g *Gateway) Create(ctx context.Context, r Request) (Observation, error) {
	if !g.config.AllowAppend || r.Validate() != nil || r.Target != g.config.Identity || g.now() >= r.Deadline {
		return Observation{}, ErrUnavailable
	}
	if e := g.Probe(ctx, true, false); e != nil {
		return Observation{}, e
	}
	if g.now() >= r.Deadline {
		return Observation{}, ErrUnavailable
	}
	var o Observation
	e := g.call(ctx, "conditional_create", r, &o)
	if e != nil {
		return o, e
	}
	if !o.decisive(r.Key, g.now()) {
		return Observation{}, ErrUnavailable
	}
	return o, nil
}
func (g *Gateway) Begin(ctx context.Context, deadline int64) (Snapshot, error) {
	if e := g.Probe(ctx, false, true); e != nil {
		return Snapshot{}, e
	}
	var s Snapshot
	e := g.call(ctx, "begin_snapshot", struct {
		Deadline int64
		Mode     string
	}{deadline, g.config.DiscoveryMode}, &s)
	if e != nil {
		return s, e
	}
	if s.Mode != g.config.DiscoveryMode || s.Root != g.config.Identity || s.ExpiresAt < deadline {
		return Snapshot{}, ErrContract
	}
	return s, nil
}
func (g *Gateway) Page(ctx context.Context, s Snapshot, cursor string, n int64) (Page, error) {
	if s.Root != g.config.Identity || s.Mode != g.config.DiscoveryMode || s.ExpiresAt <= g.now() || n < 0 || len(cursor) > 4096 {
		return Page{}, ErrContract
	}
	if e := g.Probe(ctx, false, true); e != nil {
		return Page{}, e
	}
	var p Page
	e := g.call(ctx, "snapshot_page", struct {
		Snapshot Snapshot
		Cursor   string
		Number   int64
	}{s, cursor, n}, &p)
	return p, e
}
