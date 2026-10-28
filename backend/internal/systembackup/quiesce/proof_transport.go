package quiesce

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"clawreef/internal/systembackup/flow"
)

type ProofRequest struct {
	Version  string        `json:"version"`
	Node     string        `json:"node"`
	Nonce    string        `json:"nonce"`
	Deadline time.Time     `json:"deadline"`
	Pods     []PodIdentity `json:"pods"`
}
type ProofResponse struct {
	Node, Nonce, RequestSHA256 string
	ObservedAt                 time.Time
	Stopped                    bool
}

func proofHash(r ProofRequest) string {
	b, _ := json.Marshal(r)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func readProofJSON(reader io.Reader, v any) error {
	b, e := io.ReadAll(io.LimitReader(reader, 256<<10+1))
	if e != nil || len(b) > 256<<10 {
		return flow.ErrQuiesce
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return flow.ErrQuiesce
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return flow.ErrQuiesce
	}
	return nil
}

// ProofHandler accepts exact controller certificate identities. It only asks
// the local CRIProver to inspect supplied container IDs; there is no exec,
// arbitrary runtime endpoint, filesystem path or lifecycle API in the request.
type ProofHandler struct {
	Prover         CRIProver
	ControllerURIs map[string]bool
}

func (h ProofHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.PeerCertificates[0].URIs) != 1 || !h.ControllerURIs[r.TLS.PeerCertificates[0].URIs[0].String()] {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	var request ProofRequest
	if readProofJSON(r.Body, &request) != nil || request.Version != "node-stop-proof.v1" || request.Node != h.Prover.Node || len(request.Nonce) != 64 || len(request.Pods) == 0 || len(request.Pods) > 1000 || !time.Now().Before(request.Deadline) || request.Deadline.After(time.Now().Add(15*time.Second)) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if _, e := hex.DecodeString(request.Nonce); e != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithDeadline(r.Context(), request.Deadline)
	defer cancel()
	if h.Prover.Confirm(ctx, request.Pods) != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ProofResponse{Node: request.Node, Nonce: request.Nonce, RequestSHA256: proofHash(request), ObservedAt: time.Now().UTC(), Stopped: true})
}

type ProofEndpoint struct{ URL, ServerURI string }
type ProofClient struct {
	Endpoints   map[string]ProofEndpoint
	Roots       *x509.CertPool
	Certificate tls.Certificate
}

func NewProofClient(endpoints map[string]ProofEndpoint, caFile, certFile, keyFile string) (*ProofClient, error) {
	roots, e := readProofRoots(caFile)
	if e != nil {
		return nil, e
	}
	pair, e := tls.LoadX509KeyPair(certFile, keyFile)
	if e != nil {
		return nil, flow.ErrNotReady
	}
	if len(endpoints) == 0 {
		return nil, flow.ErrNotReady
	}
	copied := make(map[string]ProofEndpoint, len(endpoints))
	for node, endpoint := range endpoints {
		u, e := url.Parse(endpoint.URL)
		identity, ie := url.Parse(endpoint.ServerURI)
		if node == "" || e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || ie != nil || identity.Scheme != "spiffe" || identity.Host == "" || identity.RawQuery != "" || identity.Fragment != "" {
			return nil, flow.ErrNotReady
		}
		copied[node] = endpoint
	}
	return &ProofClient{copied, roots, pair}, nil
}
func (c *ProofClient) Confirm(ctx context.Context, pods []PodIdentity) error {
	if c == nil || c.Roots == nil || len(c.Certificate.Certificate) == 0 {
		return flow.ErrNotReady
	}
	if _, ok := ctx.Deadline(); !ok {
		return flow.ErrNotReady
	}
	grouped := map[string][]PodIdentity{}
	for _, pod := range pods {
		if pod.Node == "" {
			return flow.ErrQuiesce
		}
		grouped[pod.Node] = append(grouped[pod.Node], pod)
	}
	// Empty is valid for an originally stopped workload; no Pod was observed.
	for node, group := range grouped {
		if e := c.confirmNode(ctx, node, group); e != nil {
			return e
		}
	}
	return ctx.Err()
}
func (c *ProofClient) confirmNode(ctx context.Context, node string, pods []PodIdentity) error {
	endpoint, ok := c.Endpoints[node]
	if !ok {
		return flow.ErrQuiesce
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	deadline, _ := bounded.Deadline()
	nonce := make([]byte, 32)
	if _, e := rand.Read(nonce); e != nil {
		return flow.ErrQuiesce
	}
	request := ProofRequest{Version: "node-stop-proof.v1", Node: node, Nonce: hex.EncodeToString(nonce), Deadline: deadline, Pods: pods}
	raw, _ := json.Marshal(request)
	transport := &http.Transport{Proxy: nil, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 10 * time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: c.Roots, Certificates: []tls.Certificate{c.Certificate}, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 || len(state.PeerCertificates[0].URIs) != 1 || state.PeerCertificates[0].URIs[0].String() != endpoint.ServerURI {
			return flow.ErrQuiesce
		}
		return nil
	}}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(bounded, http.MethodPost, endpoint.URL, bytes.NewReader(raw))
	if e != nil {
		return flow.ErrQuiesce
	}
	req.Header.Set("Content-Type", "application/json")
	started := time.Now()
	response, e := client.Do(req)
	if e != nil {
		return flow.ErrQuiesce
	}
	defer response.Body.Close()
	var proof ProofResponse
	if response.StatusCode != http.StatusOK || readProofJSON(response.Body, &proof) != nil || !proof.Stopped || proof.Node != node || proof.Nonce != request.Nonce || proof.RequestSHA256 != proofHash(request) || proof.ObservedAt.Before(started.Add(-2*time.Second)) || proof.ObservedAt.After(time.Now().Add(2*time.Second)) {
		return flow.ErrQuiesce
	}
	return bounded.Err()
}
func readProofRoots(path string) (*x509.CertPool, error) {
	file, e := os.Open(path)
	if e != nil {
		return nil, flow.ErrNotReady
	}
	defer file.Close()
	b, e := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if e != nil || len(b) > 1<<20 {
		return nil, flow.ErrNotReady
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, flow.ErrNotReady
	}
	return pool, nil
}
func ServeProof(ctx context.Context, listener net.Listener, caFile, certFile, keyFile string, handler ProofHandler) error {
	if listener == nil || handler.Prover.Node == "" || handler.Prover.Inspector == nil || len(handler.ControllerURIs) == 0 {
		return flow.ErrNotReady
	}
	pool, e := readProofRoots(caFile)
	if e != nil {
		return e
	}
	cert, e := tls.LoadX509KeyPair(certFile, keyFile)
	if e != nil {
		return flow.ErrNotReady
	}
	mux := http.NewServeMux()
	mux.Handle("/proof/v1", handler)
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 8192, BaseContext: func(net.Listener) context.Context { return ctx }}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-done:
			return
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if server.Shutdown(shutdown) != nil {
				server.Close()
			}
		}
	}()
	e = server.Serve(tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, Certificates: []tls.Certificate{cert}}))
	if errors.Is(e, http.ErrServerClosed) {
		return ctx.Err()
	}
	if e != nil {
		return flow.ErrNotReady
	}
	return nil
}
