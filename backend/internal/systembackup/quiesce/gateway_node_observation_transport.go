package quiesce

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"sync"
	"time"

	"clawreef/internal/systembackup/flow"
)

// This separate route leaves the frozen whole-Pod protocol untouched. Neither
// route can issue Agent control calls, change its journals, or acquire a lock.
type GatewayNodeObservationHandler struct {
	Observer      *NodeObserver
	ControllerURI string
	busy          sync.Mutex
}

func (h *GatewayNodeObservationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h == nil || h.Observer == nil || h.ControllerURI == "" || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.PeerCertificates[0].URIs) != 1 || r.TLS.PeerCertificates[0].URIs[0].String() != h.ControllerURI {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if !h.busy.TryLock() {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer h.busy.Unlock()
	var request GatewayNodeObservationRequest
	if observationJSON(r.Body, &request) != nil || !time.Now().Before(request.Deadline) || request.Deadline.After(time.Now().Add(15*time.Second)) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithDeadline(r.Context(), request.Deadline)
	defer cancel()
	result, e := h.Observer.ObserveGateway(ctx, request)
	if e != nil {
		var f NodeObservationFailure
		if errors.As(e, &f) && gatewayPublicStage(f.Stage) {
			w.Header().Set("X-Claw-Observation-Stage", f.Stage)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
func gatewayPublicStage(s string) bool {
	if observationPublicStage(s) {
		return true
	}
	switch s {
	case "gateway_journal_path", "gateway_journal_trust", "gateway_journal_drift", "gateway_journal_schema", "gateway_lock_visibility", "gateway_lock_owner", "gateway_lock_not_held", "gateway_agent_cri", "gateway_original_identity", "gateway_original_running", "gateway_original_stopped", "gateway_checkpoint", "gateway_monitor_missing", "gateway_monitor_owner", "gateway_private_init_ambiguous", "gateway_private_init_missing", "gateway_scope_drift", "gateway_agent_or_journal_replaced", "gateway_v1_reservation", "gateway_v1_successor", "gateway_old_scope_reused", "gateway_v2_reservation", "gateway_v2_completion", "gateway_v2_release_unconfirmed", "gateway_unexpected_writable_mount":
		return true
	}
	return false
}
func ServeGatewayNodeObservations(ctx context.Context, listener net.Listener, caFile, certFile, keyFile string, h *GatewayNodeObservationHandler) error {
	if listener == nil || h == nil || h.Observer == nil || h.Observer.hostIdentity(ctx) != nil {
		return ErrNodeObservation
	}
	u, e := url.Parse(h.ControllerURI)
	if e != nil || u.Scheme != "spiffe" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return ErrNodeObservation
	}
	pool, e := readProofRoots(caFile)
	if e != nil {
		return ErrNodeObservation
	}
	pair, e := tls.LoadX509KeyPair(certFile, keyFile)
	if e != nil {
		return ErrNodeObservation
	}
	mux := http.NewServeMux()
	mux.Handle("/gateway-observation/v1", h)
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 8192, BaseContext: func(net.Listener) context.Context { return ctx }}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-done:
			return
		case <-ctx.Done():
			stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if server.Shutdown(stop) != nil {
				server.Close()
			}
		}
	}()
	e = server.Serve(tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, Certificates: []tls.Certificate{pair}}))
	if errors.Is(e, http.ErrServerClosed) {
		return ctx.Err()
	}
	if e != nil {
		return ErrNodeObservation
	}
	return nil
}

type GatewayNodeObservationClient struct{ proof *ProofClient }

func NewGatewayNodeObservationClient(endpoints map[string]ProofEndpoint, caFile, certFile, keyFile string) (*GatewayNodeObservationClient, error) {
	p, e := NewProofClient(endpoints, caFile, certFile, keyFile)
	if e != nil {
		return nil, ErrNodeObservation
	}
	for _, endpoint := range p.Endpoints {
		u, e := url.Parse(endpoint.URL)
		if e != nil || u.Path != "/gateway-observation/v1" {
			return nil, ErrNodeObservation
		}
	}
	return &GatewayNodeObservationClient{proof: p}, nil
}

// VerifiedGatewayNodeObservation is minted only by a concrete authenticated
// native HTTP roundtrip. It is not Agent lock ownership or maintenance authority.
type VerifiedGatewayNodeObservation struct {
	response              GatewayNodeObservationResponse
	originalRestartSHA256 string
}

func (v *VerifiedGatewayNodeObservation) Response() GatewayNodeObservationResponse {
	if v == nil {
		return GatewayNodeObservationResponse{}
	}
	r := v.response
	r.Facts = append([]string(nil), r.Facts...)
	return r
}
func (v *VerifiedGatewayNodeObservation) Recheck(ctx context.Context, b ObservationBinding, phase, boot, originalStateSHA, rawSHA, completionSHA string, now time.Time) error {
	if v == nil || ctx == nil || ctx.Err() != nil || observationDigest(b) != observationDigest(v.response.Binding) || phase != v.response.Action || boot == "" || boot != v.response.BootID || originalStateSHA != v.response.OriginalStateSHA256 || rawSHA != v.response.AgentRawSHA256 || completionSHA != v.response.CompletionRawSHA256 || now.Before(v.response.StartedAt) || !now.Before(v.response.ValidUntil) || !time.Now().Before(v.response.ValidUntil) {
		return ErrNodeObservation
	}
	return nil
}

// ObserveWriter is the concrete I/O entry for D's original flow callbacks.
// It binds the unchanged original Running/UID/generation/checkpoint state; D's
// original authority still authenticates that state and durably records Raw.
func (c *GatewayNodeObservationClient) ObserveWriter(ctx context.Context, in GatewayNodeObservationRequest, original flow.State) (*VerifiedGatewayNodeObservation, error) {
	_, pod, _, _, _, instance, _, generation := gatewayOriginalIdentity(in)
	if original.UID != pod+"/gw-"+fmt.Sprint(instance)+"-"+fmt.Sprint(generation) || original.Generation != int64(generation) || original.Checkpoint == "" || original.Running != (in.Binding.Kind == GatewayNodeRunning) || in.Stopped != nil && original.Checkpoint != in.Stopped.CheckpointSHA256 {
		return nil, ErrNodeObservation
	}
	in.OriginalStateSHA256 = observationDigest(original)
	return c.ObserveVerified(ctx, in)
}
func (c *GatewayNodeObservationClient) ObserveVerified(ctx context.Context, in GatewayNodeObservationRequest) (*VerifiedGatewayNodeObservation, error) {
	if c == nil || c.proof == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrNodeObservation
	}
	d, ok := ctx.Deadline()
	if !ok {
		return nil, ErrNodeObservation
	}
	endpoint, ok := c.proof.Endpoints[in.Binding.Node]
	if !ok {
		return nil, ErrNodeObservation
	}
	now := time.Now().UTC()
	until := now.Add(10 * time.Second)
	if d.Before(until) {
		until = d
	}
	recovery := in.Action == "recovery-stopped" || in.Action == "recovered" || in.Action == "recovered-stopped"
	if !recovery && !until.Before(in.Binding.ExpiresAt) {
		until = in.Binding.ExpiresAt.Add(-time.Nanosecond)
	}
	if !now.Before(until) {
		return nil, ErrNodeObservation
	}
	bounded, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	nonce := make([]byte, 32)
	if _, e := rand.Read(nonce); e != nil {
		return nil, ErrNodeObservation
	}
	in.Version = GatewayNodeObservationProtocol
	in.Nonce = hex.EncodeToString(nonce)
	in.Deadline = until
	if !validObservationHash(in.OriginalStateSHA256) || gatewayDataReceipt(in) != nil {
		return nil, ErrNodeObservation
	}
	raw, e := json.Marshal(in)
	if e != nil || len(raw) > 512<<10 {
		return nil, ErrNodeObservation
	}
	transport := &http.Transport{Proxy: nil, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 10 * time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: c.proof.Roots, Certificates: []tls.Certificate{c.proof.Certificate}, VerifyConnection: func(s tls.ConnectionState) error {
		if len(s.VerifiedChains) == 0 || len(s.PeerCertificates) == 0 || len(s.PeerCertificates[0].URIs) != 1 || s.PeerCertificates[0].URIs[0].String() != endpoint.ServerURI {
			return ErrNodeObservation
		}
		return nil
	}}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(bounded, http.MethodPost, endpoint.URL, bytes.NewReader(raw))
	if e != nil {
		return nil, ErrNodeObservation
	}
	req.Header.Set("Content-Type", "application/json")
	res, e := client.Do(req)
	if e != nil {
		return nil, ErrNodeObservation
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		stage := res.Header.Get("X-Claw-Observation-Stage")
		if gatewayPublicStage(stage) {
			return nil, observationFailure(stage)
		}
		return nil, ErrNodeObservation
	}
	var out GatewayNodeObservationResponse
	if observationJSON(res.Body, &out) != nil || out.Version != in.Version || out.Action != in.Action || out.Nonce != in.Nonce || out.RequestSHA256 != observationDigest(in) || out.OriginalStateSHA256 != in.OriginalStateSHA256 || observationDigest(out.Binding) != observationDigest(in.Binding) || out.AgentRawSHA256 != observationRawDigest(in.Raw) || out.CompletionRawSHA256 != observationRawDigest(in.CompletionRaw) || out.Anchor == "" || out.BootID == "" || out.StartedAt.Before(now.Add(-2*time.Second)) || out.FinishedAt.Before(out.StartedAt) || out.FinishedAt.After(time.Now().Add(2*time.Second)) || !out.FinishedAt.Before(until) || !out.ValidUntil.Equal(until) || !reflect.DeepEqual(out.Facts, gatewayObservationFacts(in.Binding.Kind, in.Action)) || len(out.Facts) == 0 {
		return nil, ErrNodeObservation
	}
	if in.Action != "prepare" && out.Anchor != in.Anchor || (in.Action != "prepare" || in.Stopped != nil) && (out.TasksChecked <= 0 || out.Files <= 0) || bounded.Err() != nil {
		return nil, ErrNodeObservation
	}
	originalRestart, e := gatewayOriginalRestartFromAnchor(in, out)
	if e != nil {
		return nil, ErrNodeObservation
	}
	return &VerifiedGatewayNodeObservation{response: out, originalRestartSHA256: originalRestart}, nil
}
