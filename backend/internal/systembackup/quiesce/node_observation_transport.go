package quiesce

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"sync"
	"time"
)

// NodeObservationHandler has no stop/start route. The serial limit avoids
// concurrent unbounded whole-host scans. Uncertainty returns no success DTO.
type NodeObservationHandler struct {
	Observer      *NodeObserver
	ControllerURI string
	busy          sync.Mutex
}

func observationJSON(r io.Reader, v any) error {
	b, e := io.ReadAll(io.LimitReader(r, 512<<10+1))
	if e != nil || len(b) > 512<<10 {
		return ErrNodeObservation
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return ErrNodeObservation
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return ErrNodeObservation
	}
	return nil
}
func (h *NodeObservationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	var request NodeObservationRequest
	if observationJSON(r.Body, &request) != nil || !time.Now().Before(request.Deadline) || request.Deadline.After(time.Now().Add(15*time.Second)) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithDeadline(r.Context(), request.Deadline)
	defer cancel()
	result, e := h.Observer.Observe(ctx, request)
	if e != nil {
		var failure NodeObservationFailure
		if errors.As(e, &failure) && observationPublicStage(failure.Stage) {
			w.Header().Set("X-Claw-Observation-Stage", failure.Stage)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
func ServeNodeObservations(ctx context.Context, listener net.Listener, caFile, certFile, keyFile string, h *NodeObservationHandler) error {
	if listener == nil || h == nil || h.Observer == nil || h.ControllerURI == "" {
		return ErrNodeObservation
	}
	u, e := url.Parse(h.ControllerURI)
	if e != nil || u.Scheme != "spiffe" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return ErrNodeObservation
	}
	if h.Observer.hostIdentity(ctx) != nil {
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
	mux.Handle("/observation/v1", h)
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
	e = server.Serve(tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, Certificates: []tls.Certificate{pair}}))
	if errors.Is(e, http.ErrServerClosed) {
		return ctx.Err()
	}
	if e != nil {
		return ErrNodeObservation
	}
	return nil
}

// NodeObservationClient keeps the established proof client's CA, exact server
// URI, hostname verification, no-proxy and no-redirect policy. It does not use
// ProofClient.Confirm's empty-list behavior or upgrade an old CRI-only receipt.
type NodeObservationClient struct{ proof *ProofClient }

func NewNodeObservationClient(endpoints map[string]ProofEndpoint, caFile, certFile, keyFile string) (*NodeObservationClient, error) {
	p, e := NewProofClient(endpoints, caFile, certFile, keyFile)
	if e != nil {
		return nil, ErrNodeObservation
	}
	for _, ep := range p.Endpoints {
		u, e := url.Parse(ep.URL)
		if e != nil || u.Path != "/observation/v1" || u.User != nil {
			return nil, ErrNodeObservation
		}
	}
	return &NodeObservationClient{proof: p}, nil
}
func (c *NodeObservationClient) Observe(ctx context.Context, in NodeObservationRequest) (NodeObservationResponse, error) {
	if len(in.SharedFrozenScopes) != 0 && in.Action != "stopped" && in.Action != "recovery-stopped" {
		return NodeObservationResponse{}, ErrNodeObservation
	}
	var out NodeObservationResponse
	if c == nil || c.proof == nil || ctx.Err() != nil {
		return out, ErrNodeObservation
	}
	if _, ok := ctx.Deadline(); !ok {
		return out, ErrNodeObservation
	}
	ep, ok := c.proof.Endpoints[in.Binding.Node]
	if !ok {
		return out, ErrNodeObservation
	}
	if !nodeObservationPhaseDataValid(in, in.Binding.Node) {
		return out, ErrNodeObservation
	}
	now := time.Now().UTC()
	until := now.Add(10 * time.Second)
	if d, _ := ctx.Deadline(); d.Before(until) {
		until = d
	}
	if !nodeObservationRecoveryAction(in.Action) && !until.Before(in.Binding.ExpiresAt) {
		until = in.Binding.ExpiresAt.Add(-time.Nanosecond)
	}
	if !now.Before(until) {
		return out, ErrNodeObservation
	}
	bounded, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	nonce := make([]byte, 32)
	if _, e := rand.Read(nonce); e != nil {
		return out, ErrNodeObservation
	}
	in.Version = "node-observation.v1"
	in.Deadline = until
	in.Nonce = hex.EncodeToString(nonce)
	raw, e := json.Marshal(in)
	if e != nil || len(raw) > 512<<10 {
		return out, ErrNodeObservation
	}
	transport := &http.Transport{Proxy: nil, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 10 * time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: c.proof.Roots, Certificates: []tls.Certificate{c.proof.Certificate}, VerifyConnection: func(s tls.ConnectionState) error {
		if len(s.VerifiedChains) == 0 || len(s.PeerCertificates) == 0 || len(s.PeerCertificates[0].URIs) != 1 || s.PeerCertificates[0].URIs[0].String() != ep.ServerURI {
			return ErrNodeObservation
		}
		return nil
	}}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(bounded, http.MethodPost, ep.URL, bytes.NewReader(raw))
	if e != nil {
		return out, ErrNodeObservation
	}
	req.Header.Set("Content-Type", "application/json")
	response, e := client.Do(req)
	if e != nil {
		return out, ErrNodeObservation
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		stage := response.Header.Get("X-Claw-Observation-Stage")
		if observationPublicStage(stage) {
			return out, observationFailure(stage)
		}
		return out, ErrNodeObservation
	}
	if response.StatusCode != http.StatusOK || observationJSON(response.Body, &out) != nil || out.Version != in.Version || out.Action != in.Action || out.Nonce != in.Nonce || out.RequestSHA256 != observationDigest(in) || observationDigest(out.Binding) != observationDigest(in.Binding) || out.BootID == "" || out.StartedAt.Before(now.Add(-2*time.Second)) || out.FinishedAt.Before(out.StartedAt) || out.FinishedAt.After(time.Now().Add(2*time.Second)) || !out.FinishedAt.Before(until) || !out.ValidUntil.Equal(until) || out.Anchor == "" {
		return NodeObservationResponse{}, ErrNodeObservation
	}
	var facts []string
	switch in.Action {
	case "prepare":
		facts = []string{"original_running_cri_processes_observed", "source_mount_identities_observed"}
		if in.Anchor != "" || out.Processes <= 0 {
			return NodeObservationResponse{}, ErrNodeObservation
		}
	case "stopped", "recovery-stopped":
		facts = []string{"original_cri_containers_exited", "original_process_scopes_absent", "no_observed_writable_source_fd_or_shared_mmap", "source_mount_identities_unchanged"}
		if len(in.SharedFrozenScopes) != 0 {
			facts = sharedFrozenObservationFacts()
		}
		if out.Anchor != in.Anchor || out.TasksChecked <= 0 || out.Files <= 0 {
			return NodeObservationResponse{}, ErrNodeObservation
		}
	case "recovery-source-stopped", "recovery-reconciled":
		facts = originalRecoveryFacts(in.Action)
		if out.Anchor != in.Anchor || out.TasksChecked <= 0 || out.Files <= 0 || out.Processes < len(in.RecoveredPods) {
			return NodeObservationResponse{}, ErrNodeObservation
		}
	case "recovered":
		facts = []string{"original_cri_containers_exited", "original_process_scopes_absent", "replacement_cri_processes_running", "source_mount_identities_unchanged"}
		if out.Anchor != in.Anchor || out.TasksChecked <= 0 || out.Processes <= 0 {
			return NodeObservationResponse{}, ErrNodeObservation
		}
	default:
		return NodeObservationResponse{}, ErrNodeObservation
	}
	if !reflect.DeepEqual(out.Facts, facts) || bounded.Err() != nil {
		return NodeObservationResponse{}, ErrNodeObservation
	}
	return out, nil
}

func observationPublicStage(stage string) bool {
	switch stage {
	case "recovery_actor_anchor", "recovery_current_process", "recovery_original_changed", "recovery_current_drift", "recovery_current_scope_unknown", "host_visibility", "original_cri_exit", "original_cri_process", "original_scope", "source_mount", "source_tree_visibility", "source_tree_drift", "source_mount_drift", "mount_visibility", "mount_parse", "task_identity", "task_identity_unreadable", "task_pidfd_unavailable", "task_enumeration", "original_process_present", "task_identity_lost", "task_scope_drift", "fd_visibility", "fd_identity_drift", "fdinfo_visibility", "fdinfo_parse", "maps_visibility", "maps_parse", "async_source_scope_unknown", "deleted_source_fd_unknown", "deleted_source_mapping_unknown", "writable_source_fd", "writable_source_mapping":
		return true
	}
	return false
}

// VerifiedNodeObservation can be made only by the concrete authenticated
// client. It is a short-lived native observation, not a held-lock capability.
// Its local Recheck performs no network I/O and never renews the observation.
type VerifiedNodeObservation struct {
	response               NodeObservationResponse
	originalRecoverySHA256 string
}

func (c *NodeObservationClient) ObserveVerified(ctx context.Context, in NodeObservationRequest) (*VerifiedNodeObservation, error) {
	r, e := c.Observe(ctx, in)
	if e != nil {
		return nil, e
	}
	scope := ""
	if originalRecoveryScopedPhase(in.Action) {
		scope, e = OriginalRecoveryScopeSHA256(in, in.RecoveryAffectedPods)
		if e != nil {
			return nil, e
		}
	}
	return &VerifiedNodeObservation{response: r, originalRecoverySHA256: scope}, nil
}
func (v *VerifiedNodeObservation) Response() NodeObservationResponse {
	if v == nil {
		return NodeObservationResponse{}
	}
	r := v.response
	r.Facts = append([]string(nil), r.Facts...)
	return r
}
func (v *VerifiedNodeObservation) Recheck(ctx context.Context, b ObservationBinding, action, bootID string, now time.Time) error {
	if originalRecoveryScopedPhase(action) {
		return ErrNodeObservation
	}
	return v.recheckOriginalBinding(ctx, b, action, bootID, now)
}
func (v *VerifiedNodeObservation) recheckOriginalBinding(ctx context.Context, b ObservationBinding, action, bootID string, now time.Time) error {
	if v == nil || ctx == nil || ctx.Err() != nil || now.IsZero() || v.response.RequestSHA256 == "" || observationDigest(v.response.Binding) != observationDigest(b) || v.response.Action != action || bootID == "" || v.response.BootID != bootID || now.Before(v.response.StartedAt) || !now.Before(v.response.ValidUntil) || !time.Now().Before(v.response.ValidUntil) {
		return ErrNodeObservation
	}
	return nil
}
