package quiesce

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"clawreef/internal/systembackup/flow"
)

func StoppedProBaselineSHA256(b StoppedProBaseline) string { return observationDigest(b) }

// DATA hash only; original-state authenticity remains with D's actual owner.
func StoppedProOriginalStateSHA256(s flow.State) string { return observationDigest(s) }

type StoppedProNodeObservationHandler struct {
	Observer      *NodeObserver
	ControllerURI string
	busy          sync.Mutex
}

func stoppedProPublicStage(s string) bool {
	if observationPublicStage(s) {
		return true
	}
	switch s {
	case "stopped_pro_baseline_drift", "stopped_pro_cri_visibility", "stopped_pro_cri_inventory", "stopped_pro_cri_drift", "stopped_pro_cri_unknown", "stopped_pro_cri_mount_unknown", "stopped_pro_writable_cri_alias", "stopped_pro_writable_namespace_alias":
		return true
	}
	return false
}
func (h *StoppedProNodeObservationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	if h == nil || h.Observer == nil || h.ControllerURI == "" || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.PeerCertificates[0].URIs) != 1 || r.TLS.PeerCertificates[0].URIs[0].String() != h.ControllerURI {
		w.WriteHeader(403)
		return
	}
	if !h.busy.TryLock() {
		w.WriteHeader(503)
		return
	}
	defer h.busy.Unlock()
	var in StoppedProNodeObservationRequest
	if observationJSON(r.Body, &in) != nil || !time.Now().Before(in.Deadline) || in.Deadline.After(time.Now().Add(15*time.Second)) {
		w.WriteHeader(400)
		return
	}
	ctx, cancel := context.WithDeadline(r.Context(), in.Deadline)
	defer cancel()
	out, e := h.Observer.ObserveStoppedPro(ctx, in)
	if e != nil {
		var f NodeObservationFailure
		if errors.As(e, &f) && stoppedProPublicStage(f.Stage) {
			w.Header().Set("X-Claw-Observation-Stage", f.Stage)
		}
		w.WriteHeader(503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
func ServeStoppedProNodeObservations(ctx context.Context, l net.Listener, ca, cert, key string, h *StoppedProNodeObservationHandler) error {
	if l == nil || h == nil || h.Observer == nil || len(h.Observer.key) != 32 || h.Observer.hostIdentity(ctx) != nil {
		return ErrNodeObservation
	}
	u, e := url.Parse(h.ControllerURI)
	if e != nil || u.Scheme != "spiffe" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return ErrNodeObservation
	}
	roots, e := readProofRoots(ca)
	if e != nil {
		return e
	}
	pair, e := tls.LoadX509KeyPair(cert, key)
	if e != nil {
		return ErrNodeObservation
	}
	mux := http.NewServeMux()
	mux.Handle("/stopped-pro-observation/v1", h)
	s := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 8192, BaseContext: func(net.Listener) context.Context { return ctx }}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-done:
			return
		case <-ctx.Done():
			stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if s.Shutdown(stop) != nil {
				s.Close()
			}
		}
	}()
	e = s.Serve(tls.NewListener(l, &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, Certificates: []tls.Certificate{pair}}))
	if errors.Is(e, http.ErrServerClosed) {
		return ctx.Err()
	}
	if e != nil {
		return ErrNodeObservation
	}
	return nil
}

type StoppedProNodeObservationClient struct{ proof *ProofClient }

func NewStoppedProNodeObservationClient(endpoints map[string]ProofEndpoint, ca, cert, key string) (*StoppedProNodeObservationClient, error) {
	p, e := NewProofClient(endpoints, ca, cert, key)
	if e != nil {
		return nil, e
	}
	for _, ep := range p.Endpoints {
		u, e := url.Parse(ep.URL)
		if e != nil || u.Path != "/stopped-pro-observation/v1" {
			return nil, ErrNodeObservation
		}
	}
	return &StoppedProNodeObservationClient{proof: p}, nil
}

// The private handle authenticates only an independent current native sample.
// The original CURRENT baseline, unique node mapping and continuously held
// all-writer/recovery authority must be authenticated by D separately.
type VerifiedStoppedProNodeObservation struct {
	response StoppedProNodeObservationResponse
}

func (v *VerifiedStoppedProNodeObservation) Response() StoppedProNodeObservationResponse {
	if v == nil {
		return StoppedProNodeObservationResponse{}
	}
	return v.response
}
func (v *VerifiedStoppedProNodeObservation) Recheck(ctx context.Context, b ObservationBinding, phase, boot, baselineSHA, originalReservationSHA, originalStateSHA, nativeScopeSHA string, now time.Time) error {
	if v == nil || ctx == nil || ctx.Err() != nil || observationDigest(b) != observationDigest(v.response.Binding) || phase != v.response.Action || boot == "" || boot != v.response.BootID || baselineSHA != v.response.BaselineSHA256 || originalReservationSHA != v.response.OriginalReservationIdentitySHA256 || originalStateSHA != v.response.OriginalStateSHA256 || nativeScopeSHA != v.response.NativeScopeSHA256 || now.Before(v.response.StartedAt) || !now.Before(v.response.ValidUntil) || !time.Now().Before(v.response.ValidUntil) {
		return ErrNodeObservation
	}
	return nil
}
func (c *StoppedProNodeObservationClient) ObserveWriter(ctx context.Context, in StoppedProNodeObservationRequest, original flow.State) (*VerifiedStoppedProNodeObservation, error) {
	if original.Running || original.UID != in.Baseline.SourceKey || original.Generation <= 0 || uint64(original.Generation) != in.Baseline.InstanceGeneration || original.Checkpoint != StoppedProBaselineSHA256(in.Baseline) {
		return nil, ErrNodeObservation
	}
	in.OriginalStateSHA256 = StoppedProOriginalStateSHA256(original)
	if in.NativeScopeSHA256 != StoppedProNativeScopeSHA256(in) {
		return nil, ErrNodeObservation
	}
	return c.ObserveVerified(ctx, in)
}
func (c *StoppedProNodeObservationClient) ObserveVerified(ctx context.Context, in StoppedProNodeObservationRequest) (*VerifiedStoppedProNodeObservation, error) {
	if c == nil || c.proof == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrNodeObservation
	}
	d, ok := ctx.Deadline()
	if !ok {
		return nil, ErrNodeObservation
	}
	ep, ok := c.proof.Endpoints[in.Binding.Node]
	if !ok {
		return nil, ErrNodeObservation
	}
	if _, e := stoppedProBaselinePaths(in); e != nil {
		return nil, e
	}
	now := time.Now().UTC()
	until := now.Add(10 * time.Second)
	if d.Before(until) {
		until = d
	}
	recovery := in.Action == "recovery-stopped" || in.Action == "recovered-stopped"
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
		return nil, e
	}
	in.Version = StoppedProObservationProtocol
	in.Nonce = hex.EncodeToString(nonce)
	in.Deadline = until
	raw, e := json.Marshal(in)
	if e != nil || len(raw) > 512<<10 {
		return nil, ErrNodeObservation
	}
	t := &http.Transport{Proxy: nil, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 10 * time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: c.proof.Roots, Certificates: []tls.Certificate{c.proof.Certificate}, VerifyConnection: func(s tls.ConnectionState) error {
		if len(s.VerifiedChains) == 0 || len(s.PeerCertificates) == 0 || len(s.PeerCertificates[0].URIs) != 1 || s.PeerCertificates[0].URIs[0].String() != ep.ServerURI {
			return ErrNodeObservation
		}
		return nil
	}}}
	defer t.CloseIdleConnections()
	client := &http.Client{Transport: t, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(bounded, http.MethodPost, ep.URL, bytes.NewReader(raw))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/json")
	res, e := client.Do(req)
	if e != nil {
		return nil, ErrNodeObservation
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		stage := res.Header.Get("X-Claw-Observation-Stage")
		if stoppedProPublicStage(stage) {
			return nil, observationFailure(stage)
		}
		return nil, ErrNodeObservation
	}
	var out StoppedProNodeObservationResponse
	if observationJSON(res.Body, &out) != nil || out.Version != in.Version || out.Action != in.Action || out.Nonce != in.Nonce || out.RequestSHA256 != observationDigest(in) || observationDigest(out.Binding) != observationDigest(in.Binding) || out.BaselineSHA256 != StoppedProBaselineSHA256(in.Baseline) || out.OriginalReservationIdentitySHA256 != in.OriginalReservationIdentitySHA256 || out.OriginalStateSHA256 != in.OriginalStateSHA256 || out.NativeScopeSHA256 != in.NativeScopeSHA256 || out.Anchor == "" || out.BootID == "" || out.StartedAt.Before(now.Add(-2*time.Second)) || out.FinishedAt.Before(out.StartedAt) || out.FinishedAt.After(time.Now().Add(2*time.Second)) || !out.FinishedAt.Before(until) || !out.ValidUntil.Equal(until) || out.TasksChecked <= 0 || out.Files <= 0 || !validObservationHash(out.CRIObservationSHA256) || in.Action != "prepare" && out.Anchor != in.Anchor || bounded.Err() != nil {
		return nil, ErrNodeObservation
	}
	return &VerifiedStoppedProNodeObservation{response: out}, nil
}
