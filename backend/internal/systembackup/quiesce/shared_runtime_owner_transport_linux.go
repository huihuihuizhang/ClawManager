//go:build linux

package quiesce

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Separate mutating endpoint. NodeObservationHandler and its routes remain
// read-only. The concrete native owner cannot be replaced with a callback.
type SharedRuntimeNodeHandler struct {
	owner         *sharedRuntimeNodeOwner
	controllerURI string
}

func NewSharedRuntimeNodeHandler(o *NodeObserver, c SharedRuntimeNodeOwnerConfig) (*SharedRuntimeNodeHandler, error) {
	u, err := url.Parse(c.ControllerURI)
	if err != nil || u.Scheme != "spiffe" || u.Host == "" || u.Path == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, ErrNodeObservation
	}
	releases := map[string]sharedRuntimeAgentRelease{}
	for k, v := range c.Releases {
		if k != "openclaw" && k != "hermes" {
			return nil, ErrNodeObservation
		}
		releases[k] = sharedRuntimeAgentRelease{v.ExecutableSHA256, v.DataDir}
	}
	owner, err := newSharedRuntimeNodeOwner(o, c.CgroupMount, c.Directory, releases)
	if err != nil {
		return nil, err
	}
	return &SharedRuntimeNodeHandler{owner: owner, controllerURI: c.ControllerURI}, nil
}

// Call only after the serving loop and all in-flight requests have ended.
// Closing never thaws a source or erases recovery obligations.
func (h *SharedRuntimeNodeHandler) Close() {
	if h != nil && h.owner != nil {
		h.owner.mu.Lock()
		defer h.owner.mu.Unlock()
		h.owner.close()
	}
}

func (h *SharedRuntimeNodeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path != SharedRuntimeNodeRoute {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h == nil || h.owner == nil || h.controllerURI == "" || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.PeerCertificates[0].URIs) != 1 || r.TLS.PeerCertificates[0].URIs[0].String() != h.controllerURI {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	request, err := DecodeSharedRuntimeNodeRequest(r.Body)
	if err != nil || ValidateSharedRuntimeNodeRequest(request, time.Now().UTC()) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithDeadline(r.Context(), request.Deadline)
	defer cancel()
	result, err := h.owner.run(ctx, request)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func ServeSharedRuntimeNodeLifecycle(ctx context.Context, listener net.Listener, caFile, certFile, keyFile string, h *SharedRuntimeNodeHandler) error {
	if ctx == nil || ctx.Err() != nil || listener == nil || h == nil || h.owner == nil || h.owner.observer.hostIdentity(ctx) != nil {
		return ErrNodeObservation
	}
	pool, err := readProofRoots(caFile)
	if err != nil {
		return ErrNodeObservation
	}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return ErrNodeObservation
	}
	mux := http.NewServeMux()
	mux.Handle(SharedRuntimeNodeRoute, h)
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
				_ = server.Close()
			}
		}
	}()
	err = server.Serve(tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, Certificates: []tls.Certificate{pair}}))
	if errors.Is(err, http.ErrServerClosed) {
		return ctx.Err()
	}
	if err != nil {
		return ErrNodeObservation
	}
	return nil
}
