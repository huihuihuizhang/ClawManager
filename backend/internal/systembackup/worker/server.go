package worker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"os"
	"time"
)

// ServeControl runs the internal worker relay on a caller-owned listener.
// Certificates and private keys are mounted files. There is no plaintext,
// anonymous, forwarded-client-certificate or public-admin endpoint fallback.
func ServeControl(ctx context.Context, listener net.Listener, caFile, certFile, keyFile string, authorizer Authorizer) error {
	if listener == nil || authorizer == nil {
		return ErrRequest
	}
	ca, e := os.ReadFile(caFile)
	if e != nil || len(ca) > 1<<20 {
		return ErrNotReady
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return ErrNotReady
	}
	certificate, e := tls.LoadX509KeyPair(certFile, keyFile)
	if e != nil {
		return ErrNotReady
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, Certificates: []tls.Certificate{certificate}}
	mux := http.NewServeMux()
	mux.Handle("/worker/v1", ControlHandler{Authorizer: authorizer})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192, BaseContext: func(net.Listener) context.Context { return ctx }}
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
	e = server.Serve(tls.NewListener(listener, tlsConfig))
	if errors.Is(e, http.ErrServerClosed) {
		return ctx.Err()
	}
	if e != nil {
		return ErrNotReady
	}
	return nil
}
