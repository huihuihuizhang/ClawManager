package minionative

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestNativeSendOnceNeverReplaysAmbiguousWrite(t *testing.T) {
	for _, mode := range []string{"accepted-lost-reply", "retryable-server-error", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			var count atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				switch mode {
				case "accepted-lost-reply":
					c, _, e := w.(http.Hijacker).Hijack()
					if e == nil {
						_ = c.Close()
					}
				case "retryable-server-error":
					w.WriteHeader(503)
				case "redirect":
					w.Header().Set("Location", "/replay")
					w.WriteHeader(307)
				}
			}))
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			r, e := http.NewRequestWithContext(ctx, "PUT", server.URL+"/original", bytes.NewReader([]byte("fixed-original-request")))
			if e != nil {
				t.Fatal(e)
			}
			reply, e := SendOnce(client, r)
			if reply != nil {
				_, _ = io.Copy(io.Discard, reply.Body)
				_ = reply.Body.Close()
			}
			if mode == "accepted-lost-reply" && e == nil {
				t.Fatal("lost reply became acknowledged")
			}
			if count.Load() != 1 {
				t.Fatalf("ambiguous write replayed: %d", count.Load())
			}
		})
	}
}

func TestNativeSendOnceRefusesUnpinnedTransport(t *testing.T) {
	r, _ := http.NewRequest("PUT", "https://original.invalid/control", nil)
	for _, client := range []*http.Client{nil, {}, {Transport: &http.Transport{}}, {Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}} {
		if _, e := SendOnce(client, r); e == nil {
			t.Fatal("missing verified TLS transport accepted")
		}
	}
}
