package main

import (
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestBackupLoopbackTLSRequiresActualHandshakeAndClosedAddress(t *testing.T) {
	seed := httptest.NewTLSServer(http.NotFoundHandler())
	defer seed.Close()
	pair := seed.TLS.Certificates[0]
	key, e := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key")
	if os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}), 0600) != nil || os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600) != nil {
		t.Fatal("local TLS fixture")
	}
	values := map[string]string{"SYSTEM_BACKUP_API_TLS_ADDRESS": "127.0.0.1:9002", "SYSTEM_BACKUP_API_TLS_CERT_FILE": certFile, "SYSTEM_BACKUP_API_TLS_KEY_FILE": keyFile}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || !r.TLS.HandshakeComplete {
			w.WriteHeader(http.StatusUpgradeRequired)
			return
		}
		_, _ = io.WriteString(w, "actual_tls")
	})
	listener, e := newSystemBackupLoopbackTLS(handler, func(k string) string { return values[k] })
	if e != nil || listener == nil || listener.Addr != "127.0.0.1:9002" {
		t.Fatal(e)
	}
	secure := httptest.NewUnstartedServer(listener.Handler)
	secure.TLS = listener.TLSConfig
	secure.StartTLS()
	defer secure.Close()
	response, e := secure.Client().Get(secure.URL)
	if e != nil {
		t.Fatal(e)
	}
	body, e := io.ReadAll(response.Body)
	response.Body.Close()
	if e != nil || response.StatusCode != 200 || string(body) != "actual_tls" {
		t.Fatal("actual TLS peer not observed")
	}
	plain := httptest.NewServer(listener.Handler)
	defer plain.Close()
	request, e := http.NewRequest(http.MethodGet, plain.URL, nil)
	if e != nil {
		t.Fatal(e)
	}
	request.Header.Set("X-Forwarded-Proto", "https")
	response, e = plain.Client().Do(request)
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUpgradeRequired {
		t.Fatal("forwarded header manufactured Request.TLS")
	}
	for _, address := range []string{"0.0.0.0:9002", "127.0.0.1:9001", "localhost:9002"} {
		values["SYSTEM_BACKUP_API_TLS_ADDRESS"] = address
		if listener, e := newSystemBackupLoopbackTLS(handler, func(k string) string { return values[k] }); e == nil || listener != nil {
			t.Fatal("unselected public/arbitrary listener accepted")
		}
	}
}
