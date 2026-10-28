package worker

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type authorizeFunc func(context.Context, string, ControlRequest) (Lease, error)

func (f authorizeFunc) Authorize(ctx context.Context, identity string, r ControlRequest) (Lease, error) {
	return f(ctx, identity, r)
}

func mutualTLSFixture(t *testing.T, handler http.Handler) (*ControlClient, *httptest.Server) {
	t.Helper()
	now := time.Now()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated fixture CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, e := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	issue := func(serial int64, client bool) ([]byte, []byte, tls.Certificate) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if client {
			uri, _ := url.Parse("spiffe://clawmanager/backup/fixture")
			tpl.URIs = []*url.URL{uri}
			tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		} else {
			tpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
			tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}
		der, e := x509.CreateCertificate(rand.Reader, tpl, caCert, &key.PublicKey, caKey)
		if e != nil {
			t.Fatal(e)
		}
		keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
		cp := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		kp := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		pair, e := tls.X509KeyPair(cp, kp)
		if e != nil {
			t.Fatal(e)
		}
		return cp, kp, pair
	}
	_, _, serverCert := issue(2, false)
	clientPEM, keyPEM, _ := issue(3, true)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	server.StartTLS()
	t.Cleanup(server.Close)
	dir := t.TempDir()
	for n, b := range map[string][]byte{"ca.pem": caPEM, "client.pem": clientPEM, "client.key": keyPEM} {
		if e = os.WriteFile(filepath.Join(dir, n), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	client, e := NewControlClient(server.URL, filepath.Join(dir, "ca.pem"), filepath.Join(dir, "client.pem"), filepath.Join(dir, "client.key"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(client.Close)
	return client, server
}
func TestMTLSWorkerAuthorizationBindsIdentityAndFullInvocation(t *testing.T) {
	r, env, _ := fixture(t)
	i := Invocation{Request: r, WorkspacePath: env.Workspace.Name(), StagingPath: env.Staging.Name()}
	expected, _ := i.Hash()
	var actions []string
	h := ControlHandler{Authorizer: authorizeFunc(func(_ context.Context, identity string, r ControlRequest) (Lease, error) {
		if identity != "spiffe://clawmanager/backup/fixture" || r.InvocationSHA256 != expected {
			return Lease{}, ErrExecution
		}
		actions = append(actions, r.Action+":"+r.Point)
		lease := Lease{InvocationSHA256: expected, ExpiresAt: time.Now().Add(30 * time.Second)}
		if r.Action == "acquire" {
			lease.DEK = bytes.Repeat([]byte{19}, 32)
		}
		return lease, nil
	})}
	client, _ := mutualTLSFixture(t, h)
	ctx := context.Background()
	if e := client.Ready(ctx, i); e != nil {
		t.Fatal(e)
	}
	lease, e := client.Acquire(ctx, i)
	if e != nil || len(lease.DEK) != 32 {
		t.Fatal("key not authorized", e)
	}
	defer clear(lease.DEK)
	env.Key = lease.DEK
	env.Check = func(ctx context.Context, p string, _ Request) error { return client.Check(ctx, i, p) }
	result, e := Run(ctx, r, env)
	if e != nil {
		t.Fatal("real mTLS control + local worker failed", e)
	}
	if e = client.Complete(ctx, i, result); e != nil {
		t.Fatal("completion relay failed", e)
	}
	if len(actions) != 7 || actions[6] != "complete:" {
		t.Fatalf("missing control boundaries: %v", actions)
	}
	bad := result
	bad.Quarantined = true
	if e = client.Complete(ctx, i, bad); e == nil || len(actions) != 7 {
		t.Fatal("capture worker reported a restore result")
	}
	changed := i
	changed.StagingPath = "/unapproved"
	if _, e = client.Acquire(ctx, changed); e == nil {
		t.Fatal("different root acquired same task key")
	}
}
func TestControlRequiresVerifiedClientAndMatchingFreshLease(t *testing.T) {
	r, env, _ := fixture(t)
	i := Invocation{Request: r, WorkspacePath: env.Workspace.Name(), StagingPath: env.Staging.Name()}
	hash, _ := i.Hash()
	request := ControlRequest{Invocation: i, InvocationSHA256: hash, Action: "acquire"}
	body, _ := json.Marshal(request)
	called := false
	handler := ControlHandler{Authorizer: authorizeFunc(func(context.Context, string, ControlRequest) (Lease, error) { called = true; return Lease{}, nil })}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "https://fixture", bytes.NewReader(body)))
	if rec.Code != http.StatusForbidden || called {
		t.Fatal("unverified client authorized")
	}
	for _, mode := range []string{"expired", "wrong-hash", "extra-key", "not-ready"} {
		t.Run(mode, func(t *testing.T) {
			h := ControlHandler{Authorizer: authorizeFunc(func(_ context.Context, _ string, r ControlRequest) (Lease, error) {
				l := Lease{InvocationSHA256: r.InvocationSHA256, ExpiresAt: time.Now().Add(30 * time.Second)}
				switch mode {
				case "expired":
					l.ExpiresAt = time.Now().Add(-time.Second)
				case "wrong-hash":
					l.InvocationSHA256 = "other"
				case "extra-key":
					l.DEK = make([]byte, 32)
				case "not-ready":
					return Lease{}, ErrNotReady
				}
				return l, nil
			})}
			client, _ := mutualTLSFixture(t, h)
			if e := client.Check(context.Background(), i, "prepare"); e == nil {
				t.Fatal("invalid lease accepted")
			}
		})
	}
}
func TestControlRedirectDoesNotForwardTaskIdentity(t *testing.T) {
	hit := false
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer destination.Close()
	client, _ := mutualTLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	r, env, _ := fixture(t)
	i := Invocation{Request: r, WorkspacePath: env.Workspace.Name(), StagingPath: env.Staging.Name()}
	if client.Ready(context.Background(), i) == nil || hit {
		t.Fatal("followed control redirect")
	}
}
func TestInvocationRejectsEmbeddedSecretsAndTrailingJSON(t *testing.T) {
	for _, s := range []string{`{"key":"must-not-be-here"}`, `{} {}`, `{"request":{},"workspace_path":"x","staging_path":"y","dsn":"secret"}`} {
		if _, e := ReadInvocation(bytes.NewBufferString(s)); e == nil {
			t.Fatal("unexpected private field accepted")
		}
	}
}
