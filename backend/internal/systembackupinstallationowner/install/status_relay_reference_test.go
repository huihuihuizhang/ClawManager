package install

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Real local TLS 1.3 mutual certificate transport only. This is not an actual
// Kubernetes/SQL/original Installer lifecycle or task/Job permission result.
func statusRelayTLSFixture(t *testing.T) (StatusRelayReferenceDefinition, *atomic.Int64) {
	t.Helper()
	dir := t.TempDir()
	now := time.Now().UTC()
	caPub, caKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { clear(caKey) })
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "explicit local relay component CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, e := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caKey)
	if e != nil {
		t.Fatal(e)
	}
	ca, e := x509.ParseCertificate(caDER)
	if e != nil {
		t.Fatal(e)
	}
	issue := func(serial int64, client bool) (tls.Certificate, []byte, []byte) {
		pub, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { clear(key) })
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		if client {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			template.IPAddresses = nil
		}
		der, e := x509.CreateCertificate(rand.Reader, template, ca, pub, caKey)
		if e != nil {
			t.Fatal(e)
		}
		keyDER, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			t.Fatal(e)
		}
		defer clear(keyDER)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		pair, e := tls.X509KeyPair(certPEM, keyPEM)
		if e != nil {
			t.Fatal(e)
		}
		return pair, certPEM, keyPEM
	}
	serverPair, _, serverKey := issue(2, false)
	clear(serverKey)
	_, clientPEM, clientKey := issue(3, true)
	defer clear(clientKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	requests := &atomic.Int64{}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(http.StatusUnauthorized) }))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverPair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	t.Cleanup(server.Close)
	write := func(name string, raw []byte) BootstrapSourceFilePin {
		path := filepath.Join(dir, name)
		if e := os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
		return BootstrapSourceFilePin{File: path, SHA256: hash(raw)}
	}
	leaf, e := x509.ParseCertificate(serverPair.Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	spki, e := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	d := StatusRelayReferenceDefinition{Version: StatusRelayReferenceVersion, ReferenceVersion: "relay-r1", Deployment: write("core.json", []byte(`{"schema_version":"system-backup-public-deployment.v1"}`)), Service: "relay", ServiceUID: "service-uid", Endpoint: server.URL + "/relay", Container: "controller", ContainerImageID: "container-image", PodSpecSHA256: strings.Repeat("a", 64), CA: write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})), ClientCertificate: write("original-client.crt", clientPEM), ClientPrivateKey: write("original-client.key", clientKey), ServerLeafSHA256: hash(leaf.Raw), ServerSPKISHA256: hash(spki), NotBefore: now.Add(-time.Minute), Until: now.Add(time.Hour)}
	d.Controller = BootstrapSourceController{Namespace: "component", NamespaceUID: "component-ns-uid", Deployment: "relay", DeploymentUID: "relay-dep-uid", ReplicaSet: "relay-rs", ReplicaSetUID: "relay-rs-uid", Pod: "relay-pod", PodUID: "relay-pod-uid", ServiceAccount: "relay", ServiceAccountUID: "relay-sa-uid"}
	return d, requests
}

func TestStatusRelayTransportTLSAuthenticatesOriginalPinsWithoutTask(t *testing.T) {
	d, requests := statusRelayTLSFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	leaf, spki, until, e := statusRelayTLS(ctx, d)
	if e != nil || leaf != d.ServerLeafSHA256 || spki != d.ServerSPKISHA256 || !time.Now().Before(until) || requests.Load() != 0 {
		t.Fatal("actual original TLS source/closed no-request boundary", e)
	}
	for _, fault := range []string{"leaf", "spki", "client-key-pin", "ca-pin"} {
		t.Run(fault, func(t *testing.T) {
			bad := d
			switch fault {
			case "leaf":
				bad.ServerLeafSHA256 = strings.Repeat("b", 64)
			case "spki":
				bad.ServerSPKISHA256 = strings.Repeat("c", 64)
			case "client-key-pin":
				bad.ClientPrivateKey.SHA256 = strings.Repeat("d", 64)
			case "ca-pin":
				bad.CA.SHA256 = strings.Repeat("e", 64)
			}
			if _, _, _, e := statusRelayTLS(ctx, bad); e == nil {
				t.Fatal("changed original source accepted")
			}
		})
	}
	if requests.Load() != 0 {
		t.Fatal("TLS reference check sent HTTP/task work")
	}
}

func TestStatusRelayReferenceSelectionIsDataAndRejectsCrossSource(t *testing.T) {
	d, _ := statusRelayTLSFixture(t)
	raw, e := canonical(d)
	if e != nil {
		t.Fatal(e)
	}
	ref, e := StatusRelayReferenceIdentity(raw, hash(raw))
	if e != nil || ref.Purpose != "status_relay" || ref.IdentityHash != hash(raw) || ref.Version != d.ReferenceVersion {
		t.Fatal(e)
	}
	bad := d
	bad.Endpoint = "http://original.invalid/relay"
	raw, _ = canonical(bad)
	if _, e := StatusRelayReferenceIdentity(raw, hash(raw)); e == nil {
		t.Fatal("plaintext reference accepted")
	}
	bad = d
	bad.ReferenceVersion = "current"
	raw, _ = canonical(bad)
	if _, e := StatusRelayReferenceIdentity(raw, hash(raw)); e == nil {
		t.Fatal("floating reference accepted")
	}
	if _, e := NewOriginalStatusRelayReference(nil, StatusRelayReferenceFiles{}); e == nil {
		t.Fatal("missing enrolled capture selected")
	}
}

func TestStatusRelayReferenceCannotPromoteDetachedDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c := &statusRelayReferenceCheck{ctx: ctx, native: statusRelayNative{until: time.Now().Add(time.Second)}}
	c.origin = c
	if c.DependencyDeadline() != nil {
		t.Fatal("native DATA replaced original SQL authority")
	}
	if e := c.LockReferences(ctx, nil); e == nil || !c.failed.Load() {
		t.Fatal("unbound terminal reference admitted")
	}
	original := &statusRelayReferenceCheck{}
	original.origin = original
	copyCheck := &statusRelayReferenceCheck{origin: original}
	if copyCheck.DependencyDeadline() != nil || !original.failed.Load() {
		t.Fatal("copied source did not poison original")
	}
}
