package install

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestOriginalRelayPKIActualIssuerAndTransportRoles(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	until := now.Add(time.Hour)
	files, e := originalRelayCertificates(now, until, "spiffe://clawmanager.invalid/original-relay/client", map[string]originalRelayCertificateIdentity{"relay-server": {URI: "spiffe://clawmanager.invalid/original-relay/server", Host: "relay.system.svc"}})
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		for _, b := range files {
			clear(b)
		}
	}()
	if len(files) != 6 {
		t.Fatal("unexpected retained material set")
	}
	b, _ := pem.Decode(files["relay-ca.pem"])
	ca, e := x509.ParseCertificate(b.Bytes)
	if e != nil || !ca.IsCA || !ca.NotAfter.Equal(until) {
		t.Fatal("actual bounded CA")
	}
	issuer, e := tls.X509KeyPair(files["relay-ca.pem"], files["relay-issuer-key.pem"])
	if e != nil || issuer.PrivateKey == nil {
		t.Fatal("retained actual issuer pair")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for _, c := range []struct {
		name, host string
		usage      x509.ExtKeyUsage
	}{{"relay-server", "relay.system.svc", x509.ExtKeyUsageServerAuth}, {"relay-client", "", x509.ExtKeyUsageClientAuth}} {
		pair, e := tls.X509KeyPair(files[c.name+".pem"], files[c.name+"-key.pem"])
		if e != nil {
			t.Fatal(e)
		}
		leaf, e := x509.ParseCertificate(pair.Certificate[0])
		if e != nil {
			t.Fatal(e)
		}
		if _, e = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: c.host, KeyUsages: []x509.ExtKeyUsage{c.usage}, CurrentTime: now}); e != nil {
			t.Fatal(e)
		}
		other := x509.ExtKeyUsageClientAuth
		if c.usage == other {
			other = x509.ExtKeyUsageServerAuth
		}
		if _, e = leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{other}, CurrentTime: now}); e == nil {
			t.Fatal("cross-purpose certificate accepted")
		}
	}
}
