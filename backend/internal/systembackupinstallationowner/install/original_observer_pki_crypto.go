package install

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"time"
)

var errOriginalObserverPKI = errors.New("original observer PKI materialization rejected")

type originalObserverCertificateIdentity struct{ URI, Host string }

// Crypto alone is not installation authorization. The only production caller
// is Installer.GenerateOriginalObserverPKI after actual original authentication
// and live Kubernetes identity resolution. CA signing material is never saved.
func originalObserverCertificates(now, until time.Time, clientURI string, servers map[string]originalObserverCertificateIdentity) (map[string][]byte, error) {
	if now.IsZero() || !until.After(now) || until.Sub(now) > 24*time.Hour || len(servers) == 0 || len(servers) > 192 {
		return nil, errOriginalObserverPKI
	}
	parseURI := func(text string) (*url.URL, error) {
		u, err := url.Parse(text)
		if err != nil || u.Scheme != "spiffe" || u.Hostname() == "" || u.Host != u.Hostname() || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.Path == "" || u.String() != text {
			return nil, errOriginalObserverPKI
		}
		return u, nil
	}
	client, err := parseURI(clientURI)
	if err != nil {
		return nil, err
	}
	serial := func() (*big.Int, error) {
		for {
			n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
			if e != nil || n.Sign() != 0 {
				return n, e
			}
		}
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errOriginalObserverPKI
	}
	defer caKey.D.SetInt64(0)
	n, err := serial()
	if err != nil {
		return nil, errOriginalObserverPKI
	}
	public, err := x509.MarshalPKIXPublicKey(&caKey.PublicKey)
	if err != nil {
		return nil, errOriginalObserverPKI
	}
	id := sha256.Sum256(public)
	ca := &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: "ClawManager original observer installation CA"}, NotBefore: now.Add(-time.Minute), NotAfter: until, IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: id[:20]}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, errOriginalObserverPKI
	}
	out := map[string][]byte{"observer-ca.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
	ok := false
	defer func() {
		if !ok {
			for _, raw := range out {
				clear(raw)
			}
		}
	}()
	issue := func(prefix string, uri *url.URL, host string, usage x509.ExtKeyUsage) error {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return errOriginalObserverPKI
		}
		defer key.D.SetInt64(0)
		n, e := serial()
		if e != nil {
			return errOriginalObserverPKI
		}
		leaf := &x509.Certificate{SerialNumber: n, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, URIs: []*url.URL{uri}}
		if host != "" {
			if ip := net.ParseIP(host); ip != nil {
				leaf.IPAddresses = []net.IP{ip}
			} else {
				leaf.DNSNames = []string{host}
			}
		}
		cert, e := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
		if e != nil {
			return errOriginalObserverPKI
		}
		private, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			return errOriginalObserverPKI
		}
		defer clear(private)
		out[prefix+".pem"] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
		out[prefix+"-key.pem"] = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
		return nil
	}
	if issue("observer-client", client, "", x509.ExtKeyUsageClientAuth) != nil {
		return nil, errOriginalObserverPKI
	}
	seen := map[string]bool{clientURI: true}
	for prefix, identity := range servers {
		u, e := parseURI(identity.URI)
		if e != nil || seen[identity.URI] || identity.Host == "" || prefix == "" || prefix == "observer-client" || prefix == "observer-ca" {
			return nil, errOriginalObserverPKI
		}
		seen[identity.URI] = true
		if issue(prefix, u, identity.Host, x509.ExtKeyUsageServerAuth) != nil {
			return nil, errOriginalObserverPKI
		}
		anchor := make([]byte, 32)
		if _, err = rand.Read(anchor); err != nil {
			return nil, errOriginalObserverPKI
		}
		out[prefix+"-anchor.key"] = anchor
	}
	ok = true
	return out, nil
}
