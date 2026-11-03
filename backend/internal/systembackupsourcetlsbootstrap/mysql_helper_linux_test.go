package systembackupsourcetlsbootstrap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Actual crypto/file fixture only. No SQL, Kubernetes, helper exec, native
// reload, source grant or deployment success is claimed by this test.
func TestMySQLBootstrapSignsSANWithExistingCAAndPreservesIssuer(t *testing.T) {
	root, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "original database CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &root.PublicKey, root)
	if e != nil {
		t.Fatal(e)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	rawKey, e := x509.MarshalPKCS8PrivateKey(root)
	if e != nil {
		t.Fatal(e)
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rawKey})
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	keyFile := filepath.Join(dir, "ca-key.pem")
	if os.WriteFile(caFile, ca, 0600) != nil || os.WriteFile(keyFile, key, 0600) != nil {
		t.Fatal("issuer files")
	}
	oldKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	oldTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "old server"}, DNSNames: []string{"original-database.example"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	oldDER, e := x509.CreateCertificate(rand.Reader, oldTemplate, caTemplate, &oldKey.PublicKey, root)
	if e != nil {
		t.Fatal(e)
	}
	leaf, private, e := signedServer(MySQLNativeTLS{CA: ca, CAFile: caFile, Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: oldDER}), IssuerKeyAvailable: true}, MySQLHelperRequest{DNSNames: []string{"mysql.original.svc"}, IPAddresses: []string{"10.1.2.3"}})
	if e != nil {
		t.Fatal(e)
	}
	defer clear(private)
	parsed, e := certificate(leaf)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	for _, name := range []string{"mysql.original.svc", "original-database.example", "10.1.2.3"} {
		if _, e := parsed.Verify(x509.VerifyOptions{Roots: pool, DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); e != nil {
			t.Fatal(name, e)
		}
	}
	if _, e := parsed.Verify(x509.VerifyOptions{Roots: pool, DNSName: "other.example", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); e == nil {
		t.Fatal("wrong SAN accepted")
	}
	actual, e := os.ReadFile(keyFile)
	if e != nil || !bytes.Equal(actual, key) {
		t.Fatal("original CA key changed")
	}
	actual, e = os.ReadFile(caFile)
	if e != nil || !bytes.Equal(actual, ca) {
		t.Fatal("original CA changed")
	}
}
