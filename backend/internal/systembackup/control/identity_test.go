package control

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"
)

func testIssuer(t *testing.T) IdentityIssuer {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	return IdentityIssuer{Certificate: cert, Signer: key, ServerRoots: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), TrustDomain: "backup.internal"}
}
func TestTaskIdentityIsScopedAndExpires(t *testing.T) {
	issuer := testIssuer(t)
	task, _, _ := grantFixture()
	hash := strings.Repeat("b", 64)
	identity, e := issuer.Issue(task, hash)
	if e != nil {
		t.Fatal(e)
	}
	defer identity.Clear()
	pair, e := tls.X509KeyPair(identity.Data["tls.crt"], identity.Data["tls.key"])
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(issuer.Certificate)
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
		t.Fatal(e)
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != identity.SPIFFE || !strings.HasSuffix(identity.SPIFFE, "/"+task.ID+"/"+hash) || leaf.NotAfter.Unix() != time.UnixMilli(task.Deadline).Unix() {
		t.Fatal("identity scope changed")
	}
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); e == nil {
		t.Fatal("worker certificate accepted as server")
	}
	task.Deadline = time.Now().Add(3 * time.Hour).UnixMilli()
	if _, e = issuer.Issue(task, hash); e == nil {
		t.Fatal("unbounded identity lifetime")
	}
}
func TestIdentityCleanupNeverGeneratesMissingCredentials(t *testing.T) {
	task, _, _ := grantFixture()
	steps := append(workerCommit(task), sqlStep{contains: "SELECT record_kind"})
	store, s := scriptStore(t, steps...)
	v := testVault()
	v.Store = store
	client := fake.NewSimpleClientset()
	manager := WorkerIdentities{Vault: v, Client: client, Issuer: testIssuer(t)}
	if e := manager.Delete(context.Background(), task, "backup", "worker-identity", strings.Repeat("b", 64)); e != ErrNotFound || s.writes != 0 || len(client.Actions()) != 0 {
		t.Fatal("cleanup allocated new credentials", e)
	}
}
