package systembackupexecution

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"clawreef/internal/services"
)

func sourceProtocolOriginalTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "independent original source protocol"}, DNSNames: []string{"lite-agent.clawmanager.internal", "localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}}}
}

// Actual TLS/native production client; no SQL, native stopped witness or
// readiness is involved. This isolates the fixture SAN error that blocked all
// running scenarios before the source observer could even be exercised.
func TestSourceProtocolTLSUsesActualPinnedRuntimeHostname(t *testing.T) {
	scenario := newSourceProtocolScenario(t, false)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: scenario.server.Certificate().Raw})
	client, err := services.NewRuntimeAgentClientWithPinnedCA("source-protocol-native-token", ca)
	if err != nil {
		t.Fatal(err)
	}
	agent, ok := client.(services.RuntimeAgentBackupClient)
	if !ok {
		t.Fatal("actual native backup client missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	caps, err := agent.BackupCapabilities(ctx, scenario.server.URL, 21007)
	if err != nil || caps.PodUID != "source-agent-pod-uid" || caps.GatewayPort != 21007 {
		t.Fatal("actual pinned runtime TLS/permission protocol", err)
	}
	if err := scenario.server.Certificate().VerifyHostname("lite-agent.clawmanager.internal"); err != nil {
		t.Fatal(err)
	}
	if err := scenario.server.Certificate().VerifyHostname("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
}
