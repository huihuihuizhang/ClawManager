package install

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"testing"
	"time"
)

func TestOriginalObserverPKICertificatePurposesAndCaps(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	clientURI := "spiffe://backup.example/system-backup/installation_original%3Aselected/namespace/ns/controller-service-account/sa"
	serverURI := "spiffe://backup.example/system-backup/installation_original/namespace/ns/node-whole/node"
	files, err := originalObserverCertificates(now, now.Add(time.Hour), clientURI, map[string]originalObserverCertificateIdentity{"node-whole": {URI: serverURI, Host: "127.0.0.1"}})
	if err != nil {
		t.Fatal("certificate generation failed")
	}
	defer func() {
		for _, raw := range files {
			clear(raw)
		}
	}()
	if len(files) != 6 || len(files["node-whole-anchor.key"]) != 32 || files["observer-ca-key.pem"] != nil {
		t.Fatal("unexpected output set")
	}
	parse := func(name string) *x509.Certificate {
		b, rest := pem.Decode(files[name])
		if b == nil || b.Type != "CERTIFICATE" || len(rest) != 0 {
			t.Fatal("certificate PEM rejected")
		}
		c, e := x509.ParseCertificate(b.Bytes)
		if e != nil {
			t.Fatal("certificate DER rejected")
		}
		return c
	}
	ca, client, server := parse("observer-ca.pem"), parse("observer-client.pem"), parse("node-whole.pem")
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if !ca.IsCA || !ca.MaxPathLenZero || client.IsCA || server.IsCA || len(client.URIs) != 1 || client.URIs[0].String() != clientURI || len(server.URIs) != 1 || server.URIs[0].String() != serverURI || !server.NotAfter.Equal(now.Add(time.Hour)) {
		t.Fatal("identity or deadline mismatch")
	}
	cases := []struct {
		name    string
		cert    *x509.Certificate
		purpose x509.ExtKeyUsage
		host    string
		at      time.Time
		want    bool
	}{
		{"client", client, x509.ExtKeyUsageClientAuth, "", now, true},
		{"server", server, x509.ExtKeyUsageServerAuth, "127.0.0.1", now, true},
		{"client_cannot_serve", client, x509.ExtKeyUsageServerAuth, "", now, false},
		{"server_cannot_authenticate_client", server, x509.ExtKeyUsageClientAuth, "", now, false},
		{"wrong_server_hostname", server, x509.ExtKeyUsageServerAuth, "other.example", now, false},
		{"expired", server, x509.ExtKeyUsageServerAuth, "127.0.0.1", now.Add(2 * time.Hour), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, e := c.cert.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: c.at, DNSName: c.host, KeyUsages: []x509.ExtKeyUsage{c.purpose}})
			if (e == nil) != c.want {
				t.Fatal("unexpected verification outcome")
			}
		})
	}
}

func TestOriginalObserverPKIActualMutualTLS(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	clientURI, serverURI := "spiffe://backup.example/client/sa", "spiffe://backup.example/node/whole"
	files, err := originalObserverCertificates(now, now.Add(time.Hour), clientURI, map[string]originalObserverCertificateIdentity{"node": {URI: serverURI, Host: "127.0.0.1"}})
	if err != nil {
		t.Fatal("generation failed")
	}
	defer func() {
		for _, raw := range files {
			clear(raw)
		}
	}()
	clientCert, e := tls.X509KeyPair(files["observer-client.pem"], files["observer-client-key.pem"])
	if e != nil {
		t.Fatal("client key pair")
	}
	serverCert, e := tls.X509KeyPair(files["node.pem"], files["node-key.pem"])
	if e != nil {
		t.Fatal("server key pair")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(files["observer-ca.pem"]) {
		t.Fatal("CA")
	}
	identity := func(want string) func(tls.ConnectionState) error {
		return func(s tls.ConnectionState) error {
			if len(s.VerifiedChains) == 0 || len(s.PeerCertificates) == 0 || len(s.PeerCertificates[0].URIs) != 1 || s.PeerCertificates[0].URIs[0].String() != want {
				return errors.New("URI refused")
			}
			return nil
		}
	}
	cases := []struct {
		name, clientIdentity, serverIdentity, host string
		present                                    bool
		want                                       bool
	}{
		{"original_pair", clientURI, serverURI, "127.0.0.1", true, true},
		{"wrong_client_uri", clientURI + "-wrong", serverURI, "127.0.0.1", true, false},
		{"wrong_server_uri", clientURI, serverURI + "-wrong", "127.0.0.1", true, false},
		{"wrong_hostname", clientURI, serverURI, "wrong.example", true, false},
		{"missing_client", clientURI, serverURI, "127.0.0.1", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			_ = left.SetDeadline(time.Now().Add(2 * time.Second))
			_ = right.SetDeadline(time.Now().Add(2 * time.Second))
			server := tls.Server(left, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, VerifyConnection: identity(c.clientIdentity)})
			config := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: c.host, VerifyConnection: identity(c.serverIdentity)}
			if c.present {
				config.Certificates = []tls.Certificate{clientCert}
			}
			client := tls.Client(right, config)
			done := make(chan error, 1)
			go func() { done <- server.Handshake() }()
			clientErr := client.Handshake()
			_ = right.Close()
			serverErr := <-done
			if (clientErr == nil && serverErr == nil) != c.want {
				t.Fatal("unexpected real TLS handshake result")
			}
		})
	}
}

func TestOriginalObserverPKIRejectsUnboundedAndMixedIdentities(t *testing.T) {
	now := time.Now().UTC()
	servers := map[string]originalObserverCertificateIdentity{"node": {URI: "spiffe://backup.example/server/node", Host: "127.0.0.1"}}
	cases := []struct {
		name, client string
		until        time.Time
		servers      map[string]originalObserverCertificateIdentity
	}{
		{"expired", "spiffe://backup.example/client/sa", now, servers},
		{"over_cap", "spiffe://backup.example/client/sa", now.Add(25 * time.Hour), servers},
		{"no_servers", "spiffe://backup.example/client/sa", now.Add(time.Hour), nil},
		{"wrong_client_scheme", "https://backup.example/client/sa", now.Add(time.Hour), servers},
		{"client_server_alias", "spiffe://backup.example/server/node", now.Add(time.Hour), servers},
		{"arbitrary_server_identity", "spiffe://backup.example/client/sa", now.Add(time.Hour), map[string]originalObserverCertificateIdentity{"node": {URI: "https://backup.example/server", Host: "127.0.0.1"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if output, err := originalObserverCertificates(now, c.until, c.client, c.servers); err == nil || output != nil {
				t.Fatal("invalid selection accepted")
			}
		})
	}
}
