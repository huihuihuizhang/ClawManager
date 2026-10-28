package systembackupevidence

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Real certificate/TLS verification; the transaction pointers and all mapping
// facts in this file are synthetic. No current deployment authority is asserted.
func relayPeerFixture(t *testing.T) (*RelayPeerAuthenticator, *taskFixture, RelayPeerConfig) {
	t.Helper()
	_, f, peer := systemPeerFixture(t)
	peer.Subject = "spiffe://synthetic.example/backup/worker"
	u, err := url.Parse(peer.Subject)
	if err != nil {
		t.Fatal(err)
	}
	relayPeerLeaf(t, f, []*url.URL{u}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	peer.CertificateSHA256 = hash(f.request.TLS.PeerCertificates[0].Raw)
	now := time.Now().UTC().Truncate(time.Microsecond)
	c := RelayPeerConfig{Peer: peer, Binding: RelayJobBinding{
		Scope: peer.Scope, ConfigVersion: f.c.ConfigVersion, ConfigSHA256: f.c.ConfigSHA256,
		TargetType: f.c.OwnerType, TargetPublicID: f.c.OwnerID, AttemptNo: f.c.Attempt,
		Phase: f.c.Phase, JobUnitKey: f.c.JobUnit, JobUID: f.c.JobUID, JobGeneration: f.c.JobGeneration,
		RelayIdentityRef: f.c.RelayIdentity, RelayIdentityVersion: f.c.RelayVersion,
		RelayIdentityBoundAt: now.Add(-time.Minute), RelayIdentityExpiresAt: peer.ExpiresAt,
	}}
	a, err := NewRelayPeerAuthenticator(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a, f, c
}

func relayPeerLeaf(t *testing.T, f *taskFixture, uris []*url.URL, usage []x509.ExtKeyUsage) {
	t.Helper()
	ca := f.request.TLS.VerifiedChains[0][1]
	leaf := &x509.Certificate{SerialNumber: big.NewInt(17), Subject: pkix.Name{CommonName: "not-an-authority"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(20 * time.Minute),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usage, URIs: uris}
	key := f.client.PrivateKey.(crypto.Signer)
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	f.request.TLS.PeerCertificates = []*x509.Certificate{cert}
	f.request.TLS.VerifiedChains = [][]*x509.Certificate{{cert, ca}}
	f.request.TLS.Version = tls.VersionTLS13
	f.client.Certificate = [][]byte{der}
}

func relayPeerBound(t *testing.T, a *RelayPeerAuthenticator, f *taskFixture, c RelayPeerConfig) (*RelayPeerProof, *RelayPeerCheck, context.Context, *sql.Tx, time.Time) {
	t.Helper()
	p, err := a.AuthenticateRequest(f.request)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(p.Context(), time.Minute)
	t.Cleanup(cancel)
	tx := new(sql.Tx) // Identity anchor only: verifier must not call SQL methods.
	now := time.Now().UTC().Truncate(time.Microsecond)
	check, facts, err := a.Bind(ctx, tx, p, c.Binding, now)
	if err != nil || facts.SPIFFE != c.Peer.Subject || facts.CertificateSHA256 != c.Peer.CertificateSHA256 || facts.Binding != c.Binding || facts.ValidUntil.After(c.Binding.RelayIdentityExpiresAt) {
		t.Fatal("wrong pinned relay facts", err)
	}
	return p, check, ctx, tx, now
}

func TestRelayPeerRealMTLS(t *testing.T) {
	a, f, c := relayPeerFixture(t)
	proofs := make(chan *RelayPeerProof, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := a.AuthenticateRequest(r)
		if err != nil {
			w.WriteHeader(403)
			return
		}
		ctx, cancel := context.WithTimeout(p.Context(), time.Minute)
		defer cancel()
		tx := new(sql.Tx)
		now := time.Now().UTC().Truncate(time.Microsecond)
		check, facts, err := a.Bind(ctx, tx, p, c.Binding, now)
		if err != nil || facts.SPIFFE != c.Peer.Subject {
			t.Error("TLS Bind", err)
			w.WriteHeader(500)
			return
		}
		if _, err = check.Recheck(ctx, tx, c.Binding, time.Now().UTC().Truncate(time.Microsecond)); err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		proofs <- p
		w.WriteHeader(204)
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: a.peer.roots}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	transport := srv.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{f.client}
	t.Cleanup(transport.CloseIdleConnections)
	request, _ := http.NewRequest("POST", srv.URL, nil)
	request.Header.Set("X-Forwarded-Client-Cert", "untrusted")
	request.Header.Set("X-Relay-Identity", "untrusted")
	res, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 204 {
		t.Fatal(res.StatusCode)
	}
	p := <-proofs
	select {
	case <-p.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("proof outlived request")
	}
	if f.db.begins != 0 {
		t.Fatal("transport verifier opened SQL")
	}
	res, err = srv.Client().Post(srv.URL, "application/json", nil)
	if err == nil {
		res.Body.Close()
		t.Fatal("missing client cert passed TLS")
	}
}

func TestRelayPeerCertificateBoundary(t *testing.T) {
	for _, name := range []string{"no_tls", "old_tls", "incomplete", "unverified", "wrong_uri", "multiple_uris", "no_uri", "wrong_eku", "wrong_pin", "parsed_uri_spoof"} {
		t.Run(name, func(t *testing.T) {
			a, f, c := relayPeerFixture(t)
			u, _ := url.Parse(c.Peer.Subject)
			other, _ := url.Parse("spiffe://other.example/worker")
			switch name {
			case "no_tls":
				f.request.TLS = nil
			case "old_tls":
				f.request.TLS.Version = tls.VersionTLS12
			case "incomplete":
				f.request.TLS.HandshakeComplete = false
			case "unverified":
				f.request.TLS.VerifiedChains = nil
			case "wrong_uri", "parsed_uri_spoof":
				relayPeerLeaf(t, f, []*url.URL{other}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
				if name == "parsed_uri_spoof" {
					f.request.TLS.PeerCertificates[0].URIs = []*url.URL{u}
				}
			case "multiple_uris":
				relayPeerLeaf(t, f, []*url.URL{u, other}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
			case "no_uri":
				relayPeerLeaf(t, f, nil, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
			case "wrong_eku":
				relayPeerLeaf(t, f, []*url.URL{u}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
				a.peer.c.CertificateSHA256 = hash(f.request.TLS.PeerCertificates[0].Raw)
			case "wrong_pin":
				a.peer.c.CertificateSHA256 = strings.Repeat("f", 64)
			}
			if p, err := a.AuthenticateRequest(f.request); err != ErrAuth || p != nil {
				t.Fatal("invalid cert admitted", err)
			}
		})
	}
}

func TestRelayPeerLockedBindingChangesLatchFailure(t *testing.T) {
	mutations := map[string]func(*RelayJobBinding){
		"installation":   func(b *RelayJobBinding) { b.Scope.Installation = "installation_other" },
		"server":         func(b *RelayJobBinding) { b.Scope.ServerUUID = "99999999-2222-4333-8444-555555555555" },
		"database":       func(b *RelayJobBinding) { b.Scope.Database = "other" },
		"config_version": func(b *RelayJobBinding) { b.ConfigVersion++ },
		"config_hash":    func(b *RelayJobBinding) { b.ConfigSHA256 = strings.Repeat("e", 64) },
		"target_type":    func(b *RelayJobBinding) { b.TargetType = "preflight" },
		"target_id":      func(b *RelayJobBinding) { b.TargetPublicID = "sbk_99999999-2222-4333-8444-555555555555" },
		"attempt":        func(b *RelayJobBinding) { b.AttemptNo++ },
		"phase":          func(b *RelayJobBinding) { b.Phase = "publish" },
		"unit":           func(b *RelayJobBinding) { b.JobUnitKey = "other" },
		"job":            func(b *RelayJobBinding) { b.JobUID = "99999999-2222-4333-8444-555555555555" },
		"generation":     func(b *RelayJobBinding) { b.JobGeneration++ },
		"relay":          func(b *RelayJobBinding) { b.RelayIdentityRef = "other" },
		"relay_version":  func(b *RelayJobBinding) { b.RelayIdentityVersion = "other" },
		"bound":          func(b *RelayJobBinding) { b.RelayIdentityBoundAt = b.RelayIdentityBoundAt.Add(-time.Second) },
		"expiry":         func(b *RelayJobBinding) { b.RelayIdentityExpiresAt = b.RelayIdentityExpiresAt.Add(-time.Second) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			a, f, c := relayPeerFixture(t)
			_, check, ctx, tx, now := relayPeerBound(t, a, f, c)
			current := c.Binding
			mutate(&current)
			copy := *check
			if _, err := copy.Recheck(ctx, tx, current, now); err != ErrAuth {
				t.Fatal("changed binding passed", err)
			}
			if _, err := check.Recheck(ctx, tx, c.Binding, now); err != ErrAuth {
				t.Fatal("value copy reset failure", err)
			}
		})
	}
}

func TestRelayPeerTransactionAndDeadline(t *testing.T) {
	for _, name := range []string{"one_shot_copy", "wrong_tx", "nil_tx", "wrong_context", "clock_backwards", "clock_skew", "expired", "closed", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			a, f, c := relayPeerFixture(t)
			p, check, ctx, tx, now := relayPeerBound(t, a, f, c)
			switch name {
			case "one_shot_copy":
				copy := *p
				if _, _, err := a.Bind(ctx, tx, &copy, c.Binding, now); err != ErrAuth {
					t.Fatal("proof reused", err)
				}
				return
			case "wrong_tx":
				tx = new(sql.Tx)
			case "nil_tx":
				tx = nil
			case "wrong_context":
				ctx = context.WithValue(ctx, "synthetic-other", true)
			case "clock_backwards":
				now = now.Add(-time.Microsecond)
			case "clock_skew":
				now = now.Add(6 * time.Second)
			case "expired":
				now = c.Binding.RelayIdentityExpiresAt
			case "closed":
				a.Close()
			case "cancelled":
				cancelCtx, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelCtx
			}
			if _, err := check.Recheck(ctx, tx, c.Binding, now); err != ErrAuth {
				t.Fatal(name, err)
			}
		})
	}
	for _, name := range []string{"no_deadline", "unrelated", "nil_context", "not_bound_yet"} {
		t.Run(name, func(t *testing.T) {
			a, f, c := relayPeerFixture(t)
			p, err := a.AuthenticateRequest(f.request)
			if err != nil {
				t.Fatal(err)
			}
			ctx := p.Context()
			now := time.Now().UTC().Truncate(time.Microsecond)
			switch name {
			case "unrelated":
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
			case "nil_context":
				ctx = nil
			case "not_bound_yet":
				a.binding.RelayIdentityBoundAt = now.Add(time.Second)
				c.Binding = a.binding
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Minute)
				defer cancel()
			}
			if _, _, err = a.Bind(ctx, new(sql.Tx), p, c.Binding, now); err != ErrAuth {
				t.Fatal(name, err)
			}
		})
	}
}

func TestRelayPeerClosedConfigAndOpaqueValues(t *testing.T) {
	a, f, c := relayPeerFixture(t)
	p, check, _, _, _ := relayPeerBound(t, a, f, c)
	for _, value := range []any{c, a, *a, p, *p, check, *check} {
		if raw, err := json.Marshal(value); err == nil || len(raw) != 0 {
			t.Fatal("serialized private boundary")
		}
		if strings.Contains(fmt.Sprintf("%v %+v %#v", value, value, value), c.Peer.Subject) {
			t.Fatal("mapping leaked")
		}
	}
	for _, value := range []any{&RelayPeerConfig{}, &RelayPeerAuthenticator{}, &RelayPeerProof{}, &RelayPeerCheck{}} {
		if json.Unmarshal([]byte(`{}`), value) == nil {
			t.Fatal("JSON created authority")
		}
	}
	for _, name := range []string{"junk_ca", "private_ca", "scope", "uri", "purpose", "lifetime"} {
		t.Run(name, func(t *testing.T) {
			bad := c
			switch name {
			case "junk_ca":
				bad.Peer.ClientCAPEM = append([]byte("junk"), c.Peer.ClientCAPEM...)
			case "private_ca":
				bad.Peer.ClientCAPEM = []byte("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----")
			case "scope":
				bad.Binding.Scope.Database = "other"
			case "uri":
				bad.Peer.Subject = "spiffe://synthetic.example/backup/worker?alias=1"
			case "purpose":
				bad.Binding.Phase = "restore"
			case "lifetime":
				bad.Peer.ExpiresAt = c.Binding.RelayIdentityExpiresAt.Add(-time.Second)
			}
			bad.Peer.ClientCASHA256 = hash(bad.Peer.ClientCAPEM)
			if auth, err := NewRelayPeerAuthenticator(bad); err != ErrInvalid || auth != nil {
				t.Fatal(name, err)
			}
		})
	}
}
