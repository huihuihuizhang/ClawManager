package systembackupevidence

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackupproducer"
)

func systemPeerFixture(t *testing.T) (*SystemPeerAuthenticator, *taskFixture, SystemPeerConfig) {
	t.Helper()
	f := newTaskFixture(t, false)
	f.request.TLS.Version = tls.VersionTLS13
	c := SystemPeerConfig{Scope: systembackupproducer.Scope{ServerUUID: "11111111-2222-4333-8444-555555555555", Database: "synthetic", Installation: "installation_test"}, IssuerIdentityHash: strings.Repeat("a", 64), Subject: f.c.Subject, ClientCAPEM: f.c.ClientCAPEM, ClientCASHA256: f.c.ClientCASHA256, CertificateSHA256: f.c.CertificateSHA256, ExpiresAt: f.c.ExpiresAt}
	a, err := NewSystemPeerAuthenticator(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a, f, c
}

func TestSystemPeerRealMTLS(t *testing.T) {
	a, f, c := systemPeerFixture(t)
	proofs := make(chan *SystemPeer, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := a.AuthenticateRequest(r)
		if err != nil {
			w.WriteHeader(403)
			return
		}
		facts, err := a.Check(r.Context(), p, c.Scope, time.Now().UTC().Truncate(time.Microsecond))
		if err != nil || facts.Subject != c.Subject || facts.SubjectHash != systemPeerHash(struct{ Domain, Subject string }{"system-backup-recovery-subject.v1", c.Subject}) ||
			facts.ClientCASHA256 != c.ClientCASHA256 || facts.CertificateSHA256 != c.CertificateSHA256 ||
			facts.ActorIdentityHash == r.Header.Get("X-Actor-Identity") || facts.IssuerIdentityHash != c.IssuerIdentityHash || facts.Scope != c.Scope || !digestPattern.MatchString(facts.AdmissionHash) {
			t.Error("incorrect authenticated facts", err)
			w.WriteHeader(500)
			return
		}
		proofs <- p
		w.WriteHeader(204)
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: a.roots}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	transport := srv.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{f.client}
	client := &http.Client{Transport: transport}
	t.Cleanup(transport.CloseIdleConnections)
	req, _ := http.NewRequest("POST", srv.URL, nil)
	req.Header.Set("X-Actor-Identity", strings.Repeat("f", 64))
	req.Header.Set("X-Forwarded-Client-Cert", "untrusted")
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 204 {
		t.Fatal("valid mTLS rejected", res.StatusCode)
	}
	p := <-proofs
	select {
	case <-p.request.Done():
	case <-time.After(time.Second):
		t.Fatal("request context did not end")
	}
	if _, err := a.Check(context.Background(), p, c.Scope, time.Now().UTC().Truncate(time.Microsecond)); err != ErrAuth {
		t.Fatal("completed request proof reused")
	}
	if res, err := srv.Client().Post(srv.URL, "application/json", nil); err == nil {
		res.Body.Close()
		t.Fatal("missing client certificate passed TLS")
	}
	// Same CA and public key, freshly signed different leaf: TLS accepts the
	// certificate but the authenticator must still enforce the exact pin.
	ca := f.request.TLS.VerifiedChains[0][1]
	leaf := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "another workload"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, f.client.PrivateKey.(crypto.Signer).Public(), f.client.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	otherTransport := srv.Client().Transport.(*http.Transport).Clone()
	otherTransport.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: f.client.PrivateKey}}
	t.Cleanup(otherTransport.CloseIdleConnections)
	res, err = (&http.Client{Transport: otherTransport}).Post(srv.URL, "application/json", nil)
	if err != nil {
		t.Fatal("same CA certificate should reach pin check", err)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatal("wrong pinned leaf accepted", res.StatusCode)
	}
	if f.db.begins != 0 {
		t.Fatal("transport verifier unexpectedly performed SQL")
	}
}

func TestSystemPeerRequestBoundary(t *testing.T) {
	for name, mutate := range map[string]func(*http.Request){
		"no_tls":           func(r *http.Request) { r.TLS = nil },
		"old_tls":          func(r *http.Request) { r.TLS.Version = tls.VersionTLS10 },
		"incomplete":       func(r *http.Request) { r.TLS.HandshakeComplete = false },
		"unverified":       func(r *http.Request) { r.TLS.VerifiedChains = nil },
		"no_peer":          func(r *http.Request) { r.TLS.PeerCertificates = nil },
		"nil_leaf":         func(r *http.Request) { r.TLS.PeerCertificates[0] = nil },
		"nil_chain_leaf":   func(r *http.Request) { r.TLS.VerifiedChains[0][0] = nil },
		"nil_intermediate": func(r *http.Request) { r.TLS.PeerCertificates = append(r.TLS.PeerCertificates, nil) },
		"changed_leaf":     func(r *http.Request) { r.TLS.PeerCertificates[0] = r.TLS.VerifiedChains[0][1] },
		"canceled": func(r *http.Request) {
			ctx, cancel := context.WithCancel(r.Context())
			cancel()
			*r = *r.WithContext(ctx)
		},
	} {
		t.Run(name, func(t *testing.T) {
			a, f, _ := systemPeerFixture(t)
			mutate(f.request)
			if p, err := a.AuthenticateRequest(f.request); err != ErrAuth || p != nil {
				t.Fatal("invalid request admitted", err)
			}
		})
	}
}

func TestSystemPeerOpaqueAndTransactionChecks(t *testing.T) {
	a, f, c := systemPeerFixture(t)
	p, err := a.AuthenticateRequest(f.request)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	facts, err := a.Check(context.Background(), p, c.Scope, now)
	if err != nil || !facts.ExpiresAt.Equal(c.ExpiresAt) {
		t.Fatal("unexpected proof facts", err)
	}
	if _, err := json.Marshal(p); err == nil {
		t.Fatal("proof serialized")
	}
	if err := json.Unmarshal([]byte(`{}`), p); err != ErrAuth {
		t.Fatal("JSON minted proof")
	}
	if _, err := a.Check(context.Background(), p, c.Scope, now); err != nil {
		t.Fatal("rejected JSON corrupted existing proof")
	}
	for name, scope := range map[string]systembackupproducer.Scope{
		"server":       {ServerUUID: "aaaaaaaa-2222-4333-8444-555555555555", Database: c.Scope.Database, Installation: c.Scope.Installation},
		"database":     {ServerUUID: c.Scope.ServerUUID, Database: "other", Installation: c.Scope.Installation},
		"installation": {ServerUUID: c.Scope.ServerUUID, Database: c.Scope.Database, Installation: "installation_other"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := a.Check(context.Background(), p, scope, now); err != ErrAuth {
				t.Fatal("cross scope proof accepted")
			}
		})
	}
	for name, dbNow := range map[string]time.Time{"zero": {}, "ahead": now.Add(10 * time.Second), "behind": now.Add(-10 * time.Second), "submicrosecond": now.Add(time.Nanosecond), "non_utc": now.In(time.FixedZone("offset", 3600))} {
		t.Run(name, func(t *testing.T) {
			if _, err := a.Check(context.Background(), p, c.Scope, dbNow); err != ErrAuth {
				t.Fatal("bad DB time accepted")
			}
		})
	}
	if _, err := a.Check(context.Background(), &SystemPeer{}, c.Scope, now); err != ErrAuth {
		t.Fatal("zero proof accepted")
	}
	if _, err := a.Check(nil, p, c.Scope, now); err != ErrAuth {
		t.Fatal("nil operation context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.Check(ctx, p, c.Scope, now); err != ErrAuth {
		t.Fatal("canceled operation accepted")
	}
	other, err := NewSystemPeerAuthenticator(c)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.Check(context.Background(), p, c.Scope, now); err != ErrAuth {
		t.Fatal("foreign instance accepted proof")
	}
	// The input request's slices are not retained in the sealed proof.
	f.request.TLS.PeerCertificates = nil
	f.request.TLS.VerifiedChains = nil
	if _, err := a.Check(context.Background(), p, c.Scope, now); err != nil {
		t.Fatal("request mutation altered sealed certificate copy", err)
	}
	a.Close()
	a.Close()
	if _, err := a.Check(context.Background(), p, c.Scope, now); err != ErrAuth {
		t.Fatal("closed verifier accepted proof")
	}
}

func TestSystemPeerAdmissionAndCredentialRotation(t *testing.T) {
	a, f, c := systemPeerFixture(t)
	for name, change := range map[string]func(*SystemPeerConfig){
		"bad_server":       func(c *SystemPeerConfig) { c.Scope.ServerUUID = "bad" },
		"empty_database":   func(c *SystemPeerConfig) { c.Scope.Database = "" },
		"invalid_utf8":     func(c *SystemPeerConfig) { c.Scope.Database = systembackupproducer.Database("\xff") },
		"bad_installation": func(c *SystemPeerConfig) { c.Scope.Installation = "other" },
		"bad_issuer":       func(c *SystemPeerConfig) { c.IssuerIdentityHash = "not-a-hash" },
		"empty_subject":    func(c *SystemPeerConfig) { c.Subject = "" },
		"bad_pin":          func(c *SystemPeerConfig) { c.CertificateSHA256 = "bad" },
		"bad_ca_hash":      func(c *SystemPeerConfig) { c.ClientCASHA256 = strings.Repeat("f", 64) },
		"invalid_ca":       func(c *SystemPeerConfig) { c.ClientCAPEM = []byte("not PEM"); c.ClientCASHA256 = hash(c.ClientCAPEM) },
		"expired":          func(c *SystemPeerConfig) { c.ExpiresAt = time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := c
			change(&bad)
			if v, err := NewSystemPeerAuthenticator(bad); err != ErrInvalid || v != nil {
				t.Fatal("bad admission accepted", err)
			}
		})
	}
	rotated := c
	rotated.CertificateSHA256 = strings.Repeat("f", 64)
	v, err := NewSystemPeerAuthenticator(rotated)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if v.actor == a.actor || v.workload != a.workload || v.admission == a.admission {
		t.Fatal("credential rotation lost actor fence or changed stable workload")
	}
	if _, err := v.AuthenticateRequest(f.request); err != ErrAuth {
		t.Fatal("old leaf accepted after pin rotation")
	}
	other := newTaskFixture(t, false)
	rotated = c
	rotated.ClientCAPEM = other.c.ClientCAPEM
	rotated.ClientCASHA256 = other.c.ClientCASHA256
	v, err = NewSystemPeerAuthenticator(rotated)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if _, err := v.AuthenticateRequest(f.request); err != ErrAuth {
		t.Fatal("TLS verification under foreign CA replaced own roots")
	}
	// Recheck with DB time beyond original admission but still inside the clock
	// tolerance; no sleep or extension of that original deadline is involved.
	short := c
	short.ExpiresAt = time.Now().UTC().Add(3 * time.Second).Truncate(time.Microsecond)
	v, err = NewSystemPeerAuthenticator(short)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	p, err := v.AuthenticateRequest(f.request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Check(context.Background(), p, c.Scope, short.ExpiresAt); err != ErrAuth {
		t.Fatal("DB deadline boundary admitted")
	}
}
