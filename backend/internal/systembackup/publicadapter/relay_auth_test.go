package publicadapter

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	d "clawreef/internal/systembackupdispatch"
	e "clawreef/internal/systembackupevidence"
	p "clawreef/internal/systembackupproducer"
)

type relayOwnerFunc func(context.Context, *AuthenticatedRelay) (RelayDecision, error)

func (f relayOwnerFunc) AcceptAuthenticatedRelay(ctx context.Context, r *AuthenticatedRelay) (RelayDecision, error) {
	return f(ctx, r)
}

type authRelayFixture struct {
	peer    *e.RelayPeerAuthenticator
	scope   p.Scope
	a       d.Authority
	j       d.JobBinding
	m       RelayMessage
	request *http.Request
	cert    tls.Certificate
	roots   *x509.CertPool
}

func newAuthRelayFixture(t *testing.T) *authRelayFixture {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	clientPub, clientKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse("spiffe://isolated.test/backup/worker")
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, URIs: []*url.URL{uri}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, clientPub, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	f := &authRelayFixture{scope: p.Scope{ServerUUID: "11111111-2222-4333-8444-555555555555", Database: "synthetic", Installation: "installation_test"}, roots: x509.NewCertPool(), cert: tls.Certificate{Certificate: [][]byte{leafDER, der}, PrivateKey: clientKey}}
	f.roots.AddCert(root)
	f.a = d.Authority{InstallationID: string(f.scope.Installation), TaskPublicID: "sbk_11111111-1111-4111-8111-111111111111", TaskType: "backup", RequestID: "request", ConfigVersion: 2, ConfigSHA256: strings.Repeat("a", 64), AttemptNo: 3, Phase: "capture", ClaimOwner: "owner", ClaimRowVersion: 7, MaintenanceOwner: "gate", MaintenanceFencingToken: 11, DeadlineAt: now.Add(time.Minute)}
	f.j = d.JobBinding{JobUnitKey: "users", Namespace: "cm-drill-test", Name: "users-job", UID: "22222222-2222-4222-8222-222222222222", Generation: 5, RelayIdentityRef: "relay-ref", RelayIdentityVersion: "v2", RelayBoundAt: now.Add(-time.Second), RelayExpiresAt: f.a.DeadlineAt}
	f.m = RelayMessage{SchemaVersion: RelayVersion, InstallationID: f.a.InstallationID, TaskPublicID: f.a.TaskPublicID, TaskType: f.a.TaskType, AttemptNo: "3", Phase: f.a.Phase, JobUnitKey: f.j.JobUnitKey, Namespace: f.j.Namespace, JobName: f.j.Name, JobUID: f.j.UID, JobGeneration: "5", RelayIdentityRef: f.j.RelayIdentityRef, RelayIdentityVersion: f.j.RelayIdentityVersion, Sequence: "1", Status: "ready"}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	f.peer, err = e.NewRelayPeerAuthenticator(e.RelayPeerConfig{Peer: e.SystemPeerConfig{Scope: f.scope, IssuerIdentityHash: strings.Repeat("b", 64), Subject: uri.String(), ClientCAPEM: caPEM, ClientCASHA256: digest(caPEM), CertificateSHA256: digest(leafDER), ExpiresAt: now.Add(2 * time.Minute)}, Binding: e.RelayJobBinding{Scope: f.scope, ConfigVersion: 2, ConfigSHA256: f.a.ConfigSHA256, TargetType: f.a.TaskType, TargetPublicID: f.a.TaskPublicID, AttemptNo: 3, Phase: f.a.Phase, JobUnitKey: f.j.JobUnitKey, JobUID: f.j.UID, JobGeneration: 5, RelayIdentityRef: f.j.RelayIdentityRef, RelayIdentityVersion: f.j.RelayIdentityVersion, RelayIdentityBoundAt: f.j.RelayBoundAt, RelayIdentityExpiresAt: f.j.RelayExpiresAt}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.peer.Close)
	raw, _ := json.Marshal(f.m)
	f.request = httptest.NewRequest("POST", "https://relay.invalid/", strings.NewReader(string(raw)))
	f.request.Header.Set("Content-Type", "application/json")
	f.request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{parsed}, VerifiedChains: [][]*x509.Certificate{{parsed, root}}}
	return f
}

func (f *authRelayFixture) handler(t *testing.T, owner relayOwnerFunc) http.Handler {
	t.Helper()
	h, err := NewAuthenticatedRelayHandler(RelayAuthentication{ResolvePeer: func(context.Context, RelayMessage) (*e.RelayPeerAuthenticator, error) { return f.peer, nil }, TransactionBudget: time.Second}, owner)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestAuthenticatedRelayUsesOriginalAProofAndOneTransaction(t *testing.T) {
	for _, mode := range []string{"valid", "no-bind", "no-recheck", "wrong-job", "changed-fence", "different-tx", "revoked", "clock-backward", "duplicate-bind", "unknown-commit", "wrong-decision", "request-cancel", "tls12", "forged-uri", "mutated-body-copy"} {
		t.Run(mode, func(t *testing.T) {
			f := newAuthRelayFixture(t)
			calls := 0
			h := f.handler(t, func(ctx context.Context, session *AuthenticatedRelay) (RelayDecision, error) {
				calls++
				if mode == "no-bind" {
					return RelayAdvance, nil
				}
				if _, err := json.Marshal(session); err == nil {
					t.Error("serialized authority")
				}
				if mode == "mutated-body-copy" {
					copy, _ := session.Body()
					copy[0] = '!'
					if session.Message().Status != "ready" {
						t.Error("message drift")
					}
				}
				job := f.j
				if mode == "wrong-job" {
					job.UID = "33333333-3333-4333-8333-333333333333"
				}
				tx := new(sql.Tx) // A identity anchor, no SQL calls/commit are made
				now := time.Now().UTC().Truncate(time.Microsecond)
				decision, _, err := session.Bind(tx, f.scope, f.a, job, now, RelayCursor{})
				if err != nil {
					return "", err
				}
				if mode == "duplicate-bind" {
					_, _, err = session.Bind(tx, f.scope, f.a, job, now, RelayCursor{})
					return "", err
				}
				if mode == "no-recheck" {
					return decision, nil
				}
				if mode == "changed-fence" {
					f.a.MaintenanceFencingToken++
				}
				if mode == "different-tx" {
					tx = new(sql.Tx)
				}
				if mode == "revoked" {
					f.peer.Close()
				}
				if mode == "clock-backward" {
					now = now.Add(-time.Microsecond)
				}
				_, err = session.Recheck(tx, f.scope, f.a, job, now)
				if err != nil {
					return "", err
				}
				if mode == "unknown-commit" {
					return "", errors.New("synthetic ambiguous commit; no retry")
				}
				if mode == "wrong-decision" {
					return RelayReplay, nil
				}
				if ctx.Err() != nil {
					return "", ctx.Err()
				}
				return decision, nil // fixture confirmed result; NOT proof of SQL commit
			})
			if mode == "request-cancel" {
				ctx, cancel := context.WithCancel(f.request.Context())
				cancel()
				f.request = f.request.WithContext(ctx)
			}
			if mode == "tls12" {
				f.request.TLS.Version = tls.VersionTLS12
			}
			if mode == "forged-uri" {
				u, _ := url.Parse("spiffe://forged.invalid/worker")
				f.request.TLS.PeerCertificates[0].URIs = []*url.URL{u}
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, f.request)
			want := mode == "valid" || mode == "mutated-body-copy" || mode == "forged-uri" // A parses original DER, ignores mutable URI fields
			if (w.Code == http.StatusOK) != want {
				t.Fatal(mode, w.Code, calls)
			}
			if (mode == "tls12" || mode == "request-cancel") && calls != 0 {
				t.Fatal("unauthorized request reached D", calls)
			}
			if mode != "tls12" && mode != "request-cancel" && calls != 1 {
				t.Fatal("did not exercise the intended transaction boundary", calls)
			}
		})
	}
}

func TestAuthenticatedRelayRealTLS13RequestReachesOriginalABind(t *testing.T) {
	f := newAuthRelayFixture(t)
	h := f.handler(t, func(_ context.Context, s *AuthenticatedRelay) (RelayDecision, error) {
		tx := new(sql.Tx)
		now := time.Now().UTC().Truncate(time.Microsecond)
		decision, _, err := s.Bind(tx, f.scope, f.a, f.j, now, RelayCursor{})
		if err != nil {
			return "", err
		}
		_, err = s.Recheck(tx, f.scope, f.a, f.j, now)
		return decision, err
	})
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: f.roots}
	srv.StartTLS()
	defer srv.Close()
	client := srv.Client()
	tr := client.Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	tr.TLSClientConfig.Certificates = []tls.Certificate{f.cert}
	defer tr.CloseIdleConnections()
	client = &http.Client{Transport: tr, Timeout: time.Second}
	raw, _ := json.Marshal(f.m)
	response, err := client.Post(srv.URL, "application/json", strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
}

func TestAuthenticatedRelayRejectsMissingComposition(t *testing.T) {
	owner := relayOwnerFunc(func(context.Context, *AuthenticatedRelay) (RelayDecision, error) { return RelayAdvance, nil })
	if _, err := NewAuthenticatedRelayHandler(RelayAuthentication{}, owner); err == nil {
		t.Fatal("missing auth accepted")
	}
	f := newAuthRelayFixture(t)
	config := RelayAuthentication{ResolvePeer: func(context.Context, RelayMessage) (*e.RelayPeerAuthenticator, error) { return f.peer, nil }, TransactionBudget: time.Second}
	if _, err := NewAuthenticatedRelayHandler(config, nil); err == nil {
		t.Fatal("missing transaction owner accepted")
	}
	if _, _, err := (&AuthenticatedRelay{}).Bind(new(sql.Tx), f.scope, f.a, f.j, time.Now(), RelayCursor{}); err == nil {
		t.Fatal("minted proof")
	}
}
