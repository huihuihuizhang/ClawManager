package publicadapter

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRelaySequenceClosedReplayAndConflictRules(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	for _, c := range []struct {
		last, next     uint64
		previous, body string
		want           RelayDecision
	}{{0, 1, "", a, RelayAdvance}, {1, 1, a, a, RelayReplay}, {1, 1, a, b, ""}, {1, 3, a, a, ""}, {2, 1, a, a, ""}, {1, 2, a, b, RelayAdvance}, {0, 0, "", a, ""}, {0, 1, a, a, ""}} {
		got, err := RelaySequence(c.last, c.previous, c.next, c.body)
		if got != c.want || (err == nil) != (c.want != "") {
			t.Fatalf("%+v => %s %v", c, got, err)
		}
	}
}

func TestRelayProgressNeverReopensTerminalOrRegressesRunning(t *testing.T) {
	m := RelayMessage{SchemaVersion: RelayVersion, InstallationID: "installation_test", TaskPublicID: "sbk_11111111-1111-4111-8111-111111111111", TaskType: "backup", AttemptNo: "3", Phase: "capture", JobUnitKey: "users", Namespace: "cm-drill-b", JobName: "capture-one", JobUID: "22222222-2222-4222-8222-222222222222", JobGeneration: "5", RelayIdentityRef: "relay-ref", RelayIdentityVersion: "v2", Sequence: "1"}
	for _, c := range []struct {
		previous, next string
		decision       RelayDecision
		ok             bool
	}{{"", "ready", RelayAdvance, true}, {"", "running", RelayAdvance, false}, {"ready", "running", RelayAdvance, true}, {"ready", "failed", RelayAdvance, true}, {"running", "running", RelayAdvance, true}, {"running", "ready", RelayAdvance, false}, {"running", "completed", RelayAdvance, true}, {"completed", "running", RelayAdvance, false}, {"completed", "completed", RelayAdvance, false}, {"failed", "canceled", RelayAdvance, false}, {"completed", "completed", RelayReplay, true}, {"running", "failed", RelayReplay, false}, {"unknown", "ready", RelayAdvance, false}} {
		m.Status, m.ResultEvidence = c.next, nil
		if c.next == "completed" {
			m.ResultEvidence = &RelayEvidence{PublicID: "sev_result", SHA256: strings.Repeat("b", 64)}
		}
		if err := RelayProgress(c.previous, m, c.decision); (err == nil) != c.ok {
			t.Fatal(c, err)
		}
	}
}

type relayFixture struct {
	calls atomic.Int32
	raw   []byte
	hash  string
}

func (f *relayFixture) AcceptRelay(_ context.Context, r *http.Request, _ RelayMessage, raw []byte, hash string) (RelayDecision, error) {
	f.calls.Add(1)
	f.raw = append([]byte(nil), raw...)
	f.hash = hash
	if r.TLS == nil {
		panic("no transport identity")
	}
	return RelayAdvance, nil
}

func TestRelayTransportRequiresPeerAndForwardsExactBytesToD(t *testing.T) {
	message := RelayMessage{SchemaVersion: RelayVersion, InstallationID: "installation_test", TaskPublicID: "sbk_11111111-1111-4111-8111-111111111111", TaskType: "backup", AttemptNo: "3", Phase: "capture", JobUnitKey: "users", Namespace: "cm-drill-b", JobName: "capture-one", JobUID: "22222222-2222-4222-8222-222222222222", JobGeneration: "5", RelayIdentityRef: "relay-ref", RelayIdentityVersion: "v2", Sequence: "1", Status: "running"}
	raw, _ := json.Marshal(message)
	peer, _ := url.Parse("spiffe://example.test/worker")
	for _, kind := range []string{"plain", "double-uri", "unknown-field", "duplicate-field", "case-alias", "alias-duplicate", "zero-sequence", "valid"} {
		t.Run(kind, func(t *testing.T) {
			f := &relayFixture{}
			h, err := newRelayHandler(f)
			if err != nil {
				t.Fatal(err)
			}
			body := string(raw)
			if kind == "unknown-field" {
				body = strings.TrimSuffix(body, "}") + `,"admin":true}`
			}
			if kind == "duplicate-field" {
				body = strings.TrimSuffix(body, "}") + `,"sequence":"1"}`
			}
			if kind == "zero-sequence" {
				body = strings.Replace(body, `"sequence":"1"`, `"sequence":"0"`, 1)
			}
			if kind == "case-alias" {
				body = strings.Replace(body, `"sequence"`, `"SEQUENCE"`, 1)
			}
			if kind == "alias-duplicate" {
				body = strings.TrimSuffix(body, "}") + `,"SEQUENCE":"2"}`
			}
			r := httptest.NewRequest("POST", "https://relay.example.test/", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			if kind != "plain" {
				cert := &x509.Certificate{URIs: []*url.URL{peer}}
				if kind == "double-uri" {
					cert.URIs = append(cert.URIs, peer)
				}
				r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if kind == "valid" {
				if w.Code != http.StatusOK || f.calls.Load() != 1 || string(f.raw) != body || f.hash != digest([]byte(body)) {
					t.Fatal(w.Code, f.calls.Load())
				}
			} else if w.Code == http.StatusOK || f.calls.Load() != 0 {
				t.Fatal("invalid transport/body reached commit owner", w.Code, f.calls.Load())
			}
		})
	}
	// These are handler boundary fixtures, NOT A trust/revocation or SQL tests.
	if _, err := newRelayHandler(nil); err == nil {
		t.Fatal("missing D acceptor enabled handler")
	}
}
