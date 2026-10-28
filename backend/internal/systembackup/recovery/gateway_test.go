package recovery

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func gatewayFixture(t *testing.T, handle func(GatewayRequest) (any, []byte, int)) (*Gateway, context.Context) {
	t.Helper()
	identity := ref("provider")
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
			t.Error("client certificate missing")
		}
		raw, e := io.ReadAll(io.LimitReader(r.Body, MaxDocument+1))
		if e != nil {
			t.Error(e)
		}
		var q GatewayRequest
		if decode(raw, &q) != nil || q.Identity != identity || r.URL.Path != "/recovery/v1" {
			t.Error("invalid bound request")
		}
		payload, stream, status := handle(q)
		if status != 200 {
			w.WriteHeader(status)
			return
		}
		p, _ := Marshal(payload)
		response, _ := Marshal(GatewayResponse{GatewayProtocol, q.Nonce, Hash(raw), identity, time.Now().Add(30 * time.Second).UnixMilli(), p})
		if stream != nil {
			w.Header().Set("X-Recovery-Receipt", string(response))
			w.Write(stream)
			return
		}
		w.Write(response)
	}))
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAnyClientCert}
	s.StartTLS()
	t.Cleanup(s.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})
	keyBytes, e := x509.MarshalPKCS8PrivateKey(s.TLS.Certificates[0].PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	g, e := NewGateway(GatewayConfig{s.URL, identity, Locator{"s3", "fixture", "root", "other-site"}, "inventory_manifest", false}, ca, ca, key)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(g.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return g, ctx
}
func gatewayCapabilities() []Capability {
	now := time.Now().UnixMilli()
	out := []Capability{}
	for _, code := range []string{"scoped_read_credential", "tls_verified", "versioned_absence_proof", "inventory_manifest_listing"} {
		out = append(out, Capability{"catalog", code, "supported", ref("provider"), now - 1000, now + 30000})
	}
	return out
}

func TestGatewayCreateRequiresNativeDeadlineAndNeverRetriesUnknownWrite(t *testing.T) {
	for _, native := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing-native-expiry", true: "lost-reply"}[native], func(t *testing.T) {
			creates := 0
			g, ctx := gatewayFixture(t, func(q GatewayRequest) (any, []byte, int) {
				if q.Operation == "capabilities" {
					c := gatewayCapabilities()
					codes := []string{"conditional_create", "checksum_bound_request", "content_length_bound_request", "scoped_append_credential"}
					if native {
						codes = append(codes, "native_deadline_enforced")
					}
					for _, code := range codes {
						c = append(c, Capability{"catalog", code, "supported", ref("provider"), time.Now().Add(-time.Second).UnixMilli(), time.Now().Add(time.Minute).UnixMilli()})
					}
					return c, nil, 200
				}
				if q.Operation == "conditional_create" {
					creates++
					return nil, nil, 503
				}
				t.Error("unexpected operation", q.Operation)
				return nil, nil, 500
			})
			g.config.AllowAppend = true
			r := requestFor("create", "manifest.json", []byte(`{}`), time.Now().Add(time.Minute).UnixMilli())
			r.Target = g.Identity()
			if _, e := g.Create(ctx, r); e == nil {
				t.Fatal("unknown write accepted")
			}
			want := 0
			if native {
				want = 1
			}
			if creates != want {
				t.Fatal("unexpected sends", creates, want)
			}
		})
	}
}
func TestGatewayBindsReadsAndStreamsExactVersionWithoutWrites(t *testing.T) {
	data := []byte("isolated encrypted bytes")
	o := Object{"workspace/data.enc", "opaque+version/1", int64(len(data)), Hash(data)}
	g, ctx := gatewayFixture(t, func(q GatewayRequest) (any, []byte, int) {
		switch q.Operation {
		case "capabilities":
			return gatewayCapabilities(), nil, 200
		case "observe":
			return Observation{"present", o.Key, o, ref("proof"), true, time.Now().Add(time.Minute).UnixMilli()}, nil, 200
		case "open":
			var requested Object
			json.Unmarshal(q.Arguments, &requested)
			if requested != o {
				t.Error("immutable object changed")
			}
			return o, data, 200
		default:
			t.Error("unexpected operation", q.Operation)
			return nil, nil, 500
		}
	})
	if _, e := g.Observe(ctx, o.Key); e != nil {
		t.Fatal(e)
	}
	r, e := g.Open(ctx, o)
	if e != nil {
		t.Fatal(e)
	}
	got, _ := io.ReadAll(r)
	r.Close()
	if !bytes.Equal(got, data) {
		t.Fatal("stream changed")
	}
	rq := requestFor("action", "manifest.json", []byte(`{}`), time.Now().Add(time.Minute).UnixMilli())
	rq.Target = g.Identity()
	if _, e = g.Create(ctx, rq); e == nil {
		t.Fatal("read role created object")
	}
}
func TestGatewayRejectsHTTP404UnknownProofAndWrongStreamVersion(t *testing.T) {
	for _, scenario := range []string{"404", "weak", "wrong-version"} {
		t.Run(scenario, func(t *testing.T) {
			data := []byte("fixture")
			o := Object{"part/data", "v1", 7, Hash(data)}
			g, ctx := gatewayFixture(t, func(q GatewayRequest) (any, []byte, int) {
				if q.Operation == "capabilities" {
					return gatewayCapabilities(), nil, 200
				}
				if scenario == "404" {
					return nil, nil, 404
				}
				if scenario == "weak" {
					return Observation{State: "absent", Key: o.Key}, nil, 200
				}
				bad := o
				bad.Version = "v2"
				return bad, data, 200
			})
			if scenario == "wrong-version" {
				if r, e := g.Open(ctx, o); e == nil {
					r.Close()
					t.Fatal("replaced version accepted")
				}
			} else if _, e := g.Observe(ctx, o.Key); e == nil {
				t.Fatal("unproved absence accepted")
			}
		})
	}
}
func TestGatewayRejectsReplayedOrExpiredReceipt(t *testing.T) {
	g, ctx := gatewayFixture(t, func(GatewayRequest) (any, []byte, int) { return gatewayCapabilities(), nil, 200 })
	_ = ctx
	request := GatewayRequest{Nonce: "new"}
	sent := []byte(`{}`)
	for _, scenario := range []string{"nonce", "hash", "expired", "identity"} {
		p, _ := Marshal(gatewayCapabilities())
		r := GatewayResponse{GatewayProtocol, "new", Hash(sent), g.Identity(), time.Now().Add(time.Second).UnixMilli(), p}
		switch scenario {
		case "nonce":
			r.Nonce = "old"
		case "hash":
			r.RequestSHA256 = Hash([]byte("other"))
		case "expired":
			r.ValidUntil = 1
		case "identity":
			r.Identity = ref("other")
		}
		raw, _ := Marshal(r)
		var out []Capability
		if g.response(raw, request, sent, &out) == nil {
			t.Fatal(scenario)
		}
	}
}
