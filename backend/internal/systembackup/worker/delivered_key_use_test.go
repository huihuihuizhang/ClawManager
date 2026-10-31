package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	k "clawreef/internal/systembackupkms"
)

// This exercises real mTLS control and pinned TLS provider I/O. The authorizer
// models committed admission here; SQL commit ordering is tested by the issuer.
func TestDeliveredCaptureUsesOriginalReserveAndNeverStaticFallback(t *testing.T) {
	for _, mode := range []string{"valid", "unknown-reserve-ack", "missing", "signature", "nonce", "revoked-after-login"} {
		t.Run(mode, func(t *testing.T) {
			i, env, _ := formalInvocationFixture(t)
			pub, private, _ := ed25519.GenerateKey(rand.Reader)
			pin := k.PermitDeliveryPin{Version: k.PermitDeliveryVersion, Issuer: pub, IssuerGrantSHA256: strings.Repeat("e", 64)}
			i.FormalCapture.PermitDelivery = &pin
			jwtFile := t.TempDir() + "/identity.jwt"
			if e := os.WriteFile(jwtFile, []byte("local-projected-job-jwt"), 0600); e != nil {
				t.Fatal(e)
			}
			var mu sync.Mutex
			state, nonce := "", ""
			var identity k.JobIdentity
			revoked, unknownCommitted := false, false
			logins, generates, reserves, signatures := 0, 0, 0, 0
			provider := httptest.NewTLSServer(http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				out.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/v1/auth/job/login" {
					var login struct {
						Role string `json:"role"`
						JWT  string `json:"jwt"`
					}
					if json.NewDecoder(r.Body).Decode(&login) != nil || login.Role != "original-job-generate" || login.JWT != "local-projected-job-jwt" {
						t.Error("wrong login")
						out.WriteHeader(403)
						return
					}
					logins++
					if mode == "revoked-after-login" {
						revoked = true
					}
					json.NewEncoder(out).Encode(map[string]any{"auth": map[string]any{"client_token": "local-issued-generate-token", "token_type": "batch", "renewable": false, "lease_duration": 10, "policies": []string{"generate-only"}, "metadata": map[string]string{"role": login.Role, "namespace": identity.Namespace, "pod_uid": identity.PodUID, "service_account_uid": identity.ServiceAccountUID}}})
					return
				}
				if r.URL.Path != "/v1/transit/datakey/plaintext/backup-key" || r.Header.Get("X-Vault-Token") != "local-issued-generate-token" || !unknownCommitted {
					t.Error("Generate before unknown admission or wrong provider request")
					out.WriteHeader(403)
					return
				}
				var request struct {
					Context    string `json:"context"`
					Bits       string `json:"bits"`
					KeyVersion string `json:"key_version"`
				}
				expected, _ := k.TransitContext(i.ProviderKey.Request)
				if json.NewDecoder(r.Body).Decode(&request) != nil || request.Context != expected || request.Bits != "256" || request.KeyVersion != "1" {
					t.Error("changed full provider request")
					out.WriteHeader(403)
					return
				}
				generates++
				json.NewEncoder(out).Encode(map[string]any{"data": map[string]any{"plaintext": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), "ciphertext": "vault:v1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 60)), "key_version": 1}})
			}))
			defer provider.Close()
			i.ProviderKey.Endpoint = provider.URL
			expectedHash, _ := i.Hash()
			identity = k.JobIdentity{Namespace: "ns", PodUID: "pod", ServiceAccountUID: "sa", JobUID: "job", InvocationSHA256: expectedHash, ExecutionGrantSHA256: strings.Repeat("a", 64)}
			until := time.Now().UTC().Add(30 * time.Second).Truncate(time.Microsecond)
			var delivery k.DeliveredProviderPermit
			handler := ControlHandler{Authorizer: authorizeFunc(func(_ context.Context, peer string, r ControlRequest) (Lease, error) {
				mu.Lock()
				defer mu.Unlock()
				if peer != "spiffe://clawmanager/backup/fixture" || r.InvocationSHA256 != expectedHash || revoked {
					return Lease{}, ErrExecution
				}
				switch r.Action {
				case "key-reserve":
					reserves++
					if state == "" {
						state, nonce = "reserved", r.Point
						p := k.DeliveredPermitPayload{Version: k.PermitDeliveryVersion, IssuerGrantSHA256: pin.IssuerGrantSHA256, Nonce: nonce, Request: i.ProviderKey.Request, Permit: k.ProviderPermit{Version: "system-backup-provider-permit.v1", Identity: identity, Operation: k.Generate, Endpoint: provider.URL, KeyName: "backup-key", NotBefore: time.Now().UTC().Add(-time.Second), ExpiresAt: until, JWT: k.JWTIdentityGrant{Mount: "job", Role: "original-job-generate", Policy: "generate-only", IdentityFile: jwtFile}}}
						p.Permit.ContextBase64, _ = k.TransitContext(i.ProviderKey.Request)
						if mode == "nonce" {
							p.Nonce = strings.Repeat("0", 32)
						}
						delivery.Payload, _ = json.Marshal(p)
						delivery.Signature = ed25519.Sign(private, append([]byte(k.PermitDeliveryDomain), delivery.Payload...))
						signatures++
						if mode == "signature" {
							delivery.Signature[0] ^= 1
						}
						if mode == "unknown-reserve-ack" {
							return Lease{}, ErrNotReady
						}
					}
					if state != "reserved" || r.Point != nonce {
						return Lease{}, ErrExecution
					}
				case "key-check":
					unknownCommitted = true
				case "key-begin":
					if state != "reserved" {
						return Lease{}, ErrExecution
					}
					state = "using"
				case "key-end":
					if state != "using" {
						return Lease{}, ErrExecution
					}
					state = "finished"
				case "candidate":
					if state != "finished" {
						return Lease{}, ErrExecution
					}
				default:
					t.Error("borrowed functional action", r.Action)
					return Lease{}, ErrExecution
				}
				if r.Point != nonce {
					return Lease{}, ErrExecution
				}
				key := KeyUseLease{Identity: identity, Access: *i.ProviderKey, AuthoritySHA256: strings.Repeat("b", 64), Nonce: nonce, Until: until, State: state}
				lease := Lease{InvocationSHA256: expectedHash, ExpiresAt: until, KeyUse: &key}
				if r.Action == "key-reserve" && mode != "missing" {
					lease.ProviderPermit = &delivery
				}
				if r.Action == "candidate" {
					lease.CandidateSHA256 = FormalCandidateSHA256(i, r.Candidate)
				}
				return lease, nil
			})}
			client, _ := mutualTLSFixture(t, handler)
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: provider.Certificate().Raw})
			caHash := sha256.Sum256(ca)
			config := k.Config{InstallationID: i.ProviderKey.Request.Context.InstallationID, Key: i.ProviderKey.Request.Key, Endpoint: provider.URL, KeyName: "backup-key", CAPEM: ca, CASHA256: hex.EncodeToString(caHash[:]), NotBefore: time.Now().Add(-time.Minute), NotAfter: until.Add(time.Minute)}
			job, e := NewDeliveredCaptureKeyJob(context.Background(), client, i, config, pin)
			if e == nil {
				defer job.Close()
				var result FormalCaptureResult
				result, e = RunFormalCapture(context.Background(), i, job, env)
				if e == nil {
					e = job.ReportCandidate(context.Background(), i, result)
				}
			}
			valid := mode == "valid" || mode == "unknown-reserve-ack"
			if valid != (e == nil) {
				t.Fatal("unexpected outcome", e)
			}
			mu.Lock()
			defer mu.Unlock()
			if signatures != 1 || (mode == "unknown-reserve-ack" && reserves != 2) {
				t.Fatal("reserve replay reissued permit", signatures, reserves)
			}
			if valid {
				if generates != 1 || logins != 1 || state != "finished" {
					t.Fatal("candidate chain incomplete", generates, logins, state)
				}
			} else if generates != 0 {
				t.Fatal("invalid authority reached Generate")
			}
			if _, e := NewCaptureKeyJob(context.Background(), client, i, config, k.PermitMount{}); e == nil {
				t.Fatal("dynamic permit fell back to static constructor")
			}
		})
	}
}

func TestDeliveredMaterialsFreezeOnlyIndependentIssuerPins(t *testing.T) {
	for _, mode := range []string{"valid", "wrong-issuer", "wrong-delegation", "missing", "static-mix"} {
		t.Run(mode, func(t *testing.T) {
			i, _, _ := formalInvocationFixture(t)
			pin := k.PermitDeliveryPin{Version: k.PermitDeliveryVersion, Issuer: bytes.Repeat([]byte{4}, 32), IssuerGrantSHA256: strings.Repeat("b", 64)}
			i.FormalCapture.PermitDelivery = &pin
			copyPin := pin
			m := FormalCaptureMaterials{Version: FormalCaptureVersion, PermitDelivery: &copyPin, KMS: k.Config{InstallationID: i.ProviderKey.Request.Context.InstallationID, Key: i.ProviderKey.Request.Key, Endpoint: i.ProviderKey.Endpoint, KeyName: i.ProviderKey.KeyName}}
			switch mode {
			case "wrong-issuer":
				copyPin.Issuer = bytes.Repeat([]byte{5}, 32)
			case "wrong-delegation":
				copyPin.IssuerGrantSHA256 = strings.Repeat("c", 64)
			case "missing":
				m.PermitDelivery = nil
			case "static-mix":
				m.Permit.PermitPath = "/future-permit.json"
			}
			raw, _ := json.Marshal(m)
			h := sha256.Sum256(raw)
			i.FormalCapture.ConfigSHA256 = hex.EncodeToString(h[:])
			file := t.TempDir() + "/materials.json"
			if e := os.WriteFile(file, raw, 0600); e != nil {
				t.Fatal(e)
			}
			_, e := LoadFormalCaptureMaterials(file, i)
			if (mode == "valid") != (e == nil) {
				t.Fatal("independent pin mismatch", e)
			}
		})
	}
}
