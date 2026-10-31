package systembackupkms

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type deliveryOriginal struct {
	*testOriginal
	nonce string
}

func (o *deliveryOriginal) PermitNonce() string { return o.nonce }

func TestDeliveredPermitBindsOriginalPostCreationIdentityAndNonce(t *testing.T) {
	for _, mode := range []string{"valid", "wrong-grant", "wrong-nonce", "wrong-request", "wrong-invocation", "wrong-job", "wrong-pod", "wrong-sa", "wrong-execution-grant", "unwrap", "static-credential", "future", "expired", "beyond-original", "wrong-domain", "unknown-field", "duplicate-field", "issuer-substitution", "nonce-changed-after-construction", "revoked-after-login"} {
		t.Run(mode, func(t *testing.T) {
			pub, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(key)
			pin := PermitDeliveryPin{Version: PermitDeliveryVersion, Issuer: pub, IssuerGrantSHA256: strings.Repeat("a", 64)}
			// Frozen materials contain independent issuer/delegation pins only.
			// Compute their hash BEFORE any permit or real workload UID exists.
			frozen, _ := json.Marshal(pin)
			invocationHash := hash(append([]byte("original frozen invocation:"), frozen...))
			original := &deliveryOriginal{testOriginal: &testOriginal{i: JobIdentity{Namespace: "backup", PodUID: "actual-created-pod", ServiceAccountUID: "actual-sa", JobUID: "actual-created-job", InvocationSHA256: invocationHash, ExecutionGrantSHA256: strings.Repeat("b", 64)}, until: time.Now().Add(time.Minute)}, nonce: strings.Repeat("c", 32)}
			identityFile := filepath.Join(t.TempDir(), "projected-jwt")
			if err := os.WriteFile(identityFile, []byte("local-projected-job-jwt"), 0600); err != nil {
				t.Fatal(err)
			}
			var logins, providers atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(out http.ResponseWriter, req *http.Request) {
				if req.URL.Path == "/v1/auth/original-jwt/login" {
					logins.Add(1)
					var body map[string]string
					if json.NewDecoder(req.Body).Decode(&body) != nil || body["role"] != "original-job-generate" || body["jwt"] != "local-projected-job-jwt" {
						t.Error("wrong independently issued JWT permission")
					}
					if mode == "revoked-after-login" {
						original.revoked = true
					}
					json.NewEncoder(out).Encode(map[string]any{"auth": map[string]any{"client_token": "local-issued-generate-token", "token_type": "batch", "renewable": false, "lease_duration": 10, "policies": []string{"original-generate-only"}, "metadata": map[string]string{"role": "original-job-generate", "namespace": original.i.Namespace, "pod_uid": original.i.PodUID, "service_account_uid": original.i.ServiceAccountUID}}})
					return
				}
				providers.Add(1)
				if req.URL.Path != "/v1/transit/datakey/plaintext/backup-key" || req.Header.Get("X-Vault-Token") != "local-issued-generate-token" {
					t.Error("wrong provider operation")
				}
				var body map[string]any
				expectedContext, _ := TransitContext(testRequest())
				if json.NewDecoder(req.Body).Decode(&body) != nil || body["key_version"] != "3" || body["context"] != expectedContext || body["bits"] != "256" {
					t.Error("wrong exact provider version")
				}
				json.NewEncoder(out).Encode(map[string]any{"data": map[string]any{"plaintext": bytes.Repeat([]byte{7}, 32), "ciphertext": testCiphertext(), "key_version": 3}})
			}))
			defer server.Close()
			config := testConfig(server)
			original.access = Access{Request: testRequest(), Operation: Generate, Endpoint: server.URL, KeyName: "backup-key"}
			context64, _ := TransitContext(testRequest())
			payload := DeliveredPermitPayload{Version: PermitDeliveryVersion, IssuerGrantSHA256: pin.IssuerGrantSHA256, Nonce: original.nonce, Request: testRequest(), Permit: ProviderPermit{Version: "system-backup-provider-permit.v1", Identity: original.i, Operation: Generate, Endpoint: server.URL, KeyName: "backup-key", ContextBase64: context64, NotBefore: time.Now().Add(-time.Second), ExpiresAt: time.Now().Add(45 * time.Second), JWT: JWTIdentityGrant{Mount: "original-jwt", Role: "original-job-generate", Policy: "original-generate-only", IdentityFile: identityFile}}}
			switch mode {
			case "wrong-grant":
				payload.IssuerGrantSHA256 = strings.Repeat("d", 64)
			case "wrong-nonce":
				payload.Nonce = strings.Repeat("d", 32)
			case "wrong-request":
				payload.Request.Key.ProviderVersion = "4"
			case "wrong-invocation":
				payload.Permit.Identity.InvocationSHA256 = strings.Repeat("d", 64)
			case "wrong-job":
				payload.Permit.Identity.JobUID = "other"
			case "wrong-pod":
				payload.Permit.Identity.PodUID = "other"
			case "wrong-sa":
				payload.Permit.Identity.ServiceAccountUID = "other"
			case "wrong-execution-grant":
				payload.Permit.Identity.ExecutionGrantSHA256 = strings.Repeat("d", 64)
			case "unwrap":
				payload.Permit.Operation = Unwrap
			case "static-credential":
				payload.Permit.JWT = JWTIdentityGrant{}
				payload.Permit.CredentialRef = "static"
				payload.Permit.CredentialSHA256 = strings.Repeat("d", 64)
			case "future":
				payload.Permit.NotBefore = time.Now().Add(time.Second)
			case "expired":
				payload.Permit.ExpiresAt = time.Now().Add(-time.Second)
			case "beyond-original":
				payload.Permit.ExpiresAt = original.until.Add(time.Second)
			}
			raw, _ := json.Marshal(payload)
			if mode == "unknown-field" {
				raw = append([]byte(`{"override":true,`), raw[1:]...)
			}
			if mode == "duplicate-field" {
				raw = append([]byte(`{"nonce":"`+payload.Nonce+`",`), raw[1:]...)
			}
			domain := PermitDeliveryDomain
			if mode == "wrong-domain" {
				domain = ""
			}
			delivery := DeliveredProviderPermit{Payload: raw, Signature: ed25519.Sign(key, append([]byte(domain), raw...))}
			if mode == "issuer-substitution" {
				pin.Issuer, _, _ = ed25519.GenerateKey(rand.Reader)
			}
			job, err := NewDeliveredCaptureJob(context.Background(), config, pin, delivery, original, testRequest())
			preAdmissionNegative := mode != "valid" && mode != "nonce-changed-after-construction" && mode != "revoked-after-login"
			if preAdmissionNegative {
				if job != nil {
					job.Close()
				}
				if err == nil || logins.Load() != 0 || providers.Load() != 0 {
					t.Fatal("invalid original signed delivery admitted", err)
				}
				return
			}
			if err != nil {
				t.Fatal("valid dynamic delivery rejected", err)
			}
			defer job.Close()
			// Constructor owns byte copies; mutating a DTO cannot redirect it.
			clear(delivery.Payload)
			clear(delivery.Signature)
			clear(pin.Issuer)
			if mode == "nonce-changed-after-construction" {
				original.nonce = strings.Repeat("e", 32)
			}
			used := false
			wrapped, err := job.WithDEK(context.Background(), func(key []byte) error {
				used = true
				if !bytes.Equal(key, bytes.Repeat([]byte{7}, 32)) {
					t.Fatal("wrong DEK")
				}
				return nil
			})
			if mode == "valid" {
				if err != nil || !used || logins.Load() != 1 || providers.Load() != 1 || len(wrapped.Ciphertext) == 0 {
					t.Fatal("original dynamic Generate failed", err)
				}
				if _, err = job.WithDEK(context.Background(), func([]byte) error { t.Fatal("replayed Generate"); return nil }); err == nil || providers.Load() != 1 {
					t.Fatal("dynamic permit bypassed original single-use guard")
				}
			} else if err == nil || used || providers.Load() != 0 {
				t.Fatal("current original nonce/revocation was ignored", err)
			}
		})
	}
}
