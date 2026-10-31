package systembackupkms

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Two independent original Job authorities and signed delivered permits use
// real overlapping TLS logins/Generate. The first login cannot complete until
// the second has read its own projection. Wrong provider Pod/SA/namespace
// metadata must still fail before that Job can call Generate.
func TestDeliveredProjectedIdentitiesInterleaveDistinctJobs(t *testing.T) {
	for _, wrong := range []string{"", "pod_uid", "namespace", "service_account_uid"} {
		t.Run("wrong_"+wrong, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			public, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(key)
			pin := PermitDeliveryPin{Version: PermitDeliveryVersion, Issuer: public, IssuerGrantSHA256: strings.Repeat("a", 64)}
			var originals [2]*deliveryOriginal
			var contexts [2]string
			var loginCount, generateCount atomic.Int32
			entered := make(chan int, 2)
			release := make(chan struct{})
			server := httptest.NewTLSServer(http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
				var body map[string]string
				if json.NewDecoder(r.Body).Decode(&body) != nil {
					out.WriteHeader(403)
					return
				}
				if r.URL.Path == "/v1/auth/original-jwt/login" {
					index := -1
					for n := 0; n < 2; n++ {
						if body["jwt"] == fmt.Sprintf("original-distinct-projected-jwt-%d", n) {
							index = n
						}
					}
					if index < 0 || body["role"] != "original-job-generate" {
						out.WriteHeader(403)
						return
					}
					loginCount.Add(1)
					entered <- index
					select {
					case <-release:
					case <-r.Context().Done():
						return
					}
					identity := originals[index].i
					metadata := map[string]string{"role": "original-job-generate", "namespace": identity.Namespace, "pod_uid": identity.PodUID, "service_account_uid": identity.ServiceAccountUID}
					if wrong != "" && index == 0 {
						metadata[wrong] = "another-original-job"
					}
					_ = json.NewEncoder(out).Encode(map[string]any{"auth": map[string]any{"client_token": fmt.Sprintf("original-issued-job-token-%d", index), "token_type": "batch", "renewable": false, "lease_duration": 1, "policies": []string{"original-generate-only"}, "metadata": metadata}})
					return
				}
				index := -1
				for n := 0; n < 2; n++ {
					if r.Header.Get("X-Vault-Token") == fmt.Sprintf("original-issued-job-token-%d", n) {
						index = n
					}
				}
				if index < 0 || r.URL.Path != "/v1/transit/datakey/plaintext/backup-key" || body["context"] != contexts[index] || body["bits"] != "256" || body["key_version"] != "3" {
					out.WriteHeader(403)
					return
				}
				generateCount.Add(1)
				_ = json.NewEncoder(out).Encode(map[string]any{"data": map[string]any{"plaintext": bytes.Repeat([]byte{byte(index + 1)}, 32), "ciphertext": testCiphertext(), "key_version": 3}})
			}))
			defer server.Close()
			var jobs [2]*CaptureJob
			for n := 0; n < 2; n++ {
				request := testRequest()
				request.Context.PartIndex = fmt.Sprint(n)
				request.Context.Part = fmt.Sprintf("part-%d", n)
				original := &deliveryOriginal{testOriginal: &testOriginal{i: JobIdentity{Namespace: "backup", PodUID: fmt.Sprintf("actual-original-pod-%d", n), ServiceAccountUID: "original-worker-sa", JobUID: fmt.Sprintf("actual-original-job-%d", n), InvocationSHA256: hash([]byte(fmt.Sprint(n))), ExecutionGrantSHA256: strings.Repeat("b", 64)}, until: time.Now().Add(time.Minute)}, nonce: strings.Repeat(fmt.Sprint(n+1), 32)}
				original.access = Access{Request: request, Operation: Generate, Endpoint: server.URL, KeyName: "backup-key"}
				originals[n] = original
				file := filepath.Join(t.TempDir(), original.i.PodUID, "token")
				if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(file, []byte(fmt.Sprintf("original-distinct-projected-jwt-%d", n)), 0600); err != nil {
					t.Fatal(err)
				}
				contexts[n], err = TransitContext(request)
				if err != nil {
					t.Fatal(err)
				}
				payload := DeliveredPermitPayload{Version: PermitDeliveryVersion, IssuerGrantSHA256: pin.IssuerGrantSHA256, Nonce: original.nonce, Request: request, Permit: ProviderPermit{Version: "system-backup-provider-permit.v1", Identity: original.i, Operation: Generate, Endpoint: server.URL, KeyName: "backup-key", ContextBase64: contexts[n], NotBefore: time.Now().Add(-time.Second), ExpiresAt: time.Now().Add(45 * time.Second), JWT: JWTIdentityGrant{Mount: "original-jwt", Role: "original-job-generate", Policy: "original-generate-only", IdentityFile: file}}}
				raw, _ := json.Marshal(payload)
				delivery := DeliveredProviderPermit{Payload: raw, Signature: ed25519.Sign(key, append([]byte(PermitDeliveryDomain), raw...))}
				jobs[n], err = NewDeliveredCaptureJob(ctx, testConfig(server), pin, delivery, original, request)
				if err != nil {
					t.Fatal(err)
				}
				defer jobs[n].Close()
			}
			type outcome struct {
				index int
				err   error
				used  bool
			}
			finished := make(chan outcome, 2)
			for n := 0; n < 2; n++ {
				go func(index int) {
					used := false
					_, err := jobs[index].WithDEK(ctx, func(key []byte) error {
						used = true
						if !bytes.Equal(key, bytes.Repeat([]byte{byte(index + 1)}, 32)) {
							return fmt.Errorf("cross-Job plaintext")
						}
						return nil
					})
					finished <- outcome{index, err, used}
				}(n)
			}
			seen := map[int]bool{}
			for len(seen) < 2 {
				select {
				case index := <-entered:
					seen[index] = true
				case <-ctx.Done():
					close(release)
					t.Fatal("two original logins did not overlap", ctx.Err())
				}
			}
			close(release)
			for n := 0; n < 2; n++ {
				result := <-finished
				expected := result.index != 0 || wrong == ""
				if expected && (result.err != nil || !result.used) {
					t.Fatal("distinct original projected Job failed", result.index, result.err)
				}
				if !expected && (result.err == nil || result.used) {
					t.Fatal("wrong provider workload metadata admitted")
				}
			}
			want := int32(2)
			if wrong != "" {
				want = 1
			}
			if loginCount.Load() != 2 || generateCount.Load() != want {
				t.Fatal("original login/Generate counts", loginCount.Load(), generateCount.Load())
			}
		})
	}
}
