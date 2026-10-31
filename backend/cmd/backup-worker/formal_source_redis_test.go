package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	c "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/recovery"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/testfixture"
	"clawreef/internal/systembackup/worker"
	k "clawreef/internal/systembackupkms"
	w "clawreef/internal/systembackupwire"
)

// Actual shared CLI route, mTLS control, signed delivery, TLS JWT/Generate and
// independent signed source grant + TLS Redis protocol. Control states and
// Redis responses are named fixtures; this is not a real SQL issuer/Lua test.
func TestFormalSourceRedisCLIUsesOriginalSourceGrantAndNeverFunctionalAcquire(t *testing.T) {
	for _, mode := range []string{"valid-empty", "valid-nonempty", "source-scope-changed", "source-exclusion-changed", "source-grant-revoked", "source-credential-replaced", "wrong-server", "wrong-ca", "wrong-password"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			dir, stage := t.TempDir(), t.TempDir()
			grantFile := filepath.Join(dir, "source-grant.json")
			scenario := testfixture.RedisScenario{TLS: true, ServerID: strings.Repeat("a", 40), ExpectedUser: "original-source-reader", ExpectedPassword: "independent-source-password", PageSize: 1}
			if mode != "valid-empty" {
				scenario.Keys = []testfixture.RedisKey{{Key: "app:events", Type: "stream", Dump: []byte("named-stream-dump-with-group-pel"), PTTL: 6000, Groups: []any{[]any{[]byte("name"), []byte("original-workers"), []byte("consumers"), int64(1), []byte("pending"), int64(1), []byte("last-delivered-id"), []byte("2-0")}}}, {Key: "app:state", Type: "string", Dump: []byte("private-redis-original-state"), PTTL: -1}}
			}
			if mode == "wrong-server" {
				scenario.ServerID = strings.Repeat("c", 40)
			}
			if mode == "source-grant-revoked" {
				scenario.BeforeCommand = func(op string) {
					if op == "EVAL_RO" {
						if os.WriteFile(grantFile, []byte("revoked"), 0600) != nil {
							t.Error("source grant fixture revocation failed")
						}
					}
				}
			}
			redis := testfixture.NewRedisProtocol(t, scenario)
			pinPub, pinKey, _ := ed25519.GenerateKey(rand.Reader)
			defer clear(pinKey)
			pin := k.PermitDeliveryPin{Version: k.PermitDeliveryVersion, Issuer: pinPub, IssuerGrantSHA256: strings.Repeat("e", 64)}
			until := time.Now().UTC().Add(40 * time.Second).Truncate(time.Microsecond)
			jwtFile := skillCLIWrite(t, dir, "job.jwt", []byte("original-job-jwt"))
			var mu sync.Mutex
			var invocation worker.Invocation
			var identity k.JobIdentity
			state, nonce := "", ""
			unknown := false
			generates, candidates := 0, 0
			provider := httptest.NewTLSServer(http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				out.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/v1/auth/job/login" {
					var login struct{ Role, JWT string }
					if json.NewDecoder(r.Body).Decode(&login) != nil || login.Role != "original-job-generate" || login.JWT != "original-job-jwt" {
						t.Error("wrong original JWT login")
						out.WriteHeader(403)
						return
					}
					json.NewEncoder(out).Encode(map[string]any{"auth": map[string]any{"client_token": "local-redis-batch-token", "token_type": "batch", "renewable": false, "lease_duration": 10, "policies": []string{"generate-only"}, "metadata": map[string]string{"role": login.Role, "namespace": identity.Namespace, "pod_uid": identity.PodUID, "service_account_uid": identity.ServiceAccountUID}}})
					return
				}
				var request struct {
					Context, Bits string
					KeyVersion    string `json:"key_version"`
				}
				expected, _ := k.TransitContext(invocation.ProviderKey.Request)
				if r.URL.Path != "/v1/transit/datakey/plaintext/backup-key" || r.Header.Get("X-Vault-Token") != "local-redis-batch-token" || !unknown || json.NewDecoder(r.Body).Decode(&request) != nil || request.Context != expected || request.Bits != "256" || request.KeyVersion != "1" {
					t.Error("Generate escaped original committed-unknown/context fixture")
					out.WriteHeader(403)
					return
				}
				generates++
				json.NewEncoder(out).Encode(map[string]any{"data": map[string]any{"plaintext": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), "ciphertext": "vault:v1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 60)), "key_version": 1}})
			}))
			defer provider.Close()
			policy := &c.RedisCapturePolicy{Policy: recovery.RedisPolicy{Source: recovery.Reference{ID: "original_redis", Version: "source-v1", SHA256: strings.Repeat("d", 64)}, Topology: "shared_keyspace", CaptureMode: "scan_dump", TTLPolicy: "preserve_absolute", Purpose: "acceptance", DB: 2, Prefixes: []string{"app:"}, MaxItems: 100, MaxBytes: 1 << 20, MaxClockSkew: 3000}, ServerID: strings.Repeat("a", 40), ExcludePrefixes: []string{"app:control:"}}
			invocation = worker.Invocation{StagingPath: stage, Request: worker.Request{Version: worker.Version, Operation: "capture-source-redis", Binding: staging.Binding{BackupID: "sbk_redis_cli", Attempt: "3", Path: "source_redis", EnvelopeID: "original-redis-envelope", CaptureContextHash: strings.Repeat("c", 64)}, Deadline: until.Add(10 * time.Second), ArtifactName: "source-redis.enc", MaxArchiveBytes: 1 << 20, MaxCompressedBytes: 1 << 20, SourceRedis: policy}, ProviderKey: &k.Access{Operation: k.Generate, Endpoint: provider.URL, KeyName: "backup-key", Request: w.KeyRequest{Key: w.KeyBinding{Provider: "external-kms", IdentityHash: strings.Repeat("1", 64), RegistryVersion: "r1", ProviderKeyID: "backup-key", ProviderVersion: "1"}, Context: w.KeyContext{InstallationID: "installation_redis_cli", BackupPublicID: "sbk_redis_cli", AttemptNo: "3", Phase: "capture", Part: "source_redis", PartIndex: "0", EnvelopeID: "original-redis-envelope", CaptureContextHash: strings.Repeat("c", 64)}}}, FormalCapture: &worker.FormalCaptureSpec{Version: worker.FormalCaptureVersion, ConfigSHA256: strings.Repeat("a", 64), EnvelopeName: "source-redis.envelope", MaxFrames: 8, PermitDelivery: &pin, SourceConfigSHA256: strings.Repeat("b", 64)}}
			password := "independent-source-password"
			if mode == "wrong-password" {
				password = "wrong-independent-password"
			}
			credentialRaw, _ := json.Marshal(map[string]any{"username": "original-source-reader", "password": []byte(password)})
			credentialFile := skillCLIWrite(t, dir, "source-credential.json", credentialRaw)
			sourcePub, sourceKey, _ := ed25519.GenerateKey(rand.Reader)
			defer clear(sourceKey)
			caFile := skillCLIWrite(t, dir, "source-ca.pem", redis.CAPEM)
			mount := worker.FormalSourceMount{GrantFile: grantFile, Issuer: sourcePub, CredentialFile: credentialFile, CredentialSHA256: skillCLISHA(credentialRaw), Redis: &worker.SourceTLSMapping{Address: redis.Address, ServerName: "127.0.0.1", CAFile: caFile, CASHA256: skillCLISHA(redis.CAPEM)}, RedisScope: &worker.RedisSourceBoundary{ID: policy.Policy.Source.ID, ServerID: policy.ServerID, Database: policy.Policy.DB}, RedisPrefixes: append([]string{}, policy.Policy.Prefixes...), RedisExcludedPrefixes: append([]string{}, policy.ExcludePrefixes...)}
			scope, err := worker.FormalSourceScopeSHA256(invocation, mount)
			if err != nil {
				t.Fatal("original source scope mapping", err)
			}
			grant := worker.FormalSourceGrant{Version: worker.FormalSourceGrantVersion, InstallationID: invocation.ProviderKey.Request.Context.InstallationID, ConfigSHA256: invocation.FormalCapture.SourceConfigSHA256, WorkerNamespace: "ns", WorkerServiceAccountUID: "sa", Operation: invocation.Request.Operation, ScopeSHA256: scope, CredentialSHA256: mount.CredentialSHA256, NotBefore: time.Now().Add(-time.Minute), Until: until}
			grantRaw, _ := json.Marshal(grant)
			signed, _ := json.Marshal(worker.SignedFormalSourceGrant{Record: grantRaw, Signature: ed25519.Sign(sourceKey, append([]byte(worker.FormalSourceGrantDomain), grantRaw...))})
			mount.GrantSHA256 = skillCLISHA(signed)
			skillCLIWrite(t, dir, "source-grant.json", signed)
			kmsCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: provider.Certificate().Raw})
			materials := worker.FormalCaptureMaterials{Version: worker.FormalCaptureVersion, KMS: k.Config{InstallationID: invocation.ProviderKey.Request.Context.InstallationID, Key: invocation.ProviderKey.Request.Key, Endpoint: provider.URL, KeyName: "backup-key", CAPEM: kmsCA, CASHA256: skillCLISHA(kmsCA), NotBefore: time.Now().Add(-time.Minute), NotAfter: until.Add(time.Minute)}, PermitDelivery: &pin, Sources: &mount}
			materialRaw, _ := json.Marshal(materials)
			materialFile := skillCLIWrite(t, dir, "materials.json", materialRaw)
			invocation.FormalCapture.ConfigSHA256 = skillCLISHA(materialRaw)
			switch mode {
			case "source-scope-changed":
				invocation.Request.SourceRedis.Policy.Prefixes = []string{"foreign:"}
			case "source-exclusion-changed":
				invocation.Request.SourceRedis.ExcludePrefixes = []string{"app:"}
			case "source-credential-replaced":
				os.WriteFile(credentialFile, []byte("replacement"), 0600)
			case "wrong-ca":
				os.WriteFile(caFile, []byte("replacement-ca"), 0600)
			}
			hash, _ := invocation.Hash()
			identity = k.JobIdentity{Namespace: "ns", PodUID: "pod", ServiceAccountUID: "sa", JobUID: "job", InvocationSHA256: hash, ExecutionGrantSHA256: strings.Repeat("a", 64)}
			handler := worker.ControlHandler{Authorizer: skillCLIAuth(func(_ context.Context, peer string, r worker.ControlRequest) (worker.Lease, error) {
				mu.Lock()
				defer mu.Unlock()
				if peer != "spiffe://clawmanager/backup/fixture" || r.InvocationSHA256 != hash {
					return worker.Lease{}, worker.ErrExecution
				}
				lease := worker.Lease{InvocationSHA256: hash, ExpiresAt: until}
				if r.Action == "ready" {
					return lease, nil
				}
				switch r.Action {
				case "key-reserve":
					if state != "" {
						return worker.Lease{}, worker.ErrExecution
					}
					state, nonce = "reserved", r.Point
				case "key-check":
					unknown = true
				case "key-begin":
					if state != "reserved" {
						return worker.Lease{}, worker.ErrExecution
					}
					state = "using"
				case "key-end":
					if state != "using" {
						return worker.Lease{}, worker.ErrExecution
					}
					state = "finished"
				case "candidate":
					if state != "finished" {
						return worker.Lease{}, worker.ErrExecution
					}
					candidates++
					lease.CandidateSHA256 = worker.FormalCandidateSHA256(invocation, r.Candidate)
				default:
					t.Error("source Redis used functional control action", r.Action)
					return worker.Lease{}, worker.ErrExecution
				}
				if r.Point != nonce {
					return worker.Lease{}, worker.ErrExecution
				}
				lease.KeyUse = &worker.KeyUseLease{Identity: identity, Access: *invocation.ProviderKey, AuthoritySHA256: strings.Repeat("b", 64), Nonce: nonce, Until: until, State: state}
				if r.Action == "key-reserve" {
					payload := k.DeliveredPermitPayload{Version: k.PermitDeliveryVersion, IssuerGrantSHA256: pin.IssuerGrantSHA256, Nonce: nonce, Request: invocation.ProviderKey.Request, Permit: k.ProviderPermit{Version: "system-backup-provider-permit.v1", Identity: identity, Operation: k.Generate, Endpoint: provider.URL, KeyName: "backup-key", NotBefore: time.Now().Add(-time.Second), ExpiresAt: until, JWT: k.JWTIdentityGrant{Mount: "job", Role: "original-job-generate", Policy: "generate-only", IdentityFile: jwtFile}}}
					payload.Permit.ContextBase64, _ = k.TransitContext(invocation.ProviderKey.Request)
					raw, _ := json.Marshal(payload)
					lease.ProviderPermit = &k.DeliveredProviderPermit{Payload: raw, Signature: ed25519.Sign(pinKey, append([]byte(k.PermitDeliveryDomain), raw...))}
				}
				return lease, nil
			})}
			client := skillCLIMTLS(t, handler)
			raw, _ := json.Marshal(invocation)
			decoded, err := worker.ReadInvocation(bytes.NewReader(raw))
			if err != nil {
				t.Fatal("actual original request decoder", err)
			}
			if err := client.Ready(ctx, decoded); err != nil {
				t.Fatal("actual original Ready", err)
			}
			root, err := os.OpenRoot(stage)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			var stdout bytes.Buffer
			err = runFormalInvocation(ctx, decoded, client, materialFile, root, &stdout)
			mu.Lock()
			defer mu.Unlock()
			valid := mode == "valid-empty" || mode == "valid-nonempty"
			if !valid {
				if err == nil || stdout.Len() != 0 || candidates != 0 {
					t.Fatal("invalid source produced candidate", mode, err)
				}
				files, _ := os.ReadDir(stage)
				if len(files) != 0 {
					t.Fatal("invalid source retained candidate/partial")
				}
				if mode != "source-grant-revoked" && generates != 0 {
					t.Fatal("bad source reached Generate")
				}
				return
			}
			if err != nil || generates != 1 || candidates != 1 {
				t.Fatal("actual source Redis CLI failed", err, generates, candidates)
			}
			var candidate worker.FormalCaptureResult
			if json.Unmarshal(stdout.Bytes(), &candidate) != nil || !worker.ValidateFormalCaptureResult(decoded, &candidate) {
				t.Fatal("wrong original candidate")
			}
			frames, _ := root.ReadFile(candidate.Ciphertext.Name)
			envelope, _ := root.ReadFile(candidate.Envelope.Name)
			if bytes.Contains(frames, []byte("private-redis-original-state")) {
				t.Fatal("plaintext Redis source escaped")
			}
			compressed := skillCLIDecrypt(t, decoded, frames, envelope)
			z, err := gzip.NewReader(bytes.NewReader(compressed))
			if err != nil {
				t.Fatal(err)
			}
			defer z.Close()
			snapshot, err := c.ReadSourceRedisSnapshot(ctx, z, *decoded.Request.SourceRedis)
			if err != nil {
				t.Fatal("independent original content readback", err)
			}
			defer c.ClearSourceRedisSnapshot(snapshot)
			expected := 0
			if mode == "valid-nonempty" {
				expected = 2
			}
			if len(snapshot.Items) != expected {
				t.Fatal("lost actual empty/nonempty enumeration")
			}
			if _, err := io.Copy(io.Discard, z); err != nil {
				t.Fatal("gzip EOF", err)
			}
		})
	}
}
