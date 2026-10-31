package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	k "clawreef/internal/systembackupkms"
	w "clawreef/internal/systembackupwire"
)

// Actual shared CLI, mTLS + bearer pull, signed independent source grant,
// signed dynamic Generate permit and C framing. SQL/TokenReview are NOT claimed
// by these named control/source/provider fixtures; the service tests own those.
func TestFormalControlEvidenceCLIOriginalKeyUseAndCompleteReadback(t *testing.T) {
	for _, mode := range []string{"sidecar", "proofs", "scope-mismatch", "source-grant-revoked", "pull-grant-revoked", "wrong-nonce", "missing-proof", "forged-body", "trailing-json", "claim-lost", "revoke-after-pull"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			dir, stage := t.TempDir(), t.TempDir()
			proposal := controlCLIProposal(t)
			pinPub, pinKey, _ := ed25519.GenerateKey(rand.Reader)
			defer clear(pinKey)
			pin := k.PermitDeliveryPin{Version: k.PermitDeliveryVersion, Issuer: pinPub, IssuerGrantSHA256: strings.Repeat("e", 64)}
			until := time.Now().UTC().Add(40 * time.Second).Truncate(time.Microsecond)
			jwtFile := skillCLIWrite(t, dir, "job.jwt", []byte("original-job-jwt"))
			var mu sync.Mutex
			var invocation worker.Invocation
			var identity k.JobIdentity
			state, nonce := "", ""
			unknown, pulled := false, false
			generates, candidates, pulls := 0, 0, 0
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
					json.NewEncoder(out).Encode(map[string]any{"auth": map[string]any{"client_token": "local-control-batch-token", "token_type": "batch", "renewable": false, "lease_duration": 10, "policies": []string{"generate-only"}, "metadata": map[string]string{"role": login.Role, "namespace": identity.Namespace, "pod_uid": identity.PodUID, "service_account_uid": identity.ServiceAccountUID}}})
					return
				}
				var request struct {
					Context, Bits string
					KeyVersion    string `json:"key_version"`
				}
				expected, _ := k.TransitContext(invocation.ProviderKey.Request)
				if r.URL.Path != "/v1/transit/datakey/plaintext/backup-key" || r.Header.Get("X-Vault-Token") != "local-control-batch-token" || !unknown || json.NewDecoder(r.Body).Decode(&request) != nil || request.Context != expected || request.Bits != "256" || request.KeyVersion != "1" {
					t.Error("Generate escaped original committed-unknown context")
					out.WriteHeader(403)
					return
				}
				generates++
				json.NewEncoder(out).Encode(map[string]any{"data": map[string]any{"plaintext": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), "ciphertext": "vault:v1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 60)), "key_version": 1}})
			}))
			defer provider.Close()
			part, artifact, limit := ce.Part, ce.LogicalCipherName, int64(ce.MaxBytes)
			if mode == "proofs" {
				part, artifact, limit = ce.ProofPart, ce.LogicalProofCipherName, ce.MaxProofBytes
			}
			locator := proposal.Prepared.Locator
			invocation = worker.Invocation{StagingPath: stage, Request: worker.Request{Version: worker.Version, Operation: ce.Operation, Binding: staging.Binding{BackupID: locator.Expected.Backup, Attempt: "3", Path: part, EnvelopeID: "original-control-envelope", CaptureContextHash: strings.Repeat("c", 64)}, Deadline: until.Add(10 * time.Second), ArtifactName: artifact, MaxArchiveBytes: limit, MaxCompressedBytes: limit, ControlEvidence: &locator}, ProviderKey: &k.Access{Operation: k.Generate, Endpoint: provider.URL, KeyName: "backup-key", Request: w.KeyRequest{Key: w.KeyBinding{Provider: "external-kms", IdentityHash: strings.Repeat("1", 64), RegistryVersion: "r1", ProviderKeyID: "backup-key", ProviderVersion: "1"}, Context: w.KeyContext{InstallationID: locator.Expected.Installation, BackupPublicID: locator.Expected.Backup, AttemptNo: "3", Phase: "capture", Part: part, PartIndex: "0", EnvelopeID: "original-control-envelope", CaptureContextHash: strings.Repeat("c", 64)}}}, FormalCapture: &worker.FormalCaptureSpec{Version: worker.FormalCaptureVersion, ConfigSHA256: strings.Repeat("a", 64), EnvelopeName: "control.envelope", MaxFrames: 64, PermitDelivery: &pin, SourceConfigSHA256: locator.Expected.ConfigSHA256}}
			control := worker.ControlHandler{Authorizer: skillCLIAuth(func(_ context.Context, peer string, r worker.ControlRequest) (worker.Lease, error) {
				mu.Lock()
				defer mu.Unlock()
				if peer != "spiffe://clawmanager/backup/fixture" || r.InvocationSHA256 != identity.InvocationSHA256 || mode == "claim-lost" && pulled {
					return worker.Lease{}, worker.ErrExecution
				}
				lease := worker.Lease{InvocationSHA256: identity.InvocationSHA256, ExpiresAt: until}
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
					t.Error("control evidence used functional action", r.Action)
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
			grantFile := filepath.Join(dir, "source-grant.json")
			handler := http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/control-evidence" {
					control.ServeHTTP(out, r)
					return
				}
				mu.Lock()
				defer mu.Unlock()
				var request worker.ControlRequest
				if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || r.Header.Get("Authorization") != "Bearer original-bound-workload-token" || json.NewDecoder(r.Body).Decode(&request) != nil || !worker.ValidateControl(request) || request.Action != "key-check" || request.InvocationSHA256 != identity.InvocationSHA256 || request.Point != nonce || state != "using" {
					out.WriteHeader(403)
					return
				}
				pulls++
				pulled = true
				if mode == "pull-grant-revoked" {
					out.WriteHeader(403)
					return
				}
				response := ce.SourceResponse{Version: "system-backup-control-evidence-source-response.v1", InvocationSHA256: identity.InvocationSHA256, KeyUseNonce: nonce, AuthoritySHA256: strings.Repeat("b", 64), Until: until, Evidence: append([]ce.RegisteredEvidence(nil), proposal.Evidence...)}
				switch mode {
				case "wrong-nonce":
					response.KeyUseNonce = "foreign-nonce"
				case "missing-proof":
					response.Evidence = response.Evidence[1:]
				case "forged-body":
					response.Evidence[0].Payload = json.RawMessage(`{"foreign":"body"}`)
				case "revoke-after-pull":
					if os.WriteFile(grantFile, []byte("revoked"), 0600) != nil {
						t.Error("fixture revoke failed")
					}
				}
				out.Header().Set("Content-Type", "application/json")
				json.NewEncoder(out).Encode(response)
				if mode == "trailing-json" {
					out.Write([]byte(`{}`))
				}
			})
			client, endpoint := skillCLIMTLSAt(t, handler)
			if err := client.WithWorkloadToken(skillCLIWrite(t, dir, "bound-token", []byte("original-bound-workload-token"))); err != nil {
				t.Fatal(err)
			}
			sourcePub, sourceKey, _ := ed25519.GenerateKey(rand.Reader)
			defer clear(sourceKey)
			mount := worker.ControlEvidenceSourceMount{Endpoint: endpoint, GrantFile: grantFile, Issuer: sourcePub}
			scope, err := worker.ControlEvidenceSourceScopeSHA256(locator.Expected, endpoint)
			if err != nil {
				t.Fatal(err)
			}
			grant := worker.ControlEvidenceSourceGrant{Version: worker.ControlEvidenceSourceGrantVersion, InstallationID: locator.Expected.Installation, ConfigSHA256: locator.Expected.ConfigSHA256, WorkerNamespace: "ns", WorkerServiceAccountUID: "sa", Operation: ce.Operation, ScopeSHA256: scope, NotBefore: time.Now().Add(-time.Minute), Until: until, Revoked: mode == "source-grant-revoked"}
			if mode == "scope-mismatch" {
				grant.ScopeSHA256 = strings.Repeat("f", 64)
			}
			grantRaw, _ := json.Marshal(grant)
			signed, _ := json.Marshal(worker.SignedControlEvidenceSourceGrant{Record: grantRaw, Signature: ed25519.Sign(sourceKey, append([]byte(worker.ControlEvidenceSourceGrantDomain), grantRaw...))})
			mount.GrantSHA256 = skillCLISHA(signed)
			skillCLIWrite(t, dir, "source-grant.json", signed)
			kmsCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: provider.Certificate().Raw})
			materials := worker.FormalCaptureMaterials{Version: worker.FormalCaptureVersion, KMS: k.Config{InstallationID: locator.Expected.Installation, Key: invocation.ProviderKey.Request.Key, Endpoint: provider.URL, KeyName: "backup-key", CAPEM: kmsCA, CASHA256: skillCLISHA(kmsCA), NotBefore: time.Now().Add(-time.Minute), NotAfter: until.Add(time.Minute)}, PermitDelivery: &pin, ControlEvidence: &mount}
			materialRaw, _ := json.Marshal(materials)
			materialFile := skillCLIWrite(t, dir, "materials.json", materialRaw)
			invocation.FormalCapture.ConfigSHA256 = skillCLISHA(materialRaw)
			hash, _ := invocation.Hash()
			identity = k.JobIdentity{Namespace: "ns", PodUID: "pod", ServiceAccountUID: "sa", JobUID: "job", InvocationSHA256: hash, ExecutionGrantSHA256: strings.Repeat("a", 64)}
			raw, _ := json.Marshal(invocation)
			for _, marker := range []string{`"record_groups"`, `"payload"`, `"canonical_redacted_record_sha256"`} {
				if bytes.Contains(raw, []byte(marker)) {
					t.Fatal("plaintext in original invocation")
				}
			}
			decoded, err := worker.ReadInvocation(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			if err = client.Ready(ctx, decoded); err != nil {
				t.Fatal("original ready", err)
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
			valid := mode == "sidecar" || mode == "proofs"
			if !valid {
				if err == nil || stdout.Len() != 0 || candidates != 0 {
					t.Fatal("invalid pull produced candidate", err, generates, pulls, candidates)
				}
				files, _ := os.ReadDir(stage)
				if len(files) != 0 {
					t.Fatal("invalid pull retained candidate/partial")
				}
				if (mode == "scope-mismatch" || mode == "source-grant-revoked") && (generates != 0 || pulls != 0) {
					t.Fatal("bad source grant reached Generate/pull")
				}
				if generates > 1 || pulls > 1 {
					t.Fatal("unknown source attempt retried")
				}
				return
			}
			if err != nil || generates != 1 || candidates != 1 || pulls != 1 {
				t.Fatal("original CLI failed", err, generates, pulls, candidates)
			}
			var result worker.FormalCaptureResult
			if json.Unmarshal(stdout.Bytes(), &result) != nil || !worker.ValidateFormalCaptureResult(decoded, &result) {
				t.Fatal("invalid candidate shape")
			}
			frames, _ := root.ReadFile(result.Ciphertext.Name)
			envelope, _ := root.ReadFile(result.Envelope.Name)
			plain := skillCLIDecrypt(t, decoded, frames, envelope)
			expected := proposal.Prepared.SidecarJSON
			if part == ce.ProofPart {
				expected = proposal.Prepared.ProofsJSON
			}
			if !bytes.Equal(plain, expected) || bytes.Contains(frames, []byte(`"record_groups"`)) || bytes.Contains(frames, []byte(`"canonical_redacted_record_sha256"`)) {
				t.Fatal("complete original C readback mismatch/plaintext leak")
			}
			sidecar, proofs := plain, proposal.Prepared.ProofsJSON
			if part == ce.ProofPart {
				sidecar, proofs = proposal.Prepared.SidecarJSON, plain
			}
			verified, err := ce.Verify(ctx, sidecar, proofs, locator.Expected)
			if err != nil || verified.Groups["event"].Count != 121 {
				t.Fatal("complete decrypted independent protocol readback", err)
			}
			files, _ := os.ReadDir(stage)
			if len(files) != 2 {
				t.Fatal("unexpected plaintext/temp artifact")
			}
		})
	}
}

func controlCLIProposal(t *testing.T) ce.ProposedSource {
	t.Helper()
	end := time.Now().UTC().Add(-time.Second).Truncate(time.Microsecond)
	scope := ce.Scope{Installation: "installation_control_cli", Backup: "sbk_00000000-0000-4000-8000-000000000001", Attempt: 3}
	expected := ce.Expected{Scope: scope, ConfigSHA256: ce.SHA256([]byte("original config")), SourceIdentitySHA256: ce.SHA256([]byte("original source")), SchemaRegistry: ce.RegistryPin{Version: "schema-r1", SHA256: ce.SHA256([]byte("schema registry"))}, RedactionRegistry: ce.RegistryPin{Version: "redaction-r1", SHA256: ce.SHA256([]byte("redaction registry"))}}
	names := []string{"system_backup_v2_backups", "system_backup_v2_evidence"}
	namesRaw, _ := ce.Canonical(names)
	payload, _ := ce.Canonical(ce.SourceExclusionProof{Version: "system-backup-source-control-exclusion.v1", Scope: scope, ConfigSHA256: expected.ConfigSHA256, SourceIdentitySHA256: expected.SourceIdentitySHA256, Registry: expected.SchemaRegistry, ExcludedNamesSHA256: ce.SHA256(namesRaw)})
	source := ce.RegisteredEvidence{PublicID: "sev_original_source_fixture", SHA256: ce.SHA256(payload), OwnerType: "backup", OwnerID: scope.Backup, Type: "verifier_report", Payload: payload}
	snapshot := ce.Snapshot{Expected: expected, Start: end.Add(-time.Minute), End: end, Generated: end, ExcludedControlObjects: names, SourceExclusion: source, Groups: map[string][]ce.TimedDigest{}}
	for _, name := range ce.GroupNames() {
		snapshot.Groups[name] = []ce.TimedDigest{}
	}
	for i := 0; i < 121; i++ {
		snapshot.Groups["event"] = append(snapshot.Groups["event"], ce.TimedDigest{At: snapshot.Start.Add(time.Duration(i+1) * time.Millisecond), SHA256: ce.SHA256([]byte(fmt.Sprintf("canonical redacted event %d", i)))})
	}
	proposal, err := ce.Assemble(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return proposal
}
