package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	k "clawreef/internal/systembackupkms"
	sh "clawreef/internal/systembackupskillhub"
	w "clawreef/internal/systembackupwire"
)

type skillCLIAuth func(context.Context, string, worker.ControlRequest) (worker.Lease, error)

func (f skillCLIAuth) Authorize(ctx context.Context, p string, r worker.ControlRequest) (worker.Lease, error) {
	return f(ctx, p, r)
}
func skillCLISHA(raw []byte) string { s := sha256.Sum256(raw); return hex.EncodeToString(s[:]) }
func skillCLIWrite(t *testing.T, dir, name string, raw []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Exercises ReadInvocation and the SAME production formal phase invoked by
// the Linux CLI after Ready. Windows platform guards remain intact. The
// original authority/commit is a named fixture; D5.5 tests the actual SQL owner.
func TestFormalSkillsCLIOriginalControlPinnedSourcesAndGenerate(t *testing.T) {
	for _, mode := range []string{"valid", "wrong-request-version", "missing-version", "changed-version", "wrong-sha", "truncated-eof", "source-revoked", "outside-prefix"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			stage := t.TempDir()
			var mu sync.Mutex
			gets, generates, candidates, reserves := 0, 0, 0, 0
			grantFile := filepath.Join(dir, "source-grant.json")
			body := []byte("original Skill package bytes\x00\xff")
			orphan := []byte("unreferenced original prefix object")
			source := httptest.NewTLSServer(http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
				if _, ok := r.URL.Query()["location"]; ok {
					out.Header().Set("Content-Type", "application/xml")
					io.WriteString(out, `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">us-east-1</LocationConstraint>`)
					return
				}
				mu.Lock()
				gets++
				mu.Unlock()
				if r.Method != "GET" || r.URL.Query().Get("versionId") != "original-v1" {
					t.Error("non-exact source read")
					out.WriteHeader(403)
					return
				}
				data := body
				switch r.URL.Path {
				case "/skill-bucket/packages/skill.zip":
				case "/skill-bucket/packages/unreferenced.bin":
					data = orphan
				default:
					t.Error("wrong provider key")
					out.WriteHeader(403)
					return
				}
				if mode == "missing-version" {
					out.Header().Set("Content-Type", "application/xml")
					out.WriteHeader(404)
					io.WriteString(out, `<Error><Code>NoSuchVersion</Code></Error>`)
					return
				}
				out.Header().Set("Content-Length", strconv.Itoa(len(data)))
				out.Header().Set("Content-Type", "application/octet-stream")
				out.Header().Set("Last-Modified", time.Unix(1700000000, 0).UTC().Format(http.TimeFormat))
				out.Header().Set("ETag", `"original-etag"`)
				out.Header().Set("X-Amz-Version-Id", "original-v1")
				if mode == "changed-version" {
					out.Header().Set("X-Amz-Version-Id", "replacement-v2")
				}
				if mode == "source-revoked" {
					if err := os.WriteFile(grantFile, []byte("revoked source grant"), 0600); err != nil {
						t.Error(err)
					}
				}
				if mode == "truncated-eof" {
					data = data[:len(data)-1]
				}
				out.Write(data)
			}))
			defer source.Close()
			pinPub, pinKey, _ := ed25519.GenerateKey(rand.Reader)
			defer clear(pinKey)
			pin := k.PermitDeliveryPin{Version: k.PermitDeliveryVersion, Issuer: pinPub, IssuerGrantSHA256: strings.Repeat("e", 64)}
			until := time.Now().UTC().Add(40 * time.Second).Truncate(time.Microsecond)
			jwtFile := skillCLIWrite(t, dir, "job.jwt", []byte("original-projected-jwt"))
			var invocation worker.Invocation
			var identity k.JobIdentity
			unknown := false
			provider := httptest.NewTLSServer(http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				out.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/v1/auth/job/login" {
					var login struct{ Role, JWT string }
					if json.NewDecoder(r.Body).Decode(&login) != nil || login.Role != "original-job-generate" || login.JWT != "original-projected-jwt" {
						t.Error("wrong JWT login")
						out.WriteHeader(403)
						return
					}
					json.NewEncoder(out).Encode(map[string]any{"auth": map[string]any{"client_token": "local-batch-token", "token_type": "batch", "renewable": false, "lease_duration": 10, "policies": []string{"generate-only"}, "metadata": map[string]string{"role": login.Role, "namespace": identity.Namespace, "pod_uid": identity.PodUID, "service_account_uid": identity.ServiceAccountUID}}})
					return
				}
				expected, _ := k.TransitContext(invocation.ProviderKey.Request)
				var req struct {
					Context, Bits string
					KeyVersion    string `json:"key_version"`
				}
				if r.URL.Path != "/v1/transit/datakey/plaintext/backup-key" || r.Header.Get("X-Vault-Token") != "local-batch-token" || !unknown || json.NewDecoder(r.Body).Decode(&req) != nil || req.Context != expected || req.Bits != "256" || req.KeyVersion != "1" {
					t.Error("wrong Generate or before committed unknown fixture")
					out.WriteHeader(403)
					return
				}
				generates++
				json.NewEncoder(out).Encode(map[string]any{"data": map[string]any{"plaintext": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), "ciphertext": "vault:v1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 60)), "key_version": 1}})
			}))
			defer provider.Close()
			invocation = worker.Invocation{StagingPath: stage, Request: worker.Request{Version: worker.Version, Operation: "capture-skill-objects", Binding: staging.Binding{BackupID: "sbk_skill_cli", Attempt: "3", Path: "skills_objects", EnvelopeID: "original-skill-envelope", CaptureContextHash: strings.Repeat("c", 64)}, Deadline: until.Add(10 * time.Second), ArtifactName: "skills.enc", MaxArchiveBytes: 1 << 20, MaxCompressedBytes: 1 << 20, SkillObjects: &worker.SkillObjectCaptureSpec{Version: worker.SkillObjectCaptureVersion, InventorySHA256: strings.Repeat("d", 64), Bucket: "skill-bucket", Prefix: "packages", Blobs: []worker.SkillObjectBlobRef{{ID: 1, ObjectKey: "skill.zip", SizeBytes: int64(len(body))}}, Objects: []sh.FrozenObject{{Key: "unreferenced.bin", VersionID: "original-v1", Size: int64(len(orphan)), SHA256: skillCLISHA(orphan)}, {Key: "skill.zip", VersionID: "original-v1", Size: int64(len(body)), SHA256: skillCLISHA(body)}}, MaxObjects: 10, MaxObjectBytes: 1 << 16, MaxTotalBytes: 1 << 17, MaxIndexBytes: 1 << 16}}, ProviderKey: &k.Access{Operation: k.Generate, Endpoint: provider.URL, KeyName: "backup-key", Request: w.KeyRequest{Key: w.KeyBinding{Provider: "external-kms", IdentityHash: strings.Repeat("1", 64), RegistryVersion: "r1", ProviderKeyID: "backup-key", ProviderVersion: "1"}, Context: w.KeyContext{InstallationID: "installation_skill_cli", BackupPublicID: "sbk_skill_cli", AttemptNo: "3", Phase: "capture", Part: "skills_objects", PartIndex: "0", EnvelopeID: "original-skill-envelope", CaptureContextHash: strings.Repeat("c", 64)}}}, FormalCapture: &worker.FormalCaptureSpec{Version: worker.FormalCaptureVersion, ConfigSHA256: strings.Repeat("a", 64), EnvelopeName: "skills.envelope", MaxFrames: 8, PermitDelivery: &pin, SourceConfigSHA256: strings.Repeat("b", 64)}}
			sourceCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: source.Certificate().Raw})
			caFile := skillCLIWrite(t, dir, "source-ca.pem", sourceCA)
			credentialRaw, _ := json.Marshal(map[string]any{"access_key": "local-source-reader", "secret_key": []byte("local-independent-source-secret")})
			credentialFile := skillCLIWrite(t, dir, "source-credentials.json", credentialRaw)
			sourcePub, sourceKey, _ := ed25519.GenerateKey(rand.Reader)
			defer clear(sourceKey)
			mount := worker.FormalSourceMount{GrantFile: grantFile, Issuer: sourcePub, CredentialFile: credentialFile, CredentialSHA256: skillCLISHA(credentialRaw), Objects: &worker.SourceTLSMapping{Address: strings.TrimPrefix(source.URL, "https://"), ServerName: "example.com", CAFile: caFile, CASHA256: skillCLISHA(sourceCA)}, ObjectPrefixes: []worker.ObjectSourcePrefix{{Bucket: "skill-bucket", Prefix: "packages/"}}}
			scope, err := worker.FormalSourceScopeSHA256(invocation, mount)
			if err != nil {
				t.Fatal(err)
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
			case "wrong-request-version":
				invocation.Request.Version = "foreign-worker.v99"
			case "wrong-sha":
				invocation.Request.SkillObjects.Objects[1].SHA256 = strings.Repeat("0", 64)
			case "outside-prefix":
				invocation.Request.SkillObjects.Prefix = "foreign"
			}
			hash, _ := invocation.Hash()
			identity = k.JobIdentity{Namespace: "ns", PodUID: "pod", ServiceAccountUID: "sa", JobUID: "job", InvocationSHA256: hash, ExecutionGrantSHA256: strings.Repeat("a", 64)}
			state, nonce := "", ""
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
					reserves++
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
					t.Error("borrowed functional control action", r.Action)
					return worker.Lease{}, worker.ErrExecution
				}
				if r.Point != nonce {
					return worker.Lease{}, worker.ErrExecution
				}
				lease.KeyUse = &worker.KeyUseLease{Identity: identity, Access: *invocation.ProviderKey, AuthoritySHA256: strings.Repeat("b", 64), Nonce: nonce, Until: until, State: state}
				if r.Action == "key-reserve" {
					p := k.DeliveredPermitPayload{Version: k.PermitDeliveryVersion, IssuerGrantSHA256: pin.IssuerGrantSHA256, Nonce: nonce, Request: invocation.ProviderKey.Request, Permit: k.ProviderPermit{Version: "system-backup-provider-permit.v1", Identity: identity, Operation: k.Generate, Endpoint: provider.URL, KeyName: "backup-key", NotBefore: time.Now().Add(-time.Second), ExpiresAt: until, JWT: k.JWTIdentityGrant{Mount: "job", Role: "original-job-generate", Policy: "generate-only", IdentityFile: jwtFile}}}
					p.Permit.ContextBase64, _ = k.TransitContext(invocation.ProviderKey.Request)
					raw, _ := json.Marshal(p)
					lease.ProviderPermit = &k.DeliveredProviderPermit{Payload: raw, Signature: ed25519.Sign(pinKey, append([]byte(k.PermitDeliveryDomain), raw...))}
				}
				return lease, nil
			})}
			client := skillCLIMTLS(t, handler)
			raw, _ := json.Marshal(invocation)
			decoded, err := worker.ReadInvocation(bytes.NewReader(raw))
			if err != nil {
				t.Fatal("actual request decoder", err)
			}
			root, err := os.OpenRoot(stage)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			var stdout bytes.Buffer
			readyErr := client.Ready(ctx, decoded)
			if mode == "wrong-request-version" {
				if readyErr == nil {
					t.Fatal("wrong request version reached authority")
				}
			} else if readyErr != nil {
				t.Fatal("actual Ready", readyErr)
			}
			err = runFormalInvocation(ctx, decoded, client, materialFile, root, &stdout)
			mu.Lock()
			defer mu.Unlock()
			if mode != "valid" {
				if err == nil || stdout.Len() != 0 || candidates != 0 {
					t.Fatal("bad source produced candidate", mode, err, stdout.Len(), candidates)
				}
				files, _ := os.ReadDir(stage)
				if len(files) != 0 {
					t.Fatal("failed source retained partial candidate", mode, len(files))
				}
				if (mode == "wrong-request-version" || mode == "outside-prefix") && (gets != 0 || generates != 0) {
					t.Fatal("invalid request reached source or Generate", gets, generates)
				}
				if mode == "wrong-request-version" && reserves != 0 {
					t.Fatal("wrong request version reserved key use")
				}
				return
			}
			if err != nil || gets != 2 || generates != 1 || candidates != 1 || reserves != 1 {
				t.Fatal("actual shared CLI chain incomplete", err, gets, generates, candidates, reserves)
			}
			var result worker.FormalCaptureResult
			if json.Unmarshal(stdout.Bytes(), &result) != nil {
				t.Fatal("receipt not JSON")
			}
			encrypted, _ := root.ReadFile(result.Ciphertext.Name)
			envelope, _ := root.ReadFile(result.Envelope.Name)
			if !bytes.HasPrefix(encrypted, []byte("CMBKGC01")) || bytes.Contains(encrypted, body) || bytes.Contains(stdout.Bytes(), body) {
				t.Fatal("plaintext escaped encrypted staging")
			}
			skillCLIInspectArchive(t, decoded, encrypted, envelope, map[string][]byte{"skill.zip": body, "unreferenced.bin": orphan})
		})
	}
}

// Fully authenticate the candidate framing and inspect the actual encrypted
// object/index payload using the explicit local provider fixture's test DEK.
func skillCLIInspectArchive(t *testing.T, i worker.Invocation, frames, envelope []byte, expected map[string][]byte) {
	t.Helper()
	plain := skillCLIDecrypt(t, i, frames, envelope)
	z, err := gzip.NewReader(bytes.NewReader(plain))
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	tr := tar.NewReader(z)
	files := map[string][]byte{}
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil || h.Size > 1<<20 {
			t.Fatal("invalid inner tar", e)
		}
		b, e := io.ReadAll(io.LimitReader(tr, 1<<20+1))
		if e != nil || files[h.Name] != nil {
			t.Fatal("bad archive entry", e)
		}
		files[h.Name] = b
	}
	var header struct {
		Version, InvocationSHA256 string
		Spec                      worker.SkillObjectCaptureSpec
	}
	hash, _ := i.Hash()
	if json.Unmarshal(files["skill-hub/header.json"], &header) != nil || header.Version != worker.SkillObjectCaptureVersion || header.InvocationSHA256 != hash || header.Spec.InventorySHA256 != i.Request.SkillObjects.InventorySHA256 {
		t.Fatal("lost original frozen identity")
	}
	var index []struct {
		Key, Version, SHA string
		Size              int64
		VersionID         string `json:"version_id"`
		SHA256            string `json:"sha256"`
	}
	if json.Unmarshal(files["skill-hub/index.json"], &index) != nil || len(index) != len(expected) || len(files) != len(expected)+2 {
		t.Fatal("incomplete prefix index")
	}
	for n, item := range index {
		body, ok := expected[item.Key]
		if !ok || item.VersionID != "original-v1" || item.Size != int64(len(body)) || item.SHA256 != skillCLISHA(body) || !bytes.Equal(files["skill-hub/objects/"+strconv.Itoa(n)+".bin"], body) {
			t.Fatal("changed original bytes/version or omitted unreferenced object")
		}
	}
}

func skillCLIMTLS(t *testing.T, handler http.Handler) *worker.ControlClient {
	t.Helper()
	now := time.Now()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated fixture CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, e := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	issue := func(serial int64, client bool) ([]byte, []byte, tls.Certificate) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if client {
			uri, _ := url.Parse("spiffe://clawmanager/backup/fixture")
			tpl.URIs = []*url.URL{uri}
			tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		} else {
			tpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
			tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}
		der, e := x509.CreateCertificate(rand.Reader, tpl, caCert, &key.PublicKey, caKey)
		if e != nil {
			t.Fatal(e)
		}
		keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
		cp := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		kp := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		pair, e := tls.X509KeyPair(cp, kp)
		if e != nil {
			t.Fatal(e)
		}
		return cp, kp, pair
	}
	_, _, serverCert := issue(2, false)
	clientPEM, keyPEM, _ := issue(3, true)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	server.StartTLS()
	t.Cleanup(server.Close)
	dir := t.TempDir()
	for n, b := range map[string][]byte{"ca.pem": caPEM, "client.pem": clientPEM, "client.key": keyPEM} {
		if e = os.WriteFile(filepath.Join(dir, n), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	client, e := worker.NewControlClient(server.URL, filepath.Join(dir, "ca.pem"), filepath.Join(dir, "client.pem"), filepath.Join(dir, "client.key"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(client.Close)
	return client
}
func skillCLIDecrypt(t *testing.T, i worker.Invocation, frames, envelope []byte) []byte {
	t.Helper()
	var parsed struct {
		Entries []struct {
			KEK    json.RawMessage `json:"kek"`
			Chunks []w.StreamChunk `json:"chunks"`
		} `json:"entries"`
	}
	if json.Unmarshal(envelope, &parsed) != nil || len(parsed.Entries) != 1 {
		t.Fatal("invalid candidate envelope")
	}
	entry := parsed.Entries[0]
	kek := sha256.Sum256(entry.KEK)
	ctx := i.ProviderKey.Request.Context
	binding := w.ChunkBinding{SchemaVersion: w.FramingVersion, InstallationID: ctx.InstallationID, BackupPublicID: ctx.BackupPublicID, AttemptNo: ctx.AttemptNo, Phase: ctx.Phase, Part: ctx.Part, PartIndex: ctx.PartIndex, Path: i.Request.ArtifactName, EnvelopeID: ctx.EnvelopeID, CaptureContextHash: ctx.CaptureContextHash, KEKBindingSHA256: hex.EncodeToString(kek[:])}
	block, _ := aes.NewCipher(bytes.Repeat([]byte{9}, 32))
	gcm, _ := cipher.NewGCM(block)
	var compressed bytes.Buffer
	final := false
	for index, chunk := range entry.Chunks {
		length := 41 + int(chunk.CiphertextLength) + 16
		if length > len(frames) || chunk.Index != uint64(index) || final {
			t.Fatal("truncated/reordered frames")
		}
		frame := frames[:length]
		frames = frames[length:]
		sum := sha256.Sum256(frame)
		if hex.EncodeToString(sum[:]) != chunk.SHA256 {
			t.Fatal("frame digest mismatch")
		}
		aad, err := w.ChunkAAD(binding, uint64(index), chunk.PlaintextLength, chunk.Final)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := gcm.Open(nil, frame[29:41], frame[41:], aad)
		if err != nil {
			t.Fatal(err)
		}
		compressed.Write(plain)
		final = chunk.Final
	}
	if !final || len(frames) != 0 {
		t.Fatal("missing final frame or trailing bytes")
	}
	return compressed.Bytes()
}
