package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/sha256"
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
)

// These are real native upload-protocol bytes, not six-domain capture/AEAD or
// complete v12 manifest fixtures. They prove only the separate upload actor,
// exact named LOCAL object policy, candidate transport and no-repeat behavior.
// The local allowlist does not attest production provider permission materials.
func TestPublicationUploadOnlyNativeProtocol(t *testing.T) {
	for _, mode := range []string{"success", "lost-put-ack", "candidate-denied", "credential-withdrawn", "bad-input-sha", "bad-version", "final-object-in-request", "same-staging-root"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			directory := t.TempDir()
			input, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			output, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer output.Close()
			if err = input.Mkdir("parts", 0700); err != nil {
				t.Fatal(err)
			}
			cipher := []byte("opaque encrypted upload protocol DATA")
			index := []byte(`{"original":"public index transport DATA"}`)
			if input.WriteFile("parts/original.enc", cipher, 0400) != nil || input.WriteFile("index.json", index, 0400) != nil {
				t.Fatal("owned input")
			}
			credential := nativePublicationCredential{AccessKey: "upload-only-principal", SecretKey: strings.Repeat("u", 32), SessionToken: "original-upload-only-session", NotBefore: time.Now().Add(-time.Minute), Until: time.Now().Add(time.Minute)}
			private, _ := json.Marshal(credential)
			credentialFile := filepath.Join(directory, "upload.json")
			if os.WriteFile(credentialFile, private, 0600) != nil {
				t.Fatal("owned upload credential")
			}
			p := PublicationUploadRequest{Version: publicationUploadVersion, Installation: "installation_upload", Backup: "sbk_11111111-1111-4111-8111-111111111111", Attempt: 1, Region: "local-1", Bucket: "original", ArtifactRoot: "installation_upload/", RemoteStagingRoot: "remote-staging/installation_upload/", CredentialHash: hash(private), Deadline: time.Now().Add(50 * time.Second), Objects: []PublicationUploadInput{{Path: "parts/original.enc", SHA256: hash(cipher), Bytes: int64(len(cipher))}, {Path: "index.json", SHA256: hash(index), Bytes: int64(len(index))}}}
			p.ManifestInput = []byte(`{"schema_version":"system-backup.v1","origin_installation_id":"installation_upload","backup_public_id":"` + p.Backup + `","attempt_no":1}`)
			prefix := p.ArtifactRoot + p.Backup + "/1/"
			candidate := p.RemoteStagingRoot + p.Backup + "/1/manifest-candidate.json"
			allowed := map[string]bool{prefix + "parts/original.enc": true, prefix + "index.json": true, candidate: true}
			mu := sync.Mutex{}
			objects := map[string][]byte{}
			puts := 0
			forbidden := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				key := strings.TrimPrefix(r.URL.Path, "/original/")
				if r.Method != "PUT" || !allowed[key] || !aValidPublicationSignature(r, credential, credential.Until) {
					forbidden++
					out.WriteHeader(403)
					return
				}
				puts++
				for _, header := range []string{"content-length", "content-type", "if-none-match", "x-amz-content-sha256", "x-amz-checksum-sha256"} {
					found := false
					for _, signed := range strings.Split(r.URL.Query().Get("X-Amz-SignedHeaders"), ";") {
						if signed == header {
							found = true
						}
					}
					if !found {
						t.Error("actual PUT omitted signed header", header)
						out.WriteHeader(403)
						return
					}
					changed := r.Clone(r.Context())
					changed.Header = r.Header.Clone()
					if header == "content-length" {
						changed.ContentLength++
					} else {
						changed.Header.Set(header, "tampered")
					}
					if aValidPublicationSignature(changed, credential, credential.Until) {
						t.Error("actual native signature did not bind header", header)
					}
				}
				if mode == "candidate-denied" && key == candidate {
					out.WriteHeader(403)
					return
				}
				body, e := io.ReadAll(io.LimitReader(r.Body, 1<<20))
				signedBody := sha256.Sum256(body)
				if e != nil || r.Header.Get("If-None-Match") != "*" || int64(len(body)) != r.ContentLength || hash(body) != r.Header.Get("X-Amz-Content-Sha256") || r.Header.Get("X-Amz-Checksum-Sha256") != base64.StdEncoding.EncodeToString(signedBody[:]) {
					out.WriteHeader(400)
					return
				}
				if _, ok := objects[key]; ok {
					out.WriteHeader(412)
					return
				}
				objects[key] = bytes.Clone(body)
				if mode == "credential-withdrawn" && puts == 1 {
					if e = os.Remove(credentialFile); e != nil {
						t.Error(e)
					}
				}
				if mode == "lost-put-ack" && puts == 1 {
					out.WriteHeader(503)
					return
				}
				version := "upload-native-v1"
				if mode == "bad-version" {
					version = "null"
				}
				out.Header().Set("X-Amz-Version-Id", version)
				sum := sha256.Sum256(body)
				out.Header().Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(sum[:]))
				out.WriteHeader(200)
			}))
			defer server.Close()
			p.Endpoint = server.URL
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			caFile := filepath.Join(directory, "ca.pem")
			if os.WriteFile(caFile, ca, 0600) != nil {
				t.Fatal("owned target CA")
			}
			p.CAHash = hash(ca)
			switch mode {
			case "bad-input-sha":
				p.Objects[0].SHA256 = strings.Repeat("f", 64)
			case "final-object-in-request":
				p.Objects[0].Path = "manifest.json"
			case "same-staging-root":
				p.RemoteStagingRoot = p.ArtifactRoot + "remote/"
			}
			raw, _ := json.Marshal(p)
			result, err := RunPublicationUploadOnly(ctx, raw, caFile, credentialFile, input, output)
			if mode == "success" {
				if err != nil || len(result.Objects) != 2 || result.Candidate.Key != candidate || result.Candidate.Version != "upload-native-v1" || result.RequestSHA256 != hash(raw) {
					t.Fatal("actual upload protocol", result, err)
				}
				if _, e := output.Lstat("publication-result.json"); e != nil {
					t.Fatal("durable original Job result", e)
				}
				// Real provider policy denies even correctly signed final keys.
				transport, e := newPublicationS3Transport(PublicationTargetMaterials{Endpoint: p.Endpoint, Region: p.Region, Bucket: p.Bucket, CAFile: caFile, CASHA256: p.CAHash})
				if e != nil {
					t.Fatal(e)
				}
				defer transport.Close()
				for _, key := range []string{prefix + "manifest.json", prefix + "_COMMITTED", prefix + "_ACCEPTANCE", "catalog/original.json"} {
					if _, e = publicationUploadPut(ctx, transport.client, p, credential, key, hash([]byte("blocked")), 7, strings.NewReader("blocked")); e == nil {
						t.Fatal("provider admitted forbidden final key", key)
					}
				}
			} else {
				if err == nil {
					t.Fatal("fault accepted", mode)
				}
			}
			mu.Lock()
			before := puts
			count := len(objects)
			denied := forbidden
			mu.Unlock()
			if mode == "success" && (before != 3 || count != 3 || denied != 4) {
				t.Fatal("upload-only provider policy/count", before, count, denied)
			}
			if mode == "lost-put-ack" && (before != 1 || count != 1) {
				t.Fatal("lost ACK did not actually retain native object", before, count)
			}
			if mode == "credential-withdrawn" && before != 1 {
				t.Fatal("withdrawn upload credential continued", before)
			}
			if mode == "bad-input-sha" || mode == "final-object-in-request" || mode == "same-staging-root" {
				if before != 0 {
					t.Fatal("invalid input reached provider", before)
				}
			}
			if mode == "success" || mode == "lost-put-ack" || mode == "candidate-denied" || mode == "bad-version" {
				if _, e := RunPublicationUploadOnly(ctx, raw, caFile, credentialFile, input, output); e == nil {
					t.Fatal("original Job upload was repeated")
				}
				mu.Lock()
				after := puts
				mu.Unlock()
				if after != before {
					t.Fatal("rerun resent original PUT", before, after)
				}
			}
		})
	}
}
