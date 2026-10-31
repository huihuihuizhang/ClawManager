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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The local native verifier deliberately has NO key allowlist. Narrowness is
// enforced by actual SigV4 method/key/header/body bindings, with no signing key
// supplied to the worker. This is protocol evidence, not online provider policy.
func TestPresignedPublicationWorkerCannotMintFinalOrReadRequests(t *testing.T) {
	for _, mode := range []string{"success", "wrong-final-key", "extra-grant", "generic-keypair", "changed-condition"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			directory := t.TempDir()
			input, e := os.OpenRoot(t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			defer input.Close()
			output, e := os.OpenRoot(t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			defer output.Close()
			cipher := []byte("presigned opaque C DATA")
			index := []byte(`{"public":"index transport DATA"}`)
			if input.Mkdir("parts", 0700) != nil || input.WriteFile("parts/c.enc", cipher, 0400) != nil {
				t.Fatal("owned upload input")
			}
			issuer := nativePublicationCredential{AccessKey: "controller-issuer", SecretKey: strings.Repeat("s", 32), SessionToken: "issuer-session", NotBefore: time.Now().Add(-time.Minute), Until: time.Now().Add(time.Minute)}
			var writes, denied atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
				if !aValidPublicationSignature(r, issuer, issuer.Until) {
					denied.Add(1)
					out.WriteHeader(403)
					return
				}
				body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
				sum := sha256.Sum256(body)
				if err != nil || r.Method != "PUT" || r.ContentLength != int64(len(body)) || r.Header.Get("If-None-Match") != "*" || r.Header.Get("X-Amz-Content-Sha256") != hash(body) || r.Header.Get("X-Amz-Checksum-Sha256") != base64.StdEncoding.EncodeToString(sum[:]) {
					out.WriteHeader(400)
					return
				}
				writes.Add(1)
				out.Header().Set("X-Amz-Version-Id", "grant-native-v1")
				out.Header().Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(sum[:]))
				out.WriteHeader(200)
			}))
			defer server.Close()
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			caFile := filepath.Join(directory, "ca.pem")
			if os.WriteFile(caFile, ca, 0600) != nil {
				t.Fatal("owned target CA")
			}
			p := PublicationUploadRequest{Version: publicationPresignedUploadVersion, Installation: "installation_grants", Backup: "sbk_11111111-1111-4111-8111-111111111111", Attempt: 1, Endpoint: server.URL, Region: "local-1", Bucket: "original", ArtifactRoot: "installation_grants/", RemoteStagingRoot: "remote/installation_grants/", CAHash: hash(ca), CandidateOwnerHMAC: strings.Repeat("a", 64), Deadline: time.Now().Add(50 * time.Second), Objects: []PublicationUploadInput{{Path: "parts/c.enc", Bytes: int64(len(cipher)), SHA256: hash(cipher)}, {Path: "artifact-index.json", Bytes: int64(len(index)), SHA256: hash(index)}}}
			p.ManifestInput = []byte(`{"schema_version":"system-backup.v1","origin_installation_id":"` + p.Installation + `","backup_public_id":"` + p.Backup + `","attempt_no":1,"artifact_index":{"path":"artifact-index.json","checksum":"` + hash(index) + `"}}`)
			p.IndexBytes = index
			raw, e := makePublicationPutGrantSet(ctx, p, issuer)
			if e != nil {
				t.Fatal("restricted native request generation", e)
			}
			if bytes.Contains(raw, []byte(issuer.SecretKey)) || bytes.Contains(raw, []byte("secret_key")) || bytes.Contains(raw, []byte("SecretKey")) {
				t.Fatal("issuer signing key entered worker grant material")
			}
			var set publicationPutGrantSet
			if json.Unmarshal(raw, &set) != nil {
				t.Fatal("grant set")
			}
			original := set.Grants[0]
			switch mode {
			case "wrong-final-key":
				u, _ := url.Parse(set.Grants[0].URL)
				u.Path = "/original/" + p.ArtifactRoot + p.Backup + "/1/manifest.json"
				set.Grants[0].URL = u.String()
				raw, _ = json.Marshal(set)
			case "extra-grant":
				set.Grants = append(set.Grants, original)
				raw, _ = json.Marshal(set)
			case "generic-keypair":
				raw, _ = json.Marshal(issuer)
			case "changed-condition":
				set.Grants[0].Headers["if-none-match"] = "different"
				raw, _ = json.Marshal(set)
			}
			p.CredentialHash = hash(raw)
			grantFile := filepath.Join(directory, "upload-grants.json")
			if os.WriteFile(grantFile, raw, 0600) != nil {
				t.Fatal("owned finite upload grants")
			}
			request, _ := json.Marshal(p)
			result, err := RunPublicationUploadOnly(ctx, request, caFile, grantFile, input, output)
			if mode != "success" {
				if err == nil || writes.Load() != 0 {
					t.Fatal("invalid delegated grants reached native provider", mode, err, writes.Load())
				}
				return
			}
			if err != nil || writes.Load() != 3 || len(result.Objects) != 2 || result.Candidate.Version != "grant-native-v1" {
				t.Fatal("actual finite-capability upload", err, writes.Load())
			}
			transport, e := newPublicationS3Transport(PublicationTargetMaterials{Endpoint: p.Endpoint, Region: p.Region, Bucket: p.Bucket, CAFile: caFile, CASHA256: p.CAHash})
			if e != nil {
				t.Fatal(e)
			}
			defer transport.Close()
			// Even without a local policy allowlist, an obtained PUT URL cannot be
			// changed into a final write or a read by a worker without SecretKey.
			for _, final := range []string{"manifest.json", "_COMMITTED", "_ACCEPTANCE", "catalog.json"} {
				changed := original
				u, _ := url.Parse(changed.URL)
				u.Path = "/original/" + p.ArtifactRoot + p.Backup + "/1/" + final
				changed.URL = u.String()
				if _, e = usePublicationPutGrant(ctx, transport.client, changed, bytes.NewReader(cipher)); e == nil {
					t.Fatal("delegated PUT changed final key", final)
				}
			}
			read, e := http.NewRequestWithContext(ctx, http.MethodGet, original.URL, bytes.NewReader(cipher))
			if e != nil {
				t.Fatal(e)
			}
			for name, value := range original.Headers {
				read.Header.Set(name, value)
			}
			read.ContentLength = original.Bytes
			response, e := transport.client.Do(read)
			if e != nil {
				t.Fatal(e)
			}
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode != 403 {
				t.Fatal("PUT capability became read authority", response.StatusCode)
			}
			if writes.Load() != 3 || denied.Load() != 5 {
				t.Fatal("native signature counterexample did not reach provider", writes.Load(), denied.Load())
			}
		})
	}
}
