package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"clawreef/internal/systembackup/team"
	k "clawreef/internal/systembackupkms"
)

// Actual source-owner signature/material reread, mTLS original identity and
// pinned TLS S3 reads. KMS/frame keys are the explicit local fixture here;
// actual SQL-issued Generate and candidate handler are tested separately.
func TestOriginalSourceAuthorizationUsesFrozenInvocationAndRetainsCurrentConfig(t *testing.T) {
	ctx := context.Background()
	versions := map[string][]byte{"v1": []byte("first original version"), "v2": []byte("second original version")}
	var gets atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
		if _, ok := r.URL.Query()["location"]; ok {
			out.Header().Set("Content-Type", "application/xml")
			out.Write([]byte(`<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">us-east-1</LocationConstraint>`))
			return
		}
		body, ok := versions[r.URL.Query().Get("versionId")]
		if !ok || r.URL.Path != "/source-bucket/results/report" || (r.Method != "HEAD" && r.Method != "GET") {
			out.WriteHeader(404)
			return
		}
		out.Header().Set("Content-Length", strconv.Itoa(len(body)))
		out.Header().Set("Content-Type", "application/octet-stream")
		out.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		out.Header().Set("ETag", `"01234567890123456789012345678901"`)
		out.Header().Set("X-Amz-Version-Id", r.URL.Query().Get("versionId"))
		if r.Method == "GET" {
			gets.Add(1)
			out.Write(body)
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	caFile := filepath.Join(dir, "source-ca.pem")
	os.WriteFile(caFile, ca, 0600)
	credential := formalSourceCredential{AccessKey: "local-source-reader", SecretKey: []byte("local-source-reader-secret")}
	credentialRaw, _ := json.Marshal(credential)
	credentialFile := filepath.Join(dir, "source-credential.json")
	os.WriteFile(credentialFile, credentialRaw, 0600)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	defer clear(key)
	mapping := &SourceTLSMapping{Address: strings.TrimPrefix(server.URL, "https://"), ServerName: "example.com", CAFile: caFile, CASHA256: sourceDigest(ca)}
	mount := FormalSourceMount{GrantFile: filepath.Join(dir, "source-grant.json"), Issuer: pub, CredentialFile: credentialFile, CredentialSHA256: sourceDigest(credentialRaw), Objects: mapping, ObjectPrefixes: []ObjectSourcePrefix{{Bucket: "source-bucket", Prefix: "results/"}}}
	var originalGrant []byte
	for index, version := range []string{"v1", "v2"} {
		i, env, keyUse := formalInvocationFixture(t)
		if index == 1 {
			i.Request.Binding.BackupID = "sbk_second_fixture"
			i.ProviderKey.Request.Context.BackupPublicID = i.Request.Binding.BackupID
			keyUse.request = i.ProviderKey.Request
		}
		i.WorkspacePath = ""
		env.Workspace = nil
		i.Request.Operation = "capture-team-objects"
		i.Request.MaxFiles, i.Request.MaxFileBytes = 0, 0
		i.Request.PolicyVersion = ""
		i.Request.Files = nil
		i.Request.RuntimePolicy = nil
		i.Request.Teams = &TeamCaptureSpec{InventorySHA256: strings.Repeat("a", 64), Objects: []team.ObjectRef{{TeamID: 4242 + index, Bucket: "source-bucket", Key: "results/report", Version: version, SHA256: sourceDigest(versions[version]), Size: int64(len(versions[version]))}}, MaxItems: 10}
		i.FormalCapture.PermitDelivery = &k.PermitDeliveryPin{Version: k.PermitDeliveryVersion, Issuer: bytes.Repeat([]byte{4}, 32), IssuerGrantSHA256: strings.Repeat("d", 64)}
		i.FormalCapture.SourceConfigSHA256 = strings.Repeat("b", 64)
		i.FormalCapture.SourceAuthorizationConfigSHA256 = strings.Repeat("c", 64)
		scope, err := FormalSourceScopeSHA256(i, mount)
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			grant := FormalSourceGrant{Version: FormalSourceGrantVersion, InstallationID: i.ProviderKey.Request.Context.InstallationID, ConfigSHA256: i.FormalCapture.SourceAuthorizationConfigSHA256, WorkerNamespace: "ns", WorkerServiceAccountUID: "sa", Operation: i.Request.Operation, ScopeSHA256: scope, CredentialSHA256: mount.CredentialSHA256, NotBefore: time.Now().Add(-time.Minute), Until: time.Now().Add(time.Minute)}
			raw, _ := json.Marshal(grant)
			originalGrant, _ = json.Marshal(SignedFormalSourceGrant{Record: raw, Signature: ed25519.Sign(key, append([]byte(FormalSourceGrantDomain), raw...))})
			mount.GrantSHA256 = sourceDigest(originalGrant)
			if os.WriteFile(mount.GrantFile, originalGrant, 0600) != nil {
				t.Fatal("grant write failed")
			}
		}
		job := sourceControlJobFixture(t, i)
		originalHash, err := i.Hash()
		if err != nil {
			t.Fatal(err)
		}
		if i.FormalCapture.SourceConfigSHA256 != strings.Repeat("b", 64) {
			t.Fatal("current payload configuration changed")
		}
		if sources, err := OpenFormalCaptureSources(ctx, i, nil, &mount); err == nil || sources != nil {
			t.Fatal("unsigned caller input supplied a key job")
		}
		for _, changed := range []string{"", strings.Repeat("e", 64)} {
			bad := i
			formal := *i.FormalCapture
			bad.FormalCapture = &formal
			formal.SourceAuthorizationConfigSHA256 = changed
			badHash, err := bad.Hash()
			if err != nil || badHash == originalHash {
				t.Fatal("authorization pin was not covered by invocation hash", err)
			}
			// A real job frozen from the original invocation cannot consume
			// the changed pin, even if a caller knows both configuration hashes.
			if sources, err := OpenFormalCaptureSources(ctx, bad, job, &mount); err == nil || sources != nil {
				t.Fatal("original job accepted changed invocation")
			}
			// A separately frozen local control fixture still cannot bypass
			// the independently source-owner-signed configuration and scope.
			badJob := sourceControlJobFixture(t, bad)
			if sources, err := OpenFormalCaptureSources(ctx, bad, badJob, &mount); err == nil || sources != nil {
				t.Fatal("original signed source grant accepted foreign/missing authorization configuration")
			}
		}
		sources, err := OpenFormalCaptureSources(ctx, i, job, &mount)
		if err != nil {
			t.Fatal("same original deployed source grant rejected new actual version", version, err)
		}
		env.Teams, env.SourceAuthorize, env.SourceValidUntil = sources.Teams, sources.Authorize, sources.ValidUntil()
		result, err := runFormalCapture(ctx, i, keyUse, env)
		sources.Close()
		if err != nil || result.Ciphertext.Size == 0 {
			t.Fatal("actual pinned source capture", err)
		}
		raw, err := os.ReadFile(mount.GrantFile)
		if err != nil || !bytes.Equal(raw, originalGrant) {
			t.Fatal("task required a new source signature")
		}
		if index == 1 {
			for _, fault := range []string{"prefix", "bucket", "config", "credential", "grant"} {
				bad := i
				spec := *i.Request.Teams
				spec.Objects = append([]team.ObjectRef(nil), spec.Objects...)
				bad.Request.Teams = &spec
				restore := func() {}
				switch fault {
				case "prefix":
					spec.Objects[0].Key = "foreign/report"
				case "bucket":
					spec.Objects[0].Bucket = "foreign-bucket"
				case "config":
					formal := *i.FormalCapture
					bad.FormalCapture = &formal
					formal.SourceConfigSHA256 = strings.Repeat("f", 64)
				case "credential":
					os.WriteFile(mount.CredentialFile, []byte("changed"), 0600)
					restore = func() { os.WriteFile(mount.CredentialFile, credentialRaw, 0600) }
				case "grant":
					os.WriteFile(mount.GrantFile, append(originalGrant, ' '), 0600)
					restore = func() { os.WriteFile(mount.GrantFile, originalGrant, 0600) }
				}
				before := gets.Load()
				badJob := job
				opened, err := OpenFormalCaptureSources(ctx, bad, badJob, &mount)
				restore()
				if opened != nil {
					opened.Close()
				}
				if err == nil || gets.Load() != before {
					t.Fatal("out of original source scope reached data reads", fault, err)
				}
			}
		}
	}
	if gets.Load() != 2 {
		t.Fatal("wrong original object version read count", gets.Load())
	}
}
