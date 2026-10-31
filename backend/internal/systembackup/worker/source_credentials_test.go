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
func TestFormalSourceGrantAllowsSuccessiveVersionsWithinFixedPrefix(t *testing.T) {
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
		i.FormalCapture.SourceConfigSHA256 = strings.Repeat("c", 64)
		scope, err := FormalSourceScopeSHA256(i, mount)
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			grant := FormalSourceGrant{Version: FormalSourceGrantVersion, InstallationID: i.ProviderKey.Request.Context.InstallationID, ConfigSHA256: i.FormalCapture.SourceConfigSHA256, WorkerNamespace: "ns", WorkerServiceAccountUID: "sa", Operation: i.Request.Operation, ScopeSHA256: scope, CredentialSHA256: mount.CredentialSHA256, NotBefore: time.Now().Add(-time.Minute), Until: time.Now().Add(time.Minute)}
			raw, _ := json.Marshal(grant)
			originalGrant, _ = json.Marshal(SignedFormalSourceGrant{Record: raw, Signature: ed25519.Sign(key, append([]byte(FormalSourceGrantDomain), raw...))})
			mount.GrantSHA256 = sourceDigest(originalGrant)
			if os.WriteFile(mount.GrantFile, originalGrant, 0600) != nil {
				t.Fatal("grant write failed")
			}
		}
		job := sourceControlJobFixture(t, i)
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
					formal.SourceConfigSHA256 = strings.Repeat("b", 64)
				case "credential":
					os.WriteFile(mount.CredentialFile, []byte("changed"), 0600)
					restore = func() { os.WriteFile(mount.CredentialFile, credentialRaw, 0600) }
				case "grant":
					os.WriteFile(mount.GrantFile, append(originalGrant, ' '), 0600)
					restore = func() { os.WriteFile(mount.GrantFile, originalGrant, 0600) }
				}
				before := gets.Load()
				badJob := sourceControlJobFixture(t, bad)
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

func sourceControlJobFixture(t *testing.T, i Invocation) *CaptureKeyJob {
	t.Helper()
	expected, _ := i.Hash()
	until := time.Now().UTC().Add(45 * time.Second)
	handler := ControlHandler{Authorizer: authorizeFunc(func(_ context.Context, peer string, r ControlRequest) (Lease, error) {
		if peer != "spiffe://clawmanager/backup/fixture" || r.InvocationSHA256 != expected {
			return Lease{}, ErrExecution
		}
		if r.Action != "key-reserve" && r.Action != "key-check" {
			return Lease{}, ErrExecution
		}
		lease := Lease{InvocationSHA256: expected, ExpiresAt: until, KeyUse: &KeyUseLease{Identity: k.JobIdentity{Namespace: "ns", PodUID: "pod", ServiceAccountUID: "sa", JobUID: "job", InvocationSHA256: expected, ExecutionGrantSHA256: strings.Repeat("a", 64)}, Access: *i.ProviderKey, AuthoritySHA256: strings.Repeat("b", 64), Nonce: r.Point, Until: until, State: "reserved"}}
		if r.Action == "key-reserve" {
			lease.ProviderPermit = &k.DeliveredProviderPermit{Payload: []byte("public permit fixture; no KMS use in source test"), Signature: make([]byte, ed25519.SignatureSize)}
		}
		return lease, nil
	})}
	client, _ := mutualTLSFixture(t, handler)
	original, err := NewOriginalKeyAuthority(context.Background(), client, i)
	if err != nil {
		t.Fatal(err)
	}
	return &CaptureKeyJob{original: original, access: *i.ProviderKey, until: original.ValidUntil()}
}

func TestFormalRedisSourceScopeKeepsDeploymentBoundaryAcrossTeamChanges(t *testing.T) {
	i, _, _ := formalInvocationFixture(t)
	i.WorkspacePath = ""
	i.Request.Operation = "capture-team-redis"
	i.Request.Teams = &TeamCaptureSpec{InventorySHA256: strings.Repeat("a", 64), Redis: &team.RedisScope{ID: "original_redis", ServerID: strings.Repeat("b", 40), Database: 2, TeamIDs: []int{20}}, MaxItems: 10}
	m := FormalSourceMount{Redis: &SourceTLSMapping{Address: "redis.original:6380", ServerName: "redis.original", CAFile: "/mounted/ca.pem", CASHA256: strings.Repeat("c", 64)}, RedisScope: &RedisSourceBoundary{ID: "original_redis", ServerID: strings.Repeat("b", 40), Database: 2, KeyPrefix: "claw:team:"}}
	first, err := FormalSourceScopeSHA256(i, m)
	if err != nil {
		t.Fatal(err)
	}
	i.Request.Teams.InventorySHA256 = strings.Repeat("d", 64)
	i.Request.Teams.Redis.TeamIDs = []int{20, 21, 22}
	second, err := FormalSourceScopeSHA256(i, m)
	if err != nil || first != second {
		t.Fatal("dynamic Team inventory required new deployment grant", err)
	}
	for _, fault := range []string{"server", "database", "scope", "prefix"} {
		bad := m
		boundary := *m.RedisScope
		bad.RedisScope = &boundary
		switch fault {
		case "server":
			boundary.ServerID = strings.Repeat("e", 40)
		case "database":
			boundary.Database = 3
		case "scope":
			boundary.ID = "other_redis"
		case "prefix":
			boundary.KeyPrefix = "*"
		}
		if _, err := FormalSourceScopeSHA256(i, bad); err == nil {
			t.Fatal("Redis source boundary widened", fault)
		}
	}
}
