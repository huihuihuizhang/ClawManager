package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	c "clawreef/internal/systembackup"
	authzv1 "k8s.io/api/authorization/v1"
)

func resourceInvocationFixture(t *testing.T, secret bool) (Invocation, FormalCaptureEnvironment, *formalKeyFixture) {
	i, env, key := formalInvocationFixture(t)
	part, op, resource, name := "deployment_resources", "capture-deployment-resources", "configmaps", "settings"
	if secret {
		part, op, resource, name = "secret_bundle", "capture-secret-bundle", "secrets", "credential"
	}
	i.WorkspacePath = ""
	i.Request.Operation = op
	i.Request.Binding.Path = part
	i.ProviderKey.Request.Context.Part = part
	i.Request.MaxFiles, i.Request.MaxFileBytes = 0, 0
	i.Request.Resources = &ResourceCaptureSpec{Part: part, Namespace: "source", NamespaceUID: "source-namespace-uid", ServiceAccountName: part, ServiceAccountUID: part + "-reader-uid", Selections: []c.KubernetesSelection{{Version: "v1", Resource: resource, Name: name, UID: name + "-original-uid"}}, MaxItems: 10, OriginalWriters: []ResourceWriterOriginal{}}
	i.Request.Resources.ServiceAccountName = strings.ReplaceAll(part, "_", "-")
	key.request = i.ProviderKey.Request
	return i, env, key
}

func sourceRules(s ResourceCaptureSpec) authzv1.SubjectRulesReviewStatus {
	r := authzv1.SubjectRulesReviewStatus{ResourceRules: []authzv1.ResourceRule{}, NonResourceRules: []authzv1.NonResourceRule{{Verbs: []string{"get"}, NonResourceURLs: []string{"/api", "/api/*", "/apis", "/apis/*", "/openapi/*", "/version", "/healthz"}}}}
	for _, ref := range s.Selections {
		r.ResourceRules = append(r.ResourceRules, authzv1.ResourceRule{Verbs: []string{"get"}, APIGroups: []string{ref.Group}, Resources: []string{ref.Resource}, ResourceNames: []string{ref.Name}})
	}
	return r
}

func TestResourceSourceRulesRejectUnknownNonResourceAndSourcePrivileges(t *testing.T) {
	i, _, _ := resourceInvocationFixture(t, false)
	for _, fault := range []string{"", "*", "/logs/*", "/debug/*", "/metrics", "/healthz/*", "mutation", "list", "resource-wildcard", "extra-name", "incomplete", "no-source-right"} {
		t.Run(fault, func(t *testing.T) {
			r := sourceRules(*i.Request.Resources)
			switch fault {
			case "mutation":
				r.ResourceRules[0].Verbs = []string{"update"}
			case "list":
				r.ResourceRules[0].Verbs = []string{"list"}
			case "resource-wildcard":
				r.ResourceRules[0].ResourceNames = nil
			case "extra-name":
				r.ResourceRules[0].ResourceNames = append(r.ResourceRules[0].ResourceNames, "not-in-original-inventory")
			case "incomplete":
				r.Incomplete = true
			case "no-source-right":
				r.ResourceRules = nil
			default:
				if fault != "" {
					r.NonResourceRules[0].NonResourceURLs = append(r.NonResourceRules[0].NonResourceURLs, fault)
				}
			}
			if ResourceSourceRules(*i.Request.Resources, r) != (fault == "") {
				t.Fatal("wrong exact source privilege decision", fault)
			}
		})
	}
}

func TestResourceFormalCaptureUsesIndependentTLSCredentialAndExactOriginalObjects(t *testing.T) {
	for _, fault := range []string{"", "secret", "identity-uid", "namespace-uid", "extra-right", "uid-drift", "revoked-after-get", "changed-scope"} {
		t.Run(fault, func(t *testing.T) {
			i, env, key := resourceInvocationFixture(t, fault == "secret")
			scope := i.Request.Resources
			reads, reviews := 0, 0
			revoked := false
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer independent-source-token" {
					w.WriteHeader(403)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				switch {
				case strings.HasSuffix(r.URL.Path, "/selfsubjectreviews"):
					reviews++
					uid := scope.ServiceAccountUID
					if fault == "identity-uid" || revoked {
						uid = "replacement-sa"
					}
					json.NewEncoder(w).Encode(map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview", "status": map[string]any{"userInfo": map[string]any{"username": "system:serviceaccount:" + scope.Namespace + ":" + scope.ServiceAccountName, "uid": uid}}})
				case strings.HasSuffix(r.URL.Path, "/selfsubjectrulesreviews"):
					rules := sourceRules(*scope)
					if fault == "extra-right" {
						rules.NonResourceRules[0].NonResourceURLs = []string{"*"}
					}
					json.NewEncoder(w).Encode(map[string]any{"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectRulesReview", "status": rules})
				case strings.HasPrefix(r.URL.Path, "/api/v1/namespaces/source/"):
					reads++
					ref := scope.Selections[0]
					uid := ref.UID
					if fault == "uid-drift" {
						uid = "replacement-object"
					}
					kind := "ConfigMap"
					if fault == "secret" {
						kind = "Secret"
					}
					if fault == "revoked-after-get" {
						revoked = true
					}
					json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": kind, "metadata": map[string]any{"namespace": "source", "name": ref.Name, "uid": uid}, "data": map[string]any{"value": "private-source-content"}})
				default:
					w.WriteHeader(403)
				}
			}))
			defer server.Close()
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			sum := sha256.Sum256(ca)
			dir := t.TempDir()
			caFile, tokenFile := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "source-token")
			if os.WriteFile(caFile, ca, 0600) != nil || os.WriteFile(tokenFile, []byte("independent-source-token"), 0600) != nil {
				t.Fatal("source mounts failed")
			}
			mount := &ResourceSourceMount{Server: server.URL, CAFile: caFile, CASHA256: hex.EncodeToString(sum[:]), TokenFile: tokenFile}
			sources, err := OpenResourceCaptureSources(context.Background(), i, mount)
			if fault == "identity-uid" || fault == "extra-right" {
				if err == nil {
					sources.Close()
					t.Fatal("untrusted source bootstrap accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer sources.Close()
			if fault == "changed-scope" {
				changed := i
				copy := *scope
				copy.NamespaceUID = "changed"
				changed.Request.Resources = &copy
				if sources.Authorize(context.Background(), changed) == nil {
					t.Fatal("source credential reused for changed original scope")
				}
				return
			}
			env.Resources = sources
			result, err := runFormalCapture(context.Background(), i, key, env)
			if fault == "uid-drift" || fault == "revoked-after-get" {
				if err == nil || result.Ciphertext.Name != "" {
					t.Fatal("changed source produced candidate", err)
				}
				return
			}
			if fault == "namespace-uid" { // exact readback never accepts a changed namespace pin
				var archive bytes.Buffer
				if captureResourceSource(context.Background(), sources, i, &archive, func() error { return nil }) != nil {
					t.Fatal("original source capture")
				}
				changed := *scope
				changed.NamespaceUID = "other-namespace-uid"
				if ReadResourceCaptureArchive(context.Background(), bytes.NewReader(archive.Bytes()), changed, i.Request.MaxArchiveBytes, nil) == nil {
					t.Fatal("changed namespace accepted")
				}
				return
			}
			if err != nil || !ValidateFormalCaptureResult(i, &result) || reads != 1 || reviews < 3 {
				t.Fatal("actual resource candidate failed", err, reads, reviews)
			}
			cipher, _ := env.Staging.ReadFile(result.Ciphertext.Name)
			if !bytes.HasPrefix(cipher, []byte("CMBKGC01")) || bytes.Contains(cipher, []byte("private-source-content")) {
				t.Fatal("resource plaintext or wrong framing")
			}
			var archive bytes.Buffer
			if captureResourceSource(context.Background(), sources, i, &archive, func() error { return nil }) != nil {
				t.Fatal("resource archive readback source")
			}
			seen := 0
			if err = ReadResourceCaptureArchive(context.Background(), bytes.NewReader(archive.Bytes()), *scope, i.Request.MaxArchiveBytes, func(ref c.KubernetesSelection, raw json.RawMessage) error {
				seen++
				if ref != scope.Selections[0] || !bytes.Contains(raw, []byte("private-source-content")) {
					t.Fatal("original source bytes lost")
				}
				return nil
			}); err != nil || seen != 1 {
				t.Fatal("independent exact resource archive readback failed", err)
			}
			if err = ReadResourceCaptureArchive(context.Background(), io.LimitReader(bytes.NewReader(archive.Bytes()), int64(archive.Len()-5)), *scope, i.Request.MaxArchiveBytes, nil); err == nil {
				t.Fatal("truncated resource archive accepted")
			}
		})
	}
}
