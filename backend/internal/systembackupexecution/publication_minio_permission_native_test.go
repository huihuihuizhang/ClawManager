package systembackupexecution

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
)

// These are local protocol fixtures for the pinned official API shapes. They
// do NOT establish compatibility with a live MinIO release, SQL success or a
// complete effective-policy/runtime observation.
type minioPermissionNativeFixture struct {
	reader        *minioPermissionHTTP
	configuration minioPermissionConfiguration
	uses          []minioPermissionUse
	responses     map[string]any
	status        map[string]int
	headers       map[string]string
}

func minioPermissionFixture(t *testing.T) *minioPermissionNativeFixture {
	t.Helper()
	f := &minioPermissionNativeFixture{responses: map[string]any{}, status: map[string]int{}, headers: map[string]string{}}
	now := time.Now().UTC().Truncate(time.Second)
	policy := func(rules []minioPermissionRule) (json.RawMessage, string) {
		statements := []any{}
		for _, rule := range rules {
			statements = append(statements, map[string]any{"Effect": "Allow", "Action": rule.Actions, "Resource": rule.Resources})
		}
		raw, err := ce.Canonical(map[string]any{"Version": "2012-10-17", "Statement": statements})
		if err != nil {
			t.Fatal(err)
		}
		return raw, hash(raw)
	}
	add := func(account, name string, rules []minioPermissionRule) string {
		raw, digest := policy(rules)
		f.responses["user:"+account] = map[string]any{"userAuthInfo": map[string]any{"type": "builtin", "authServerUserID": account}, "policyName": name, "status": "enabled", "updatedAt": now}
		f.responses["policy:"+name] = map[string]any{"PolicyName": name, "Policy": raw, "CreateDate": now, "UpdateDate": now}
		return digest
	}
	observerRules := []minioPermissionRule{{[]string{"admin:GetUser", "admin:GetPolicy", "admin:ServerInfo"}, []string{"*"}}, {[]string{"s3:GetBucketPolicy", "s3:GetBucketVersioning"}, []string{"arn:aws:s3:::artifacts", "arn:aws:s3:::catalog"}}}
	f.configuration.ObserverPolicyName = "observer"
	f.configuration.ObserverAccountSHA256 = hash([]byte("observer-account"))
	f.configuration.ObserverPolicySHA256 = add("observer-account", "observer", observerRules)
	for _, purpose := range []string{"artifact_read", "artifact_write", "artifact_delete", "catalog_read", "catalog_append"} {
		bucket, root, staging := "artifacts", "formal/", "staging/"
		if strings.HasPrefix(purpose, "catalog_") {
			bucket, root, staging = "catalog", "catalog/", ""
		}
		rules, err := minioPermissionObjectRules(purpose, bucket, root, staging)
		if err != nil {
			t.Fatal(err)
		}
		account := purpose + "-account"
		digest := add(account, purpose, rules)
		f.uses = append(f.uses, minioPermissionUse{principal: minioPermissionPrincipal{Purpose: purpose, AccountSHA256: hash([]byte(account)), PolicyName: purpose, PolicySHA256: digest}, credential: nativePublicationCredential{AccessKey: account, SecretKey: "separate-test-secret", NotBefore: now.Add(-time.Minute), Until: now.Add(time.Minute)}, bucket: bucket, root: root, staging: staging})
	}
	f.responses["server"] = map[string]any{"deploymentID": "deployment", "region": "us-east-1", "servers": []any{map[string]any{"state": "ok", "version": minioPermissionVersion, "commitID": minioPermissionCommit}}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for key, value := range f.headers {
			w.Header().Set(key, value)
		}
		if !minioPermissionFixtureSignature(r, "observer-account", "observer-secret") {
			t.Error("native GET did not carry a valid SigV4 signature")
			http.Error(w, "denied", 403)
			return
		}
		key := ""
		switch r.URL.Path {
		case "/minio/admin/v3/info":
			if r.URL.RawQuery != "metrics=false" {
				t.Error("unexpected server query")
			}
			key = "server"
		case "/minio/admin/v3/user-info":
			if len(r.URL.Query()) != 1 {
				t.Error("unexpected user query")
			}
			key = "user:" + r.URL.Query().Get("accessKey")
		case "/minio/admin/v3/info-canned-policy":
			if len(r.URL.Query()) != 2 || r.URL.Query().Get("v") != "2" {
				t.Error("unexpected policy query")
			}
			key = "policy:" + r.URL.Query().Get("name")
		case "/artifacts", "/catalog":
			if r.URL.RawQuery == "policy=" {
				w.WriteHeader(404)
				_, _ = w.Write([]byte(`<Error><Code>NoSuchBucketPolicy</Code></Error>`))
				return
			}
			if r.URL.RawQuery == "versioning=" {
				_, _ = w.Write([]byte(`<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`))
				return
			}
		}
		if key == "" || f.responses[key] == nil {
			t.Error("unexpected native request")
			http.Error(w, "missing", 404)
			return
		}
		if status := f.status[key]; status != 0 {
			w.WriteHeader(status)
		}
		_ = json.NewEncoder(w).Encode(f.responses[key])
	}))
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, ca, 0600); err != nil {
		t.Fatal(err)
	}
	p := minioPermissionProvider{Endpoint: server.URL, Region: "us-east-1", DeploymentID: "deployment", CAFile: path, CASHA256: hash(ca), SPKISHA256: hash(server.Certificate().RawSubjectPublicKeyInfo)}
	var err error
	f.reader, err = newMinioPermissionHTTP(p, nativePublicationCredential{AccessKey: "observer-account", SecretKey: "observer-secret", NotBefore: now.Add(-time.Minute), Until: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.reader.close)
	return f
}

// Independently verify the actual transmitted timestamp, canonical request,
// credential scope and HMAC. Merely having an Authorization header is not a
// positive signing test. Fixture paths/queries are ASCII and bounded.
func minioPermissionFixtureSignature(r *http.Request, account, secret string) bool {
	if r.Method != "GET" || r.Header.Get("X-Amz-Security-Token") != "" || r.Header.Get("X-Amz-Content-Sha256") != hash(nil) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 "), ", ")
	if len(parts) != 3 {
		return false
	}
	credential := strings.Split(strings.TrimPrefix(parts[0], "Credential="), "/")
	if len(credential) != 5 || credential[0] != account || credential[2] != "us-east-1" || credential[3] != "s3" || credential[4] != "aws4_request" {
		return false
	}
	signed := strings.TrimPrefix(parts[1], "SignedHeaders=")
	names := strings.Split(signed, ";")
	if !sort.StringsAreSorted(names) || signed != "host;x-amz-content-sha256;x-amz-date" {
		return false
	}
	date := r.Header.Get("X-Amz-Date")
	if len(date) != 16 || date[:8] != credential[1] {
		return false
	}
	headers := "host:" + r.Host + "\nx-amz-content-sha256:" + hash(nil) + "\nx-amz-date:" + date + "\n"
	canonical := "GET\n" + r.URL.EscapedPath() + "\n" + strings.ReplaceAll(r.URL.Query().Encode(), "+", "%20") + "\n" + headers + "\n" + signed + "\n" + hash(nil)
	scope := strings.Join(credential[1:], "/")
	stringToSign := "AWS4-HMAC-SHA256\n" + date + "\n" + scope + "\n" + hash([]byte(canonical))
	hmacBytes := func(key []byte, value string) []byte {
		h := hmac.New(sha256.New, key)
		_, _ = h.Write([]byte(value))
		return h.Sum(nil)
	}
	key := hmacBytes([]byte("AWS4"+secret), credential[1])
	for _, value := range credential[2:] {
		key = hmacBytes(key, value)
	}
	want := hex.EncodeToString(hmacBytes(key, stringToSign))
	got := strings.TrimPrefix(parts[2], "Signature=")
	return hmac.Equal([]byte(want), []byte(got))
}

func TestMinIOPermissionNativeTLSProtocol(t *testing.T) {
	f := minioPermissionFixture(t)
	first, err := f.reader.collect(context.Background(), f.configuration, f.uses)
	if err != nil || first == "" {
		t.Fatalf("first native collection: %v", err)
	}
	last, err := f.reader.collect(context.Background(), f.configuration, f.uses)
	if err != nil || last != first {
		t.Fatalf("stable complete collection: %v", err)
	}
}

func TestMinIOPermissionNativeRefusesUnknownOrIncompleteSources(t *testing.T) {
	for _, name := range []string{"unknown-version", "group", "external-user", "disabled", "extra-policy", "missing-policy", "wrong-account", "expired-credential", "wrong-spki", "incomplete-json", "oversized-response", "unexpected-pagination", "redirect"} {
		t.Run(name, func(t *testing.T) {
			f := minioPermissionFixture(t)
			user := f.responses["user:artifact_read-account"].(map[string]any)
			switch name {
			case "unknown-version":
				f.responses["server"].(map[string]any)["servers"] = []any{map[string]any{"state": "ok", "version": "unknown", "commitID": minioPermissionCommit}}
			case "group":
				user["memberOf"] = []string{"inherited"}
			case "external-user":
				user["userAuthInfo"] = map[string]any{"type": "ldap", "authServerUserID": "external"}
			case "disabled":
				user["status"] = "disabled"
			case "extra-policy":
				user["policyName"] = "artifact_read,admin"
			case "missing-policy":
				f.status["policy:artifact_read"] = 403
			case "wrong-account":
				f.uses[0].credential.AccessKey = "substitution"
			case "expired-credential":
				f.reader.credential.Until = time.Now().Add(-time.Second)
			case "wrong-spki":
				f.reader.provider.SPKISHA256 = hash([]byte("wrong"))
				reader, err := newMinioPermissionHTTP(f.reader.provider, f.reader.credential)
				if err != nil {
					t.Fatal(err)
				}
				defer reader.close()
				f.reader = reader
			case "incomplete-json":
				f.responses["server"] = json.RawMessage(`{"deploymentID":`)
			case "oversized-response":
				f.responses["server"].(map[string]any)["unexpected"] = strings.Repeat("x", 1<<20)
			case "unexpected-pagination":
				f.headers["X-Next-Token"] = "unconsumed"
			case "redirect":
				f.status["server"] = 302
			}
			if _, err := f.reader.collect(context.Background(), f.configuration, f.uses); err == nil {
				t.Fatal("incomplete native source accepted")
			}
		})
	}
}

func TestMinIOPermissionPolicyClosedSubset(t *testing.T) {
	rules := []minioPermissionRule{{[]string{"s3:GetObject"}, []string{"arn:aws:s3:::bucket/formal/*"}}}
	valid := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/formal/*"}]}`
	for _, name := range []string{"valid", "deny", "condition", "wildcard-action", "broader-resource", "duplicate-json", "trailing-json"} {
		t.Run(name, func(t *testing.T) {
			raw := valid
			switch name {
			case "deny":
				raw = strings.ReplaceAll(raw, `"Allow"`, `"Deny"`)
			case "condition":
				raw = strings.Replace(raw, `"Effect":`, `"Condition":{},"Effect":`, 1)
			case "wildcard-action":
				raw = strings.ReplaceAll(raw, `s3:GetObject`, `s3:*`)
			case "broader-resource":
				raw = strings.ReplaceAll(raw, `bucket/formal/*`, `bucket/*`)
			case "duplicate-json":
				raw = strings.Replace(raw, `"Version":`, `"Version":"2012-10-17","Version":`, 1)
			case "trailing-json":
				raw += "{}"
			}
			var document any
			_ = json.Unmarshal([]byte(raw), &document)
			canonical, _ := ce.Canonical(document)
			err := minioPermissionPolicy([]byte(raw), hash(canonical), rules)
			if (err == nil) != (name == "valid") {
				t.Fatalf("closed policy result: %v", err)
			}
		})
	}
}

func TestMinIOOwnerConfigurationIsNotRuntimeProof(t *testing.T) {
	raw := []byte(`{"status":"success","config":[{"subSystem":"policy_plugin","kv":[{"key":"url","value":"","envOverride":{"name":"MINIO_POLICY_PLUGIN_URL","value":"https://active.example"}}]}]}`)
	if digest, err := minioOwnerConfigResponse(raw, "policy_plugin"); err != nil || digest == "" {
		t.Fatalf("complete configuration parse: %v", err)
	}
	if _, err := (MinIOOriginalOwnerConfigurationObservation{}).MarshalJSON(); err == nil {
		t.Fatal("partial configuration observation serialized as proof")
	}
	for _, bad := range []string{`{"status":"success","config":[]}`, `{"status":"success","config":[{"subSystem":"other","kv":[{"key":"url","value":""}]}]}`, `{"status":"success","config":[{"subSystem":"policy_plugin","kv":[{"key":"url","value":""},{"key":"url","value":"other"}]}]}`} {
		if _, err := minioOwnerConfigResponse([]byte(bad), "policy_plugin"); err == nil {
			t.Fatal("incomplete configuration response accepted")
		}
	}
}
