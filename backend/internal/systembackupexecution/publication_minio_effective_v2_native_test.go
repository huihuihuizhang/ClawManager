package systembackupexecution

import (
	"bytes"
	ce "clawreef/internal/systembackupcontrolevidence"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// Local protocol fixture, not actual MinIO compatibility. The counterexample
// models opaque stored credentials whose ParentUser makes the native owner
// flag true while AccountInfo still emits a narrow regular-account policy.
func TestMinIOEffectiveV2NativeSixAccountsAndS3OwnerPredicate(t *testing.T) {
	f := minioPermissionV2Fixture(t)
	for _, scenario := range []string{"six-original-narrow-accounts", "parent-owner-bypass", "observer-owner-bypass", "signature-error-is-not-denial", "disabled-key-is-not-denial", "missing-api-is-not-denial", "wrong-resource", "duplicate-code", "trailing-json", "redirect"} {
		t.Run(scenario, func(t *testing.T) {
			helpReads := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					t.Error("owner discriminator attempted mutation")
					http.Error(w, "method", 405)
					return
				}
				var current *minioPermissionUse
				for i := range f.uses {
					if minioPermissionFixtureSignature(r, f.uses[i].credential.AccessKey, f.uses[i].credential.SecretKey) {
						current = &f.uses[i]
						break
					}
				}
				if minioPermissionFixtureSignature(r, f.reader.credential.AccessKey, f.reader.credential.SecretKey) {
					current = &minioPermissionUse{principal: minioPermissionPrincipal{Purpose: "observer", PolicyName: f.configuration.ObserverPolicyName}, credential: f.reader.credential}
				}
				if current == nil {
					t.Error("original credential signature missing")
					http.Error(w, "auth", 403)
					return
				}
				if r.URL.Path == "/minio/admin/v3/accountinfo" && r.URL.RawQuery == "" {
					policy := f.responses["policy:"+current.principal.PolicyName].(map[string]any)["Policy"]
					_ = json.NewEncoder(w).Encode(map[string]any{"AccountName": current.credential.AccessKey, "Server": map[string]any{"Type": 3}, "Policy": policy, "Buckets": nil})
					return
				}
				if r.URL.Path != minioEffectiveOwnerGuardPath || r.URL.RawQuery != "key=&subSys=policy_plugin" {
					t.Error("unexpected discriminator API")
					http.Error(w, "path", 404)
					return
				}
				helpReads++
				if scenario == "parent-owner-bypass" && current.principal.Purpose == "artifact_read" || scenario == "observer-owner-bypass" && current.principal.Purpose == "observer" {
					_, _ = w.Write([]byte(`{"subSys":"policy_plugin","keysHelp":[]}`))
					return
				}
				status := 403
				reply := minioEffectiveGuardFixtureError()
				switch scenario {
				case "signature-error-is-not-denial":
					reply["Code"] = "SignatureDoesNotMatch"
				case "disabled-key-is-not-denial":
					reply["Code"] = "AccessKeyDisabled"
				case "missing-api-is-not-denial":
					status = 404
					reply["Code"] = "NotImplemented"
				case "wrong-resource":
					reply["Resource"] = "/unrelated"
				case "redirect":
					status = 302
				}
				body, _ := json.Marshal(reply)
				if scenario == "duplicate-code" {
					body = []byte(`{"Code":"SignatureDoesNotMatch","Code":"AccessDenied","Message":"Access Denied.","Resource":"/minio/admin/v3/help-config-kv","RequestId":"request","HostId":"server"}`)
				}
				if scenario == "trailing-json" {
					body = append(body, []byte(`{}`)...)
				}
				w.WriteHeader(status)
				_, _ = w.Write(body)
			}))
			defer server.Close()
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			path := filepath.Join(t.TempDir(), "ca.pem")
			if err := os.WriteFile(path, ca, 0600); err != nil {
				t.Fatal(err)
			}
			p := f.reader.provider
			p.Endpoint = server.URL
			p.CAFile = path
			p.CASHA256 = hash(ca)
			p.SPKISHA256 = hash(server.Certificate().RawSubjectPublicKeyInfo)
			// Check the actual v2 narrow policies before testing the owner
			// discriminator. The v1 helper correctly rejects v2's additional
			// staging DeleteObject action and cannot establish this premise.
			for _, use := range f.uses {
				rules, err := minioPermissionObjectRulesV2(use.principal.Purpose, use.bucket, use.root, use.staging)
				if err != nil {
					t.Fatal(err)
				}
				native, err := newMinioPermissionHTTP(p, use.credential)
				if err != nil {
					t.Fatal(err)
				}
				_, err = native.effectiveSelfPolicyV2(context.Background(), use.credential.AccessKey, use.principal.PolicySHA256, rules)
				native.close()
				if err != nil {
					t.Fatalf("counterexample's original v2 narrow self policy changed: %v", err)
				}
			}
			observer, err := newMinioPermissionHTTP(p, f.reader.credential)
			if err != nil {
				t.Fatal(err)
			}
			_, err = observer.effectiveSelfPolicyV2(context.Background(), f.reader.credential.AccessKey, f.configuration.ObserverPolicySHA256, minioPermissionObserverRulesV2(f.uses))
			observer.close()
			if err != nil {
				t.Fatal(err)
			}
			stamp, err := minioEffectiveGuardAllV2(context.Background(), p, f.configuration, f.uses, f.reader.credential)
			if (err == nil) != (scenario == "six-original-narrow-accounts") {
				t.Fatalf("effective source plus actual owner discriminator: %v", err)
			}
			if err == nil && (helpReads != 6 || stamp == "") {
				t.Fatal("did not observe every actual account's owner discriminator")
			}
		})
	}
}

func minioPermissionV2Fixture(t *testing.T) *minioPermissionNativeFixture {
	t.Helper()
	f := minioPermissionFixture(t)
	policy := func(name string, rules []minioPermissionRule) string {
		statements := []json.RawMessage{}
		for _, rule := range rules {
			actions, resources := append([]string(nil), rule.Actions...), append([]string(nil), rule.Resources...)
			sort.Strings(actions)
			sort.Strings(resources)
			raw, _ := ce.Canonical(map[string]any{"Effect": "Allow", "Action": actions, "Resource": resources})
			statements = append(statements, raw)
		}
		sort.Slice(statements, func(i, j int) bool { return bytes.Compare(statements[i], statements[j]) < 0 })
		raw, _ := ce.Canonical(map[string]any{"Version": "2012-10-17", "Statement": statements})
		f.responses["policy:"+name].(map[string]any)["Policy"] = json.RawMessage(raw)
		return hash(raw)
	}
	for i := range f.uses {
		u := &f.uses[i]
		rules, err := minioPermissionObjectRulesV2(u.principal.Purpose, u.bucket, u.root, u.staging)
		if err != nil {
			t.Fatal(err)
		}
		u.principal.PolicySHA256 = policy(u.principal.PolicyName, rules)
	}
	f.configuration.ObserverPolicySHA256 = policy(f.configuration.ObserverPolicyName, minioPermissionObserverRulesV2(f.uses))
	if _, err := f.reader.collectV2(context.Background(), f.configuration, f.uses); err != nil {
		t.Fatal("v2 actual named native sources", err)
	}
	return f
}
