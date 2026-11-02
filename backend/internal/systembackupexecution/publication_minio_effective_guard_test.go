package systembackupexecution

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func minioEffectiveGuardFixtureError() map[string]string {
	return map[string]string{"Code": "AccessDenied", "Message": "Access Denied.", "Resource": minioEffectiveOwnerGuardPath, "RequestId": "request", "HostId": "server"}
}

// Local protocol fixture, not actual MinIO compatibility. The counterexample
// models opaque stored credentials whose ParentUser makes the native owner
// flag true while AccountInfo still emits a narrow regular-account policy.
func TestMinIOEffectiveGuardDistinguishesS3OwnerPredicate(t *testing.T) {
	f := minioPermissionFixture(t)
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
			if _, err := minioEffectiveAccounts(context.Background(), p, f.uses); err != nil {
				t.Fatalf("counterexample's original narrow self policies changed: %v", err)
			}
			observer, err := newMinioPermissionHTTP(p, f.reader.credential)
			if err != nil {
				t.Fatal(err)
			}
			_, err = minioEffectiveObserver(context.Background(), observer, f.configuration, f.uses)
			observer.close()
			if err != nil {
				t.Fatal(err)
			}
			stamp, err := minioEffectiveGuardAll(context.Background(), p, f.configuration, f.uses, f.reader.credential)
			if (err == nil) != (scenario == "six-original-narrow-accounts") {
				t.Fatalf("effective source plus actual owner discriminator: %v", err)
			}
			if err == nil && (helpReads != 6 || stamp == "") {
				t.Fatal("did not observe every actual account's owner discriminator")
			}
		})
	}
}

func TestMinIOEffectiveGuardRequiresCompleteUnambiguousNativeError(t *testing.T) {
	valid, _ := json.Marshal(minioEffectiveGuardFixtureError())
	if err := minioEffectiveAdminAccessDenied(valid); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"missing-code", "missing-request-id", "bucket-context", "wrong-case", "unknown-field", "wrong-code"} {
		reply := minioEffectiveGuardFixtureError()
		switch scenario {
		case "missing-code":
			delete(reply, "Code")
		case "missing-request-id":
			delete(reply, "RequestId")
		case "bucket-context":
			reply["BucketName"] = "bucket"
		case "wrong-case":
			delete(reply, "Code")
			reply["code"] = "AccessDenied"
		case "unknown-field":
			reply["Passed"] = "true"
		case "wrong-code":
			reply["Code"] = "InvalidToken"
		}
		raw, _ := json.Marshal(reply)
		if err := minioEffectiveAdminAccessDenied(raw); err == nil {
			t.Fatalf("unrelated or incomplete error accepted: %s", scenario)
		}
	}
	for _, raw := range []string{"", `{"Code":"AccessDenied"`, string(valid) + `{}`, `{"Code":"AccessDenied","Code":"AccessDenied"}`, `<Error><Code>AccessDenied</Code></Error>`} {
		if err := minioEffectiveAdminAccessDenied([]byte(raw)); err == nil {
			t.Fatal("ambiguous native denial accepted")
		}
	}
}
