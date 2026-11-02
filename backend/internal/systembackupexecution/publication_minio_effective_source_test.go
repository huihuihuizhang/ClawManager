package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

// Local native protocol fixtures, not live MinIO compatibility evidence.
// The runtime branch proof is pinned to official server+pkg sources, not to
// invented ConfigUpdate/disabled-engine assertions in these fixtures.
func TestMinIOEffectiveSelfPolicyActualFiveCredentialGETs(t *testing.T) {
	f := minioPermissionFixture(t)
	for _, scenario := range []string{"complete-original-five", "active-plugin-console-admin", "root-console-admin", "parent-account", "hidden-group-broader-policy", "missing-policy", "not-authenticated", "unconsumed-json", "incomplete-json", "policy-as-string", "named-policy-is-not-effective-policy", "observer-is-root", "observer-config-update"} {
		t.Run(scenario, func(t *testing.T) {
			requests := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.Method != "GET" || r.URL.Path != "/minio/admin/v3/accountinfo" || r.URL.RawQuery != "" {
					t.Error("not the exact native self accountinfo GET")
					http.Error(w, "denied", 403)
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
					t.Error("self policy was not authenticated using an original role credential")
					http.Error(w, "denied", 403)
					return
				}
				account := current.credential.AccessKey
				policy := f.responses["policy:"+current.principal.PolicyName].(map[string]any)["Policy"]
				if current.principal.Purpose == "observer" && (scenario == "observer-is-root" || scenario == "observer-config-update") {
					policy = json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["admin:*"],"Resource":["*"]}]}`)
				}
				if current.principal.Purpose == "artifact_read" {
					switch scenario {
					case "active-plugin-console-admin", "root-console-admin":
						policy = json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["admin:*"]},{"Effect":"Allow","Action":["kms:*"]},{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::*"]}]}`)
					case "parent-account":
						account = "parent-user"
					case "hidden-group-broader-policy", "named-policy-is-not-effective-policy":
						policy = json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":["arn:aws:s3:::*"]}]}`)
					case "missing-policy":
						policy = nil
					case "not-authenticated":
						http.Error(w, "denied", 403)
						return
					case "unconsumed-json":
						_, _ = w.Write([]byte(`{"AccountName":"` + account + `","Policy":{},"Server":{},"Buckets":null,"NextToken":"unconsumed"}`))
						return
					case "incomplete-json":
						_, _ = w.Write([]byte(`{"AccountName":`))
						return
					case "policy-as-string":
						policy = string(policy.(json.RawMessage))
					}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"AccountName": account, "Server": map[string]any{"Type": 3}, "Policy": policy, "Buckets": nil})
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
			stamp, err := minioEffectiveAccounts(context.Background(), p, f.uses)
			if err == nil {
				observer, openErr := newMinioPermissionHTTP(p, f.reader.credential)
				if openErr != nil {
					t.Fatal(openErr)
				}
				_, err = minioEffectiveObserver(context.Background(), observer, f.configuration, f.uses)
				observer.close()
			}
			if (err == nil) != (scenario == "complete-original-five") {
				t.Fatalf("native current effective policy: %v", err)
			}
			if err == nil && (requests != 6 || stamp == "") {
				t.Fatal("did not read every original principal's complete native policy")
			}
		})
	}
}

func TestMinIOEffectiveOwnerCurrentRevocableSourceWithoutEngineDeclaration(t *testing.T) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	cfg := minioEffectivePermissionConfiguration{Version: "minio-publication-effective-permission-source.v1", Installation: "installation", Namespace: "scope", NamespaceUID: "scope-uid", Issuer: public, MinimumEpoch: 3, Grant: minioPermissionObject{"grant", "grant-uid"}, Head: minioPermissionObject{"head", "head-uid"}, ObserverCredentialSHA256: hash([]byte("credential")), ObserverAccountSHA256: hash([]byte("observer")), ObserverPolicySHA256: hash([]byte("policy")), ObserverPolicyName: "observer"}
	grant := minioPermissionGrant{Version: "minio-permission-grant.v1", Installation: cfg.Installation, Namespace: cfg.Namespace, NamespaceUID: cfg.NamespaceUID, Profile: minioPermissionProfile, Epoch: 3, NotBefore: now.Add(-time.Second), Until: now.Add(time.Minute)}
	g, _ := ce.Canonical(grant)
	cfg.GrantSHA256 = hash(g)
	head := minioPermissionHead{Version: "minio-permission-head.v1", Installation: cfg.Installation, State: "active", GrantSHA256: cfg.GrantSHA256, Epoch: 3, NotBefore: grant.NotBefore, Until: grant.Until}
	object := func(ref minioPermissionObject, domain string, value any) *corev1.ConfigMap {
		raw, _ := ce.Canonical(value)
		return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: ref.Name, Namespace: cfg.Namespace, UID: types.UID(ref.UID), ResourceVersion: "5"}, Data: map[string]string{"record.json": string(raw)}, BinaryData: map[string][]byte{"signature": ed25519.Sign(key, append([]byte(domain), raw...))}}
	}
	raw, _ := ce.Canonical(cfg)
	path := filepath.Join(t.TempDir(), "source.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	r, err := NewMinIOEffectivePublicationPermissionReader(MinIOPublicationPermissionInput{path, hash(raw)})
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"original-active-no-engine-object", "revoked", "replayed-epoch", "wrong-namespace", "invalid-signature", "expired"} {
		t.Run(scenario, func(t *testing.T) {
			changed := head
			nsUID := cfg.NamespaceUID
			at := now
			switch scenario {
			case "revoked":
				changed.State = "revoked"
			case "replayed-epoch":
				changed.Epoch = 2
			case "wrong-namespace":
				nsUID = "substitution"
			case "expired":
				at = now.Add(2 * time.Minute)
			}
			gcm, hcm := object(cfg.Grant, minioPermissionOwnerDomain, grant), object(cfg.Head, minioPermissionHeadDomain, changed)
			if scenario == "invalid-signature" {
				hcm.BinaryData["signature"][0] ^= 1
			}
			client := fake.NewSimpleClientset(gcm, hcm, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: cfg.Namespace, UID: types.UID(nsUID)}})
			owner, err := r.effectiveOwner(context.Background(), client, at)
			if (err == nil) != (scenario == "original-active-no-engine-object") {
				t.Fatalf("original revocable authority source: %v", err)
			}
			if err == nil && owner.stamp == "" {
				t.Fatal("original authority stamp missing")
			}
		})
	}
}
