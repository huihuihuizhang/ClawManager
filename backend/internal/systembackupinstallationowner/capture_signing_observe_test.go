package systembackupinstallationowner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	a "clawreef/internal/systembackupkekadapter"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// Real local TLS + signing crypto and API protocol mocks, NOT actual Vault,
// Kubernetes identity verification, SQL admission or installation enrollment.
func signingObserverFixture(t *testing.T, mode string) (*CaptureSigningObserver, *AuthenticatedRecord, *int) {
	t.Helper()
	f := ownerRecordFixture(t)
	b := f.record.Binding
	signs := new(int)
	role, _ := a.VaultJWTAuthRole(a.VaultPermissionRole{AuthMount: b.AuthMount, Role: b.Role, Policy: b.Policy, Audience: b.Audience, Namespace: b.Namespace, ServiceAccountName: b.ServiceAccountName, ServiceAccountUID: b.ServiceAccountUID, PodUID: b.PodUID})
	trust := a.VaultJWTTrust{Issuer: "https://kubernetes.default.svc.cluster.local", ValidationPublicKeys: []string{"test protocol pin, not a live issuer"}, Algorithms: []string{"RS256"}}
	trustJSON, _ := a.VaultJWTAuthConfig(trust)
	policy, _ := CaptureSigningACL(b)
	f.record.Binding.RoleSHA256 = digest(role)
	f.record.Binding.JWTConfigSHA256 = digest(trustJSON)
	f.record.Binding.PolicySHA256 = digest([]byte(policy))
	observerPolicy := "capture-metadata-reader"
	metadataToken := []byte("metadata-token-original-private")
	runtimeJWT := []byte("runtime-jwt-original-projected")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		send := func(v any) { _ = json.NewEncoder(w).Encode(v) }
		data := func(v any) { send(map[string]any{"data": v}) }
		if r.URL.Path == "/v1/sys/health" {
			cluster := b.ProviderClusterID
			if mode == "wrong_cluster" {
				cluster = "other"
			}
			send(map[string]any{"initialized": true, "sealed": false, "cluster_id": cluster})
			return
		}
		if r.Method == "GET" && r.Header.Get("X-Vault-Token") != string(metadataToken) {
			w.WriteHeader(403)
			return
		}
		switch r.URL.Path {
		case "/v1/auth/token/lookup-self":
			policies := []string{observerPolicy}
			if mode == "root_observer" {
				policies = []string{"root"}
			}
			data(map[string]any{"policies": policies, "identity_policies": []string{}, "ttl": 120})
		case "/v1/sys/policies/acl/" + observerPolicy:
			p, _ := CaptureSigningObserverACL(f.record, observerPolicy)
			data(map[string]any{"name": observerPolicy, "policy": p})
		case "/v1/sys/policies/acl/" + b.Policy:
			p := policy
			if mode == "broad_policy" {
				p += "path \"*\" { capabilities = [\"sudo\"] }"
			}
			data(map[string]any{"name": b.Policy, "policy": p})
		case "/v1/auth/" + b.AuthMount + "/role/" + b.Role:
			var v map[string]any
			_ = json.Unmarshal(role, &v)
			if mode == "wrong_role" {
				v["token_no_default_policy"] = false
			}
			data(v)
		case "/v1/auth/" + b.AuthMount + "/config":
			var v any
			_ = json.Unmarshal(trustJSON, &v)
			data(v)
		case "/v1/auth/" + b.AuthMount + "/login":
			if r.Method != "POST" {
				w.WriteHeader(405)
				return
			}
			var input map[string]string
			if json.NewDecoder(r.Body).Decode(&input) != nil || input["role"] != b.Role || input["jwt"] != string(runtimeJWT) {
				w.WriteHeader(403)
				return
			}
			pod := b.PodUID
			if mode == "wrong_login_identity" {
				pod = "other"
			}
			send(map[string]any{"auth": map[string]any{"client_token": "short-private-runtime-token", "token_type": "batch", "renewable": false, "lease_duration": 10, "policies": []string{b.Policy}, "token_policies": []string{b.Policy}, "identity_policies": []string{}, "metadata": map[string]string{"role": b.Role, "namespace": b.Namespace, "pod_uid": pod, "service_account_uid": b.ServiceAccountUID}}})
		case "/v1/transit/sign/" + b.KeyName:
			if r.Method != "POST" || r.Header.Get("X-Vault-Token") != "short-private-runtime-token" {
				w.WriteHeader(403)
				return
			}
			var input struct {
				Input      string `json:"input"`
				KeyVersion int    `json:"key_version"`
			}
			if json.NewDecoder(r.Body).Decode(&input) != nil || input.KeyVersion != 1 {
				w.WriteHeader(400)
				return
			}
			message, e := base64.StdEncoding.Strict().DecodeString(input.Input)
			if e != nil || !bytes.HasPrefix(message, []byte(ProbeDomain)) {
				w.WriteHeader(400)
				return
			}
			*signs++
			sig := ed25519.Sign(f.signing[b.KeyName], message)
			if mode == "wrong_signature" {
				sig[0] ^= 1
			}
			data(map[string]any{"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(sig)})
		default:
			for _, history := range f.record.Histories {
				if r.URL.Path == "/v1/transit/keys/"+history.KeyName {
					keys := map[string]any{}
					for _, k := range history.Keys {
						public := k.PublicKey
						if mode == "wrong_public" && history.Purpose == b.Purpose {
							public = base64.StdEncoding.EncodeToString(make([]byte, 32))
						}
						keys[k.Version] = map[string]any{"public_key": public}
					}
					data(map[string]any{"type": "ed25519", "supports_signing": true, "derived": false, "exportable": false, "allow_plaintext_backup": false, "deletion_allowed": false, "keys": keys})
					return
				}
			}
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	f.record.Binding.Endpoint = server.URL
	f.record.Binding.CASHA256 = digest(ca)
	identity, _ := ReferenceIdentity(f.record.Binding)
	f.record.Reference.IdentityHash = identity
	bindFixtureConfig(t, &f)
	f.resign(t)
	auth, e := VerifyRecord(f.raw, f.sig, f.pin)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	tokenFile, jwtFile := filepath.Join(dir, "observer.token"), filepath.Join(dir, "runtime.jwt")
	if os.WriteFile(tokenFile, metadataToken, 0600) != nil || os.WriteFile(jwtFile, runtimeJWT, 0600) != nil {
		t.Fatal("private files")
	}
	kube := kubefake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID(f.record.Target.ClusterID)}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: b.Namespace, UID: types.UID(b.NamespaceUID)}}, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: b.ServiceAccountName, Namespace: b.Namespace, UID: types.UID(b.ServiceAccountUID)}}, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: b.PodName, Namespace: b.Namespace, UID: types.UID(b.PodUID)}, Spec: corev1.PodSpec{ServiceAccountName: b.ServiceAccountName}, Status: corev1.PodStatus{Phase: corev1.PodRunning}})
	kube.PrependReactor("create", "tokenreviews", func(action ktesting.Action) (bool, runtime.Object, error) {
		request := action.(ktesting.CreateAction).GetObject().(*authenticationv1.TokenReview)
		ok := request.Spec.Token == string(runtimeJWT) && len(request.Spec.Audiences) == 1 && request.Spec.Audiences[0] == b.Audience && mode != "tokenreview_denied"
		return true, &authenticationv1.TokenReview{Status: authenticationv1.TokenReviewStatus{Authenticated: ok, Audiences: []string{b.Audience}, User: authenticationv1.UserInfo{Username: "system:serviceaccount:" + b.Namespace + ":" + b.ServiceAccountName, UID: b.ServiceAccountUID, Extra: map[string]authenticationv1.ExtraValue{"authentication.kubernetes.io/pod-uid": {b.PodUID}}}}}, nil
	})
	observer, e := NewCaptureSigningObserver(SigningObserverConfig{Endpoint: server.URL, CASHA256: digest(ca), CAPEM: ca, ObserverPolicy: observerPolicy, ObserverTokenFile: tokenFile, ObserverTokenSHA256: digest(metadataToken), RuntimeJWTFile: jwtFile, Trust: trust, Kubernetes: kube})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(observer.Close)
	return observer, auth, signs
}
func TestCaptureSigningObserverTLSActualProtocolAndProbeDomain(t *testing.T) {
	o, a, signs := signingObserverFixture(t, "")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	observation, e := o.observe(ctx, a)
	if e != nil || observation == nil || *signs != 1 || observation.recordHash != a.pin.RecordSHA256 || observation.until.After(a.record.Probe.Until) || len(observation.probeSignature) != 64 {
		t.Fatal("actual TLS protocol observation", e)
	}
	if _, e := json.Marshal(observation); e == nil {
		t.Fatal("observation can be supplied as DTO")
	}
}
func TestCaptureSigningJSONSubsetCanonicalValues(t *testing.T) {
	for _, tc := range []struct {
		name, actual, expected string
		want                   bool
	}{
		{"scalar_fields", `{"role_type":"jwt","token_no_default_policy":true,"token_ttl":10}`, `{"token_ttl":10,"token_no_default_policy":true,"role_type":"jwt"}`, true},
		{"nested_values", `{"claims":{"uid":"pod-1"},"audiences":["capture"]}`, `{"audiences":["capture"],"claims":{"uid":"pod-1"}}`, true},
		{"changed_bool", `{"required":false}`, `{"required":true}`, false},
		{"changed_number", `{"ttl":11}`, `{"ttl":10}`, false},
		{"wrong_type", `{"ttl":"10"}`, `{"ttl":10}`, false},
		{"missing_field", `{}`, `{"required":true}`, false},
		{"case_alias", `{"required":true,"Required":true}`, `{"required":true}`, false},
		{"nested_duplicate", `{"claims":{"uid":"pod-1","uid":"pod-1"}}`, `{"claims":{"uid":"pod-1"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := jsonSubset([]byte(tc.actual), []byte(tc.expected)); got != tc.want {
				t.Fatal("metadata subset comparison", got, "want", tc.want)
			}
		})
	}
	if equalJSON([]byte(`true,false`), []byte(`true,false`)) || equalJSON(nil, nil) {
		t.Fatal("missing or multiple scalar values accepted")
	}
}
func TestCaptureSigningObserverRejectsProviderAndWorkloadDrift(t *testing.T) {
	for _, mode := range []string{"wrong_cluster", "root_observer", "broad_policy", "wrong_role", "wrong_login_identity", "wrong_signature", "wrong_public", "tokenreview_denied"} {
		t.Run(mode, func(t *testing.T) {
			o, a, _ := signingObserverFixture(t, mode)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if _, e := o.observe(ctx, a); e == nil {
				t.Fatal("provider/workload drift accepted")
			}
		})
	}
	o, a, signs := signingObserverFixture(t, "")
	p := a.record
	p.Probe.Until = time.Now().UTC().Add(-time.Second).Truncate(time.Microsecond)
	a.record = p
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, e := o.observe(ctx, a); e == nil || *signs != 0 {
		t.Fatal("expired probe reached signer")
	}
	if !strings.Contains(ProbeDomain, "bootstrap-signing-probe") || strings.Contains(RecordDomain, "capture-certificate") {
		t.Fatal("domains")
	}
}
