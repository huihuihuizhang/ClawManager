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

// Real local TLS and Ed25519, protocol model for Vault/Kubernetes only. These
// tests do NOT claim a native provider, original SQL admission or deployment.
func signingResourceObserverFixture(t *testing.T, purpose, mode string) (*SigningResourceObserver, *signingResourceFixture, *int) {
	t.Helper()
	f := originalSigningResourceFixture(t, purpose)
	trust := a.VaultJWTTrust{Issuer: "https://kubernetes.default.svc.cluster.local", ValidationPublicKeys: []string{"protocol model public pin"}, Algorithms: []string{"RS256"}}
	trustRaw, e := a.VaultJWTAuthConfig(trust)
	if e != nil {
		t.Fatal(e)
	}
	roles, policies := map[string][]byte{}, map[string]string{}
	for n, b := range f.grant.Bindings {
		role, e := a.VaultJWTAuthRole(a.VaultPermissionRole{AuthMount: b.AuthMount, Role: b.Role, Policy: b.Policy, Audience: b.Audience, Namespace: b.Namespace, ServiceAccountName: b.ServiceAccountName, ServiceAccountUID: b.ServiceAccountUID, PodUID: b.PodUID})
		if e != nil {
			t.Fatal(e)
		}
		acl, e := CaptureSigningACL(b)
		if e != nil {
			t.Fatal(e)
		}
		b.RoleSHA256, b.PolicySHA256, b.JWTConfigSHA256 = digest(role), digest([]byte(acl)), digest(trustRaw)
		f.grant.Bindings[n] = b
		roles[b.Role], policies[b.Policy] = role, acl
		if b.Purpose == purpose {
			f.grant.Binding = b
		}
	}
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private directory")
	}
	metadataToken, jwt := []byte("private-resource-metadata-reader-token"), []byte("private-original-resource-runtime-jwt")
	tokenFile, jwtFile := filepath.Join(dir, "observer.token"), filepath.Join(dir, "runtime.jwt")
	if os.WriteFile(tokenFile, metadataToken, 0600) != nil || os.WriteFile(jwtFile, jwt, 0600) != nil {
		t.Fatal("tokens")
	}
	observerPolicy := "all-signing-public-metadata"
	signs := new(int)
	lookup := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		send := func(v any) { _ = json.NewEncoder(w).Encode(v) }
		data := func(v any) { send(map[string]any{"data": v}) }
		b := f.grant.Binding
		if r.URL.Path == "/v1/sys/health" {
			cluster := b.ProviderClusterID
			if mode == "wrong_cluster" {
				cluster = "other"
			}
			send(map[string]any{"cluster_id": cluster, "initialized": true, "sealed": false})
			return
		}
		if r.Method == "GET" && r.Header.Get("X-Vault-Token") != string(metadataToken) {
			w.WriteHeader(403)
			return
		}
		switch r.URL.Path {
		case "/v1/auth/token/lookup-self":
			lookup++
			ttl := 120 - lookup
			data(map[string]any{"policies": []string{observerPolicy}, "identity_policies": []string{}, "ttl": ttl})
			return
		case "/v1/sys/policies/acl/" + observerPolicy:
			p, _ := SigningResourceObserverACL(f.grant, observerPolicy)
			if mode == "broad_observer" {
				p += "path \"*\" { capabilities = [\"update\"] }\n"
			}
			data(map[string]any{"name": observerPolicy, "policy": p})
			return
		case "/v1/auth/" + b.AuthMount + "/login":
			var input map[string]string
			if r.Method != "POST" || json.NewDecoder(r.Body).Decode(&input) != nil || input["role"] != b.Role || input["jwt"] != string(jwt) {
				w.WriteHeader(403)
				return
			}
			pod := b.PodUID
			if mode == "wrong_login_identity" {
				pod = "other"
			}
			send(map[string]any{"auth": map[string]any{"client_token": "private-short-purpose-runtime-token", "token_type": "batch", "renewable": false, "lease_duration": 10, "policies": []string{b.Policy}, "token_policies": []string{b.Policy}, "identity_policies": []string{}, "metadata": map[string]string{"role": b.Role, "namespace": b.Namespace, "pod_uid": pod, "service_account_uid": b.ServiceAccountUID}}})
			return
		case "/v1/" + b.TransitMount + "/sign/" + b.KeyName:
			if r.Method != "POST" || r.Header.Get("X-Vault-Token") != "private-short-purpose-runtime-token" {
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
			if e != nil || !bytes.HasPrefix(message, []byte(SigningResourceProbeDomain)) || bytes.HasPrefix(message, []byte(ProbeDomain)) {
				w.WriteHeader(400)
				return
			}
			var probe map[string]json.RawMessage
			if json.Unmarshal(message[len(SigningResourceProbeDomain):], &probe) != nil || !bytes.Equal(probe["Purpose"], []byte(`"`+purpose+`"`)) || !bytes.Equal(probe["GrantSHA256"], []byte(`"`+f.pin.GrantSHA256+`"`)) || len(probe["BackupID"]) > 0 || len(probe["Task"]) > 0 {
				w.WriteHeader(400)
				return
			}
			*signs++
			sig := ed25519.Sign(f.capture.signing[b.KeyName], message)
			if mode == "wrong_signature" {
				sig[0] ^= 1
			}
			if mode == "jwt_replaced" {
				_ = os.WriteFile(jwtFile, []byte("changed-original-runtime-jwt-file"), 0600)
			}
			data(map[string]any{"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(sig)})
			return
		}
		for n, other := range f.grant.Bindings {
			if r.URL.Path == "/v1/sys/policies/acl/"+other.Policy {
				p := policies[other.Policy]
				if mode == "other_policy" && other.Purpose != purpose {
					p += "path \"*\" { capabilities = [\"read\"] }\n"
				}
				data(map[string]any{"name": other.Policy, "policy": p})
				return
			}
			if r.URL.Path == "/v1/auth/"+other.AuthMount+"/role/"+other.Role {
				var role map[string]any
				_ = json.Unmarshal(roles[other.Role], &role)
				if mode == "other_role" && other.Purpose != purpose {
					role["token_no_default_policy"] = false
				}
				data(role)
				return
			}
			if r.URL.Path == "/v1/auth/"+other.AuthMount+"/config" {
				var v any
				_ = json.Unmarshal(trustRaw, &v)
				data(v)
				return
			}
			if r.URL.Path == "/v1/"+other.TransitMount+"/keys/"+other.KeyName {
				keys := map[string]any{}
				for _, key := range f.grant.Histories[n].Keys {
					pub := key.PublicKey
					if mode == "tail_public_drift" && *signs > 0 {
						pub = base64.StdEncoding.EncodeToString(make([]byte, 32))
					}
					keys[key.Version] = map[string]any{"public_key": pub}
				}
				data(map[string]any{"type": "ed25519", "supports_signing": true, "derived": false, "exportable": false, "allow_plaintext_backup": false, "deletion_allowed": false, "keys": keys})
				return
			}
		}
		// Any attempted capture or other-purpose signing is refused.
		w.WriteHeader(404)
	}))
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	for n, b := range f.grant.Bindings {
		b.Endpoint, b.CASHA256 = server.URL, digest(ca)
		f.grant.Bindings[n] = b
		if b.Purpose == purpose {
			f.grant.Binding = b
		}
	}
	id, e := SigningResourceReferenceIdentity(f.grant.Binding)
	if e != nil {
		t.Fatal(e)
	}
	f.grant.Reference.IdentityHash = id
	f.resign(t)
	b := f.grant.Binding
	kube := kubefake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID(f.grant.Target.ClusterID)}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: b.Namespace, UID: types.UID(b.NamespaceUID)}}, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: b.ServiceAccountName, Namespace: b.Namespace, UID: types.UID(b.ServiceAccountUID)}}, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: b.PodName, Namespace: b.Namespace, UID: types.UID(b.PodUID)}, Spec: corev1.PodSpec{ServiceAccountName: b.ServiceAccountName}, Status: corev1.PodStatus{Phase: corev1.PodRunning}})
	kube.PrependReactor("create", "tokenreviews", func(action ktesting.Action) (bool, runtime.Object, error) {
		request := action.(ktesting.CreateAction).GetObject().(*authenticationv1.TokenReview)
		ok := request.Spec.Token == string(jwt) && len(request.Spec.Audiences) == 1 && request.Spec.Audiences[0] == b.Audience && mode != "tokenreview_denied"
		return true, &authenticationv1.TokenReview{Status: authenticationv1.TokenReviewStatus{Authenticated: ok, Audiences: []string{b.Audience}, User: authenticationv1.UserInfo{Username: "system:serviceaccount:" + b.Namespace + ":" + b.ServiceAccountName, UID: b.ServiceAccountUID, Extra: map[string]authenticationv1.ExtraValue{"authentication.kubernetes.io/pod-uid": {b.PodUID}}}}}, nil
	})
	o, e := NewSigningResourceObserver(SigningObserverConfig{Endpoint: server.URL, CASHA256: digest(ca), CAPEM: ca, ObserverPolicy: observerPolicy, ObserverTokenFile: tokenFile, ObserverTokenSHA256: digest(metadataToken), RuntimeJWTFile: jwtFile, Trust: trust, Kubernetes: kube})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(o.Close)
	return o, f, signs
}

func TestSigningResourceObserverActualPurposeJWTAndNonBusinessProbe(t *testing.T) {
	for _, purpose := range SigningResourcePurposes() {
		t.Run(purpose, func(t *testing.T) {
			o, f, signs := signingResourceObserverFixture(t, purpose, "")
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			started := time.Now().UTC()
			observation, e := o.ObserveSigningResource(ctx, f.raw, f.sig, f.pin)
			if e != nil || observation == nil || *signs != 1 {
				t.Fatal("actual purpose probe", e)
			}
			a, b, e := observation.Window()
			if e != nil || a.Before(started.Truncate(time.Microsecond)) || b.Sub(a) > 30*time.Second || b.After(f.grant.Until) || !sameContext(observation.ctx, ctx) {
				t.Fatal("original bounded window", e)
			}
			if _, e := json.Marshal(observation); e == nil {
				t.Fatal("observation serialized as approval")
			}
			if !observation.pinsCurrent() {
				t.Fatal("original runtime file pins")
			}
			if os.WriteFile(o.transport.cfg.RuntimeJWTFile, []byte("changed-runtime-projected-jwt-data"), 0600) != nil {
				t.Fatal("jwt replacement")
			}
			if observation.pinsCurrent() {
				t.Fatal("replaced runtime source retained physical permission")
			}
		})
	}
}

func TestSigningResourceObserverRejectsOtherPurposeMetadataAndTailDrift(t *testing.T) {
	for _, mode := range []string{"wrong_cluster", "broad_observer", "other_role", "other_policy", "wrong_login_identity", "wrong_signature", "jwt_replaced", "tail_public_drift", "tokenreview_denied"} {
		t.Run(mode, func(t *testing.T) {
			o, f, _ := signingResourceObserverFixture(t, "acceptance_record", mode)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if _, e := o.ObserveSigningResource(ctx, f.raw, f.sig, f.pin); e == nil {
				t.Fatal("drift accepted", mode)
			}
		})
	}
}
