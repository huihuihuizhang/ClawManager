package install

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	a "clawreef/internal/systembackupkekadapter"
	sec "clawreef/internal/systembackupsecurity"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

type authorityFixture struct {
	i                               *Installer
	s                               *authoritySQLState
	password, key, draft            []byte
	files                           RequestFiles
	enrollment                      EnrollmentPin
	record                          owner.Record
	config                          sec.BootstrapConfig
	grant                           sec.OfflineBootstrapGrant
	signs                           atomic.Int32
	permissionDenied, resourceDrift atomic.Bool
}

// This tests one real capture owner only: real Ed25519, local TLS Vault
// protocol, fake Kubernetes API responses and a database/sql transaction model.
// Closed synthetic config refs supply no other resource validator or admission.
func newAuthorityFixture(t *testing.T) *authorityFixture {
	t.Helper()
	base, auth, _, password := enrollmentFixture(t, "")
	public, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	f := &authorityFixture{password: password, key: key}
	t.Cleanup(func() { clear(password); clear(key) })
	p := base.plan
	p.IssuerPublicKeySHA256 = hash(public)
	auth.plan = p
	s := &authoritySQLState{auth: auth, data: authoritySQLData{grants: map[string][]driver.Value{}}}
	f.s = s
	now := time.Now().UTC().Truncate(time.Microsecond)
	digest := strings.Repeat("a", 64)
	b := owner.Binding{InstallationID: p.Target.InstallationID, Purpose: "capture_certificate", KeyID: "capture-key", KeyVersion: "registry-1", Endpoint: "https://pending.invalid", ProviderClusterID: "vault-original", TransitMount: "transit", KeyName: "capture-key", ProviderVersion: "1", AuthMount: "backup-jwt", Role: "capture-role", Policy: "capture-policy", Audience: "capture-audience", Namespace: p.Target.Namespace, NamespaceUID: p.Target.NamespaceUID, PodName: "controller", PodUID: "controller-uid", ServiceAccountName: "controller", ServiceAccountUID: "controller-sa-uid", CASHA256: digest, RoleSHA256: digest, PolicySHA256: digest, JWTConfigSHA256: digest}
	r := owner.Record{SchemaVersion: owner.RecordVersion, EnrollmentID: p.EnrollmentID, IssuerID: p.IssuerID, GrantID: "grant-1", EnrollmentRevision: p.EnrollmentRevision, Revision: 1, NotBefore: now.Add(-10 * time.Second), Until: now.Add(10 * time.Minute), Target: p.Target, Actor: owner.Actor{UserID: 7, Username: p.LocalAdminUsername, OwnerSubject: p.OwnerUsername}, Endpoint: sec.BootstrapConfigEndpoint, IdempotencyKey: "original-bootstrap-key-1", MatrixKey: "k8s-cluster", SelectionSHA256: digest, CanonicalProfile: "system-backup-config-values.v1", Binding: b, Probe: owner.Probe{Challenge: digest, Until: now.Add(5 * time.Minute)}}
	keys := map[string]ed25519.PrivateKey{}
	for _, v := range []struct{ purpose, name string }{{"acceptance_record", "acceptance-key"}, {"capture_certificate", "capture-key"}, {"catalog_record", "catalog-key"}} {
		pub, private, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		keys[v.name] = private
		t.Cleanup(func() { clear(private) })
		r.Histories = append(r.Histories, owner.PurposeKeys{Purpose: v.purpose, KeyName: v.name, Keys: []owner.PublicKey{{Version: "1", PublicKey: base64.StdEncoding.EncodeToString(pub), ProtectedUntil: r.Until.Add(time.Hour)}}})
	}
	roleRaw, e := a.VaultJWTAuthRole(a.VaultPermissionRole{AuthMount: b.AuthMount, Role: b.Role, Policy: b.Policy, Audience: b.Audience, Namespace: b.Namespace, ServiceAccountName: b.ServiceAccountName, ServiceAccountUID: b.ServiceAccountUID, PodUID: b.PodUID})
	if e != nil {
		t.Fatal(e)
	}
	trust := a.VaultJWTTrust{Issuer: "https://kubernetes.default.svc.cluster.local", ValidationPublicKeys: []string{"local protocol key only"}, Algorithms: []string{"RS256"}}
	trustRaw, e := a.VaultJWTAuthConfig(trust)
	if e != nil {
		t.Fatal(e)
	}
	policy, e := owner.CaptureSigningACL(b)
	if e != nil {
		t.Fatal(e)
	}
	r.Binding.RoleSHA256 = hash(roleRaw)
	r.Binding.JWTConfigSHA256 = hash(trustRaw)
	r.Binding.PolicySHA256 = hash([]byte(policy))
	observerPolicy := "capture-metadata-reader"
	metadataToken := []byte("original-metadata-private-token")
	jwt := []byte("original-runtime-projected-jwt")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requireNoOpenAuthorityTx(t, s)
		w.Header().Set("Content-Type", "application/json")
		send := func(v any) { _ = json.NewEncoder(w).Encode(v) }
		data := func(v any) { send(map[string]any{"data": v}) }
		if req.URL.Path == "/v1/sys/health" {
			send(map[string]any{"initialized": true, "sealed": false, "cluster_id": b.ProviderClusterID})
			return
		}
		if req.Method == "GET" && req.Header.Get("X-Vault-Token") != string(metadataToken) {
			w.WriteHeader(403)
			return
		}
		switch req.URL.Path {
		case "/v1/auth/token/lookup-self":
			data(map[string]any{"policies": []string{observerPolicy}, "identity_policies": []string{}, "ttl": 120})
		case "/v1/sys/policies/acl/" + observerPolicy:
			acl, _ := owner.CaptureSigningObserverACL(r, observerPolicy)
			data(map[string]any{"name": observerPolicy, "policy": acl})
		case "/v1/sys/policies/acl/" + b.Policy:
			data(map[string]any{"name": b.Policy, "policy": policy})
		case "/v1/auth/" + b.AuthMount + "/role/" + b.Role:
			var v any
			_ = json.Unmarshal(roleRaw, &v)
			data(v)
		case "/v1/auth/" + b.AuthMount + "/config":
			var v any
			_ = json.Unmarshal(trustRaw, &v)
			data(v)
		case "/v1/auth/" + b.AuthMount + "/login":
			var in map[string]string
			if json.NewDecoder(req.Body).Decode(&in) != nil || in["role"] != b.Role || in["jwt"] != string(jwt) {
				w.WriteHeader(403)
				return
			}
			send(map[string]any{"auth": map[string]any{"client_token": "original-short-runtime-token", "token_type": "batch", "renewable": false, "lease_duration": 10, "policies": []string{b.Policy}, "token_policies": []string{b.Policy}, "identity_policies": []string{}, "metadata": map[string]string{"role": b.Role, "namespace": b.Namespace, "pod_uid": b.PodUID, "service_account_uid": b.ServiceAccountUID}}})
		case "/v1/transit/sign/" + b.KeyName:
			var in struct {
				Input   string `json:"input"`
				Version string `json:"key_version"`
			}
			if req.Method != "POST" || req.Header.Get("X-Vault-Token") != "original-short-runtime-token" || json.NewDecoder(req.Body).Decode(&in) != nil || in.Version != "1" {
				w.WriteHeader(403)
				return
			}
			message, e := base64.StdEncoding.Strict().DecodeString(in.Input)
			if e != nil || !strings.HasPrefix(string(message), owner.ProbeDomain) {
				w.WriteHeader(400)
				return
			}
			f.signs.Add(1)
			signature := ed25519.Sign(keys[b.KeyName], message)
			data(map[string]string{"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(signature)})
		default:
			for _, h := range r.Histories {
				if req.URL.Path == "/v1/transit/keys/"+h.KeyName {
					pub := h.Keys[0].PublicKey
					if f.resourceDrift.Load() && h.KeyName == b.KeyName {
						pub = base64.StdEncoding.EncodeToString(make([]byte, 32))
					}
					data(map[string]any{"type": "ed25519", "supports_signing": true, "derived": false, "exportable": false, "allow_plaintext_backup": false, "deletion_allowed": false, "keys": map[string]any{"1": map[string]string{"public_key": pub}}})
					return
				}
			}
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	r.Binding.Endpoint = server.URL
	r.Binding.CASHA256 = hash(ca)
	identity, e := owner.ReferenceIdentity(r.Binding)
	if e != nil {
		t.Fatal(e)
	}
	r.Reference = sec.BootstrapSecretRef{Purpose: "capture_signing", IdentityHash: identity, Version: b.KeyVersion}
	config := authorityConfig(t, r.Reference)
	g := sec.OfflineBootstrapGrant{InstallationID: p.Target.InstallationID, ServerUUID: p.Target.ServerUUID, Database: p.Target.Database, Username: p.LocalAdminUsername, UserID: 7, MatrixKey: r.MatrixKey, ConfigSHA256: config.SHA256(), IdempotencyKey: r.IdempotencyKey, ChangeReason: "explicit original owner request"}
	grantJSON, _ := json.Marshal(g)
	r.GrantSHA256 = hash(grantJSON)
	r.ConfigSHA256 = config.SHA256()
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(config.CanonicalJSON(), &fields)
	r.RegistrySetSHA256 = hash(fields["registries"])
	r.ReferenceSetSHA256 = hash(fields["references"])
	f.record = r
	f.config = config
	f.grant = g
	f.draft, e = owner.EncodeRecord(r)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	write := func(name string, raw []byte) string {
		path := filepath.Join(dir, name)
		if e := os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
		return path
	}
	configPath := write("config.json", config.CanonicalJSON())
	grantDoc, e := canonical(sec.BootstrapGrantFile{SchemaVersion: "system-backup-offline-bootstrap-grant.v1", NotBefore: r.NotBefore.Add(-time.Minute), ExpiresAt: r.Until.Add(time.Minute), Grant: g})
	if e != nil {
		t.Fatal(e)
	}
	grantPath := write("grant.json", grantDoc)
	caPath := write("provider.ca", ca)
	tokenPath := write("observer.token", metadataToken)
	jwtPath := write("runtime.jwt", jwt)
	observerRaw, e := canonical(observerDocument{Endpoint: server.URL, CASHA256: hash(ca), CAFile: caPath, ObserverPolicy: observerPolicy, ObserverTokenFile: tokenPath, ObserverTokenSHA256: hash(metadataToken), RuntimeJWTFile: jwtPath, Trust: trust})
	if e != nil {
		t.Fatal(e)
	}
	f.files = RequestFiles{ConfigFile: configPath, ConfigFileSHA256: hash(config.CanonicalJSON()), GrantFile: grantPath, GrantFileSHA256: hash(grantDoc), ObserverFile: write("observer.json", observerRaw), ObserverFileSHA256: hash(observerRaw)}
	kube := kubefake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID(p.Target.ClusterID)}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: p.Target.Namespace, UID: types.UID(p.Target.NamespaceUID)}}, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: b.PodName, Namespace: b.Namespace, UID: types.UID(b.PodUID)}, Spec: corev1.PodSpec{ServiceAccountName: b.ServiceAccountName}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: b.ServiceAccountName, Namespace: b.Namespace, UID: types.UID(b.ServiceAccountUID)}})
	kube.PrependReactor("create", "selfsubjectreviews", func(ktesting.Action) (bool, runtime.Object, error) {
		requireNoOpenAuthorityTx(t, s)
		return true, &authenticationv1.SelfSubjectReview{Status: authenticationv1.SelfSubjectReviewStatus{UserInfo: authenticationv1.UserInfo{Username: p.OwnerUsername, UID: p.OwnerUID, Groups: p.OwnerGroups}}}, nil
	})
	kube.PrependReactor("create", "selfsubjectaccessreviews", func(action ktesting.Action) (bool, runtime.Object, error) {
		requireNoOpenAuthorityTx(t, s)
		a := action.(ktesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview).Spec.ResourceAttributes
		allowed := a != nil && a.Namespace == p.Target.Namespace && a.Name == p.EnrollmentName && a.Resource == "configmaps" && a.Group == "" && (a.Verb == "get" || a.Verb == "create" || a.Verb == "update") && !f.permissionDenied.Load()
		return true, &authorizationv1.SelfSubjectAccessReview{Status: authorizationv1.SubjectAccessReviewStatus{Allowed: allowed, Denied: !allowed}}, nil
	})
	kube.PrependReactor("create", "tokenreviews", func(action ktesting.Action) (bool, runtime.Object, error) {
		requireNoOpenAuthorityTx(t, s)
		v := action.(ktesting.CreateAction).GetObject().(*authenticationv1.TokenReview)
		return true, &authenticationv1.TokenReview{Status: authenticationv1.TokenReviewStatus{Authenticated: v.Spec.Token == string(jwt) && len(v.Spec.Audiences) == 1 && v.Spec.Audiences[0] == b.Audience, Audiences: []string{b.Audience}, User: authenticationv1.UserInfo{Username: "system:serviceaccount:" + b.Namespace + ":" + b.ServiceAccountName, UID: b.ServiceAccountUID, Extra: map[string]authenticationv1.ExtraValue{"authentication.kubernetes.io/pod-uid": {b.PodUID}}}}}, nil
	})
	kube.PrependReactor("create", "configmaps", func(action ktesting.Action) (bool, runtime.Object, error) {
		v := action.(ktesting.CreateAction).GetObject().(*corev1.ConfigMap).DeepCopy()
		v.UID = "original-authority-enrollment"
		v.ResourceVersion = "1"
		e := kube.Tracker().Create(corev1.SchemeGroupVersion.WithResource("configmaps"), v, p.Target.Namespace)
		return true, v, e
	})
	db := sql.OpenDB(authorityConnector{s})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	plan, e := canonical(p)
	if e != nil {
		t.Fatal(e)
	}
	f.i, e = New(db, kube, plan, hash(plan), public, hash(public))
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	receipt, e := f.i.Enroll(ctx, password)
	if e != nil {
		t.Fatal("authenticated fixture enrollment", e)
	}
	f.enrollment = receipt.Pin
	return f
}

func authorityConfig(t *testing.T, capture sec.BootstrapSecretRef) sec.BootstrapConfig {
	t.Helper()
	raw, e := os.ReadFile("../../../../contracts/system-backup/v12/admin-control-resources.schema.json")
	if e != nil {
		t.Fatal(e)
	}
	var schema struct {
		Defs map[string]struct {
			Properties map[string]struct {
				Default json.RawMessage `json:"default"`
			} `json:"properties"`
		} `json:"$defs"`
	}
	if json.Unmarshal(raw, &schema) != nil {
		t.Fatal("contract")
	}
	doc := map[string]any{"enabled": false, "alert_profile": "development", "minimum_recovery_points": 1}
	for group, def := range map[string]string{"durations": "DurationConfig", "capacity": "CapacityConfig", "concurrency": "ConcurrencyConfig", "preflight_limits": "PreflightLimits"} {
		v := map[string]json.RawMessage{}
		for name, p := range schema.Defs[def].Properties {
			if len(p.Default) == 0 {
				t.Fatal("contract default", name)
			}
			v[name] = p.Default
		}
		doc[group] = v
	}
	var registries []sec.BootstrapRegistryRef
	for _, kind := range []string{"parts", "redis_sources", "failure_domains", "disaster_identity_mapping", "source_writers", "rbac_bindings", "secret_allowlist", "strong_auth_issuers", "provider_proof_issuers"} {
		registries = append(registries, sec.BootstrapRegistryRef{Kind: kind, Version: "registry-1", SHA256: hash([]byte(kind))})
	}
	doc["registries"] = registries
	var refs []sec.BootstrapSecretRef
	for _, purpose := range []string{"artifact_write", "artifact_read", "artifact_delete", "artifact_upload_issuer", "artifact_ca", "evidence_store", "evidence_write", "evidence_read", "evidence_delete", "evidence_ca", "evidence_kek", "kek", "capture_signing", "acceptance_signing", "catalog_signing", "catalog_read", "catalog_append", "catalog_snapshot", "nonce_hmac", "status_relay"} {
		ref := sec.BootstrapSecretRef{Purpose: purpose, IdentityHash: hash([]byte(purpose)), Version: "registry-1"}
		if purpose == "capture_signing" {
			ref = capture
		}
		refs = append(refs, ref)
	}
	doc["references"] = refs
	raw, e = json.Marshal(doc)
	if e != nil {
		t.Fatal(e)
	}
	config, e := sec.DecodeBootstrapConfig(raw)
	if e != nil {
		t.Fatal(e)
	}
	return config
}
