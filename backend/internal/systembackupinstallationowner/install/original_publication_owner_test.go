package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
	appsv1 "k8s.io/api/apps/v1"
	authn "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	kt "k8s.io/client-go/testing"
)

func TestOriginalPublicationNativeKeyRequiresActualCompleteFirstVersion(t *testing.T) {
	pub, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"valid", "missing-derived", "missing-sealed", "exportable", "deletion", "rotated", "bad-key"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/v1/sys/health" {
					h := map[string]any{"cluster_id": "actual-provider", "initialized": true, "sealed": false}
					if mode == "missing-sealed" {
						delete(h, "sealed")
					}
					_ = json.NewEncoder(w).Encode(h)
					return
				}
				k := map[string]any{"type": "ed25519", "supports_signing": true, "derived": false, "exportable": false, "allow_plaintext_backup": false, "deletion_allowed": false, "latest_version": 1, "keys": map[string]any{"1": map[string]any{"public_key": base64.StdEncoding.EncodeToString(pub)}}}
				switch mode {
				case "missing-derived":
					delete(k, "derived")
				case "exportable":
					k["exportable"] = true
				case "deletion":
					k["deletion_allowed"] = true
				case "rotated":
					k["latest_version"] = 2
				case "bad-key":
					k["keys"] = map[string]any{"1": map[string]any{"public_key": "invalid"}}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"data": k})
			}))
			defer server.Close()
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			v, e := newOriginalPublicationVault(server.URL, ca, hash(ca))
			if e != nil {
				t.Fatal(e)
			}
			defer v.close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if mode == "missing-sealed" {
				if v.health(ctx, "actual-provider") == nil {
					t.Fatal("missing sealed accepted")
				}
				return
			}
			actual, e := v.key(ctx, "transit", "original", nil)
			if mode == "valid" {
				if e != nil || !bytes.Equal(actual, pub) {
					t.Fatal("actual TLS public key rejected", e)
				}
			} else if e == nil {
				t.Fatal("incomplete/expanded native key accepted")
			}
		})
	}
}

func TestOriginalPublicationNativeProbeUsesActualPurposeTokenAndSignature(t *testing.T) {
	pub, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(private)
	for _, mode := range []string{"valid", "wrong-token-purpose", "missing-type", "expanded-policy", "renewable", "long-ttl", "wrong-version", "bad-signature"} {
		t.Run(mode, func(t *testing.T) {
			kube := fake.NewSimpleClientset()
			kube.PrependReactor("create", "tokenreviews", func(action kt.Action) (bool, runtime.Object, error) {
				request := action.(kt.CreateAction).GetObject().(*authn.TokenReview)
				if len(request.Spec.Audiences) != 1 || request.Spec.Audiences[0] != "actual-purpose" {
					t.Fatal("actual audience not reviewed")
				}
				audience := "actual-purpose"
				if mode == "wrong-token-purpose" {
					audience = "other-purpose"
				}
				return true, &authn.TokenReview{Status: authn.TokenReviewStatus{Authenticated: true, Audiences: []string{audience}, User: authn.UserInfo{Username: "system:serviceaccount:actual:controller", UID: "actual-sa", Extra: map[string]authn.ExtraValue{"authentication.kubernetes.io/pod-uid": {"actual-pod"}}}}}, nil
			})
			signs := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if strings.HasSuffix(r.URL.Path, "/login") {
					auth := map[string]any{"client_token": "actual-private-short-token", "token_type": "batch", "renewable": false, "lease_duration": 10, "policies": []string{"actual-policy"}, "token_policies": []string{"actual-policy"}, "identity_policies": []string{}, "metadata": map[string]string{"role": "actual-role", "namespace": "actual", "pod_uid": "actual-pod", "service_account_uid": "actual-sa"}}
					switch mode {
					case "missing-type":
						delete(auth, "token_type")
					case "expanded-policy":
						auth["policies"] = []string{"actual-policy", "extra"}
					case "renewable":
						auth["renewable"] = true
					case "long-ttl":
						auth["lease_duration"] = 11
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"auth": auth})
					return
				}
				if r.URL.Path != "/v1/transit/sign/actual-key" || r.Header.Get("X-Vault-Token") != "actual-private-short-token" {
					t.Error("wrong signing transport or credential")
					w.WriteHeader(403)
					return
				}
				var in map[string]string
				if json.NewDecoder(r.Body).Decode(&in) != nil || in["key_version"] != "1" {
					t.Error("exact version wire missing")
					return
				}
				message, e := base64.StdEncoding.DecodeString(in["input"])
				if e != nil || !bytes.HasPrefix(message, []byte("system-backup-original-publication-installation-probe.v1\x00")) {
					t.Error("business/task domain used for installation probe")
					return
				}
				signs++
				signature := ed25519.Sign(private, message)
				if mode == "bad-signature" {
					signature[0] ^= 1
				}
				version := "1"
				if mode == "wrong-version" {
					version = "2"
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"signature": "vault:v" + version + ":" + base64.StdEncoding.EncodeToString(signature)}})
			}))
			defer server.Close()
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			v, e := newOriginalPublicationVault(server.URL, ca, hash(ca))
			if e != nil {
				t.Fatal(e)
			}
			defer v.close()
			i := &Installer{kube: kube, planHash: strings.Repeat("a", 64)}
			b := owner.Binding{Namespace: "actual", ServiceAccountName: "controller", ServiceAccountUID: "actual-sa", PodUID: "actual-pod", Audience: "actual-purpose", AuthMount: "actual-auth", Role: "actual-role", Policy: "actual-policy", TransitMount: "transit", KeyName: "actual-key", ProviderVersion: "1", Purpose: "catalog_record"}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			end, e := i.originalPublicationProbe(ctx, v, b, pub, []byte("actual-private-jwt"))
			if mode == "valid" {
				if e != nil || signs != 1 || !time.Now().Before(end) {
					t.Fatal("real challenge signature rejected", e)
				}
			} else if e == nil {
				t.Fatal("wrong/expanded native proof accepted")
			}
			if mode == "wrong-token-purpose" && signs != 0 {
				t.Fatal("foreign audience reached provider")
			}
		})
	}
}

func TestOriginalPublicationIssuerRejectsBeforeAnyProviderMutation(t *testing.T) {
	for _, mode := range []string{"password", "enrollment", "expired", "wrong-issuer"} {
		t.Run(mode, func(t *testing.T) {
			f := newAuthorityFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			password := f.password
			enrollment := f.enrollment
			key := f.key
			until := time.Now().Add(time.Minute)
			switch mode {
			case "password":
				password = []byte("foreign-admin")
			case "enrollment":
				enrollment.DocumentSHA256 = strings.Repeat("f", 64)
			case "expired":
				until = time.Now().Add(-time.Second)
			case "wrong-issuer":
				_, key, _ = ed25519.GenerateKey(rand.Reader)
				defer clear(key)
			}
			directory := t.TempDir()
			_ = os.Chmod(directory, 0700)
			var providerCalls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { providerCalls.Add(1); w.WriteHeader(403) }))
			defer server.Close()
			inputs := t.TempDir()
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			caFile := filepath.Join(inputs, "ca.pem")
			rootFile := filepath.Join(inputs, "native-root.token")
			rootToken := []byte("original-retained-native-root-token")
			if os.WriteFile(caFile, ca, 0600) != nil || os.WriteFile(rootFile, rootToken, 0600) != nil {
				t.Fatal("native source files")
			}

			b := f.record.Binding
			depName := "actual-publication-controller"
			depUID := types.UID("actual-deployment-uid")
			rsUID := types.UID("actual-rs-uid")
			controlled := true
			if _, e := f.i.kube.AppsV1().Deployments(b.Namespace).Create(ctx, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: depName, Namespace: b.Namespace, UID: depUID}, Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: b.ServiceAccountName}}}}, metav1.CreateOptions{}); e != nil {
				t.Fatal(e)
			}
			if _, e := f.i.kube.AppsV1().ReplicaSets(b.Namespace).Create(ctx, &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "actual-rs", Namespace: b.Namespace, UID: rsUID, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: depName, UID: depUID, Controller: &controlled}}}}, metav1.CreateOptions{}); e != nil {
				t.Fatal(e)
			}
			pod, e := f.i.kube.CoreV1().Pods(b.Namespace).Get(ctx, b.PodName, metav1.GetOptions{})
			if e != nil {
				t.Fatal(e)
			}
			pod.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "actual-rs", UID: rsUID, Controller: &controlled}}
			if _, e = f.i.kube.CoreV1().Pods(b.Namespace).Update(ctx, pod, metav1.UpdateOptions{}); e != nil {
				t.Fatal(e)
			}
			o := OriginalPublicationSigningOptions{ControllerDeployment: depName, ControllerPodName: b.PodName, CA: BootstrapSourceFilePin{File: caFile, SHA256: hash(ca)}, VaultOwnerMaterial: BootstrapSourceFilePin{File: rootFile, SHA256: hash(rootToken)}, Endpoint: server.URL, ProviderClusterID: "actual", JWTMount: "actual-jwt", Until: until, OutputDirectory: directory}
			if r, e := f.i.ProduceOriginalPublicationSigningMaterial(ctx, password, enrollment, o, key); e == nil || r.Version != "" {
				t.Fatal("invalid original owner emitted signing record")
			}
			if providerCalls.Load() != 0 {
				t.Fatal("invalid original issuer reached native provider")
			}
			entries, e := os.ReadDir(directory)
			if e != nil || len(entries) != 0 {
				t.Fatal("invalid owner wrote partial issuance")
			}
		})
	}
}

func TestOriginalPublicationOwnerTokenRejectsDuplicateInitRoot(t *testing.T) {
	directory := t.TempDir()
	file := filepath.Join(directory, "native-init.json")
	raw := []byte(`{"root_token":"actual-native-root-token","root_token":"foreign-native-root-token"}`)
	if os.WriteFile(file, raw, 0600) != nil {
		t.Fatal("input")
	}
	if _, e := originalPublicationOwnerToken(BootstrapSourceFilePin{File: file, SHA256: hash(raw)}, true); e == nil {
		t.Fatal("ambiguous native source accepted")
	}
}

func TestOriginalPublicationManifestCannotEnrollItsOwnIssuer(t *testing.T) {
	issuer, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(key)
	_, foreign, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(foreign)
	directory := t.TempDir()
	file := filepath.Join(directory, "original-publication-signing.material.json")
	raw, e := canonical(OriginalPublicationSigningFiles{Version: "original-publication-signing-material.v1"})
	if e != nil {
		t.Fatal(e)
	}
	if os.WriteFile(file, raw, 0600) != nil {
		t.Fatal("material")
	}
	signatureFile := filepath.Join(directory, "original-publication-signing.material.signature")
	pin := BootstrapSourceFilePin{File: file, SHA256: hash(raw)}
	if os.WriteFile(signatureFile, ed25519.Sign(foreign, append([]byte(originalPublicationSigningMaterialDomain), raw...)), 0600) != nil {
		t.Fatal("signature")
	}
	if _, e = readOriginalPublicationSigningFiles(context.Background(), issuer, pin); e == nil {
		t.Fatal("foreign self-signed manifest accepted")
	}
	if os.WriteFile(signatureFile, ed25519.Sign(key, append([]byte(originalPublicationSigningMaterialDomain), raw...)), 0600) != nil {
		t.Fatal("signature")
	}
	if _, e = readOriginalPublicationSigningFiles(context.Background(), issuer, pin); e != nil {
		t.Fatal("original issuer transport rejected", e)
	}
}
