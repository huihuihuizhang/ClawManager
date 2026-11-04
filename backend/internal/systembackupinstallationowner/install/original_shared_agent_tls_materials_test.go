package install

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// Crypto/source fixtures only. No installer authority, actual deployed Secret,
// live Agent, native source proof, or successful rollout is manufactured.
func TestSharedAgentTLSMaterialPurposeAndPrivateOutput(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	sources := []originalSharedAgentTLSSource{{"openclaw", "openclaw-model", "openclaw-uid-model", strings.Repeat("a", 64), 2}, {"hermes", "hermes-model", "hermes-uid-model", strings.Repeat("b", 64), 3}}
	files, targets, err := originalSharedAgentTLSFiles(now, now.Add(time.Hour), "installation-model", "namespace-model", "namespace-uid-model", "sbk-model-agent-tls", sources)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, raw := range files {
			clear(raw)
		}
	}()
	if len(files) != 7 || len(targets) != 2 {
		t.Fatal("unexpected private material roster")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(files["observer-ca.pem"]) {
		t.Fatal("missing actual certificate CA")
	}
	for _, target := range targets {
		prefix := "agent-" + hash([]byte(target.DeploymentUID))[:24]
		if _, err := tls.X509KeyPair(files[prefix+".pem"], files[prefix+"-key.pem"]); err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(files[prefix+".pem"])
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil || hash(leaf.Raw) != target.ServerCertificateDERSHA256 || len(leaf.URIs) != 1 || leaf.URIs[0].String() != target.ServerURI {
			t.Fatal("leaf binding lost")
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: originalSharedAgentServerName, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			t.Fatal(err)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
			t.Fatal("server leaf became a client authority")
		}
		var secret corev1.Secret
		if json.Unmarshal(files[prefix+"-secret.private.json"], &secret) != nil || secret.Name != target.SecretName || secret.Namespace != "namespace-model" || secret.Immutable == nil || !*secret.Immutable || secret.Type != corev1.SecretTypeTLS || !strings.Contains(string(secret.Data["tls.key"]), "PRIVATE KEY") {
			t.Fatal("exact immutable Secret output missing")
		}
	}
	for name := range files {
		if strings.Contains(name, "anchor") || strings.Contains(name, "observer-client") || strings.Contains(name, "ca-key") {
			t.Fatal("unneeded authority/private key material retained")
		}
	}
}

func TestSharedAgentTLSRejectsMixedSourceAndUnboundedMaterial(t *testing.T) {
	for _, name := range []string{"duplicate-uid", "unsupported-runtime", "missing-source-pin", "wrong-secret-prefix", "empty-namespace", "unbounded-certificate"} {
		t.Run(name, func(t *testing.T) {
			now := time.Now().UTC()
			sources := []originalSharedAgentTLSSource{{"openclaw", "openclaw-model", "uid-model", strings.Repeat("a", 64), 1}}
			prefix, namespace, until := "sbk-model-tls", "namespace-model", now.Add(time.Hour)
			switch name {
			case "duplicate-uid":
				sources = append(sources, sources[0])
			case "unsupported-runtime":
				sources[0].RuntimeType = "unknown"
			case "missing-source-pin":
				sources[0].SpecSHA256 = ""
			case "wrong-secret-prefix":
				prefix = "../foreign"
			case "empty-namespace":
				namespace = ""
			case "unbounded-certificate":
				until = now.Add(25 * time.Hour)
			}
			if files, _, err := originalSharedAgentTLSFiles(now, until, "installation-model", namespace, "namespace-uid-model", prefix, sources); err == nil {
				for _, raw := range files {
					clear(raw)
				}
				t.Fatal("invalid certificate/source selection admitted")
			}
		})
	}
}

func TestSharedAgentTLSReadsCompleteActualDeploymentCensus(t *testing.T) {
	for _, name := range []string{"exact-two-including-empty-hermes", "unknown-runtime", "non-shared-role", "denied-list"} {
		t.Run(name, func(t *testing.T) {
			one := int32(1)
			deployment := func(kind string) *appsv1.Deployment {
				return &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: kind + "-model", Namespace: "namespace-model", UID: types.UID("uid-" + kind), Generation: 1, Labels: map[string]string{"clawmanager.io/runtime-type": kind}}, Spec: appsv1.DeploymentSpec{Replicas: &one, Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "runtime"}}}}}}
			}
			openclaw, hermes := deployment("openclaw"), deployment("hermes")
			if name == "unknown-runtime" {
				hermes.Labels["clawmanager.io/runtime-type"] = "unknown"
			}
			if name == "non-shared-role" {
				hermes.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "RUNTIME_AGENT_ROLE", Value: "slot"}}
			}
			kube := fake.NewSimpleClientset(openclaw, hermes)
			kube.PrependReactor("create", "selfsubjectaccessreviews", func(ktesting.Action) (bool, runtime.Object, error) {
				return true, &authorizationv1.SelfSubjectAccessReview{Status: authorizationv1.SubjectAccessReviewStatus{Allowed: name != "denied-list", Denied: name == "denied-list"}}, nil
			})
			plan := Plan{}
			plan.Target.Namespace = "namespace-model"
			operator := &authenticatedOperator{installer: &Installer{kube: kube, plan: plan}}
			actual, err := operator.readOriginalSharedAgentTLSSources(context.Background())
			if name == "exact-two-including-empty-hermes" {
				if err != nil || len(actual) != 2 || actual[0].RuntimeType != "hermes" {
					t.Fatal("complete actual Agent source set missing", err)
				}
			} else if err == nil {
				t.Fatal("unknown or unauthorized source accepted")
			}
		})
	}
}
