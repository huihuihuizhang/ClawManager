package systembackupexecution

import (
	"context"
	"errors"
	"slices"
	"testing"

	"clawreef/internal/systembackup/kube"
	authv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	kt "k8s.io/client-go/testing"
)

func captureAccessFixture(t *testing.T) DeploymentConfig {
	cfg := testDeploymentConfiguration(t)
	cfg.Security.Volumes = []kube.MountIdentity{{Kind: "PersistentVolumeClaim", Name: "source", UID: "source-uid", PVName: "source-pv", PVUID: "source-pv-uid"}, {Kind: "PersistentVolumeClaim", Name: "staging", UID: "stage-uid", PVName: "stage-pv", PVUID: "stage-pv-uid"}}
	return cfg
}

func TestCaptureKubernetesGrantsDoNotGrantSourceSecretsOrAdministration(t *testing.T) {
	cfg := captureAccessFixture(t)
	cfg.Writers = append(cfg.Writers, PlatformDeployment{Namespace: "source-other", Name: "original-source", UID: "dep-2"})
	objects, err := CaptureKubernetesGrants(cfg, "controller")
	if err != nil {
		t.Fatal(err)
	}
	for _, object := range objects {
		var ns string
		var rules []rbacv1.PolicyRule
		switch v := object.(type) {
		case *rbacv1.Role:
			ns, rules = v.Namespace, v.Rules
		case *rbacv1.ClusterRole:
			rules = v.Rules
		default:
			continue
		}
		for _, rule := range rules {
			if slices.Contains(rule.Verbs, "*") || slices.Contains(rule.Resources, "*") || slices.Contains(rule.Resources, "roles") || slices.Contains(rule.Resources, "pods/exec") || slices.Contains(rule.Resources, "pods/log") || slices.Contains(rule.Resources, "nodes/proxy") {
				t.Fatal("broad administration granted")
			}
			if slices.Contains(rule.Resources, "secrets") && (ns != cfg.Namespace || slices.Contains(rule.Verbs, "list") || slices.Contains(rule.Verbs, "delete")) {
				t.Fatal("source secret access granted")
			}
			if slices.Contains(rule.Resources, "deployments") && (len(rule.ResourceNames) == 0 || slices.Contains(rule.Verbs, "create") || slices.Contains(rule.Verbs, "delete")) {
				t.Fatal("unbounded source lifecycle granted")
			}
			if (slices.Contains(rule.Resources, "nodes") || slices.Contains(rule.Resources, "persistentvolumes") || slices.Contains(rule.Resources, "namespaces")) && (len(rule.ResourceNames) == 0 || len(rule.Verbs) != 1 || rule.Verbs[0] != "get") {
				t.Fatal("unbounded cluster access granted")
			}
		}
	}
	if _, err = CaptureKubernetesGrants(cfg, cfg.Security.ServiceAccountName); err == nil {
		t.Fatal("worker was granted controller permissions")
	}
	cfg.Writers[0].Namespace = "*"
	if _, err = CaptureKubernetesGrants(cfg, "controller"); err == nil {
		t.Fatal("wildcard namespace accepted")
	}
}

func TestCaptureKubernetesProbeRejectsDeniedUnavailableAndInconclusive(t *testing.T) {
	for _, mode := range []string{"allowed", "denied", "evaluation-error", "transport"} {
		t.Run(mode, func(t *testing.T) {
			client := fake.NewSimpleClientset()
			calls := 0
			client.PrependReactor("create", "selfsubjectaccessreviews", func(a kt.Action) (bool, runtime.Object, error) {
				calls++
				r := a.(kt.CreateAction).GetObject().(*authv1.SelfSubjectAccessReview)
				if r.Spec.ResourceAttributes == nil {
					t.Fatal("missing exact resource request")
				}
				r.Status.Allowed = true
				switch mode {
				case "denied":
					r.Status.Denied = true
				case "evaluation-error":
					r.Status.EvaluationError = "unavailable"
				case "transport":
					return true, nil, errors.New("unavailable")
				}
				return true, r, nil
			})
			err := CheckCaptureKubernetesAccess(context.Background(), client, captureAccessFixture(t))
			if (err == nil) != (mode == "allowed") || calls == 0 {
				t.Fatal("inconclusive permissions became readiness", err)
			}
		})
	}
}
