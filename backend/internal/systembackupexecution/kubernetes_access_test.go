package systembackupexecution

import (
	"context"
	"errors"
	"path/filepath"
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
	if _, err := CaptureKubernetesGrants(cfg, "controller"); err == nil {
		t.Fatal("cross-namespace writer widened backup scope")
	}
	cfg.Writers[1].Namespace = cfg.Namespace
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

func TestPublicationSignerKubernetesGrantsAndProbeUseExactControllerSA(t *testing.T) {
	cfg := captureAccessFixture(t)
	for _, enabled := range []bool{false, true} {
		if enabled {
			cfg.PublicationSigners = &PublicationSignerReference{Protocol: PublicationSignerMaterialsVersion, Path: filepath.Join(t.TempDir(), "materials.json")}
		}
		objects, err := CaptureKubernetesGrants(cfg, "publisher-controller")
		if err != nil {
			t.Fatal(err)
		}
		worker, controller := 0, 0
		for _, object := range objects {
			if role, ok := object.(*rbacv1.Role); ok {
				for _, rule := range role.Rules {
					if slices.Contains(rule.Resources, "serviceaccounts") {
						if role.Namespace != cfg.Namespace || len(rule.APIGroups) != 1 || rule.APIGroups[0] != "" || len(rule.Verbs) != 1 || rule.Verbs[0] != "get" || len(rule.ResourceNames) != 1 {
							t.Fatal("unbounded or writable ServiceAccount access")
						}
						switch rule.ResourceNames[0] {
						case cfg.Security.ServiceAccountName:
							worker++
						case "publisher-controller":
							controller++
						default:
							t.Fatal("unrelated ServiceAccount granted")
						}
					}
				}
			}
		}
		if worker != 1 || (controller == 1) != enabled {
			t.Fatal("controller self-SA read did not match publication feature")
		}
	}
	for _, sa := range []string{"", "*", cfg.Security.ServiceAccountName} {
		if _, err := CaptureKubernetesGrants(cfg, sa); err == nil {
			t.Fatal("invalid/worker controller SA admitted")
		}
	}
	if _, err := RequiredCaptureAccess(cfg); err == nil {
		t.Fatal("publication permission inventory silently omitted controller identity")
	}
	for _, allow := range []bool{true, false} {
		client := fake.NewSimpleClientset()
		ownReads := 0
		client.PrependReactor("create", "selfsubjectaccessreviews", func(action kt.Action) (bool, runtime.Object, error) {
			r := action.(kt.CreateAction).GetObject().(*authv1.SelfSubjectAccessReview)
			a := r.Spec.ResourceAttributes
			r.Status.Allowed = true
			if a.Resource == "serviceaccounts" && a.Name == "publisher-controller" {
				ownReads++
				if a.Namespace != cfg.Namespace || a.Group != "" || a.Verb != "get" {
					t.Fatal("wrong own-SA probe")
				}
				r.Status.Allowed = allow
				r.Status.Denied = !allow
			}
			return true, r, nil
		})
		if err := CheckCaptureKubernetesAccess(context.Background(), client, cfg, "publisher-controller"); (err == nil) != allow || ownReads != 1 {
			t.Fatal("own-SA denial not reflected in real capture probe", err)
		}
	}
}
