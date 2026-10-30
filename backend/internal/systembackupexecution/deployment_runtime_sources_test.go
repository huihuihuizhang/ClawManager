package systembackupexecution

import (
	b "clawreef/internal/systembackup/publicadapter"
	"context"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"
)

func runtimeDeploymentFixture(t *testing.T) DeploymentConfig {
	cfg := captureAccessFixture(t)
	cfg.CaptureScope = "runtime-workspace"
	cfg.RuntimeSources = &RuntimeSourceConfig{Supported: []b.AgentKind{{Type: "openclaw", Mode: "pro", Variant: "linux", OS: "linux"}}, Namespaces: []string{cfg.Namespace}, LeaseParticipants: []string{"application-mutations"}, WorkspaceRoot: "/workspaces"}
	return cfg
}

func TestNativeRuntimeRequiresPinnedAgentCA(t *testing.T) {
	cfg := runtimeDeploymentFixture(t)
	cfg.RuntimeSources.Supported = []b.AgentKind{{Type: "openclaw", Mode: "lite", Variant: "linux", OS: "linux"}}
	cfg.RuntimeSources.AgentTokenFile = filepath.Join(t.TempDir(), "agent-token")
	if cfg.RuntimeSources.validate() == nil {
		t.Fatal("native runtime admitted without a pinned Agent CA")
	}
	cfg.RuntimeSources.AgentCAFile = filepath.Join(t.TempDir(), "agent-ca.pem")
	cfg.RuntimeSources.AgentCASHA256 = "abcdef"
	if cfg.RuntimeSources.validate() == nil {
		t.Fatal("native runtime admitted an unpinned Agent CA")
	}
	cfg.RuntimeSources.AgentCASHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if err := cfg.RuntimeSources.validate(); err != nil {
		t.Fatal(err)
	}
}
func TestDeploymentRuntimeScopeAndRBACAreExplicit(t *testing.T) {
	cfg := runtimeDeploymentFixture(t)
	if e := cfg.Validate(); e != nil {
		t.Fatal(e)
	}
	access, e := RequiredCaptureAccess(cfg)
	if e != nil {
		t.Fatal(e)
	}
	podAccess := false
	secretRules := 0
	for _, item := range access {
		if item.Namespace != "" && item.Namespace != cfg.Namespace {
			t.Fatal("runtime role escaped namespace")
		}
		if item.Namespace == cfg.Namespace {
			if slices.Contains(item.Rule.Resources, "secrets") {
				// Worker identity Secrets already require this exact rule in the
				// installation namespace. Runtime admission must not expand it.
				secretRules++
				if !slices.Equal(item.Rule.Verbs, []string{"get", "create"}) || len(item.Rule.ResourceNames) != 0 {
					t.Fatal("runtime expanded identity secret rule")
				}
			}
			if slices.Contains(item.Rule.Resources, "pods") && slices.Contains(item.Rule.Verbs, "patch") && slices.Contains(item.Rule.Verbs, "create") {
				podAccess = true
			}
		}
	}
	if !podAccess || secretRules != 1 {
		t.Fatal("actual Pod resume calls lack RBAC")
	}
	cfg.CaptureScope = "platform-workspace"
	if cfg.Validate() == nil {
		t.Fatal("runtime enabled implicitly")
	}
	cfg.CaptureScope = "runtime-workspace"
	cfg.RuntimeSources.LeaseParticipants = nil
	if cfg.Validate() == nil {
		t.Fatal("missing participants accepted")
	}
}

func TestDeploymentRuntimeCannotExpandNamespaceScope(t *testing.T) {
	for _, fault := range []string{"runtime-namespace", "additional-namespace", "runtime-deployment", "platform-deployment"} {
		t.Run(fault, func(t *testing.T) {
			cfg := runtimeDeploymentFixture(t)
			switch fault {
			case "runtime-namespace":
				cfg.RuntimeSources.Namespaces[0] = "other"
			case "additional-namespace":
				cfg.RuntimeSources.Namespaces = append(cfg.RuntimeSources.Namespaces, "other")
			case "runtime-deployment":
				cfg.RuntimeSources.Deployments = []PlatformDeployment{{Namespace: "other", Name: "runtime", UID: "uid"}}
			case "platform-deployment":
				cfg.Writers[0].Namespace = "other"
			}
			if cfg.Validate() == nil {
				t.Fatal("scope expansion accepted")
			}
			if _, err := RequiredCaptureAccess(cfg); err == nil {
				t.Fatal("out-of-scope role generated")
			}
		})
	}
}
func TestDeploymentRuntimeChecksActualCapturedVolume(t *testing.T) {
	cfg := runtimeDeploymentFixture(t)
	s := &DeploymentService{Config: cfg}
	source := b.InstanceIdentity{ID: 7, UserID: 2, Generation: 3, Mode: "pro", Type: "openclaw", Variant: "linux", OS: "linux", Status: "running", Namespace: cfg.Namespace, Pod: "original", Workspace: "/workspaces/2/7"}
	for _, fault := range []string{"", "namespace", "path", "volume", "subpath", "missing", "replacement", "overlay"} {
		t.Run(fault, func(t *testing.T) {
			item := source
			target := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Namespace: cfg.Namespace, Name: cfg.Workspace.Claim, UID: types.UID("source-uid")}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "source-pv"}}
			mounted := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Namespace: source.Namespace, Name: "runtime-work"}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "source-pv"}}
			pv := &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "source-pv", UID: types.UID("source-pv-uid")}}
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: source.Namespace, Name: source.Pod}, Spec: corev1.PodSpec{Volumes: []corev1.Volume{{Name: "workspace", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: mounted.Name}}}}, Containers: []corev1.Container{{Name: "source", VolumeMounts: []corev1.VolumeMount{{Name: "workspace", MountPath: "/workspaces"}}}}}}
			switch fault {
			case "namespace":
				item.Namespace = "other"
			case "path":
				item.Workspace = "/workspaces/../escape"
			case "volume":
				mounted.Spec.VolumeName = "different-pv"
			case "subpath":
				pod.Spec.Containers[0].VolumeMounts[0].SubPath = "different"
			case "missing":
				pod.Spec.Volumes = nil
			case "replacement":
				pv.UID = "new-pv"
			case "overlay":
				pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "different", MountPath: "/workspaces/2/7/nested"})
			}
			inv := b.SourceInventory{Database: cfg.SourceDatabase, ServerUUID: cfg.SourceServerUUID, Instances: []b.InstanceIdentity{item}}
			e := s.validateRuntimeInventory(inv)
			if e == nil {
				e = s.checkRuntimeWorkspace(context.Background(), fake.NewSimpleClientset(target, mounted, pod, pv), inv.Instances)
			}
			if (e == nil) != (fault == "") {
				t.Fatal("volume scope mismatch", e)
			}
		})
	}
}

func TestDeploymentRuntimeChecksOwnedNFSSubtree(t *testing.T) {
	cfg := runtimeDeploymentFixture(t)
	cfg.Workspace.Claim = ""
	cfg.Workspace.NFS = &NFSWorkspace{Server: "10.107.165.245", Export: "/"}
	cfg.Workspace.SubPath = "installations/" + hash([]byte(cfg.InstallationID))
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	s := &DeploymentService{Config: cfg}
	source := b.InstanceIdentity{ID: 7, UserID: 2, Generation: 3, Mode: "pro", Type: "openclaw", Variant: "linux", OS: "linux", Status: "running", Namespace: cfg.Namespace, Pod: "original", Workspace: "/workspaces/" + cfg.Workspace.SubPath + "/users/2/instances/7"}
	for _, fault := range []string{"", "outside", "server", "export", "subpath", "missing", "overlay", "subpath-expr"} {
		t.Run(fault, func(t *testing.T) {
			item := source
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: cfg.Namespace, Name: source.Pod}, Spec: corev1.PodSpec{Volumes: []corev1.Volume{{Name: "workspace", VolumeSource: corev1.VolumeSource{NFS: &corev1.NFSVolumeSource{Server: cfg.Workspace.NFS.Server, Path: cfg.Workspace.NFS.Export}}}}, Containers: []corev1.Container{{Name: "source", VolumeMounts: []corev1.VolumeMount{{Name: "workspace", MountPath: "/workspaces"}}}}}}
			switch fault {
			case "outside":
				item.Workspace = "/workspaces/openclaw/user-2/instance-7"
			case "server":
				pod.Spec.Volumes[0].NFS.Server = "10.111.9.69"
			case "export":
				pod.Spec.Volumes[0].NFS.Path = "/other"
			case "subpath":
				pod.Spec.Containers[0].VolumeMounts[0].SubPath = "other"
			case "missing":
				pod.Spec.Volumes = nil
			case "overlay":
				pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "other", MountPath: item.Workspace + "/nested"})
			case "subpath-expr":
				pod.Spec.Containers[0].VolumeMounts[0].SubPathExpr = "$(POD_NAME)"
			}
			inv := b.SourceInventory{Database: cfg.SourceDatabase, ServerUUID: cfg.SourceServerUUID, Instances: []b.InstanceIdentity{item}}
			err := s.validateRuntimeInventory(inv)
			if err == nil {
				err = s.checkRuntimeWorkspace(context.Background(), fake.NewSimpleClientset(pod), inv.Instances)
			}
			if (err == nil) != (fault == "") {
				t.Fatal("NFS source scope mismatch", fault, err)
			}
		})
	}
	stopped := source
	stopped.Status = "stopped"
	stopped.Pod = ""
	if err := s.checkRuntimeWorkspace(context.Background(), fake.NewSimpleClientset(), []b.InstanceIdentity{stopped}); err != nil {
		t.Fatal("stopped source inside installation subtree rejected", err)
	}
	stopped.Workspace = "/workspaces/openclaw/user-2/instance-7"
	if err := s.checkRuntimeWorkspace(context.Background(), fake.NewSimpleClientset(), []b.InstanceIdentity{stopped}); err == nil {
		t.Fatal("stopped source outside installation subtree admitted")
	}
}
func TestDeploymentRuntimeRegistersRelayBehindWorkloadIdentity(t *testing.T) {
	cfg := runtimeDeploymentFixture(t)
	controlCalls := 0
	s := &DeploymentService{Config: cfg, Runtime: &PublicCapture{Owner: &PublicJobOwner{}, Control: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { controlCalls++; w.WriteHeader(204) })}}
	handler := s.controlHandler()
	for _, route := range []string{"/relay", "/worker/v1"} {
		req := httptest.NewRequest("POST", route, nil)
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		if route == "/relay" && out.Code != 403 {
			t.Fatal("relay reached unprotected handler", out.Code)
		}
		if route == "/worker/v1" && out.Code != 204 {
			t.Fatal("original control route lost")
		}
	}
	if controlCalls != 1 {
		t.Fatal("relay fell through to worker control")
	}
}
