package systembackupexecution

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func currentStoppedProMetadataFixture(t *testing.T) (context.Context, DeploymentConfig, b.InstanceIdentity, currentStoppedProSQLStorage, *fake.Clientset) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	i := b.InstanceIdentity{ID: 7, UserID: 3, Generation: 2, Mode: "pro", OS: "linux", Status: "stopped", Type: "openclaw", Backend: "desktop", Namespace: "app", Workspace: "/workspace"}
	l := CurrentStoppedProLayout{InstanceID: 7, Mounts: []CurrentStoppedProMountLayout{{MountID: "workspace", Claim: "instance-data", MountPath: "/workspace", DataPath: "/workspace"}}}
	cfg := DeploymentConfig{Namespace: "app", NamespaceUID: "namespace-uid", Workspace: WorkspaceCapture{Node: "node-a"}, RuntimeSources: &RuntimeSourceConfig{CurrentStoppedProLayouts: []CurrentStoppedProLayout{l}}}
	cfg.Security.NodeUIDs = map[string]string{"node-a": "node-a-uid", "node-b": "node-b-uid"}
	pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "instance-data", Namespace: "app", UID: types.UID("pvc-uid")}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "instance-pv"}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}}
	pv := &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "instance-pv", UID: types.UID("pv-uid")}, Spec: corev1.PersistentVolumeSpec{PersistentVolumeSource: corev1.PersistentVolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/data/instance-7"}}, ClaimRef: &corev1.ObjectReference{Name: pvc.Name, Namespace: pvc.Namespace, UID: pvc.UID}, NodeAffinity: &corev1.VolumeNodeAffinity{Required: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "kubernetes.io/hostname", Operator: corev1.NodeSelectorOpIn, Values: []string{"node-a"}}}}}}}}, Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound}}
	cfg.Security.Volumes = []kube.MountIdentity{{Volume: "workspace", Kind: "PersistentVolumeClaim", Name: pvc.Name, UID: string(pvc.UID), PVName: pv.Name, PVUID: string(pv.UID), SHA256: kube.ContentHash(pv.Spec)}}
	client := fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app", UID: types.UID("namespace-uid")}}, pvc, pv, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: types.UID("node-a-uid"), Labels: map[string]string{corev1.LabelOSStable: "linux", "kubernetes.io/hostname": "node-a"}}}, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-b", UID: types.UID("node-b-uid"), Labels: map[string]string{corev1.LabelOSStable: "linux", "kubernetes.io/hostname": "node-b"}}})
	return ctx, cfg, i, currentStoppedProSQLStorage{Claim: pvc.Name, MountPath: "/workspace"}, client
}

// Kubernetes fake reads verify only metadata production/consumer semantics.
// None of these tests creates an Installer capability, a held gate or a P7
// native positive. Full native CRI/keeper/page validation belongs to root/D.
func TestCurrentStoppedProActualMetadataAndMaterialConsumption(t *testing.T) {
	ctx, cfg, i, storage, client := currentStoppedProMetadataFixture(t)
	m, err := observeCurrentStoppedPro(ctx, client, cfg, i, storage)
	if err != nil {
		t.Fatal(err)
	}
	if m.validate() != nil || m.Baseline.ControllerUID != "" || m.OriginalState().Running || m.Baseline.Volumes[0].DataNodeUID != "node-a-uid" {
		t.Fatal("current absent-controller baseline lost")
	}
	scopeRaw, err := BuildOriginalInstanceMountScope(ctx, client, cfg, []b.InstanceIdentity{i}, []b.RuntimeWriterSpec{{Source: i, Kind: "stopped", Stopped: m.OriginalState()}}, []InstancePersistentMountLayout{})
	if err != nil {
		t.Fatal(err)
	}
	var scope productionPersistentMountScope
	if json.Unmarshal(scopeRaw, &scope) != nil || scope.validate() != nil || len(scope.Mounts) != 0 || len(scope.CurrentStoppedPro) != 1 {
		t.Fatal("separate current material branch required")
	}
	if _, err := persistentMountsForInstances(&scope, []b.InstanceIdentity{i}); err != nil {
		t.Fatal(err)
	}
	metadata := productionSQLSourceMetadata{CurrentStoppedProStorage: map[int]currentStoppedProSQLStorage{i.ID: storage}}
	if checkCurrentStoppedProSQL(&scope, metadata, []b.InstanceIdentity{i}) != nil {
		t.Fatal("exact actual storage rejected")
	}
	metadata.CurrentStoppedProStorage[i.ID] = currentStoppedProSQLStorage{Claim: "replaced", MountPath: "/workspace"}
	if checkCurrentStoppedProSQL(&scope, metadata, []b.InstanceIdentity{i}) == nil {
		t.Fatal("changed SQL claim accepted")
	}
	mount := currentStoppedProCaptureMount(m, m.Mounts[0], productionInstanceMount{})
	if mount.Source.PersistentVolumeClaim == nil || !mount.Source.PersistentVolumeClaim.ReadOnly || mount.Source.PersistentVolumeClaim.ClaimName != storage.Claim || mount.SubPath != "" || mount.NodeName != "node-a" {
		t.Fatal("Pro must use its own pinned PVC root")
	}
	cfg.CaptureModules = &ProductionCaptureReference{Path: "/later/final-material"}
	again, err := observeCurrentStoppedPro(ctx, client, cfg, i, storage)
	if err != nil || again.Baseline.CurrentConfigSHA256 != m.Baseline.CurrentConfigSHA256 {
		t.Fatal("late material pin created a hash cycle", err)
	}
}

func TestCurrentStoppedProRefusesUnownedOrAmbiguousMetadata(t *testing.T) {
	t.Run("missing-owner-layout", func(t *testing.T) {
		ctx, cfg, i, s, c := currentStoppedProMetadataFixture(t)
		cfg.RuntimeSources.CurrentStoppedProLayouts = nil
		if _, err := observeCurrentStoppedPro(ctx, c, cfg, i, s); err == nil {
			t.Fatal("missing complete current layout accepted")
		}
	})
	t.Run("actual-sql-disagrees", func(t *testing.T) {
		ctx, cfg, i, s, c := currentStoppedProMetadataFixture(t)
		s.Claim = "other"
		if _, err := observeCurrentStoppedPro(ctx, c, cfg, i, s); err == nil {
			t.Fatal("layout DTO overrode actual SQL")
		}
	})
	t.Run("two-hostpath-nodes", func(t *testing.T) {
		ctx, cfg, i, s, c := currentStoppedProMetadataFixture(t)
		pv, err := c.CoreV1().PersistentVolumes().Get(ctx, "instance-pv", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		pv.Spec.NodeAffinity = nil
		if _, err = c.CoreV1().PersistentVolumes().Update(ctx, pv, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := observeCurrentStoppedPro(ctx, c, cfg, i, s); err == nil {
			t.Fatal("same pathname selected an arbitrary node")
		}
	})
	t.Run("new-pod-even-if-terminated", func(t *testing.T) {
		ctx, cfg, i, s, c := currentStoppedProMetadataFixture(t)
		_, err := c.CoreV1().Pods("app").Create(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "successor", Labels: map[string]string{"instance-id": "7"}}, Status: corev1.PodStatus{Phase: corev1.PodSucceeded}}, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := observeCurrentStoppedPro(ctx, c, cfg, i, s); err == nil {
			t.Fatal("a current instance Pod was ignored")
		}
	})
	t.Run("volume-replacement", func(t *testing.T) {
		ctx, cfg, i, s, c := currentStoppedProMetadataFixture(t)
		m, err := observeCurrentStoppedPro(ctx, c, cfg, i, s)
		if err != nil {
			t.Fatal(err)
		}
		pvc, err := c.CoreV1().PersistentVolumeClaims("app").Get(ctx, s.Claim, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		pvc.UID = types.UID("replacement")
		if _, err = c.CoreV1().PersistentVolumeClaims("app").Update(ctx, pvc, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		if recheckCurrentStoppedProMaterial(ctx, c, cfg, m) == nil {
			t.Fatal("changed actual PVC accepted")
		}
	})
}

func TestCurrentStoppedProCurrentControllerAndCompleteLayout(t *testing.T) {
	ctx, cfg, i, s, c := currentStoppedProMetadataFixture(t)
	cfg.RuntimeSources.CurrentStoppedProLayouts[0].ControllerName = "current-controller"
	zero := int32(0)
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "current-controller", Namespace: "app", UID: types.UID("deployment-uid"), Generation: 1, Labels: map[string]string{"instance-id": "7", "user-id": "3"}}, Spec: appsv1.DeploymentSpec{Replicas: &zero, Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "desktop", VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/workspace"}}}}, Volumes: []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: s.Claim}}}}}}}}
	if _, err := c.AppsV1().Deployments("app").Create(ctx, dep, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	m, err := observeCurrentStoppedPro(ctx, c, cfg, i, s)
	if err != nil || m.Baseline.ControllerUID != "deployment-uid" {
		t.Fatal("real zero-replica controller rejected", err)
	}
	dep.Spec.Template.Spec.Volumes = append(dep.Spec.Template.Spec.Volumes, corev1.Volume{Name: "unknown", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/unowned"}}})
	dep.Spec.Template.Spec.Containers[0].VolumeMounts = append(dep.Spec.Template.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "unknown", MountPath: "/unknown"})
	if _, err := c.AppsV1().Deployments("app").Update(ctx, dep, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := observeCurrentStoppedPro(ctx, c, cfg, i, s); err == nil {
		t.Fatal("unregistered persistent mount accepted")
	}
}

func TestCurrentStoppedProKeepsLegacyMaterialEncoding(t *testing.T) {
	raw, err := json.Marshal(productionPersistentMountScope{Version: persistentMountScopeVersion, Mounts: []productionPersistentMountBinding{}})
	if err != nil || strings.Contains(string(raw), "CurrentStoppedPro") || string(raw) != `{"Version":"original-instance-persistent-mounts.v1","Mounts":[]}` {
		t.Fatal("legacy no-current encoding changed", string(raw), err)
	}
	if requireRunningSourceMetadata(b.SourceInventory{Instances: []b.InstanceIdentity{{ID: 1, UserID: 1, Generation: 1, Mode: "lite", OS: "linux", Status: "stopped"}}}) == nil {
		t.Fatal("stopped Lite was silently admitted")
	}
}
