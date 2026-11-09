package systembackupexecution

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	c "clawreef/internal/systembackupcontroller"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestRunningTenantProUsesOriginalPodClaim(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	source := b.InstanceIdentity{ID: 2, UserID: 1, Generation: 7, Type: "openclaw", Variant: "linux", Mode: "pro", OS: "linux", Status: "running", Pod: "runtime-pod", Namespace: "test-user-1", Workspace: "/srv/workspace/user"}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: source.Namespace, UID: "tenant-uid", Labels: map[string]string{"app": "clawreef", "managed-by": "clawreef", "user-id": "1"}}}
	labels := map[string]string{"app": "clawreef", "managed-by": "clawreef", "user-id": "1", "instance-id": "2"}
	controller := true
	deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "runtime", Namespace: source.Namespace, UID: "deployment-uid"},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}}}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "runtime-rs", Namespace: source.Namespace, UID: "rs-uid",
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: deployment.Name, UID: deployment.UID, Controller: &controller}}},
		Spec: appsv1.ReplicaSetSpec{Template: deployment.Spec.Template}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: source.Pod, Namespace: source.Namespace, UID: "pod-uid", Labels: labels,
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &controller}}},
		Spec: corev1.PodSpec{NodeName: "node", Volumes: []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "tenant-data"}}}},
			Containers: []corev1.Container{{Name: "runtime", VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/srv/workspace", SubPath: "payload"}}}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "tenant-data", Namespace: source.Namespace, UID: "claim-uid"},
		Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "tenant-pv", AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}}
	pv := &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "tenant-pv", UID: "pv-uid"}, Spec: corev1.PersistentVolumeSpec{
		ClaimRef:               &corev1.ObjectReference{Namespace: source.Namespace, Name: claim.Name, UID: claim.UID},
		PersistentVolumeSource: corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{Driver: "driver.longhorn.io", VolumeHandle: "volume"}},
	}}
	mount := runningTenantProMount{Source: source, NamespaceUID: string(ns.UID), PodUID: string(pod.UID), PodSpecSHA256: kube.ContentHash(pod.Spec),
		ReplicaSetUID: string(rs.UID), Deployment: deployment.Name, DeploymentUID: string(deployment.UID), SubPath: "payload/user",
		Identity: kube.MountIdentity{Volume: "workspace", Kind: "PersistentVolumeClaim", Name: claim.Name, UID: string(claim.UID), PVName: pv.Name, PVUID: string(pv.UID), SHA256: kube.ContentHash(pv.Spec)}}
	client := fake.NewSimpleClientset(ns, pod, rs, deployment, claim, pv,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-system", UID: "system-uid"}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node", UID: "node-uid", Labels: map[string]string{corev1.LabelOSStable: "linux"}}})
	if err := mount.check(ctx, client, "test-system"); err != nil {
		t.Fatal(err)
	}
	scope := &productionPersistentMountScope{Version: persistentMountScopeVersion, RunningTenantPro: []runningTenantProMount{mount}}
	if _, err := persistentMountsForInstances(scope, []b.InstanceIdentity{source}); err != nil {
		t.Fatal(err)
	}
	cfg := DeploymentConfig{Namespace: "test-system", NamespaceUID: "system-uid", Security: kube.WorkerSecurity{NodeUIDs: map[string]string{"node": "node-uid"}}}
	spec := b.RuntimeWriterSpec{Source: source, Kind: "deployment", Name: deployment.Name, UID: string(deployment.UID)}
	raw, err := BuildOriginalInstanceMountScope(ctx, client, cfg, []b.InstanceIdentity{source}, []b.RuntimeWriterSpec{spec}, nil)
	var observed productionPersistentMountScope
	if err != nil || json.Unmarshal(raw, &observed) != nil || len(observed.RunningTenantPro) != 1 || observed.RunningTenantPro[0] != mount {
		t.Fatalf("actual mount author projection = %s, %v", raw, err)
	}
	for _, action := range client.Actions() {
		if action.GetVerb() != "get" {
			t.Fatalf("read-only author performed %s", action.GetVerb())
		}
	}
	t.Run("exact source enters runtime controller", func(t *testing.T) {
		runtimeConfig := cfg
		runtimeConfig.RuntimeSources = &RuntimeSourceConfig{Namespaces: []string{cfg.Namespace}, Supported: []b.AgentKind{{Type: source.Type, Mode: source.Mode, Variant: source.Variant, OS: source.OS}}}
		service := &DeploymentService{Config: runtimeConfig, captureMaterials: &productionCaptureMaterials{Discovery: &productionSourceDiscovery{PersistentMounts: scope}}, Runtime: &PublicCapture{Owner: &PublicJobOwner{Client: client}}}
		inventory := b.SourceInventory{Instances: []b.InstanceIdentity{source}}
		if err := service.validateRuntimeInventory(inventory); err != nil {
			t.Fatalf("signed Pro source rejected at actual inventory entry: %v", err)
		}
		controls := c.RuntimeControlConfig{DeploymentChecks: map[string]c.ReadinessProbe{}}
		if err := service.attachTenantProRuntimeControls(&controls); err != nil || controls.TenantProSourceCheck == nil {
			t.Fatalf("actual controller source check not installed: %v", err)
		}
		if err := controls.TenantProSourceCheck(ctx, source); err != nil {
			t.Fatalf("actual source failed native recheck: %v", err)
		}
		if controls.DeploymentChecks[source.Namespace+"/"+deployment.Name] == nil {
			t.Fatal("original Pro Deployment has no reconciler probe")
		}
		for _, mutate := range []func(*b.InstanceIdentity){func(s *b.InstanceIdentity) { s.Generation++ }, func(s *b.InstanceIdentity) { s.ID++ }, func(s *b.InstanceIdentity) { s.Namespace = "other-user-1" }} {
			changed := source
			mutate(&changed)
			if controls.TenantProSourceCheck(ctx, changed) == nil || service.validateRuntimeInventory(b.SourceInventory{Instances: []b.InstanceIdentity{changed}}) == nil {
				t.Fatal("a changed source inherited another instance's control admission")
			}
		}
		service.captureMaterials = nil
		if service.validateRuntimeInventory(inventory) == nil {
			t.Fatal("unsigned tenant source accepted")
		}
	})
	t.Run("actual tenant census and original author mapping", func(t *testing.T) {
		dep := deployment.DeepCopy()
		replicas := int32(1)
		dep.Spec.Replicas = &replicas
		dep.Generation = 1
		dep.Status.ReadyReplicas, dep.Status.ObservedGeneration = 1, 1
		current := pod.DeepCopy()
		current.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
		current.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "runtime", Ready: true, ContainerID: "containerd://original", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}
		apiClient := fake.NewSimpleClientset(ns.DeepCopy(), current, rs.DeepCopy(), dep, claim.DeepCopy(), pv.DeepCopy(),
			&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node", UID: "node-uid", Labels: map[string]string{corev1.LabelOSStable: "linux"}}})
		apiClient.PrependReactor("list", "*", func(action ktesting.Action) (bool, runtime.Object, error) {
			resource := action.GetResource()
			kinds := map[string]string{"deployments": "Deployment", "replicasets": "ReplicaSet", "statefulsets": "StatefulSet", "daemonsets": "DaemonSet", "jobs": "Job", "cronjobs": "CronJob", "horizontalpodautoscalers": "HorizontalPodAutoscaler", "pods": "Pod", "persistentvolumeclaims": "PersistentVolumeClaim"}
			object, err := apiClient.Tracker().List(resource, schema.GroupVersionKind{Group: resource.Group, Version: resource.Version, Kind: kinds[resource.Resource]}, action.GetNamespace())
			if err != nil {
				return true, nil, err
			}
			accessor, err := meta.ListAccessor(object)
			if err == nil {
				accessor.SetResourceVersion("census-version")
			}
			return true, object, err
		})
		rows, err := observeTenantProWriterAPI(ctx, apiClient, cfg, []b.InstanceIdentity{source}, nil, func(ctx context.Context) error { return ctx.Err() })
		if err != nil || len(rows) != 6 {
			t.Fatalf("complete tenant source census failed: rows=%d, %v", len(rows), err)
		}
		api := &observedWriterAPI{objects: append(rows, observedWriterAPIObject{Kind: "Deployment", Namespace: cfg.Namespace, Name: "backup-controller", UID: "controller-uid"})}
		actual, err := observeTenantProMountFromCensus(ctx, apiClient, cfg, source, api)
		if err != nil || actual != mount {
			t.Fatalf("original author cannot join actual Pro census: %v", err)
		}
		native := bootstrapSourceNativeWriter{InstanceID: source.ID, UserID: source.UserID, Generation: source.Generation, Namespace: source.Namespace, Pod: source.Pod, PodUID: actual.PodUID, Deployment: actual.Deployment, DeploymentUID: actual.DeploymentUID, ReplicaSetUID: actual.ReplicaSetUID, State: "running", RunningTenantPro: &actual}
		mapped, err := originalMountNativeSpecs([]b.InstanceIdentity{source}, []bootstrapSourceNativeWriter{native})
		if err != nil || len(mapped) != 1 || mapped[0] != spec {
			t.Fatalf("actual native projection failed to reach mount author: %v", err)
		}
		graphConfig := cfg
		graphConfig.RuntimeSources = &RuntimeSourceConfig{Namespaces: []string{cfg.Namespace}}
		discovery := &productionSourceDiscovery{ControllerDeployment: "backup-controller", ControllerDeploymentUID: "controller-uid", PersistentMounts: scope}
		reader := &bootstrapSourceRegistryReader{config: graphConfig, materials: productionCaptureMaterials{Discovery: discovery}}
		inventory := b.SourceInventory{Instances: []b.InstanceIdentity{source}}
		service := &DeploymentService{Config: graphConfig, captureMaterials: &productionCaptureMaterials{Discovery: discovery}}
		if err := reader.checkWriterGraph(inventory, api); err != nil {
			t.Fatalf("original installation graph rejected joined tenant: %v", err)
		}
		if err := checkObservedWriterGraph(service, inventory, api); err != nil {
			t.Fatalf("production graph rejected signed tenant: %v", err)
		}
		unknown := *api
		unknown.objects = append(append([]observedWriterAPIObject{}, api.objects...), observedWriterAPIObject{Kind: "Deployment", Namespace: source.Namespace, Name: "unlisted-writer", UID: "unlisted-uid", Replicas: 1, Ready: 1})
		if reader.checkWriterGraph(inventory, &unknown) == nil || checkObservedWriterGraph(service, inventory, &unknown) == nil {
			t.Fatal("unknown tenant writer was omitted from stop coverage")
		}
		replaced := *api
		replaced.objects = append([]observedWriterAPIObject{}, api.objects...)
		for i := range replaced.objects {
			if replaced.objects[i].Kind == "Namespace" {
				replaced.objects[i].UID = "replacement-tenant-uid"
			}
		}
		if checkObservedWriterGraph(service, inventory, &replaced) == nil {
			t.Fatal("same-name tenant replacement inherited source authority")
		}
		for _, action := range apiClient.Actions() {
			if action.GetVerb() != "get" && action.GetVerb() != "list" {
				t.Fatalf("original source observation mutated cluster: %s", action.GetVerb())
			}
		}
	})
	t.Run("workspace at PVC root", func(t *testing.T) {
		rootSource := source
		rootSource.Workspace = "/srv/workspace"
		rootPod := pod.DeepCopy()
		rootPod.Spec.Containers[0].VolumeMounts[0].SubPath = ""
		rootClient := fake.NewSimpleClientset(ns.DeepCopy(), rootPod, rs.DeepCopy(), deployment.DeepCopy(), claim.DeepCopy(), pv.DeepCopy(),
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-system", UID: "system-uid"}},
			&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node", UID: "node-uid", Labels: map[string]string{corev1.LabelOSStable: "linux"}}})
		rootSpec := spec
		rootSpec.Source = rootSource
		raw, err := BuildOriginalInstanceMountScope(ctx, rootClient, cfg, []b.InstanceIdentity{rootSource}, []b.RuntimeWriterSpec{rootSpec}, nil)
		var scope productionPersistentMountScope
		if err != nil || json.Unmarshal(raw, &scope) != nil || len(scope.RunningTenantPro) != 1 || scope.RunningTenantPro[0].SubPath != "" {
			t.Fatalf("PVC-root workspace rejected: %s, %v", raw, err)
		}
		rootMount := scope.RunningTenantPro[0]
		if err := rootMount.check(ctx, rootClient, cfg.Namespace); err != nil {
			t.Fatalf("root evidence cannot be rechecked: %v", err)
		}
		rootPod.Spec.Containers[0].VolumeMounts[0].SubPathExpr = "$(POD_NAME)"
		if rootMount.matchesPodMount(rootPod) {
			t.Fatal("unresolved subPathExpr accepted for root workspace")
		}
	})
	changed := mount
	changed.SubPath = "other/user"
	if err := changed.check(ctx, client, "test-system"); err == nil {
		t.Fatal("different workspace subpath accepted")
	}
	if err := mount.check(ctx, client, "other-system"); err == nil {
		t.Fatal("other installation accepted the tenant mount")
	}
	claim.UID = "replacement-claim-uid"
	if _, err := client.CoreV1().PersistentVolumeClaims(source.Namespace).Update(ctx, claim, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := mount.check(ctx, client, "test-system"); err == nil {
		t.Fatal("same-name replacement claim accepted")
	}
}
