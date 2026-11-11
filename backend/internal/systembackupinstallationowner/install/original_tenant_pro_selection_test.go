package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/domain"
	c "clawreef/internal/systembackupcontroller"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func tenantSelectionFixture() (*OriginalWriterMaintenance, domain.SourceInstance, *fake.Clientset) {
	const namespace = "validation-user-1"
	labels := map[string]string{"app": "clawreef", "managed-by": "clawreef", "user-id": "1", "instance-id": "2"}
	controller, replicas := true, int32(1)
	ns := &core.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace, UID: "tenant-uid", Labels: labels}}
	dep := &apps.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "instance-2", Namespace: namespace, UID: "deployment-uid", Generation: 2, Labels: labels},
		Spec:   apps.DeploymentSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: labels}, Template: core.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}}},
		Status: apps.DeploymentStatus{ObservedGeneration: 2, ReadyReplicas: 1}}
	rs := &apps.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "instance-2-rs", Namespace: namespace, UID: "rs-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: dep.Name, UID: dep.UID, Controller: &controller}}},
		Spec: apps.ReplicaSetSpec{Template: core.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}}}}
	pod := &core.Pod{ObjectMeta: metav1.ObjectMeta{Name: "instance-2-rs-pod", Namespace: namespace, UID: "pod-uid", Labels: labels,
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &controller}}},
		Spec:   core.PodSpec{NodeName: "original-node", Containers: []core.Container{{Name: "runtime", Image: "registry.invalid/original@sha256:" + strings.Repeat("a", 64)}}},
		Status: core.PodStatus{Phase: core.PodRunning, ContainerStatuses: []core.ContainerStatus{{Name: "runtime", ContainerID: "containerd://actual", Ready: true, State: core.ContainerState{Running: &core.ContainerStateRunning{}}}}}}
	client := fake.NewSimpleClientset(ns, dep, rs, pod)
	installer := &Installer{kube: client}
	installer.plan.Target.Namespace = "validation-system"
	maintenance := &OriginalWriterMaintenance{operator: &authenticatedOperator{installer: installer}}
	source := domain.SourceInstance{ID: 2, UserID: 1, Generation: 0, Mode: "pro", Type: "openclaw", Backend: "desktop", OS: "linux", Status: "running", Namespace: namespace, Pod: pod.Name}
	return maintenance, source, client
}

func TestOriginalTenantProSelectionUsesActualControllerGraph(t *testing.T) {
	maintenance, source, _ := tenantSelectionFixture()
	identity, pod, dep, _, err := maintenance.readInitialTenantPro(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	record, err := originalTenantProCapture(source, identity, pod, dep)
	if err != nil || record.Identity.PodUID != "pod-uid" || record.Identity.DeploymentUID != "deployment-uid" || record.Source.Generation != 0 {
		t.Fatal("actual zero-generation tenant controller was not retained", err)
	}
	census := originalMaintenanceKubernetesCensus{Namespace: source.Namespace, NamespaceUID: "tenant-uid",
		Pods: []originalMaintenanceObjectPin{{Name: source.Pod, UID: "pod-uid"}}, Deployments: []originalMaintenanceObjectPin{{Name: dep.Name, UID: "deployment-uid"}}}
	if err := originalTenantProCensusMatches(census, []OriginalTenantProSelection{record}); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"extra-pod", "extra-deployment", "namespace-uid", "pod-uid", "controller-uid", "autoscaler", "duplicate-source"} {
		t.Run(kind, func(t *testing.T) {
			changed := census
			changed.Pods = append([]originalMaintenanceObjectPin(nil), census.Pods...)
			changed.Deployments = append([]originalMaintenanceObjectPin(nil), census.Deployments...)
			records := []OriginalTenantProSelection{record}
			switch kind {
			case "extra-pod":
				changed.Pods = append(changed.Pods, originalMaintenanceObjectPin{Name: "other", UID: "other"})
			case "extra-deployment":
				changed.Deployments = append(changed.Deployments, originalMaintenanceObjectPin{Name: "other", UID: "other"})
			case "namespace-uid":
				changed.NamespaceUID = "other"
			case "pod-uid":
				changed.Pods[0].UID = "other"
			case "controller-uid":
				changed.Deployments[0].UID = "other"
			case "autoscaler":
				changed.Autoscalers = []originalMaintenanceObjectPin{{Name: "hpa", UID: "hpa-uid"}}
			case "duplicate-source":
				records = append(records, record)
			}
			if originalTenantProCensusMatches(changed, records) == nil {
				t.Fatal("unaccounted controller/source was omitted")
			}
		})
	}
}

func TestOriginalTenantProSelectionRefusesChangedAPIOwner(t *testing.T) {
	maintenance, source, client := tenantSelectionFixture()
	pod, _ := client.CoreV1().Pods(source.Namespace).Get(context.Background(), source.Pod, metav1.GetOptions{})
	pod.OwnerReferences[0].UID = types.UID("replacement-rs")
	if _, err := client.CoreV1().Pods(source.Namespace).Update(context.Background(), pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := maintenance.readInitialTenantPro(context.Background(), source); err == nil {
		t.Fatal("a named but unrelated controller was accepted")
	}
}

func TestOriginalSelectionPhaseRetainsCauseWithoutRawError(t *testing.T) {
	cause := errors.New("mysql://private:RAW_SECRET@host")
	err := originalSelectionStageFailure("first_collection", originalSelectionStageFailure("observer_materials", cause))
	var phase OriginalWriterSelectionFailure
	if !errors.As(err, &phase) || phase.Stage != "first_collection/observer_materials" || !errors.Is(err, cause) || strings.Contains(err.Error(), "RAW_SECRET") {
		t.Fatal("bounded phase or private cause handling changed")
	}
	if originalSelectionStageFailure("unused", nil) != nil {
		t.Fatal("successful author was changed into a failure")
	}
}

func TestOriginalTenantProSelectionDataCannotMintNativeWriter(t *testing.T) {
	selection := OriginalWriterSetSelection{Version: OriginalWriterSetSelectionVersion,
		Policy:    c.GatePolicy{LockTTL: 900 * time.Second, AcquisitionTimeout: 60 * time.Second, MaxHold: 600 * time.Second},
		TenantPro: []OriginalTenantProSelection{{Source: domain.SourceInstance{ID: 2}}}}
	raw, err := canonical(selection)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "tenant-selection.json")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	writer, err := (&Installer{}).PrepareOriginalWriterSet(context.Background(), nil, EnrollmentPin{}, BootstrapSourceFilePin{File: file, SHA256: hash(raw)})
	var failure OriginalWriterSourceFailure
	if writer != nil || !errors.As(err, &failure) || failure.Dependency != "tenant_pro_original_native_stop_recovery_owner_required" {
		t.Fatal("coordinate data entered the original native writer factory", err)
	}
}
