package systembackupexecution

import (
	"context"
	"testing"

	d "clawreef/internal/systembackupdispatch"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// API protocol observations only. A passing workload comparison is not an
// authority constructor, a deployment approval, or physical source evidence.
func TestSourceObservationSharesOriginalControllerWorkloadChecks(t *testing.T) {
	for _, fault := range []string{"original", "namespace", "pod", "pod-service-account", "replicaset", "deployment", "controller-sa", "source-sa"} {
		t.Run(fault, func(t *testing.T) {
			controller := true
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "original", UID: "original-ns"}}
			dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "controller", Namespace: ns.Name, UID: "original-dep"}, Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: "controller"}}}}
			rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "controller-rs", Namespace: ns.Name, UID: "original-rs", OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: dep.Name, UID: dep.UID, Controller: &controller}}}}
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "controller-pod", Namespace: ns.Name, UID: "original-pod", OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &controller}}}, Spec: corev1.PodSpec{ServiceAccountName: "controller"}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
			controllerSA := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "controller", Namespace: ns.Name, UID: "original-controller-sa"}}
			sourceSA := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "metadata", Namespace: ns.Name, UID: "original-source-sa"}}
			discovery := &productionSourceDiscovery{ControllerDeployment: dep.Name, ControllerDeploymentUID: string(dep.UID), ControllerServiceAccount: controllerSA.Name, ControllerServiceAccountUID: string(controllerSA.UID), SourceAPIServiceAccount: sourceSA.Name, SourceAPIServiceAccountUID: string(sourceSA.UID)}
			s := &DeploymentService{Config: DeploymentConfig{Namespace: ns.Name, NamespaceUID: string(ns.UID)}, captureMaterials: &productionCaptureMaterials{Discovery: discovery}, controllerActor: controllerObservedActor{PodName: pod.Name, PodUID: string(pod.UID), ServiceAccountName: controllerSA.Name}}
			switch fault {
			case "namespace":
				ns.UID = "replacement"
			case "pod":
				pod.UID = "replacement"
			case "pod-service-account":
				pod.Spec.ServiceAccountName = "replacement"
			case "replicaset":
				rs.UID = "replacement"
			case "deployment":
				dep.UID = "replacement"
			case "controller-sa":
				controllerSA.UID = "replacement"
			case "source-sa":
				sourceSA.UID = "replacement"
			}
			owner := &PublicJobOwner{Client: fake.NewSimpleClientset(ns, dep, rs, pod, controllerSA, sourceSA)}
			binding := &sourceMetadataDelegation{service: s, owner: owner}
			if (binding.checkWorkload(context.Background()) == nil) != (fault == "original") {
				t.Fatal("original workload comparison accepted replacement or refused original")
			}
		})
	}
}

func TestSourceObservationDoesNotCreateTasklessCaptureAuthority(t *testing.T) {
	s := &DeploymentService{}
	if _, err := s.sourceMetadataAuthority(context.Background(), &PublicJobOwner{}, d.Input{}); err == nil {
		t.Fatal("empty capture task accepted")
	}
	if (&originalSourceMetadataAuthority{}).Recheck(context.Background()) == nil {
		t.Fatal("empty capture authority bypassed original gate")
	}
	if _, err := s.newSourceSQLObservation(context.Background()); err == nil {
		t.Fatal("unbound deployment manufactured SQL observation")
	}
	if (&sourceSQLObservation{}).recheck(context.Background()) == nil {
		t.Fatal("empty observer manufactured authority")
	}
}
