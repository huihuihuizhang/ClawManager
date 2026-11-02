package systembackupexecution

import (
	"context"
	"errors"
	"testing"
	"time"

	b "clawreef/internal/systembackup/publicadapter"
	c "clawreef/internal/systembackupcontroller"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Pure graph projections only, not source authorization or native evidence.
func sourceWriterGraphFixture() (*DeploymentService, *observedWriterAPI) {
	controller := true
	s := &DeploymentService{Config: DeploymentConfig{Namespace: "source", Writers: []PlatformDeployment{{Namespace: "source", Name: "writer", UID: "writer-uid"}}, RuntimeSources: &RuntimeSourceConfig{}}, captureMaterials: &productionCaptureMaterials{Discovery: &productionSourceDiscovery{ControllerDeployment: "controller", ControllerDeploymentUID: "controller-uid"}}}
	api := &observedWriterAPI{objects: []observedWriterAPIObject{
		{Kind: "Deployment", Namespace: "source", Name: "controller", UID: "controller-uid"},
		{Kind: "Deployment", Namespace: "source", Name: "writer", UID: "writer-uid", Generation: 4, ObservedGeneration: 4, Replicas: 1, Ready: 1},
		{Kind: "ReplicaSet", Namespace: "source", Name: "writer-rs", UID: "rs-uid", Owners: []metav1.OwnerReference{{Kind: "Deployment", Name: "writer", UID: "writer-uid", Controller: &controller}}},
		{Kind: "Pod", Namespace: "source", Name: "writer-pod", UID: "pod-uid", Running: true, Owners: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "writer-rs", UID: "rs-uid", Controller: &controller}}},
	}}
	return s, api
}

func TestSourceWriterGraphRequiresCompletePinnedControllerClosure(t *testing.T) {
	for _, fault := range []string{"original", "unknown-deployment", "statefulset", "daemonset", "job", "cronjob", "hpa", "dangling-owner", "foreign-owner-uid", "missing-pod", "pod-not-running", "missing-claim", "extra-pod", "writer-zero", "generation-drift", "duplicate"} {
		t.Run(fault, func(t *testing.T) {
			s, api := sourceWriterGraphFixture()
			switch fault {
			case "unknown-deployment":
				api.objects = append(api.objects, observedWriterAPIObject{Kind: "Deployment", Namespace: "source", Name: "unknown", UID: "unknown-uid"})
			case "statefulset", "daemonset", "job", "cronjob", "hpa":
				kind := map[string]string{"statefulset": "StatefulSet", "daemonset": "DaemonSet", "job": "Job", "cronjob": "CronJob", "hpa": "HorizontalPodAutoscaler"}[fault]
				api.objects = append(api.objects, observedWriterAPIObject{Kind: kind, Namespace: "source", Name: "unknown", UID: "unknown-uid"})
			case "dangling-owner":
				api.objects[3].Owners[0].Name = "foreign"
			case "foreign-owner-uid":
				api.objects[3].Owners[0].UID = "replacement"
			case "missing-pod":
				api.objects = api.objects[:3]
			case "pod-not-running":
				api.objects[3].Running = false
			case "missing-claim":
				api.objects[3].Claims = []string{"foreign"}
			case "extra-pod":
				api.objects = append(api.objects, observedWriterAPIObject{Kind: "Pod", Namespace: "source", Name: "unknown", UID: "unknown-uid", Running: true})
			case "writer-zero":
				api.objects[1].Replicas = 0
			case "generation-drift":
				api.objects[1].ObservedGeneration = 3
			case "duplicate":
				api.objects = append(api.objects, api.objects[3])
			}
			err := checkObservedWriterGraph(s, b.SourceInventory{}, api)
			if (err == nil) != (fault == "original") {
				t.Fatal("complete actual graph was narrowed or rejected", err)
			}
			if fault == "writer-zero" && !errors.Is(err, c.ErrSourceRecoveryStoppedWitnessRequired) {
				t.Fatal("zero replicas silently treated as positive stopped proof", err)
			}
		})
	}
}

func TestSourceWriterObservationDoesNotInferPhysicalStoppedFromSQL(t *testing.T) {
	for _, state := range []string{"running", "stopped", "unknown"} {
		err := requireRunningSourceMetadata(b.SourceInventory{Instances: []b.InstanceIdentity{{ID: 9, Status: state}}})
		if (err == nil) != (state == "running") || state == "stopped" && !errors.Is(err, c.ErrSourceRecoveryStoppedWitnessRequired) {
			t.Fatal("SQL state became a native physical proof", state, err)
		}
	}
	// A successfully observed empty set requires no invented stopped observer;
	// the actual constructor still has to prove complete source and API EOF.
	if requireRunningSourceMetadata(b.SourceInventory{Instances: []b.InstanceIdentity{}}) != nil {
		t.Fatal("global future-observer gate added")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if facts, err := (*DeploymentService)(nil).ObserveSourceDependencies(ctx); err == nil || facts.WriterSHA256() != "" {
		t.Fatal("nil service manufactured current writer facts")
	}
}

func TestSourceWriterAPIProjectionRetainsActualProcessIdentity(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "source", Namespace: "source", UID: "original-pod"}, Spec: corev1.PodSpec{NodeName: "node"}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: "writer", Ready: true, ContainerID: "containerd://original", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}
	original, err := projectWriterAPIObject("Pod", pod)
	if err != nil || !original.Running || len(original.Processes) != 1 {
		t.Fatal("actual running process omitted", err)
	}
	pod.Status.ContainerStatuses[0].ContainerID = "containerd://replacement"
	changed, err := projectWriterAPIObject("Pod", pod)
	if err != nil || original.Processes[0] == changed.Processes[0] {
		t.Fatal("same Pod UID concealed process replacement", err)
	}
	pod.Status.ContainerStatuses[0].State.Running = nil
	changed, err = projectWriterAPIObject("Pod", pod)
	if err != nil || changed.Running {
		t.Fatal("non-running container treated as a live writer", err)
	}
}
