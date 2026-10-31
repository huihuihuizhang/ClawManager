package systembackupexecution

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"clawreef/internal/systembackup/kube"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
	ktest "k8s.io/client-go/testing"
)

// A finite API/kubelet protocol model for the original named local sources.
// Source ACKs enter the ORIGINAL KubeletStopWitness watch/SQL store; no direct
// stop-proof INSERT or success callback is supplied. This is not a real node.
func (f *dOriginalSixPartTask) installOriginalKubeLifecycle(ctx context.Context, t *testing.T) {
	t.Helper()
	client := f.owner.Client.(*kubefake.Clientset)
	ns := f.service.Config.Namespace
	for _, object := range []runtime.Object{
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: f.owner.Security.ServiceAccountName, Namespace: ns, UID: types.UID(f.owner.Security.ServiceAccountUID)}},
		&corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "staging", Namespace: ns, UID: "stage-uid"}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "stage-pv"}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}},
		&corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "stage-pv", UID: "stage-pv-uid"}, Spec: corev1.PersistentVolumeSpec{ClaimRef: &corev1.ObjectReference{Name: "staging", Namespace: ns, UID: "stage-uid"}}},
	} {
		if err := client.Tracker().Add(object); err != nil {
			t.Fatal("original worker storage/service-account fixture", err)
		}
	}
	pods := corev1.SchemeGroupVersion.WithResource("pods")
	deployments := appsv1.SchemeGroupVersion.WithResource("deployments")
	platform, err := client.CoreV1().Pods(ns).Get(ctx, "d-platform-pod", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	nextRV := func(old string) string { value, _ := strconv.Atoi(old); return strconv.Itoa(value + 1) }
	terminate := func(name string, expected types.UID) error {
		object, err := client.Tracker().Get(pods, ns, name)
		if err != nil {
			return err
		}
		pod := object.(*corev1.Pod).DeepCopy()
		if pod.UID != expected || pod.Spec.NodeName != "node" {
			return fmt.Errorf("original source process identity changed")
		}
		pod.ResourceVersion = nextRV(pod.ResourceVersion)
		pod.Status.Phase = corev1.PodSucceeded
		for index, status := range pod.Status.ContainerStatuses {
			if status.ContainerID == "" || status.State.Running == nil {
				return fmt.Errorf("original source lacked running container")
			}
			status.Ready = false
			status.State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ContainerID: status.ContainerID, StartedAt: status.State.Running.StartedAt, FinishedAt: metav1.Now(), ExitCode: 0}}
			pod.Status.ContainerStatuses[index] = status
		}
		if err := client.Tracker().Update(pods, pod, ns); err != nil {
			return err
		}
		return client.Tracker().Delete(pods, ns, name)
	}
	client.PrependReactor("delete", "pods", func(action ktest.Action) (bool, runtime.Object, error) {
		request := action.(ktest.DeleteAction)
		if request.GetNamespace() != ns || request.GetName() != "d-original-7" {
			return false, nil, nil
		}
		object, err := client.Tracker().Get(pods, ns, request.GetName())
		if err != nil {
			return true, nil, err
		}
		pod := object.(*corev1.Pod)
		options := request.GetDeleteOptions()
		if options.Preconditions == nil || options.Preconditions.UID == nil || options.Preconditions.ResourceVersion == nil || *options.Preconditions.UID != pod.UID || *options.Preconditions.ResourceVersion != pod.ResourceVersion {
			return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "pods"}, pod.Name, fmt.Errorf("original UID/resourceVersion precondition"))
		}
		return true, nil, terminate(pod.Name, pod.UID)
	})
	client.PrependReactor("get", "deployments", func(action ktest.Action) (bool, runtime.Object, error) {
		request := action.(ktest.GetAction)
		if request.GetNamespace() != ns || request.GetName() != "source" {
			return false, nil, nil
		}
		object, err := client.Tracker().Get(deployments, ns, "source")
		if err != nil {
			return true, nil, err
		}
		deployment := object.(*appsv1.Deployment).DeepCopy()
		if deployment.UID != "dep-uid" || deployment.Spec.Replicas == nil {
			return true, nil, fmt.Errorf("original platform deployment changed")
		}
		if deployment.Status.Replicas != *deployment.Spec.Replicas {
			if *deployment.Spec.Replicas == 0 {
				if err := terminate(platform.Name, platform.UID); err != nil {
					return true, nil, err
				}
			} else if *deployment.Spec.Replicas == 1 {
				if err := f.checkOriginalStoppedBeforePhysicalResume(ctx); err != nil {
					return true, nil, err
				}
				resumed := platform.DeepCopy()
				resumed.UID = "d-platform-resumed-uid"
				resumed.ResourceVersion = "3"
				resumed.Status.ContainerStatuses[0].ContainerID = "containerd://d-platform-resumed"
				resumed.Status.ContainerStatuses[0].State.Running.StartedAt = metav1.Now()
				if err := client.Tracker().Create(pods, resumed, ns); err != nil {
					return true, nil, err
				}
			} else {
				return true, nil, fmt.Errorf("unsupported original platform replicas")
			}
			deployment.Generation++
			deployment.ResourceVersion = nextRV(deployment.ResourceVersion)
			deployment.Status.ObservedGeneration = deployment.Generation
			deployment.Status.Replicas = *deployment.Spec.Replicas
			deployment.Status.ReadyReplicas = *deployment.Spec.Replicas
			if err := client.Tracker().Update(deployments, deployment, ns); err != nil {
				return true, nil, err
			}
		}
		return true, deployment, nil
	})
	client.PrependReactor("create", "pods", func(action ktest.Action) (bool, runtime.Object, error) {
		request := action.(ktest.CreateAction)
		pod := request.GetObject().(*corev1.Pod).DeepCopy()
		if pod.Namespace != ns || pod.Name != "d-original-7" {
			return false, nil, nil
		}
		if pod.UID != "" || pod.ResourceVersion != "" || pod.Annotations["backup.clawmanager.io/source-resume-fence"] == "" || len(pod.OwnerReferences) != 0 {
			return true, nil, fmt.Errorf("original Pro restart request changed")
		}
		if err := f.checkOriginalStoppedBeforePhysicalResume(ctx); err != nil {
			return true, nil, err
		}
		pod.UID = "d-original-7-resumed-uid"
		pod.ResourceVersion = "3"
		pod.Status = corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: pod.Spec.Containers[0].Name, ContainerID: "containerd://d-original-7-resumed", Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(time.Now().UTC())}}}}}
		if err := client.Tracker().Create(pods, pod, ns); err != nil {
			return true, nil, err
		}
		return true, pod, nil
	})
	for _, resource := range []string{"configmaps", "secrets"} {
		resource := resource
		client.PrependReactor("create", resource, func(action ktest.Action) (bool, runtime.Object, error) {
			object := action.(ktest.CreateAction).GetObject().DeepCopyObject()
			metadata := object.(metav1.Object)
			if metadata.GetNamespace() != ns || metadata.GetLabels()[kube.OwnerLabel] != f.publicID {
				return false, nil, nil
			}
			if metadata.GetUID() != "" || metadata.GetResourceVersion() != "" {
				return true, nil, fmt.Errorf("original task create request supplied API identity")
			}
			metadata.SetUID(types.UID("original-" + hash([]byte(resource + "/" + metadata.GetName()))[:32]))
			metadata.SetResourceVersion("1")
			if err := client.Tracker().Create(corev1.SchemeGroupVersion.WithResource(resource), object, ns); err != nil {
				return true, nil, err
			}
			return true, object, nil
		})
	}
}
