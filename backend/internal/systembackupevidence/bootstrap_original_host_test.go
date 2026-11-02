package systembackupevidence

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func originalHostNativeFixture(t *testing.T) (*fake.Clientset, BootstrapOriginalHostInput, string) {
	t.Helper()
	authenticator, _, peer := systemPeerFixture(t)
	raw, err := json.Marshal(peer)
	if err != nil {
		t.Fatal(err)
	}
	i := BootstrapOriginalHostInput{Scope: peer.Scope, ClusterUID: "original-cluster-uid", Namespace: "original-source", NamespaceUID: "original-namespace-uid", Pod: "original-service", PodUID: "original-pod-uid", ServiceAccount: "original-service", ServiceAccountUID: "original-service-account-uid", Container: "service", ContainerImageID: "docker-pullable://original.invalid/service@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Volume: "original-peer", PeerPath: "/run/original-peer/peer.json", PeerConfigMap: "original-peer", PeerConfigMapUID: "original-peer-cm-uid", PeerKey: "peer.json", PeerSHA256: hash(raw)}
	yes := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: i.Pod, Namespace: i.Namespace, UID: types.UID(i.PodUID), ResourceVersion: "1"}, Spec: corev1.PodSpec{ServiceAccountName: i.ServiceAccount, Containers: []corev1.Container{{Name: i.Container, Image: "original.invalid/service@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", VolumeMounts: []corev1.VolumeMount{{Name: i.Volume, MountPath: "/run/original-peer", ReadOnly: true}}}}, Volumes: []corev1.Volume{{Name: i.Volume, VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: i.PeerConfigMap}}}}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: i.Container, ImageID: i.ContainerImageID, ContainerID: "containerd://original-service", Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(time.Now().Add(-time.Minute))}}}}}}
	spec, err := json.Marshal(pod.Spec)
	if err != nil {
		t.Fatal(err)
	}
	i.PodSpecSHA256 = hash(spec)
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: i.PeerConfigMap, Namespace: i.Namespace, UID: types.UID(i.PeerConfigMapUID), ResourceVersion: "1"}, Immutable: &yes, Data: map[string]string{i.PeerKey: string(raw)}}
	client := fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID(i.ClusterUID)}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: i.Namespace, UID: types.UID(i.NamespaceUID)}}, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: i.ServiceAccount, Namespace: i.Namespace, UID: types.UID(i.ServiceAccountUID)}}, pod, cm)
	return client, i, authenticator.workload
}

func TestBootstrapOriginalHostNativeProjectionUsesProductionPeerIdentity(t *testing.T) {
	client, input, workload := originalHostNativeFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	observed, err := ObserveBootstrapOriginalHost(ctx, client, input)
	if err != nil || observed.Input != input || observed.WorkloadIdentitySHA256 != workload || observed.PodSpecSHA256 != input.PodSpecSHA256 || !digestPattern.MatchString(observed.SourceSHA256) || !observed.Until.After(observed.ObservedAt) || observed.Until.Sub(observed.ObservedAt) > 15*time.Second {
		t.Fatal("actual original projection/production identity", err)
	}
	for _, action := range client.Actions() {
		if action.GetVerb() != "get" {
			t.Fatal("host observer mutated a native source")
		}
	}
}

func TestBootstrapOriginalHostRejectsUnboundSourceAndTailDrift(t *testing.T) {
	for _, fault := range []string{"source-pin", "scope", "pod-spec", "image", "config-uid", "mutable", "writable", "subpath", "shadow", "tail", "unbounded"} {
		t.Run(fault, func(t *testing.T) {
			client, input, _ := originalHostNativeFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			cmObject, err := client.Tracker().Get(corev1.SchemeGroupVersion.WithResource("configmaps"), input.Namespace, input.PeerConfigMap)
			if err != nil {
				t.Fatal(err)
			}
			cm := cmObject.(*corev1.ConfigMap).DeepCopy()
			podObject, err := client.Tracker().Get(corev1.SchemeGroupVersion.WithResource("pods"), input.Namespace, input.Pod)
			if err != nil {
				t.Fatal(err)
			}
			pod := podObject.(*corev1.Pod).DeepCopy()
			switch fault {
			case "source-pin":
				input.PeerSHA256 = hash([]byte("foreign config"))
			case "scope":
				input.Scope.Database = "another-database"
			case "pod-spec":
				input.PodSpecSHA256 = hash([]byte("foreign spec"))
			case "image":
				input.ContainerImageID = "foreign-image"
			case "config-uid":
				input.PeerConfigMapUID = "foreign-cm-uid"
			case "mutable":
				no := false
				cm.Immutable = &no
			case "writable":
				pod.Spec.Containers[0].VolumeMounts[0].ReadOnly = false
			case "subpath":
				pod.Spec.Containers[0].VolumeMounts[0].SubPath = "peer.json"
			case "shadow":
				pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "foreign", MountPath: input.PeerPath})
			case "tail":
				reads := 0
				client.PrependReactor("get", "configmaps", func(ktesting.Action) (bool, runtime.Object, error) {
					reads++
					actual := cm.DeepCopy()
					if reads > 1 {
						actual.ResourceVersion = "2"
					}
					return true, actual, nil
				})
			case "unbounded":
				ctx = context.Background()
			}
			if fault == "writable" || fault == "subpath" || fault == "shadow" {
				spec, err := json.Marshal(pod.Spec)
				if err != nil {
					t.Fatal(err)
				}
				input.PodSpecSHA256 = hash(spec)
			}
			if err := client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("configmaps"), cm, input.Namespace); err != nil {
				t.Fatal(err)
			}
			if err := client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("pods"), pod, input.Namespace); err != nil {
				t.Fatal(err)
			}
			if _, err := ObserveBootstrapOriginalHost(ctx, client, input); err == nil {
				t.Fatal("unbound source or changed native tail accepted")
			}
		})
	}
}
