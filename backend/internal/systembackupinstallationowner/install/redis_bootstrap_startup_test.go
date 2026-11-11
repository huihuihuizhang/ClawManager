package install

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestOriginalRedisEffectiveServerArgsPreservesSelectedStartup(t *testing.T) {
	for _, c := range []core.Container{
		{Command: []string{"redis-server"}, Args: []string{"--appendonly", "yes"}},
		{Args: []string{"redis-server", "--appendonly", "yes"}},
		{Args: []string{"redis-server", "--appendonly", "yes", "--tls-port", "6380"}},
	} {
		before := c.DeepCopy()
		args, err := originalRedisEffectiveServerArgs(&c)
		if err != nil || len(args) < 2 || !reflect.DeepEqual(args[:2], []string{"--appendonly", "yes"}) || !reflect.DeepEqual(before, &c) {
			t.Fatal("real original startup rejected or mutated", err)
		}
	}
	for _, c := range []*core.Container{nil, {}, {Command: []string{"sh", "-c"}, Args: []string{"redis-server --appendonly yes"}},
		{Command: []string{"/data/redis-server"}}, {Args: []string{"/data/start.sh"}}, {Args: []string{"--appendonly", "yes"}}} {
		if _, err := originalRedisEffectiveServerArgs(c); err == nil {
			t.Fatal("unclassified startup borrowed original Redis image identity")
		}
	}
}

func TestOriginalRedisNativePodPinsDefaultEntryAndActualMembership(t *testing.T) {
	for _, mode := range []string{"default-entry", "explicit-entry", "other-image", "changed-pod-args", "changed-owner", "sidecar"} {
		t.Run(mode, func(t *testing.T) {
			replicas, controller := int32(1), true
			container := core.Container{Name: "redis", Image: originalPeerRedisImage, Args: []string{"redis-server", "--appendonly", "yes"}}
			if mode == "explicit-entry" {
				container.Command, container.Args = []string{"redis-server"}, []string{"--appendonly", "yes"}
			}
			dep := &apps.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "redis", Namespace: "validation-system", UID: "dep-uid", ResourceVersion: "7", Generation: 1},
				Spec: apps.DeploymentSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "redis"}},
					Template: core.PodTemplateSpec{Spec: core.PodSpec{Containers: []core.Container{container}}}}, Status: apps.DeploymentStatus{ObservedGeneration: 1, ReadyReplicas: 1}}
			rs := &apps.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "redis-rs", Namespace: dep.Namespace, UID: "rs-uid",
				OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: dep.Name, UID: dep.UID, Controller: &controller}}}}
			pod := &core.Pod{ObjectMeta: metav1.ObjectMeta{Name: "redis-pod", Namespace: dep.Namespace, UID: "pod-uid", Labels: map[string]string{"app": "redis"},
				OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &controller}}}, Spec: *dep.Spec.Template.Spec.DeepCopy(),
				Status: core.PodStatus{Phase: core.PodRunning, PodIP: "10.0.0.12", ContainerStatuses: []core.ContainerStatus{{Name: "redis", ImageID: originalPeerRedisImage,
					ContainerID: "containerd://original", Ready: true, State: core.ContainerState{Running: &core.ContainerStateRunning{}}}}}}
			switch mode {
			case "other-image":
				pod.Status.ContainerStatuses[0].ImageID = "unqualified@sha256:other"
			case "changed-pod-args":
				pod.Spec.Containers[0].Args = []string{"redis-server", "--appendonly", "no"}
			case "changed-owner":
				pod.OwnerReferences[0].UID = "different-rs"
			case "sidecar":
				pod.Spec.Containers = append(pod.Spec.Containers, core.Container{Name: "extra"})
			}
			i := &Installer{kube: fake.NewSimpleClientset(dep, rs, pod)}
			i.plan.Target.Namespace = dep.Namespace
			_, _, err := i.redisNativePod(context.Background(), dep.Name, string(dep.UID))
			accepted := mode == "default-entry" || mode == "explicit-entry"
			if (err == nil) != accepted {
				t.Fatal("actual native membership/startup classification changed", err)
			}
		})
	}
}

func TestOriginalRedisMaterialFailureRedactsCauseAndRetainsIdentity(t *testing.T) {
	private := errors.New("mysql://admin:RAW_PRIVATE_SECRET@source")
	err := OriginalRedisMaterialFailure{phase: "original_redis_pod", cause: private}
	if !errors.Is(err, private) || err.Phase() != "original_redis_pod" || strings.Contains(err.Error(), "RAW_PRIVATE_SECRET") {
		t.Fatal("phase exposed credentials or discarded the original failure")
	}
	_, failure := (&Installer{}).ProduceOriginalRedisNativeMaterials(nil, nil, EnrollmentPin{}, BootstrapSourceFilePin{}, BootstrapSourceFilePin{}, RedisNativeMaterialOptions{})
	var actual OriginalRedisMaterialFailure
	if !errors.As(failure, &actual) || actual.Phase() != "input_validation" {
		t.Fatal("real material owner discarded refusal phase", failure)
	}
}
