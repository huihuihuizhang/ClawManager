package systembackupexecution

import (
	"clawreef/internal/systembackupinstallationowner/install"
	"context"
	"encoding/json"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	kt "k8s.io/client-go/testing"
	"strings"
	"testing"
)

// Kubernetes protocol projection, not a real running business writer proof.
func TestTeamWriterBuildRequiresOriginalImmutableImageAndPod(t *testing.T) {
	for _, mode := range []string{"app-different-from-worker", "worker-only-change", "manifest-id", "config-id", "tag", "wrong-spec", "wrong-pod-spec", "wrong-content", "wrong-uid", "wrong-rs", "wrong-parent", "missing-pins", "missing-writer", "extra-pin", "duplicate-pin", "sidecar-unpinned", "sidecar-distinct-release", "init-distinct-release", "duplicate-status", "zero-without-original", "original-pause", "pause-drift", "build-drift", "pause-template-drift", "two-writers-distinct-release"} {
		t.Run(mode, func(t *testing.T) {
			image := "original/app@sha256:" + strings.Repeat("a", 64)
			pin := productionTeamWriterImage{Container: "app", Image: image, ConfigDigest: "sha256:" + strings.Repeat("c", 64), BuildCommit: strings.Repeat("1", 40)}
			cfg := DeploymentConfig{Namespace: "source", WorkerImage: "original/backup-worker@sha256:" + strings.Repeat("b", 64), Writers: []PlatformDeployment{{Namespace: "source", Name: "app", UID: "deployment-uid"}}}
			m := productionCaptureMaterials{Discovery: &productionSourceDiscovery{TeamPlatformUnits: map[string][]string{"deployment/source/app": {"team.workspace_http"}}, TeamWriterImages: map[string][]productionTeamWriterImage{"deployment/source/app": {pin}}}}
			controller := true
			replicas := int32(1)
			deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "source", UID: types.UID("deployment-uid")}, Spec: appsv1.DeploymentSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "source"}}, Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: image}}}}}}
			rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "app-rs", Namespace: "source", UID: types.UID("rs-uid"), OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "app", UID: deployment.UID, Controller: &controller}}}}
			pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app-pod", Namespace: "source", UID: types.UID("pod-uid"), Labels: map[string]string{"app": "source"}, OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "app-rs", UID: rs.UID, Controller: &controller}}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: image}}}, Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "app", ImageID: "containerd://sha256:" + strings.Repeat("a", 64)}}}}
			var saved *productionTeamZeroCensus
			switch mode {
			case "worker-only-change":
				cfg.WorkerImage = "original/backup-worker:other"
			case "manifest-id":
				pod.Status.ContainerStatuses[0].ImageID = image
			case "config-id":
				pod.Status.ContainerStatuses[0].ImageID = "docker://" + pin.ConfigDigest
			case "tag":
				m.Discovery.TeamWriterImages["deployment/source/app"][0].Image = "original/app:mutable"
			case "wrong-spec":
				deployment.Spec.Template.Spec.Containers[0].Image = cfg.WorkerImage
			case "wrong-pod-spec":
				pod.Spec.Containers[0].Image = cfg.WorkerImage
			case "wrong-content":
				pod.Status.ContainerStatuses[0].ImageID = "containerd://sha256:" + strings.Repeat("b", 64)
			case "wrong-uid":
				deployment.UID = "foreign-deployment"
			case "wrong-rs":
				pod.OwnerReferences[0].UID = "foreign-rs"
			case "wrong-parent":
				rs.OwnerReferences[0].UID = "foreign-parent"
			case "missing-pins":
				m.Discovery.TeamWriterImages = nil
			case "missing-writer":
				cfg.Writers = nil
			case "extra-pin":
				m.Discovery.TeamWriterImages["deployment/source/missing"] = []productionTeamWriterImage{pin}
			case "duplicate-pin":
				m.Discovery.TeamWriterImages["deployment/source/app"] = []productionTeamWriterImage{pin, pin}
			case "sidecar-unpinned":
				deployment.Spec.Template.Spec.Containers = append(deployment.Spec.Template.Spec.Containers, corev1.Container{Name: "sidecar", Image: image})
			case "sidecar-distinct-release", "init-distinct-release":
				other := productionTeamWriterImage{Container: "sidecar", Image: "original/sidecar@sha256:" + strings.Repeat("d", 64), ConfigDigest: "sha256:" + strings.Repeat("e", 64), BuildCommit: strings.Repeat("2", 40)}
				m.Discovery.TeamWriterImages["deployment/source/app"] = append(m.Discovery.TeamWriterImages["deployment/source/app"], other)
				container := corev1.Container{Name: other.Container, Image: other.Image}
				status := corev1.ContainerStatus{Name: other.Container, ImageID: "containerd://" + other.ConfigDigest}
				if mode == "init-distinct-release" {
					deployment.Spec.Template.Spec.InitContainers = []corev1.Container{container}
					pod.Spec.InitContainers = []corev1.Container{container}
					pod.Status.InitContainerStatuses = []corev1.ContainerStatus{status}
				} else {
					deployment.Spec.Template.Spec.Containers = append(deployment.Spec.Template.Spec.Containers, container)
					pod.Spec.Containers = append(pod.Spec.Containers, container)
					pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, status)
				}
			case "duplicate-status":
				pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, pod.Status.ContainerStatuses[0])
			case "zero-without-original", "original-pause", "pause-drift", "build-drift", "pause-template-drift":
				replicas = 0
			}
			if mode == "original-pause" || mode == "pause-drift" || mode == "build-drift" || mode == "pause-template-drift" {
				templateRaw, e := json.Marshal(deployment.Spec.Template)
				if e != nil {
					t.Fatal(e)
				}
				saved = &productionTeamZeroCensus{Writers: []productionTeamWriterBuild{{Deployment: "deployment/source/app", DeploymentUID: "deployment-uid", Container: "app", Kind: "container", Image: image, ConfigDigest: pin.ConfigDigest, BuildCommit: pin.BuildCommit, TemplateSHA256: hash(templateRaw), Pods: []productionTeamWriterPod{{UID: "pod-uid", ImageID: pod.Status.ContainerStatuses[0].ImageID}}}}}
				if mode == "pause-template-drift" {
					deployment.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "DRIFT", Value: "changed"}}
				}
				if mode == "pause-drift" {
					deployment.Spec.Template.Spec.Containers[0].Image = cfg.WorkerImage
				}
				if mode == "build-drift" {
					m.Discovery.TeamWriterImages["deployment/source/app"][0].BuildCommit = strings.Repeat("2", 40)
				}
			}
			objects := []runtime.Object{deployment, rs}
			allPods := []corev1.Pod{pod}
			if mode == "two-writers-distinct-release" {
				other := productionTeamWriterImage{Container: "app", Image: "original/other-app@sha256:" + strings.Repeat("d", 64), ConfigDigest: "sha256:" + strings.Repeat("e", 64), BuildCommit: strings.Repeat("2", 40)}
				second := deployment.DeepCopy()
				second.Name = "other"
				second.UID = "other-deployment-uid"
				second.Spec.Selector.MatchLabels = map[string]string{"app": "other"}
				second.Spec.Template.Spec.Containers[0].Image = other.Image
				secondRS := rs.DeepCopy()
				secondRS.Name = "other-rs"
				secondRS.UID = "other-rs-uid"
				secondRS.OwnerReferences[0].Name = second.Name
				secondRS.OwnerReferences[0].UID = second.UID
				secondPod := pod.DeepCopy()
				secondPod.Name = "other-pod"
				secondPod.UID = "other-pod-uid"
				secondPod.Labels = map[string]string{"app": "other"}
				secondPod.OwnerReferences[0].Name = secondRS.Name
				secondPod.OwnerReferences[0].UID = secondRS.UID
				secondPod.Spec.Containers[0].Image = other.Image
				secondPod.Status.ContainerStatuses[0].ImageID = "containerd://" + other.ConfigDigest
				cfg.Writers = append(cfg.Writers, PlatformDeployment{Namespace: "source", Name: "other", UID: string(second.UID)})
				m.Discovery.TeamPlatformUnits["deployment/source/other"] = []string{"team.event_projection"}
				m.Discovery.TeamWriterImages["deployment/source/other"] = []productionTeamWriterImage{other}
				objects = append(objects, second, secondRS)
				allPods = append(allPods, *secondPod)
			}
			api := fake.NewSimpleClientset(objects...)
			api.PrependReactor("list", "pods", func(action kt.Action) (bool, runtime.Object, error) {
				list := &corev1.PodList{ListMeta: metav1.ListMeta{ResourceVersion: "stable-version"}}
				selector := action.(kt.ListAction).GetListRestrictions().Labels
				if replicas != 0 {
					for _, item := range allPods {
						if selector.Matches(labels.Set(item.Labels)) {
							list.Items = append(list.Items, item)
						}
					}
				}
				return true, list, nil
			})
			observed, err := observeTeamWriterBuild(context.Background(), api, cfg, m, saved)
			valid := mode == "app-different-from-worker" || mode == "worker-only-change" || mode == "manifest-id" || mode == "config-id" || mode == "sidecar-distinct-release" || mode == "init-distinct-release" || mode == "original-pause" || mode == "two-writers-distinct-release"
			if (err == nil) != valid {
				t.Fatal("writer identity", mode, err)
			}
			if valid {
				expected := 1
				if mode == "sidecar-distinct-release" || mode == "init-distinct-release" || mode == "two-writers-distinct-release" {
					expected = 2
				}
				if len(observed) != expected {
					t.Fatal("incomplete per-container observation")
				}
				for _, writer := range observed {
					if len(writer.Pods) != 1 || writer.Pods[0].UID == "" {
						t.Fatal("missing original Pod observation")
					}
				}
			}
		})
	}
}
func TestTeamWriterImagePinRequiresOriginalImmutableRelease(t *testing.T) {
	good := productionTeamWriterImage{Container: "app", Image: "registry/app@sha256:" + strings.Repeat("a", 64), ConfigDigest: "sha256:" + strings.Repeat("b", 64), BuildCommit: strings.Repeat("1", 40)}
	if !validTeamWriterImage(good) {
		t.Fatal("valid immutable release rejected")
	}
	for _, field := range []string{"name", "image", "config", "commit"} {
		pin := good
		switch field {
		case "name":
			pin.Container = ""
		case "image":
			pin.Image = "registry/app:mutable"
		case "config":
			pin.ConfigDigest = "sha256:no"
		case "commit":
			pin.BuildCommit = "dev"
		}
		if validTeamWriterImage(pin) {
			t.Fatal("unknown release accepted", field)
		}
	}
}

// Verifies the producer and bootstrap typed projection retain the identical
// field order/scope; changing a business pin changes existing signed scope.
func TestTeamWriterImagesUseExistingSourceMetadataScope(t *testing.T) {
	pin := productionTeamWriterImage{Container: "app", Image: "original/app@sha256:" + strings.Repeat("a", 64), ConfigDigest: "sha256:" + strings.Repeat("c", 64), BuildCommit: strings.Repeat("1", 40)}
	m := productionCaptureMaterials{Discovery: &productionSourceDiscovery{TeamWriterImages: map[string][]productionTeamWriterImage{"deployment/source/app": {pin}}}}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	want, err := sourceMetadataScope(m)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := install.BootstrapSourceMetadataScopeFromMaterials(raw)
	if err != nil || actual != want {
		t.Fatal("bootstrap must preserve original writer metadata scope", err)
	}
	m.Discovery.TeamWriterImages["deployment/source/app"][0].BuildCommit = strings.Repeat("2", 40)
	changed, err := sourceMetadataScope(m)
	if err != nil || changed == want {
		t.Fatal("business release drift did not change existing signed scope")
	}
}
