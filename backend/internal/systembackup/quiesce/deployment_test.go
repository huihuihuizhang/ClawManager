package quiesce

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/scope"
	jsonpatch "gopkg.in/evanphx/json-patch.v4"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

type deploymentFixture struct {
	client                     *fake.Clientset
	writer                     *DeploymentWriter
	proof, losePause, holdPods bool
	blocked                    string
	delayed                    []byte
	patches                    int
	pod                        *corev1.Pod
}

var deploymentGVR = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
var podGVR = schema.GroupVersionResource{Version: "v1", Resource: "pods"}

func TestOwnedUnscheduledResumePodIsPendingButCannotProveStopped(t *testing.T) {
	f := newDeploymentFixture(t, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	pod := f.pod.DeepCopy()
	pod.Spec.NodeName = ""
	pod.Status.Phase = corev1.PodPending
	pod.Status.ContainerStatuses = nil
	if e := f.client.Tracker().Update(podGVR, pod, "fixture"); e != nil {
		t.Fatal(e)
	}
	dep, e := f.client.AppsV1().Deployments("fixture").Get(ctx, "agent", metav1.GetOptions{})
	if e != nil {
		t.Fatal(e)
	}
	pods, ready, e := f.writer.pods(ctx, dep)
	if e != nil || ready || len(pods) != 1 {
		t.Fatal("legitimate scheduling wait rejected", ready, e)
	}
	if _, e = f.writer.Observe(ctx); e == nil {
		t.Fatal("unscheduled source froze as healthy")
	}
	pod.OwnerReferences[0].UID = "foreign-replicaset"
	if e = f.client.Tracker().Update(podGVR, pod, "fixture"); e != nil {
		t.Fatal(e)
	}
	if _, _, e = f.writer.pods(ctx, dep); e == nil {
		t.Fatal("foreign pending pod accepted")
	}
}

func newDeploymentFixture(t *testing.T, replicas int32) *deploymentFixture {
	t.Helper()
	controller := true
	labels := map[string]string{"app": "fixture-source"}
	d := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "agent", Namespace: "fixture", UID: "deployment-uid", ResourceVersion: "1", Generation: 3}, Spec: appsv1.DeploymentSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: labels}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "agent", Image: "fixture@sha256:abc", Env: []corev1.EnvVar{{Name: "SECRET", Value: "fixture-private"}}}}}}}, Status: appsv1.DeploymentStatus{ObservedGeneration: 3, Replicas: replicas, ReadyReplicas: replicas}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "agent-rs", Namespace: "fixture", UID: "rs-uid", Labels: labels, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: d.Name, UID: d.UID, Controller: &controller}}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "agent-pod", Namespace: "fixture", UID: "pod-uid", Labels: labels, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &controller}}}, Spec: corev1.PodSpec{NodeName: "node-a", Containers: []corev1.Container{{Name: "agent", Image: "fixture@sha256:abc"}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: "agent", ContainerID: "containerd://original", Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}
	f := &deploymentFixture{client: fake.NewSimpleClientset(d, rs), proof: true, pod: pod}
	if replicas > 0 {
		if err := f.client.Tracker().Create(podGVR, pod, pod.Namespace); err != nil {
			t.Fatal(err)
		}
	}
	f.client.PrependReactor("patch", "deployments", func(action ktesting.Action) (bool, runtime.Object, error) {
		a := action.(ktesting.PatchAction)
		f.patches++
		if f.losePause && !strings.Contains(string(a.GetPatch()), resumeFenceAnnotation) && !strings.Contains(string(a.GetPatch()), "source-resume-fence") {
			f.delayed = append([]byte(nil), a.GetPatch()...)
			return true, nil, apierrors.NewTimeoutError("reply lost before application", 1)
		}
		current, e := f.client.Tracker().Get(deploymentGVR, "fixture", "agent")
		if e != nil {
			return true, nil, e
		}
		before := current.(*appsv1.Deployment)
		b, _ := json.Marshal(before)
		patch, e := jsonpatch.DecodePatch(a.GetPatch())
		if e != nil {
			return true, nil, e
		}
		changed, e := patch.Apply(b)
		if e != nil {
			return true, nil, apierrors.NewConflict(schema.GroupResource{Group: "apps", Resource: "deployments"}, "agent", e)
		}
		var after appsv1.Deployment
		if e = json.Unmarshal(changed, &after); e != nil {
			return true, nil, e
		}
		rv, _ := strconv.Atoi(before.ResourceVersion)
		after.ResourceVersion = strconv.Itoa(rv + 1)
		if *after.Spec.Replicas != *before.Spec.Replicas {
			after.Generation++
		}
		after.Status.ObservedGeneration = after.Generation
		after.Status.Replicas = *after.Spec.Replicas
		after.Status.ReadyReplicas = *after.Spec.Replicas
		if *after.Spec.Replicas == 0 && !f.holdPods {
			_ = f.client.Tracker().Delete(podGVR, "fixture", "agent-pod")
		}
		if *after.Spec.Replicas > 0 {
			if _, e = f.client.Tracker().Get(podGVR, "fixture", "agent-pod"); apierrors.IsNotFound(e) {
				p := f.pod.DeepCopy()
				p.UID = "restored-pod"
				p.Status.ContainerStatuses[0].ContainerID = "containerd://restored"
				if e = f.client.Tracker().Create(podGVR, p, "fixture"); e != nil {
					return true, nil, e
				}
			}
		}
		if e = f.client.Tracker().Update(deploymentGVR, &after, "fixture"); e != nil {
			return true, nil, e
		}
		return true, &after, nil
	})
	w := &DeploymentWriter{Client: f.client, Namespace: "fixture", Name: "agent", UID: "deployment-uid", FenceID: "task-attempt-recovery-1", Runtime: scope.Runtime{Type: "hermes", Mode: "pro", Backend: "desktop", OS: "linux"}, PollInterval: time.Millisecond}
	w.Guard = func(_ context.Context, point string, _ flow.State) error {
		if f.blocked == point {
			return errors.New("fence")
		}
		return nil
	}
	w.ConfirmStopped = func(_ context.Context, _ flow.State, pods []PodIdentity) error {
		if !f.proof {
			return errors.New("node proof missing")
		}
		if replicas > 0 && (len(pods) != 1 || pods[0].UID != "pod-uid" || pods[0].Containers[0] != "containerd://original") {
			return errors.New("wrong process inventory")
		}
		return nil
	}
	w.ConfirmResumed = func(context.Context, flow.State) error { return nil }
	f.writer = w
	return f
}
func testDeadline(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	return ctx
}
func TestDeploymentWriterRestoresOriginalPowerAndUsesUIDRV(t *testing.T) {
	for _, count := range []int32{0, 1} {
		t.Run(strconv.Itoa(int(count)), func(t *testing.T) {
			f := newDeploymentFixture(t, count)
			ctx := testDeadline(t)
			s, err := f.writer.Observe(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if s.Running != (count > 0) || strings.Contains(s.Checkpoint, "fixture-private") {
				t.Fatal("checkpoint leaks configuration or loses power state")
			}
			ack, err := f.writer.Pause(ctx, s)
			if err != nil || !ack.Stopped {
				t.Fatal(err)
			}
			if err = f.writer.CheckPaused(ctx, s); err != nil {
				t.Fatal(err)
			}
			if err = f.writer.Resume(ctx, s); err != nil {
				t.Fatal(err)
			}
			patches := f.patches
			if err = f.writer.Resume(ctx, s); err != nil || patches != f.patches {
				t.Fatal("repeated resume mutated source", err)
			}
			d, _ := f.writer.get(ctx)
			if *d.Spec.Replicas != count || d.Annotations[resumeFenceAnnotation] != f.writer.FenceID {
				t.Fatal("original replicas not restored")
			}
			if _, err = f.writer.Pause(ctx, s); err == nil {
				t.Fatal("old task can pause after recovery")
			}
		})
	}
}
func TestDeploymentWriterLatePauseCannotStopRecoveredSource(t *testing.T) {
	f := newDeploymentFixture(t, 1)
	ctx := testDeadline(t)
	s, err := f.writer.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.losePause = true
	if _, err = f.writer.Pause(ctx, s); err == nil {
		t.Fatal("uncertain pause reported ACK")
	}
	if err = f.writer.Resume(ctx, s); err != nil {
		t.Fatal(err)
	}
	f.losePause = false
	if _, err = f.client.AppsV1().Deployments("fixture").Patch(ctx, "agent", types.JSONPatchType, f.delayed, metav1.PatchOptions{}); !apierrors.IsConflict(err) {
		t.Fatal("late pause was not fenced by resourceVersion", err)
	}
	d, _ := f.writer.get(ctx)
	if *d.Spec.Replicas != 1 {
		t.Fatal("late stop damaged recovered source")
	}
}
func TestDeploymentWriterRequiresContainerTerminationProof(t *testing.T) {
	f := newDeploymentFixture(t, 1)
	ctx := testDeadline(t)
	s, err := f.writer.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.proof = false
	if _, err = f.writer.Pause(ctx, s); err == nil {
		t.Fatal("Pod absence treated as stop proof")
	}
	if err = f.writer.Resume(ctx, s); err == nil {
		t.Fatal("started duplicate writer while old process may be alive")
	}
	d, _ := f.writer.get(ctx)
	if *d.Spec.Replicas != 0 {
		t.Fatal("unsafe source restart")
	}
	f.proof = true
	if err = f.writer.Resume(ctx, s); err != nil {
		t.Fatal("recovery failed after termination proof", err)
	}
}
func TestDeploymentWriterRejectsIdentityTemplateAndPodDrift(t *testing.T) {
	for _, mode := range []string{"uid", "image", "pod", "guard", "no-deadline"} {
		t.Run(mode, func(t *testing.T) {
			f := newDeploymentFixture(t, 1)
			ctx := testDeadline(t)
			s, err := f.writer.Observe(ctx)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "uid", "image":
				d, _ := f.writer.get(ctx)
				if mode == "uid" {
					d.UID = "replacement"
				} else {
					d.Spec.Template.Spec.Containers[0].Image = "other"
				}
				if err = f.client.Tracker().Update(deploymentGVR, d, "fixture"); err != nil {
					t.Fatal(err)
				}
			case "pod":
				p := f.pod.DeepCopy()
				p.UID = "other-pod"
				if err = f.client.Tracker().Update(podGVR, p, "fixture"); err != nil {
					t.Fatal(err)
				}
			case "guard":
				f.blocked = "before-stop"
			case "no-deadline":
				ctx = context.Background()
			}
			if _, err = f.writer.Pause(ctx, s); err == nil {
				t.Fatal("unsafe pause succeeded")
			}
			if f.patches != 0 {
				t.Fatal("mutated source after drift")
			}
		})
	}
}
func TestDeploymentWriterDoesNotACKWhilePodsRemain(t *testing.T) {
	f := newDeploymentFixture(t, 1)
	ctx := testDeadline(t)
	s, err := f.writer.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.holdPods = true
	short, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	if _, err = f.writer.Pause(short, s); err == nil {
		t.Fatal("replicas zero treated as drained")
	}
}
