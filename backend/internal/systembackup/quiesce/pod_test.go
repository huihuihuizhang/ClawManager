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
	jsonpatch "gopkg.in/evanphx/json-patch.v4"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	typedcore "k8s.io/client-go/kubernetes/typed/core/v1"
	ktesting "k8s.io/client-go/testing"
)

// Intercept the typed API so DeleteOptions are tested even when a fake tracker
// ignores preconditions. This models API-server UID/resourceVersion checks.
type podClient struct {
	kubernetes.Interface
	remove func(context.Context, string, metav1.DeleteOptions) error
}
type podCore struct {
	typedcore.CoreV1Interface
	remove func(context.Context, string, metav1.DeleteOptions) error
}
type podAPI struct {
	typedcore.PodInterface
	remove func(context.Context, string, metav1.DeleteOptions) error
}

func (c podClient) CoreV1() typedcore.CoreV1Interface { return podCore{c.Interface.CoreV1(), c.remove} }
func (c podCore) Pods(ns string) typedcore.PodInterface {
	return podAPI{c.CoreV1Interface.Pods(ns), c.remove}
}
func (c podAPI) Delete(ctx context.Context, name string, o metav1.DeleteOptions) error {
	return c.remove(ctx, name, o)
}

type podFixture struct {
	client                                   *fake.Clientset
	writer                                   *PodWriter
	original                                 *corev1.Pod
	proof, claimed, delayDelete, delayCreate bool
	deletes, creates, completes              int
	delayed                                  metav1.DeleteOptions
	pending                                  *corev1.Pod
}

func newPodFixture(t *testing.T, running bool) *podFixture {
	t.Helper()
	base := newDeploymentFixture(t, 1)
	pod := base.pod.DeepCopy()
	pod.OwnerReferences = nil
	pod.ResourceVersion = "1"
	pod.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "SECRET", Value: "private-fixture"}}
	f := &podFixture{client: fake.NewSimpleClientset(), original: pod, proof: true}
	if running {
		if e := f.client.Tracker().Create(podGVR, pod, pod.Namespace); e != nil {
			t.Fatal(e)
		}
	}
	w := &PodWriter{Client: podClient{f.client, f.remove}, Namespace: pod.Namespace, Name: pod.Name, InstanceKey: "instance-1", FenceID: "attempt-1", RestartRef: "encrypted-ref", Generation: 1, Runtime: base.writer.Runtime, PollInterval: time.Millisecond}
	if running {
		w.UID = string(pod.UID)
	}
	w.Guard = func(context.Context, string, flow.State) error { return nil }
	w.LoadRestart = func(context.Context, string) (*corev1.Pod, error) {
		p := pod.DeepCopy()
		p.UID = ""
		p.ResourceVersion = ""
		p.Status = corev1.PodStatus{}
		return p, nil
	}
	w.ClaimRestart = func(context.Context, flow.State) (bool, error) {
		if f.claimed {
			return false, nil
		}
		f.claimed = true
		return true, nil
	}
	w.CompleteRestart = func(_ context.Context, _ flow.State, uid string) error {
		if uid == "" {
			return errors.New("missing UID")
		}
		f.completes++
		return nil
	}
	w.ConfirmStopped = func(_ context.Context, _ flow.State, ids []PodIdentity) error {
		if !f.proof {
			return errors.New("missing node proof")
		}
		if running && (len(ids) != 1 || ids[0].UID != string(pod.UID) || ids[0].Containers[0] != "containerd://original") {
			return errors.New("wrong process")
		}
		return nil
	}
	w.ConfirmResumed = func(context.Context, flow.State) error { return nil }
	f.writer = w
	f.client.PrependReactor("create", "pods", func(a ktesting.Action) (bool, runtime.Object, error) {
		f.creates++
		p := a.(ktesting.CreateAction).GetObject().(*corev1.Pod).DeepCopy()
		p.UID = "recovered-pod"
		p.ResourceVersion = "10"
		p.Status = pod.Status
		if f.delayCreate {
			f.pending = p
			return true, nil, apierrors.NewTimeoutError("lost", 1)
		}
		e := f.client.Tracker().Create(podGVR, p, p.Namespace)
		return true, p, e
	})
	f.client.PrependReactor("patch", "pods", func(a ktesting.Action) (bool, runtime.Object, error) {
		obj, e := f.client.Tracker().Get(podGVR, pod.Namespace, pod.Name)
		if e != nil {
			return true, nil, e
		}
		before := obj.(*corev1.Pod)
		b, _ := json.Marshal(before)
		patch, e := jsonpatch.DecodePatch(a.(ktesting.PatchAction).GetPatch())
		if e != nil {
			return true, nil, e
		}
		b, e = patch.Apply(b)
		if e != nil {
			return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "pods"}, pod.Name, e)
		}
		var after corev1.Pod
		if e = json.Unmarshal(b, &after); e != nil {
			return true, nil, e
		}
		rv, _ := strconv.Atoi(before.ResourceVersion)
		after.ResourceVersion = strconv.Itoa(rv + 1)
		e = f.client.Tracker().Update(podGVR, &after, pod.Namespace)
		return true, &after, e
	})
	return f
}
func (f *podFixture) remove(_ context.Context, name string, o metav1.DeleteOptions) error {
	f.deletes++
	if o.Preconditions == nil || o.Preconditions.UID == nil || o.Preconditions.ResourceVersion == nil {
		return errors.New("unguarded delete")
	}
	if f.delayDelete {
		f.delayed = o
		return apierrors.NewTimeoutError("lost", 1)
	}
	obj, e := f.client.Tracker().Get(podGVR, f.writer.Namespace, name)
	if e != nil {
		return e
	}
	p := obj.(*corev1.Pod)
	if p.UID != *o.Preconditions.UID || p.ResourceVersion != *o.Preconditions.ResourceVersion {
		return apierrors.NewConflict(schema.GroupResource{Resource: "pods"}, name, errors.New("precondition"))
	}
	return f.client.Tracker().Delete(podGVR, p.Namespace, p.Name)
}
func TestPodWriterRoundTripAndAbsentSource(t *testing.T) {
	for _, running := range []bool{true, false} {
		t.Run(strconv.FormatBool(running), func(t *testing.T) {
			f := newPodFixture(t, running)
			ctx := testDeadline(t)
			s, e := f.writer.Observe(ctx)
			if e != nil {
				t.Fatal(e)
			}
			if s.Running != running || strings.Contains(s.Checkpoint, "private-fixture") {
				t.Fatal("unsafe checkpoint")
			}
			ack, e := f.writer.Pause(ctx, s)
			if e != nil || !ack.Stopped {
				t.Fatal(e)
			}
			if e = f.writer.CheckPaused(ctx, s); e != nil {
				t.Fatal(e)
			}
			if e = f.writer.Resume(ctx, s); e != nil {
				t.Fatal(e)
			}
			if e = f.writer.Resume(ctx, s); e != nil {
				t.Fatal(e)
			}
			if running && f.creates != 1 {
				t.Fatal("non-idempotent recreation")
			}
			if !running && (f.creates != 0 || f.deletes != 0) {
				t.Fatal("started originally stopped source")
			}
			if running {
				if _, e = f.writer.Pause(ctx, s); e == nil {
					t.Fatal("old pause accepted after recovery")
				}
			}
		})
	}
}
func TestPodWriterLateDeleteCannotKillSource(t *testing.T) {
	for _, applied := range []bool{false, true} {
		t.Run(strconv.FormatBool(applied), func(t *testing.T) {
			f := newPodFixture(t, true)
			ctx := testDeadline(t)
			s, e := f.writer.Observe(ctx)
			if e != nil {
				t.Fatal(e)
			}
			f.delayDelete = true
			if _, e = f.writer.Pause(ctx, s); e == nil {
				t.Fatal("uncertain stop acknowledged")
			}
			f.delayDelete = false
			if applied {
				if e = f.remove(ctx, f.writer.Name, f.delayed); e != nil {
					t.Fatal(e)
				}
			}
			if e = f.writer.Resume(ctx, s); e != nil {
				t.Fatal(e)
			}
			if e = f.remove(ctx, f.writer.Name, f.delayed); !apierrors.IsConflict(e) {
				t.Fatal("late DELETE not fenced", e)
			}
			if _, e = f.writer.get(ctx); e != nil {
				t.Fatal("source deleted", e)
			}
		})
	}
}
func TestPodWriterRequiresNodeProofAndReconcilesUncertainCreate(t *testing.T) {
	f := newPodFixture(t, true)
	ctx := testDeadline(t)
	s, e := f.writer.Observe(ctx)
	if e != nil {
		t.Fatal(e)
	}
	f.proof = false
	if _, e = f.writer.Pause(ctx, s); e == nil {
		t.Fatal("API absence accepted as node proof")
	}
	if e = f.writer.Resume(ctx, s); e == nil || f.creates != 0 {
		t.Fatal("unsafe restart")
	}
	f.proof = true
	f.delayCreate = true
	for i := 0; i < 2; i++ {
		short, cancel := context.WithTimeout(ctx, 25*time.Millisecond)
		e = f.writer.Resume(short, s)
		cancel()
		if e == nil {
			t.Fatal("pending create marked done")
		}
	}
	if f.creates != 1 {
		t.Fatal("uncertain create repeated")
	}
	if e = f.client.Tracker().Create(podGVR, f.pending, f.writer.Namespace); e != nil {
		t.Fatal(e)
	}
	copyWriter := *f.writer
	if e = copyWriter.Resume(ctx, s); e != nil {
		t.Fatal(e)
	}
	if f.completes != 1 {
		t.Fatal("binding not reconciled")
	}
}
func TestPodWriterRejectsDriftBeforeMutation(t *testing.T) {
	for _, mode := range []string{"owner", "uid", "spec", "container", "checkpoint", "deadline", "guard"} {
		t.Run(mode, func(t *testing.T) {
			f := newPodFixture(t, true)
			ctx := testDeadline(t)
			s, e := f.writer.Observe(ctx)
			if e != nil {
				t.Fatal(e)
			}
			p, _ := f.writer.get(ctx)
			switch mode {
			case "owner":
				p.OwnerReferences = []metav1.OwnerReference{{UID: "controller"}}
			case "uid":
				p.UID = "replacement"
			case "spec":
				p.Spec.Containers[0].Image = "other"
			case "container":
				p.Status.ContainerStatuses[0].ContainerID = "containerd://other"
			case "checkpoint":
				s.Checkpoint += " "
			case "deadline":
				ctx = context.Background()
			case "guard":
				f.writer.Guard = func(context.Context, string, flow.State) error { return errors.New("lost fence") }
			}
			if e = f.client.Tracker().Update(podGVR, p, p.Namespace); e != nil {
				t.Fatal(e)
			}
			if _, e = f.writer.Pause(ctx, s); e == nil || f.deletes != 0 {
				t.Fatal("unsafe mutation", e)
			}
		})
	}
}
