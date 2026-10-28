package quiesce

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/scope"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

type podCheckpoint struct {
	Version, Namespace, Name, FenceID, RestartRef, SpecSHA256 string
	Process                                                   PodIdentity
}

// PodWriter handles legacy standalone Linux Pro Pods (not controller-owned
// Pods). A missing source is explicitly registered with UID="" and remains
// stopped. Running Pod restart specifications must come from an immutable,
// encrypted ref; no secret-bearing Pod manifest enters the pause journal.
// Guard at check-resumed/commit-resumed must validate the original source or
// this attempt's durable create dispatch. A copied annotation alone is not
// proof of ownership. CompleteRestart reconciles the new UID in the source
// binding; it must be idempotent and fenced in the same transaction.
type PodWriter struct {
	Client                                                 kubernetes.Interface
	Namespace, Name, UID, InstanceKey, FenceID, RestartRef string
	Generation                                             int64
	Runtime                                                scope.Runtime
	Guard                                                  func(context.Context, string, flow.State) error
	LoadRestart                                            func(context.Context, string) (*corev1.Pod, error)
	ClaimRestart                                           func(context.Context, flow.State) (bool, error)
	CompleteRestart                                        func(context.Context, flow.State, string) error
	ConfirmStopped                                         func(context.Context, flow.State, []PodIdentity) error
	ConfirmResumed                                         func(context.Context, flow.State) error
	PollInterval                                           time.Duration
}

var _ flow.Writer = (*PodWriter)(nil)

func (w *PodWriter) ID() string { return "pod/" + w.Namespace + "/" + w.Name }
func (w *PodWriter) sourceUID() string {
	if w.UID != "" {
		return w.UID
	}
	return "absent:" + w.InstanceKey
}
func (w *PodWriter) ready(ctx context.Context) error {
	if _, ok := ctx.Deadline(); !ok {
		return flow.ErrNotReady
	}
	profile, err := scope.PlanRuntime(w.Runtime)
	if err != nil || profile.Mode != "pro" || w.Client == nil || w.Namespace == "" || w.Name == "" || w.InstanceKey == "" || w.FenceID == "" || len(w.FenceID) > 128 || w.Generation <= 0 || w.Guard == nil || w.LoadRestart == nil || w.ClaimRestart == nil || w.CompleteRestart == nil || w.ConfirmStopped == nil || w.ConfirmResumed == nil || (w.UID != "" && w.RestartRef == "") {
		return flow.ErrNotReady
	}
	return ctx.Err()
}
func podSpecHash(p *corev1.Pod) string {
	b, _ := json.Marshal(p.Spec)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func standalone(p *corev1.Pod) bool {
	return len(p.OwnerReferences) == 0 && len(p.Spec.EphemeralContainers) == 0 && (p.Spec.OS == nil || p.Spec.OS.Name != corev1.Windows) && p.Annotations[corev1.MirrorPodAnnotationKey] == ""
}
func (w *PodWriter) get(ctx context.Context) (*corev1.Pod, error) {
	return w.Client.CoreV1().Pods(w.Namespace).Get(ctx, w.Name, metav1.GetOptions{})
}
func (w *PodWriter) restart(ctx context.Context, hash string) (*corev1.Pod, error) {
	p, err := w.LoadRestart(ctx, w.RestartRef)
	if err != nil || p == nil || p.Namespace != w.Namespace || p.Name != w.Name || p.UID != "" || p.ResourceVersion != "" || p.GenerateName != "" || p.DeletionTimestamp != nil || len(p.Finalizers) != 0 || !standalone(p) || podSpecHash(p) != hash {
		return nil, flow.ErrResume
	}
	b, _ := json.Marshal(p.Status)
	if string(b) != "{}" {
		return nil, flow.ErrResume
	}
	p = p.DeepCopy()
	if p.Annotations == nil {
		p.Annotations = map[string]string{}
	}
	p.Annotations[resumeFenceAnnotation] = w.FenceID
	return p, nil
}
func (w *PodWriter) Observe(ctx context.Context) (flow.State, error) {
	if w.ready(ctx) != nil {
		return flow.State{}, flow.ErrNotReady
	}
	s := flow.State{UID: w.sourceUID(), Generation: w.Generation, Running: w.UID != ""}
	if w.Guard(ctx, "observe", s) != nil {
		return flow.State{}, flow.ErrJournal
	}
	p := podCheckpoint{Version: "pod-quiesce.v1", Namespace: w.Namespace, Name: w.Name, FenceID: w.FenceID, RestartRef: w.RestartRef}
	pod, err := w.get(ctx)
	if w.UID == "" {
		if !apierrors.IsNotFound(err) {
			return flow.State{}, flow.ErrQuiesce
		}
	} else {
		if err != nil || string(pod.UID) != w.UID || pod.ResourceVersion == "" || !standalone(pod) || pod.Annotations[resumeFenceAnnotation] == w.FenceID {
			return flow.State{}, flow.ErrQuiesce
		}
		var ready bool
		p.Process, ready = podProcess(pod)
		if !ready {
			return flow.State{}, flow.ErrQuiesce
		}
		p.SpecSHA256 = podSpecHash(pod)
		if _, err = w.restart(ctx, p.SpecSHA256); err != nil {
			return flow.State{}, err
		}
	}
	b, _ := json.Marshal(p)
	if len(b) > 128<<10 {
		return flow.State{}, flow.ErrQuiesce
	}
	s.Checkpoint = string(b)
	if w.Guard(ctx, "observed", s) != nil {
		return flow.State{}, flow.ErrJournal
	}
	return s, nil
}
func (w *PodWriter) checkpoint(s flow.State) (podCheckpoint, error) {
	var p podCheckpoint
	if s.UID != w.sourceUID() || s.Generation != w.Generation || s.Running != (w.UID != "") || len(s.Checkpoint) > 128<<10 || json.Unmarshal([]byte(s.Checkpoint), &p) != nil {
		return p, flow.ErrQuiesce
	}
	b, _ := json.Marshal(p)
	if string(b) != s.Checkpoint || p.Version != "pod-quiesce.v1" || p.Namespace != w.Namespace || p.Name != w.Name || p.FenceID != w.FenceID || p.RestartRef != w.RestartRef {
		return p, flow.ErrQuiesce
	}
	if s.Running && (p.Process.UID != w.UID || p.Process.Name != w.Name || p.Process.Node == "" || len(p.Process.Containers) == 0 || len(p.SpecSHA256) != 64) {
		return p, flow.ErrQuiesce
	}
	if !s.Running && (p.SpecSHA256 != "" || p.Process.UID != "") {
		return p, flow.ErrQuiesce
	}
	return p, nil
}
func (w *PodWriter) Pause(ctx context.Context, s flow.State) (flow.ACK, error) {
	if w.ready(ctx) != nil {
		return flow.ACK{}, flow.ErrNotReady
	}
	p, err := w.checkpoint(s)
	if err != nil {
		return flow.ACK{}, err
	}
	if w.Guard(ctx, "before-stop", s) != nil {
		return flow.ACK{}, flow.ErrJournal
	}
	pod, err := w.get(ctx)
	if s.Running && !apierrors.IsNotFound(err) {
		if err != nil || string(pod.UID) != w.UID || !standalone(pod) || podSpecHash(pod) != p.SpecSHA256 || pod.Annotations[resumeFenceAnnotation] == w.FenceID {
			return flow.ACK{}, flow.ErrQuiesce
		}
		identity, ready := podProcess(pod)
		if pod.DeletionTimestamp == nil {
			if !ready || !samePods([]PodIdentity{identity}, []PodIdentity{p.Process}) {
				return flow.ACK{}, flow.ErrQuiesce
			}
			uid, rv := pod.UID, pod.ResourceVersion
			err = w.Client.CoreV1().Pods(w.Namespace).Delete(ctx, w.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}})
			if err != nil && !apierrors.IsNotFound(err) {
				return flow.ACK{}, flow.ErrQuiesce
			}
		}
	} else if !s.Running && !apierrors.IsNotFound(err) {
		return flow.ACK{}, flow.ErrQuiesce
	}
	if wait(ctx, w.PollInterval, func() (bool, error) { return w.stopped(ctx, s, p, false) }) != nil {
		return flow.ACK{}, flow.ErrQuiesce
	}
	return flow.ACK{UID: s.UID, Generation: s.Generation, Stopped: true}, nil
}
func (w *PodWriter) stopped(ctx context.Context, s flow.State, p podCheckpoint, recovery bool) (bool, error) {
	point := "check-stopped"
	if recovery {
		point = "recovery-check-stopped"
	}
	if w.Guard(ctx, point, s) != nil {
		return false, flow.ErrJournal
	}
	pod, err := w.get(ctx)
	if err == nil {
		if !s.Running || string(pod.UID) != w.UID || podSpecHash(pod) != p.SpecSHA256 || !standalone(pod) {
			return false, flow.ErrQuiesce
		}
		return false, nil
	}
	if !apierrors.IsNotFound(err) {
		return false, flow.ErrQuiesce
	}
	var processes []PodIdentity
	if s.Running {
		processes = []PodIdentity{p.Process}
	}
	if w.ConfirmStopped(ctx, s, processes) != nil {
		return false, flow.ErrQuiesce
	}
	return true, nil
}
func (w *PodWriter) CheckPaused(ctx context.Context, s flow.State) error {
	if w.ready(ctx) != nil {
		return flow.ErrQuiesce
	}
	p, err := w.checkpoint(s)
	if err != nil {
		return err
	}
	ok, err := w.stopped(ctx, s, p, false)
	if err != nil || !ok {
		return flow.ErrQuiesce
	}
	return nil
}
func (w *PodWriter) resumeMarker(ctx context.Context, pod *corev1.Pod) error {
	ops := []map[string]any{{"op": "test", "path": "/metadata/uid", "value": string(pod.UID)}, {"op": "test", "path": "/metadata/resourceVersion", "value": pod.ResourceVersion}}
	if pod.Annotations == nil {
		ops = append(ops, map[string]any{"op": "add", "path": "/metadata/annotations", "value": map[string]string{resumeFenceAnnotation: w.FenceID}})
	} else {
		ops = append(ops, map[string]any{"op": "add", "path": "/metadata/annotations/" + strings.ReplaceAll(resumeFenceAnnotation, "/", "~1"), "value": w.FenceID})
	}
	b, _ := json.Marshal(ops)
	_, err := w.Client.CoreV1().Pods(w.Namespace).Patch(ctx, w.Name, types.JSONPatchType, b, metav1.PatchOptions{})
	return err
}
func (w *PodWriter) Resume(ctx context.Context, s flow.State) error {
	if w.ready(ctx) != nil {
		return flow.ErrResume
	}
	p, err := w.checkpoint(s)
	if err != nil || w.Guard(ctx, "before-resume", s) != nil {
		return flow.ErrResume
	}
	if !s.Running {
		ok, e := w.stopped(ctx, s, p, true)
		if e != nil || !ok {
			return flow.ErrResume
		}
		return nil
	}
	pod, err := w.get(ctx)
	if err == nil {
		if !standalone(pod) || podSpecHash(pod) != p.SpecSHA256 {
			return flow.ErrResume
		}
		if string(pod.UID) == w.UID {
			if pod.DeletionTimestamp == nil {
				// Cancel a not-yet-applied DELETE by changing RV, even when the
				// original process is still healthy. Never use force deletion.
				if pod.Annotations[resumeFenceAnnotation] != w.FenceID && w.resumeMarker(ctx, pod) != nil {
					return flow.ErrResume
				}
			} else {
				if wait(ctx, w.PollInterval, func() (bool, error) { return w.stopped(ctx, s, p, true) }) != nil {
					return flow.ErrResume
				}
			}
		} else if pod.Annotations[resumeFenceAnnotation] != w.FenceID {
			return flow.ErrResume
		}
	} else if !apierrors.IsNotFound(err) {
		return flow.ErrResume
	}
	pod, err = w.get(ctx)
	if apierrors.IsNotFound(err) {
		if w.ConfirmStopped(ctx, s, []PodIdentity{p.Process}) != nil {
			return flow.ErrResume
		}
		restart, e := w.restart(ctx, p.SpecSHA256)
		if e != nil {
			return flow.ErrResume
		}
		if w.Guard(ctx, "before-restart-dispatch", s) != nil {
			return flow.ErrResume
		}
		claimed, e := w.ClaimRestart(ctx, s)
		if e != nil {
			return flow.ErrResume
		}
		if claimed {
			if w.Guard(ctx, "restart-dispatched", s) != nil {
				return flow.ErrResume
			}
			// Whether create succeeds or times out, reconcile the exact marker.
			_, _ = w.Client.CoreV1().Pods(w.Namespace).Create(ctx, restart, metav1.CreateOptions{})
		}
	} else if err != nil {
		return flow.ErrResume
	}
	var uid string
	err = wait(ctx, w.PollInterval, func() (bool, error) {
		if w.Guard(ctx, "check-resumed", s) != nil {
			return false, flow.ErrResume
		}
		current, e := w.get(ctx)
		if apierrors.IsNotFound(e) {
			return false, nil
		}
		if e != nil || current.UID == "" || !standalone(current) || podSpecHash(current) != p.SpecSHA256 || current.Annotations[resumeFenceAnnotation] != w.FenceID {
			return false, flow.ErrResume
		}
		_, ready := podProcess(current)
		if !ready {
			return false, nil
		}
		if w.ConfirmResumed(ctx, s) != nil {
			return false, flow.ErrResume
		}
		uid = string(current.UID)
		return true, nil
	})
	if err != nil || w.Guard(ctx, "commit-resumed", s) != nil || w.CompleteRestart(ctx, s, uid) != nil {
		return flow.ErrResume
	}
	return nil
}
