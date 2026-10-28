// Package quiesce contains source-runtime adapters. They never restore backup
// data or operate without a controller-owned writer/recovery fence.
package quiesce

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/scope"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

const resumeFenceAnnotation = "backup.clawmanager.io/source-resume-fence"

type PodIdentity struct {
	Name, UID, Node string
	Containers      []string // CRI container IDs; never environment or Pod spec
}
type deploymentCheckpoint struct {
	Version, Namespace, Name, FenceID, SpecSHA256 string
	Replicas                                      int32
	Pods                                          []PodIdentity
}

// DeploymentWriter handles registered Linux Pro Deployments. Guard must prove
// full writer inventory, autoscaler/reconciler fencing and pause/recovery intent
// ownership. ConfirmStopped must prove the recorded containers cannot still
// write (e.g. runtime/node acknowledgement); API Pod disappearance alone is NOT
// proof after force deletion or a node partition. ConfirmResumed checks runtime
// health/reconciliation, beyond Deployment readiness. No permissive defaults.
type DeploymentWriter struct {
	Client                        kubernetes.Interface
	Namespace, Name, UID, FenceID string
	Runtime                       scope.Runtime
	Guard                         func(context.Context, string, flow.State) error
	ConfirmStopped                func(context.Context, flow.State, []PodIdentity) error
	ConfirmResumed                func(context.Context, flow.State) error
	PollInterval                  time.Duration
}

var _ flow.Writer = (*DeploymentWriter)(nil)

func (w *DeploymentWriter) ID() string { return "deployment/" + w.Namespace + "/" + w.Name }
func (w *DeploymentWriter) ready(ctx context.Context) error {
	if _, ok := ctx.Deadline(); !ok {
		return flow.ErrNotReady
	}
	if w.Client == nil || w.Namespace == "" || w.Name == "" || w.UID == "" || w.FenceID == "" || len(w.FenceID) > 128 || w.Guard == nil || w.ConfirmStopped == nil || w.ConfirmResumed == nil {
		return flow.ErrNotReady
	}
	p, err := scope.PlanRuntime(w.Runtime)
	if err != nil || p.Mode != "pro" {
		return flow.ErrNotReady
	}
	return ctx.Err()
}
func deploymentHash(d *appsv1.Deployment) string {
	spec := d.Spec.DeepCopy()
	spec.Replicas = nil
	b, err := json.Marshal(spec)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func (w *DeploymentWriter) get(ctx context.Context) (*appsv1.Deployment, error) {
	d, err := w.Client.AppsV1().Deployments(w.Namespace).Get(ctx, w.Name, metav1.GetOptions{})
	if err != nil || string(d.UID) != w.UID || d.ResourceVersion == "" || d.Generation <= 0 || d.DeletionTimestamp != nil || d.Spec.Replicas == nil || *d.Spec.Replicas < 0 || *d.Spec.Replicas > 1000 || d.Spec.Selector == nil {
		return nil, flow.ErrQuiesce
	}
	return d, nil
}
func (w *DeploymentWriter) pods(ctx context.Context, d *appsv1.Deployment) ([]PodIdentity, bool, error) {
	selector, err := metav1.LabelSelectorAsSelector(d.Spec.Selector)
	if err != nil || selector.Empty() {
		return nil, false, flow.ErrQuiesce
	}
	sets, err := w.Client.AppsV1().ReplicaSets(w.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil {
		return nil, false, flow.ErrQuiesce
	}
	owned := map[types.UID]bool{}
	for _, rs := range sets.Items {
		owner := metav1.GetControllerOf(&rs)
		if owner == nil || owner.Kind != "Deployment" || owner.UID != d.UID {
			return nil, false, flow.ErrQuiesce
		}
		owned[rs.UID] = true
	}
	pods, err := w.Client.CoreV1().Pods(w.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil || len(pods.Items) > 1000 {
		return nil, false, flow.ErrQuiesce
	}
	var identities []PodIdentity
	ready := true
	for _, pod := range pods.Items {
		owner := metav1.GetControllerOf(&pod)
		if owner == nil || owner.Kind != "ReplicaSet" || !owned[owner.UID] || pod.UID == "" || pod.Spec.NodeName == "" || (pod.Spec.OS != nil && pod.Spec.OS.Name == corev1.Windows) {
			return nil, false, flow.ErrQuiesce
		}
		identity, podReady := podProcess(&pod)
		ready = ready && podReady
		identities = append(identities, identity)
	}
	return identities, ready, nil
}
func podProcess(pod *corev1.Pod) (PodIdentity, bool) {
	identity := PodIdentity{Name: pod.Name, UID: string(pod.UID), Node: pod.Spec.NodeName}
	ready := pod.UID != "" && pod.Spec.NodeName != "" && pod.DeletionTimestamp == nil && pod.Status.Phase == corev1.PodRunning && len(pod.Spec.Containers) > 0 && len(pod.Status.ContainerStatuses) == len(pod.Spec.Containers)
	podReady := false
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
			podReady = true
		}
	}
	ready = ready && podReady
	for _, s := range pod.Status.ContainerStatuses {
		if s.ContainerID == "" || s.State.Running == nil || !s.Ready {
			ready = false
		}
		if s.ContainerID != "" {
			identity.Containers = append(identity.Containers, s.ContainerID)
		}
	}
	for _, s := range append(append([]corev1.ContainerStatus(nil), pod.Status.InitContainerStatuses...), pod.Status.EphemeralContainerStatuses...) {
		if s.State.Running != nil {
			if s.ContainerID == "" {
				ready = false
			} else {
				identity.Containers = append(identity.Containers, s.ContainerID)
			}
		}
	}
	return identity, ready
}
func (w *DeploymentWriter) Observe(ctx context.Context) (flow.State, error) {
	if err := w.ready(ctx); err != nil {
		return flow.State{}, err
	}
	if w.Guard(ctx, "observe", flow.State{UID: w.UID}) != nil {
		return flow.State{}, flow.ErrJournal
	}
	d, err := w.get(ctx)
	if err != nil {
		return flow.State{}, err
	}
	if d.Annotations[resumeFenceAnnotation] == w.FenceID {
		return flow.State{}, flow.ErrQuiesce
	}
	pods, ready, err := w.pods(ctx, d)
	if err != nil || !ready || len(pods) != int(*d.Spec.Replicas) || d.Status.ObservedGeneration < d.Generation || d.Status.ReadyReplicas != *d.Spec.Replicas {
		return flow.State{}, flow.ErrQuiesce
	}
	checkpoint := deploymentCheckpoint{Version: "deployment-quiesce.v1", Namespace: w.Namespace, Name: w.Name, FenceID: w.FenceID, SpecSHA256: deploymentHash(d), Replicas: *d.Spec.Replicas, Pods: pods}
	b, err := json.Marshal(checkpoint)
	if err != nil || len(b) > 128<<10 {
		return flow.State{}, flow.ErrQuiesce
	}
	s := flow.State{UID: w.UID, Generation: d.Generation, Running: *d.Spec.Replicas > 0, Checkpoint: string(b)}
	if w.Guard(ctx, "observed", s) != nil {
		return flow.State{}, flow.ErrJournal
	}
	return s, nil
}
func (w *DeploymentWriter) checkpoint(s flow.State) (deploymentCheckpoint, error) {
	var p deploymentCheckpoint
	if s.UID != w.UID || s.Generation <= 0 || len(s.Checkpoint) > 128<<10 || json.Unmarshal([]byte(s.Checkpoint), &p) != nil {
		return p, flow.ErrQuiesce
	}
	b, _ := json.Marshal(p)
	if string(b) != s.Checkpoint || p.Version != "deployment-quiesce.v1" || p.Namespace != w.Namespace || p.Name != w.Name || p.FenceID != w.FenceID || p.Replicas < 0 || p.Replicas > 1000 || s.Running != (p.Replicas > 0) || len(p.SpecSHA256) != 64 || len(p.Pods) != int(p.Replicas) {
		return p, flow.ErrQuiesce
	}
	seen := map[string]bool{}
	for _, pod := range p.Pods {
		if pod.Name == "" || pod.UID == "" || pod.Node == "" || len(pod.Containers) == 0 || seen[pod.UID] {
			return p, flow.ErrQuiesce
		}
		seen[pod.UID] = true
	}
	return p, nil
}
func (w *DeploymentWriter) matches(d *appsv1.Deployment, p deploymentCheckpoint) bool {
	return deploymentHash(d) == p.SpecSHA256
}
func (w *DeploymentWriter) patch(ctx context.Context, d *appsv1.Deployment, replicas int32, resume bool) error {
	ops := []map[string]any{{"op": "test", "path": "/metadata/uid", "value": string(d.UID)}, {"op": "test", "path": "/metadata/resourceVersion", "value": d.ResourceVersion}, {"op": "replace", "path": "/spec/replicas", "value": replicas}}
	if resume {
		if d.Annotations == nil {
			ops = append(ops, map[string]any{"op": "add", "path": "/metadata/annotations", "value": map[string]string{resumeFenceAnnotation: w.FenceID}})
		} else {
			ops = append(ops, map[string]any{"op": "add", "path": "/metadata/annotations/" + strings.ReplaceAll(resumeFenceAnnotation, "/", "~1"), "value": w.FenceID})
		}
	}
	b, _ := json.Marshal(ops)
	_, err := w.Client.AppsV1().Deployments(w.Namespace).Patch(ctx, w.Name, types.JSONPatchType, b, metav1.PatchOptions{})
	if err != nil {
		return flow.ErrQuiesce
	}
	return nil
}
func (w *DeploymentWriter) Pause(ctx context.Context, s flow.State) (flow.ACK, error) {
	if err := w.ready(ctx); err != nil {
		return flow.ACK{}, err
	}
	p, err := w.checkpoint(s)
	if err != nil {
		return flow.ACK{}, err
	}
	if w.Guard(ctx, "before-stop", s) != nil {
		return flow.ACK{}, flow.ErrJournal
	}
	d, err := w.get(ctx)
	if err != nil || !w.matches(d, p) || d.Annotations[resumeFenceAnnotation] == w.FenceID || (*d.Spec.Replicas != p.Replicas && *d.Spec.Replicas != 0) {
		return flow.ACK{}, flow.ErrQuiesce
	}
	if *d.Spec.Replicas != 0 {
		current, ready, e := w.pods(ctx, d)
		if e != nil || !ready || !samePods(current, p.Pods) {
			return flow.ACK{}, flow.ErrQuiesce
		}
		if err = w.patch(ctx, d, 0, false); err != nil {
			return flow.ACK{}, err
		}
	}
	if err = wait(ctx, w.PollInterval, func() (bool, error) { return w.stopped(ctx, s, p, false) }); err != nil {
		return flow.ACK{}, flow.ErrQuiesce
	}
	return flow.ACK{UID: s.UID, Generation: s.Generation, Stopped: true}, nil
}
func (w *DeploymentWriter) stopped(ctx context.Context, s flow.State, p deploymentCheckpoint, recovery bool) (bool, error) {
	point := "check-stopped"
	if recovery {
		point = "recovery-check-stopped"
	}
	if w.Guard(ctx, point, s) != nil {
		return false, flow.ErrJournal
	}
	d, err := w.get(ctx)
	if err != nil || !w.matches(d, p) || *d.Spec.Replicas != 0 || (!recovery && d.Annotations[resumeFenceAnnotation] == w.FenceID) {
		return false, flow.ErrQuiesce
	}
	pods, _, err := w.pods(ctx, d)
	if err != nil {
		return false, err
	}
	if len(pods) != 0 || d.Status.ObservedGeneration < d.Generation || d.Status.Replicas != 0 {
		return false, nil
	}
	if w.ConfirmStopped(ctx, s, p.Pods) != nil {
		return false, flow.ErrQuiesce
	}
	return true, nil
}
func (w *DeploymentWriter) CheckPaused(ctx context.Context, s flow.State) error {
	if err := w.ready(ctx); err != nil {
		return err
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
func (w *DeploymentWriter) Resume(ctx context.Context, s flow.State) error {
	if err := w.ready(ctx); err != nil {
		return flow.ErrResume
	}
	p, err := w.checkpoint(s)
	if err != nil {
		return flow.ErrResume
	}
	if w.Guard(ctx, "before-resume", s) != nil {
		return flow.ErrResume
	}
	d, err := w.get(ctx)
	if err != nil || !w.matches(d, p) || (*d.Spec.Replicas != 0 && *d.Spec.Replicas != p.Replicas) {
		return flow.ErrResume
	}
	if p.Replicas > 0 && *d.Spec.Replicas == 0 {
		if wait(ctx, w.PollInterval, func() (bool, error) { return w.stopped(ctx, s, p, true) }) != nil {
			return flow.ErrResume
		}
		// Refresh RV after waiting; do not send an old mutation across recovery.
		d, err = w.get(ctx)
		if err != nil || !w.matches(d, p) || *d.Spec.Replicas != 0 {
			return flow.ErrResume
		}
		if w.Guard(ctx, "before-resume", s) != nil {
			return flow.ErrResume
		}
	}
	// A unique durable recovery marker changes resourceVersion even if replicas
	// already equal the original value. Any delayed stop PATCH holding an old
	// RV is then rejected instead of stopping the source after reported recovery.
	if d.Annotations[resumeFenceAnnotation] != w.FenceID || *d.Spec.Replicas != p.Replicas {
		if w.patch(ctx, d, p.Replicas, true) != nil {
			return flow.ErrResume
		}
	}
	err = wait(ctx, w.PollInterval, func() (bool, error) {
		if w.Guard(ctx, "check-resumed", s) != nil {
			return false, flow.ErrResume
		}
		d, e := w.get(ctx)
		if e != nil || !w.matches(d, p) || *d.Spec.Replicas != p.Replicas || d.Annotations[resumeFenceAnnotation] != w.FenceID {
			return false, flow.ErrResume
		}
		pods, ready, e := w.pods(ctx, d)
		if e != nil {
			return false, e
		}
		if !ready || len(pods) != int(p.Replicas) || d.Status.ObservedGeneration < d.Generation || d.Status.ReadyReplicas != p.Replicas {
			return false, nil
		}
		if p.Replicas == 0 {
			if w.ConfirmStopped(ctx, s, p.Pods) != nil {
				return false, flow.ErrResume
			}
		} else if w.ConfirmResumed(ctx, s) != nil {
			return false, flow.ErrResume
		}
		return true, nil
	})
	if err != nil {
		return flow.ErrResume
	}
	return nil
}
func samePods(a, b []PodIdentity) bool {
	if len(a) != len(b) {
		return false
	}
	encode := func(pods []PodIdentity) []string {
		out := make([]string, 0, len(pods))
		for _, pod := range pods {
			pod.Containers = append([]string(nil), pod.Containers...)
			sort.Strings(pod.Containers)
			data, _ := json.Marshal(pod)
			out = append(out, string(data))
		}
		sort.Strings(out)
		return out
	}
	x, y := encode(a), encode(b)
	for idx := range x {
		if x[idx] != y[idx] {
			return false
		}
	}
	return true
}
func wait(ctx context.Context, interval time.Duration, check func() (bool, error)) error {
	if _, ok := ctx.Deadline(); !ok {
		return flow.ErrNotReady
	}
	if interval <= 0 || interval > time.Second {
		interval = 100 * time.Millisecond
	}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		done, err := check()
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
