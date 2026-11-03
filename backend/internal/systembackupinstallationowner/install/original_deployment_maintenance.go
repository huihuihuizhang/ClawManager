package install

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"clawreef/internal/systembackup/flow"
	q "clawreef/internal/systembackup/quiesce"
	c "clawreef/internal/systembackupcontroller"
	appsv1 "k8s.io/api/apps/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
)

type OriginalDeploymentSelection struct{ Name, UID, Role string }
type originalDeploymentMaintenance struct {
	owner          *OriginalWriterMaintenance
	journal        *originalWriterJournal
	selection      OriginalDeploymentSelection
	namespace      string
	original       flow.State
	replicas       int32
	specSHA        string
	pods           []q.PodIdentity
	stopDispatched bool
	recovery       *originalWriterRecoveryFence
}

const originalDeploymentRecoveryAnnotation = "backup.clawreef.io/original-maintenance-recovery"

func originalDeploymentSpecSHA(d *appsv1.Deployment) string {
	spec := d.Spec.DeepCopy()
	spec.Replicas = nil
	return originalObjectSHA(spec)
}
func (w *originalDeploymentMaintenance) ID() string {
	return "deployment/" + w.namespace + "/" + w.selection.Name
}

func (p *OriginalWriterMaintenance) prepareDeployment(ctx context.Context, s OriginalDeploymentSelection, j *originalWriterJournal) (*originalDeploymentMaintenance, error) {
	if p.check(ctx) != nil || s.Name == "" || s.UID == "" || s.Role != "writer" || j == nil {
		return nil, ErrInstall
	}
	ns := p.operator.installer.plan.Target.Namespace
	r, err := p.operator.installer.kube.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authorizationv1.SelfSubjectAccessReview{Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authorizationv1.ResourceAttributes{Namespace: ns, Verb: "patch", Group: "apps", Resource: "deployments", Name: s.Name}}}, metav1.CreateOptions{})
	if err != nil || !r.Status.Allowed || r.Status.Denied || r.Status.EvaluationError != "" {
		return nil, ErrInstall
	}
	d, err := p.operator.installer.kube.AppsV1().Deployments(ns).Get(ctx, s.Name, metav1.GetOptions{})
	if err != nil || string(d.UID) != s.UID || d.ResourceVersion == "" || d.DeletionTimestamp != nil || d.Spec.Replicas == nil || *d.Spec.Replicas < 0 || *d.Spec.Replicas > 1000 || d.Status.ObservedGeneration < d.Generation || d.Status.ReadyReplicas != *d.Spec.Replicas || d.Annotations[originalDeploymentRecoveryAnnotation] == p.operation {
		return nil, ErrInstall
	}
	w := &originalDeploymentMaintenance{owner: p, journal: j, selection: s, namespace: ns, replicas: *d.Spec.Replicas, specSHA: originalDeploymentSpecSHA(d)}
	w.pods, err = w.currentPods(ctx, d, true)
	if err != nil || len(w.pods) != int(w.replicas) {
		return nil, ErrInstall
	}
	checkpoint, _ := json.Marshal(struct {
		Version, Namespace, Name, SpecSHA256 string
		Replicas                             int32
		Pods                                 []q.PodIdentity
	}{"original-deployment-checkpoint.v1", ns, s.Name, w.specSHA, w.replicas, w.pods})
	w.original = flow.State{UID: s.UID, Generation: d.Generation, Running: w.replicas > 0, Checkpoint: string(checkpoint)}
	return w, nil
}

// All ordinary containers and restartable init containers are accounted for.
// An unknown/restarting process status is a refusal, never an empty CRI list.
func originalMaintenancePodIdentity(p *corev1.Pod) (q.PodIdentity, error) {
	var out q.PodIdentity
	if p == nil || p.UID == "" || p.Spec.NodeName == "" || p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning || len(p.Spec.EphemeralContainers) != 0 || len(p.Status.ContainerStatuses) != len(p.Spec.Containers) {
		return out, ErrInstall
	}
	out = q.PodIdentity{Name: p.Name, UID: string(p.UID), Node: p.Spec.NodeName}
	statuses := append([]corev1.ContainerStatus(nil), p.Status.ContainerStatuses...)
	for _, s := range p.Status.InitContainerStatuses {
		if s.State.Running != nil {
			statuses = append(statuses, s)
		} else if s.State.Terminated == nil {
			return q.PodIdentity{}, ErrInstall
		}
	}
	for _, s := range statuses {
		if s.ContainerID == "" || s.State.Running == nil || !s.Ready {
			return q.PodIdentity{}, ErrInstall
		}
		out.Containers = append(out.Containers, s.ContainerID)
	}
	sort.Strings(out.Containers)
	if len(out.Containers) == 0 {
		return q.PodIdentity{}, ErrInstall
	}
	return out, nil
}

func (w *originalDeploymentMaintenance) currentPods(ctx context.Context, d *appsv1.Deployment, ready bool) ([]q.PodIdentity, error) {
	selector, err := metav1.LabelSelectorAsSelector(d.Spec.Selector)
	if err != nil || selector.Empty() {
		return nil, ErrInstall
	}
	all, err := w.owner.operator.installer.kube.CoreV1().Pods(w.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, ErrInstall
	}
	var out []q.PodIdentity
	for n := range all.Items {
		p := &all.Items[n]
		if !selector.Matches(labels.Set(p.Labels)) {
			continue
		}
		if len(p.OwnerReferences) != 1 || p.OwnerReferences[0].Kind != "ReplicaSet" || p.OwnerReferences[0].Controller == nil || !*p.OwnerReferences[0].Controller {
			return nil, ErrInstall
		}
		rs, err := w.owner.operator.installer.kube.AppsV1().ReplicaSets(w.namespace).Get(ctx, p.OwnerReferences[0].Name, metav1.GetOptions{})
		if err != nil || rs.UID != p.OwnerReferences[0].UID || len(rs.OwnerReferences) != 1 || rs.OwnerReferences[0].UID != d.UID || rs.OwnerReferences[0].Kind != "Deployment" {
			return nil, ErrInstall
		}
		if !ready {
			out = append(out, q.PodIdentity{Name: p.Name, UID: string(p.UID), Node: p.Spec.NodeName})
			continue
		}
		identity, err := originalMaintenancePodIdentity(p)
		if err != nil {
			return nil, ErrInstall
		}
		out = append(out, identity)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UID < out[j].UID })
	return out, nil
}

func (w *originalDeploymentMaintenance) current(ctx context.Context) (*appsv1.Deployment, error) {
	if w == nil || originalMaintenanceReadCheck(ctx, w.owner, w.recovery) != nil {
		return nil, ErrInstall
	}
	d, err := w.owner.operator.installer.kube.AppsV1().Deployments(w.namespace).Get(ctx, w.selection.Name, metav1.GetOptions{})
	if err != nil || string(d.UID) != w.selection.UID || d.ResourceVersion == "" || d.DeletionTimestamp != nil || d.Spec.Replicas == nil || originalDeploymentSpecSHA(d) != w.specSHA {
		return nil, ErrInstall
	}
	return d, nil
}

func (w *originalDeploymentMaintenance) patch(ctx context.Context, d *appsv1.Deployment, replicas int32, recovery bool) error {
	if d == nil || string(d.UID) != w.selection.UID {
		return ErrInstall
	}
	if recovery {
		if w.recovery == nil || w.recovery.checkReleasing(ctx) != nil {
			return ErrInstall
		}
	} else if w.recovery != nil || w.owner.checkCurrentGate(ctx, c.GateAcquiring) != nil {
		return ErrInstall
	}
	if recovery && (w.recovery == nil || w.recovery.owner != w.owner) {
		return ErrInstall
	}
	ops := []map[string]any{{"op": "test", "path": "/metadata/uid", "value": string(d.UID)}, {"op": "test", "path": "/metadata/resourceVersion", "value": d.ResourceVersion}, {"op": "replace", "path": "/spec/replicas", "value": replicas}}
	if recovery {
		if d.Annotations == nil {
			ops = append(ops, map[string]any{"op": "add", "path": "/metadata/annotations", "value": map[string]string{originalDeploymentRecoveryAnnotation: w.owner.operation}})
		} else {
			ops = append(ops, map[string]any{"op": "add", "path": "/metadata/annotations/" + strings.ReplaceAll(originalDeploymentRecoveryAnnotation, "/", "~1"), "value": w.owner.operation})
		}
	}
	raw, _ := json.Marshal(ops)
	action := "scale_zero_send_unknown"
	if recovery {
		action = "restore_replicas_send_unknown"
	}
	if w.journal.append(ctx, w.ID(), action, &w.original, struct {
		UID, RV     string
		Replicas    int32
		PatchSHA256 string
	}{string(d.UID), d.ResourceVersion, replicas, hash(raw)}) != nil {
		return ErrInstall
	}
	_, err := w.owner.operator.installer.kube.AppsV1().Deployments(w.namespace).Patch(ctx, w.selection.Name, types.JSONPatchType, raw, metav1.PatchOptions{})
	if err != nil {
		return ErrInstall
	}
	if recovery {
		return w.recovery.checkReleasing(ctx)
	}
	return w.owner.checkCurrentGate(ctx, c.GateAcquiring)
}

// This is dispatch/readback, deliberately not a native stopped ACK. The full
// owner stops ALL writers before B's complete FD/mmap/namespace observation.
func (w *originalDeploymentMaintenance) stop(ctx context.Context) error {
	if w.owner.checkCurrentGate(ctx, c.GateAcquiring) != nil || w.stopDispatched {
		return ErrInstall
	}
	d, err := w.current(ctx)
	if err != nil || *d.Spec.Replicas != w.replicas {
		return ErrInstall
	}
	w.stopDispatched = true
	if w.replicas > 0 {
		_ = w.patch(ctx, d, 0, false)
	}
	return w.wait(ctx, false)
}

func (w *originalDeploymentMaintenance) wait(ctx context.Context, recovery bool) error {
	for {
		d, err := w.current(ctx)
		if err != nil {
			return ErrInstall
		}
		expected := int32(0)
		if recovery {
			expected = w.replicas
		}
		if *d.Spec.Replicas != expected {
			return ErrInstall
		}
		pods, err := w.currentPods(ctx, d, recovery)
		if err != nil {
			return ErrInstall
		}
		if d.Status.ObservedGeneration >= d.Generation && d.Status.Replicas == expected && d.Status.ReadyReplicas == expected && len(pods) == int(expected) {
			if recovery && d.Annotations[originalDeploymentRecoveryAnnotation] != w.owner.operation {
				return ErrInstall
			}
			return nil
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ErrInstall
		case <-timer.C:
		}
	}
}

func (w *originalDeploymentMaintenance) restore(ctx context.Context, fence *originalWriterRecoveryFence) error {
	if fence == nil || fence.owner != w.owner || fence.journalSHA == "" || fence.checkReleasing(ctx) != nil {
		return ErrInstall
	}
	w.recovery = fence
	d, err := w.current(ctx)
	if err != nil || *d.Spec.Replicas != 0 && *d.Spec.Replicas != w.replicas {
		return ErrInstall
	}
	// Even an original zero gets a new RV marker. Delayed old stop requests
	// cannot cross this exact recovery boundary after readback.
	_ = w.patch(ctx, d, w.replicas, true)
	return w.wait(ctx, true)
}
