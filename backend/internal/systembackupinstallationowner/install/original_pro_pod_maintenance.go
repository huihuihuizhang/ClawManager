package install

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strconv"
	"time"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/flow"
	q "clawreef/internal/systembackup/quiesce"
	"clawreef/internal/systembackup/staging"
	c "clawreef/internal/systembackupcontroller"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type OriginalProPodSelection struct {
	InstanceID  int
	RecoveryKey BootstrapSourceFilePin
}
type originalProPodMaintenance struct {
	owner                            *OriginalWriterMaintenance
	journal                          *originalWriterJournal
	source                           domain.SourceInstance
	key                              BootstrapSourceFilePin
	material                         staging.Receipt
	binding                          staging.Binding
	original                         flow.State
	process                          q.PodIdentity
	specSHA, plainSHA                string
	stopDispatched, createDispatched bool
	recovery                         *originalWriterRecoveryFence
}

func (w *originalProPodMaintenance) ID() string {
	return "pod/" + w.source.Namespace + "/" + w.source.Pod
}

func (p *OriginalWriterMaintenance) prepareProPod(ctx context.Context, source domain.SourceInstance, s OriginalProPodSelection, j *originalWriterJournal) (*originalProPodMaintenance, error) {
	if p.check(ctx) != nil || source.ID != s.InstanceID || source.Status != "running" || source.Namespace != p.operator.installer.plan.Target.Namespace || source.Pod == "" || j == nil {
		return nil, ErrInstall
	}
	for _, verb := range []string{"delete", "create", "patch"} {
		r, e := p.operator.installer.kube.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authorizationv1.SelfSubjectAccessReview{Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authorizationv1.ResourceAttributes{Namespace: source.Namespace, Verb: verb, Resource: "pods", Name: source.Pod}}}, metav1.CreateOptions{})
		if e != nil || !r.Status.Allowed || r.Status.Denied || r.Status.EvaluationError != "" {
			return nil, ErrInstall
		}
	}
	pod, err := p.operator.installer.kube.CoreV1().Pods(source.Namespace).Get(ctx, source.Pod, metav1.GetOptions{})
	if err != nil || len(pod.OwnerReferences) != 0 || len(pod.Finalizers) != 0 || pod.GenerateName != "" || pod.Labels["instance-id"] != strconv.Itoa(source.ID) || pod.Labels["user-id"] != strconv.Itoa(source.UserID) {
		return nil, ErrInstall
	}
	process, err := originalMaintenancePodIdentity(pod)
	if err != nil {
		return nil, ErrInstall
	}
	if pod.Spec.OS != nil && pod.Spec.OS.Name != corev1.Linux {
		return nil, ErrInstall
	}
	key, err := readBootstrapSourcePin(s.RecoveryKey, 32)
	defer clear(key)
	if err != nil || len(key) != 32 {
		return nil, ErrInstall
	}
	restart := pod.DeepCopy()
	restart.TypeMeta = metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"}
	restart.ObjectMeta = metav1.ObjectMeta{Name: pod.Name, Namespace: pod.Namespace, Labels: pod.Labels, Annotations: pod.Annotations}
	restart.Status = corev1.PodStatus{}
	plain, err := json.Marshal(restart)
	defer clear(plain)
	if err != nil || len(plain) > 7<<20 {
		return nil, ErrInstall
	}
	w := &originalProPodMaintenance{owner: p, journal: j, source: source, key: s.RecoveryKey, process: process, specSHA: originalObjectSHA(pod.Spec), plainSHA: hash(plain)}
	w.binding = staging.Binding{BackupID: p.operator.installer.plan.Target.InstallationID, Attempt: p.operation, Path: "original-pro-pod/" + strconv.Itoa(source.ID), CaptureContextHash: j.inventory, EnvelopeID: w.plainSHA}
	name := "original-pod-" + p.operation + "-" + strconv.Itoa(source.ID) + ".enc"
	if j.append(ctx, w.ID(), "original_pod_seal_send_unknown", nil, struct {
		Source            domain.SourceInstance
		Key               BootstrapSourceFilePin
		Binding           staging.Binding
		Name, PlainSHA256 string
	}{source, s.RecoveryKey, w.binding, name, w.plainSHA}) != nil {
		return nil, ErrInstall
	}
	err = staging.WithCustodyLock(ctx, j.root, func() error {
		var e error
		w.material, e = staging.SealFile(ctx, j.root, name, key, w.binding, func(out io.Writer) error { _, e := out.Write(plain); return e })
		return e
	})
	if err != nil {
		return nil, ErrInstall
	}
	if _, err = w.loadRestart(ctx); err != nil {
		return nil, ErrInstall
	}
	checkpoint, _ := json.Marshal(struct {
		Version    string
		Source     domain.SourceInstance
		Process    q.PodIdentity
		SpecSHA256 string
		Material   staging.Receipt
		Binding    staging.Binding
		Key        BootstrapSourceFilePin
	}{"original-pro-pod-checkpoint.v1", source, process, w.specSHA, w.material, w.binding, w.key})
	w.original = flow.State{UID: process.UID, Generation: int64(source.Generation), Running: true, Checkpoint: string(checkpoint)}
	if p.check(ctx) != nil || j.append(ctx, w.ID(), "original_pod_seal_readback", &w.original, w.material) != nil {
		return nil, ErrInstall
	}
	return w, nil
}

func (w *originalProPodMaintenance) loadRestart(ctx context.Context) (*corev1.Pod, error) {
	if originalMaintenanceReadCheck(ctx, w.owner, w.recovery) != nil {
		return nil, ErrInstall
	}
	key, err := readBootstrapSourcePin(w.key, 32)
	defer clear(key)
	if err != nil || len(key) != 32 {
		return nil, ErrInstall
	}
	f, err := staging.OpenFile(ctx, w.journal.root, w.material)
	if err != nil {
		return nil, ErrInstall
	}
	defer f.Close()
	var plain bytes.Buffer
	defer func() { clear(plain.Bytes()) }()
	if staging.Open(ctx, f, &plain, key, w.binding, 7<<20) != nil || hash(plain.Bytes()) != w.plainSHA {
		return nil, ErrInstall
	}
	var pod corev1.Pod
	d := json.NewDecoder(bytes.NewReader(plain.Bytes()))
	d.DisallowUnknownFields()
	if d.Decode(&pod) != nil || d.Decode(new(any)) != io.EOF || pod.Name != w.source.Pod || pod.Namespace != w.source.Namespace || pod.UID != "" || pod.ResourceVersion != "" || pod.DeletionTimestamp != nil || len(pod.OwnerReferences) != 0 || len(pod.Finalizers) != 0 || originalObjectSHA(pod.Spec) != w.specSHA || originalObjectSHA(pod.Status) != originalObjectSHA(corev1.PodStatus{}) {
		return nil, ErrInstall
	}
	return &pod, nil
}

func (w *originalProPodMaintenance) stop(ctx context.Context) error {
	if w.owner.checkCurrentGate(ctx, c.GateAcquiring) != nil || w.stopDispatched {
		return ErrInstall
	}
	k := w.owner.operator.installer.kube
	pod, err := k.CoreV1().Pods(w.source.Namespace).Get(ctx, w.source.Pod, metav1.GetOptions{})
	if err != nil || string(pod.UID) != w.original.UID || pod.ResourceVersion == "" || originalObjectSHA(pod.Spec) != w.specSHA {
		return ErrInstall
	}
	uid, rv := pod.UID, pod.ResourceVersion
	if w.journal.append(ctx, w.ID(), "delete_original_pod_send_unknown", &w.original, struct{ UID, RV string }{string(uid), rv}) != nil {
		return ErrInstall
	}
	w.stopDispatched = true
	_ = k.CoreV1().Pods(w.source.Namespace).Delete(ctx, w.source.Pod, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}})
	return w.waitAbsent(ctx)
}

func (w *originalProPodMaintenance) waitAbsent(ctx context.Context) error {
	for {
		pod, err := w.owner.operator.installer.kube.CoreV1().Pods(w.source.Namespace).Get(ctx, w.source.Pod, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil || string(pod.UID) != w.original.UID {
			return ErrInstall
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

// The holder sets this private recovery fence only after concrete archive
// workers stop and the old native scopes are re-observed as absent.
func (w *originalProPodMaintenance) restore(ctx context.Context, fence *originalWriterRecoveryFence) error {
	if fence == nil || fence.owner != w.owner || fence.journalSHA == "" || fence.checkReleasing(ctx) != nil {
		return ErrInstall
	}
	w.recovery = fence
	k := w.owner.operator.installer.kube
	pod, err := k.CoreV1().Pods(w.source.Namespace).Get(ctx, w.source.Pod, metav1.GetOptions{})
	if err == nil && string(pod.UID) == w.original.UID && pod.DeletionTimestamp != nil {
		if w.waitAbsent(ctx) != nil {
			return ErrInstall
		}
		pod = nil
		err = apierrors.NewNotFound(corev1.Resource("pods"), w.source.Pod)
	}
	if apierrors.IsNotFound(err) {
		if w.createDispatched {
			return ErrCommitUnknown
		}
		restart, e := w.loadRestart(ctx)
		if e != nil {
			return e
		}
		if restart.Annotations == nil {
			restart.Annotations = map[string]string{}
		}
		restart.Annotations[originalDeploymentRecoveryAnnotation] = w.owner.operation
		if w.journal.append(ctx, w.ID(), "create_original_pod_send_unknown", &w.original, w.material) != nil {
			return ErrInstall
		}
		w.createDispatched = true
		_, _ = k.CoreV1().Pods(w.source.Namespace).Create(ctx, restart, metav1.CreateOptions{})
	} else if err != nil {
		return ErrInstall
	} else {
		if originalObjectSHA(pod.Spec) != w.specSHA || len(pod.OwnerReferences) != 0 {
			return ErrInstall
		}
		if string(pod.UID) != w.original.UID && pod.Annotations[originalDeploymentRecoveryAnnotation] != w.owner.operation {
			return ErrInstall
		}
		// Change RV even when DELETE never took effect, fencing a delayed stop.
		if string(pod.UID) == w.original.UID {
			ops := []map[string]any{{"op": "test", "path": "/metadata/uid", "value": string(pod.UID)}, {"op": "test", "path": "/metadata/resourceVersion", "value": pod.ResourceVersion}}
			if pod.Annotations == nil {
				ops = append(ops, map[string]any{"op": "add", "path": "/metadata/annotations", "value": map[string]string{originalDeploymentRecoveryAnnotation: w.owner.operation}})
			} else {
				ops = append(ops, map[string]any{"op": "add", "path": "/metadata/annotations/backup.clawreef.io~1original-maintenance-recovery", "value": w.owner.operation})
			}
			raw, _ := json.Marshal(ops)
			if w.journal.append(ctx, w.ID(), "cancel_delayed_pod_delete_send_unknown", &w.original, hash(raw)) != nil {
				return ErrInstall
			}
			_, _ = k.CoreV1().Pods(w.source.Namespace).Patch(ctx, w.source.Pod, types.JSONPatchType, raw, metav1.PatchOptions{})
		}
	}
	for {
		current, e := k.CoreV1().Pods(w.source.Namespace).Get(ctx, w.source.Pod, metav1.GetOptions{})
		if e == nil {
			if originalObjectSHA(current.Spec) != w.specSHA || current.Annotations[originalDeploymentRecoveryAnnotation] != w.owner.operation || len(current.OwnerReferences) != 0 {
				return ErrInstall
			}
			if _, e = originalMaintenancePodIdentity(current); e == nil {
				return w.journal.append(ctx, w.ID(), "original_pro_pod_api_restored", &w.original, struct{ UID string }{string(current.UID)})
			}
		} else if !apierrors.IsNotFound(e) {
			return ErrInstall
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
