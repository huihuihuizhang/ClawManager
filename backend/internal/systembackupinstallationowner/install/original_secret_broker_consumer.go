package install

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// Called by D's genuine finite consumer dispatcher BEFORE the existing view/C
// classifiers. Unknown images return the existing unclassified sentinel. This
// known original image with an unknown selected launch refuses, never falls
// through to the fix18 server or a role/name exemption.
func classifyOriginalSecretBrokerStartup(ctx context.Context, p *PreparedOriginalAdoptionSQLCut, h *OriginalWriterHold, pod *corev1.Pod, spec *corev1.PodSpec, c *corev1.Container, status *corev1.ContainerStatus, init bool) (originalBackupStartupDisposition, error) {
	zero := originalBackupStartupDisposition{}
	if c == nil || spec == nil {
		return zero, ErrInstall
	}
	if c.Image != originalSecretBrokerImage && (status == nil || status.ImageID != originalSecretBrokerImage) {
		return zero, errOriginalBackupConsumerUnclassified
	}
	if !originalEmptyHistoryOwner(ctx, p, h, false) || p.used || h.set.historyMounted == nil || !h.set.historyMounted.local(ctx) || h.set.historyMounted.installer != p.operator.installer || c.Image != originalSecretBrokerImage {
		return zero, ErrInstall
	}
	namespace := p.operator.installer.plan.Target.Namespace
	actualSpec, actualContainer := spec, c
	if pod != nil {
		actual, err := originalPeerCapturedPod(h, pod)
		if err != nil || actual.Namespace != namespace || status == nil || !originalPeerContainerMatches(actual, spec, c, status, init) || status.ImageID != originalSecretBrokerImage {
			return zero, ErrInstall
		}
		actualSpec = &actual.Spec
		list := actual.Spec.Containers
		if init {
			list = actual.Spec.InitContainers
		}
		actualContainer = nil
		for n := range list {
			if list[n].Name == c.Name {
				if actualContainer != nil {
					return zero, ErrInstall
				}
				actualContainer = &list[n]
			}
		}
		if actualContainer == nil {
			return zero, ErrInstall
		}
	} else {
		// A genuine retained immutable template can be classified independently.
		// It cannot borrow a current Pod status or synthesize a historical ImageID.
		if status != nil {
			return zero, ErrInstall
		}
		list := spec.Containers
		if init {
			list = spec.InitContainers
		}
		count := 0
		for _, x := range list {
			if x.Name == c.Name {
				if !reflect.DeepEqual(x, *c) {
					return zero, ErrInstall
				}
				count++
			}
		}
		if count != 1 {
			return zero, ErrInstall
		}
	}
	if !originalSecretBrokerStartupEntry(namespace, actualSpec, actualContainer, init) {
		return zero, ErrInstall
	}
	until := p.until
	for _, cap := range []time.Time{h.set.owner.until, h.set.historyMounted.until, p.reservation.ExpiresAt} {
		if cap.IsZero() {
			return zero, ErrInstall
		}
		if cap.Before(until) {
			until = cap
		}
	}
	deadline, bounded := ctx.Deadline()
	if !bounded {
		return zero, ErrInstall
	}
	if deadline.Before(until) {
		until = deadline
	}
	if !time.Now().Before(until) {
		return zero, ErrInstall
	}
	version := originalSecretBrokerProfile
	if init {
		version = "original-secret-broker-fixed-openssl-wait.v1"
	}
	source := originalObjectSHA(struct {
		Version, MainSHA, WaitSourceSHA, Namespace, MountedRevision string
		Spec                                                        corev1.PodSpec
		Container                                                   corev1.Container
		Pod                                                         *corev1.Pod
		Status                                                      *corev1.ContainerStatus
	}{version, originalSecretBrokerMainSHA, originalSecretBrokerWaitSourceSHA, namespace, h.set.historyMounted.revision, *spec, *c, pod, status})
	return originalBackupStartupDisposition{kind: "original_non_backup_consumer", version: version, sourceSHA256: source, until: until}, nil
}

// Actual retained original-Pod reader. Caller holds set.mu -> p.mu, outside
// final SQL. No current template/inspection JSON substitutes for the old Pod.
func readOriginalSecretBrokerConsumerLocked(ctx context.Context, p *PreparedOriginalAdoptionSQLCut, h *OriginalWriterHold, podName, container string, init bool) (originalBackupHistoryConsumer, error) {
	zero := originalBackupHistoryConsumer{}
	if !originalEmptyHistoryOwner(ctx, p, h, false) || h.set.historyMounted == nil || h.recheckBeforeSQL(ctx) != nil || p.operator.authority(ctx, p.enrollment) != nil {
		return zero, ErrInstall
	}
	source := h.set.historyMounted
	if source.origin != source || !source.local(ctx) || source.installer != p.operator.installer {
		return zero, ErrInstall
	}
	namespace := p.operator.installer.plan.Target.Namespace
	key := "Pod/" + namespace + "/" + podName
	object := source.objects[key]
	if object == nil || object.kind != "Pod" || object.namespace != namespace || object.name != podName || object.uid == "" || object.resourceVersion == "" || hash(object.body) != object.digest {
		return zero, ErrInstall
	}
	var pod corev1.Pod
	if json.Unmarshal(object.body, &pod) != nil || string(pod.UID) != object.uid || pod.ResourceVersion != object.resourceVersion || pod.Namespace != namespace || pod.Name != podName {
		return zero, ErrInstall
	}
	list, statuses := pod.Spec.Containers, pod.Status.ContainerStatuses
	if init {
		list, statuses = pod.Spec.InitContainers, pod.Status.InitContainerStatuses
	}
	var selected *corev1.Container
	for n := range list {
		if list[n].Name == container {
			if selected != nil {
				return zero, ErrInstall
			}
			selected = &list[n]
		}
	}
	if selected == nil {
		return zero, ErrInstall
	}
	status := originalContainerStatus(statuses, container)
	disposition, err := classifyOriginalSecretBrokerStartup(ctx, p, h, &pod, &pod.Spec, selected, status, init)
	if err != nil || h.recheckBeforeSQL(ctx) != nil || p.operator.authority(ctx, p.enrollment) != nil || !source.local(ctx) || h.set.historyMounted != source || source.objects[key] != object || hash(object.body) != object.digest {
		return zero, ErrInstall
	}
	return originalBackupHistoryConsumer{id: string(pod.UID) + "/" + container, kind: disposition.kind, sourceVersion: disposition.version, sourceSHA256: disposition.sourceSHA256}, nil
}
