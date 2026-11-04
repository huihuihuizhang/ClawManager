package install

import (
	"context"
	"reflect"
	"strings"
	"time"

	q "clawreef/internal/systembackup/quiesce"
	corev1 "k8s.io/api/core/v1"
)

// The shared native owner independently qualified actual loaded approved
// GoAgent/initial environment/CRI/private original journal/FLOCK and frozen
// complete source scope. Image/configuration data alone cannot enter here.
func classifyOriginalSharedRuntimePeer(ctx context.Context, p *PreparedOriginalAdoptionSQLCut, h *OriginalWriterHold, pod *corev1.Pod, spec *corev1.PodSpec, container *corev1.Container, status *corev1.ContainerStatus, until time.Time) (originalBackupStartupDisposition, error) {
	zero := originalBackupStartupDisposition{}
	if !originalEmptyHistoryOwner(ctx, p, h, false) || h.set == nil || pod == nil || spec == nil || container == nil || status == nil || !originalPeerContainerMatches(pod, spec, container, status, false) {
		return zero, ErrInstall
	}
	var actor *originalSharedRuntimeLifecycle
	for _, candidate := range h.set.sharedLifecycle {
		if candidate.source.row.UID == string(pod.UID) {
			if actor != nil {
				return zero, ErrInstall
			}
			actor = candidate
		}
	}
	if actor == nil {
		return zero, errOriginalBackupConsumerUnclassified
	}
	r := actor.request
	if actor.source.state == nil || actor.current == nil || actor.completed != nil || actor.agentResumeDispatched || len(r.AgentPod.Containers) != 1 || r.AgentPod.Containers[0] != status.ContainerID || r.AgentPod.UID != string(pod.UID) || r.Binding.OperationID != h.set.owner.operation || r.Binding.InventorySHA256 != h.set.inventorySHA || !reflect.DeepEqual(r.Original.Entries, actor.source.state.Entries) {
		return zero, ErrInstall
	}
	response := actor.current.Response()
	if actor.current.Recheck(ctx, r.Binding, "check-frozen", r.Original.BootID, r.Original.OriginalSHA256, r.Anchor, q.SharedRuntimeNodeCohortSHA(r), q.SharedRuntimeNodeSourcePathsSHA(r), time.Now().UTC()) != nil {
		return zero, ErrInstall
	}
	image := originalRuntimeImageForContainer(h.set.runtimeStartups, container, status)
	if image == nil || len(container.Args) != 0 || len(container.Command) != 0 && !reflect.DeepEqual(container.Command, []string{"/usr/local/bin/clawmanager-agent"}) || len(container.EnvFrom) != 0 {
		return zero, ErrInstall
	}
	// Preserve the existing content-authenticated finite startup decoder. The
	// native shared proof supplements loaded-state qualification; it must not
	// silently admit custom hooks/commands or unknown consumer environment.
	if _, _, err := decodeOriginalRuntimeStartup(image, spec, container); err != nil {
		return zero, err
	}
	for _, entry := range container.Env {
		if strings.HasPrefix(entry.Name, "SYSTEM_BACKUP_") {
			return zero, ErrInstall
		}
		if entry.Name == "RUNTIME_AGENT_ROLE" && (entry.ValueFrom != nil || entry.Value != "") {
			return zero, ErrInstall
		}
	}
	if response.ValidUntil.Before(until) {
		until = response.ValidUntil
	}
	if r.Binding.ExpiresAt.Before(until) {
		until = r.Binding.ExpiresAt
	}
	if !time.Now().Before(until) {
		return zero, ErrInstall
	}
	source := originalObjectSHA(struct {
		Version, Image, Runtime, PodUID, ContainerID, OriginalSHA256, CohortSHA256, SourcePathsSHA256 string
		Container                                                                                     corev1.Container
	}{"original-shared-runtime-fixed-startup-native.v1", image.source, image.runtime, string(pod.UID), status.ContainerID, r.Original.OriginalSHA256, q.SharedRuntimeNodeCohortSHA(r), q.SharedRuntimeNodeSourcePathsSHA(r), *container})
	return originalBackupStartupDisposition{kind: "original_non_backup_consumer", version: "original-held-shared-" + image.runtime + "-fixed-startup.v1", sourceSHA256: source, until: until}, nil
}
