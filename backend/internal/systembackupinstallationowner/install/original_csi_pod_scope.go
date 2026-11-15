package install

import (
	"context"
	"reflect"
	"time"

	q "clawreef/internal/systembackup/quiesce"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// A concrete link to this prepared set's real source actor, not a path, native
// observation, grant or caller assertion. Current site Pods have one CSI volume
// and one ordinary container; other storage shapes remain closed.
type originalCSIPodScope struct {
	set                   *PreparedOriginalWriterSet
	pod                   q.PodIdentity
	class                 originalPodVolumeClass
	pin                   originalPhysicalVolumePin
	namespaceUID, nodeUID string
	specSHA               string
	rwx                   *originalLonghornRWXHold
	client                originalLonghornRWXClient
	keeper                *originalLonghornKeeper
}

func (s *PreparedOriginalWriterSet) prepareCSIPodScope(ctx context.Context, pod *core.Pod, classes []originalPodVolumeClass) (*originalCSIPodScope, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || s.owner == nil || s.owner.operator == nil || s.owner.operator.installer == nil || s.longhornMaterials == nil || pod == nil || pod.Namespace == "" || pod.Name == "" || pod.UID == "" || pod.Spec.NodeName == "" || pod.DeletionTimestamp != nil || len(classes) != 1 || len(pod.Spec.Containers) != 1 || len(pod.Status.ContainerStatuses) != 1 || len(pod.Spec.EphemeralContainers) != 0 || len(pod.Status.InitContainerStatuses) != len(pod.Spec.InitContainers) {
		return nil, ErrInstall
	}
	for _, status := range pod.Status.InitContainerStatuses {
		if status.State.Terminated == nil || status.State.Terminated.ExitCode != 0 {
			return nil, ErrInstall
		}
	}
	status := pod.Status.ContainerStatuses[0]
	if status.Name != pod.Spec.Containers[0].Name || status.State.Running == nil || status.ContainerID == "" || !status.Ready {
		return nil, ErrInstall
	}
	v := classes[0]
	source, found := s.longhornSources[pod.Namespace+"/"+v.ClaimName]
	if v.Kind != originalPodVolumeLonghorn || !found || source.PVCUID != v.ClaimUID || source.PVUID != v.PVUID || source.VolumeHandle != v.Handle {
		return nil, ErrInstall
	}
	mounts, err := originalPodVolumeMounts(pod, v.VolumeName)
	if err != nil || len(mounts) != 1 || mounts[0].Container != status.Name || mounts[0].SubPath != "" {
		return nil, ErrInstall
	}
	k := s.owner.operator.installer.kube
	actual, err := k.CoreV1().Pods(pod.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
	if err != nil || actual.UID != pod.UID || actual.DeletionTimestamp != nil || originalObjectSHA(actual.Spec) != originalObjectSHA(pod.Spec) || len(actual.Status.ContainerStatuses) != 1 || actual.Status.ContainerStatuses[0].ContainerID != status.ContainerID || actual.Status.ContainerStatuses[0].State.Running == nil || !actual.Status.ContainerStatuses[0].Ready {
		return nil, ErrInstall
	}
	ns, err := k.CoreV1().Namespaces().Get(ctx, pod.Namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != source.Binding.NamespaceUID || ns.DeletionTimestamp != nil {
		return nil, ErrInstall
	}
	node, err := k.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
	if err != nil || node.UID == "" || node.DeletionTimestamp != nil {
		return nil, ErrInstall
	}
	claim, err := k.CoreV1().PersistentVolumeClaims(pod.Namespace).Get(ctx, v.ClaimName, metav1.GetOptions{})
	if err != nil || string(claim.UID) != v.ClaimUID || claim.Spec.VolumeName != v.PVName || claim.DeletionTimestamp != nil || claim.Status.Phase != core.ClaimBound {
		return nil, ErrInstall
	}
	pv, err := k.CoreV1().PersistentVolumes().Get(ctx, v.PVName, metav1.GetOptions{})
	if err != nil || string(pv.UID) != v.PVUID || pv.DeletionTimestamp != nil || pv.Spec.CSI == nil || pv.Spec.CSI.Driver != "driver.longhorn.io" || pv.Spec.CSI.VolumeHandle != v.Handle || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID != claim.UID || pv.Spec.ClaimRef.Namespace != pod.Namespace || pv.Spec.ClaimRef.Name != claim.Name {
		return nil, ErrInstall
	}
	scope := &originalCSIPodScope{set: s, pod: q.PodIdentity{Name: pod.Name, UID: string(pod.UID), Node: pod.Spec.NodeName, Containers: []string{status.ContainerID}}, class: v, namespaceUID: string(ns.UID), nodeUID: string(node.UID), specSHA: originalObjectSHA(pod.Spec), pin: originalPhysicalVolumePin{pod.Namespace, claim.Name, string(claim.UID), originalObjectSHA(claim.Spec), pv.Name, string(pv.UID), originalObjectSHA(pv.Spec), pod.Spec.NodeName}}
	for _, actor := range s.longhornRWX {
		if actor == nil || actor.set != s {
			return nil, ErrInstall
		}
		if !reflect.DeepEqual(actor.source, source) {
			continue
		}
		if !reflect.DeepEqual(pv.Spec.AccessModes, []core.PersistentVolumeAccessMode{core.ReadWriteMany}) {
			return nil, ErrInstall
		}
		for _, client := range actor.clients {
			if client.PodUID != scope.pod.UID || client.ContainerID != status.ContainerID {
				continue
			}
			if scope.rwx != nil || client.PodName != pod.Name || client.Template.PodNamespace != pod.Namespace || client.Template.Binding.Node != pod.Spec.NodeName || client.Template.Binding.NodeUID != scope.nodeUID || client.Template.PVCUID != v.ClaimUID || client.Template.PVUID != v.PVUID || client.Template.VolumeHandle != v.Handle || client.Volume != v.VolumeName || client.ContainerName != status.Name || client.Template.MountPoint != mounts[0].MountPath || client.SpecSHA != scope.specSHA {
				return nil, ErrInstall
			}
			scope.rwx, scope.client = actor, client
		}
	}
	for _, keeper := range s.longhornKeepers {
		if keeper == nil || keeper.set != s {
			return nil, ErrInstall
		}
		if keeper.plan.Identity.Namespace != pod.Namespace || keeper.plan.Source.Name != v.ClaimName {
			continue
		}
		if !reflect.DeepEqual(pv.Spec.AccessModes, []core.PersistentVolumeAccessMode{core.ReadWriteOnce}) {
			return nil, ErrInstall
		}
		if scope.rwx != nil || scope.keeper != nil || keeper.writer == nil || keeper.plan.Source.UID != v.ClaimUID || keeper.plan.Source.PVUID != v.PVUID || keeper.plan.Node != pod.Spec.NodeName || keeper.plan.NodeUID != scope.nodeUID || len(keeper.writer.pods) != 1 || !reflect.DeepEqual(keeper.writer.pods[0], scope.pod) || source.ProviderPodUID != scope.pod.UID || source.ProviderContainerID != status.ContainerID || source.MountPoint != mounts[0].MountPath {
			return nil, ErrInstall
		}
		scope.keeper = keeper
	}
	if (scope.rwx == nil) == (scope.keeper == nil) {
		return nil, OriginalWriterSourceFailure{Dependency: "original_csi_physical_actor_required"}
	}
	for _, old := range s.csiPods {
		if old.pod.UID == scope.pod.UID {
			if !reflect.DeepEqual(old, scope) {
				return nil, ErrInstall
			}
			return old, nil
		}
	}
	s.csiPods = append(s.csiPods, scope)
	return scope, nil
}

func (s *PreparedOriginalWriterSet) csiPodScope(uid string) *originalCSIPodScope {
	for _, scope := range s.csiPods {
		if scope.pod.UID == uid {
			return scope
		}
	}
	return nil
}

func (p *originalCSIPodScope) sharedClient() (*q.LonghornRWXClientCoordinates, error) {
	if p == nil || p.rwx == nil || p.keeper != nil || p.rwx.clientIsColdWriter(p.client) {
		return nil, ErrInstall
	}
	c := p.client.Template
	c.PodName, c.PodUID, c.ContainerID = p.client.PodName, p.client.PodUID, p.client.ContainerID
	return &c, nil
}

func (s *PreparedOriginalWriterSet) recheckCSIResourcePins(ctx context.Context) error {
	if len(s.csiPods) == 0 {
		return nil
	}
	k := s.owner.operator.installer.kube
	for _, scope := range s.csiPods {
		p := scope.pin
		claim, err := k.CoreV1().PersistentVolumeClaims(p.Namespace).Get(ctx, p.ClaimName, metav1.GetOptions{})
		if err != nil || string(claim.UID) != p.ClaimUID || claim.DeletionTimestamp != nil || originalObjectSHA(claim.Spec) != p.ClaimSpecSHA256 {
			return ErrInstall
		}
		pv, err := k.CoreV1().PersistentVolumes().Get(ctx, p.PVName, metav1.GetOptions{})
		if err != nil || string(pv.UID) != p.PVUID || pv.DeletionTimestamp != nil || originalObjectSHA(pv.Spec) != p.PVSpecSHA256 {
			return ErrInstall
		}
		ns, err := k.CoreV1().Namespaces().Get(ctx, p.Namespace, metav1.GetOptions{})
		if err != nil || string(ns.UID) != scope.namespaceUID || ns.DeletionTimestamp != nil {
			return ErrInstall
		}
		node, err := k.CoreV1().Nodes().Get(ctx, p.Node, metav1.GetOptions{})
		if err != nil || string(node.UID) != scope.nodeUID || node.DeletionTimestamp != nil {
			return ErrInstall
		}
	}
	return nil
}

func (s *PreparedOriginalWriterSet) recheckCSIPodsHeld(now time.Time) error {
	for _, scope := range s.csiPods {
		if scope.set != s {
			return ErrInstall
		}
		if scope.keeper != nil {
			h := scope.keeper
			if h.recheckHeld(now) != nil || h.registration == nil || h.registration.Keeper == nil || h.registration.Keeper.OriginalPodUID != scope.pod.UID {
				return ErrInstall
			}
			continue
		}
		h := scope.rwx
		if h == nil || h.recheckHeld(now) != nil || len(h.synced) != len(h.clients) {
			return ErrInstall
		}
		matched := false
		for _, synced := range h.synced {
			if synced.ClientPodUID == scope.pod.UID && synced.ClientContainerID == scope.pod.Containers[0] && synced.SourceIdentity == scope.client.Template.Identity && synced.ClientMustExit == h.clientIsColdWriter(scope.client) {
				matched = true
			}
		}
		if !matched {
			return ErrInstall
		}
		if !h.clientIsColdWriter(scope.client) {
			client, err := scope.sharedClient()
			if err != nil {
				return err
			}
			frozen := false
			for _, actor := range s.sharedLifecycle {
				if reflect.DeepEqual(actor.request.AgentPod, scope.pod) && reflect.DeepEqual(actor.request.LonghornClient, client) && actor.current != nil && actor.current.Response().Phase == "frozen" {
					frozen = true
				}
			}
			if !frozen {
				return ErrInstall
			}
		}
	}
	return nil
}
