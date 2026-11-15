//go:build linux

package quiesce

import "context"

// Node-derived while both original and keeper mounts are still qualified.
// This is retained in the authenticated native event, never accepted through
// LonghornExt4Request or inferred later from a replacement Pod.
type longhornExt4OriginalHolder struct {
	Namespace, PodName, PodUID, ContainerID string
	Process                                 observedProcess
}

func (o *NodeObserver) observeLonghornOriginalHolder(ctx context.Context, s LonghornExt4Source) (*longhornExt4OriginalHolder, error) {
	p, err := longhornExt4ProviderProcess(ctx, o, s)
	if err != nil || p.PID != s.MountOwnerPID || p.Start != s.MountOwnerStart || p.MountNamespace != s.MountNamespace || p.PIDNamespace == "" {
		return nil, ErrNodeObservation
	}
	p.Cgroup, err = observationPodCgroup(p.Cgroup, s.ProviderPodUID)
	if err != nil {
		return nil, err
	}
	return &longhornExt4OriginalHolder{Namespace: s.ProviderNamespace, PodName: s.ProviderPodName, PodUID: s.ProviderPodUID, ContainerID: s.ProviderContainerID, Process: p}, nil
}

func (o *NodeObserver) originalLonghornKeeperHolderExited(ctx context.Context, s LonghornExt4Source) error {
	h := s.OriginalHolder
	if s.Keeper == nil || h == nil || h.PodUID != s.Keeper.OriginalPodUID || h.Namespace != s.Binding.Namespace || h.PodName == "" || h.ContainerID == "" || h.PodUID == s.ProviderPodUID || h.ContainerID == s.ProviderContainerID {
		return observationFailure("longhorn_original_keeper_holder_required")
	}
	original := s
	original.ProviderNamespace, original.ProviderPodName = h.Namespace, h.PodName
	original.ProviderPodUID, original.ProviderContainerID = h.PodUID, h.ContainerID
	original.MountOwnerPID, original.MountOwnerStart, original.MountNamespace = h.Process.PID, h.Process.Start, h.Process.MountNamespace
	return o.originalLonghornContainerExited(ctx, original, h.Process)
}

// CRI EXITED and two complete native task scans must agree. Neither Pod API
// disappearance nor a missing/garbage-collected CRI record is exit evidence.
func (o *NodeObserver) originalLonghornContainerExited(ctx context.Context, s LonghornExt4Source, original observedProcess) error {
	if o == nil || ctx == nil || ctx.Err() != nil || s.Binding.Node != o.Node || original.PID <= 1 || original.PID != s.MountOwnerPID || original.Start == "" || original.Start != s.MountOwnerStart || original.MountNamespace == "" || original.MountNamespace != s.MountNamespace || original.PIDNamespace == "" || original.Cgroup == "" {
		return ErrNodeObservation
	}
	pod := PodIdentity{Name: s.ProviderPodName, UID: s.ProviderPodUID, Node: s.Binding.Node, Containers: []string{s.ProviderContainerID}}
	if (CRIProver{Node: o.Node, Inspector: o.CRI}).Confirm(ctx, []PodIdentity{pod}) != nil {
		return observationFailure("longhorn_original_container_exit_unconfirmed")
	}
	if _, _, err := o.scan(ctx, nodeObservationAnchor{Binding: s.Binding, BootID: o.BootID, Processes: []observedProcess{original}}, nil); err != nil {
		return err
	}
	return ctx.Err()
}
