package quiesce

import "reflect"

// DATA shape only. The native owner must additionally match the independently
// installed template (or its own authenticated original journal on recovery),
// inspect this same original CRI process and open its actual NFS mount.
func validSharedRuntimeLonghornClient(r SharedRuntimeNodeRequest) bool {
	c := r.LonghornClient
	if c == nil || len(r.SourcePaths) != 0 || len(r.AgentPod.Containers) != 1 {
		return false
	}
	b := c.Binding
	identity, err := LonghornExt4SourceIdentity(c.OriginalSourceSHA256, c.ProviderNamespaceUID, b.NodeUID)
	return err == nil && identity == c.Identity && b.Kind == LonghornExt4Protocol && b.InstallationID == r.Binding.InstallationID &&
		b.Namespace == r.Binding.Namespace && b.NamespaceUID == r.Binding.NamespaceUID && b.Node == r.Binding.Node && b.NodeUID == r.Binding.NodeUID &&
		b.OperationID == "" && b.ReservationID == "" && b.InventorySHA256 == "" && b.Generation == 0 && b.FenceEpoch == 0 && b.ExpiresAt.IsZero() && c.Attempt == 0 && c.Claim == (LonghornExt4Claim{}) &&
		c.PVCName != "" && c.PVCUID != "" && c.PVUID != "" && c.VolumeHandle != "" && c.PodNamespace == b.Namespace &&
		c.PodName == r.AgentPod.Name && c.PodUID == r.AgentPod.UID && c.ContainerID == r.AgentPod.Containers[0] &&
		c.MountPoint == r.WorkspaceRoot && c.MountPoint != "/" && absoluteObservationPath(c.MountPoint) && c.NFSSource != "" && c.Endpoint != ""
}

func sharedRuntimeLonghornTemplate(c LonghornRWXClientCoordinates) LonghornRWXClientCoordinates {
	c.PodName, c.PodUID, c.ContainerID = "", "", ""
	return c
}

func sameSharedRuntimeSourceScope(a, b SharedRuntimeNodeRequest) bool {
	if a.LonghornClient == nil && b.LonghornClient == nil {
		return reflect.DeepEqual(a.SourcePaths, b.SourcePaths)
	}
	return validSharedRuntimeLonghornClient(a) && validSharedRuntimeLonghornClient(b) &&
		reflect.DeepEqual(sharedRuntimeLonghornTemplate(*a.LonghornClient), sharedRuntimeLonghornTemplate(*b.LonghornClient))
}
