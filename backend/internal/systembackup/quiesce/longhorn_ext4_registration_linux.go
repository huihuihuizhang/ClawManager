//go:build linux

package quiesce

import (
	"context"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// Registration is an authenticated command from the existing controller after
// its concrete current gate/claim check. Paths and provider identities remain
// installation inputs. The boundary digest is retained as correlation data.
func longhornExt4RegistrationMatches(installed LonghornExt4Source, r LonghornExt4Request) bool {
	a, b := installed.Binding, r.Binding
	return r.Claim.valid() && r.Attempt > 0 && b.OperationID != "" && b.Generation > 0 &&
		validObservationHash(b.InventorySHA256) && !b.ExpiresAt.IsZero() &&
		a.Kind == b.Kind && a.InstallationID == b.InstallationID && a.Namespace == b.Namespace &&
		a.NamespaceUID == b.NamespaceUID && a.Node == b.Node && a.NodeUID == b.NodeUID &&
		installed.Identity == r.SourceIdentity
}

func (a *longhornExt4Actions) sourceForRequest(ctx context.Context, r LonghornExt4Request) (string, error) {
	template, ok := a.templates[r.SourceIdentity]
	if !ok || !longhornExt4RegistrationMatches(template, r) || r.ClientPodUID != "" || r.ClientPodName != "" || r.ClientContainerID != "" {
		return "", ErrNodeObservation
	}
	if r.Action == "register" && !validObservationHash(r.RegistrationBoundarySHA256) {
		return "", ErrNodeObservation
	}
	for key, source := range a.sources {
		// The same registration cannot replace a previously authenticated
		// process or fall back to the original writer after handover.
		if source.Keeper == nil || source.Identity != r.SourceIdentity || source.Attempt != r.Attempt ||
			observationDigest(source.Claim) != observationDigest(r.Claim) || observationDigest(source.Binding) != observationDigest(r.Binding) {
			continue
		}
		if !longhornExt4RequestMatches(source, r) {
			return "", ErrNodeObservation
		}
		return key, nil
	}
	source := template
	source.Binding, source.Attempt, source.Claim = r.Binding, r.Attempt, r.Claim
	templateKey := longhornExt4SourceKey(template)
	volume, ok := a.volumes[templateKey]
	if !ok {
		return "", ErrNodeObservation
	}
	if r.Keeper != nil {
		// A recovery request can reopen the exact keeper to reconcile a
		// lost register reply. The normal device and journal checks still
		// apply, and reopening never restores ownership of a freeze.
		if (r.Action != "register" && r.Action != "release") || len(a.sources) >= 1024 {
			return "", ErrNodeObservation
		}
		return a.registerKeeperSource(ctx, r, template, volume)
	}
	key := longhornExt4SourceKey(source)
	if _, exists := a.sources[key]; !exists && len(a.sources) >= 1024 {
		return "", ErrNodeObservation
	}
	if r.Action == "register" {
		if err := a.checkDeviceObligations(key, source); err != nil {
			return "", err
		}
	}
	a.sources[key], a.volumes[key] = source, volume
	return key, nil
}

func (a *longhornExt4Actions) registerKeeperSource(ctx context.Context, r LonghornExt4Request, original LonghornExt4Source, originalVolume longhornExt4Volume) (string, error) {
	keeper := *r.Keeper
	if r.Claim.TaskPublicID != r.Binding.OperationID || !validObservationHash(r.Binding.ReservationID) || r.Binding.FenceEpoch == 0 ||
		keeper.OriginalPodUID != original.ProviderPodUID ||
		keeper.PodUID == "" || keeper.PodUID == original.ProviderPodUID || keeper.PodName == "" || keeper.PodName == original.ProviderPodName ||
		keeper.ContainerID == "" || keeper.ContainerID == original.ProviderContainerID || original.ProviderNamespace != original.Binding.Namespace {
		return "", ErrNodeObservation
	}
	bounded, cancel := context.WithDeadline(ctx, r.Deadline)
	defer cancel()
	o := a.parent.owner.observer
	if longhornExt4ProviderCurrent(bounded, o, original) != nil || originalVolume.qualify(bounded) != nil {
		return "", ErrNodeObservation
	}
	source, err := o.openLonghornExt4Source(bounded, LonghornExt4SourceCoordinates{
		Binding: original.Binding, Identity: original.Identity, VolumeHandle: original.VolumeHandle,
		PVCUID: original.PVCUID, PVUID: original.PVUID, OriginalSourceSHA256: original.OriginalSourceSHA256,
		ProviderNamespaceUID: original.ProviderNamespaceUID, ProviderNamespace: original.ProviderNamespace,
		ProviderPodName: keeper.PodName, ProviderPodUID: keeper.PodUID, ProviderContainerID: keeper.ContainerID, MountPoint: "/source",
	})
	if err != nil {
		return "", err
	}
	volume := longhornExt4Volume{freeze: &longhornExt4FreezeCustody{}, pin: source.Pin, mountFD: source.MountFD,
		blockFD: source.BlockFD, hostRootFD: source.HostRootFD, mountProc: filepath.Join(o.HostProc, strconv.Itoa(source.MountOwnerPID))}
	keep := false
	defer func() {
		if !keep {
			closeLonghornExt4Volume(volume)
		}
	}()
	var fs unix.Statfs_t
	if !sameLonghornKeeperDevice(original.Pin, source.Pin) || unix.Fstatfs(volume.mountFD, &fs) != nil ||
		fs.Flags&unix.ST_RDONLY == 0 || volume.qualify(bounded) != nil || longhornExt4ProviderCurrent(bounded, o, original) != nil {
		return "", ErrNodeObservation
	}
	source.Binding, source.Attempt, source.Claim, source.Keeper = r.Binding, r.Attempt, r.Claim, &keeper
	source = longhornExt4StableSource(source)
	key := longhornExt4SourceKey(source)
	if err := a.checkDeviceObligations(key, source); err != nil {
		return "", err
	}
	if err := bounded.Err(); err != nil {
		return "", err
	}
	a.sources[key], a.volumes[key] = source, volume
	keep = true
	return key, nil
}

func sameLonghornKeeperDevice(original, keeper longhornExt4Pin) bool {
	return original.BootID == keeper.BootID && original.Device == keeper.Device &&
		original.DiskSequence == keeper.DiskSequence && original.RootInode == keeper.RootInode && original.ErrorCount == keeper.ErrorCount &&
		original.UniqueMountID != keeper.UniqueMountID
}

func closeLonghornExt4Volume(volume longhornExt4Volume) {
	for _, fd := range []int{volume.mountFD, volume.blockFD, volume.hostRootFD} {
		_ = unix.Close(fd)
	}
}
