//go:build linux

package quiesce

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func (h *SharedRuntimeNodeHandler) ConfigureLonghornExt4Materials(ctx context.Context, file, digest string) error {
	if h == nil || h.owner == nil || !filepath.IsAbs(file) || filepath.Clean(file) != file || !validObservationHash(digest) {
		return ErrNodeObservation
	}
	raw, _, _, err := sharedRuntimeNativeRead(ctx, filepath.Dir(file), "/"+filepath.Base(file), 1<<20)
	sum := sha256.Sum256(raw)
	if err != nil || hex.EncodeToString(sum[:]) != digest {
		return ErrNodeObservation
	}
	var material LonghornExt4Materials
	if sharedRuntimeNodeJSON(raw, &material) != nil || material.Version != LonghornExt4Protocol ||
		len(material.Sources)+len(material.Clients) == 0 || len(material.Sources) > 8 || len(material.Clients) > 128 {
		return ErrNodeObservation
	}
	sources := []LonghornExt4Source{}
	defer func() {
		for _, s := range sources {
			for _, fd := range []int{s.MountFD, s.BlockFD, s.HostRootFD} {
				_ = unix.Close(fd)
			}
		}
	}()
	for _, coordinates := range material.Sources {
		if coordinates.Binding.Node != h.owner.observer.Node {
			continue
		}
		source, err := h.owner.observer.openLonghornExt4Source(ctx, coordinates)
		if err != nil {
			return err
		}
		sources = append(sources, source)
	}
	if err := h.ConfigureLonghornExt4(ctx, material.RecoveryURI, sources); err != nil {
		return err
	}
	clients := []LonghornRWXClientCoordinates{}
	for _, c := range material.Clients {
		if c.Binding.Node == h.owner.observer.Node {
			clients = append(clients, c)
		}
	}
	if len(sources)+len(clients) == 0 {
		return ErrNodeObservation
	}
	return h.configureLonghornRWXClients(ctx, clients)
}

func (o *NodeObserver) openLonghornExt4Source(ctx context.Context, c LonghornExt4SourceCoordinates) (out LonghornExt4Source, err error) {
	identity, err := LonghornExt4SourceIdentity(c.OriginalSourceSHA256, c.ProviderNamespaceUID, o.NodeUID)
	if err != nil || c.Identity != "" && c.Identity != identity {
		return out, ErrNodeObservation
	}
	c.Identity = identity
	out = LonghornExt4Source{Binding: c.Binding, Attempt: c.Attempt, Claim: c.Claim, Identity: c.Identity,
		VolumeHandle: c.VolumeHandle, PVCUID: c.PVCUID, PVUID: c.PVUID, ProviderNamespace: c.ProviderNamespace,
		OriginalSourceSHA256: c.OriginalSourceSHA256, ProviderNamespaceUID: c.ProviderNamespaceUID,
		ProviderPodName: c.ProviderPodName, ProviderPodUID: c.ProviderPodUID, ProviderContainerID: c.ProviderContainerID,
		MountFD: -1, BlockFD: -1, HostRootFD: -1}
	if o.hostIdentity(ctx) != nil || c.Binding.Node != o.Node || c.Binding.NodeUID != o.NodeUID ||
		c.Claim != (LonghornExt4Claim{}) || c.Attempt != 0 || !validObservationHash(c.Identity) || c.PVCUID == "" || c.PVUID == "" ||
		!strings.HasPrefix(c.VolumeHandle, "pvc-") || strings.ContainsAny(c.VolumeHandle, "/\\\x00\r\n") {
		return out, ErrNodeObservation
	}
	defer func() {
		if err != nil {
			for _, fd := range []int{out.MountFD, out.BlockFD, out.HostRootFD} {
				if fd >= 0 {
					_ = unix.Close(fd)
				}
			}
		}
	}()
	p, err := longhornExt4ProviderProcess(ctx, o, out)
	if err != nil {
		return out, err
	}
	out.MountOwnerPID, out.MountOwnerStart, out.MountNamespace = p.PID, p.Start, p.MountNamespace
	out.HostRootFD, err = unix.Open(o.HostRoot, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return out, err
	}
	out.BlockFD, err = unix.Openat2(out.HostRootFD, "dev/longhorn/"+c.VolumeHandle,
		&unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return out, err
	}
	var block unix.Stat_t
	if unix.Fstat(out.BlockFD, &block) != nil || block.Mode&unix.S_IFMT != unix.S_IFBLK {
		return out, ErrNodeObservation
	}
	proc := filepath.Join(o.HostProc, strconv.Itoa(p.PID))
	table, err := observationRead(ctx, filepath.Join(proc, "mountinfo"), observationReadLimit)
	if err != nil {
		return out, err
	}
	device := fmt.Sprintf("%d:%d", unix.Major(uint64(block.Rdev)), unix.Minor(uint64(block.Rdev)))
	var selected []string
	for _, line := range strings.Split(string(table), "\n") {
		f := strings.Fields(line)
		sep := mountSeparator(f)
		if sep < 0 || f[2] != device || f[3] != "/" || f[sep+1] != "ext4" {
			continue
		}
		point, e := mountUnescape(f[4])
		if e != nil || point == "/" || !absoluteObservationPath(point) {
			return out, ErrNodeObservation
		}
		if c.MountPoint != "" && point != c.MountPoint {
			continue
		}
		if selected != nil {
			return out, observationFailure("longhorn_ext4_mount_not_unique")
		}
		selected = f
	}
	if selected == nil {
		return out, observationFailure("longhorn_ext4_mount_unobserved")
	}
	point, _ := mountUnescape(selected[4])
	sep := mountSeparator(selected)
	source, err := mountUnescape(selected[sep+2])
	if err != nil {
		return out, err
	}
	pathFD, err := o.openOriginalMount(ctx, proc, point, selected[0])
	if err != nil {
		return out, err
	}
	defer unix.Close(pathFD)
	// Only reopen after its kernel mount ID has matched the ext4 table entry.
	out.MountFD, err = unix.Open(fmt.Sprintf("/proc/self/fd/%d", pathFD), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return out, err
	}
	var dir unix.Stat_t
	var unique unix.Statx_t
	if unix.Fstat(out.MountFD, &dir) != nil || uint64(dir.Dev) != uint64(block.Rdev) ||
		unix.Statx(out.MountFD, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID_UNIQUE, &unique) != nil ||
		unique.Mask&unix.STATX_MNT_ID_UNIQUE == 0 {
		return out, ErrNodeObservation
	}
	sysdev := "/sys/dev/block/" + device
	link, err := os.Readlink(sysdev)
	if err != nil {
		return out, err
	}
	raw, err := observationRead(ctx, filepath.Join(sysdev, "diskseq"), 64)
	if err != nil {
		return out, err
	}
	diskseq, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return out, err
	}
	raw, err = observationRead(ctx, filepath.Join("/sys/fs/ext4", filepath.Base(link), "errors_count"), 64)
	if err != nil {
		return out, err
	}
	errors, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return out, err
	}
	out.Pin = longhornExt4Pin{BootID: o.BootID, MountID: selected[0], MountPoint: point, Source: source,
		UniqueMountID: unique.Mnt_id, Device: uint64(dir.Dev), RootInode: uint64(dir.Ino), DiskSequence: diskseq, ErrorCount: errors}
	if err = longhornExt4ProviderCurrent(ctx, o, out); err != nil {
		return out, err
	}
	return out, nil
}

func (o *NodeObserver) openOriginalMount(ctx context.Context, proc, point, mountID string) (int, error) {
	root, err := unix.Open(filepath.Join(proc, "root"), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	defer unix.Close(root)
	fd, err := unix.Openat2(root, strings.TrimPrefix(point, "/"),
		&unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS})
	if err != nil {
		return -1, err
	}
	_, id, _, err := observationFDInfo(ctx, "/proc/self", strconv.Itoa(fd))
	if err != nil || id != mountID {
		unix.Close(fd)
		return -1, ErrNodeObservation
	}
	return fd, nil
}

// Resolve actual container identity before accepting a mount namespace.
func longhornExt4ProviderProcess(ctx context.Context, o *NodeObserver, s LonghornExt4Source) (observedProcess, error) {
	var zero observedProcess
	parts := strings.Split(s.ProviderContainerID, "://")
	if len(parts) != 2 || (parts[0] != "containerd" && parts[0] != "cri-o") ||
		!criID.MatchString(parts[1]) || s.ProviderNamespace == "" || s.ProviderPodName == "" || s.ProviderPodUID == "" {
		return zero, ErrNodeObservation
	}
	raw, err := o.CRI.Inspect(ctx, parts[1])
	if err != nil {
		return zero, err
	}
	var result struct {
		Status struct {
			ID     string            `json:"id"`
			State  json.RawMessage   `json:"state"`
			Labels map[string]string `json:"labels"`
		} `json:"status"`
		Info struct {
			PID json.Number `json:"pid"`
		} `json:"info"`
	}
	if json.Unmarshal(raw, &result) != nil || result.Status.ID != parts[1] ||
		result.Status.Labels["io.kubernetes.pod.uid"] != s.ProviderPodUID ||
		result.Status.Labels["io.kubernetes.pod.namespace"] != s.ProviderNamespace ||
		result.Status.Labels["io.kubernetes.pod.name"] != s.ProviderPodName {
		return zero, ErrNodeObservation
	}
	state := strings.Trim(string(result.Status.State), "\"")
	pid, err := strconv.Atoi(result.Info.PID.String())
	if err != nil || pid <= 1 || (state != "CONTAINER_RUNNING" && state != "1") {
		return zero, ErrNodeObservation
	}
	p, err := observationProcess(ctx, filepath.Join(o.HostProc, strconv.Itoa(pid)))
	if err != nil || !strings.Contains(p.Cgroup, parts[1]) {
		return zero, ErrNodeObservation
	}
	if _, err := observationPodCgroup(p.Cgroup, s.ProviderPodUID); err != nil {
		return zero, err
	}
	return p, nil
}
