//go:build linux

package quiesce

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type longhornRWXClient struct {
	source     LonghornExt4Source
	pin        longhornRWXClientMountPin
	fd         int
	original   observedProcess
	mountTable []byte
}

func longhornRWXClientKey(c longhornRWXClient) string {
	p := c.pin
	return observationDigest([]any{c.source.Binding, c.source.Claim, c.source.Attempt, c.source.Identity,
		c.source.ProviderPodUID, c.source.ProviderContainerID,
		[]string{p.mountID, p.device, p.root, p.point, p.source, p.endpoint.String()}})
}

func (h *SharedRuntimeNodeHandler) configureLonghornRWXClients(ctx context.Context, coordinates []LonghornRWXClientCoordinates) error {
	if h.longhorn == nil {
		return ErrNodeObservation
	}
	a, o := h.longhorn, h.owner.observer
	h.owner.mu.Lock()
	defer h.owner.mu.Unlock()
	if a.clients == nil {
		a.clients = map[string]longhornRWXClient{}
	}
	for _, c := range coordinates {
		identity, err := LonghornExt4SourceIdentity(c.OriginalSourceSHA256, c.ProviderNamespaceUID, o.NodeUID)
		if err != nil || c.Identity != "" && c.Identity != identity {
			return ErrNodeObservation
		}
		c.Identity = identity
		if c.Binding.Namespace != c.PodNamespace || c.Binding.Node != o.Node || c.Binding.NodeUID != o.NodeUID ||
			c.Claim != (LonghornExt4Claim{}) || c.Attempt != 0 || c.Binding.OperationID != "" || c.Binding.Generation != 0 ||
			c.Binding.InventorySHA256 != "" || !c.Binding.ExpiresAt.IsZero() ||
			c.PodUID != "" || c.PodName != "" || c.ContainerID != "" || !validObservationHash(c.Identity) || c.PVCUID == "" || c.PVUID == "" ||
			c.VolumeHandle == "" || c.MountPoint == "/" || !absoluteObservationPath(c.MountPoint) || c.NFSSource == "" {
			return ErrNodeObservation
		}
		if _, err := netip.ParseAddr(c.Endpoint); err != nil {
			return err
		}
		if _, exists := a.clientTemplates[c.Identity]; exists {
			return ErrNodeObservation
		}
		a.clientTemplates[c.Identity] = c
	}
	o.longhornClientTemplates = make(map[string]LonghornRWXClientCoordinates, len(a.clientTemplates))
	for identity, c := range a.clientTemplates {
		o.longhornClientTemplates[identity] = c
	}
	return nil
}

func (a *longhornExt4Actions) registerClient(r LonghornExt4Request) (LonghornExt4Response, error) {
	var out LonghornExt4Response
	c, exists := a.clientTemplates[r.SourceIdentity]
	installed := LonghornExt4Source{Binding: c.Binding, Identity: c.Identity}
	if !validLonghornRWXClientTransition(r) || !exists || !longhornExt4RegistrationMatches(installed, r) ||
		r.RecoveryBoundarySHA256 != "" || r.DrainBoundarySHA256 != "" ||
		!validObservationHash(r.RegistrationBoundarySHA256) || r.ClientPodUID == "" || r.ClientPodName == "" ||
		r.ClientContainerID == "" || !time.Now().Before(longhornExt4ForwardUntil(r.Binding, r.Claim)) {
		return out, ErrNodeObservation
	}
	c.Binding, c.Claim, c.Attempt = r.Binding, r.Claim, r.Attempt
	c.PodUID, c.PodName, c.ContainerID = r.ClientPodUID, r.ClientPodName, r.ClientContainerID
	ctx, cancel := context.WithDeadline(context.Background(), longhornExt4ForwardUntil(r.Binding, r.Claim))
	defer cancel()
	client, err := a.openClient(ctx, c)
	if err != nil {
		return out, err
	}
	key := longhornRWXClientKey(client)
	if !time.Now().Before(longhornExt4ForwardUntil(r.Binding, r.Claim)) {
		unix.Close(client.fd)
		return out, ErrNodeObservation
	}
	for previousKey, previous := range a.clients {
		if previousKey != key && longhornExt4RequestMatches(previous.source, r) &&
			previous.source.ProviderPodUID == r.ClientPodUID && previous.source.ProviderContainerID == r.ClientContainerID {
			unix.Close(client.fd)
			return out, ErrNodeObservation
		}
	}
	if previous, exists := a.clients[key]; exists {
		unix.Close(client.fd)
		if observationDigest(previous.source) != observationDigest(client.source) || previous.pin != client.pin {
			return out, ErrNodeObservation
		}
	} else {
		if len(a.clients) >= 1024 {
			unix.Close(client.fd)
			return out, ErrNodeObservation
		}
		a.clients[key] = client
	}
	return longhornRWXClientReply(r, "client-prepared"), nil
}

func (a *longhornExt4Actions) openClient(ctx context.Context, c LonghornRWXClientCoordinates) (longhornRWXClient, error) {
	var zero longhornRWXClient
	o := a.parent.owner.observer
	source := LonghornExt4Source{Binding: c.Binding, Attempt: c.Attempt, Claim: c.Claim, Identity: c.Identity,
		VolumeHandle: c.VolumeHandle, PVCUID: c.PVCUID, PVUID: c.PVUID, ProviderNamespace: c.PodNamespace,
		ProviderPodName: c.PodName, ProviderPodUID: c.PodUID, ProviderContainerID: c.ContainerID}
	p, err := longhornExt4ProviderProcess(ctx, o, source)
	if err != nil {
		return zero, err
	}
	source.MountOwnerPID, source.MountOwnerStart, source.MountNamespace = p.PID, p.Start, p.MountNamespace
	proc := filepath.Join(o.HostProc, fmt.Sprint(p.PID))
	raw, err := observationRead(ctx, filepath.Join(proc, "mountinfo"), observationReadLimit)
	if err != nil {
		return zero, err
	}
	pin := longhornRWXClientMountPin{point: c.MountPoint, source: c.NFSSource}
	pin.endpoint, err = netip.ParseAddr(c.Endpoint)
	if err != nil {
		return zero, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		sep := mountSeparator(f)
		if sep < 0 {
			continue
		}
		point, err := mountUnescape(f[4])
		if err != nil {
			return zero, err
		}
		if point != c.MountPoint {
			continue
		}
		if pin.mountID != "" {
			return zero, ErrNodeObservation
		}
		pin.mountID, pin.device = f[0], f[2]
		pin.root, err = mountUnescape(f[3])
		if err != nil {
			return zero, err
		}
	}
	if !pin.matchesMountTable(raw) {
		return zero, ErrNodeObservation
	}
	pathFD, err := o.openOriginalMount(ctx, proc, c.MountPoint, pin.mountID)
	if err != nil {
		return zero, err
	}
	fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", pathFD), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	unix.Close(pathFD)
	if err != nil {
		return zero, err
	}
	if o.hostIdentity(ctx) != nil || longhornExt4ProviderCurrent(ctx, o, source) != nil {
		unix.Close(fd)
		return zero, ErrNodeObservation
	}
	p.Cgroup, err = observationPodCgroup(p.Cgroup, c.PodUID)
	if err != nil {
		unix.Close(fd)
		return zero, err
	}
	return longhornRWXClient{source: source, pin: pin, fd: fd, original: p, mountTable: append([]byte(nil), raw...)}, nil
}

func longhornRWXClientReply(r LonghornExt4Request, phase string) LonghornExt4Response {
	return LonghornExt4Response{Version: LonghornExt4Protocol, Action: r.Action, Nonce: r.Nonce, RequestSHA256: observationDigest(r),
		SourceIdentity: r.SourceIdentity, ClientPodUID: r.ClientPodUID, ClientContainerID: r.ClientContainerID, Binding: r.Binding, Claim: r.Claim, Attempt: r.Attempt,
		Phase: phase, NativeState: "nfs-client", ProviderObservedAt: time.Now().UTC(), ExpiresAt: longhornExt4ForwardUntil(r.Binding, r.Claim)}
}
func (a *longhornExt4Actions) syncClient(r LonghornExt4Request) (LonghornExt4Response, error) {
	var out LonghornExt4Response
	if !validLonghornRWXClientTransition(r) {
		return out, ErrNodeObservation
	}
	var client longhornRWXClient
	found := false
	for _, c := range a.clients {
		if longhornExt4RequestMatches(c.source, r) && c.source.ProviderPodUID == r.ClientPodUID &&
			c.source.ProviderContainerID == r.ClientContainerID && c.source.ProviderPodName == r.ClientPodName {
			if found {
				return out, ErrNodeObservation
			}
			client, found = c, true
		}
	}
	until := longhornExt4ForwardUntil(r.Binding, r.Claim)
	if !found || !time.Now().Before(until) {
		return out, ErrNodeObservation
	}
	ctx, cancel := context.WithDeadline(context.Background(), until)
	defer cancel()
	o := a.parent.owner.observer
	if o.hostIdentity(ctx) != nil {
		return out, ErrNodeObservation
	}
	proc := filepath.Join(o.HostProc, fmt.Sprint(client.source.MountOwnerPID))
	stopped := longhornExt4ProviderCurrent(ctx, o, client.source) != nil
	var table []byte
	var err error
	if stopped {
		if err = o.originalLonghornRWXClientExited(ctx, client); err != nil {
			return out, err
		}
		// The FD and table were pinned while the original process was live.
		// Namespace exit does not authorize opening a successor's mount.
		table = client.mountTable
	} else {
		table, err = observationRead(ctx, filepath.Join(proc, "mountinfo"), observationReadLimit)
		if err != nil {
			return out, err
		}
	}
	if err := syncPinnedLonghornRWXClientMount(ctx, client.fd, table, client.pin); err != nil {
		return out, err
	}
	if stopped {
		err = o.originalLonghornRWXClientExited(ctx, client)
	} else {
		err = longhornExt4ProviderCurrent(ctx, o, client.source)
		if err == nil {
			table, err = observationRead(ctx, filepath.Join(proc, "mountinfo"), observationReadLimit)
		}
	}
	if err != nil || o.hostIdentity(ctx) != nil || !client.pin.matchesMountTable(table) || !time.Now().Before(until) {
		return out, ErrNodeObservation
	}
	return longhornRWXClientReply(r, "client-synced"), nil
}

// This is process-exit evidence only, never a filesystem hold. Both the CRI
// record and two complete host task scans must exclude the registered original
// before its retained mount FD can be synced after Deployment scale-down.
func (o *NodeObserver) originalLonghornRWXClientExited(ctx context.Context, client longhornRWXClient) error {
	s := client.source
	if ctx == nil || ctx.Err() != nil || client.original.PID != s.MountOwnerPID || client.original.Start != s.MountOwnerStart || client.original.MountNamespace != s.MountNamespace || client.original.PIDNamespace == "" || client.original.Cgroup == "" || !client.pin.matchesMountTable(client.mountTable) {
		return ErrNodeObservation
	}
	return o.originalLonghornContainerExited(ctx, s, client.original)
}
