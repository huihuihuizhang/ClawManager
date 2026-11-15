//go:build linux

package quiesce

import (
	"context"
	"reflect"

	"golang.org/x/sys/unix"
)

type sharedRuntimeLonghornWitness struct {
	Coordinates                                    LonghornRWXClientCoordinates
	MountID, Device, Root, Point, Source, Endpoint string
	DeviceNumber, RootInode                        uint64
	Process                                        observedProcess
}

// This only observes the original installed NFS client. It neither syncs the
// filesystem nor asserts that other clients are stopped. The separate Longhorn
// source actor still has to sync the complete cohort and hold its provider.
func (o *NodeObserver) sharedRuntimeLonghornMount(ctx context.Context, r SharedRuntimeNodeRequest, prior *sharedRuntimeNativeWitness) (*sharedRuntimeLonghornWitness, error) {
	if o == nil || ctx == nil || ctx.Err() != nil || !validSharedRuntimeLonghornClient(r) {
		return nil, ErrNodeObservation
	}
	c := *r.LonghornClient
	if prior == nil {
		template, found := o.longhornClientTemplates[c.Identity]
		if !found || !reflect.DeepEqual(template, sharedRuntimeLonghornTemplate(c)) {
			return nil, observationFailure("shared_longhorn_installed_client_required")
		}
	} else if prior.Longhorn == nil || !reflect.DeepEqual(prior.Longhorn.Coordinates, c) {
		return nil, observationFailure("shared_longhorn_original_client_required")
	}
	// Reuse the exact CRI, original namespace FD and installed NFS mount checks
	// of register-client, without creating a claim or registering another actor.
	a := longhornExt4Actions{parent: &SharedRuntimeNodeHandler{owner: &sharedRuntimeNodeOwner{observer: o}}}
	client, err := a.openClient(ctx, c)
	if err != nil {
		return nil, err
	}
	defer unix.Close(client.fd)
	var st unix.Stat_t
	if unix.Fstat(client.fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, ErrNodeObservation
	}
	p := client.pin
	w := &sharedRuntimeLonghornWitness{Coordinates: c, MountID: p.mountID, Device: p.device, Root: p.root, Point: p.point, Source: p.source, Endpoint: p.endpoint.String(), DeviceNumber: uint64(st.Dev), RootInode: st.Ino, Process: client.original}
	if prior != nil && !reflect.DeepEqual(w, prior.Longhorn) {
		return nil, observationFailure("shared_longhorn_original_mount_changed")
	}
	return w, nil
}
