//go:build linux

package quiesce

import (
	"context"
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// The authenticated Node owner makes this pin from the original CRI mount
// namespace and the separately verified Longhorn export identity.
type longhornRWXClientMountPin struct {
	mountID, device, root, point, source string
	endpoint                             netip.Addr
}

func (p longhornRWXClientMountPin) matchesMountTable(table []byte) bool {
	if p.mountID == "" || p.device == "" || p.root == "" || p.point == "" || p.source == "" ||
		!p.endpoint.IsValid() || len(table) == 0 || len(table) > observationReadLimit {
		return false
	}
	matched := false
	for _, line := range strings.Split(string(table), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != p.mountID {
			continue
		}
		sep := mountSeparator(fields)
		if matched || sep < 0 || fields[2] != p.device || (fields[sep+1] != "nfs" && fields[sep+1] != "nfs4") {
			return false
		}
		root, rootErr := mountUnescape(fields[3])
		point, pointErr := mountUnescape(fields[4])
		source, sourceErr := mountUnescape(fields[sep+2])
		if rootErr != nil || pointErr != nil || sourceErr != nil || root != p.root || point != p.point || source != p.source {
			return false
		}
		var address netip.Addr
		for _, opt := range strings.Split(fields[sep+3], ",") {
			value, ok := strings.CutPrefix(opt, "addr=")
			if !ok {
				continue
			}
			parsed, err := netip.ParseAddr(value)
			if err != nil || address.IsValid() {
				return false
			}
			address = parsed
		}
		if !address.IsValid() || address.Unmap() != p.endpoint.Unmap() {
			return false
		}
		matched = true
	}
	return matched
}

// Run in a supervised, single-operation helper. A hard NFS syncfs can outlive
// cancellation. The parent keeps its durable drain intent unresolved in that
// case. mountTable and dirFD come from the same authenticated original client
// namespace before its writer exits. The writer's admission stays closed.
//
// Success acknowledges client filesystem sync only. Provider admission,
// server-side drain and continuity are checked by the original hold owner.
func syncPinnedLonghornRWXClientMount(ctx context.Context, dirFD int, mountTable []byte, pin longhornRWXClientMountPin) error {
	if ctx == nil || ctx.Err() != nil || !pin.matchesMountTable(mountTable) {
		return observationFailure("longhorn_rwx_client_mount_unverified")
	}
	fd, err := unix.FcntlInt(uintptr(dirFD), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return observationFailure("longhorn_rwx_client_mount_unavailable")
	}
	defer unix.Close(fd)
	flags, mountID, _, err := observationFDInfo(ctx, "/proc/self", strconv.Itoa(fd))
	if err != nil || mountID != pin.mountID || flags&unix.O_PATH != 0 || ctx.Err() != nil {
		return observationFailure("longhorn_rwx_client_fd_unverified")
	}
	if err := unix.Syncfs(fd); err != nil {
		return observationFailure("longhorn_rwx_client_sync_unconfirmed")
	}
	_, mountID, _, err = observationFDInfo(ctx, "/proc/self", strconv.Itoa(fd))
	if err != nil || mountID != pin.mountID || ctx.Err() != nil {
		return observationFailure("longhorn_rwx_client_sync_unconfirmed")
	}
	return nil
}
