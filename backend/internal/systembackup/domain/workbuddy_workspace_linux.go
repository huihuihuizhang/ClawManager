//go:build linux

package domain

import (
	"os"
	"syscall"
)

func verifyWorkBuddyHomeOwner(info os.FileInfo, want WorkBuddyUIDIdentity) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(want.UID) || st.Gid != uint32(want.GID) {
		return ErrData
	}
	return nil
}
