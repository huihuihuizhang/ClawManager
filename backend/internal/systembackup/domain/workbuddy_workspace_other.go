//go:build !linux

package domain

import "os"

func verifyWorkBuddyHomeOwner(os.FileInfo, WorkBuddyUIDIdentity) error { return ErrIsolation }
