package staging

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"regexp"
)

// StorePrivateReport uses the EXISTING seal-custody owner, lock, policy and
// whole-root accounting. This low-level writer grants no authority; the caller
// must supply its current original task guard. Reports are private metadata,
// never source payloads/keys. Unknown files and partials remain counted/retained.
func StorePrivateReport(ctx context.Context, root *os.Root, policy CustodyPolicy, name string, raw []byte, current func(context.Context) error) (out Receipt, err error) {
	if ctx == nil || root == nil || current == nil || len(raw) == 0 || !regexp.MustCompile(`^report-[0-9a-f]{64}\.json$`).MatchString(name) {
		return out, ErrFile
	}
	sum := sha256.Sum256(raw)
	wanted := Receipt{Name: name, Size: int64(len(raw)), SHA256: hex.EncodeToString(sum[:])}
	err = WithCustodyLock(ctx, root, func() error {
		if e := current(ctx); e != nil {
			return e
		}
		info, e := root.Stat(".")
		if e != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
			return ErrFile
		}
		if e = validateCustodyPolicy(root, policy); e != nil {
			return e
		}
		inventory, e := inventoryCustody(root)
		if e != nil {
			return e
		}
		if inventory.UsedBytes > policy.MaxBytes {
			return ErrCapacity
		}
		info, e = root.Lstat(name)
		if e == nil {
			if !info.Mode().IsRegular() || info.Mode().Perm() != 0400 {
				return ErrFile
			}
			f, e := OpenFileGuarded(ctx, root, wanted, current)
			if e != nil {
				return e
			}
			defer f.Close()
			if e = f.Sync(); e != nil {
				return e
			}
			if e = syncDirectory(root); e != nil {
				return e
			}
			if e = current(ctx); e != nil {
				return e
			}
			out = wanted
			return nil
		}
		if !errors.Is(e, os.ErrNotExist) {
			return ErrFile
		}
		if wanted.Size > policy.MaxBytes || inventory.UsedBytes > policy.MaxBytes-wanted.Size || len(inventory.Entries) > maxCustodyFiles-2 {
			return ErrCapacity
		}
		available, e := custodyAvailable(root)
		reserve := policy.MaxBytes / 20
		if reserve < 64<<20 {
			reserve = 64 << 20
		}
		if e != nil || available < wanted.Size+reserve {
			return ErrCapacity
		}
		if e = current(ctx); e != nil {
			return e
		}
		receipt, e := WriteUnpublishedFile(ctx, root, name, func(dst io.Writer) error {
			if e := current(ctx); e != nil {
				return e
			}
			return writeAll(dst, raw)
		})
		if e != nil {
			return e
		}
		if receipt != wanted {
			return ErrFile
		}
		f, e := OpenFileGuarded(ctx, root, wanted, current)
		if e != nil {
			return e
		}
		if e = f.Close(); e != nil {
			return e
		}
		if e = current(ctx); e != nil {
			return e
		}
		out = wanted
		return nil
	})
	return
}
