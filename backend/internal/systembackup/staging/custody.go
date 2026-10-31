package staging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

var ErrCapacity = errors.New("seal custody capacity exhausted or unknown")
var ErrCustodyBusy = errors.New("seal custody lock unavailable")

const maxCustodyFiles = 10000

var sealObjectName = regexp.MustCompile(`^seal-[0-9a-f]{64}\.enc$`)
var sealPartialName = regexp.MustCompile(`^\.seal-[0-9a-f]{32}\.partial$`)

type CustodyPolicy struct {
	Installation string `json:"installation_id"`
	MaxBytes     int64  `json:"max_bytes"`
}
type SealIntent struct {
	Schema   string    `json:"schema_version"`
	Scope    SealScope `json:"scope"`
	Original Receipt   `json:"original"`
}
type CustodyEntry struct {
	Name     string    `json:"name"`
	Bytes    int64     `json:"bytes"`
	Modified time.Time `json:"modified"`
	Kind     string    `json:"kind"`
	identity os.FileInfo
}
type CustodyInventory struct {
	UsedBytes int64          `json:"used_bytes"`
	Entries   []CustodyEntry `json:"entries"`
}

// WithCustodyLock serializes copies, capacity decisions, and maintenance across
// processes. The stable lock inode is NEVER removed. Kernel release on process
// exit avoids stale time-based locks. Shared-storage locking must pass the probe.
func WithCustodyLock(ctx context.Context, root *os.Root, fn func() error) error {
	if ctx == nil || root == nil || fn == nil {
		return ErrFile
	}
	const name = ".custody.lock"
	f, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		info, e := root.Lstat(name)
		if e != nil || !info.Mode().IsRegular() {
			return ErrFile
		}
		f, err = root.OpenFile(name, os.O_RDWR, 0)
		if err == nil {
			actual, e := f.Stat()
			if e != nil || !os.SameFile(info, actual) {
				f.Close()
				return ErrFile
			}
		}
	}
	if err != nil {
		return err
	}
	defer f.Close()
	// Never wait forever on a provider that does not implement this primitive.
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if tryCustodyLock(f) == nil {
			break
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-deadline.C:
			timer.Stop()
			return ErrCustodyBusy
		case <-timer.C:
		}
	}
	defer releaseCustodyLock(f)
	if err = f.Sync(); err != nil {
		return err
	}
	if err = syncDirectory(root); err != nil {
		return err
	}
	return fn()
}

func inventoryCustody(root *os.Root) (CustodyInventory, error) {
	out := CustodyInventory{Entries: []CustodyEntry{}}
	dir, err := root.Open(".")
	if err != nil {
		return out, err
	}
	defer dir.Close()
	for {
		entries, e := dir.ReadDir(128)
		if e != nil && e != io.EOF {
			return out, e
		}
		for _, entry := range entries {
			info, z := root.Lstat(entry.Name())
			if z != nil || !info.Mode().IsRegular() || info.Size() < 0 {
				return out, ErrFile
			}
			if len(out.Entries) >= maxCustodyFiles || info.Size() > 1<<50 || out.UsedBytes > 1<<50-info.Size() {
				return out, ErrCapacity
			}
			kind := "untracked"
			switch {
			case entry.Name() == ".custody.lock" || entry.Name() == ".custody-policy.json":
				kind = "control"
			case sealObjectName.MatchString(entry.Name()):
				kind = "seal"
			case sealPartialName.MatchString(entry.Name()):
				kind = "partial"
			case strings.HasSuffix(entry.Name(), ".intent.json") && sealObjectName.MatchString(strings.TrimSuffix(entry.Name(), ".intent.json")):
				kind = "intent"
			}
			out.UsedBytes += info.Size()
			out.Entries = append(out.Entries, CustodyEntry{entry.Name(), info.Size(), info.ModTime().UTC(), kind, info})
		}
		if e == io.EOF {
			break
		}
	}
	sort.Slice(out.Entries, func(i, j int) bool { return out.Entries[i].Name < out.Entries[j].Name })
	return out, nil
}

func exactCustodyJSON(root *os.Root, name string, raw []byte) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		info, e := root.Lstat(name)
		if e != nil || !info.Mode().IsRegular() || info.Size() != int64(len(raw)) {
			return ErrFile
		}
		got, e := root.ReadFile(name)
		if e != nil || !bytes.Equal(got, raw) {
			return ErrFile
		}
		return nil
	}
	if err != nil {
		return err
	}
	if err = writeAll(f, raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return syncDirectory(root)
}

func validateCustodyPolicy(root *os.Root, p CustodyPolicy) error {
	if p.Installation == "" || len(p.Installation) > 128 || p.MaxBytes < 1<<20 || p.MaxBytes > 1<<40 {
		return ErrCapacity
	}
	raw, _ := json.Marshal(p)
	return exactCustodyJSON(root, ".custody-policy.json", raw)
}

// ObserveManaged is the production writer. Policy is pinned to this root and
// installation, so overlapping controller versions cannot use different caps.
// All files, including interrupted copies and unknown legacy files, count.
func ObserveManaged(ctx context.Context, source, custody *os.Root, p CustodyPolicy, scope SealScope, original Receipt, key []byte, max int64) (out Observation, err error) {
	return observeManaged(ctx, source, custody, p, scope, original, func() (Observation, error) { return ObserveFile(ctx, source, custody, scope, original, key, max) })
}

func observeManaged(ctx context.Context, source, custody *os.Root, p CustodyPolicy, scope SealScope, original Receipt, observe func() (Observation, error)) (out Observation, err error) {
	err = WithCustodyLock(ctx, custody, func() error {
		if scope.Installation != p.Installation {
			return ErrFile
		}
		if e := validateCustodyPolicy(custody, p); e != nil {
			return e
		}
		receipt, e := observedReceipt(scope, original)
		if e != nil {
			return e
		}
		intent := SealIntent{Schema: "controller-staging-seal-intent.v1", Scope: scope, Original: original}
		raw, _ := json.Marshal(intent)
		if len(raw) > 8192 {
			return ErrFile
		}
		inventory, e := inventoryCustody(custody)
		if e != nil {
			return e
		}
		additional := original.Size + int64(len(raw))
		for _, entry := range inventory.Entries {
			if entry.Name == receipt.Name {
				additional -= original.Size
			}
			if entry.Name == receipt.Name+".intent.json" {
				additional -= int64(len(raw))
			}
		}
		if additional < 0 || additional > p.MaxBytes || inventory.UsedBytes > p.MaxBytes-additional || len(inventory.Entries) > maxCustodyFiles-3 {
			return ErrCapacity
		}
		if additional > 0 {
			available, e := custodyAvailable(custody)
			reserve := p.MaxBytes / 20
			if reserve < 64<<20 {
				reserve = 64 << 20
			}
			if e != nil || available < additional+reserve {
				return ErrCapacity
			}
		}
		if e = exactCustodyJSON(custody, receipt.Name+".intent.json", raw); e != nil {
			return e
		}
		out, e = observe()
		return e
	})
	return
}

func InventoryCustody(ctx context.Context, root *os.Root, p CustodyPolicy) (out CustodyInventory, err error) {
	err = WithCustodyLock(ctx, root, func() error {
		if e := validateCustodyPolicy(root, p); e != nil {
			return e
		}
		var e error
		out, e = inventoryCustody(root)
		return e
	})
	return
}

// RemoveOrphans calls the owner while the filesystem lock is held. The owner
// must keep its original SQL row locks until remove returns. Unknown files and
// referenced/active Jobs are never inferred to be garbage from age alone.
type SealPruneAuthority interface {
	WithUnreferencedSeal(context.Context, SealIntent, string, func() error) (bool, error)
}
type SealPruneItem struct {
	Name     string `json:"name"`
	Decision string `json:"decision"`
}

func PruneCustody(ctx context.Context, root *os.Root, p CustodyPolicy, cutoff time.Time, apply bool, authority SealPruneAuthority) (out []SealPruneItem, err error) {
	out = []SealPruneItem{}
	if authority == nil || cutoff.IsZero() || cutoff.After(time.Now().Add(-time.Hour)) {
		return nil, ErrFile
	}
	err = WithCustodyLock(ctx, root, func() error {
		if e := validateCustodyPolicy(root, p); e != nil {
			return e
		}
		inventory, e := inventoryCustody(root)
		if e != nil {
			return e
		}
		entries := map[string]CustodyEntry{}
		for _, entry := range inventory.Entries {
			entries[entry.Name] = entry
		}
		for _, entry := range inventory.Entries {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if entry.Kind == "control" {
				continue
			}
			decision := "retained"
			if entry.Kind == "intent" {
				if _, exists := entries[strings.TrimSuffix(entry.Name, ".intent.json")]; exists {
					continue
				}
			}
			if entry.Modified.After(cutoff) {
				out = append(out, SealPruneItem{entry.Name, "too_recent"})
				continue
			}
			if entry.Kind == "partial" {
				decision = "orphan_partial"
				if apply {
					if e = removeCustodyEntry(root, entry); e != nil {
						return e
					}
					decision = "removed_partial"
				}
			}
			if entry.Kind == "seal" || entry.Kind == "intent" {
				name := strings.TrimSuffix(entry.Name, ".intent.json")
				intentEntry, exists := entries[name+".intent.json"]
				if !exists || intentEntry.Bytes <= 0 || intentEntry.Bytes > 8192 || intentEntry.Modified.After(cutoff) {
					out = append(out, SealPruneItem{entry.Name, "untracked_or_recent_intent"})
					continue
				}
				raw, z := root.ReadFile(name + ".intent.json")
				if z != nil || len(raw) > 8192 {
					out = append(out, SealPruneItem{entry.Name, "untracked"})
					continue
				}
				var intent SealIntent
				dec := json.NewDecoder(bytes.NewReader(raw))
				dec.DisallowUnknownFields()
				if dec.Decode(&intent) != nil {
					out = append(out, SealPruneItem{entry.Name, "invalid_intent"})
					continue
				}
				canonical, _ := json.Marshal(intent)
				receipt, z := observedReceipt(intent.Scope, intent.Original)
				if z != nil || !bytes.Equal(raw, canonical) || intent.Schema != "controller-staging-seal-intent.v1" || intent.Scope.Installation != p.Installation || receipt.Name != name {
					out = append(out, SealPruneItem{entry.Name, "invalid_intent"})
					continue
				}
				admitted, z := authority.WithUnreferencedSeal(ctx, intent, "controller-staging-seal.v1/"+name, func() error {
					if !apply {
						return nil
					}
					if entry.Kind == "seal" {
						if e := removeCustodyEntry(root, entry); e != nil {
							return e
						}
					}
					return removeCustodyEntry(root, intentEntry)
				})
				if z != nil {
					return z
				}
				if admitted {
					decision = "orphan_seal"
					if apply {
						decision = "removed_seal"
					}
				}
			}
			out = append(out, SealPruneItem{entry.Name, decision})
		}
		return syncDirectory(root)
	})
	return
}

func removeCustodyEntry(root *os.Root, entry CustodyEntry) error {
	info, err := root.Lstat(entry.Name)
	if err != nil || entry.identity == nil || !os.SameFile(entry.identity, info) || !info.Mode().IsRegular() || info.Size() != entry.Bytes || !info.ModTime().Equal(entry.Modified) {
		return ErrFile
	}
	// Windows marks 0400 files read-only; the custody lock and SQL owner guard
	// protect this precise orphan. Never chmod or delete unknown paths.
	if err = root.Chmod(entry.Name, 0600); err != nil {
		return err
	}
	return root.Remove(entry.Name)
}
