package quiesce

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"
)

// OriginalNodeHistoryDirectory exposes bounded directory pages only. It never
// exposes an os.Root/File or lazy DirEntry.Info, and grants no write/body access.
// D must independently check its actual complete holder and original gates
// before and after every read. This local reader is neither that holder nor a
// complete history/NoS3/empty-directory proof. The concrete classifier owns EOF.
type OriginalNodeHistoryDirectory struct {
	mu          sync.Mutex
	origin      *OriginalNodeHistoryDirectory
	ctx         context.Context
	proof       *VerifiedNodeObservation
	binding     ObservationBinding
	boot, token string
	path        observedPath
	until       time.Time
	dir         *os.File
	info        os.FileInfo
	stopTimer   *time.Timer
	stopContext func() bool
	closed      bool
}

// Entries contain inert metadata; they cannot perform filesystem I/O later.
type OriginalNodeHistoryDirectoryEntry struct {
	Name string
	Type fs.FileMode
}

func (*OriginalNodeHistoryDirectory) MarshalJSON() ([]byte, error) { return nil, ErrNodeObservation }
func (*OriginalNodeHistoryDirectory) String() string               { return "OriginalNodeHistoryDirectory" }
func (*OriginalNodeHistoryDirectory) GoString() string             { return "OriginalNodeHistoryDirectory" }

// OpenOriginalNodeHistoryDirectory accepts only the original capture's genuine
// verified stopped observation and an EXACT anchor path. There is no raw-anchor,
// alias, child-path, fallback, renewal or recovery-phase constructor. Linux must
// see the same boot, path identity and original mount namespace entry locally.
func OpenOriginalNodeHistoryDirectory(ctx context.Context, v *VerifiedNodeObservation, b ObservationBinding, boot, filename string) (*OriginalNodeHistoryDirectory, error) {
	p, until, err := originalHistoryDirectoryPath(ctx, v, b, boot, filename)
	if err != nil {
		return nil, ErrNodeObservation
	}
	r := &OriginalNodeHistoryDirectory{ctx: ctx, proof: v, binding: b, boot: boot, token: v.response.Anchor, path: p, until: until}
	r.origin = r
	if r.local(ctx) != nil {
		return nil, ErrNodeObservation
	}
	r.dir, r.info, err = openOriginalHistoryDirectoryNative(ctx, p, boot)
	if err != nil {
		return nil, ErrNodeObservation
	}
	if r.check(ctx) != nil {
		r.dir.Close()
		return nil, ErrNodeObservation
	}
	// Close abandoned descriptors at the original cap/cancellation as well as
	// refusing each later read. Neither path renews an observation or a gate.
	r.mu.Lock()
	r.stopTimer = time.AfterFunc(time.Until(until), func() { _ = r.Close() })
	r.stopContext = context.AfterFunc(ctx, func() { _ = r.Close() })
	r.mu.Unlock()
	return r, nil
}

func originalHistoryDirectoryPath(ctx context.Context, v *VerifiedNodeObservation, b ObservationBinding, boot, filename string) (observedPath, time.Time, error) {
	var zero observedPath
	now := time.Now()
	if ctx == nil || ctx.Err() != nil || v == nil || b.Kind != NodeObservationWholePodColdCut || b.InstallationID == "" || b.OperationID == "" || b.ReservationID == "" || !validObservationHash(b.InventorySHA256) || b.Namespace == "" || b.NamespaceUID == "" || b.Node == "" || b.NodeUID == "" || b.Generation == 0 || !now.Before(b.ExpiresAt) || !absoluteObservationPath(filename) || filename == "/" || v.Recheck(ctx, b, "stopped", boot, now) != nil {
		return zero, time.Time{}, ErrNodeObservation
	}
	deadline, ok := ctx.Deadline()
	if !ok || !reflect.TypeOf(ctx).Comparable() {
		return zero, time.Time{}, ErrNodeObservation
	}
	response := v.response
	if response.Version != "node-observation.v1" || response.FinishedAt.Before(response.StartedAt) || response.FinishedAt.After(now) || response.TasksChecked <= 0 || response.Files <= 0 {
		return zero, time.Time{}, ErrNodeObservation
	}
	parts := strings.Split(response.Anchor, ".")
	if len(parts) != 2 || len(response.Anchor) > 256<<10 {
		return zero, time.Time{}, ErrNodeObservation
	}
	raw, e := base64.RawURLEncoding.DecodeString(parts[0])
	mac, merr := hex.DecodeString(parts[1])
	if e != nil || merr != nil || len(mac) != 32 {
		return zero, time.Time{}, ErrNodeObservation
	}
	// The HMAC was authenticated by the original native observer before the
	// concrete mTLS client created v. We do not accept caller token strings or
	// claim to verify that server-only MAC locally. Strict roundtrip rejects an
	// unsupported anchor schema rather than silently dropping source fields.
	var anchor nodeObservationAnchor
	if json.Unmarshal(raw, &anchor) != nil {
		return zero, time.Time{}, ErrNodeObservation
	}
	round, e := json.Marshal(anchor)
	if e != nil || !bytes.Equal(raw, round) || observationDigest(anchor.Binding) != observationDigest(b) || anchor.BootID != boot || anchor.PreparedAt.IsZero() || anchor.PreparedAt.After(response.StartedAt) || len(anchor.Paths) == 0 || len(anchor.Paths) > 128 {
		return zero, time.Time{}, ErrNodeObservation
	}
	seen := map[string]bool{}
	var selected observedPath
	for _, p := range anchor.Paths {
		if !absoluteObservationPath(p.Path) || p.Path == "/" || p.Device == 0 || p.Inode == 0 || p.Mount == "" || seen[p.Path] {
			return zero, time.Time{}, ErrNodeObservation
		}
		seen[p.Path] = true
		if p.Path == filename {
			selected = p
		}
	}
	if selected.Path == "" {
		return zero, time.Time{}, ErrNodeObservation
	}
	until := response.ValidUntil
	for _, cap := range []time.Time{b.ExpiresAt, deadline} {
		if cap.Before(until) {
			until = cap
		}
	}
	if !now.Before(until) {
		return zero, time.Time{}, ErrNodeObservation
	}
	return selected, until, nil
}

func (r *OriginalNodeHistoryDirectory) local(ctx context.Context) error {
	if r == nil || r.origin != r || r.closed || ctx == nil || ctx.Err() != nil || !reflect.TypeOf(ctx).Comparable() || ctx != r.ctx || r.proof == nil || r.proof.response.Anchor != r.token || !time.Now().Before(r.until) || !time.Now().Before(r.binding.ExpiresAt) || r.proof.Recheck(ctx, r.binding, "stopped", r.boot, time.Now()) != nil {
		return ErrNodeObservation
	}
	return nil
}

func (r *OriginalNodeHistoryDirectory) check(ctx context.Context) error {
	if r.local(ctx) != nil || r.dir == nil || r.info == nil {
		return ErrNodeObservation
	}
	return checkOriginalHistoryDirectoryNative(ctx, r.dir, r.info, r.path, r.boot)
}

// ReadDir performs a real bounded read and checks the original cap/opaque and
// native path/descriptor before and after it. Errors, drift or expiry discard
// partial entries and permanently close the reader. Only real io.EOF is EOF.
// A returned page/EOF is DATA; D's actual authority and classifier must consume
// it under their original holder, and nonempty/unknown entries cannot be skipped.
func (r *OriginalNodeHistoryDirectory) ReadDir(ctx context.Context, n int) ([]OriginalNodeHistoryDirectoryEntry, error) {
	if r == nil || r.origin != r {
		return nil, ErrNodeObservation
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if n <= 0 || n > 256 || r.check(ctx) != nil {
		r.closeLocked()
		return nil, ErrNodeObservation
	}
	entries, err := r.dir.ReadDir(n)
	if err != nil && err != io.EOF || r.check(ctx) != nil {
		r.closeLocked()
		return nil, ErrNodeObservation
	}
	out := make([]OriginalNodeHistoryDirectoryEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, OriginalNodeHistoryDirectoryEntry{Name: e.Name(), Type: e.Type()})
	}
	return out, err
}

func (r *OriginalNodeHistoryDirectory) closeLocked() error {
	if r.closed {
		return nil
	}
	r.closed = true
	if r.stopTimer != nil {
		r.stopTimer.Stop()
	}
	if r.stopContext != nil {
		r.stopContext()
	}
	if r.dir != nil {
		err := r.dir.Close()
		r.dir = nil
		return err
	}
	return nil
}
func (r *OriginalNodeHistoryDirectory) Close() error {
	if r == nil || r.origin != r {
		return ErrNodeObservation
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closeLocked()
}
