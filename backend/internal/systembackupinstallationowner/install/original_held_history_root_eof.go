package install

import (
	"context"
	"io"
	"reflect"
	"time"

	q "clawreef/internal/systembackup/quiesce"
)

// Actual empty-branch directory observation bound to D's genuine original set.
// This is not a complete source universe, NoS3, Reference or PreparedCoverage.
// All methods require the original set.mu -> preparation.mu lock order.
type originalHeldHistoryRootEOF struct {
	origin             *originalHeldHistoryRootEOF
	ctx                context.Context
	prep               *PreparedOriginalAdoptionSQLCut
	hold               *OriginalWriterHold
	node               *originalWholeNodeScope
	proof              *q.VerifiedNodeObservation
	binding            q.ObservationBinding
	anchor, boot, path string
	until, observedAt  time.Time
	failed             bool
}

func (*originalHeldHistoryRootEOF) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (*originalHeldHistoryRootEOF) String() string               { return "OriginalHeldHistoryRootEOF" }
func (*originalHeldHistoryRootEOF) GoString() string             { return "OriginalHeldHistoryRootEOF" }

// Missing logical classification is blocking evidence, never released or empty.
// The private authority can retain the exact root and observed page internally;
// the public error string discloses no filenames or configuration bytes.
type originalHeldHistoryRootUnclassified struct {
	node, path     string
	entries        []q.OriginalNodeHistoryDirectoryEntry
	pageReachedEOF bool
	until          time.Time
}

func (*originalHeldHistoryRootUnclassified) Error() string {
	return "nonempty original held history root requires logical classification"
}
func (*originalHeldHistoryRootUnclassified) MarshalJSON() ([]byte, error) { return nil, ErrInstall }

func readOriginalHeldHistoryRootEOF(ctx context.Context, p *PreparedOriginalAdoptionSQLCut, h *OriginalWriterHold, nodeName, exactPath string) (*originalHeldHistoryRootEOF, error) {
	if p == nil || h == nil || h.set == nil {
		return nil, ErrInstall
	}
	h.set.mu.Lock()
	defer h.set.mu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	return readOriginalHeldHistoryRootEOFLocked(ctx, p, h, nodeName, exactPath)
}

// D's complete factory uses this entry when already inside the original owner
// locks. The node/path selector cannot supply a proof, native anchor or EOF DTO.
func readOriginalHeldHistoryRootEOFLocked(ctx context.Context, p *PreparedOriginalAdoptionSQLCut, h *OriginalWriterHold, nodeName, exactPath string) (result *originalHeldHistoryRootEOF, err error) {
	if !originalEmptyHistoryOwner(ctx, p, h, false) || h.recheckBeforeSQL(ctx) != nil || p.operator.authority(ctx, p.enrollment) != nil {
		return nil, ErrInstall
	}
	var selected *originalWholeNodeScope
	for _, node := range h.set.nodes {
		if node != nil && node.request.Binding.Node == nodeName {
			if selected != nil {
				return nil, ErrInstall
			}
			selected = node
		}
	}
	if selected == nil || selected.set != h.set || selected.prepare == nil || selected.current == nil {
		return nil, ErrInstall
	}
	count := 0
	for _, root := range selected.request.SourcePaths {
		if root == exactPath {
			count++
		}
	}
	if count != 1 {
		return nil, OriginalWriterSourceFailure{Dependency: "exact_original_history_root_missing_from_prepare_scope"}
	}
	until, bounded := ctx.Deadline()
	if !bounded {
		return nil, ErrInstall
	}
	proof := selected.current
	for _, cap := range []time.Time{proof.Response().ValidUntil, selected.request.Binding.ExpiresAt, p.until, h.set.owner.until, p.reservation.ExpiresAt} {
		if cap.IsZero() {
			return nil, ErrInstall
		}
		if cap.Before(until) {
			until = cap
		}
	}
	r := &originalHeldHistoryRootEOF{ctx: ctx, prep: p, hold: h, node: selected, proof: proof, binding: selected.request.Binding, anchor: selected.prepare.Response().Anchor, boot: selected.boot, path: exactPath, until: until}
	r.origin = r
	if err = r.recheckBeforeOriginalHistoryRootSQLLocked(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *originalHeldHistoryRootEOF) local(ctx context.Context, final bool) bool {
	if r == nil || r.origin != r || r.failed || !consumerSameContext(ctx, r.ctx) || !originalEmptyHistoryOwner(ctx, r.prep, r.hold, final) || r.node == nil || r.node.set != r.hold.set || r.proof == nil || r.node.prepare == nil || r.node.current == nil || r.path == "" || !time.Now().Before(r.until) {
		return false
	}
	count := 0
	for _, node := range r.hold.set.nodes {
		if node == r.node {
			count++
		}
	}
	if count != 1 || !reflect.DeepEqual(r.binding, r.node.request.Binding) || r.binding.OperationID != r.hold.set.owner.operation || r.binding.InventorySHA256 != r.hold.set.inventorySHA || r.binding.InstallationID != r.prep.operator.installer.plan.Target.InstallationID || r.binding.ReservationID != r.node.claim.ReservationID || r.binding.Generation != r.hold.set.owner.token.Generation || r.binding.FenceEpoch != r.hold.set.owner.token.FencingToken {
		return false
	}
	count = 0
	for _, root := range r.node.request.SourcePaths {
		if root == r.path {
			count++
		}
	}
	// refreshNativeHold may replace node.current. It must describe the SAME
	// original anchor/binding/boot and stopped phase, and never replaces this
	// observation's original proof pointer or extends its original until.
	if count != 1 || r.boot != r.node.boot || r.anchor == "" || r.node.prepare.Response().Anchor != r.anchor || r.node.current.Response().Anchor != r.anchor || r.proof.Response().Anchor != r.anchor || r.proof.Recheck(ctx, r.binding, "stopped", r.boot, time.Now()) != nil || r.node.current.Recheck(ctx, r.binding, "stopped", r.boot, time.Now()) != nil {
		return false
	}
	return true
}

func (r *originalHeldHistoryRootEOF) guardBeforeOrAfterRead(ctx context.Context) error {
	if !r.local(ctx, false) || r.hold.recheckBeforeSQL(ctx) != nil || r.prep.operator.authority(ctx, r.prep.enrollment) != nil || !r.local(ctx, false) {
		return ErrInstall
	}
	return nil
}

// This is the concrete consumer of C's actual directory reader. Empty requires
// actual zero entries AND io.EOF, under actual holder/gate checks on BOTH sides.
// Any nonempty page returns a private blocking input (not a synthesized Ref).
// No native I/O, gate refresh or separate SQL transaction is allowed in final SQL.
func (r *originalHeldHistoryRootEOF) recheckBeforeOriginalHistoryRootSQLLocked(ctx context.Context) (err error) {
	if r == nil {
		return ErrInstall
	}
	defer func() {
		if err != nil {
			r.failed = true
		}
	}()
	if r.guardBeforeOrAfterRead(ctx) != nil {
		return ErrInstall
	}
	directory, err := q.OpenOriginalNodeHistoryDirectory(ctx, r.proof, r.binding, r.boot, r.path)
	if err != nil {
		return err
	}
	defer directory.Close()
	entries, readErr := directory.ReadDir(ctx, 128)
	if r.guardBeforeOrAfterRead(ctx) != nil {
		return ErrInstall
	}
	if readErr != nil && readErr != io.EOF {
		return readErr
	}
	if len(entries) != 0 {
		return &originalHeldHistoryRootUnclassified{node: r.binding.Node, path: r.path, entries: append([]q.OriginalNodeHistoryDirectoryEntry(nil), entries...), pageReachedEOF: readErr == io.EOF, until: r.until}
	}
	if readErr != io.EOF {
		return ErrInstall
	}
	if err = directory.Close(); err != nil {
		return err
	}
	if !r.local(ctx, false) {
		return ErrInstall
	}
	r.observedAt = time.Now().UTC()
	return nil
}

// Pure local check only. D still owns authenticated source ranges/tx/epoch and
// the complete universe; never perform filesystem/native/network I/O here.
func (r *originalHeldHistoryRootEOF) matchesOriginalRootEOFAtSQL(ctx context.Context, p *PreparedOriginalAdoptionSQLCut, h *OriginalWriterHold, now time.Time) bool {
	return r != nil && r.prep == p && r.hold == h && !r.observedAt.IsZero() && !now.IsZero() && !now.Before(r.observedAt) && now.Before(r.until) && r.local(ctx, true)
}
