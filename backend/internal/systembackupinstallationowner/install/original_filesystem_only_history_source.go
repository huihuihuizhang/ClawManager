package install

import (
	"context"
	"database/sql"
	"reflect"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
)

// Only D's genuine, complete, finite installed-source factory implements this
// private authority. The choice recheck MUST read/verify its actual SQL-backed
// consumer identities, original fixed provider mappings, actually selected
// independent consumers/retired outputs and necessary roots. It must reject an
// unresolved source. Nil scopes, zero refs, defaults, hashes or caller flags are
// not an implementation of that authority. All callbacks run under set.mu then
// preparation.mu, outside final SQL except the explicitly Locked callback.
type originalFilesystemOnlyAuthority interface {
	readOriginalFilesystemOnlyInputs(context.Context, *PreparedOriginalAdoptionSQLCut, *OriginalWriterHold) (originalEmptyHistoryReadInputs, *originalHistorySQLMetadata, error)
	recheckOriginalFilesystemOnlyChoice(context.Context, *PreparedOriginalAdoptionSQLCut, *OriginalWriterHold, *originalHistorySQLMetadata, originalEmptyHistoryReadInputs) error
	recheckOriginalFilesystemOnlyLocked(context.Context, *sql.Tx, reg.LockedSnapshot, time.Time) error
}

type originalFilesystemOnlyHistory struct {
	origin    *originalFilesystemOnlyHistory
	source    *originalEmptyHistorySource
	authority originalFilesystemOnlyAuthority
	metadata  *originalHistorySQLMetadata
}

func (*originalFilesystemOnlyHistory) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (*originalFilesystemOnlyHistory) String() string               { return "OriginalFilesystemOnlyHistory" }
func (*originalFilesystemOnlyHistory) GoString() string             { return "OriginalFilesystemOnlyHistory" }

// This is a separate private entry, not a relaxation of the existing three-S3
// collector or public DATA interfaces. It still returns the original concrete
// classified-source type expected by D's actual coverage metadata binding.
func collectOriginalFilesystemOnlyHistorySource(ctx context.Context, p *PreparedOriginalAdoptionSQLCut, h *OriginalWriterHold, authority originalFilesystemOnlyAuthority) (*originalEmptyHistorySource, error) {
	if p == nil || h == nil || h.set == nil {
		return nil, ErrInstall
	}
	h.set.mu.Lock()
	defer h.set.mu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	return collectOriginalFilesystemOnlyHistorySourceLocked(ctx, p, h, authority)
}

func collectOriginalFilesystemOnlyHistorySourceLocked(ctx context.Context, p *PreparedOriginalAdoptionSQLCut, h *OriginalWriterHold, authority originalFilesystemOnlyAuthority) (result *originalEmptyHistorySource, err error) {
	if authority == nil {
		return nil, ErrInstall
	}
	v := reflect.ValueOf(authority)
	if v.Kind() != reflect.Pointer || v.IsNil() || !originalEmptyHistoryOwner(ctx, p, h, false) || h.recheckBeforeSQL(ctx) != nil || p.operator.authority(ctx, p.enrollment) != nil {
		return nil, ErrInstall
	}
	inputs, metadata, err := authority.readOriginalFilesystemOnlyInputs(ctx, p, h)
	if err != nil || metadata == nil || metadata.prep != p || metadata.hold != h || !metadata.local(ctx, false) || !metadata.classifiesOriginalSQL(ctx, p.observed.Facts()) || !validOriginalFilesystemOnlyInputs(ctx, p, h, inputs) {
		return nil, ErrInstall
	}
	// The genuine source owner must positively authenticate the finite choice;
	// the structurally empty S3 fields are never themselves absence evidence.
	if authority.recheckOriginalFilesystemOnlyChoice(ctx, p, h, metadata, inputs) != nil {
		return nil, ErrInstall
	}
	inputs.heldFilesystem = append([]*originalHeldHistoryRootEOF(nil), inputs.heldFilesystem...)
	until, bounded := ctx.Deadline()
	if !bounded {
		return nil, ErrInstall
	}
	caps := []time.Time{inputs.until, metadata.until, p.until, h.set.owner.until, p.reservation.ExpiresAt}
	for _, root := range inputs.heldFilesystem {
		caps = append(caps, root.until)
	}
	for _, cap := range caps {
		if cap.IsZero() {
			return nil, ErrInstall
		}
		if cap.Before(until) {
			until = cap
		}
	}
	if !time.Now().Before(until) {
		return nil, ErrInstall
	}
	s := &originalEmptyHistorySource{ctx: ctx, prep: p, hold: h, inputs: inputs, until: until}
	s.origin = s
	f := &originalFilesystemOnlyHistory{source: s, authority: authority, metadata: metadata}
	f.origin = f
	s.filesystemOnly = f
	if err = s.readActualEmptySources(ctx); err != nil {
		s.failed = true
		metadata.close()
		return nil, err
	}
	return s, nil
}

// Structural checks never assert NoS3. That conclusion is mandatory in the
// separate genuine-authority callback above and on every later native round.
// Raw os.Root is prohibited here; every chosen root must be an actual held EOF
// observation with the exact original preparation/holder and immutable cap.
func validOriginalFilesystemOnlyInputs(ctx context.Context, p *PreparedOriginalAdoptionSQLCut, h *OriginalWriterHold, i originalEmptyHistoryReadInputs) bool {
	if !digestPattern.MatchString(i.revision) || i.until.IsZero() || !time.Now().Before(i.until) || i.scopes.Artifact != nil || i.scopes.Staging != nil || i.scopes.Catalog != nil || len(i.scopes.Additional) != 0 || len(i.filesystem) != 0 || len(i.heldFilesystem) > 256 {
		return false
	}
	seen := map[*originalHeldHistoryRootEOF]bool{}
	for n, root := range i.heldFilesystem {
		if root == nil || seen[root] || root.prep != p || root.hold != h || root.observedAt.IsZero() || !root.local(ctx, false) {
			return false
		}
		seen[root] = true
		for _, prior := range i.heldFilesystem[:n] {
			if prior.node == root.node && prior.path == root.path {
				return false
			}
		}
	}
	return true
}

func (f *originalFilesystemOnlyHistory) local(ctx context.Context, final bool) bool {
	return f != nil && f.origin == f && f.source != nil && f.source.origin == f.source && f.source.filesystemOnly == f && !f.source.failed && f.authority != nil && f.metadata != nil && f.metadata.prep == f.source.prep && f.metadata.hold == f.source.hold && consumerSameContext(ctx, f.source.ctx) && originalEmptyHistoryOwner(ctx, f.source.prep, f.source.hold, final) && time.Now().Before(f.source.until) && f.metadata.local(ctx, final)
}

// Actual source reads stay outside the final SQL prefix. No caller-supplied
// unadmitted table result, inferred empty target or old exhausted cursor enters.
func (s *originalEmptyHistorySource) readActualFilesystemOnlySources(ctx context.Context) (err error) {
	f := s.filesystemOnly
	defer func() {
		if err != nil {
			s.failed = true
			if f != nil && f.metadata != nil {
				f.metadata.close()
			}
		}
	}()
	if !f.local(ctx, false) {
		return ErrInstall
	}
	p, h, m := s.prep, s.hold, f.metadata
	if h.recheckBeforeSQL(ctx) != nil || p.operator.authority(ctx, p.enrollment) != nil || f.authority.recheckOriginalFilesystemOnlyChoice(ctx, p, h, m, s.inputs) != nil {
		return ErrInstall
	}
	inputs, actualMetadata, err := f.authority.readOriginalFilesystemOnlyInputs(ctx, p, h)
	if err != nil || actualMetadata != m || !validOriginalFilesystemOnlyInputs(ctx, p, h, inputs) || !sameOriginalEmptyHistoryInputs(inputs, s.inputs) || m.recheckBeforeSQL(ctx) != nil {
		return ErrInstall
	}
	for _, root := range inputs.heldFilesystem {
		if err = root.recheckBeforeOriginalHistoryRootSQLLocked(ctx); err != nil {
			return err
		}
	}
	tail, err := p.scanner.Observe(ctx)
	if err != nil || !m.classifiesOriginalSQL(ctx, tail.Facts()) || tail.Facts().ObservedAt.Before(m.floor) {
		return ErrInstall
	}
	for _, root := range inputs.heldFilesystem {
		if err = root.recheckBeforeOriginalHistoryRootSQLLocked(ctx); err != nil {
			return err
		}
	}
	if f.authority.recheckOriginalFilesystemOnlyChoice(ctx, p, h, m, s.inputs) != nil || h.recheckBeforeSQL(ctx) != nil || p.operator.authority(ctx, p.enrollment) != nil || !f.local(ctx, false) {
		return ErrInstall
	}
	s.sqlAt = tail.Facts().ObservedAt
	return nil
}

// Exact same original coverage/tx/epoch is bound by D before this callback.
// Metadata's guard rejects first-callback transaction learning. These callbacks
// are SQL-only and cannot refresh an observation or perform filesystem I/O.
func (f *originalFilesystemOnlyHistory) recheckLocked(ctx context.Context, tx *sql.Tx, locked reg.LockedSnapshot, now time.Time) (err error) {
	if !f.local(ctx, true) {
		return ErrInstall
	}
	defer func() {
		if err != nil {
			f.source.failed = true
			f.metadata.close()
		}
	}()
	if f.metadata.coverage == nil || f.metadata.coverage.history != f.source || f.metadata.recheckLocked(ctx, tx, locked, now) != nil {
		return ErrInstall
	}
	return f.authority.recheckOriginalFilesystemOnlyLocked(ctx, tx, locked, now)
}
