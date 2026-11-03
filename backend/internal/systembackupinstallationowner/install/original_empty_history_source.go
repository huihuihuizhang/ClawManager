package install

import (
	"context"
	"database/sql"
	"os"
	"reflect"
	"sync"
	"time"

	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
)

// Only D's original installed-source owner implements this private boundary.
// Its factory must derive the COMPLETE original universe, including Additional
// and necessary filesystem sources. No public constructor accepts scope DTOs,
// Unadmitted DATA, a Passed flag or a claim that newly created buckets are empty.
// All methods run under the caller's original set.mu -> preparation.mu order.
type originalEmptyHistoryAuthority interface {
	readOriginalEmptyHistoryInputs(context.Context, *PreparedOriginalAdoptionSQLCut, *OriginalWriterHold) (originalEmptyHistoryReadInputs, error)
	recheckOriginalEmptyHistoryBeforeSQL(context.Context, originalEmptyHistoryReadInputs) error
	recheckOriginalEmptyHistoryLocked(context.Context, *sql.Tx, reg.LockedSnapshot, time.Time) error
}

type originalEmptyHistoryReadInputs struct {
	scopes         a.OriginalEmptyHistoryScopes
	filesystem     []*os.Root
	heldFilesystem []*originalHeldHistoryRootEOF
	revision       string
	until          time.Time
}

// This private classified source is created only AFTER actual source reads.
// It is not PreparedCoverage; D still owns the original17 controls, their exact
// own-row journal, final transaction, authenticated source associations and epoch.
type originalEmptyHistorySource struct {
	filesystemOnly *originalFilesystemOnlyHistory
	mu             sync.Mutex
	origin         *originalEmptyHistorySource
	ctx            context.Context
	prep           *PreparedOriginalAdoptionSQLCut
	hold           *OriginalWriterHold
	authority      originalEmptyHistoryAuthority
	inputs         originalEmptyHistoryReadInputs
	roots          []*originalEmptyHistoryRootObservation
	until          time.Time
	sqlAt          time.Time
	boundTx        *sql.Tx
	epoch          uint64
	failed         bool
}

func (*originalEmptyHistorySource) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (*originalEmptyHistorySource) String() string               { return "OriginalEmptyHistorySource" }
func (*originalEmptyHistorySource) GoString() string             { return "OriginalEmptyHistorySource" }

// Caller enters through D's authenticated ORIGINAL source-set factory, without
// already holding these mutexes. This method takes no final SQL/KEK range locks.
func collectOriginalEmptyHistorySource(ctx context.Context, p *PreparedOriginalAdoptionSQLCut, hold *OriginalWriterHold, authority originalEmptyHistoryAuthority) (*originalEmptyHistorySource, error) {
	if p == nil || hold == nil || hold.set == nil || authority == nil {
		return nil, ErrInstall
	}
	rv := reflect.ValueOf(authority)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return nil, ErrInstall
	}
	hold.set.mu.Lock()
	defer hold.set.mu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	if !originalEmptyHistoryOwner(ctx, p, hold, false) || hold.recheckBeforeSQL(ctx) != nil {
		return nil, ErrInstall
	}
	inputs, err := authority.readOriginalEmptyHistoryInputs(ctx, p, hold)
	if err != nil || !validOriginalEmptyHistoryInputs(inputs) {
		return nil, ErrInstall
	}
	inputs.scopes.Additional = append([]*a.S3CoverageCensus(nil), inputs.scopes.Additional...)
	inputs.filesystem = append([]*os.Root(nil), inputs.filesystem...)
	inputs.heldFilesystem = append([]*originalHeldHistoryRootEOF(nil), inputs.heldFilesystem...)
	until := inputs.until
	caps := []time.Time{p.until, hold.set.owner.until, p.reservation.ExpiresAt}
	for _, root := range inputs.heldFilesystem {
		if root.prep != p || root.hold != hold || !root.local(ctx, false) || root.observedAt.IsZero() {
			return nil, ErrInstall
		}
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
	s := &originalEmptyHistorySource{ctx: ctx, prep: p, hold: hold, authority: authority, inputs: inputs, until: until}
	s.origin = s
	if err = s.readActualEmptySources(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func validOriginalEmptyHistoryInputs(i originalEmptyHistoryReadInputs) bool {
	if !digestPattern.MatchString(i.revision) || i.until.IsZero() || i.scopes.Artifact == nil || i.scopes.Staging == nil || i.scopes.Catalog == nil || len(i.scopes.Additional) > 256 || len(i.filesystem) > 256 || len(i.heldFilesystem) > 256 {
		return false
	}
	for _, scope := range i.scopes.Additional {
		if scope == nil {
			return false
		}
	}
	for _, root := range i.heldFilesystem {
		if root == nil || root.origin != root || root.failed || root.observedAt.IsZero() || root.until.IsZero() {
			return false
		}
	}
	for _, root := range i.filesystem {
		if root == nil {
			return false
		}
	}
	return true
}

func originalEmptyHistoryOwner(ctx context.Context, p *PreparedOriginalAdoptionSQLCut, h *OriginalWriterHold, final bool) bool {
	if ctx == nil || ctx.Err() != nil || p == nil || p.origin != p || p.operator == nil || p.scanner == nil || p.observed == nil || h == nil || h.origin != h || h.closed || h.adoptionUnknown || h.set == nil || h.set.origin != h.set || h.set.owner == nil || h.set.owner.operator == nil || h.set.owner.origin != h.set.owner {
		return false
	}
	owner := h.set.owner
	if !consumerSameContext(ctx, p.ctx) || !consumerSameContext(ctx, h.ctx) || !consumerSameContext(ctx, owner.ctx) || p.operator.installer != owner.operator.installer || p.enrollment != owner.enrollment || p.reservation.OperationID != owner.operation || p.reservation.SourceWritersSHA256 != h.set.inventorySHA || !p.operator.live(ctx) || !owner.operator.live(ctx) || !time.Now().Before(p.until) || !time.Now().Before(owner.until) {
		return false
	}
	return p.used == final
}

func sameOriginalEmptyHistoryInputs(a, b originalEmptyHistoryReadInputs) bool {
	if a.revision != b.revision || !a.until.Equal(b.until) || a.scopes.Artifact != b.scopes.Artifact || a.scopes.Staging != b.scopes.Staging || a.scopes.Catalog != b.scopes.Catalog || len(a.scopes.Additional) != len(b.scopes.Additional) || len(a.filesystem) != len(b.filesystem) || len(a.heldFilesystem) != len(b.heldFilesystem) {
		return false
	}
	for n, p := range a.scopes.Additional {
		if p != b.scopes.Additional[n] {
			return false
		}
	}
	for n, p := range a.heldFilesystem {
		if p != b.heldFilesystem[n] {
			return false
		}
	}
	for n, p := range a.filesystem {
		if p != b.filesystem[n] {
			return false
		}
	}
	return true
}

func emptyOriginalSQLObservation(p *a.UnadmittedSQLCoverageCensus) bool {
	if p == nil {
		return false
	}
	facts := p.Facts()
	if facts.ObservedAt.IsZero() || len(facts.Tables) == 0 {
		return false
	}
	for _, table := range facts.Tables {
		if table.Rows != 0 || table.Bytes != 0 {
			return false
		}
	}
	return true
}

// All actual SQL/S3/FS/native I/O stays OUTSIDE the final SQL lock segment.
// Repeated calls retain the original roots, revision and expiry; no renewal.
func (s *originalEmptyHistorySource) readActualEmptySources(ctx context.Context) error {
	if s != nil && s.filesystemOnly != nil {
		return s.readActualFilesystemOnlySources(ctx)
	}
	if s == nil || s.origin != s || s.failed || !originalEmptyHistoryOwner(ctx, s.prep, s.hold, false) || !consumerSameContext(ctx, s.ctx) || !time.Now().Before(s.until) {
		return ErrInstall
	}
	p := s.prep
	if s.hold.recheckBeforeSQL(ctx) != nil || p.operator.authority(ctx, p.enrollment) != nil || s.authority.recheckOriginalEmptyHistoryBeforeSQL(ctx, s.inputs) != nil {
		return ErrInstall
	}
	inputs, err := s.authority.readOriginalEmptyHistoryInputs(ctx, p, s.hold)
	if err != nil || !validOriginalEmptyHistoryInputs(inputs) || !sameOriginalEmptyHistoryInputs(inputs, s.inputs) || !emptyOriginalSQLObservation(p.observed) {
		return ErrInstall
	}
	for _, root := range inputs.heldFilesystem {
		if root.prep != p || root.hold != s.hold {
			return ErrInstall
		}
		if err := root.recheckBeforeOriginalHistoryRootSQLLocked(ctx); err != nil {
			return err
		}
	}
	for _, old := range s.roots {
		if old.recheck(ctx) != nil {
			return ErrInstall
		}
	}
	roots := make([]*originalEmptyHistoryRootObservation, 0, len(inputs.filesystem))
	for _, root := range inputs.filesystem {
		observed, e := observeEmptyOriginalHistoryRoot(ctx, root)
		if e != nil {
			return e
		}
		for _, prior := range roots {
			if os.SameFile(prior.info, observed.info) {
				return ErrInstall
			}
		}
		roots = append(roots, observed)
	}
	// Neither an Unadmitted object from a caller nor a supplied reference list
	// can enter here: invoke the actual original scanners now.
	actual, err := a.CollectEmptyOriginalHistory(ctx, p.scanner, inputs.scopes)
	if err != nil {
		return err
	}
	refs, err := actual.EmptyReferences()
	if err != nil || refs == nil || len(refs) != 0 {
		return ErrInstall
	}
	tail, err := p.scanner.Observe(ctx)
	if err != nil || !emptyOriginalSQLObservation(tail) || !reflect.DeepEqual(tail.Facts().Tables, p.observed.Facts().Tables) || tail.Facts().Database != p.observed.Facts().Database || tail.Facts().InstallationID != p.observed.Facts().InstallationID {
		return ErrInstall
	}
	for _, root := range roots {
		if root.recheck(ctx) != nil {
			return ErrInstall
		}
	}
	for _, root := range inputs.heldFilesystem {
		if err := root.recheckBeforeOriginalHistoryRootSQLLocked(ctx); err != nil {
			return err
		}
	}
	if s.authority.recheckOriginalEmptyHistoryBeforeSQL(ctx, s.inputs) != nil || s.hold.recheckBeforeSQL(ctx) != nil || p.operator.authority(ctx, p.enrollment) != nil || !time.Now().Before(s.until) {
		return ErrInstall
	}
	s.roots = roots
	s.sqlAt = tail.Facts().ObservedAt
	return nil
}

// D MUST call this with set.mu -> prep.mu already held, immediately before its
// BeginOriginalTransaction. Replaying only an old inspection/hash is refused.
func (s *originalEmptyHistorySource) recheckBeforeOriginalHistorySQL(ctx context.Context) (err error) {
	if s == nil {
		return ErrInstall
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() {
		if err != nil {
			s.failed = true
		}
	}()
	return s.readActualEmptySources(ctx)
}

func (s *originalEmptyHistorySource) references() []reg.Reference {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.origin != s || s.failed || s.sqlAt.IsZero() || s.until.IsZero() {
		return nil
	}
	return []reg.Reference{}
}

func (s *originalEmptyHistorySource) validUntil() time.Time {
	if s == nil {
		return time.Time{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.origin != s || s.failed || s.sqlAt.IsZero() || s.until.IsZero() {
		return time.Time{}
	}
	return s.until
}

// No HTTP, provider, filesystem or new SQL transaction is allowed here.
// D's coverage recheck has already authenticated its actual original control
// cut/transaction. This additionally locks/rechecks the original source owner.
func (s *originalEmptyHistorySource) recheckOriginalHistory(ctx context.Context, tx *sql.Tx, locked reg.LockedSnapshot, now time.Time) (err error) {
	if s == nil {
		return ErrInstall
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() {
		if err != nil {
			s.failed = true
		}
	}()
	if s.origin != s || s.failed || s.sqlAt.IsZero() || tx == nil || !originalEmptyHistoryOwner(ctx, s.prep, s.hold, true) || !consumerSameContext(ctx, s.ctx) || now.IsZero() || now.Before(s.sqlAt) || !now.Before(s.until) {
		return ErrInstall
	}
	for _, root := range s.inputs.heldFilesystem {
		if !root.matchesOriginalRootEOFAtSQL(ctx, s.prep, s.hold, now) {
			return ErrInstall
		}
	}
	facts := locked.Facts()
	if facts.Database != s.prep.observed.Facts().Database || facts.InstallationID != s.prep.observed.Facts().InstallationID || facts.References == nil || len(facts.References) != 0 || (s.boundTx != nil && (s.boundTx != tx || facts.Epoch != s.epoch)) {
		return ErrInstall
	}
	if s.filesystemOnly != nil {
		if s.filesystemOnly.recheckLocked(ctx, tx, locked, now) != nil {
			return ErrInstall
		}
	} else if s.authority.recheckOriginalEmptyHistoryLocked(ctx, tx, locked, now) != nil {
		return ErrInstall
	}
	if s.boundTx == nil {
		s.boundTx = tx
		s.epoch = facts.Epoch
	}
	return nil
}

var _ originalClassifiedHistorySource = (*originalEmptyHistorySource)(nil)
