package install

import (
	"context"
	"database/sql"
	"reflect"
	"sort"
	"time"

	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
)

// This SEALED boundary is implemented by the real finite original-consumer
// reader, not a page/CLI DTO or a callback struct. Its production constructor
// must authenticate actual installed/retired consumer provenance and map ONLY
// those consumers to original storage. General business config.Load memory is
// not a universal input. A's reviewed finite-consumer contract defines scope.
// The source must return its own original opaque observation, reread real
// sources before SQL, and use ONLY already-held original SQL ranges in Locked.
type originalBackupHistoryConsumerSource interface {
	readOriginalBackupHistoryConsumers(context.Context, *PreparedOriginalAdoptionSQLCut, *OriginalWriterHold, *originalHistorySQLMetadata) (*originalResolvedBackupHistorySources, error)
	recheckOriginalBackupHistoryConsumersBeforeSQL(context.Context, *originalResolvedBackupHistorySources) error
	recheckOriginalBackupHistoryConsumersLocked(context.Context, *sql.Tx, reg.LockedSnapshot, time.Time, *originalResolvedBackupHistorySources) error
}

// Private producer-derived source observation. There is no public constructor,
// JSON authority, Passed/Complete/NoS3 field or scope-descriptor conversion.
// The ONLY permitted producer is the actual original consumer-source reader
// above. Zero value/unknown kinds/missing original source evidence refuse.
type originalResolvedBackupHistorySources struct {
	origin            *originalResolvedBackupHistorySources
	ctx               context.Context
	prep              *PreparedOriginalAdoptionSQLCut
	hold              *OriginalWriterHold
	metadata          *originalHistorySQLMetadata
	producer          originalBackupHistoryConsumerSource
	consumers         []originalBackupHistoryConsumer
	roots             []originalBackupHistoryRoot
	external          []*a.S3CoverageCensus
	revision          string
	observedAt, until time.Time
}

// Kind is derived by the real source reader from the actual supported image,
// entrypoint and retained SQL/installation source, never from a requested role.
// Independent offline/host consumers need their real original mappings. An
// unclassified or S3-backed independent consumer cannot enter this FS branch.
type originalBackupHistoryConsumer struct {
	id, kind, sourceVersion, sourceSHA256 string
}

type originalBackupHistoryRoot struct {
	consumerID, definitionSHA256, node, path string
}

type originalHistorySourceSet struct {
	origin                            *originalHistorySourceSet
	ctx                               context.Context
	prep                              *PreparedOriginalAdoptionSQLCut
	hold                              *OriginalWriterHold
	metadata                          *originalHistorySQLMetadata
	consumerSource                    originalBackupHistoryConsumerSource
	resolved                          *originalResolvedBackupHistorySources
	consumerRevision                  string
	consumerObservedAt, consumerUntil time.Time
	originalNative                    *originalHeldReadiness
	nativeUntil                       time.Time
	heldFilesystem                    []*originalHeldHistoryRootEOF
	inputs                            originalEmptyHistoryReadInputs
	snapshotRevision, fenceRevision   string
	until                             time.Time
	failed                            bool
}

func (*originalHistorySourceSet) MarshalJSON() ([]byte, error)             { return nil, ErrInstall }
func (*originalResolvedBackupHistorySources) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (*originalHistorySourceSet) String() string                           { return "OriginalHistorySourceSet" }
func (*originalHistorySourceSet) GoString() string                         { return "OriginalHistorySourceSet" }

func sameOriginalConsumerSource(a, b originalBackupHistoryConsumerSource) bool {
	if a == nil || b == nil {
		return false
	}
	x, y := reflect.ValueOf(a), reflect.ValueOf(b)
	return x.Kind() == reflect.Pointer && y.Kind() == reflect.Pointer && !x.IsNil() && !y.IsNil() && x.Type() == y.Type() && x.Pointer() == y.Pointer()
}

// Code-owned full projection; hashing the private structs themselves would
// encode {} and lose their original source/root correspondence.
func originalResolvedBackupHistoryRevision(s *originalResolvedBackupHistorySources) string {
	if s == nil || s.metadata == nil || s.hold == nil || s.hold.set == nil {
		return ""
	}
	type consumerFact struct{ ID, Kind, SourceVersion, SourceSHA256 string }
	type rootFact struct{ ConsumerID, DefinitionSHA256, Node, Path string }
	consumers := make([]consumerFact, 0, len(s.consumers))
	for _, c := range s.consumers {
		consumers = append(consumers, consumerFact{c.id, c.kind, c.sourceVersion, c.sourceSHA256})
	}
	roots := make([]rootFact, 0, len(s.roots))
	for _, r := range s.roots {
		roots = append(roots, rootFact{r.consumerID, r.definitionSHA256, r.node, r.path})
	}
	sort.Slice(consumers, func(i, j int) bool { return consumers[i].ID < consumers[j].ID })
	sort.Slice(roots, func(i, j int) bool {
		if roots[i].Node != roots[j].Node {
			return roots[i].Node < roots[j].Node
		}
		return roots[i].Path < roots[j].Path
	})
	return originalObjectSHA(struct {
		Version, SQL, OriginalWriterSet string
		Consumers                       []consumerFact
		Roots                           []rootFact
	}{"original-finite-consumer-source-selection.v1", s.metadata.revision, s.hold.set.inventorySHA, consumers, roots})
}

// Caller holds original set.mu -> prep.mu. This branch admits only the exact
// unconfigured-singleton SQL classification and a genuine closed finite
// original-consumer source. It does not choose FS-only because scanners are nil.
func prepareOriginalHistorySourceSetLocked(ctx context.Context, p *PreparedOriginalAdoptionSQLCut, h *OriginalWriterHold, producer originalBackupHistoryConsumerSource) (result *originalHistorySourceSet, err error) {
	if !originalEmptyHistoryOwner(ctx, p, h, false) || !sameOriginalConsumerSource(producer, producer) || h.recheckBeforeSQL(ctx) != nil || p.operator.authority(ctx, p.enrollment) != nil {
		return nil, ErrInstall
	}
	metadata, err := prepareOriginalHistorySQLMetadataLocked(ctx, p, h)
	if err != nil {
		return nil, err
	}
	r := &originalHistorySourceSet{ctx: ctx, prep: p, hold: h, metadata: metadata, consumerSource: producer}
	r.origin = r
	defer func() {
		if err != nil {
			r.failed = true
			metadata.close()
		}
	}()
	r.resolved, err = producer.readOriginalBackupHistoryConsumers(ctx, p, h, metadata)
	if r.resolved != nil {
		r.consumerRevision = r.resolved.revision
		r.consumerObservedAt, r.consumerUntil = r.resolved.observedAt, r.resolved.until
	}
	if err != nil || !r.resolvedSources(ctx, false) {
		return nil, ErrInstall
	}
	r.originalNative, err = h.set.refreshNativeHold(ctx)
	if err != nil {
		return nil, err
	}
	r.nativeUntil, err = originalAdoptionNativeUntil(r.originalNative)
	if err != nil {
		return nil, err
	}
	r.until = r.resolved.until
	for _, cap := range []time.Time{r.nativeUntil, metadata.until, p.until, h.set.owner.until, p.reservation.ExpiresAt} {
		if cap.IsZero() {
			return nil, ErrInstall
		}
		if cap.Before(r.until) {
			r.until = cap
		}
	}
	deadline, bounded := ctx.Deadline()
	if !bounded {
		return nil, ErrInstall
	}
	if deadline.Before(r.until) {
		r.until = deadline
	}
	if !time.Now().Before(r.until) {
		return nil, ErrInstall
	}
	// These are ONLY actual consumer-derived history roots. The full physical
	// B SourcePaths/PVC list is NOT substituted for the history-root universe.
	seen := map[string]bool{}
	for _, required := range r.resolved.roots {
		key := required.node + "\x00" + required.path
		if seen[key] {
			return nil, ErrInstall
		}
		seen[key] = true
		root, e := readOriginalHeldHistoryRootEOFLocked(ctx, p, h, required.node, required.path)
		if e != nil {
			return nil, e
		}
		r.heldFilesystem = append(r.heldFilesystem, root)
		if root.until.Before(r.until) {
			r.until = root.until
		}
	}
	// Empty root lists are legal only after resolvedSources established the
	// genuine finite producer and each actual consumer's no-external disposition.
	rootBindings := append([]originalBackupHistoryRoot(nil), r.resolved.roots...)
	sort.Slice(rootBindings, func(i, j int) bool {
		if rootBindings[i].node != rootBindings[j].node {
			return rootBindings[i].node < rootBindings[j].node
		}
		return rootBindings[i].path < rootBindings[j].path
	})
	// Do not hash unexported structs (json would encode {}). Explicit public
	// projection below preserves every derived root/source association.
	type rootFact struct{ Consumer, Definition, Node, Path string }
	roots := make([]rootFact, 0, len(rootBindings))
	for _, b := range rootBindings {
		roots = append(roots, rootFact{b.consumerID, b.definitionSHA256, b.node, b.path})
	}
	r.snapshotRevision = originalObjectSHA(struct {
		Version, SQL, Consumers string
		Roots                   []rootFact
	}{"original-finite-backup-history-source-set.v1", metadata.revision, r.resolved.revision, roots})
	r.fenceRevision = originalObjectSHA(struct {
		Version, Operation, Inventory string
		Reservation                   any
	}{"original-finite-backup-history-fence.v1", h.set.owner.operation, h.set.inventorySHA, p.reservation})
	r.inputs = originalEmptyHistoryReadInputs{heldFilesystem: append([]*originalHeldHistoryRootEOF(nil), r.heldFilesystem...), revision: r.snapshotRevision, until: r.until}
	if r.recheckOriginalFilesystemOnlyChoice(ctx, p, h, metadata, r.inputs) != nil {
		return nil, ErrInstall
	}
	return r, nil
}

func (r *originalHistorySourceSet) resolvedSources(ctx context.Context, final bool) bool {
	if r == nil || r.origin != r || r.failed || r.metadata == nil || !r.metadata.local(ctx, final) || !originalEmptyHistoryOwner(ctx, r.prep, r.hold, final) || !consumerSameContext(ctx, r.ctx) || !sameOriginalConsumerSource(r.consumerSource, r.consumerSource) {
		return false
	}
	s := r.resolved
	if s == nil || s.origin != s || !consumerSameContext(ctx, s.ctx) || s.prep != r.prep || s.hold != r.hold || s.metadata != r.metadata || !sameOriginalConsumerSource(s.producer, r.consumerSource) || s.observedAt.IsZero() || !s.observedAt.Equal(r.consumerObservedAt) || s.observedAt.Before(r.metadata.original.ObservedAt) || s.until.IsZero() || !s.until.Equal(r.consumerUntil) || !time.Now().Before(s.until) || !digestPattern.MatchString(s.revision) || s.revision != r.consumerRevision || s.revision != originalResolvedBackupHistoryRevision(s) || len(s.consumers) == 0 || len(s.consumers) > 512 || len(s.roots) > 256 || len(s.external) != 0 {
		return false
	}
	seen := map[string]bool{}
	local := map[string]bool{}
	rootCount := map[string]int{}
	for _, c := range s.consumers {
		if c.id == "" || seen[c.id] || c.sourceVersion == "" || !digestPattern.MatchString(c.sourceSHA256) {
			return false
		}
		seen[c.id] = true
		switch c.kind {
		case "original_legacy_sql_snapshot", "original_public_sql_snapshot", "original_non_backup_consumer", "original_local_history":
		default:
			return false
		}
		if c.kind == "original_local_history" {
			local[c.id] = true
		}
	}
	for _, root := range s.roots {
		if !seen[root.consumerID] || !local[root.consumerID] || !digestPattern.MatchString(root.definitionSHA256) || root.node == "" || root.path == "" {
			return false
		}
		rootCount[root.consumerID]++
	}
	for consumer := range local {
		if rootCount[consumer] == 0 {
			return false
		}
	}
	return true
}

func (r *originalHistorySourceSet) local(ctx context.Context, final bool) bool {
	return r.resolvedSources(ctx, final) && r.originalNative != nil && r.originalNative.set == r.hold.set && r.originalNative.digest != "" && !r.nativeUntil.IsZero() && !r.until.After(r.nativeUntil) && !r.until.IsZero() && time.Now().Before(r.until) && r.inputs.revision == r.snapshotRevision && r.inputs.until.Equal(r.until)
}

// These three concrete methods are C's private finite FS-only ABI. All source
// reads happen before final SQL. No public NoS3 flag or nil-scanner fallback.
func (r *originalHistorySourceSet) readOriginalFilesystemOnlyInputs(ctx context.Context, p *PreparedOriginalAdoptionSQLCut, h *OriginalWriterHold) (originalEmptyHistoryReadInputs, *originalHistorySQLMetadata, error) {
	if !r.local(ctx, false) || r.prep != p || r.hold != h {
		return originalEmptyHistoryReadInputs{}, nil, ErrInstall
	}
	if r.consumerSource.recheckOriginalBackupHistoryConsumersBeforeSQL(ctx, r.resolved) != nil {
		r.failed = true
		return originalEmptyHistoryReadInputs{}, nil, ErrInstall
	}
	current, err := r.consumerSource.readOriginalBackupHistoryConsumers(ctx, p, h, r.metadata)
	if err != nil || current != r.resolved || !r.local(ctx, false) {
		r.failed = true
		return originalEmptyHistoryReadInputs{}, nil, ErrInstall
	}
	return r.inputs, r.metadata, nil
}

func (r *originalHistorySourceSet) recheckOriginalFilesystemOnlyChoice(ctx context.Context, p *PreparedOriginalAdoptionSQLCut, h *OriginalWriterHold, metadata *originalHistorySQLMetadata, inputs originalEmptyHistoryReadInputs) error {
	if !r.local(ctx, false) || r.prep != p || r.hold != h || r.metadata != metadata || !sameOriginalEmptyHistoryInputs(r.inputs, inputs) || len(inputs.filesystem) != 0 || inputs.scopes.Artifact != nil || inputs.scopes.Staging != nil || inputs.scopes.Catalog != nil || len(inputs.scopes.Additional) != 0 {
		return ErrInstall
	}
	if h.recheckBeforeSQL(ctx) != nil || p.operator.authority(ctx, p.enrollment) != nil || metadata.recheckBeforeSQL(ctx) != nil || r.consumerSource.recheckOriginalBackupHistoryConsumersBeforeSQL(ctx, r.resolved) != nil {
		r.failed = true
		return ErrInstall
	}
	current, err := r.consumerSource.readOriginalBackupHistoryConsumers(ctx, p, h, metadata)
	if err != nil || current != r.resolved || !r.local(ctx, false) {
		r.failed = true
		return ErrInstall
	}
	return nil
}

func (r *originalHistorySourceSet) recheckOriginalFilesystemOnlyLocked(ctx context.Context, tx *sql.Tx, locked reg.LockedSnapshot, now time.Time) error {
	if !r.local(ctx, true) || tx == nil || r.metadata.boundTx != tx || r.metadata.coverage == nil || r.metadata.coverage.sourceSet != r || r.metadata.coverage.sqlMetadata != r.metadata || r.metadata.coverage.history == nil || now.IsZero() || now.Before(r.resolved.observedAt) || !now.Before(r.until) {
		return ErrInstall
	}
	if r.consumerSource.recheckOriginalBackupHistoryConsumersLocked(ctx, tx, locked, now, r.resolved) != nil {
		r.failed = true
		return ErrInstall
	}
	return nil
}

var _ originalFilesystemOnlyAuthority = (*originalHistorySourceSet)(nil)

// Concrete source-consuming coverage constructor. This is an actual production
// call to C's private finite branch, not CheckControls/rollback diagnostics.
// The consumer source's real production constructor is a separate mandatory
// input; there is no default/JSON/Passed implementation in this slice.
func (p *PreparedOriginalAdoptionSQLCut) PrepareOriginalFilesystemHistoryCoverage(ctx context.Context, h *OriginalWriterHold, producer originalBackupHistoryConsumerSource) (*PreparedOriginalAdoptionCoverage, error) {
	if p == nil || h == nil || h.set == nil {
		return nil, ErrInstall
	}
	h.set.mu.Lock()
	defer h.set.mu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	sources, err := prepareOriginalHistorySourceSetLocked(ctx, p, h, producer)
	if err != nil {
		return nil, err
	}
	history, err := collectOriginalFilesystemOnlyHistorySourceLocked(ctx, p, h, sources)
	if err != nil {
		sources.failed = true
		sources.metadata.close()
		return nil, err
	}
	if !sources.local(ctx, false) || history == nil || history.origin != history || history.prep != p || history.hold != h || !consumerSameContext(ctx, history.ctx) || history.recheckBeforeOriginalHistorySQL(ctx) != nil {
		sources.failed = true
		sources.metadata.close()
		return nil, ErrInstall
	}
	refs := history.references()
	if refs == nil || len(refs) != 0 {
		return nil, ErrInstall
	}
	until := sources.until
	if history.validUntil().Before(until) {
		until = history.validUntil()
	}
	coverage := &PreparedOriginalAdoptionCoverage{ctx: ctx, hold: h, history: history, refs: refs, epoch: ^uint64(0), until: until, sourceSet: sources, sqlMetadata: sources.metadata}
	coverage.origin = coverage
	return coverage, nil
}

// A real final caller. It never substitutes four INSERTs or a rollback proof.
// C/A's supplied records remain untrusted until original Stage/Bind's actual
// authentication. The same original ctx/hold/p/source preparation is consumed.
func (p *PreparedOriginalAdoptionSQLCut) AdoptOriginalFilesystemHistory(ctx context.Context, h *OriginalWriterHold, producer originalBackupHistoryConsumerSource, preparation *a.SQLBootstrapKEKPreparation, records a.OriginalAdoptionControlRecords) (OriginalAdoptionCommitInspection, error) {
	coverage, err := p.PrepareOriginalFilesystemHistoryCoverage(ctx, h, producer)
	if err != nil {
		return OriginalAdoptionCommitInspection{}, err
	}
	return p.CommitOriginalAdoption(ctx, h, records, preparation, coverage)
}
