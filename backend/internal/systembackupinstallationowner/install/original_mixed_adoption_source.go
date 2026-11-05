package install

import (
	"context"
	"database/sql"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"time"

	c "clawreef/internal/systembackupcontroller"
	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
)

// A separate first-adoption type. The existing finite empty implementation
// retains its zero-reference rules. Only this concrete source-owning factory
// can bind nonempty original history to the original transaction and epoch.
type PreparedOriginalMixedAdoptionCoverage struct {
	origin        *PreparedOriginalMixedAdoptionCoverage
	ctx           context.Context
	hold          *OriginalWriterHold
	history       *originalMixedHistorySource
	cut           *a.OriginalAdoptionControlCut
	authenticated *a.AuthenticatedFirstAdoption
	native        *originalHeldReadiness
	tx            *sql.Tx
	sources       []reg.CoverageSource
	refs          []reg.Reference
	epoch         uint64
	until         time.Time
	adopted       bool // Set ONLY after this owner's actual Bound.AdoptCoverage succeeds.
}

func (*PreparedOriginalMixedAdoptionCoverage) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (p *PreparedOriginalMixedAdoptionCoverage) Sources() []reg.CoverageSource {
	if p == nil || p.origin != p {
		return nil
	}
	return retainedC1Copy(p.sources)
}
func (p *PreparedOriginalMixedAdoptionCoverage) References() []reg.Reference {
	if p == nil || p.origin != p {
		return nil
	}
	return retainedC1Copy(p.refs)
}
func (p *PreparedOriginalMixedAdoptionCoverage) ExpectedEpoch() uint64 {
	if p == nil || p.origin != p {
		return ^uint64(0)
	}
	return p.epoch
}
func (p *PreparedOriginalMixedAdoptionCoverage) ValidUntil() time.Time {
	if p == nil || p.origin != p {
		return time.Time{}
	}
	return p.until
}

func originalMixedPartitionReferences(refs []reg.Reference, partition reg.Partition) []reg.Reference {
	owned := make([]reg.Reference, 0)
	for _, ref := range refs {
		if ref.Partition == partition {
			owned = append(owned, ref)
		}
	}
	sort.Slice(owned, func(i, j int) bool {
		if owned[i].SourceRecordID != owned[j].SourceRecordID {
			return owned[i].SourceRecordID < owned[j].SourceRecordID
		}
		return owned[i].SourceRecordVersion < owned[j].SourceRecordVersion
	})
	return owned
}

// Only after actual Stage17 / independent A Bind+authentication. No first
// Recheck callback or unsigned claim can attach a transaction to this source.
func (p *PreparedOriginalMixedAdoptionCoverage) bindOriginalMixedHistoryControls(ctx context.Context, cfg a.SQLCoverageOwnerConfig, records a.OriginalAdoptionControlRecords) error {
	if p == nil || p.origin != p || !consumerSameContext(ctx, p.ctx) || p.history == nil || p.history.coverage != p || !p.history.local(ctx, true) || p.tx == nil || p.cut == nil || p.authenticated == nil || p.native == nil || p.native.set != p.hold.set || p.epoch != p.history.retained.before.Epoch || p.history.retained.tx != p.tx || !p.history.retained.staged || len(p.sources) != 0 || len(p.refs) == 0 || !reflect.DeepEqual(p.refs, p.history.references()) || len(records) != 17 || cfg.DB != p.history.prep.operator.installer.db || cfg.Database != p.history.retained.before.Database || cfg.InstallationID != p.history.retained.before.InstallationID {
		return ErrInstall
	}
	signed, found := records[cfg.Adoption.Source.RecordID]
	var adoption a.CoverageAdoptionRecord
	if !found || decodeExact(signed.Record, &adoption) != nil || adoption.Source != cfg.Adoption.Source || adoption.Facts.Database != cfg.Database || adoption.Facts.InstallationID != cfg.InstallationID || adoption.Facts.AdoptedEpoch != p.epoch+1 || len(adoption.Facts.Partitions) != 4 {
		return ErrInstall
	}
	seen := map[reg.Partition]bool{}
	for _, part := range adoption.Facts.Partitions {
		valid := false
		for _, known := range originalAdoptionPartitions {
			if part.Partition == known {
				valid = true
			}
		}
		owned := originalMixedPartitionReferences(p.refs, part.Partition)
		if !valid || seen[part.Partition] || part.SourceID == "" || len(part.SourceID) > 256 || part.SnapshotRevision != p.history.snapshotRevision || part.FenceRevision != p.history.fenceRevision || part.ReferenceCount != uint64(len(owned)) || part.ReferencesSHA256 != originalObjectSHA(owned) {
			return ErrInstall
		}
		seen[part.Partition] = true
		p.sources = append(p.sources, reg.CoverageSource{Partition: part.Partition, SourceID: part.SourceID, SnapshotRevision: part.SnapshotRevision, FenceRevision: part.FenceRevision, AdoptionSource: adoption.Source})
	}
	sort.Slice(p.sources, func(i, j int) bool { return p.sources[i].Partition < p.sources[j].Partition })
	p.until = minTime(p.until, minTime(p.authenticated.ValidUntil(), p.history.until))
	if p.until.IsZero() || !time.Now().Before(p.until) {
		return ErrInstall
	}
	m := p.history.finite.metadata
	if m.boundTx != nil || m.coverage != nil {
		return ErrInstall
	}
	m.boundTx, m.epoch = p.tx, p.epoch
	return nil
}

func (p *PreparedOriginalMixedAdoptionCoverage) Recheck(ctx context.Context, view reg.SQLReadView, locked reg.LockedSnapshot, now time.Time) error {
	if p == nil || p.origin != p || !consumerSameContext(ctx, p.ctx) || p.history == nil || p.history.coverage != p || p.tx == nil || view != p.tx || p.cut == nil || p.authenticated == nil || p.native == nil || p.hold == nil || p.native.set != p.hold.set || p.hold.closed || p.hold.adoptionUnknown || now.IsZero() || !now.Before(p.until) || locked.Facts().Epoch != p.epoch || !reflect.DeepEqual(locked.Facts().References, p.refs) || !reflect.DeepEqual(p.history.references(), p.refs) || len(p.sources) != 4 {
		return ErrInstall
	}
	if p.authenticated.Recheck(ctx, p.tx, locked, now) != nil || p.cut.Recheck(ctx) != nil || p.native.VerifyParticipantsPaused(ctx, c.SQLCoordinationTransaction{Tx: p.tx}, p.hold.set.owner.token.Key, p.hold.set.owner.token.Generation) != nil {
		return ErrInstall
	}
	return p.history.recheckLocked(ctx, p.tx, locked, now)
}

type originalMixedHistorySource struct {
	origin                          *originalMixedHistorySource
	ctx                             context.Context
	prep                            *PreparedOriginalAdoptionSQLCut
	hold                            *OriginalWriterHold
	finite                          *originalHistorySourceSet
	consumer                        *originalFiniteBackupConsumerSource
	retained                        *OriginalC1RetainedEvidence
	external                        *originalProtectedMinIOArchive
	coverage                        *PreparedOriginalMixedAdoptionCoverage
	snapshotRevision, fenceRevision string
	until                           time.Time
	failed                          bool
	objectClasses                   []originalMinIOHistoryObjectClass
	business                        *originalMinIOBusinessHistorySource
}

func (r *originalMixedHistorySource) validUntil() time.Time {
	if r == nil || r.origin != r || r.failed {
		return time.Time{}
	}
	return r.until
}

func (r *originalMixedHistorySource) references() []reg.Reference {
	if r == nil || r.origin != r || r.failed || r.retained == nil {
		return nil
	}
	return r.retained.References()
}

func (r *originalMixedHistorySource) local(ctx context.Context, final bool) bool {
	return r != nil && r.origin == r && !r.failed && consumerSameContext(ctx, r.ctx) && r.prep != nil && r.hold != nil && r.finite != nil && r.finite.prep == r.prep && r.finite.hold == r.hold && r.finite.local(ctx, final) && r.consumer != nil && r.finite.consumerSource == r.consumer && r.retained != nil && r.retained.origin == r.retained && !r.retained.failed && r.retained.receipt != nil && r.retained.receipt.prep == r.prep && r.retained.receipt.hold == r.hold && r.external != nil && r.external.origin == r.external && r.external.hold == r.hold && r.external.archive != nil && r.external.warm != nil && r.external.archive.provider == r.retained.provider && r.external.warm.set == r.hold.set && r.business != nil && r.business.origin == r.business && r.business.prep == r.prep && r.business.hold == r.hold && r.business.local(ctx) && !r.until.IsZero() && time.Now().Before(r.until)
}

func (r *originalMixedHistorySource) recheckBeforeOriginalHistorySQL(ctx context.Context) error {
	if !r.local(ctx, false) || r.coverage == nil || r.coverage.tx != nil || r.retained.recheckBeforeSQL(ctx) != nil || r.external.archive.RecheckBeforeOriginalSQL(ctx) != nil || r.finite.recheckOriginalFilesystemOnlyChoice(ctx, r.prep, r.hold, r.finite.metadata, r.finite.inputs) != nil {
		return ErrInstall
	}
	if r.business.recheckBeforeSQL(ctx) != nil {
		return ErrInstall
	}
	facts, e := r.external.warm.protected.OriginalHistoryData(ctx)
	if e != nil || !reflect.DeepEqual(facts, r.external.warm.facts) {
		return ErrInstall
	}
	if recheckOriginalNativeInventoryFile(r.external.warm.warmEvidence, r.external.warm.warm.raw) != nil || recheckOriginalNativeInventoryFile(r.external.afterEvidence, r.external.cold.raw) != nil {
		return ErrInstall
	}
	actual, e := readOriginalMinIOFullTree(ctx, r.external.native, "cold")
	if e != nil || !sameOriginalMinIOTree(actual, r.external.cold) || r.hold.recheckBeforeSQL(ctx) != nil {
		return ErrInstall
	}
	return nil
}

// No provider/Kube/filesystem I/O here. All source ranges and the original
// fence are already owned by this tx. Only the actual 17 writer journal is
// allowed to account for source differences in the complete raw scan.
func (r *originalMixedHistorySource) recheckLocked(ctx context.Context, tx *sql.Tx, locked reg.LockedSnapshot, now time.Time) error {
	if !r.local(ctx, true) || r.coverage == nil || r.coverage.origin != r.coverage || r.coverage.tx != tx || r.coverage.cut == nil || r.retained.tx != tx || !r.retained.staged || r.finite.metadata.boundTx != tx || now.Before(r.finite.metadata.floor) || now.Before(r.finite.resolved.observedAt) || !now.Before(r.until) {
		return ErrInstall
	}
	p := r.coverage
	if locked.Facts().Database != r.retained.before.Database || locked.Facts().InstallationID != r.retained.before.InstallationID || locked.Facts().Epoch != r.retained.before.Epoch || !reflect.DeepEqual(locked.Facts().References, r.references()) {
		return ErrInstall
	}
	if r.business.recheckLocked(ctx, tx) != nil {
		return ErrInstall
	}
	m := r.finite.metadata
	if m.installed.recheckLocked(ctx, tx) != nil || !m.installedMatchesOriginal() || r.consumer.controllerInventory == nil || !r.consumer.controllerInventory.matchesOriginalSQLPhase(ctx, m, now) || r.consumer.resolved != r.finite.resolved || r.finite.resolved.revision != originalResolvedBackupHistoryRevision(r.finite.resolved) {
		return ErrInstall
	}
	row, e := readOriginalHistorySingletonRow(ctx, tx, m.installed.installation, true)
	if e != nil {
		return ErrInstall
	}
	defer row.clear()
	if !reflect.DeepEqual(row.cells, m.row.cells) {
		return ErrInstall
	}
	epoch := p.epoch
	if p.adopted {
		if epoch == ^uint64(0) {
			return ErrInstall
		}
		epoch++
	}
	if r.prep.runtimeMetadata == nil || r.prep.runtimeMetadata.recheck(ctx, tx, epoch, p.cut) != nil || r.retained.receipt.recheckLocked(ctx, tx, epoch, p.cut) != nil {
		return ErrInstall
	}
	stamp, e := r.prep.operator.installer.database(ctx, tx, r.until)
	if e != nil || stamp.Before(now) || stamp.Before(m.floor) {
		return ErrInstall
	}
	return nil
}

// The encrypted raw archive is itself a retained original evidence envelope.
// Its real key must be one of the independently authenticated C1 retained
// bindings; it cannot alias the backup KEK or silently lose its protection.
func (r *originalMixedHistorySource) attachActualRawArchiveReference() error {
	copy := r.external.archive.retained.data.Copy
	data := r.external.archive.retained.data
	var binding *reg.Binding
	for n := range r.retained.bindings {
		b := &r.retained.bindings[n]
		if b.ConfigRef == (reg.ReferencePin{IdentityHash: copy.EvidenceKey.Identity, Version: copy.EvidenceKey.Version}) {
			if binding != nil {
				return ErrInstall
			}
			binding = b
		}
	}
	if binding == nil || binding.Retention == nil || copy.Reservation != r.prep.reservation || copy.NativePlanSHA256 != r.external.warm.native.PlanSHA256 || data.Readback.CiphertextSHA256 != copy.CiphertextSHA256 || data.Readback.CiphertextBytes != copy.CiphertextBytes || !digestPattern.MatchString(data.Readback.PlaintextSHA256) || data.SnapshotRevision == "" {
		return ErrInstall
	}
	fingerprint, e := reg.BindingFingerprint(*binding)
	if e != nil {
		return ErrInstall
	}
	id := "original-raw-archive:" + copy.AssociationSHA256
	intent := reg.SourceRecord{SourceID: "original-archive-intent.v1", RecordID: copy.Reservation.OperationID, RecordVersion: copy.NativePlanSHA256, ContentSHA256: originalObjectSHA(data.Journal)}
	lifecycle := reg.SourceRecord{SourceID: "original-retained-archive.v1", RecordID: copy.Name, RecordVersion: originalObjectSHA(data), ContentSHA256: originalObjectSHA(data)}
	r.retained.refs = append(r.retained.refs, reg.Reference{Partition: reg.RetainedArtifacts, State: reg.ReferenceRetained, SourceRecordID: id, SourceRecordVersion: copy.CiphertextSHA256, EnvelopeID: id, Key: binding.Key, BindingSHA256: fingerprint, MappingSource: binding.Retention.Source, ExpectedRequestSource: intent, LifecycleSource: lifecycle})
	sort.Slice(r.retained.refs, func(i, j int) bool {
		a, b := r.retained.refs[i], r.retained.refs[j]
		if a.Partition != b.Partition {
			return a.Partition < b.Partition
		}
		if a.SourceRecordID != b.SourceRecordID {
			return a.SourceRecordID < b.SourceRecordID
		}
		return a.SourceRecordVersion < b.SourceRecordVersion
	})
	return nil
}

type OriginalMixedFirstAdoptionInputs struct {
	ArchiveTemplate         BootstrapSourceFilePin
	BusinessSourceSelection BootstrapSourceFilePin
	CustodyReader           BootstrapSourceFilePin
	OutputDirectory         string
}

type PreparedOriginalMixedFirstAdoption struct {
	mu       sync.Mutex
	origin   *PreparedOriginalMixedFirstAdoption
	ctx      context.Context
	prep     *PreparedOriginalAdoptionSQLCut
	hold     *OriginalWriterHold
	coverage *PreparedOriginalMixedAdoptionCoverage
	owner    *a.SQLCoverageOwnerPreparation
	started  bool
}

func (*PreparedOriginalMixedFirstAdoption) MarshalJSON() ([]byte, error) { return nil, ErrInstall }

func (s *PreparedOriginalMixedFirstAdoption) AdoptOriginal(ctx context.Context, issuerMaterial BootstrapSourceFilePin) (OriginalAdoptionCommitInspection, error) {
	if s == nil {
		return OriginalAdoptionCommitInspection{}, ErrInstall
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.origin != s || s.started || !consumerSameContext(ctx, s.ctx) || s.prep == nil || s.hold == nil || s.coverage == nil || s.coverage.origin != s.coverage || s.coverage.history.prep != s.prep || s.coverage.hold != s.hold || s.coverage.tx != nil || !s.coverage.history.local(ctx, false) {
		return OriginalAdoptionCommitInspection{}, ErrInstall
	}
	s.started = true // All partial/unknown outcomes remain THIS original operation.
	issued, e := s.prep.issueOriginalMixedAdoptionControls(ctx, s.hold, s.coverage, issuerMaterial)
	if e != nil {
		return OriginalAdoptionCommitInspection{}, e
	}
	records, owner, e := issued.originalCommitInputs(ctx, s.prep, s.hold, s.coverage)
	if e != nil {
		return OriginalAdoptionCommitInspection{}, e
	}
	// Retain the actual17 preparation through readback/recovery/initialization.
	// Never rebuild it from a supplied CoverageOwnerConfig or receipt.
	s.owner = owner
	return s.prep.commitOriginalMixedOwnerAdoption(ctx, s.hold, records, owner, s.coverage)
}

func (h *OriginalWriterHold) PrepareOriginalMixedFirstAdoption(ctx context.Context, password []byte, enrollment EnrollmentPin, installed *OriginalRuntimeC1Installed, warm *OriginalProtectedMinIOWarmHistory, in OriginalMixedFirstAdoptionInputs) (*PreparedOriginalMixedFirstAdoption, error) {
	if h == nil || h.set == nil || installed == nil || installed.origin != installed || !consumerSameContext(ctx, installed.ctx) || installed.production == nil || installed.production.head1 == nil || installed.production.run.parent.enrollment != enrollment || warm == nil || warm.set != h.set || privateDirectory(in.OutputDirectory) != nil {
		return nil, ErrInstall
	}
	result, e := installed.OriginalInstallationResult(ctx)
	if e != nil {
		return nil, e
	}
	p, e := h.prepareOriginalFirstAdoptionSQL(ctx, password, enrollment)
	if e != nil {
		return nil, e
	}
	if e = p.AttachOriginalRuntimeInstalledSQLMetadata(ctx, result.SQLMetadataReceipt); e != nil {
		return nil, e
	}
	// This is a location/configuration template, not an authorization JSON.
	// The actual original owner derives every operation/Plan/reservation field.
	raw, e := readBootstrapSourcePin(in.ArchiveTemplate, 262144)
	var definition OriginalArchiveProviderDefinition
	if e != nil || decodeExact(raw, &definition) != nil || definition.Version != "original-adoption-evidence-archive-template.v1" || definition.PlanSHA256 != "" || definition.OperationIdentitySHA256 != "" {
		return nil, ErrInstall
	}
	definition.Version = OriginalArchiveProviderVersion
	definition.PlanSHA256 = p.operator.installer.planHash
	definition.OperationIdentitySHA256, e = c.OriginalAdoptionReservationIdentitySHA256(p.reservation)
	if e != nil {
		return nil, ErrInstall
	}
	raw, e = canonical(definition)
	if e != nil || writeNewFiles(in.OutputDirectory, map[string][]byte{"original-archive-provider.json": raw}) != nil {
		return nil, ErrInstall
	}
	var minio MinIOPermissionDefinition
	minioRaw, e := readBootstrapSourcePin(BootstrapSourceFilePin{File: definition.MinIODefinitionFile, SHA256: definition.MinIODefinitionSHA256}, 262144)
	if e != nil || decodeExact(minioRaw, &minio) != nil || p.reservation.WriterID != "node/"+minio.Grant.Provider.Node {
		return nil, ErrInstall
	}
	provider, e := h.PrepareArchiveProvider(ctx, password, enrollment, minio.Grant.Provider.Node, filepath.Join(in.OutputDirectory, "original-archive-provider.json"), hash(raw))
	if e != nil {
		return nil, e
	}
	if provider.reservation != p.reservation {
		return nil, ErrInstall
	}
	external, e := h.createOriginalProtectedMinIOArchive(ctx, warm, provider, in.CustodyReader.File, in.CustodyReader.SHA256)
	if e != nil {
		return nil, e
	}
	retained, e := p.PrepareOriginalC1RetainedEvidence(ctx, h, result.SQLMetadataReceipt, provider)
	if e != nil {
		return nil, e
	}
	producer, e := p.PrepareOriginalBackupConsumerHistorySource(ctx, h)
	if e != nil {
		return nil, e
	}
	consumer, ok := producer.(*originalFiniteBackupConsumerSource)
	if !ok || consumer == nil {
		return nil, ErrInstall
	}
	h.set.mu.Lock()
	defer h.set.mu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	finite, e := prepareOriginalHistorySourceSetLocked(ctx, p, h, consumer)
	if e != nil {
		return nil, e
	}
	r := &originalMixedHistorySource{ctx: ctx, prep: p, hold: h, finite: finite, consumer: consumer, retained: retained, external: external, until: minTime(finite.until, minTime(retained.until, external.until))}
	r.origin = r
	r.business, e = prepareOriginalMinIOBusinessHistory(ctx, p, h, external, in.BusinessSourceSelection)
	if e != nil {
		return nil, e
	}
	r.until = minTime(r.until, r.business.until)
	if r.attachActualRawArchiveReference() != nil || r.classifyActualOriginalMinIOObjects(ctx, installed, in.OutputDirectory) != nil {
		return nil, ErrInstall
	}
	r.snapshotRevision = originalObjectSHA(struct{ Version, Finite, Runtime, S3, Tree, Archive, References, Classes, Business string }{"original-mixed-history-snapshot.v1", finite.snapshotRevision, result.SQLMetadataReceipt.SHA256, warm.facts.SnapshotSHA256, external.cold.TreeSHA256, external.archive.SnapshotRevision(), originalObjectSHA(retained.refs), originalObjectSHA(r.objectClasses), r.business.revision})
	r.fenceRevision = originalObjectSHA(struct{ Version, Finite, Operation, Inventory, Native string }{"original-mixed-history-fence.v1", finite.fenceRevision, h.set.owner.operation, h.set.inventorySHA, finite.originalNative.digest})
	coverage := &PreparedOriginalMixedAdoptionCoverage{ctx: ctx, hold: h, history: r, refs: r.references(), epoch: ^uint64(0), until: r.until}
	coverage.origin = coverage
	r.coverage = coverage
	if !r.local(ctx, false) || len(coverage.refs) == 0 || r.recheckBeforeOriginalHistorySQL(ctx) != nil {
		return nil, ErrInstall
	}
	session := &PreparedOriginalMixedFirstAdoption{ctx: ctx, prep: p, hold: h, coverage: coverage}
	session.origin = session
	return session, nil
}
