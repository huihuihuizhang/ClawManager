package systembackupkekadapter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

const OriginalCoverageDomain = "system-backup-original-coverage-adoption.v1\x00"
const OriginalCoverageWitnessDomain = "system-backup-original-coverage-witness.v1\x00"

// These are receipts from the ORIGINAL source owners, not operator approvals.
// The adoption owner signs the exact four partitions, complete reference sets
// and the original source receipts used during historical adoption. Each source
// receipt is independently authenticated using its own deployment-pinned issuer.
// This reader does NOT create source receipts, stop writers, backfill references,
// turn a live LIST into an immutable snapshot, or perform adoption on its own.
type CoverageOwnerPin struct {
	Source reg.SourceRecord
	Issuer ed25519.PublicKey
}

type CoverageWitnessPin struct {
	CoverageOwnerPin
	Partition   reg.Partition
	Kind        string
	ScopeSHA256 string
}

type CoverageWitnessFacts struct {
	Database                             reg.DatabaseIdentity
	InstallationID                       string
	Partition                            reg.Partition
	Kind, ScopeSHA256, ObservationSHA256 string
	SnapshotRevision, FenceRevision      string
}

type CoverageWitnessRecord struct {
	Facts            CoverageWitnessFacts
	Source           reg.SourceRecord
	Revision         string
	NotBefore, Until time.Time
	Revoked          bool
}

type CoveragePartitionAdoption struct {
	Partition                                 reg.Partition
	SourceID, SnapshotRevision, FenceRevision string
	ReferenceCount                            uint64
	ReferencesSHA256                          string
	// Exactly one of each original witness kind is mandatory, including empty
	// reference sets. A count/hash of the new KEK index supplies none of these.
	SQLCensus, ImmutableExternalSnapshot, WriterFence, HistoricalBackfill reg.SourceRecord
}

type CoverageAdoptionFacts struct {
	Database       reg.DatabaseIdentity
	InstallationID string
	AdoptedEpoch   uint64
	Partitions     []CoveragePartitionAdoption
}

type CoverageAdoptionRecord struct {
	Facts            CoverageAdoptionFacts
	Source           reg.SourceRecord
	Revision         string
	NotBefore, Until time.Time
	Revoked          bool
}

type SignedCoverageOwnerRecord struct{ Record, Signature []byte }

type SQLCoverageOwnerConfig struct {
	DB             *sql.DB
	Database       reg.DatabaseIdentity
	InstallationID string
	Adoption       CoverageOwnerPin
	Witnesses      []CoverageWitnessPin
}

type SQLCoverageOwnerPreparation struct{ cfg SQLCoverageOwnerConfig }

var coverageWitnessKinds = []string{"original_sql_census", "immutable_external_snapshot", "original_writer_fence", "historical_backfill"}

func coveragePartition(p reg.Partition) bool {
	return p == reg.RetainedArtifacts || p == reg.InflightAndUnknownWrites || p == reg.HoldsAndCatalog || p == reg.RestoreAndPrune
}
func coverageWitnessKind(k string) bool {
	for _, kind := range coverageWitnessKinds {
		if k == kind {
			return true
		}
	}
	return false
}
func coverageWitnessKey(partition reg.Partition, kind string) string {
	return string(partition) + "\x00" + kind
}

func NewSQLCoverageOwnerPreparation(cfg SQLCoverageOwnerConfig) (*SQLCoverageOwnerPreparation, error) {
	if cfg.DB == nil || cfg.InstallationID == "" || cfg.Database.ServerUUID == "" || cfg.Database.Database == "" || !authoritySource(cfg.Adoption.Source) || !strings.HasPrefix(cfg.Adoption.Source.RecordID, "sev_") || len(cfg.Adoption.Issuer) != ed25519.PublicKeySize || len(cfg.Witnesses) != 16 {
		return nil, sec.ErrRegistrationUnavailable
	}
	cfg.Witnesses = append([]CoverageWitnessPin(nil), cfg.Witnesses...)
	seen, records := map[string]bool{}, map[string]bool{cfg.Adoption.Source.RecordID: true}
	for i, witness := range cfg.Witnesses {
		key := coverageWitnessKey(witness.Partition, witness.Kind)
		if !coveragePartition(witness.Partition) || !coverageWitnessKind(witness.Kind) || seen[key] || !authorityHash.MatchString(witness.ScopeSHA256) || !authoritySource(witness.Source) || !strings.HasPrefix(witness.Source.RecordID, "sev_") || records[witness.Source.RecordID] || len(witness.Issuer) != ed25519.PublicKeySize {
			return nil, sec.ErrRegistrationUnavailable
		}
		seen[key], records[witness.Source.RecordID] = true, true
		cfg.Witnesses[i].Issuer = append(ed25519.PublicKey(nil), witness.Issuer...)
	}
	cfg.Adoption.Issuer = append(ed25519.PublicKey(nil), cfg.Adoption.Issuer...)
	return &SQLCoverageOwnerPreparation{cfg}, nil
}

// All owner receipts are original system evidence. Their named purpose, current
// health, exact payload bytes, checksum, size and unchanged expiry are checked
// again under the caller's original transaction. No arbitrary object URL opens.
func readCoverageOwnerEvidence(ctx context.Context, view reg.SQLReadView, installation string, pin CoverageOwnerPin, locked bool) (capabilityEvidence, error) {
	if nilSource(ctx) || ctx.Err() != nil || nilSource(view) {
		return capabilityEvidence{}, sec.ErrRegistrationUnavailable
	}
	suffix := ""
	if locked {
		suffix = " FOR SHARE"
	}
	var e capabilityEvidence
	var checksum string
	var size uint64
	if view.QueryRowContext(ctx, `SELECT inline_payload,content_checksum,content_size_bytes,expires_at FROM system_backup_v2_evidence WHERE public_id=? AND owner_target_type='system' AND owner_target_public_id=? AND evidence_type='catalog_scan_receipt' AND storage_state='inline' AND observed_health='healthy' AND encryption='none'`+suffix, pin.Source.RecordID, installation).Scan(&e.raw, &checksum, &size, &e.until) != nil || validateCapabilityEvidenceRow(e, checksum, size) != nil {
		return capabilityEvidence{}, sec.ErrRegistrationUnavailable
	}
	return e, nil
}

func decodeCoverageOwnerRecord(e capabilityEvidence, pin CoverageOwnerPin, domain string, target any, now time.Time) error {
	var envelope SignedCoverageOwnerRecord
	if now.IsZero() || !now.Before(e.until) || strictPermitIssuerJSON(e.raw, &envelope) != nil || len(envelope.Record) == 0 || len(envelope.Record) > 8192 || len(pin.Issuer) != ed25519.PublicKeySize || !ed25519.Verify(pin.Issuer, append([]byte(domain), envelope.Record...), envelope.Signature) || strictPermitIssuerJSON(envelope.Record, target) != nil {
		return sec.ErrRegistrationUnavailable
	}
	return nil
}

func coverageFactsHash(facts any) string {
	raw, err := json.Marshal(facts)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func authenticateCoverageAdoption(e capabilityEvidence, pin CoverageOwnerPin, now time.Time) (CoverageAdoptionRecord, error) {
	var record CoverageAdoptionRecord
	if decodeCoverageOwnerRecord(e, pin, OriginalCoverageDomain, &record, now) != nil || record.Source != pin.Source || record.Source.ContentSHA256 != coverageFactsHash(record.Facts) || !authorityExact(record.Revision) || record.Revoked || record.NotBefore.IsZero() || now.Before(record.NotBefore) || !now.Before(record.Until) || len(record.Facts.Partitions) != 4 || record.Facts.AdoptedEpoch == 0 {
		return CoverageAdoptionRecord{}, sec.ErrRegistrationUnavailable
	}
	return record, nil
}

func authenticateCoverageWitness(e capabilityEvidence, pin CoverageWitnessPin, now time.Time) (CoverageWitnessRecord, error) {
	var record CoverageWitnessRecord
	if decodeCoverageOwnerRecord(e, pin.CoverageOwnerPin, OriginalCoverageWitnessDomain, &record, now) != nil || record.Source != pin.Source || record.Source.ContentSHA256 != coverageFactsHash(record.Facts) || !authorityExact(record.Revision) || record.Revoked || record.NotBefore.IsZero() || now.Before(record.NotBefore) || !now.Before(record.Until) || record.Facts.Partition != pin.Partition || record.Facts.Kind != pin.Kind || record.Facts.ScopeSHA256 != pin.ScopeSHA256 || !authorityHash.MatchString(record.Facts.ObservationSHA256) || !authorityExact(record.Facts.SnapshotRevision) || !authorityExact(record.Facts.FenceRevision) {
		return CoverageWitnessRecord{}, sec.ErrRegistrationUnavailable
	}
	return record, nil
}

type coverageEvidenceSnapshot struct {
	pin      CoverageOwnerPin
	evidence capabilityEvidence
}
type SQLPreparedOriginalCoverage struct {
	mu       sync.Mutex
	owner    *SQLCoverageOwnerPreparation
	snapshot reg.Snapshot
	sources  []reg.CoverageSource
	until    time.Time
	evidence []coverageEvidenceSnapshot
	lock     *coverageOriginalEvidenceLock
	failed   bool
}
type coverageOriginalEvidenceLock struct {
	ctx       context.Context
	native    *sql.Tx
	bootstrap pd.BootstrapSQL
}

func (p *SQLPreparedOriginalCoverage) Sources() []reg.CoverageSource {
	if p == nil {
		return nil
	}
	return append([]reg.CoverageSource(nil), p.sources...)
}
func (p *SQLPreparedOriginalCoverage) References() []reg.Reference {
	if p == nil {
		return nil
	}
	return append(make([]reg.Reference, 0, len(p.snapshot.References)), p.snapshot.References...)
}
func (p *SQLPreparedOriginalCoverage) ExpectedEpoch() uint64 {
	if p == nil {
		return 0
	}
	return p.snapshot.Epoch
}
func (p *SQLPreparedOriginalCoverage) ValidUntil() time.Time {
	if p == nil {
		return time.Time{}
	}
	return p.until
}

func originalCoverageReferences(refs []reg.Reference, partition reg.Partition) (uint64, string, error) {
	if refs == nil {
		return 0, "", sec.ErrRegistrationUnavailable
	}
	owned := make([]reg.Reference, 0)
	seen := map[string]bool{}
	for _, ref := range refs {
		if !coveragePartition(ref.Partition) {
			return 0, "", sec.ErrRegistrationUnavailable
		}
		if ref.Partition != partition {
			continue
		}
		key := ref.SourceRecordID + "\x00" + ref.SourceRecordVersion
		if ref.SourceRecordID == "" || !authorityExact(ref.SourceRecordVersion) || seen[key] || strings.ContainsRune(ref.SourceRecordID, '\x00') {
			return 0, "", sec.ErrRegistrationUnavailable
		}
		seen[key] = true
		owned = append(owned, ref)
	}
	sort.Slice(owned, func(i, j int) bool {
		if owned[i].SourceRecordID != owned[j].SourceRecordID {
			return owned[i].SourceRecordID < owned[j].SourceRecordID
		}
		return owned[i].SourceRecordVersion < owned[j].SourceRecordVersion
	})
	return uint64(len(owned)), coverageFactsHash(owned), nil
}

// Prepare consumes ALREADY ADOPTED original source receipts. It deliberately
// fails before first adoption instead of blessing a newly-created empty index.
// The original adoption writer must first hold old writers, scan/backfill all
// history and commit the exact four receipts and references under the KEK fence.
func (s *SQLCoverageOwnerPreparation) Prepare(ctx context.Context, snapshot reg.Snapshot) (*SQLPreparedOriginalCoverage, error) {
	fail := func() (*SQLPreparedOriginalCoverage, error) { return nil, sec.ErrRegistrationUnavailable }
	if s == nil || nilSource(ctx) || ctx.Err() != nil || snapshot.Database != s.cfg.Database || snapshot.InstallationID != s.cfg.InstallationID || snapshot.ObservedAt.IsZero() || snapshot.References == nil || snapshot.Bindings == nil || len(snapshot.Coverage) != 4 {
		return fail()
	}
	tx, err := s.cfg.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return fail()
	}
	defer tx.Rollback()
	var database reg.DatabaseIdentity
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6)`).Scan(&database.ServerUUID, &database.Database, &now) != nil || database != s.cfg.Database || now.Before(snapshot.ObservedAt) {
		return fail()
	}
	e, err := readCoverageOwnerEvidence(ctx, tx, s.cfg.InstallationID, s.cfg.Adoption, false)
	if err != nil {
		return fail()
	}
	record, err := authenticateCoverageAdoption(e, s.cfg.Adoption, now)
	if err != nil || record.Facts.Database != s.cfg.Database || record.Facts.InstallationID != s.cfg.InstallationID || snapshot.Epoch != record.Facts.AdoptedEpoch {
		return fail()
	}
	p := &SQLPreparedOriginalCoverage{owner: s, snapshot: snapshot, until: record.Until, evidence: []coverageEvidenceSnapshot{{s.cfg.Adoption, e}}}
	if e.until.Before(p.until) {
		p.until = e.until
	}
	parts := map[reg.Partition]CoveragePartitionAdoption{}
	for _, part := range record.Facts.Partitions {
		if !coveragePartition(part.Partition) || parts[part.Partition].SourceID != "" || part.SourceID == "" || !authorityExact(part.SnapshotRevision) || !authorityExact(part.FenceRevision) {
			return fail()
		}
		count, digest, err := originalCoverageReferences(snapshot.References, part.Partition)
		if err != nil || count != part.ReferenceCount || digest != part.ReferencesSHA256 {
			return fail()
		}
		parts[part.Partition] = part
		p.sources = append(p.sources, reg.CoverageSource{Partition: part.Partition, SourceID: part.SourceID, SnapshotRevision: part.SnapshotRevision, FenceRevision: part.FenceRevision, AdoptionSource: record.Source})
	}
	sort.Slice(p.sources, func(i, j int) bool { return p.sources[i].Partition < p.sources[j].Partition })
	if !reflect.DeepEqual(p.sources, snapshot.Coverage) {
		return fail()
	}
	for _, pin := range s.cfg.Witnesses {
		part := parts[pin.Partition]
		wanted := map[string]reg.SourceRecord{"original_sql_census": part.SQLCensus, "immutable_external_snapshot": part.ImmutableExternalSnapshot, "original_writer_fence": part.WriterFence, "historical_backfill": part.HistoricalBackfill}[pin.Kind]
		if wanted != pin.Source {
			return fail()
		}
		e, err := readCoverageOwnerEvidence(ctx, tx, s.cfg.InstallationID, pin.CoverageOwnerPin, false)
		if err != nil {
			return fail()
		}
		w, err := authenticateCoverageWitness(e, pin, now)
		if err != nil || w.Facts.Database != s.cfg.Database || w.Facts.InstallationID != s.cfg.InstallationID || w.Facts.SnapshotRevision != part.SnapshotRevision || w.Facts.FenceRevision != part.FenceRevision {
			return fail()
		}
		for _, limit := range []time.Time{w.Until, e.until} {
			if limit.Before(p.until) {
				p.until = limit
			}
		}
		p.evidence = append(p.evidence, coverageEvidenceSnapshot{pin.CoverageOwnerPin, e})
	}
	// Own all comparison slices; later mutation of the input cannot change the
	// authenticated historical reference set or replace evidence dependencies.
	raw, err := json.Marshal(snapshot)
	if err != nil || json.Unmarshal(raw, &p.snapshot) != nil || ctx.Err() != nil {
		return fail()
	}
	sort.Slice(p.evidence, func(i, j int) bool { return p.evidence[i].pin.Source.RecordID < p.evidence[j].pin.Source.RecordID })
	return p, nil
}

// LockOriginalEvidence belongs BEFORE the KEK fence in the caller's original
// lock order. Recheck refuses a foreign/reopened transaction, so callers cannot
// silently discover new earlier-layer evidence locks after taking that fence.
func (p *SQLPreparedOriginalCoverage) LockOriginalEvidence(ctx context.Context, view reg.SQLReadView) error {
	if p == nil {
		return sec.ErrRegistrationUnavailable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failed || p.owner == nil || p.lock != nil || nilSource(ctx) || ctx.Err() != nil || nilSource(view) {
		p.failed = true
		return sec.ErrRegistrationUnavailable
	}
	p.failed = true
	lock := &coverageOriginalEvidenceLock{ctx: ctx}
	switch tx := view.(type) {
	case *sql.Tx:
		if tx == nil {
			return sec.ErrRegistrationUnavailable
		}
		lock.native = tx
	case pd.BootstrapSQL:
		if !pd.SameBootstrapTransaction(tx, tx) {
			return sec.ErrRegistrationUnavailable
		}
		lock.bootstrap = tx
	default:
		return sec.ErrRegistrationUnavailable
	}
	if p.recheckEvidence(ctx, view) != nil {
		return sec.ErrRegistrationUnavailable
	}
	p.lock = lock
	p.failed = false
	return nil
}

func (p *SQLPreparedOriginalCoverage) recheckEvidence(ctx context.Context, view reg.SQLReadView) error {
	for _, item := range p.evidence {
		e, err := readCoverageOwnerEvidence(ctx, view, p.owner.cfg.InstallationID, item.pin, true)
		if err != nil || !bytes.Equal(e.raw, item.evidence.raw) || !e.until.Equal(item.evidence.until) {
			return sec.ErrRegistrationUnavailable
		}
	}
	return nil
}

func (p *SQLPreparedOriginalCoverage) Recheck(ctx context.Context, view reg.SQLReadView, locked reg.LockedSnapshot, now time.Time) error {
	if p == nil {
		return sec.ErrRegistrationUnavailable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failed || p.owner == nil || p.lock == nil || nilSource(ctx) || ctx.Err() != nil || !reflect.ValueOf(ctx).Comparable() || !reflect.ValueOf(p.lock.ctx).Comparable() || ctx != p.lock.ctx || now.IsZero() || now.Before(p.snapshot.ObservedAt) || !now.Before(p.until) || !reg.SameSnapshotFacts(locked.Facts(), p.snapshot) {
		p.failed = true
		return sec.ErrRegistrationUnavailable
	}
	p.failed = true
	if p.lock.native != nil {
		tx, ok := view.(*sql.Tx)
		if !ok || tx != p.lock.native {
			return sec.ErrRegistrationUnavailable
		}
	} else {
		read, ok := view.(pd.BootstrapReadSQL)
		if !ok || !pd.SameBootstrapTransaction(p.lock.bootstrap, read) {
			return sec.ErrRegistrationUnavailable
		}
	}
	if p.recheckEvidence(ctx, view) != nil {
		return sec.ErrRegistrationUnavailable
	}
	p.failed = false
	return nil
}

var _ reg.PreparedCoverage = (*SQLPreparedOriginalCoverage)(nil)
