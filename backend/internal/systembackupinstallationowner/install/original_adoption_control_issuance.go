package install

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"time"

	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
)

// Only the actual source-consuming issuer constructs this handle. Keys are
// never retained. It preserves the ONE original coverage, operation and hold;
// it cannot be decoded from inspection JSON or used to rebuild coverage.
type IssuedOriginalAdoptionControls struct {
	origin    *IssuedOriginalAdoptionControls
	ctx       context.Context
	prep      *PreparedOriginalAdoptionSQLCut
	hold      *OriginalWriterHold
	coverage  *PreparedOriginalAdoptionCoverage
	material  BootstrapSourceFilePin
	keyConfig originalAdoptionIssuerMaterial
	snapshot  reg.Snapshot
	pins      a.OriginalAdoptionControlPins
	records   a.OriginalAdoptionControlRecords
	until     time.Time
	failed    bool
}

func (*IssuedOriginalAdoptionControls) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (*IssuedOriginalAdoptionControls) String() string               { return "IssuedOriginalAdoptionControls" }
func (*IssuedOriginalAdoptionControls) GoString() string             { return "IssuedOriginalAdoptionControls" }

var originalAdoptionPartitions = []reg.Partition{reg.RetainedArtifacts, reg.InflightAndUnknownWrites, reg.HoldsAndCatalog, reg.RestoreAndPrune}

// All callers already hold original set.mu -> prep.mu. All real I/O is before
// final SQL. This admits ONLY D/C's genuine exact finite FS/singleton branch.
func originalAdoptionIssuable(ctx context.Context, p *PreparedOriginalAdoptionSQLCut, h *OriginalWriterHold, coverage *PreparedOriginalAdoptionCoverage) error {
	if !originalEmptyHistoryOwner(ctx, p, h, false) || p.used || coverage == nil || coverage.origin != coverage || coverage.hold != h || !consumerSameContext(ctx, coverage.ctx) || coverage.tx != nil || coverage.cut != nil || coverage.authenticated != nil || coverage.sourceSet == nil || coverage.sourceSet.prep != p || coverage.sourceSet.hold != h || !coverage.sourceSet.local(ctx, false) || coverage.sqlMetadata != coverage.sourceSet.metadata || coverage.refs == nil || len(coverage.refs) != 0 || !time.Now().Before(coverage.until) {
		return ErrInstall
	}
	history, ok := coverage.history.(*originalEmptyHistorySource)
	if !ok || history == nil || history.origin != history || history.prep != p || history.hold != h || history.filesystemOnly == nil || history.filesystemOnly.source != history || history.filesystemOnly.metadata != coverage.sqlMetadata || history.filesystemOnly.authority != coverage.sourceSet {
		return ErrInstall
	}
	if _, err := originalAdoptionSigningAuthority(ctx, p.operator, p.enrollment, &h.set.owner.initial); err != nil {
		return err
	}
	if history.recheckBeforeOriginalHistorySQL(ctx) != nil || h.recheckBeforeSQL(ctx) != nil || !coverage.sourceSet.local(ctx, false) || !reflect.DeepEqual(history.references(), coverage.refs) {
		return ErrInstall
	}
	return nil
}

func originalAdoptionEmptyRegistry(p *PreparedOriginalAdoptionSQLCut, snapshot reg.Snapshot) bool {
	return p != nil && snapshot.Database == (reg.DatabaseIdentity{ServerUUID: p.database.ServerUUID, Database: p.database.Database}) && snapshot.InstallationID == p.reservation.InstallationID && !snapshot.ObservedAt.IsZero() && snapshot.Epoch != ^uint64(0) && snapshot.Bindings != nil && snapshot.References != nil && len(snapshot.References) == 0 && snapshot.Coverage != nil && len(snapshot.Coverage) == 0
}

// IssueOriginalFilesystemAdoptionControls performs the real17 issuance. Its
// parameters contain only genuine opaque sources and original signer-file
// locators. Witness facts/revisions/epoch/recordIDs are all derived here.
func (p *PreparedOriginalAdoptionSQLCut) IssueOriginalFilesystemAdoptionControls(ctx context.Context, h *OriginalWriterHold, coverage *PreparedOriginalAdoptionCoverage, material BootstrapSourceFilePin) (result *IssuedOriginalAdoptionControls, err error) {
	if p == nil || h == nil || h.set == nil {
		return nil, ErrInstall
	}
	h.set.mu.Lock()
	defer h.set.mu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	if originalAdoptionIssuable(ctx, p, h, coverage) != nil {
		return nil, ErrInstall
	}
	definition, keys, err := readOriginalAdoptionIssuerMaterial(p, material)
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, key := range keys {
			clear(key)
		}
	}()
	before, err := (reg.SQLStore{}).ReadSnapshot(ctx, p.operator.installer.db, p.reservation.InstallationID)
	if err != nil || !originalAdoptionEmptyRegistry(p, before) {
		return nil, ErrInstall
	}
	until := coverage.until
	for _, cap := range []time.Time{p.until, h.set.owner.until, p.reservation.ExpiresAt, coverage.history.validUntil(), coverage.sourceSet.until, coverage.sourceSet.nativeUntil} {
		if cap.IsZero() {
			return nil, ErrInstall
		}
		if cap.Before(until) {
			until = cap
		}
	}
	deadline, bounded := ctx.Deadline()
	if !bounded {
		return nil, ErrInstall
	}
	if deadline.Before(until) {
		until = deadline
	}
	until = until.UTC().Truncate(time.Microsecond)
	if !time.Now().Before(until) {
		return nil, ErrInstall
	}
	b := &IssuedOriginalAdoptionControls{ctx: ctx, prep: p, hold: h, coverage: coverage, material: material, keyConfig: definition, snapshot: before, records: a.OriginalAdoptionControlRecords{}, until: until}
	b.origin = b
	defer func() {
		if err != nil {
			b.failed = true
		}
	}()
	for _, partition := range originalAdoptionPartitions {
		for _, kind := range originalAdoptionIssuerRoles[:4] {
			source := b.controlSource(partition, kind)
			var signed a.SignedCoverageOwnerRecord
			var pin a.CoverageWitnessPin
			if kind == "original_sql_census" {
				// Existing ORIGINAL opaque SQL owner API, not a reimplemented DTO signer.
				signed, pin, err = p.observed.SignOriginalSQLWitness(ctx, partition, source, b.recordRevision(), coverage.sourceSet.snapshotRevision, coverage.sourceSet.fenceRevision, until, keys[kind])
			} else {
				signed, pin, err = b.signActualOriginalOwnerWitness(ctx, partition, kind, keys[kind])
			}
			if err != nil {
				return nil, err
			}
			b.records[pin.Source.RecordID] = signed
			b.pins.Witnesses = append(b.pins.Witnesses, pin)
		}
	}
	adoption, pin, err := b.signActualOriginalAdoption(ctx, keys["adoption"])
	if err != nil {
		return nil, err
	}
	b.pins.Adoption = pin
	b.records[pin.Source.RecordID] = adoption
	if len(b.records) != 17 || len(b.pins.Witnesses) != 16 {
		return nil, ErrInstall
	}
	// Real independent keys/material and complete sources are checked again
	// before ANY signed record is returned. Nothing is inserted in this method.
	if b.recheckLockedBeforeSQL(ctx) != nil {
		return nil, ErrInstall
	}
	return b, nil
}

func (b *IssuedOriginalAdoptionControls) recheckLockedBeforeSQL(ctx context.Context) (err error) {
	defer func() {
		if err != nil && b != nil && b.origin == b {
			b.failed = true
		}
	}()
	if b == nil || b.origin != b || b.failed || !consumerSameContext(ctx, b.ctx) || !time.Now().Before(b.until) || originalAdoptionIssuable(ctx, b.prep, b.hold, b.coverage) != nil {
		return ErrInstall
	}
	d, keys, e := readOriginalAdoptionIssuerMaterial(b.prep, b.material)
	for _, key := range keys {
		clear(key)
	}
	if e != nil || !reflect.DeepEqual(d, b.keyConfig) {
		return ErrInstall
	}
	current, e := (reg.SQLStore{}).ReadSnapshot(ctx, b.prep.operator.installer.db, b.prep.reservation.InstallationID)
	if e != nil || !originalAdoptionEmptyRegistry(b.prep, current) || !reg.SameSnapshotFacts(current, b.snapshot) || current.ObservedAt.Before(b.snapshot.ObservedAt) {
		return ErrInstall
	}
	return nil
}

// The exact source correspondence is comparison DATA only; never a signing
// input. Public pins are obtained from the actual prepared configuration above.
func (b *IssuedOriginalAdoptionControls) RecordSources(ctx context.Context) ([]a.FirstAdoptionRecordSource, error) {
	if b == nil || b.hold == nil || b.hold.set == nil || b.prep == nil {
		return nil, ErrInstall
	}
	b.hold.set.mu.Lock()
	defer b.hold.set.mu.Unlock()
	b.prep.mu.Lock()
	defer b.prep.mu.Unlock()
	if b.recheckLockedBeforeSQL(ctx) != nil {
		return nil, ErrInstall
	}
	out := []a.FirstAdoptionRecordSource{{Kind: "adoption", Source: b.pins.Adoption.Source}}
	for _, pin := range b.pins.Witnesses {
		out = append(out, a.FirstAdoptionRecordSource{Partition: pin.Partition, Kind: pin.Kind, Source: pin.Source})
	}
	return out, nil
}

func originalIssuedJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, ErrInstall
	}
	return raw, nil
}

// D's genuine same-session caller consumes the actual control preparation
// without a fake KEK configuration. First adoption precedes legal KEK/config
// activation; no provider/mapping capability is minted on this path.
func (b *IssuedOriginalAdoptionControls) originalCommitInputs(ctx context.Context, p *PreparedOriginalAdoptionSQLCut, h *OriginalWriterHold, coverage *PreparedOriginalAdoptionCoverage) (a.OriginalAdoptionControlRecords, *a.SQLCoverageOwnerPreparation, error) {
	if b == nil || b.origin != b || p == nil || p != b.prep || h == nil || h != b.hold || h.set == nil || coverage == nil || coverage != b.coverage {
		return nil, nil, ErrInstall
	}
	h.set.mu.Lock()
	defer h.set.mu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	if b.recheckLockedBeforeSQL(ctx) != nil {
		return nil, nil, ErrInstall
	}
	owner, err := a.NewSQLCoverageOwnerPreparation(a.SQLCoverageOwnerConfig{DB: p.operator.installer.db, Database: b.snapshot.Database, InstallationID: b.snapshot.InstallationID, Adoption: b.pins.Adoption, Witnesses: b.pins.Witnesses})
	if err != nil {
		return nil, nil, err
	}
	records := a.OriginalAdoptionControlRecords{}
	for id, record := range b.records {
		records[id] = a.SignedCoverageOwnerRecord{Record: bytes.Clone(record.Record), Signature: bytes.Clone(record.Signature)}
	}
	return records, owner, nil
}
