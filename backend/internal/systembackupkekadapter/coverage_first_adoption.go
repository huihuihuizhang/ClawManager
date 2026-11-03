package systembackupkekadapter

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"sort"
	"sync"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
	sec "clawreef/internal/systembackupsecurity"
)

// AuthenticatedFirstAdoption authenticates staged original-owner records, not
// physical writer exclusion or immutable external history. Deliberately NOT
// reg.PreparedCoverage: the adoption executor still needs B/C's current native
// source guards and actual historical backfill before it may authorize adoption.
// There is no signer accepting caller-supplied Passed flags or observation hashes.
type AuthenticatedFirstAdoption struct {
	mu       sync.Mutex
	origin   *AuthenticatedFirstAdoption
	owner    *SQLCoverageOwnerPreparation
	cut      *OriginalAdoptionControlCut
	snapshot reg.Snapshot
	until    time.Time
	failed   bool
}

type FirstAdoptionRecordSource struct {
	Partition reg.Partition
	Kind      string
	Source    reg.SourceRecord
}

// AuthenticateFirstAdoption is the FIRST-adoption authentication route; Prepare
// remains the reader for already adopted coverage. Call AFTER Stage and Bind in
// the same original RR transaction. This method owns no SQL writes or commit.
// The config pins must come from the independently installed authority, never
// from the records submitted for authentication.
func (s *SQLCoverageOwnerPreparation) AuthenticateFirstAdoption(ctx context.Context, cut *OriginalAdoptionControlCut, locked reg.LockedSnapshot) (*AuthenticatedFirstAdoption, error) {
	if s == nil || cut == nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	cut.mu.Lock()
	defer cut.mu.Unlock()
	if !cut.good(ctx) || !cut.staged || len(cut.rows) != 17 || !sameFirstAdoptionPins(s.cfg, cut.pins) || cut.recheck(ctx) != nil {
		return nil, cut.poison()
	}
	now, err := cut.now(ctx)
	if err != nil {
		return nil, err
	}
	snapshot := locked.Facts()
	until, err := authenticateFirstAdoptionSnapshot(s.cfg, cut, snapshot, now)
	if err != nil {
		return nil, cut.poison()
	}
	p := &AuthenticatedFirstAdoption{owner: s, cut: cut, snapshot: snapshot, until: until}
	p.origin = p
	return p, nil
}

func sameFirstAdoptionPins(cfg SQLCoverageOwnerConfig, pins OriginalAdoptionControlPins) bool {
	if !reflect.DeepEqual(cfg.Adoption, pins.Adoption) || len(cfg.Witnesses) != 16 || len(pins.Witnesses) != 16 {
		return false
	}
	byKey := map[string]CoverageWitnessPin{}
	for _, p := range cfg.Witnesses {
		byKey[coverageWitnessKey(p.Partition, p.Kind)] = p
	}
	seen := map[string]bool{}
	for _, p := range pins.Witnesses {
		key := coverageWitnessKey(p.Partition, p.Kind)
		if seen[key] || !reflect.DeepEqual(byKey[key], p) {
			return false
		}
		seen[key] = true
	}
	return len(byKey) == 16
}

func authenticateFirstAdoptionSnapshot(cfg SQLCoverageOwnerConfig, cut *OriginalAdoptionControlCut, snapshot reg.Snapshot, now time.Time) (time.Time, error) {
	bad := func() (time.Time, error) { return time.Time{}, sec.ErrRegistrationUnavailable }
	if snapshot.Database != cfg.Database || snapshot.InstallationID != cfg.InstallationID || snapshot.Database != cut.observed.Database || snapshot.InstallationID != cut.observed.InstallationID || snapshot.ObservedAt.IsZero() || now.Before(snapshot.ObservedAt) || snapshot.Bindings == nil || snapshot.References == nil || len(snapshot.Coverage) != 0 || snapshot.Epoch == ^uint64(0) {
		return bad()
	}
	records := OriginalAdoptionControlRecords{}
	until := cut.until
	for id, row := range cut.rows {
		var signed SignedCoverageOwnerRecord
		if row == nil || strictPermitIssuerJSON(row.envelope, &signed) != nil || !now.Before(row.expires) {
			return bad()
		}
		records[id] = signed
		if row.expires.Before(until) {
			until = row.expires
		}
	}
	// Repeat independent signatures, source associations and the exact original
	// SQL observation checks; a private row journal alone is not authentication.
	if _, err := cut.authenticateBatch(records, now); err != nil {
		return bad()
	}
	row := cut.rows[cfg.Adoption.Source.RecordID]
	if row == nil {
		return bad()
	}
	record, err := authenticateCoverageAdoption(capabilityEvidence{raw: row.envelope, until: row.expires}, cfg.Adoption, now)
	if err != nil || record.Facts.AdoptedEpoch != snapshot.Epoch+1 {
		return bad()
	}
	for _, part := range record.Facts.Partitions {
		count, digest, err := originalCoverageReferences(snapshot.References, part.Partition)
		if err != nil || count != part.ReferenceCount || digest != part.ReferencesSHA256 {
			return bad()
		}
	}
	if !now.Before(until) {
		return bad()
	}
	return until, nil
}

func (*AuthenticatedFirstAdoption) MarshalJSON() ([]byte, error) {
	return nil, sec.ErrRegistrationUnavailable
}

// ValidUntil is the original nonrenewing authentication cap, not a lease or a
// permission to resume writers.
func (p *AuthenticatedFirstAdoption) ValidUntil() time.Time {
	if p == nil || p.origin != p {
		return time.Time{}
	}
	return p.until
}

// RecordSources returns the exact source correspondence, without payloads or
// keys. The independent adoption record has no partition; the other16 do.
func (p *AuthenticatedFirstAdoption) RecordSources() []FirstAdoptionRecordSource {
	if p == nil || p.origin != p {
		return nil
	}
	result := []FirstAdoptionRecordSource{{Kind: "adoption", Source: p.owner.cfg.Adoption.Source}}
	for _, pin := range p.owner.cfg.Witnesses {
		result = append(result, FirstAdoptionRecordSource{Partition: pin.Partition, Kind: pin.Kind, Source: pin.Source})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Partition != result[j].Partition {
			return result[i].Partition < result[j].Partition
		}
		return result[i].Kind < result[j].Kind
	})
	return result
}

// Recheck refuses a foreign transaction/context, expiry, changed original
// registry facts, revoked/changed signed records, or any unjournaled source or
// chunk mutation. Failure poisons this handle and the underlying SQL cut.
func (p *AuthenticatedFirstAdoption) Recheck(ctx context.Context, view reg.SQLReadView, locked reg.LockedSnapshot, now time.Time) error {
	if p == nil {
		return sec.ErrRegistrationUnavailable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.origin != p || p.failed || p.cut == nil {
		return sec.ErrRegistrationUnavailable
	}
	p.failed = true
	cut := p.cut
	cut.mu.Lock()
	defer cut.mu.Unlock()
	tx, ok := view.(*sql.Tx)
	if !ok || !cut.good(ctx) || tx != cut.original.tx || now.IsZero() || now.Before(p.snapshot.ObservedAt) || !now.Before(p.until) || !reg.SameSnapshotFacts(locked.Facts(), p.snapshot) {
		return cut.poison()
	}
	if cut.recheck(ctx) != nil {
		return cut.poison()
	}
	stamp, err := cut.now(ctx)
	if err != nil || stamp.Before(now) {
		return cut.poison()
	}
	until, err := authenticateFirstAdoptionSnapshot(p.owner.cfg, cut, p.snapshot, stamp)
	if err != nil || !until.Equal(p.until) {
		return cut.poison()
	}
	p.failed = false
	return nil
}

// Keep the diagnostic source list transportable without making the private
// authenticated handle serializable.
var _ json.Marshaler = (*AuthenticatedFirstAdoption)(nil)
