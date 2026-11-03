package install

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"sort"
	"time"

	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
)

// Capture the shortest cap of the exact B observations held by the paused
// verifier. This is computed BEFORE opening final SQL and never renewed there.
func originalAdoptionNativeUntil(proof *originalHeldReadiness) (time.Time, error) {
	if proof == nil || proof.set == nil || proof.set.owner == nil || proof.digest == "" {
		return time.Time{}, ErrInstall
	}
	s := proof.set
	until := s.owner.until
	add := func(cap time.Time) bool {
		if cap.IsZero() {
			return false
		}
		if cap.Before(until) {
			until = cap
		}
		return true
	}
	for _, n := range s.nodes {
		if n == nil || n.current == nil || !add(n.current.Response().ValidUntil) || !add(n.request.Binding.ExpiresAt) {
			return time.Time{}, ErrInstall
		}
	}
	for _, g := range s.gateways {
		if g == nil || g.proof == nil || !add(g.proof.Response().ValidUntil) || !add(g.request.Binding.ExpiresAt) {
			return time.Time{}, ErrInstall
		}
	}
	for _, w := range s.stopped {
		if w == nil || w.proof == nil || !add(w.proof.Response().ValidUntil) || !add(w.request.Binding.ExpiresAt) {
			return time.Time{}, ErrInstall
		}
	}
	for _, w := range s.deployments {
		if w == nil {
			return time.Time{}, ErrInstall
		}
		if w.redis != nil && (w.redis.held == nil || !add(w.redis.held.Data().ValidUntil)) {
			return time.Time{}, ErrInstall
		}
	}
	for _, provider := range s.providerDependencies {
		if provider == nil || !add(provider.nativeUntil) || !add(provider.sourceUntil) {
			return time.Time{}, ErrInstall
		}
	}
	// Before A1 the installed provider has no future active KEK record. Consume
	// its genuine same-hold local observation without renewing it or doing I/O.
	if len(s.preAdoptionProviders) != 0 {
		cap, err := s.actualHold.originalVaultDependenciesUntil(s.owner.ctx)
		if err != nil || !add(cap) {
			return time.Time{}, ErrInstall
		}
	}
	if until.IsZero() || !time.Now().Before(until) {
		return time.Time{}, ErrInstall
	}
	return until, nil
}

// This is called ONLY after actual original Stage -> Bind -> A authentication
// has filled the same coverage tx/cut/auth/native/epoch fields. Reading a DTO
// before that point cannot construct Sources or bind metadata to an arbitrary tx.
func (p *PreparedOriginalAdoptionCoverage) bindOriginalHistoryControls(ctx context.Context, cfg a.SQLCoverageOwnerConfig, records a.OriginalAdoptionControlRecords) error {
	if p == nil || p.origin != p || p.sourceSet == nil || p.sourceSet.origin != p.sourceSet || p.sqlMetadata == nil || p.sourceSet.metadata != p.sqlMetadata || !p.sourceSet.local(ctx, true) || p.sourceSet.hold != p.hold || !consumerSameContext(ctx, p.ctx) || p.tx == nil || p.cut == nil || p.authenticated == nil || p.native == nil || p.native.set != p.hold.set || p.epoch == ^uint64(0) || p.refs == nil || len(p.refs) != 0 || len(p.sources) != 0 {
		return ErrInstall
	}
	if p.authenticated.ValidUntil().IsZero() {
		return ErrInstall
	}
	if p.authenticated.ValidUntil().Before(p.until) {
		p.until = p.authenticated.ValidUntil()
	}
	if p.sourceSet.until.Before(p.until) {
		p.until = p.sourceSet.until
	}
	signed, exists := records[cfg.Adoption.Source.RecordID]
	if !exists || len(records) != 17 {
		return ErrInstall
	}
	var adoption a.CoverageAdoptionRecord
	d := json.NewDecoder(bytes.NewReader(signed.Record))
	d.DisallowUnknownFields()
	if d.Decode(&adoption) != nil || d.Decode(new(any)) != io.EOF || adoption.Source != cfg.Adoption.Source || adoption.Facts.Database != cfg.Database || adoption.Facts.InstallationID != cfg.InstallationID || adoption.Facts.AdoptedEpoch != p.epoch+1 || len(adoption.Facts.Partitions) != 4 {
		return ErrInstall
	}
	// Stage authenticated these EXACT original bytes and all16 witnesses. Only
	// now extract comparison data, and additionally bind their source revisions
	// to this actually read finite original source/holder, never a supplied hash.
	seen := map[reg.Partition]bool{}
	sources := make([]reg.CoverageSource, 0, 4)
	for _, part := range adoption.Facts.Partitions {
		switch part.Partition {
		case reg.RetainedArtifacts, reg.InflightAndUnknownWrites, reg.HoldsAndCatalog, reg.RestoreAndPrune:
		default:
			return ErrInstall
		}
		if seen[part.Partition] || part.SourceID == "" || len(part.SourceID) > 256 || part.ReferenceCount != 0 || part.SnapshotRevision != p.sourceSet.snapshotRevision || part.FenceRevision != p.sourceSet.fenceRevision {
			return ErrInstall
		}
		seen[part.Partition] = true
		sources = append(sources, reg.CoverageSource{Partition: part.Partition, SourceID: part.SourceID, SnapshotRevision: part.SnapshotRevision, FenceRevision: part.FenceRevision, AdoptionSource: adoption.Source})
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].Partition < sources[j].Partition })
	p.sources = sources
	// This existing concrete binder checks the actual source/preparation/hold,
	// authenticated original tx/cut/native set, four sources, empty real refs,
	// epoch and all caps. First callback can never self-authorize a transaction.
	if p.sqlMetadata.bindOriginalCoverage(ctx, p) != nil {
		p.sources = nil
		return ErrInstall
	}
	return nil
}

// Comparison facts for ORIGINAL source-owner signing/execution. This object is
// not authority, does not sign records, and cannot be decoded into coverage.
type OriginalHistoryCoverageInspection struct {
	Version, SnapshotRevision, FenceRevision, SQLRevision, ConsumerRevision string
}

func (p *PreparedOriginalAdoptionCoverage) OriginalHistoryInspection(ctx context.Context) (OriginalHistoryCoverageInspection, error) {
	if p == nil || p.origin != p || p.hold == nil || p.hold.set == nil {
		return OriginalHistoryCoverageInspection{}, ErrInstall
	}
	p.hold.set.mu.Lock()
	defer p.hold.set.mu.Unlock()
	if p.sourceSet == nil || p.sourceSet.prep == nil {
		return OriginalHistoryCoverageInspection{}, ErrInstall
	}
	p.sourceSet.prep.mu.Lock()
	defer p.sourceSet.prep.mu.Unlock()
	if !p.sourceSet.local(ctx, false) || p.sqlMetadata != p.sourceSet.metadata || p.tx != nil {
		return OriginalHistoryCoverageInspection{}, ErrInstall
	}
	return OriginalHistoryCoverageInspection{"original-history-coverage-inspection.v1", p.sourceSet.snapshotRevision, p.sourceSet.fenceRevision, p.sqlMetadata.revision, p.sourceSet.resolved.revision}, nil
}
