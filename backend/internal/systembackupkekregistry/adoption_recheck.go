package systembackupkekregistry

import (
	"context"
	"reflect"
	"sort"
)

func adoptionSources(sources []CoverageSource) []CoverageSource {
	out := append([]CoverageSource(nil), sources...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Partition != out[j].Partition {
			return out[i].Partition < out[j].Partition
		}
		return out[i].SourceID < out[j].SourceID
	})
	return out
}

// RecheckAdoption reads the exact derived index AFTER this Bound's first
// AdoptCoverage and before D's original commit. Snapshot intentionally remains
// the original pre-adoption snapshot for A/native source rechecks. This method
// never opens/commits a transaction, backfills, advances an epoch, calls a
// provider or turns source DATA into PreparedCoverage. Earlier owner/evidence/
// domain locks and genuine source-owned guards remain the caller's obligation.
func (b *Bound) RecheckAdoption(ctx context.Context, prepared PreparedCoverage) error {
	bad := func() error { return ErrKEKCoverage }
	if ctx == nil || ctx.Err() != nil || b == nil || !present(b.tx) || !present(prepared) || b.installationID == "" || b.original.InstallationID != b.installationID ||
		b.original.Epoch == ^uint64(0) || b.epoch != b.original.Epoch+1 || prepared.ExpectedEpoch() != b.original.Epoch || b.original.ObservedAt.IsZero() ||
		b.original.Coverage == nil || len(b.original.Coverage) != 0 || b.original.Bindings == nil || b.original.References == nil {
		return bad()
	}
	sources := adoptionSources(prepared.Sources())
	refs := prepared.References()
	until := prepared.ValidUntil()
	if !validCoverageSources(sources) || refs == nil || !reflect.DeepEqual(refs, b.original.References) {
		return bad()
	}
	now, err := b.sqlNow(ctx)
	if err != nil || now.Before(b.original.ObservedAt) || !now.Before(until) || prepared.Recheck(ctx, b.tx, b.Snapshot(), now) != nil {
		return bad()
	}
	// Guard first, then current locking reads: even an unexpected same-tx index
	// mutation by a source check cannot hide behind the old Bound.Snapshot.
	current := Snapshot{InstallationID: b.installationID, Bindings: []BindingFacts{}, References: []Reference{}, Coverage: []CoverageSource{}}
	if b.tx.QueryRowContext(ctx, `SELECT epoch FROM system_backup_v2_kek_fences WHERE installation_id=? FOR UPDATE`, b.installationID).Scan(&current.Epoch) != nil || current.Epoch != b.epoch {
		return bad()
	}
	if b.tx.QueryRowContext(ctx, `SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6)`).Scan(&current.Database.ServerUUID, &current.Database.Database, &current.ObservedAt) != nil || current.Database != b.original.Database || current.ObservedAt.Before(now) {
		return bad()
	}
	if readBindings(ctx, b.tx, &current, true) != nil || readReferences(ctx, b.tx, &current, true) != nil || readCoverage(ctx, b.tx, &current, true) != nil {
		return bad()
	}
	expected := cloneSnapshot(b.original)
	expected.Epoch, expected.Coverage = b.epoch, sources
	current.Coverage = adoptionSources(current.Coverage)
	if !SameSnapshotFacts(expected, current) {
		return bad()
	}
	after, err := b.sqlNow(ctx)
	if err != nil || after.Before(current.ObservedAt) || !after.Before(until) || ctx.Err() != nil || prepared.ExpectedEpoch() != b.original.Epoch || !prepared.ValidUntil().Equal(until) ||
		!reflect.DeepEqual(adoptionSources(prepared.Sources()), sources) || prepared.References() == nil || !reflect.DeepEqual(prepared.References(), b.original.References) {
		return bad()
	}
	return nil
}
