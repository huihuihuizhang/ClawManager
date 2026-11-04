package systembackupkekregistry

import "context"

// ReadExistingSnapshotInView is a read-only comparison of an already adopted
// index. It never creates a missing fence, advances it or authenticates sources.
// The original caller owns the transaction and its earlier lock prefix.
func (SQLStore) ReadExistingSnapshotInView(ctx context.Context, view SQLReadView, installation string) (Snapshot, error) {
	if ctx == nil || ctx.Err() != nil || !present(view) || installation == "" || len(installation) > 128 {
		return Snapshot{}, ErrKEKFacts
	}
	s := Snapshot{InstallationID: installation, Bindings: []BindingFacts{}, Coverage: []CoverageSource{}, References: []Reference{}}
	if view.QueryRowContext(ctx, "SELECT epoch FROM system_backup_v2_kek_fences WHERE installation_id=? FOR SHARE", installation).Scan(&s.Epoch) != nil || s.Epoch == 0 {
		return Snapshot{}, ErrKEKCoverage
	}
	if view.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6)").Scan(&s.Database.ServerUUID, &s.Database.Database, &s.ObservedAt) != nil || s.Database.ServerUUID == "" || s.Database.Database == "" || s.ObservedAt.IsZero() {
		return Snapshot{}, ErrKEKFacts
	}
	if err := readBindings(ctx, view, &s, true); err != nil {
		return Snapshot{}, err
	}
	if err := readReferences(ctx, view, &s, true); err != nil {
		return Snapshot{}, err
	}
	if err := readCoverage(ctx, view, &s, true); err != nil {
		return Snapshot{}, err
	}
	return cloneSnapshot(s), nil
}
