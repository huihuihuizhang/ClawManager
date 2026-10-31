package systembackupkekregistry

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
)

// MarkUnknown records an ORIGINAL producer's send/use intent in its original
// transaction BEFORE it can return permission to make a provider request. It
// never creates a missing planned member, changes its key/request provenance,
// releases a reference, or interprets a task status/TTL as external absence.
func (b *Bound) MarkUnknown(ctx context.Context, prepared PreparedReferenceChange) error {
	if ctx == nil || ctx.Err() != nil || b == nil || b.tx == nil || !present(prepared) || prepared.ExpectedEpoch() != b.epoch || b.epoch != b.original.Epoch {
		return ErrKEKFacts
	}
	r := prepared.Reference()
	if r.State != ReferenceUnknown || !validPartition(r.Partition) || r.SourceRecordID == "" || r.SourceRecordVersion == "" || prepared.Source() != r.LifecycleSource || prepared.Source().RecordID != r.SourceRecordID || prepared.Source().RecordVersion != r.SourceRecordVersion {
		return ErrKEKFacts
	}
	now, err := b.sqlNow(ctx)
	if err != nil || !now.Before(prepared.ValidUntil()) || prepared.Recheck(ctx, b.tx, b.Snapshot(), now) != nil {
		return ErrKEKFacts
	}
	var oldDigest string
	var oldRaw []byte
	if b.tx.QueryRowContext(ctx, `SELECT reference_sha256,reference_json FROM system_backup_v2_kek_references WHERE installation_id=? AND partition_name=? AND source_record_id=? AND source_record_version=? FOR UPDATE`, b.installationID, r.Partition, r.SourceRecordID, r.SourceRecordVersion).Scan(&oldDigest, &oldRaw) != nil {
		return ErrKEKFacts
	}
	var old Reference
	if json.Unmarshal(oldRaw, &old) != nil || (old.State != ReferencePlanned && old.State != ReferenceUnknown) {
		return ErrKEKFacts
	}
	canonical, oldHash, err := hashJSON(old)
	if err != nil || oldHash != oldDigest || !bytes.Equal(canonical, oldRaw) {
		return ErrKEKFacts
	}
	want, got := old, r
	want.State, got.State = "", ""
	want.LifecycleSource, got.LifecycleSource = SourceRecord{}, SourceRecord{}
	if !reflect.DeepEqual(want, got) {
		return ErrKEKFacts
	}
	raw, digest, err := hashJSON(r)
	if err != nil || len(raw) > 1<<20 {
		return ErrKEKFacts
	}
	if digest == oldDigest && bytes.Equal(raw, oldRaw) {
		return nil
	}
	result, err := b.tx.ExecContext(ctx, `UPDATE system_backup_v2_kek_references SET reference_state='unknown',reference_sha256=?,reference_json=? WHERE installation_id=? AND partition_name=? AND source_record_id=? AND source_record_version=? AND reference_sha256=? AND reference_state IN ('planned','unknown')`, digest, raw, b.installationID, r.Partition, r.SourceRecordID, r.SourceRecordVersion, oldDigest)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return ErrKEKFacts
	}
	return b.advance(ctx)
}
