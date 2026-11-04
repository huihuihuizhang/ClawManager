package systembackupproducer

import "context"

func OriginalPendingHoldData(h HistoricalBindingRecord) (ReferenceRecord, error) {
	key, e := pendingReferenceHash(h)
	if e != nil {
		return ReferenceRecord{}, e
	}
	return ReferenceRecord{Scope: h.Scope, EvidenceID: h.Evidence.EvidenceID, ReferenceKind: "hold", ReferenceKeyHash: key, ProtectedUntil: h.RetentionExpiresAt, CreatedAt: h.CreatedAt}, nil
}

// Comparison/source read only. The source owner must authenticate the original
// history independently; this function never creates or releases a hold.
func ReadOriginalPendingHold(ctx context.Context, read ReadSQL, h HistoricalBindingRecord) (ReferenceRecord, error) {
	key, e := pendingReferenceHash(h)
	if e != nil {
		return ReferenceRecord{}, e
	}
	want := ReferenceRecord{Scope: h.Scope, EvidenceID: h.Evidence.EvidenceID, ReferenceKind: "hold", ReferenceKeyHash: key, ProtectedUntil: h.RetentionExpiresAt, CreatedAt: h.CreatedAt}
	var actual ReferenceRecord
	found, e := ReadOriginalSharedRecord(ctx, read, h.Scope, RecordKey{EvidenceID: want.EvidenceID, ReferenceKind: want.ReferenceKind, Hash: want.ReferenceKeyHash}, &actual)
	if e != nil || !found || actual != want {
		return ReferenceRecord{}, ErrGuardRequired
	}
	return actual, nil
}
