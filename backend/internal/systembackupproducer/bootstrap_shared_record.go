package systembackupproducer

import (
	"context"
	"reflect"
)

// Private bootstrap-only shared read state. This is deliberately a different
// type from LockedRecord: it cannot be passed to InsertRecord/ReplaceRecord or
// exposed as a write capability. Only the domain uses the normal exclusive
// LockRecord and can be closed by the bootstrap transaction.
type bootstrapSharedRecord struct {
	owner *Transaction
	key   RecordKey
	typ   reflect.Type
	row   StoredRecord
}

func (*bootstrapSharedRecord) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// Uses the existing full canonical/projection/hash/EOF shared reader. Retain
// transaction state/fault latching and the closed type set, never caller SQL.
func (t *Transaction) lockBootstrapSharedRecord(ctx context.Context, key RecordKey, out any) (*bootstrapSharedRecord, error) {
	if t == nil || t.rejectCopy() {
		return nil, ErrGuardRequired
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.open || t.tx == nil {
		return nil, ErrGuardRequired
	}
	if t.fault != nil {
		return nil, t.fault
	}
	fail := func(err error) (*bootstrapSharedRecord, error) { t.fault = err; return nil, err }
	switch out.(type) {
	case *GrantRecord, *RunRecord, *TargetRecord, *HistoricalBindingRecord, *ReceiptRecord, *ReferenceRecord:
	default:
		return fail(ErrInvalid)
	}
	found, err := ReadOriginalSharedRecord(ctx, t.tx, t.scope, key, out)
	if err != nil {
		return fail(err)
	}
	if !found {
		return fail(ErrGuardRequired)
	}
	row, err := EncodeStoredRecord(out)
	if err != nil {
		return fail(err)
	}
	return &bootstrapSharedRecord{owner: t, key: key, typ: reflect.TypeOf(out).Elem(), row: row}, nil
}

// FinalGuard keeps these rows protected/current with FOR SHARE. Domain final
// verification remains the existing FOR UPDATE path including closed bytes.
func (p *bootstrapConsumptionPolicy) verifySharedRecord(ctx context.Context, read ReadSQL, lock *bootstrapSharedRecord) error {
	if p == nil || lock == nil || lock.owner != p.tx || lock.typ == nil || !SameGuardedTransaction(p.tx, read) {
		return ErrGuardRequired
	}
	out := reflect.New(lock.typ).Interface()
	found, err := ReadOriginalSharedRecord(ctx, read, p.request.Scope, lock.key, out)
	if err != nil {
		return err
	}
	if !found {
		return ErrConflict
	}
	actual, err := EncodeStoredRecord(out)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, lock.row) {
		return ErrConflict
	}
	return nil
}
