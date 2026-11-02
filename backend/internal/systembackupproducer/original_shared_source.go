package systembackupproducer

import (
	"context"
	"reflect"
	"strings"
)

// ReadOriginalSharedRecord reads DATA only, never an execution/admission/lock
// credential. It uses the exact closed storage projection, full PK and every
// canonical/projection/hash check of LockRecord, with SELECT-only FOR SHARE.
// Issuers may use it outside their completed admin/head snapshot; consumers
// may recheck only exact rows already held at their original earlier prefix.
func ReadOriginalSharedRecord(ctx context.Context, read ReadSQL, scope Scope, key RecordKey, out any) (bool, error) {
	if nilEnvironment(ctx) || ctx.Err() != nil || nilEnvironment(read) {
		return false, ErrGuardRequired
	}
	if out == nil || reflect.ValueOf(out).Kind() != reflect.Pointer || reflect.ValueOf(out).IsNil() {
		return false, ErrInvalid
	}
	definition, e := storageFor(out)
	if e != nil {
		return false, e
	}
	values, e := recordKeyValues(definition, scope, key)
	if e != nil {
		return false, e
	}
	keys, columns := recordPrimary(definition), recordColumns(definition)
	conditions := make([]string, len(keys))
	for n, key := range keys {
		conditions[n] = key + " = ?"
	}
	rows, e := read.QueryContext(ctx, "SELECT "+strings.Join(columns, ", ")+" FROM "+definition.table+" WHERE "+strings.Join(conditions, " AND ")+" FOR SHARE", values...)
	if e != nil {
		return false, ErrUnavailable
	}
	defer rows.Close()
	actual, e := rows.Columns()
	if e != nil || !reflect.DeepEqual(actual, columns) {
		return false, ErrInvalid
	}
	if !rows.Next() {
		if rows.Err() != nil || rows.Close() != nil {
			return false, ErrUnavailable
		}
		return false, nil
	}
	cells := make([]any, len(columns))
	dest := make([]any, len(cells))
	for n := range cells {
		dest[n] = &cells[n]
	}
	if rows.Scan(dest...) != nil {
		return false, ErrUnavailable
	}
	row := StoredRecord{Table: definition.table, Columns: map[string]any{}}
	for n, key := range columns {
		row.Columns[key] = cells[n]
	}
	if rows.Next() {
		return false, ErrInvalid
	}
	if rows.Err() != nil || rows.Close() != nil {
		return false, ErrUnavailable
	}
	next := reflect.New(reflect.ValueOf(out).Elem().Type())
	if e := DecodeStoredRecord(row, scope, next.Interface()); e != nil {
		return false, e
	}
	for n, key := range keys {
		if !sameStoredValue(values[n], row.Columns[key]) {
			return false, ErrConflict
		}
	}
	reflect.ValueOf(out).Elem().Set(next.Elem())
	return true, nil
}

// OriginalPendingReferenceHash exposes only the existing comparison identity;
// it does not create a reference, hold, observation or consumption permission.
func OriginalPendingReferenceHash(history HistoricalBindingRecord) (Hash, error) {
	return pendingReferenceHash(history)
}
