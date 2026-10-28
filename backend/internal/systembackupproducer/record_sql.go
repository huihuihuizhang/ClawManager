package systembackupproducer

import (
	"bytes"
	"context"
	"encoding/hex"
	"reflect"
	"strconv"
	"strings"
)

// RecordKey contains only a record's primary key after its transaction scope.
// Which fields are required is fixed by the concrete output record type. Unused
// fields must be empty. It neither chooses a SQL identifier nor grants authority.
type RecordKey struct {
	ID            ID
	Hash          Hash
	EvidenceID    EvidenceID
	ReferenceKind string
}

// LockedRecord is transaction-local read state. It is not an execution handle.
// Only a successful current locking read can create one, including an absent
// primary-key range. Authentication and global L0-L10 ordering remain Policy's
// responsibility. No constructor or JSON representation is exposed.
type LockedRecord struct {
	owner      *Transaction
	definition storageDefinition
	keys       []string
	keyValues  []any
	row        StoredRecord
	found      bool
}

func (r *LockedRecord) Found() bool {
	if r == nil || r.owner == nil {
		return false
	}
	r.owner.mu.Lock()
	defer r.owner.mu.Unlock()
	return r.found
}
func (*LockedRecord) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*LockedRecord) UnmarshalJSON([]byte) error   { return ErrInvalid }

func recordPrimary(s storageDefinition) []string {
	keys := []string{"scope_key"}
	switch strings.TrimPrefix(s.table, "system_backup_producer_") {
	case "domains":
	case "grants":
		keys = append(keys, "grant_id")
	case "runs":
		keys = append(keys, "run_id")
	case "targets":
		keys = append(keys, "target_hash")
	case "evidence_bindings":
		keys = append(keys, "evidence_id")
	case "result_receipts", "command_receipts":
		keys = append(keys, "receipt_key_hash")
	case "evidence_refs":
		keys = append(keys, "evidence_id", "reference_kind", "reference_key_hash")
	default:
		return nil
	}
	return keys
}

func recordKeyValues(s storageDefinition, scope Scope, k RecordKey) ([]any, error) {
	if validateTyped(reflect.ValueOf(scope)) != nil {
		return nil, ErrInvalid
	}
	m, e := recordTree(scope)
	if e != nil {
		return nil, e
	}
	h, e := hashTree(ScopeDomain, m)
	if e != nil {
		return nil, e
	}
	b, e := hex.DecodeString(string(h))
	if e != nil {
		return nil, ErrInvalid
	}
	values := []any{b}
	used := RecordKey{}
	for _, name := range recordPrimary(s)[1:] {
		switch name {
		case "grant_id", "run_id":
			if validateTyped(reflect.ValueOf(k.ID)) != nil {
				return nil, ErrInvalid
			}
			used.ID = k.ID
			values = append(values, string(k.ID))
		case "target_hash", "receipt_key_hash", "reference_key_hash":
			if validateTyped(reflect.ValueOf(k.Hash)) != nil {
				return nil, ErrInvalid
			}
			used.Hash = k.Hash
			b, e := hex.DecodeString(string(k.Hash))
			if e != nil {
				return nil, ErrInvalid
			}
			values = append(values, b)
		case "evidence_id":
			if validateTyped(reflect.ValueOf(k.EvidenceID)) != nil {
				return nil, ErrInvalid
			}
			used.EvidenceID = k.EvidenceID
			values = append(values, string(k.EvidenceID))
		case "reference_kind":
			if !in(k.ReferenceKind, "producer_result", "producer_receipt", "bootstrap_candidate", "hold") {
				return nil, ErrInvalid
			}
			used.ReferenceKind = k.ReferenceKind
			values = append(values, k.ReferenceKind)
		}
	}
	if used != k {
		return nil, ErrInvalid
	}
	return values, nil
}

func recordColumns(s storageDefinition) []string {
	columns := make([]string, 0, len(s.fields)+2)
	for _, f := range s.fields {
		columns = append(columns, f.name)
	}
	return append(columns, "record_bytes", "record_sha256")
}

// LockRecord uses a full primary-key current read, never a snapshot or a
// LIMIT-truncated scan. It consumes/closes rows and validates all projections
// before exposing data. Absent records leave out unchanged. Any read/scan/close
// or validation error is latched so ignored errors cannot lead to commit.
func (t *Transaction) LockRecord(ctx context.Context, key RecordKey, out any) (*LockedRecord, error) {
	if t.rejectCopy() {
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
	fail := func(e error) (*LockedRecord, error) { t.fault = e; return nil, e }
	s, e := storageFor(out)
	if e != nil {
		return fail(e)
	}
	values, e := recordKeyValues(s, t.scope, key)
	if e != nil {
		return fail(e)
	}
	keys, columns := recordPrimary(s), recordColumns(s)
	conditions := make([]string, len(keys))
	for i, k := range keys {
		conditions[i] = k + " = ?"
	}
	q := "SELECT " + strings.Join(columns, ", ") + " FROM " + s.table + " WHERE " + strings.Join(conditions, " AND ") + " FOR UPDATE"
	rows, e := t.tx.QueryContext(ctx, q, values...)
	if e != nil {
		return fail(ErrUnavailable)
	}
	defer rows.Close()
	actual, e := rows.Columns()
	if e != nil || !reflect.DeepEqual(actual, columns) {
		return fail(ErrInvalid)
	}
	locked := &LockedRecord{owner: t, definition: s, keys: keys, keyValues: values}
	if !rows.Next() {
		if rows.Err() != nil || rows.Close() != nil {
			return fail(ErrUnavailable)
		}
		return locked, nil
	}
	cell := make([]any, len(columns))
	dest := make([]any, len(columns))
	for i := range cell {
		dest[i] = &cell[i]
	}
	if rows.Scan(dest...) != nil {
		return fail(ErrUnavailable)
	}
	row := StoredRecord{Table: s.table, Columns: map[string]any{}}
	for i, k := range columns {
		row.Columns[k] = cell[i]
	}
	if rows.Next() {
		return fail(ErrInvalid)
	}
	if rows.Err() != nil || rows.Close() != nil {
		return fail(ErrUnavailable)
	}
	next := reflect.New(reflect.ValueOf(out).Elem().Type())
	if e = DecodeStoredRecord(row, t.scope, next.Interface()); e != nil {
		return fail(e)
	}
	for i, k := range keys {
		if !sameStoredValue(values[i], row.Columns[k]) {
			return fail(ErrInvalid)
		}
	}
	// Encode a separate immutable copy, never retaining the caller's object.
	locked.row, e = EncodeStoredRecord(next.Interface())
	if e != nil {
		return fail(e)
	}
	locked.found = true
	reflect.ValueOf(out).Elem().Set(next.Elem())
	return locked, nil
}

// InsertRecord requires a previously locked absence. It never upserts or
// performs an idempotent replay implicitly. Receipts/history must be compared
// and authorized by the lifecycle service before returning an existing value.
func (t *Transaction) InsertRecord(ctx context.Context, locked *LockedRecord, record any) error {
	return t.writeRecord(ctx, locked, record, false)
}

// ReplaceRecord updates all projections and canonical bytes together, using
// every previously read column as a null-safe compare predicate. Only the four
// versioned control records are mutable. No delete/purge/receipt rewrite exists.
func (t *Transaction) ReplaceRecord(ctx context.Context, locked *LockedRecord, record any) error {
	return t.writeRecord(ctx, locked, record, true)
}

func (t *Transaction) writeRecord(ctx context.Context, locked *LockedRecord, record any, replace bool) error {
	if t.rejectCopy() {
		return ErrGuardRequired
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.open || t.tx == nil {
		return ErrGuardRequired
	}
	if t.fault != nil {
		return t.fault
	}
	fail := func(e error) error { t.fault = e; return e }
	if locked == nil || locked.owner != t || locked.found != replace {
		return fail(ErrGuardRequired)
	}
	row, e := EncodeStoredRecord(record)
	if e != nil {
		return fail(e)
	}
	if row.Table != locked.definition.table {
		return fail(ErrInvalid)
	}
	if reflect.ValueOf(record).Elem().FieldByName("Scope").Interface().(Scope) != t.scope {
		return fail(ErrInvalid)
	}
	for i, k := range locked.keys {
		if !sameStoredValue(locked.keyValues[i], row.Columns[k]) {
			return fail(ErrConflict)
		}
	}
	columns := recordColumns(locked.definition)
	var q string
	args := []any{}
	if replace {
		if e = validReplacement(locked.row, row, record); e != nil {
			return fail(e)
		}
		sets, conditions := []string{}, []string{}
		for _, k := range columns {
			if !containsKey(locked.keys, k) {
				sets = append(sets, k+" = ?")
				args = append(args, sqlRecordValue(row.Columns[k]))
			}
		}
		for _, k := range columns {
			conditions = append(conditions, k+" <=> ?")
			args = append(args, sqlRecordValue(locked.row.Columns[k]))
		}
		q = "UPDATE " + row.Table + " SET " + strings.Join(sets, ", ") + " WHERE " + strings.Join(conditions, " AND ")
	} else {
		placeholders := make([]string, len(columns))
		for i, k := range columns {
			placeholders[i] = "?"
			args = append(args, sqlRecordValue(row.Columns[k]))
		}
		q = "INSERT INTO " + row.Table + " (" + strings.Join(columns, ", ") + ") VALUES (" + strings.Join(placeholders, ", ") + ")"
	}
	result, e := t.tx.ExecContext(ctx, q, args...)
	if e != nil {
		return fail(ErrUnavailable)
	}
	n, e := result.RowsAffected()
	if e != nil || n != 1 {
		return fail(ErrConflict)
	}
	locked.row = row
	locked.found = true
	return nil
}

func containsKey(keys []string, k string) bool {
	for _, key := range keys {
		if key == k {
			return true
		}
	}
	return false
}
func sqlRecordValue(v any) any {
	if n, ok := v.(uint64); ok {
		return strconv.FormatUint(n, 10)
	}
	return v
}

// Structural monotonicity is enforced here in addition to exact CAS. It does
// not substitute for live authorization, deadlines, capacity or state-machine
// decisions by the lifecycle service.
func validReplacement(old, next StoredRecord, record any) error {
	oldVersion, ok := old.Columns["row_version"].(uint64)
	newVersion, newOK := next.Columns["row_version"].(uint64)
	if !ok || !newOK || oldVersion == ^uint64(0) || newVersion != oldVersion+1 {
		return ErrConflict
	}
	before, e := parseFrame(old.Columns["record_bytes"].([]byte), 98304)
	if e != nil {
		return e
	}
	after, e := parseFrame(next.Columns["record_bytes"].([]byte), 98304)
	if e != nil {
		return e
	}
	a, b := before.(map[string]any), after.(map[string]any)
	allowed := []string{"row_version"}
	switch record.(type) {
	case *DomainRecord:
		x, y := old.Columns["epoch"].(uint64), next.Columns["epoch"].(uint64)
		if y != x && (x == ^uint64(0) || y != x+1) {
			return ErrConflict
		}
		if b["updated_at"].(string) < a["updated_at"].(string) {
			return ErrConflict
		}
		allowed = append(allowed, "state", "updated_at")
		if y != x {
			allowed = append(allowed, "epoch", "issuer_identity_hash", "admission", "admission_expires_at")
		} else if a["state"] != "open" && b["state"] != a["state"] {
			return ErrConflict
		}
	case *GrantRecord:
		if a["state"] != "active" {
			return ErrConflict
		}
		allowed = append(allowed, "state", "lease_expires_at")
	case *RunRecord:
		from, to := a["state"].(string), b["state"].(string)
		if from != to && !((from == "acquired" && to == "pending") || (from == "pending" && to == "published") || (from == "published" && to == "committed") || (in(from, "acquired", "pending", "published") && to == "superseded")) {
			return ErrConflict
		}
		allowed = append(allowed, "state")
		if a["observed_at"] == nil && from == "acquired" && in(to, "acquired", "pending") {
			allowed = append(allowed, "observed_at", "observation_expires_at")
		}
	case *TargetRecord:
		x, y := old.Columns["generation"].(uint64), next.Columns["generation"].(uint64)
		r, s := old.Columns["result_version"].(uint64), next.Columns["result_version"].(uint64)
		if x == y {
			if r == ^uint64(0) || s != r+1 {
				return ErrConflict
			}
			allowed = append(allowed, "result_version")
		} else {
			if x == ^uint64(0) || y != x+1 || r != s || a["current_run_id"] == b["current_run_id"] {
				return ErrConflict
			}
			allowed = append(allowed, "generation", "current_run_id", "target")
		}
	default:
		return ErrConflict
	}
	for _, k := range allowed {
		delete(a, k)
		delete(b, k)
	}
	x, e := canonicalTree(a)
	if e != nil {
		return e
	}
	y, e := canonicalTree(b)
	if e != nil {
		return e
	}
	if !bytes.Equal(x, y) {
		return ErrConflict
	}
	return nil
}
