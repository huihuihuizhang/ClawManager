package systembackupproducer

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

type storedRows struct {
	names                 []string
	data                  [][]driver.Value
	position              int
	nextError, closeError error
}

func (r *storedRows) Columns() []string { return r.names }
func (r *storedRows) Close() error      { return r.closeError }
func (r *storedRows) Next(dest []driver.Value) error {
	if r.position >= len(r.data) {
		if r.nextError != nil {
			return r.nextError
		}
		return io.EOF
	}
	copy(dest, r.data[r.position])
	r.position++
	return nil
}

func recordFixture(t *testing.T, name string) any {
	t.Helper()
	for _, f := range fixtures(t).Records {
		if f.Definition == name {
			out := destination(name)
			if e := DecodeRecord(f.Value, out); e != nil {
				t.Fatal(e)
			}
			return out
		}
	}
	t.Fatal("fixture missing", name)
	return nil
}
func keyForRecord(record any) RecordKey {
	switch r := record.(type) {
	case *DomainRecord:
		return RecordKey{}
	case *GrantRecord:
		return RecordKey{ID: r.GrantID}
	case *RunRecord:
		return RecordKey{ID: r.RunID}
	case *TargetRecord:
		return RecordKey{Hash: r.TargetHash}
	case *HistoricalBindingRecord:
		return RecordKey{EvidenceID: r.Evidence.EvidenceID}
	case *ReceiptRecord:
		return RecordKey{Hash: r.ReceiptKeyHash}
	case *CommandReceiptRecord:
		return RecordKey{Hash: r.ReceiptKeyHash}
	case *ReferenceRecord:
		return RecordKey{EvidenceID: r.EvidenceID, ReferenceKind: r.ReferenceKind, Hash: r.ReferenceKeyHash}
	}
	panic("unknown test record")
}
func rowsForRecord(t *testing.T, record any, found bool) *storedRows {
	t.Helper()
	s, e := storageFor(record)
	if e != nil {
		t.Fatal(e)
	}
	row, e := EncodeStoredRecord(record)
	if e != nil {
		t.Fatal(e)
	}
	result := &storedRows{names: recordColumns(s)}
	if found {
		values := make([]driver.Value, len(result.names))
		for i, k := range result.names {
			values[i] = sqlRecordValue(row.Columns[k])
		}
		result.data = [][]driver.Value{values}
	}
	return result
}
func assertRecordQuery(t *testing.T, q string, args []driver.NamedValue, record any) {
	t.Helper()
	s, e := storageFor(record)
	if e != nil {
		t.Fatal(e)
	}
	pk := "scope_key = ?"
	switch record.(type) {
	case *GrantRecord:
		pk += " AND grant_id = ?"
	case *RunRecord:
		pk += " AND run_id = ?"
	case *TargetRecord:
		pk += " AND target_hash = ?"
	case *HistoricalBindingRecord:
		pk += " AND evidence_id = ?"
	case *ReceiptRecord, *CommandReceiptRecord:
		pk += " AND receipt_key_hash = ?"
	case *ReferenceRecord:
		pk += " AND evidence_id = ? AND reference_kind = ? AND reference_key_hash = ?"
	}
	if !strings.HasPrefix(q, "SELECT ") || !strings.HasSuffix(q, " FROM "+s.table+" WHERE "+pk+" FOR UPDATE") || strings.Contains(q, "LIMIT") {
		t.Fatal("not an exact current PK read", q)
	}
	if len(args) != strings.Count(pk, "?") {
		t.Fatal("bad predicate args")
	}
	scope := reflect.ValueOf(record).Elem().FieldByName("Scope").Interface().(Scope)
	expected, e := recordKeyValues(s, scope, keyForRecord(record))
	if e != nil {
		t.Fatal(e)
	}
	for i, arg := range args {
		if !reflect.DeepEqual(arg.Value, expected[i]) {
			t.Fatal("query binding", i)
		}
	}
}

func TestSQLRecordLocksAndInserts(t *testing.T) {
	for _, f := range fixtures(t).Records {
		for _, exists := range []bool{false, true} {
			name := "absent_insert"
			if exists {
				name = "existing_read"
			}
			t.Run(f.Definition+"/"+name, func(t *testing.T) {
				r, s, _ := setupTx(t)
				record := recordFixture(t, f.Definition)
				out := destination(f.Definition)
				var lock *LockedRecord
				var retained *Transaction
				writes := 0
				s.queryRecord = func(q string, args []driver.NamedValue) (driver.Rows, error) {
					assertRecordQuery(t, q, args, record)
					return rowsForRecord(t, record, exists), nil
				}
				s.execRecord = func(q string, args []driver.NamedValue) (driver.Result, error) {
					writes++
					row, e := EncodeStoredRecord(record)
					if e != nil {
						t.Fatal(e)
					}
					def, _ := storageFor(record)
					cols := recordColumns(def)
					if !strings.HasPrefix(q, "INSERT INTO "+row.Table+" (") || strings.Contains(q, "UPDATE") || strings.Contains(q, "IGNORE") || len(args) != len(cols) {
						t.Fatal("bad insert", q)
					}
					for i, col := range cols {
						if !reflect.DeepEqual(args[i].Value, sqlRecordValue(row.Columns[col])) {
							t.Fatal("bad insert binding", col)
						}
					}
					return driver.RowsAffected(1), nil
				}
				got, e := r.Run(context.Background(), func(ctx context.Context, tx *Transaction) error {
					retained = tx
					var err error
					lock, err = tx.LockRecord(ctx, keyForRecord(record), out)
					if err != nil {
						return err
					}
					if lock.Found() != exists {
						t.Fatal("wrong presence")
					}
					if exists {
						if !reflect.DeepEqual(record, out) {
							t.Fatal("read mismatch")
						}
						return nil
					}
					if !reflect.DeepEqual(out, destination(f.Definition)) {
						t.Fatal("absence changed output")
					}
					return tx.InsertRecord(ctx, lock, record)
				})
				if e != nil || !got.Committed() || !lock.Found() {
					t.Fatal(got, e)
				}
				if (exists && writes != 0) || (!exists && writes != 1) {
					t.Fatal("write count", writes)
				}
				if _, e = retained.LockRecord(context.Background(), keyForRecord(record), out); !errors.Is(e, ErrGuardRequired) {
					t.Fatal("escaped read", e)
				}
				if e = retained.InsertRecord(context.Background(), lock, record); !errors.Is(e, ErrGuardRequired) {
					t.Fatal("escaped write", e)
				}
				if _, e = json.Marshal(lock); !errors.Is(e, ErrInvalid) {
					t.Fatal("serializable locked record", e)
				}
			})
		}
	}
}

func advanceRecord(t *testing.T, record any) {
	t.Helper()
	rv := reflect.ValueOf(record).Elem()
	version := rv.FieldByName("RowVersion")
	n, e := Counter(version.String()).Uint64()
	if e != nil {
		t.Fatal(e)
	}
	version.SetString(CounterString(n + 1))
	switch r := record.(type) {
	case *DomainRecord:
		r.State = "revoked"
	case *GrantRecord:
		r.State = "revoked"
	case *RunRecord:
		r.State = "published"
	case *TargetRecord:
		n, e := r.ResultVersion.Uint64()
		if e != nil {
			t.Fatal(e)
		}
		r.ResultVersion = ZeroCounter(CounterString(n + 1))
	}
}

func TestSQLRecordExactReplacement(t *testing.T) {
	for _, name := range []string{"DomainRecord", "GrantRecord", "RunRecord", "TargetRecord"} {
		t.Run(name, func(t *testing.T) {
			r, s, _ := setupTx(t)
			original := recordFixture(t, name)
			replacement := recordFixture(t, name)
			advanceRecord(t, replacement)
			out := destination(name)
			s.queryRecord = func(q string, args []driver.NamedValue) (driver.Rows, error) {
				assertRecordQuery(t, q, args, original)
				return rowsForRecord(t, original, true), nil
			}
			writes := 0
			s.execRecord = func(q string, args []driver.NamedValue) (driver.Result, error) {
				writes++
				old, e := EncodeStoredRecord(original)
				if e != nil {
					t.Fatal(e)
				}
				next, e := EncodeStoredRecord(replacement)
				if e != nil {
					t.Fatal(e)
				}
				def, _ := storageFor(original)
				cols := recordColumns(def)
				pk := recordPrimary(def)
				conditions := strings.SplitN(q, " WHERE ", 2)
				if !strings.HasPrefix(q, "UPDATE "+old.Table+" SET ") || len(conditions) != 2 {
					t.Fatal("bad update", q)
				}
				for _, col := range cols {
					if !strings.Contains(conditions[1], col+" <=> ?") {
						t.Fatal("missing old column predicate", col)
					}
				}
				expected := []any{}
				for _, col := range cols {
					if !containsKey(pk, col) {
						expected = append(expected, sqlRecordValue(next.Columns[col]))
					}
				}
				for _, col := range cols {
					expected = append(expected, sqlRecordValue(old.Columns[col]))
				}
				if len(expected) != len(args) {
					t.Fatal("parameter count")
				}
				for i, arg := range args {
					if !reflect.DeepEqual(expected[i], arg.Value) {
						t.Fatal("lost old/new binding", i)
					}
				}
				return driver.RowsAffected(1), nil
			}
			got, e := r.Run(context.Background(), func(ctx context.Context, tx *Transaction) error {
				lock, e := tx.LockRecord(ctx, keyForRecord(original), out)
				if e != nil {
					return e
				}
				return tx.ReplaceRecord(ctx, lock, replacement)
			})
			if e != nil || !got.Committed() || writes != 1 {
				t.Fatal(got, e, writes)
			}
		})
	}
}

func TestSQLRecordFailureLatches(t *testing.T) {
	for _, name := range []string{"query_error", "iteration_error", "close_error", "duplicate_rows", "wrong_columns", "corrupt_record", "wrong_scope", "wrong_key", "unused_key", "key_injection", "nil_out", "unknown_out", "zero_handle", "foreign_handle", "insert_existing", "replace_absent", "version_unchanged", "version_skip", "scope_change", "cas_zero", "cas_many", "exec_error", "affected_error"} {
		t.Run(name, func(t *testing.T) {
			r, s, _ := setupTx(t)
			record := recordFixture(t, "GrantRecord")
			key := keyForRecord(record)
			out := &GrantRecord{}
			rows := rowsForRecord(t, record, true)
			found := true
			queryErr := error(nil)
			switch name {
			case "query_error":
				queryErr = errors.New("read failure")
			case "iteration_error":
				rows.nextError = errors.New("iteration failure")
			case "close_error":
				rows.closeError = errors.New("close failure")
			case "duplicate_rows":
				rows.data = append(rows.data, rows.data[0])
			case "wrong_columns":
				rows.names[0] = "unexpected"
			case "corrupt_record":
				for i, c := range rows.names {
					if c == "record_sha256" {
						rows.data[0][i] = make([]byte, 32)
					}
				}
			case "wrong_scope":
				r.scope.Installation = "different_installation"
			case "wrong_key":
				key.ID = "different_grant"
			case "unused_key":
				key.EvidenceID = "ev_unused"
			case "key_injection":
				key.ID = "x' OR 1=1"
			case "replace_absent":
				rows.data = nil
				found = false
			}
			s.queryRecord = func(string, []driver.NamedValue) (driver.Rows, error) { return rows, queryErr }
			writes := 0
			s.execRecord = func(string, []driver.NamedValue) (driver.Result, error) {
				writes++
				switch name {
				case "cas_zero":
					return driver.RowsAffected(0), nil
				case "cas_many":
					return driver.RowsAffected(2), nil
				case "exec_error":
					return nil, errors.New("write error")
				case "affected_error":
					return badAffected{}, nil
				}
				return driver.RowsAffected(1), nil
			}
			var returned error
			got, e := r.Run(context.Background(), func(ctx context.Context, tx *Transaction) error {
				var destination any = out
				if name == "nil_out" {
					destination = (*GrantRecord)(nil)
				}
				if name == "unknown_out" {
					destination = &Scope{}
				}
				lock, err := tx.LockRecord(ctx, key, destination)
				returned = err
				if err != nil {
					return nil
				}
				if lock.Found() != found {
					t.Fatal("wrong found")
				}
				switch name {
				case "zero_handle":
					lock = &LockedRecord{}
				case "foreign_handle":
					lock = &LockedRecord{owner: &Transaction{}}
				}
				next := recordFixture(t, "GrantRecord").(*GrantRecord)
				advanceRecord(t, next)
				if name == "version_unchanged" {
					next.RowVersion = "1"
				}
				if name == "version_skip" {
					next.RowVersion = "3"
				}
				if name == "scope_change" {
					next.Scope.Installation = "different_installation"
				}
				if name == "insert_existing" {
					returned = tx.InsertRecord(ctx, lock, next)
				} else {
					returned = tx.ReplaceRecord(ctx, lock, next)
				}
				return nil // Deliberately ignore errors: transaction must still abort.
			})
			if returned == nil || e == nil || got.Committed() || s.commits != 0 || s.rollbacks != 1 {
				t.Fatal("ignored failure committed", returned, e, got, s.events)
			}
			if !in(name, "cas_zero", "cas_many", "exec_error", "affected_error") && writes != 0 {
				t.Fatal("invalid mutation reached SQL")
			}
			if in(name, "query_error", "iteration_error", "close_error", "duplicate_rows", "wrong_columns", "corrupt_record", "wrong_scope", "wrong_key") && !reflect.DeepEqual(out, &GrantRecord{}) {
				t.Fatal("failed load changed output")
			}
		})
	}
}

type badAffected struct{}

func (badAffected) LastInsertId() (int64, error) { return 0, nil }
func (badAffected) RowsAffected() (int64, error) { return 0, errors.New("no row count") }

func TestSQLRecordImmutableAndStructuralInvariants(t *testing.T) {
	for _, name := range []string{"HistoricalBindingRecord", "ReceiptRecord", "CommandReceiptRecord", "ReferenceRecord"} {
		t.Run(name, func(t *testing.T) {
			r, s, _ := setupTx(t)
			record := recordFixture(t, name)
			s.queryRecord = func(string, []driver.NamedValue) (driver.Rows, error) { return rowsForRecord(t, record, true), nil }
			got, e := r.Run(context.Background(), func(ctx context.Context, tx *Transaction) error {
				lock, e := tx.LockRecord(ctx, keyForRecord(record), destination(name))
				if e != nil {
					return e
				}
				return tx.ReplaceRecord(ctx, lock, record)
			})
			if !errors.Is(e, ErrConflict) || got.Committed() || s.commits != 0 {
				t.Fatal("immutable row updated", e)
			}
		})
	}
	for _, name := range []string{"grant_subject", "grant_generation", "grant_host", "run_deadline", "run_input", "run_observation", "run_backwards", "target_reset", "target_takeover_same_run", "domain_epoch_skip", "domain_reopen", "version_overflow"} {
		t.Run(name, func(t *testing.T) {
			definition := "GrantRecord"
			if strings.HasPrefix(name, "run_") {
				definition = "RunRecord"
			}
			if strings.HasPrefix(name, "target_") {
				definition = "TargetRecord"
			}
			if strings.HasPrefix(name, "domain_") {
				definition = "DomainRecord"
			}
			old := recordFixture(t, definition)
			next := recordFixture(t, definition)
			advanceRecord(t, next)
			switch name {
			case "grant_subject":
				next.(*GrantRecord).SubjectIdentityHash = Hash(strings.Repeat("b", 64))
			case "grant_generation":
				next.(*GrantRecord).Generation = "2"
			case "grant_host":
				next.(*GrantRecord).Host.Service.WorkloadIdentityHash = Hash(strings.Repeat("b", 64))
			case "run_deadline":
				next.(*RunRecord).OwnerWriteExpiresAt = "2026-09-30T02:00:00.000001Z"
			case "run_input":
				next.(*RunRecord).InputHash = Hash(strings.Repeat("b", 64))
			case "run_observation":
				v := Timestamp("2026-09-30T01:00:00.000002Z")
				next.(*RunRecord).ObservedAt = &v
			case "run_backwards":
				next.(*RunRecord).State = "acquired"
			case "target_reset":
				next.(*TargetRecord).ResultVersion = "0"
			case "target_takeover_same_run":
				next.(*TargetRecord).Generation = "2"
				next.(*TargetRecord).ResultVersion = old.(*TargetRecord).ResultVersion
			case "domain_epoch_skip":
				next.(*DomainRecord).Epoch = "3"
			case "domain_reopen":
				old.(*DomainRecord).State = "revoked"
				next.(*DomainRecord).State = "open"
			case "version_overflow":
				old.(*GrantRecord).RowVersion = "18446744073709551615"
				next.(*GrantRecord).RowVersion = "1"
			}
			a, e := EncodeStoredRecord(old)
			if e != nil {
				t.Fatal("test old invalid", e)
			}
			b, e := EncodeStoredRecord(next)
			if e != nil {
				t.Fatal("test next invalid", e)
			}
			if e = validReplacement(a, b, next); !errors.Is(e, ErrConflict) {
				t.Fatal("structural invariant changed", e)
			}
		})
	}
	// A uint64 value above max int64 is bound as exact decimal rather than
	// letting database/sql reject or silently wrap it at a driver boundary.
	if sqlRecordValue(^uint64(0)) != "18446744073709551615" {
		t.Fatal("unsigned SQL parameter")
	}
	var forged LockedRecord
	if json.Unmarshal([]byte(`{"found":true}`), &forged) == nil || forged.Found() {
		t.Fatal("forged lock")
	}
	if (&Transaction{}).ReplaceRecord(context.Background(), &forged, &DomainRecord{}) != ErrGuardRequired {
		t.Fatal("zero transaction")
	}
}

func TestSQLRecordReturnedDataCannotChangeCAS(t *testing.T) {
	r, s, _ := setupTx(t)
	original := recordFixture(t, "GrantRecord")
	out := &GrantRecord{}
	s.queryRecord = func(string, []driver.NamedValue) (driver.Rows, error) { return rowsForRecord(t, original, true), nil }
	s.execRecord = func(q string, args []driver.NamedValue) (driver.Result, error) {
		old, _ := EncodeStoredRecord(original)
		if !bytes.Equal(args[len(args)-1].Value.([]byte), old.Columns["record_sha256"].([]byte)) {
			t.Fatal("caller mutated stored CAS hash")
		}
		return driver.RowsAffected(1), nil
	}
	got, e := r.Run(context.Background(), func(ctx context.Context, tx *Transaction) error {
		lock, e := tx.LockRecord(ctx, keyForRecord(original), out)
		if e != nil {
			return e
		}
		out.SubjectIdentityHash = Hash(hex.EncodeToString(make([]byte, 32)))
		next := recordFixture(t, "GrantRecord")
		advanceRecord(t, next)
		return tx.ReplaceRecord(ctx, lock, next)
	})
	if e != nil || !got.Committed() {
		t.Fatal(got, e)
	}
}
