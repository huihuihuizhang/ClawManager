package systembackupproducer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// StoredRecord is an untrusted SQL row, never an authorization or lock proof.
// Columns include every typed projection, record_bytes and record_sha256.
// MySQL callers must scan DATETIME(6) as UTC time.Time (parseTime=true).
type StoredRecord struct {
	Table   string
	Columns map[string]any
}

type storageProjection struct{ name, path, kind string }
type storageDefinition struct {
	table  string
	limit  int
	fields []storageProjection
}

// These closed identifiers are the only table/column names a future SQL adapter
// may use. The persistence dictionary is checked against this list in tests.
func storageFor(out any) (storageDefinition, error) {
	var suffix, fields string
	limit := 16384
	switch out.(type) {
	case *DomainRecord:
		suffix = "domains"
		fields = "scope_bytes epoch row_version state admission_expires_at"
	case *GrantRecord:
		suffix = "grants"
		limit = 32768
		fields = "grant_id generation domain_epoch row_version state subject_identity_hash lease_expires_at authorization_expires_at"
	case *RunRecord:
		suffix = "runs"
		fields = "run_id grant_id grant_generation target_hash target_generation evidence_id owner_write_expires_at observed_at observation_expires_at state row_version"
	case *TargetRecord:
		suffix = "targets"
		fields = "target_hash generation current_run_id result_version row_version"
	case *HistoricalBindingRecord:
		suffix = "evidence_bindings"
		limit = 32768
		fields = "scope_bytes run_id evidence_id:evidence.evidence_id grant_id grant_generation owner_write_expires_at observation_expires_at retention_expires_at"
	case *ReceiptRecord:
		suffix = "result_receipts"
		limit = 98304
		fields = "scope_bytes receipt_key_hash request_hash run_id:request.run_id evidence_id:request.evidence.evidence_id target_hash:@target result_version committed_at retention_expires_at charged_bytes"
	case *CommandReceiptRecord:
		suffix = "command_receipts"
		limit = 65536
		fields = "scope_bytes receipt_key_hash request_hash committed_at retention_expires_at charged_bytes"
	case *ReferenceRecord:
		suffix = "evidence_refs"
		limit = 8192
		fields = "evidence_id reference_kind reference_key_hash protected_until"
	default:
		return storageDefinition{}, ErrInvalid
	}
	if reflect.ValueOf(out).IsNil() {
		return storageDefinition{}, ErrInvalid
	}
	s := storageDefinition{table: "system_backup_producer_" + suffix, limit: limit}
	for _, f := range strings.Fields("scope_key " + fields) {
		pair := strings.SplitN(f, ":", 2)
		name, path := pair[0], pair[0]
		if len(pair) == 2 {
			path = pair[1]
		}
		kind := "text"
		switch name {
		case "scope_key", "scope_bytes":
			kind = name
		case "epoch", "row_version", "generation", "domain_epoch", "grant_generation", "target_generation", "result_version", "charged_bytes":
			kind = "counter"
		default:
			if strings.HasSuffix(name, "_hash") {
				kind = "hash"
			}
			if strings.HasSuffix(name, "_at") || name == "protected_until" {
				kind = "time"
			}
		}
		s.fields = append(s.fields, storageProjection{name, path, kind})
	}
	return s, nil
}

// EncodeStoredRecord validates all eight record types and derives projections
// from the complete record. The returned data grants no right to insert it.
func EncodeStoredRecord(record any) (StoredRecord, error) {
	s, e := storageFor(record)
	if e != nil {
		return StoredRecord{}, e
	}
	if e = validateTyped(reflect.ValueOf(record)); e != nil {
		return StoredRecord{}, e
	}
	m, e := recordTree(record)
	if e != nil {
		return StoredRecord{}, e
	}
	encoded, e := canonicalTree(m)
	if e != nil || len(encoded) > s.limit {
		return StoredRecord{}, ErrInvalid
	}
	digest := sha256.Sum256(encoded)
	row := StoredRecord{Table: s.table, Columns: map[string]any{"record_bytes": encoded, "record_sha256": append([]byte(nil), digest[:]...)}}
	for _, f := range s.fields {
		v, e := projectStored(m, f)
		if e != nil {
			return StoredRecord{}, e
		}
		row.Columns[f.name] = v
	}
	return row, nil
}

func projectStored(m map[string]any, f storageProjection) (any, error) {
	if f.kind == "scope_bytes" {
		return canonicalTree(m["scope"])
	}
	if f.kind == "scope_key" {
		h, e := hashTree(ScopeDomain, m["scope"])
		if e != nil {
			return nil, e
		}
		return hex.DecodeString(string(h))
	}
	if f.path == "@target" {
		request, ok := m["request"].(map[string]any)
		if !ok {
			return nil, ErrInvalid
		}
		target, ok := request["target"].(map[string]any)
		if !ok {
			return nil, ErrInvalid
		}
		h, e := hashTree(TargetDomain, logicalTarget(target))
		if e != nil {
			return nil, e
		}
		return hex.DecodeString(string(h))
	}
	var v any = m
	for _, k := range strings.Split(f.path, ".") {
		obj, ok := v.(map[string]any)
		if !ok {
			return nil, ErrInvalid
		}
		v, ok = obj[k]
		if !ok {
			return nil, ErrInvalid
		}
	}
	if v == nil {
		return nil, nil
	}
	str, ok := v.(string)
	if !ok {
		return nil, ErrInvalid
	}
	switch f.kind {
	case "hash":
		return hex.DecodeString(str)
	case "counter":
		return strconv.ParseUint(str, 10, 64)
	case "time":
		return Timestamp(str).Time()
	default:
		return str, nil
	}
}

// DecodeStoredRecord checks the complete row and exact caller scope before
// changing out. A valid SHA alone proves neither authority nor projection
// integrity. Callers still need current locking reads and authenticated policy.
func DecodeStoredRecord(row StoredRecord, scope Scope, out any) error {
	s, e := storageFor(out)
	if e != nil || row.Table != s.table {
		return ErrInvalid
	}
	if validateTyped(reflect.ValueOf(scope)) != nil {
		return ErrInvalid
	}
	raw, ok := row.Columns["record_bytes"].([]byte)
	if !ok || len(raw) == 0 || len(raw) > s.limit {
		return ErrInvalid
	}
	digest, ok := row.Columns["record_sha256"].([]byte)
	if !ok {
		return ErrInvalid
	}
	wantHash := sha256.Sum256(raw)
	if !bytes.Equal(digest, wantHash[:]) {
		return ErrInvalid
	}
	tree, e := parseFrame(raw, s.limit)
	if e != nil {
		return e
	}
	jsonBytes, e := json.Marshal(tree)
	if e != nil {
		return ErrInvalid
	}
	next := reflect.New(reflect.ValueOf(out).Elem().Type())
	if e = DecodeRecord(jsonBytes, next.Interface()); e != nil {
		return e
	}
	if next.Elem().FieldByName("Scope").Interface().(Scope) != scope {
		return ErrInvalid
	}
	expected, e := EncodeStoredRecord(next.Interface())
	if e != nil {
		return e
	}
	if len(row.Columns) != len(expected.Columns) {
		return ErrInvalid
	}
	for k, want := range expected.Columns {
		got, ok := row.Columns[k]
		if !ok || !sameStoredValue(want, got) {
			return ErrInvalid
		}
	}
	reflect.ValueOf(out).Elem().Set(next.Elem())
	return nil
}

func sameStoredValue(want, got any) bool {
	switch w := want.(type) {
	case nil:
		return got == nil
	case []byte:
		b, ok := got.([]byte)
		return ok && bytes.Equal(w, b)
	case string:
		switch g := got.(type) {
		case string:
			return w == g
		case []byte:
			return w == string(g)
		}
	case uint64:
		switch g := got.(type) {
		case uint64:
			return w == g
		case int64:
			return g >= 0 && w == uint64(g)
		case []byte:
			return sameStoredValue(w, string(g))
		case string:
			n, e := parseCounter(g, true)
			return e == nil && w == n
		}
	case time.Time:
		g, ok := got.(time.Time)
		return ok && validDBTime(g) && w.Equal(g)
	}
	return false
}
