package systembackupproducer

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestStoredRecordRoundtripAndColumnIntegrity(t *testing.T) {
	for _, f := range fixtures(t).Records {
		t.Run(f.Definition, func(t *testing.T) {
			source := destination(f.Definition)
			if e := DecodeRecord(f.Value, source); e != nil {
				t.Fatal(e)
			}
			row, e := EncodeStoredRecord(source)
			if e != nil {
				t.Fatal(e)
			}
			scope := reflect.ValueOf(source).Elem().FieldByName("Scope").Interface().(Scope)
			out := destination(f.Definition)
			if e = DecodeStoredRecord(row, scope, out); e != nil || !reflect.DeepEqual(source, out) {
				t.Fatal("roundtrip", e)
			}
			golden, e := CanonicalJSON(f.Value)
			if e != nil || !bytes.Equal(golden, row.Columns["record_bytes"].([]byte)) {
				t.Fatal("C1 storage bytes", e)
			}
			// Tamper every projection independently, including integrity columns.
			for k, v := range row.Columns {
				t.Run("tamper_"+k, func(t *testing.T) {
					bad := copyStored(row)
					switch x := v.(type) {
					case []byte:
						b := append([]byte(nil), x...)
						b[0] ^= 1
						bad.Columns[k] = b
					case uint64:
						bad.Columns[k] = x + 1
					case string:
						bad.Columns[k] = x + "x"
					case time.Time:
						bad.Columns[k] = x.Add(time.Microsecond)
					case nil:
						bad.Columns[k] = time.Now()
					}
					before, _ := json.Marshal(out)
					if DecodeStoredRecord(bad, scope, out) == nil {
						t.Fatal("accepted changed column")
					}
					after, _ := json.Marshal(out)
					if !bytes.Equal(before, after) {
						t.Fatal("failed decode changed output")
					}
				})
			}
			for k := range row.Columns {
				bad := copyStored(row)
				delete(bad.Columns, k)
				if DecodeStoredRecord(bad, scope, out) == nil {
					t.Fatal("accepted missing", k)
				}
			}
			bad := copyStored(row)
			bad.Columns["unknown"] = nil
			if DecodeStoredRecord(bad, scope, out) == nil {
				t.Fatal("accepted extra column")
			}
			wrong := scope
			wrong.Database = "different_db"
			if DecodeStoredRecord(row, wrong, out) == nil {
				t.Fatal("accepted cross scope")
			}
			bad = copyStored(row)
			bad.Table += "_other"
			if DecodeStoredRecord(bad, scope, out) == nil {
				t.Fatal("accepted wrong table")
			}
			// database/sql may represent unsigned BIGINT as decimal bytes.
			driver := copyStored(row)
			for k, v := range driver.Columns {
				if n, ok := v.(uint64); ok {
					driver.Columns[k] = []byte(CounterString(n))
				}
			}
			if e = DecodeStoredRecord(driver, scope, out); e != nil {
				t.Fatal("driver uint64 bytes", e)
			}
		})
	}
}

func copyStored(r StoredRecord) StoredRecord {
	next := StoredRecord{Table: r.Table, Columns: map[string]any{}}
	for k, v := range r.Columns {
		next.Columns[k] = v
	}
	return next
}
func CounterString(n uint64) string { b, _ := json.Marshal(n); return string(b) }

func TestStoredSQLScalarConversion(t *testing.T) {
	for _, bad := range []any{"01", "+1", "1 ", "-1", "1.0", "18446744073709551616", float64(1), int64(-1), []byte("01"), nil} {
		if sameStoredValue(uint64(1), bad) {
			t.Fatalf("accepted %v", bad)
		}
	}
	for _, good := range []any{uint64(1), int64(1), "1", []byte("1")} {
		if !sameStoredValue(uint64(1), good) {
			t.Fatalf("rejected %v", good)
		}
	}
	if !sameStoredValue(^uint64(0), []byte("18446744073709551615")) {
		t.Fatal("unsigned max lost")
	}
	now := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	if sameStoredValue(now, now.In(time.FixedZone("shift", 3600))) || sameStoredValue(now, now.Add(time.Nanosecond)) {
		t.Fatal("time coercion")
	}
	if _, e := EncodeStoredRecord(&ResultRequest{}); e == nil {
		t.Fatal("request is not a stored row")
	}
	var nilRecord *DomainRecord
	if _, e := EncodeStoredRecord(nilRecord); e == nil {
		t.Fatal("nil destination")
	}
}

func TestStoredFrameHostileInput(t *testing.T) {
	frame := func(v any) []byte {
		b, e := canonicalTree(v)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	str := frame("a")
	object := func(keys ...string) []byte {
		b := []byte{'o', 0, 0, 0, 0, 0, 0, 0, byte(len(keys))}
		for _, k := range keys {
			b = append(b, frame(k)...)
			b = append(b, 'n')
		}
		return b
	}
	deep := []byte{'n'}
	for i := 0; i < 18; i++ {
		deep = append([]byte{'a', 0, 0, 0, 0, 0, 0, 0, 1}, deep...)
	}
	for name, b := range map[string][]byte{"empty": nil, "tag": {'x'}, "number": {'1'}, "trailing": {'n', 'n'}, "shortlen": {'s', 0}, "huge": {'s', 255, 255, 255, 255, 255, 255, 255, 255}, "array_huge": {'a', 255, 255, 255, 255, 255, 255, 255, 255}, "truncated": str[:len(str)-1], "utf8": {'s', 0, 0, 0, 0, 0, 0, 0, 1, 255}, "duplicate": object("a", "a"), "unsorted": object("b", "a"), "nonstringkey": {'o', 0, 0, 0, 0, 0, 0, 0, 1, 'n', 'n'}, "depth": deep} {
		t.Run(name, func(t *testing.T) {
			if _, e := parseFrame(b, 98304); e == nil {
				t.Fatal("accepted invalid frame")
			}
		})
	}
	for _, f := range fixtures(t).Encoding {
		b, e := CanonicalJSON(f.Value)
		if e != nil {
			t.Fatal(e)
		}
		v, e := parseFrame(b, MaxJSONBytes)
		if e != nil {
			t.Fatal(e)
		}
		again, e := canonicalTree(v)
		if e != nil || !bytes.Equal(b, again) {
			t.Fatal("frame parity", e)
		}
	}
	if _, e := parseFrame(str, len(str)-1); e == nil {
		t.Fatal("size cap")
	}
	// All truncation points of one real stored record must reject, including
	// frames whose attacker-controlled checksum has been recomputed.
	f := fixtures(t).Records[0]
	src := destination(f.Definition)
	if e := DecodeRecord(f.Value, src); e != nil {
		t.Fatal(e)
	}
	row, e := EncodeStoredRecord(src)
	if e != nil {
		t.Fatal(e)
	}
	scope := src.(*DomainRecord).Scope
	raw := row.Columns["record_bytes"].([]byte)
	for i := 0; i < len(raw); i++ {
		bad := copyStored(row)
		bad.Columns["record_bytes"] = raw[:i]
		h := sha256.Sum256(raw[:i])
		bad.Columns["record_sha256"] = h[:]
		if DecodeStoredRecord(bad, scope, &DomainRecord{}) == nil {
			t.Fatalf("accepted truncation %d", i)
		}
	}
	// Huge container count must fail without allocation proportional to it.
	b := make([]byte, 9)
	b[0] = 'o'
	binary.BigEndian.PutUint64(b[1:], ^uint64(0))
	if _, e := parseFrame(b, 98304); e == nil {
		t.Fatal("container size")
	}
}

func TestPersistenceDictionaryAndDDLCoverage(t *testing.T) {
	raw, e := os.ReadFile("../../../contracts/system-backup/v12/producer-authority-persistence.json")
	if e != nil {
		t.Fatal(e)
	}
	var dictionary struct {
		Tables []struct {
			Name, Definition string
			Limit            int `json:"record_max_bytes"`
			Columns          map[string]string
			Primary          []string   `json:"primary_key"`
			Unique           [][]string `json:"unique_keys"`
			Indexes          [][]string
			Foreign          []struct {
				Columns    []string
				Table      string
				References []string
			} `json:"foreign_keys"`
		}
	}
	if e = json.Unmarshal(raw, &dictionary); e != nil {
		t.Fatal(e)
	}
	ddl, e := os.ReadFile("../../../contracts/system-backup/v12/producer-authority-candidate.sql")
	if e != nil {
		t.Fatal(e)
	}
	if len(dictionary.Tables) != 8 || strings.Count(string(ddl), "CREATE TABLE ") != 8 {
		t.Fatal("table count")
	}
	for _, table := range dictionary.Tables {
		s, e := storageFor(destination(table.Definition))
		if e != nil {
			t.Fatal(e)
		}
		if s.table != table.Name || s.limit != table.Limit || len(s.fields)+2 != len(table.Columns) {
			t.Fatal("dictionary drift", table.Name)
		}
		for _, field := range s.fields {
			if _, ok := table.Columns[field.name]; !ok {
				t.Fatal("projection not in dictionary", field.name)
			}
		}
		start := strings.Index(string(ddl), "CREATE TABLE "+table.Name+" (")
		if start < 0 {
			t.Fatal("missing DDL", table.Name)
		}
		block := strings.SplitN(string(ddl)[start:], ";", 2)[0]
		for column := range table.Columns {
			if !strings.Contains(block, "\n  "+column+" ") {
				t.Fatal("DDL column missing", table.Name, column)
			}
		}
		keys := append([][]string{table.Primary}, table.Unique...)
		keys = append(keys, table.Indexes...)
		for _, key := range keys {
			if !strings.Contains(block, "("+strings.Join(key, ", ")+")") {
				t.Fatal("missing index", table.Name, key)
			}
		}
		for _, fk := range table.Foreign {
			want := "FOREIGN KEY (" + strings.Join(fk.Columns, ", ") + ") REFERENCES " + fk.Table + " (" + strings.Join(fk.References, ", ") + ") ON DELETE RESTRICT ON UPDATE RESTRICT"
			if !strings.Contains(block, want) {
				t.Fatal("missing FK", table.Name)
			}
		}
		if !strings.Contains(block, "OCTET_LENGTH(record_bytes) <= "+CounterString(uint64(table.Limit))) {
			t.Fatal("missing record bound")
		}
	}
}
