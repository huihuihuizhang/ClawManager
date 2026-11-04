package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Fixed diagnostic ceilings are separate from live ImportBackupCopy budgets.
// They do not omit/truncate a table, sample rows, hash server-side coercions,
// change NULL framing, deduplicate hashes or accept an interrupted iterator.
const (
	legacy177MaxRows     int64 = 32_000_000
	legacy177MaxBytes    int64 = 64 << 30
	legacy177MaxRowBytes int64 = 64 << 20
	legacy177MaxScratch  int64 = 3 << 30
)

// Safe metadata only: every Table originates in the pinned reviewed99 schema.
// Error() contains no SQL text, DSN, column values, paths or row hashes.
type Legacy177RowProofBudgetError struct {
	Table           string `json:"table"`
	Limit           string `json:"limit"`
	Rows            int64  `json:"processed_rows"`
	Bytes           int64  `json:"processed_bytes"`
	ExpectedRows    int64  `json:"snapshot_rows"`
	LargestRowBytes int64  `json:"largest_sql_row_bytes"`
	MaxRows         int64  `json:"max_rows"`
	MaxBytes        int64  `json:"max_bytes"`
	MaxRowBytes     int64  `json:"max_row_bytes"`
	MaxScratch      int64  `json:"max_scratch_bytes"`
}

func (e *Legacy177RowProofBudgetError) Error() string {
	return "legacy177 isolated row proof resource budget exceeded"
}

func proveLegacy177TableRows(ctx context.Context, conn importQueryer, table importTable, target string, m backupImportMap) (proof importTableProof, resultErr error) {
	proof.Table = table
	name, e := importIdentifier(target)
	if e != nil {
		return proof, e
	}
	if len(table.Columns) == 0 {
		return proof, errors.New("legacy177 original columns absent")
	}
	columns := []string{}
	lengths := []string{}
	for _, column := range table.Columns {
		q, e := importIdentifier(column)
		if e != nil {
			return proof, e
		}
		columns = append(columns, q)
		lengths = append(lengths, "COALESCE(OCTET_LENGTH("+q+"),0)")
	}
	where := ""
	var args []any
	if table.Name == "schema_migrations" {
		names := []string{}
		for file := range m.Migrations {
			names = append(names, file)
		}
		sort.Strings(names)
		if len(names) == 0 {
			return proof, errors.New("legacy177 original ledger set absent")
		}
		for _, file := range names {
			args = append(args, file)
		}
		where = " WHERE filename IN (" + strings.TrimSuffix(strings.Repeat("?,", len(args)), ",") + ")"
	}
	budget := &Legacy177RowProofBudgetError{Table: table.Name, MaxRows: legacy177MaxRows, MaxBytes: legacy177MaxBytes, MaxRowBytes: legacy177MaxRowBytes, MaxScratch: legacy177MaxScratch}
	// Read only lengths/count under the SAME RR snapshot before transmitting a
	// potentially huge row. Date/time driver formatting can add per-column
	// bytes, so reserve 64 bytes/column; allow worst-case 4x character-set
	// conversion in the driver transport before the 64MiB client row ceiling.
	q := "SELECT COUNT(*),COALESCE(MAX(" + strings.Join(lengths, "+") + "),0) FROM " + name + where
	if e = conn.QueryRowContext(ctx, q, args...).Scan(&budget.ExpectedRows, &budget.LargestRowBytes); e != nil {
		return proof, e
	}
	if budget.ExpectedRows > legacy177MaxRows {
		budget.Limit = "rows"
		return proof, budget
	}
	if budget.LargestRowBytes > (legacy177MaxRowBytes-int64(len(columns))*64)/4 {
		budget.Limit = "largest_row_bytes"
		return proof, budget
	}
	sorter, e := newLegacy177HashSort(ctx, 65536, 32, legacy177MaxScratch)
	if e != nil {
		return proof, e
	}
	defer func() {
		if e := sorter.Close(); e != nil {
			if resultErr == nil {
				resultErr = errors.New("legacy177 row hash scratch cleanup failed")
			}
		}
	}()
	rows, e := conn.QueryContext(ctx, "SELECT "+strings.Join(columns, ",")+" FROM "+name+where, args...)
	if e != nil {
		return proof, e
	}
	defer rows.Close()
	values := make([]sql.RawBytes, len(columns))
	dest := make([]any, len(columns))
	for n := range values {
		dest[n] = &values[n]
	}
	for rows.Next() {
		if e = ctx.Err(); e != nil {
			return proof, e
		}
		if e = rows.Scan(dest...); e != nil {
			return proof, e
		}
		h := sha256.New()
		var rowBytes int64
		for _, value := range values {
			if value == nil {
				_, _ = h.Write([]byte{0})
				continue
			}
			_, _ = h.Write([]byte{1})
			var frame [8]byte
			binary.BigEndian.PutUint64(frame[:], uint64(len(value)))
			_, _ = h.Write(frame[:])
			_, _ = h.Write(value)
			rowBytes += int64(len(value))
		}
		proof.Rows++
		budget.Rows = proof.Rows
		budget.Bytes += rowBytes
		if proof.Rows > legacy177MaxRows {
			budget.Limit = "rows"
			return proof, budget
		}
		if rowBytes > legacy177MaxRowBytes {
			budget.Limit = "row_bytes"
			return proof, budget
		}
		if budget.Bytes > legacy177MaxBytes {
			budget.Limit = "total_bytes"
			return proof, budget
		}
		var hash [32]byte
		copy(hash[:], h.Sum(nil))
		if e = sorter.add(hash); e != nil {
			if errors.Is(e, errLegacy177Scratch) {
				budget.Limit = "hash_scratch_bytes"
				return proof, budget
			}
			return proof, e
		}
	}
	if e = rows.Err(); e != nil {
		return proof, e
	}
	if e = rows.Close(); e != nil {
		return proof, e
	}
	if proof.Rows != budget.ExpectedRows {
		return proof, fmt.Errorf("legacy177 original table count differs: %s", table.Name)
	}
	proof.SHA256, e = sorter.digest(proof.Rows)
	if errors.Is(e, errLegacy177Scratch) {
		budget.Limit = "hash_scratch_bytes"
		return proof, budget
	}
	return proof, e
}
