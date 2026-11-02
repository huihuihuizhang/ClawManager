package domain

import (
	"context"
	"reflect"
	"strconv"
	"strings"
)

const sourceRowCountBatch = 64
const sourceRowCountMaxSQL = 16 << 10

// Exact counts use the original readonly RR, never statistics or another
// session. One bounded SQL result row retains every query/Next/EOF guard.
func captureSourceRowCounts(ctx context.Context, q queryer, tables []Table, check func() error) (map[string]uint64, error) {
	if len(tables) == 0 || len(tables) > 1000 {
		return nil, ErrSchema
	}
	selected, seen := rules(), map[string]bool{}
	for _, t := range tables {
		if _, ok := selected[t.Name]; !ok || seen[t.Name] || !identifier.MatchString(t.Name) || t.Engine != "InnoDB" || len(t.Columns) == 0 || len(t.PrimaryKey) == 0 || len(t.Rows) != 0 {
			return nil, ErrSchema
		}
		seen[t.Name] = true
		columns := map[string]bool{}
		for _, c := range t.Columns {
			if !identifier.MatchString(c.Name) || columns[c.Name] {
				return nil, ErrSchema
			}
			columns[c.Name] = true
		}
		keys := map[string]bool{}
		for _, name := range t.PrimaryKey {
			if !columns[name] || keys[name] {
				return nil, ErrSchema
			}
			keys[name] = true
		}
	}
	counts := make(map[string]uint64, len(tables))
	for start := 0; start < len(tables); start += sourceRowCountBatch {
		end := min(start+sourceRowCountBatch, len(tables))
		var terms, columns []string
		for i, t := range tables[start:end] {
			name, err := quoted(t.Name)
			if err != nil {
				return nil, err
			}
			alias := "c" + strconv.Itoa(i)
			terms = append(terms, "(SELECT COUNT(*) FROM "+name+") AS "+alias)
			columns = append(columns, alias)
		}
		statement := "SELECT " + strings.Join(terms, ",")
		if len(statement) > sourceRowCountMaxSQL {
			return nil, ErrCapacity
		}
		values, err := readSourceRowCounts(ctx, q, statement, columns, check)
		if err != nil {
			return nil, err
		}
		for i, n := range values {
			counts[tables[start+i].Name] = n
		}
	}
	return counts, nil
}

func readSourceRowCounts(ctx context.Context, q queryer, statement string, columns []string, check func() error) ([]uint64, error) {
	rows, err := (sourceGuardedQuery{q, check}).QueryContext(ctx, statement)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	actual, err := rows.Columns()
	if err != nil || !reflect.DeepEqual(actual, columns) {
		return nil, ErrSchema
	}
	next, err := sourceRowsNext(ctx, rows, check)
	if err != nil {
		return nil, err
	}
	if !next {
		return nil, ErrDatabase
	}
	// Raw decimal bytes reject NULL/negative/fractional/overflow without a
	// floating point conversion. MySQL COUNT returns an unsigned decimal.
	raw, pointers := make([][]byte, len(columns)), make([]any, len(columns))
	for i := range raw {
		pointers[i] = &raw[i]
	}
	if rows.Scan(pointers...) != nil {
		return nil, ErrDatabase
	}
	values := make([]uint64, len(raw))
	for i, v := range raw {
		if len(v) == 0 || len(v) > 20 {
			return nil, ErrData
		}
		for _, b := range v {
			if b < '0' || b > '9' {
				return nil, ErrData
			}
		}
		n, e := strconv.ParseUint(string(v), 10, 64)
		if e != nil {
			return nil, ErrData
		}
		values[i] = n
	}
	next, err = sourceRowsNext(ctx, rows, check)
	if err != nil {
		return nil, err
	}
	if next || rows.Err() != nil {
		return nil, ErrDatabase
	}
	return values, nil
}

func sameSourceCatalog(original, locked []Table) bool {
	return reflect.DeepEqual(original, locked)
}
