package systembackupresources

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
)

// readRestoreFieldRows is a private transaction-scoped reader candidate. It
// neither opens nor ends the caller's transaction and returns unqualified data.
// B must first authenticate this exact target/session/schema, isolation and
// SELECT-only identity; the owner must confirm transaction completion before
// using any comparison result. No production caller is wired to this helper.
func readRestoreFieldRows(ctx context.Context, tx *sql.Tx, budget restoreFieldBudget) ([]restoreFieldTable, error) {
	return readRestoreFieldRowsMode(ctx, tx, budget, false)
}

// Writable normalization must compare the current locked rows, even if B's
// common RR transaction has already established an older consistent snapshot.
func readRestoreFieldRowsMode(ctx context.Context, tx *sql.Tx, budget restoreFieldBudget, lock bool) ([]restoreFieldTable, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tx == nil || budget.Rows <= 0 || budget.Rows == math.MaxInt64 || budget.Bytes <= 0 {
		return nil, errors.New("resources field reader requires transaction and bounded capacity")
	}
	var zone string
	if err := tx.QueryRowContext(ctx, "SELECT @@session.time_zone").Scan(&zone); err != nil || zone != "+00:00" {
		return nil, errors.New("resources field reader requires explicit UTC session")
	}
	definitions := restoreFieldColumns()
	tables := make([]string, 0, len(definitions))
	for table := range definitions {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	remaining := budget
	result := make([]restoreFieldTable, 0, len(tables))
	for _, table := range tables {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		columns := definitions[table]
		if err := inspectRestoreFieldTable(ctx, tx, table, columns); err != nil {
			return nil, err
		}
		projection := make([]string, len(columns))
		for i, column := range columns {
			// Only compile-time closed identifiers enter SQL. SQL text conversion
			// avoids driver parseTime/float coercion, preserving DECIMAL scale and
			// the session's UTC fractional timestamp representation.
			projection[i] = "CAST(`" + column + "` AS CHAR CHARACTER SET utf8mb4) AS `" + column + "`"
		}
		query := "SELECT " + strings.Join(projection, ", ") + " FROM `" + table + "` ORDER BY `id` LIMIT " + strconv.FormatInt(remaining.Rows+1, 10)
		if lock {
			query += " FOR UPDATE"
		}
		rows, err := tx.QueryContext(ctx, query)
		if err != nil {
			return nil, errors.New("resources field read failed")
		}
		values, err := scanRestoreFieldRows(ctx, rows, columns, &remaining)
		if err != nil {
			return nil, err
		}
		result = append(result, restoreFieldTable{Name: table, Columns: append([]string(nil), columns...), Rows: values})
	}
	// Validate IDs, duplicates and the complete shape even without comparison.
	if _, err := indexRestoreFields(ctx, result, budget); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func inspectRestoreFieldTable(ctx context.Context, tx *sql.Tx, table string, columns []string) error {
	var engine string
	if err := tx.QueryRowContext(ctx, `SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND TABLE_TYPE = 'BASE TABLE'`, table).Scan(&engine); err != nil || !strings.EqualFold(engine, "InnoDB") {
		return errors.New("resources field table must be transactional InnoDB")
	}
	query := `SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? ORDER BY ORDINAL_POSITION LIMIT ` + strconv.Itoa(len(columns)+1)
	rows, err := tx.QueryContext(ctx, query, table)
	if err != nil {
		return errors.New("resources field schema read failed")
	}
	defer rows.Close()
	seen := make(map[string]bool, len(columns))
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return err
		}
		var name string
		if err := rows.Scan(&name); err != nil || seen[name] || len(seen) >= len(columns) {
			return errors.New("resources field schema differs")
		}
		seen[name] = true
	}
	if rows.Err() != nil {
		return errors.New("resources field schema iteration failed")
	}
	if rows.Close() != nil {
		return errors.New("resources field schema close failed")
	}
	if len(seen) != len(columns) {
		return errors.New("resources field schema differs")
	}
	for _, name := range columns {
		if !seen[name] {
			return errors.New("resources field schema differs")
		}
	}
	return ctx.Err()
}

// Driver buffers may already contain a large cell. This limits retained value
// bytes before copying; it is not a provider packet/memory-capacity proof.
type restoreSQLText struct {
	value     *string
	remaining *int64
}

func (cell *restoreSQLText) Scan(value any) error {
	cell.value = nil
	if value == nil {
		return nil
	}
	var size int
	switch text := value.(type) {
	case string:
		size = len(text)
	case []byte:
		size = len(text)
	default:
		return errors.New("resources field projection must return SQL text")
	}
	if int64(size) > *cell.remaining {
		return errors.New("resources field byte budget exceeded")
	}
	*cell.remaining -= int64(size)
	var text string
	switch value := value.(type) {
	case string:
		text = value
	case []byte:
		text = string(value)
	}
	cell.value = &text
	return nil
}

func scanRestoreFieldRows(ctx context.Context, rows *sql.Rows, columns []string, budget *restoreFieldBudget) ([]restoreFieldRow, error) {
	defer rows.Close()
	actual, err := rows.Columns()
	if err != nil || len(actual) != len(columns) {
		return nil, errors.New("resources field projection differs")
	}
	for i := range columns {
		if actual[i] != columns[i] {
			return nil, errors.New("resources field projection differs")
		}
	}
	var result []restoreFieldRow
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if budget.Rows == 0 {
			return nil, errors.New("resources field row budget exceeded")
		}
		budget.Rows--
		cells := make([]restoreSQLText, len(columns))
		dest := make([]any, len(columns))
		for i := range cells {
			cells[i].remaining = &budget.Bytes
			dest[i] = &cells[i]
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, errors.New("resources field scan failed")
		}
		row := make(restoreFieldRow, len(columns))
		for i, column := range columns {
			row[column] = cells[i].value
		}
		result = append(result, row)
	}
	if rows.Err() != nil {
		return nil, errors.New("resources field iteration failed")
	}
	if rows.Close() != nil {
		return nil, errors.New("resources field close failed")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
