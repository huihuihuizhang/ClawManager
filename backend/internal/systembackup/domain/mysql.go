package domain

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"clawreef/internal/systembackup/scope"
)

type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

// Catalog reads metadata only. The supplied connection must already select the
// desired database; unlike the application startup path it never runs migrations.
func Catalog(ctx context.Context, q queryer) ([]Table, error) {
	rows, err := q.QueryContext(ctx, `SELECT TABLE_NAME, COALESCE(ENGINE, '') FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE' ORDER BY TABLE_NAME`)
	if err != nil {
		return nil, ErrDatabase
	}
	var tables []Table
	for rows.Next() {
		var t Table
		if rows.Scan(&t.Name, &t.Engine) != nil {
			rows.Close()
			return nil, ErrDatabase
		}
		if !identifier.MatchString(t.Name) {
			rows.Close()
			return nil, ErrSchema
		}
		tables = append(tables, t)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, ErrDatabase
	}
	for i := range tables {
		t := &tables[i]
		rows, err = q.QueryContext(ctx, `SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_DEFAULT, EXTRA FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? ORDER BY ORDINAL_POSITION`, t.Name)
		if err != nil {
			return nil, ErrDatabase
		}
		for rows.Next() {
			var c Column
			var nullable string
			var def sql.NullString
			if rows.Scan(&c.Name, &c.Type, &nullable, &def, &c.Extra) != nil {
				rows.Close()
				return nil, ErrDatabase
			}
			if !identifier.MatchString(c.Name) {
				rows.Close()
				return nil, ErrSchema
			}
			c.Nullable = nullable == "YES"
			if def.Valid {
				s := def.String
				c.Default = &s
			}
			t.Columns = append(t.Columns, c)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, ErrDatabase
		}
		rows, err = q.QueryContext(ctx, `SELECT COLUMN_NAME, CONSTRAINT_NAME, REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND (CONSTRAINT_NAME = 'PRIMARY' OR REFERENCED_TABLE_NAME IS NOT NULL) ORDER BY CONSTRAINT_NAME, ORDINAL_POSITION`, t.Name)
		if err != nil {
			return nil, ErrDatabase
		}
		for rows.Next() {
			var col, key string
			var refTable, refCol sql.NullString
			if rows.Scan(&col, &key, &refTable, &refCol) != nil {
				rows.Close()
				return nil, ErrDatabase
			}
			if key == "PRIMARY" {
				t.PrimaryKey = append(t.PrimaryKey, col)
			} else {
				t.ForeignKeys = append(t.ForeignKeys, ForeignKey{col, refTable.String, refCol.String})
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, ErrDatabase
		}
		if t.Name == "workbuddy_linux_identities" || t.Name == "workbuddy_linux_identity_allocator" {
			rows, err = q.QueryContext(ctx, `SELECT INDEX_NAME, COLUMN_NAME, SEQ_IN_INDEX, SUB_PART FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND NON_UNIQUE = 0 AND INDEX_NAME <> 'PRIMARY' ORDER BY INDEX_NAME, SEQ_IN_INDEX`, t.Name)
			if err != nil {
				return nil, ErrDatabase
			}
			for rows.Next() {
				var name string
				var column sql.NullString
				var sequence int
				var prefix sql.NullInt64
				if rows.Scan(&name, &column, &sequence, &prefix) != nil || !identifier.MatchString(name) || !column.Valid || !identifier.MatchString(column.String) || prefix.Valid {
					rows.Close()
					return nil, ErrSchema
				}
				if len(t.UniqueKeys) == 0 || t.UniqueKeys[len(t.UniqueKeys)-1].Name != name {
					t.UniqueKeys = append(t.UniqueKeys, UniqueKey{Name: name})
				}
				key := &t.UniqueKeys[len(t.UniqueKeys)-1]
				if sequence != len(key.Columns)+1 {
					rows.Close()
					return nil, ErrSchema
				}
				key.Columns = append(key.Columns, column.String)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return nil, ErrDatabase
			}
		}
	}
	return tables, nil
}

// Capture uses one repeatable-read, read-only transaction for every domain
// table. The shared coordinator holds the writer/DDL gate while this bounded
// capture runs. Readers receive raw cells, including password_hash, not API DTOs.
// Limits apply to the entire capture. Large installations should use the common
// streaming MySQL collector instead of raising these limits without a memory budget.
func Capture(ctx context.Context, db *sql.DB, limits Limits) (Snapshot, error) {
	return capture(ctx, db, limits, nil)
}

// CaptureSource pins the observed database identity and SELECT-only grants on
// the SAME session used by the capture transaction. A worker cannot silently
// switch to another database after preflight or use application write credentials.
func CaptureSource(ctx context.Context, db *sql.DB, limits Limits, database, serverUUID string) (Snapshot, error) {
	if !identifier.MatchString(database) || serverUUID == "" {
		return Snapshot{}, ErrIsolation
	}
	return capture(ctx, db, limits, func(conn *sql.Conn) error {
		var actualDB, actualUUID string
		if conn.QueryRowContext(ctx, "SELECT DATABASE(), @@server_uuid").Scan(&actualDB, &actualUUID) != nil {
			return ErrDatabase
		}
		if actualDB != database || actualUUID != serverUUID {
			return ErrIsolation
		}
		return checkSelectOnly(ctx, conn, database)
	})
}

func capture(ctx context.Context, db *sql.DB, limits Limits, check func(*sql.Conn) error) (Snapshot, error) {
	if db == nil || !limits.valid() {
		return Snapshot{}, ErrData
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return Snapshot{}, ErrDatabase
	}
	defer conn.Close()
	if check != nil {
		if err = check(conn); err != nil {
			return Snapshot{}, err
		}
	}
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return Snapshot{}, ErrDatabase
	}
	defer tx.Rollback()
	tables, err := Catalog(ctx, tx)
	if err != nil {
		return Snapshot{}, err
	}
	selected := rules()
	external := map[string]bool{}
	for _, d := range scope.CrossDomainDependencies() {
		for _, n := range d.Tables {
			external[n] = true
		}
	}
	result := Snapshot{Version: Version}
	var byteCount, rowCount int64
	for _, t := range tables {
		if _, ok := selected[t.Name]; !ok {
			if !external[t.Name] && (strings.HasPrefix(t.Name, "user_") || strings.HasPrefix(t.Name, "enterprise_auth_") || strings.HasPrefix(t.Name, "instance_") || strings.HasPrefix(t.Name, "runtime_") || strings.HasPrefix(t.Name, "openclaw_") || strings.HasPrefix(t.Name, "workbuddy_") || strings.HasPrefix(t.Name, "team_") || strings.HasPrefix(t.Name, "skill_") || strings.HasPrefix(t.Name, "chat_")) {
				return Snapshot{}, ErrSchema
			}
			continue
		}
		if t.Engine != "InnoDB" || len(t.PrimaryKey) == 0 || len(t.Columns) == 0 {
			return Snapshot{}, ErrSchema
		}
		var cols, pk []string
		for _, c := range t.Columns {
			name, _ := quoted(c.Name)
			cols = append(cols, name)
		}
		for _, c := range t.PrimaryKey {
			name, e := quoted(c)
			if e != nil {
				return Snapshot{}, e
			}
			pk = append(pk, name)
		}
		name, _ := quoted(t.Name)
		rows, err := tx.QueryContext(ctx, "SELECT "+strings.Join(cols, ",")+" FROM "+name+" ORDER BY "+strings.Join(pk, ","))
		if err != nil {
			return Snapshot{}, ErrDatabase
		}
		for rows.Next() {
			values := make([]any, len(cols))
			pointers := make([]any, len(cols))
			for i := range values {
				pointers[i] = &values[i]
			}
			if rows.Scan(pointers...) != nil {
				rows.Close()
				return Snapshot{}, ErrDatabase
			}
			r := Row{}
			for i, v := range values {
				cell, e := rawCell(v)
				if e != nil {
					rows.Close()
					return Snapshot{}, e
				}
				// Include map/cell overhead in the bounded memory estimate.
				byteCount += int64(len(cell.Bytes) + len(t.Columns[i].Name) + 128)
				if byteCount > limits.MaxBytes {
					rows.Close()
					return Snapshot{}, ErrCapacity
				}
				r[t.Columns[i].Name] = cell
			}
			rowCount++
			if rowCount > limits.MaxRows {
				rows.Close()
				return Snapshot{}, ErrCapacity
			}
			t.Rows = append(t.Rows, r)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return Snapshot{}, ErrDatabase
		}
		result.Tables = append(result.Tables, t)
	}
	for _, required := range []string{"users", "user_quotas", "instances"} {
		found := false
		for _, t := range result.Tables {
			if t.Name == required {
				found = true
			}
		}
		if !found {
			return Snapshot{}, ErrSchema
		}
	}
	if err = tx.Commit(); err != nil {
		return Snapshot{}, ErrDatabase
	}
	return result, nil
}

func rawCell(v any) (Cell, error) {
	switch v := v.(type) {
	case nil:
		return Cell{Null: true}, nil
	case []byte:
		return Cell{Bytes: append([]byte(nil), v...)}, nil
	case string:
		return Text(v), nil
	case int64:
		return Text(fmt.Sprint(v)), nil
	case uint64:
		return Text(fmt.Sprint(v)), nil
	case float64:
		return Text(fmt.Sprint(v)), nil
	case bool:
		if v {
			return Text("1"), nil
		}
		return Text("0"), nil
	case time.Time:
		// Require parseTime=false on a capture connection. Otherwise zero dates
		// and source timezone representations may already have been lost.
		return Cell{}, ErrSchema
	default:
		return Cell{}, ErrSchema
	}
}
