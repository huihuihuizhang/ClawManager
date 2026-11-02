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
	return catalogGuarded(ctx, q, nil)
}

type sourceGuardedQuery struct {
	queryer
	check func() error
}

func (q sourceGuardedQuery) QueryContext(ctx context.Context, statement string, args ...any) (*sql.Rows, error) {
	if sourceReadGuard(ctx, q.check) != nil {
		return nil, ErrIsolation
	}
	finish := BeginCaptureTiming(ctx, CaptureSQLQuery)
	rows, err := q.queryer.QueryContext(ctx, statement, args...)
	finish.Finish(err)
	if err != nil {
		return nil, err
	}
	if sourceReadGuard(ctx, q.check) != nil {
		rows.Close()
		return nil, ErrIsolation
	}
	return rows, nil
}
func sourceReadGuard(ctx context.Context, check func() error) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrIsolation
	}
	if check != nil {
		finish := BeginCaptureTiming(ctx, CaptureGuard)
		err := check()
		finish.Finish(err)
		if err != nil {
			return ErrIsolation
		}
	}
	return nil
}
func sourceRowsNext(ctx context.Context, rows *sql.Rows, check func() error) (bool, error) {
	if sourceReadGuard(ctx, check) != nil {
		rows.Close()
		return false, ErrIsolation
	}
	finish := BeginCaptureTiming(ctx, CaptureSQLNext)
	next := rows.Next()
	finish.Finish(rows.Err())
	if sourceReadGuard(ctx, check) != nil {
		rows.Close()
		return false, ErrIsolation
	}
	return next, nil
}
func catalogGuarded(ctx context.Context, original queryer, check func() error) ([]Table, error) {
	q := sourceGuardedQuery{original, check}
	rows, err := q.QueryContext(ctx, `SELECT TABLE_NAME, COALESCE(ENGINE, '') FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE' ORDER BY TABLE_NAME`)
	if err != nil {
		return nil, ErrDatabase
	}
	var tables []Table
	for {
		next, guardErr := sourceRowsNext(ctx, rows, check)
		if guardErr != nil {
			return nil, guardErr
		}
		if !next {
			break
		}
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
		for {
			next, guardErr := sourceRowsNext(ctx, rows, check)
			if guardErr != nil {
				return nil, guardErr
			}
			if !next {
				break
			}
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
		for {
			next, guardErr := sourceRowsNext(ctx, rows, check)
			if guardErr != nil {
				return nil, guardErr
			}
			if !next {
				break
			}
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
		if requiresUniqueCatalog(t.Name) {
			rows, err = q.QueryContext(ctx, `SELECT INDEX_NAME, COLUMN_NAME, SEQ_IN_INDEX, SUB_PART FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND NON_UNIQUE = 0 AND INDEX_NAME <> 'PRIMARY' ORDER BY INDEX_NAME, SEQ_IN_INDEX`, t.Name)
			if err != nil {
				return nil, ErrDatabase
			}
			for {
				next, guardErr := sourceRowsNext(ctx, rows, check)
				if guardErr != nil {
					return nil, guardErr
				}
				if !next {
					break
				}
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
	return captureSourceGuarded(ctx, db, limits, database, serverUUID, nil)
}

// The same admitted session and RR snapshot retain source-owner checks at all
// catalog queries, table reads, row advances/EOF and final commit boundaries.
func CaptureSourceGuarded(ctx context.Context, db *sql.DB, limits Limits, database, serverUUID string, authorize func(context.Context) error) (Snapshot, error) {
	if authorize == nil {
		return Snapshot{}, ErrIsolation
	}
	return captureSourceGuarded(ctx, db, limits, database, serverUUID, func() error { return authorize(ctx) })
}
func captureSourceGuarded(ctx context.Context, db *sql.DB, limits Limits, database, serverUUID string, authorize func() error) (Snapshot, error) {
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
	}, authorize)
}

func capture(ctx context.Context, db *sql.DB, limits Limits, check func(*sql.Conn) error, sourceChecks ...func() error) (Snapshot, error) {
	return captureWithCatalog(ctx, db, limits, check, catalogGuarded, sourceChecks...)
}

func captureWithCatalog(ctx context.Context, db *sql.DB, limits Limits, check func(*sql.Conn) error, readCatalog func(context.Context, queryer, func() error) ([]Table, error), sourceChecks ...func() error) (Snapshot, error) {
	return captureWithCatalogMode(ctx, db, limits, check, readCatalog, false, sourceChecks...)
}

func captureWithCatalogMode(ctx context.Context, db *sql.DB, limits Limits, check func(*sql.Conn) error, readCatalog func(context.Context, queryer, func() error) ([]Table, error), countEmpty bool, sourceChecks ...func() error) (Snapshot, error) {
	var authorize func() error
	if len(sourceChecks) > 1 {
		return Snapshot{}, ErrIsolation
	}
	if len(sourceChecks) == 1 {
		authorize = sourceChecks[0]
	}
	if sourceReadGuard(ctx, authorize) != nil {
		return Snapshot{}, ErrIsolation
	}
	if db == nil || !limits.valid() {
		return Snapshot{}, ErrData
	}
	finishConnection := BeginCaptureTiming(ctx, CaptureConnection)
	conn, err := db.Conn(ctx)
	finishConnection.Finish(err)
	if err != nil {
		return Snapshot{}, ErrDatabase
	}
	defer conn.Close()
	if check != nil {
		finish := BeginCaptureTiming(ctx, CaptureSessionBefore)
		err = check(conn)
		finish.Finish(err)
		if err != nil {
			return Snapshot{}, err
		}
	}
	if sourceReadGuard(ctx, authorize) != nil {
		return Snapshot{}, ErrIsolation
	}
	finishBegin := BeginCaptureTiming(ctx, CaptureBeginRR)
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	finishBegin.Finish(err)
	if err != nil {
		return Snapshot{}, ErrDatabase
	}
	defer tx.Rollback()
	finishCatalog := BeginCaptureTiming(ctx, CaptureCatalogInitial)
	tables, err := readCatalog(ctx, tx, authorize)
	finishCatalog.Finish(err)
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
	var counts map[string]uint64
	if countEmpty {
		var counted []Table
		for _, t := range tables {
			if _, ok := selected[t.Name]; ok {
				counted = append(counted, t)
			} else if !external[t.Name] && (strings.HasPrefix(t.Name, "user_") || strings.HasPrefix(t.Name, "enterprise_auth_") || strings.HasPrefix(t.Name, "instance_") || strings.HasPrefix(t.Name, "runtime_") || strings.HasPrefix(t.Name, "openclaw_") || strings.HasPrefix(t.Name, "workbuddy_") || strings.HasPrefix(t.Name, "team_") || strings.HasPrefix(t.Name, "skill_") || strings.HasPrefix(t.Name, "chat_")) {
				return Snapshot{}, ErrSchema
			}
		}
		finishCounts := BeginCaptureTiming(ctx, CaptureExactCounts)
		counts, err = captureSourceRowCounts(ctx, tx, counted, authorize)
		finishCounts.Finish(err)
		if err != nil {
			return Snapshot{}, err
		}
		// COUNT has acquired transaction-duration MDL on every selected table.
		// Refuse DDL between the original catalog and COUNT, including empty
		// tables whose data SELECT will be omitted. Never adopt a new shape.
		finishLocked := BeginCaptureTiming(ctx, CaptureCatalogLocked)
		locked, e := readCatalog(ctx, tx, authorize)
		finishLocked.Finish(e)
		if e != nil {
			return Snapshot{}, e
		}
		if !sameSourceCatalog(tables, locked) {
			return Snapshot{}, ErrSchema
		}
	}
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
		if countEmpty {
			n, ok := counts[t.Name]
			if !ok {
				return Snapshot{}, ErrSchema
			}
			if n == 0 {
				result.Tables = append(result.Tables, t)
				continue
			}
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
		rows, err := (sourceGuardedQuery{tx, authorize}).QueryContext(ctx, "SELECT "+strings.Join(cols, ",")+" FROM "+name+" ORDER BY "+strings.Join(pk, ","))
		if err != nil {
			return Snapshot{}, ErrDatabase
		}
		// Reuse only scan slots within this table. rawCell still owns every
		// returned byte slice; rows and authorization boundaries are unchanged.
		scan := newCaptureScanSlots(len(cols))
		for {
			next, guardErr := sourceRowsNext(ctx, rows, authorize)
			if guardErr != nil {
				return Snapshot{}, guardErr
			}
			if !next {
				break
			}
			values, scanErr := scan.scan(ctx, rows)
			if scanErr != nil {
				rows.Close()
				return Snapshot{}, ErrDatabase
			}
			r := make(Row, len(cols))
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
			clear(values) // release driver-owned intermediate references per row
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
		if countEmpty && uint64(len(t.Rows)) != counts[t.Name] {
			return Snapshot{}, ErrIsolation
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
	if sourceReadGuard(ctx, authorize) != nil {
		return Snapshot{}, ErrIsolation
	}
	finishCommit := BeginCaptureTiming(ctx, CaptureCommitRR)
	err = tx.Commit()
	finishCommit.Finish(err)
	if err != nil {
		return Snapshot{}, ErrDatabase
	}
	// Recheck the original session after the complete RR, before returning any
	// source bytes to the encrypting collector. A mid-capture grant/identity
	// change cannot be certified by an earlier admission observation.
	if check != nil {
		finish := BeginCaptureTiming(ctx, CaptureSessionAfter)
		err = check(conn)
		finish.Finish(err)
		if err != nil {
			return Snapshot{}, ErrIsolation
		}
	}
	if sourceReadGuard(ctx, authorize) != nil {
		return Snapshot{}, ErrIsolation
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
