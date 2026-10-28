package systembackupskillhub

import (
	"context"
	"database/sql"
	"reflect"
	"sort"
	"strings"
)

// ReadOnlyQueries exposes queries without Exec or commit methods. It does not
// constrain SQL text; SELECT-only credentials must enforce database permissions.
// This interface and TxOptions alone do not prove a read-only principal.
type ReadOnlyQueries interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// TargetReadAuthority must authenticate the complete source/mapping/limits,
// target identity, completed normalization, frozen deployment registry/schema,
// startup isolation and an independently credentialed SELECT-only principal
// on this exact transaction. It must not accept flags or hash syntax as proof.
// Recheck must verify the same bound target and current authority before commit.
type TargetReadAuthority interface {
	VerifyTargetRead(context.Context, ReadOnlyQueries, RestoreRequest) error
	RecheckTargetRead(context.Context, ReadOnlyQueries, RestoreRequest) error
}
type SQLRestoreVerifier struct {
	DB        *sql.DB
	Authority TargetReadAuthority
}

// Verify compares a real SQL snapshot, never a caller-supplied target Rows.
// It returns nil only after complete row comparison and final authority/commit.
// This local result excludes object/workspace checks and is NOT a v12 public
// verifier or eligibility result; D's reviewed check registry is still required.
func (v SQLRestoreVerifier) Verify(ctx context.Context, request RestoreRequest) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if v.DB == nil || nilObjectAdapter(v.Authority) {
		return ErrRestoreAuthority
	}
	frozen, err := freezeRestoreRequest(ctx, request)
	if err != nil {
		return err
	}
	tx, err := v.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return restoreFailure(ctx, ErrTargetRead)
	}
	defer tx.Rollback()
	queries := readOnlyTransaction{tx: tx}
	if err := v.Authority.VerifyTargetRead(ctx, queries, cloneRestoreRequest(frozen)); err != nil {
		return restoreFailure(ctx, ErrRestoreAuthority)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	actual, err := readRestoreRows(ctx, tx, frozen)
	if err != nil {
		return err
	}
	if err := CompareRestoredRows(ctx, frozen.Source, frozen.Mapping, actual); err != nil {
		return err
	}
	if err := checkExternalRestoreReferences(ctx, tx, actual); err != nil {
		return err
	}
	if err := v.Authority.RecheckTargetRead(ctx, queries, cloneRestoreRequest(frozen)); err != nil {
		return restoreFailure(ctx, ErrRestoreAuthority)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return restoreFailure(ctx, ErrTargetRead)
	}
	return ctx.Err()
}

// Hide the underlying *sql.Tx from capability consumers.
type readOnlyTransaction struct{ tx *sql.Tx }

func (q readOnlyTransaction) QueryContext(ctx context.Context, s string, args ...any) (*sql.Rows, error) {
	return q.tx.QueryContext(ctx, s, args...)
}
func (q readOnlyTransaction) QueryRowContext(ctx context.Context, s string, args ...any) *sql.Row {
	return q.tx.QueryRowContext(ctx, s, args...)
}

type sqlTableLayout struct {
	columns           []string
	payloadExpression string
}

func sqlLayout(t tableView) sqlTableLayout {
	model := t.rows.Type().Elem()
	layout := sqlTableLayout{}
	lengths := []string{}
	for i := 0; i < model.NumField(); i++ {
		f := model.Field(i)
		column := "`" + dbColumn(f.Tag.Get("db")) + "`"
		layout.columns = append(layout.columns, column)
		typ := f.Type
		if typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		if typ.Kind() == reflect.String {
			lengths = append(lengths, "COALESCE(OCTET_LENGTH("+column+"),0)")
		}
	}
	layout.payloadExpression = "0"
	if len(lengths) > 0 {
		layout.payloadExpression = strings.Join(lengths, "+")
	}
	return layout
}
func readRestoreRows(ctx context.Context, tx *sql.Tx, request RestoreRequest) (Rows, error) {
	var empty Rows
	views := tables(request.Source)
	// Preflight payload sizes IN the same repeatable-read snapshot, before any
	// long manifest/findings string is brought into Go memory.
	var totalRows, totalBytes int64
	for _, t := range views {
		var engine string
		if err := tx.QueryRowContext(ctx, "SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND TABLE_TYPE='BASE TABLE'", t.name).Scan(&engine); err != nil {
			return empty, restoreFailure(ctx, ErrTargetRead)
		}
		if !strings.EqualFold(engine, "InnoDB") {
			return empty, ErrTargetRead
		}
		layout := sqlLayout(t)
		query := "SELECT COUNT(*),COALESCE(SUM(" + layout.payloadExpression + "),0) FROM `" + t.name + "`"
		var count, payload int64
		if err := tx.QueryRowContext(ctx, query).Scan(&count, &payload); err != nil {
			return empty, restoreFailure(ctx, ErrTargetRead)
		}
		if count < 0 || payload < 0 {
			return empty, ErrTargetRead
		}
		if count > request.Limits.MaxRows-totalRows || payload > request.Limits.MaxPayloadBytes-totalBytes {
			return empty, ErrCapacity
		}
		totalRows += count
		totalBytes += payload
		if count != int64(t.rows.Len()) {
			return empty, invalid(ErrMismatch, t.name, "row_count")
		}
	}
	actual := Rows{}
	output := reflect.ValueOf(&actual).Elem()
	for i, t := range views {
		layout := sqlLayout(t)
		// Static model-derived columns, closed table names and a bound numeric LIMIT.
		// Read a sentinel row to detect unexpected growth; do not use SELECT *.
		limit := int64(t.rows.Len()) + 1
		query := "SELECT " + strings.Join(layout.columns, ",") + " FROM `" + t.name + "` ORDER BY `id` LIMIT ?"
		result, err := tx.QueryContext(ctx, query, limit)
		if err != nil {
			return empty, restoreFailure(ctx, ErrTargetRead)
		}
		rows, err := scanRestoreTable(ctx, result, t, layout)
		if err != nil {
			return empty, err
		}
		output.Field(i).Set(rows)
	}
	if err := checkRowsCapacity(ctx, actual, request.Limits); err != nil {
		return empty, err
	}
	return actual, nil
}
func scanRestoreTable(ctx context.Context, result *sql.Rows, t tableView, layout sqlTableLayout) (reflect.Value, error) {
	defer result.Close()
	columns, err := result.Columns()
	if err != nil || len(columns) != len(layout.columns) {
		return reflect.Value{}, ErrTargetRead
	}
	for i, column := range columns {
		if column != strings.Trim(layout.columns[i], "`") {
			return reflect.Value{}, ErrTargetRead
		}
	}
	rows := reflect.MakeSlice(t.rows.Type(), 0, t.rows.Len())
	for result.Next() {
		if err := ctx.Err(); err != nil {
			return reflect.Value{}, err
		}
		if rows.Len() >= t.rows.Len() {
			return reflect.Value{}, invalid(ErrMismatch, t.name, "row_count")
		}
		row := reflect.New(t.rows.Type().Elem()).Elem()
		dest := make([]any, row.NumField())
		for i := range dest {
			dest[i] = row.Field(i).Addr().Interface()
		}
		if err := result.Scan(dest...); err != nil {
			return reflect.Value{}, restoreFailure(ctx, ErrTargetRead)
		}
		rows = reflect.Append(rows, row)
	}
	if err := result.Err(); err != nil {
		return reflect.Value{}, restoreFailure(ctx, ErrTargetRead)
	}
	if err := result.Close(); err != nil {
		return reflect.Value{}, restoreFailure(ctx, ErrTargetRead)
	}
	if rows.Len() != t.rows.Len() {
		return reflect.Value{}, invalid(ErrMismatch, t.name, "row_count")
	}
	return rows, nil
}
func checkExternalRestoreReferences(ctx context.Context, tx *sql.Tx, rows Rows) error {
	refs := map[string]map[int]bool{"users": {}, "instances": {}}
	for _, t := range tables(rows) {
		for _, ref := range t.refs {
			set, external := refs[ref.table]
			if !external {
				continue
			}
			for i := 0; i < t.rows.Len(); i++ {
				id, present := intField(t.rows.Index(i).FieldByName(ref.field))
				if present {
					set[id] = true
				}
			}
		}
	}
	for _, table := range []string{"users", "instances"} {
		ids := make([]int, 0, len(refs[table]))
		for id := range refs[table] {
			ids = append(ids, id)
		}
		sort.Ints(ids)
		// Dependency tables must also participate in the same transactional snapshot.
		if len(ids) == 0 {
			continue
		}
		var engine string
		if err := tx.QueryRowContext(ctx, "SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND TABLE_TYPE='BASE TABLE'", table).Scan(&engine); err != nil {
			return restoreFailure(ctx, ErrTargetRead)
		}
		if !strings.EqualFold(engine, "InnoDB") {
			return ErrTargetRead
		}
		for start := 0; start < len(ids); start += 256 {
			end := start + 256
			if end > len(ids) {
				end = len(ids)
			}
			args := make([]any, end-start)
			for i, id := range ids[start:end] {
				args[i] = id
			}
			query := "SELECT `id` FROM `" + table + "` WHERE `id` IN (" + strings.TrimSuffix(strings.Repeat("?,", len(args)), ",") + ") ORDER BY `id`"
			result, err := tx.QueryContext(ctx, query, args...)
			if err != nil {
				return restoreFailure(ctx, ErrTargetRead)
			}
			if err := scanExternalIDs(ctx, result, ids[start:end], table); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}
func scanExternalIDs(ctx context.Context, result *sql.Rows, expected []int, table string) error {
	defer result.Close()
	index := 0
	for result.Next() {
		var id int
		if err := result.Scan(&id); err != nil {
			return restoreFailure(ctx, ErrTargetRead)
		}
		if index >= len(expected) || id != expected[index] {
			return invalid(ErrMismatch, table, "id")
		}
		index++
	}
	if err := result.Err(); err != nil {
		return restoreFailure(ctx, ErrTargetRead)
	}
	if err := result.Close(); err != nil {
		return restoreFailure(ctx, ErrTargetRead)
	}
	if index != len(expected) {
		return invalid(ErrMismatch, table, "id")
	}
	return ctx.Err()
}
