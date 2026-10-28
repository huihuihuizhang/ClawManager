package systembackupevidence

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

func dIntegrationDatabaseScope(ctx context.Context, db *sql.DB, scope pd.Scope) (pd.Scope, error) {
	var server, database string
	if err := db.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE()").Scan(&server, &database); err != nil {
		return pd.Scope{}, err
	}
	if server == "" || database == "" {
		return pd.Scope{}, pd.ErrInvalid
	}
	scope.ServerUUID, scope.Database = pd.ServerUUID(server), pd.Database(database)
	return scope, nil
}

func (f *dIntegrationFixture) sample() time.Time {
	if f.realDB {
		return time.Now().UTC().Truncate(time.Microsecond)
	}
	return f.d.now
}

func (f *dIntegrationFixture) seed(record any) {
	if !f.realDB {
		f.d.seed(record)
		return
	}
	r, err := pd.EncodeStoredRecord(record)
	if err != nil {
		f.t.Fatal(err)
	}
	var cols, marks []string
	var args []any
	for k, v := range r.Columns {
		cols = append(cols, k)
		marks = append(marks, "?")
		args = append(args, v)
	}
	_, err = f.db.Exec("INSERT INTO "+r.Table+" ("+strings.Join(cols, ",")+") VALUES ("+strings.Join(marks, ",")+")", args...)
	if err != nil {
		f.t.Fatal(err)
	}
}

func (f *dIntegrationFixture) load(table string, out any) {
	if !f.realDB {
		f.d.load(table, out)
		return
	}
	rows, err := f.db.Query("SELECT * FROM " + table)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		f.t.Fatal(err)
	}
	if !rows.Next() {
		f.t.Fatal("missing record", table, rows.Err())
	}
	values, ptrs := make([]any, len(cols)), make([]any, len(cols))
	for i := range values {
		ptrs[i] = &values[i]
	}
	if err = rows.Scan(ptrs...); err != nil {
		f.t.Fatal(err)
	}
	m := map[string]any{}
	for i, col := range cols {
		m[col] = values[i]
	}
	if err = pd.DecodeStoredRecord(pd.StoredRecord{Table: table, Columns: m}, f.command.Scope, out); err != nil {
		f.t.Fatal(err)
	}
	if rows.Next() || rows.Err() != nil {
		f.t.Fatal("expected one record", table, rows.Err())
	}
}

// Rechecks use the service's own transaction, including uncommitted rows.
func (f *dIntegrationFixture) check(ctx context.Context, tx pd.ReadSQL, records ...any) error {
	if !f.realDB {
		return f.d.check(records...)
	}
	for _, record := range records {
		r, err := pd.EncodeStoredRecord(record)
		if err != nil {
			return err
		}
		var conditions []string
		var args []any
		for k, v := range r.Columns {
			conditions = append(conditions, k+" <=> ?")
			args = append(args, v)
		}
		var count int
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+r.Table+" WHERE "+strings.Join(conditions, " AND "), args...).Scan(&count); err != nil {
			return fmt.Errorf("recheck: %w", err)
		}
		if count != 1 {
			return pd.ErrConflict
		}
	}
	return nil
}
