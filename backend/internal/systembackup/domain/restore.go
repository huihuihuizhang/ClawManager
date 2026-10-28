package domain

import (
	"context"
	"database/sql"
	"reflect"
	"strings"
)

// DrillTarget can only name an isolated temporary database. CheckIsolation is
// the shared controller's observed-identity/network/credential check; a name
// prefix by itself is never sufficient. It must remain valid until completion.
type DrillTarget struct {
	Database, ServerUUID string
	CheckIsolation       func(context.Context) error
}

func (t DrillTarget) check(ctx context.Context, conn *sql.Conn) error {
	if !identifier.MatchString(t.Database) || !strings.HasPrefix(t.Database, "cm_drill_") || t.ServerUUID == "" || t.CheckIsolation == nil {
		return ErrIsolation
	}
	var database, uuid string
	if conn.QueryRowContext(ctx, "SELECT DATABASE(), @@server_uuid").Scan(&database, &uuid) != nil {
		return ErrDatabase
	}
	if database != t.Database || uuid != t.ServerUUID {
		return ErrIsolation
	}
	if t.CheckIsolation(ctx) != nil {
		return ErrIsolation
	}
	return nil
}

// RestoreDrill replaces the isolated target's bootstrap admin transactionally.
// This is deliberately not a production restore API. It uses parameterized
// inserts and never executes source DDL/SQL, disables foreign keys or runs an
// application initializer. Incompatible schemas roll back the entire database.
func RestoreDrill(ctx context.Context, db *sql.DB, target DrillTarget, source Snapshot, policy Policy) (RestorePlan, error) {
	return restoreDrill(ctx, db, target, source, policy, nil)
}

// RestoreDrillWithEvidence seals the exact normalized plan before COMMIT.
// Evidence is sensitive and must be encrypted. Failure rolls back the database;
// a sealed orphan or an uncertain commit remains for controller reconciliation.
func RestoreDrillWithEvidence(ctx context.Context, db *sql.DB, target DrillTarget, source Snapshot, policy Policy, evidence func(context.Context, RestorePlan) error) (RestorePlan, error) {
	if evidence == nil {
		return RestorePlan{}, ErrIsolation
	}
	return restoreDrill(ctx, db, target, source, policy, evidence)
}

func restoreDrill(ctx context.Context, db *sql.DB, target DrillTarget, source Snapshot, policy Policy, evidence func(context.Context, RestorePlan) error) (RestorePlan, error) {
	if db == nil {
		return RestorePlan{}, ErrDatabase
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return RestorePlan{}, ErrDatabase
	}
	defer conn.Close()
	if err = target.check(ctx, conn); err != nil {
		return RestorePlan{}, err
	}
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return RestorePlan{}, ErrDatabase
	}
	defer tx.Rollback()
	catalog, err := Catalog(ctx, tx)
	if err != nil {
		return RestorePlan{}, err
	}
	plan, err := Normalize(ctx, source, catalog, policy)
	if err != nil {
		return RestorePlan{}, err
	}
	if err = checkBlankPolicy(ctx, tx, catalog, policy); err != nil {
		return RestorePlan{}, err
	}
	// Check observed resource identity again at the first write boundary.
	if err = target.check(ctx, conn); err != nil {
		return RestorePlan{}, err
	}
	statements := []string{"DELETE FROM `user_quotas`", "DELETE FROM `users`"}
	if policy.WorkBuddy.uidLayout() {
		statements = append(statements, "DELETE FROM `workbuddy_linux_identity_allocator`")
	}
	for _, statement := range statements {
		if _, err = tx.ExecContext(ctx, statement); err != nil {
			return RestorePlan{}, ErrDatabase
		}
	}
	for _, t := range plan.Data.Tables {
		name, _ := quoted(t.Name)
		var cols, marks []string
		for _, c := range t.Columns {
			n, _ := quoted(c.Name)
			cols = append(cols, n)
			marks = append(marks, "?")
		}
		stmt, err := tx.PrepareContext(ctx, "INSERT INTO "+name+" ("+strings.Join(cols, ",")+") VALUES ("+strings.Join(marks, ",")+")")
		if err != nil {
			return RestorePlan{}, ErrDatabase
		}
		for _, r := range t.Rows {
			args := make([]any, len(t.Columns))
			for i, c := range t.Columns {
				v := r[c.Name]
				if !v.Null {
					args[i] = v.Bytes
				}
			}
			if _, err = stmt.ExecContext(ctx, args...); err != nil {
				stmt.Close()
				return RestorePlan{}, ErrDatabase
			}
		}
		if stmt.Close() != nil {
			return RestorePlan{}, ErrDatabase
		}
	}
	if evidence != nil {
		if err = evidence(ctx, plan); err != nil {
			return RestorePlan{}, err
		}
		if err = target.check(ctx, conn); err != nil {
			return RestorePlan{}, err
		}
	}
	if err = tx.Commit(); err != nil {
		return RestorePlan{}, ErrDatabase
	}
	return plan, nil
}

func checkBlank(ctx context.Context, tx *sql.Tx, tables []Table) error {
	return checkBlankPolicy(ctx, tx, tables, Policy{})
}
func checkBlankPolicy(ctx context.Context, tx *sql.Tx, tables []Table, policy Policy) error {
	// Imported code must not activate triggers/events or write through views.
	var executable int
	if tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = DATABASE()) + (SELECT COUNT(*) FROM information_schema.EVENTS WHERE EVENT_SCHEMA = DATABASE()) + (SELECT COUNT(*) FROM information_schema.VIEWS WHERE TABLE_SCHEMA = DATABASE())`).Scan(&executable) != nil {
		return ErrDatabase
	}
	if executable != 0 {
		return ErrSchema
	}
	var admins int
	if tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM `users` WHERE username = 'admin' AND role = 'admin'").Scan(&admins) != nil {
		return ErrDatabase
	}
	if admins > 1 {
		return ErrNotEmpty
	}
	for _, t := range tables {
		if t.Name == "schema_migrations" {
			continue
		}
		if t.Engine != "InnoDB" {
			return ErrSchema
		}
		name, _ := quoted(t.Name)
		var count int
		if tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+name).Scan(&count) != nil {
			return ErrDatabase
		}
		if t.Name == "users" {
			if count != admins {
				return ErrNotEmpty
			}
			continue
		}
		if t.Name == "user_quotas" {
			var invalid int
			if tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM `user_quotas` q LEFT JOIN `users` u ON q.user_id = u.id WHERE u.id IS NULL OR u.username <> 'admin' OR u.role <> 'admin'").Scan(&invalid) != nil {
				return ErrDatabase
			}
			if invalid > 0 || count > 1 {
				return ErrNotEmpty
			}
			continue
		}
		if t.Name == workBuddyAllocator && policy.WorkBuddy.uidLayout() {
			if count == 0 {
				continue
			}
			if count != 1 {
				return ErrNotEmpty
			}
			var id, next string
			if tx.QueryRowContext(ctx, "SELECT `id`,`next_uid` FROM `workbuddy_linux_identity_allocator` ORDER BY `id`").Scan(&id, &next) != nil {
				return ErrDatabase
			}
			// Only an empty allocator seed is replaceable, and all other tables
			// must still satisfy the bootstrap-only checks in this transaction.
			if id != "1" || next != "10000" {
				return ErrNotEmpty
			}
			continue
		}
		if count != 0 {
			return ErrNotEmpty
		}
	}
	return nil
}

// VerifyDrill requires a separate SELECT-only connection. Call only after the
// restore Job has ended and its credentials have been revoked by the controller.
// The grant check rejects roles, wildcard grants and write privileges rather
// than accepting a read-only transaction as proof of independent permissions.
func VerifyDrill(ctx context.Context, db *sql.DB, target DrillTarget, plan RestorePlan) error {
	if db == nil {
		return ErrDatabase
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return ErrDatabase
	}
	defer conn.Close()
	if err = target.check(ctx, conn); err != nil {
		return err
	}
	if err = checkSelectOnly(ctx, conn, target.Database); err != nil {
		return err
	}
	return verifyRows(ctx, conn, plan)
}

func checkSelectOnly(ctx context.Context, conn *sql.Conn, database string) error {
	grantDatabase, err := QuotedGrantDatabase(ctx, conn, database)
	if err != nil {
		return err
	}
	grants, err := conn.QueryContext(ctx, "SHOW GRANTS FOR CURRENT_USER")
	if err != nil {
		return ErrDatabase
	}
	found := false
	for grants.Next() {
		var g string
		if grants.Scan(&g) != nil {
			grants.Close()
			return ErrDatabase
		}
		if strings.Contains(g, " WITH GRANT OPTION") {
			grants.Close()
			return ErrIsolation
		}
		if strings.HasPrefix(g, "GRANT USAGE ON *.* TO ") {
			continue
		}
		if !strings.HasPrefix(g, "GRANT SELECT ON "+grantDatabase+".* TO ") {
			grants.Close()
			return ErrIsolation
		}
		found = true
	}
	err = grants.Err()
	grants.Close()
	if err != nil {
		return ErrDatabase
	}
	if !found {
		return ErrIsolation
	}
	return nil
}

func verifyRows(ctx context.Context, conn *sql.Conn, plan RestorePlan) error {
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return ErrDatabase
	}
	defer tx.Rollback()
	expected := map[string]int{}
	for _, t := range plan.Data.Tables {
		expected[t.Name] = len(t.Rows)
		name, e := quoted(t.Name)
		if e != nil {
			return e
		}
		var cols, pk []string
		for _, c := range t.Columns {
			n, e := quoted(c.Name)
			if e != nil {
				return e
			}
			cols = append(cols, n)
		}
		for _, c := range t.PrimaryKey {
			n, e := quoted(c)
			if e != nil {
				return e
			}
			pk = append(pk, n)
		}
		if len(cols) == 0 || len(pk) == 0 {
			return ErrSchema
		}
		rows, err := tx.QueryContext(ctx, "SELECT "+strings.Join(cols, ",")+" FROM "+name+" ORDER BY "+strings.Join(pk, ","))
		if err != nil {
			return ErrDatabase
		}
		index := 0
		for rows.Next() {
			if index >= len(t.Rows) {
				rows.Close()
				return ErrData
			}
			values := make([]any, len(cols))
			pointers := make([]any, len(cols))
			for i := range values {
				pointers[i] = &values[i]
			}
			if rows.Scan(pointers...) != nil {
				rows.Close()
				return ErrDatabase
			}
			for i, v := range values {
				c, e := rawCell(v)
				want := t.Rows[index][t.Columns[i].Name]
				if e != nil || c.Null != want.Null || !reflect.DeepEqual(string(c.Bytes), string(want.Bytes)) {
					rows.Close()
					return ErrData
				}
			}
			index++
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return ErrDatabase
		}
		if index != len(t.Rows) {
			return ErrData
		}
	}
	// A row in an omitted/replayable/control table also invalidates the drill.
	catalog, err := Catalog(ctx, tx)
	if err != nil {
		return err
	}
	if ident, ok := workBuddyTable(plan.Data, workBuddyIdentities); ok && SchemaDigest(ident) == WorkBuddyUIDSchema().SHA256 {
		metadata := map[string]Table{}
		for _, t := range catalog {
			metadata[t.Name] = t
		}
		if err := validateWorkBuddyUIDTarget(metadata, WorkBuddyUIDSchema()); err != nil {
			return err
		}
	}
	for _, t := range catalog {
		if t.Name == "schema_migrations" {
			continue
		}
		name, _ := quoted(t.Name)
		var n int
		if tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+name).Scan(&n) != nil {
			return ErrDatabase
		}
		if n != expected[t.Name] {
			return ErrData
		}
	}
	if tx.Commit() != nil {
		return ErrDatabase
	}
	return nil
}
