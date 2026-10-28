//go:build systembackup_mysql

package systembackupevidence

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	sec "clawreef/internal/systembackupsecurity"
	"github.com/go-sql-driver/mysql"
)

// This probe installs candidate privileges ONLY in the disposable MySQL Pod
// guarded by downloadAuditProbeDatabase's namespace UID and server UUID. It
// exercises the early component, not Collect, a production GC policy or grant
// approval. Expected metadata comes from the separate privileged observer.
var aGCRoleCases = []string{
	"least_privilege_metadata_and_lock", "forbidden_data_and_ddl",
	"table_revoke_old_and_new_sessions", "column_revoke_old_and_new_sessions",
	"database_revoke_old_and_new_sessions", "global_revoke_old_and_new_sessions",
	"active_role_rejected", "cross_schema_restrict_rejected",
	"cross_schema_cascade_rejected", "metadata_drift",
}

// This table is created by the formal capsule in every isolated role database.
// The role fixture does not create the MFA owner's separate synthetic table.
const aGCRoleMetadataDriftSQL = "ALTER TABLE system_backup_v2_configs ADD COLUMN gc_role_probe INT NULL"

func aGCRoleHint(c DownloadGCEarlyReferenceConfig) DownloadGCEarlyScope {
	return DownloadGCEarlyScope{Database: c.Database, Installation: c.Installation, WorkerOperation: "sop_11111111-2222-4333-8444-555555555555", Operation: "sop_66666666-7777-4888-8999-aaaaaaaaaaaa", PrincipalSHA256: strings.Repeat("b", 64), OperationID: 1, ActorID: 42, IntentAuditID: 1, ResultAuditID: 2}
}

func aGCRoleGrants(database, user string) []string {
	recipient := "'" + user + "'@'%'"
	object := func(table string) string { return "`" + database + "`.`" + table + "`" }
	grants := []string{"GRANT REFERENCES ON *.* TO " + recipient, "GRANT LOCK TABLES ON `" + database + "`.* TO " + recipient, "GRANT SELECT (`id`) ON " + object("users") + " TO " + recipient}
	for _, table := range gcRequiredReadTables(false) {
		privileges := "SELECT"
		if gcDeleteTables[table] {
			privileges += ", DELETE"
		}
		if table == "system_backup_v2_compact_tombstones" {
			privileges += ", INSERT"
		}
		if table == "system_backup_v2_metadata_reservations" {
			privileges += ", UPDATE"
		}
		grants = append(grants, "GRANT "+privileges+" ON "+object(table)+" TO "+recipient)
	}
	return grants
}

func TestADownloadGCRoleMySQLSeed(t *testing.T) {
	if _, err := decodeADownloadMFAInputs(aDownloadMFASeed); err != nil {
		t.Fatal("GC role capsule invalid")
	}
	if !strings.Contains(aGCRoleMetadataDriftSQL, "ALTER TABLE system_backup_v2_configs ADD COLUMN") {
		t.Fatal("GC role drift must alter an existing formal fixture table")
	}
	seen := map[string]bool{}
	for _, name := range aGCRoleCases {
		if seen[name] || !regexp.MustCompile(`^[a-z_]+$`).MatchString(name) {
			t.Fatal("GC role case identity")
		}
		seen[name] = true
	}
	grants := aGCRoleGrants("agc_seed", "a_gc_seed")
	source := &SQLDownloadGCEarlyReferences{c: DownloadGCEarlyReferenceConfig{Database: sec.DatabaseIdentity{Database: "agc_seed"}, Account: "a_gc_seed@%", MaintenanceReceipts: "absent"}}
	source.c.Installation = "installation_gc_role_probe"
	if len(seen) != 10 || source.grants(grants) != nil || !validGCEarlyScope(source.c, aGCRoleHint(source.c)) {
		t.Fatal("GC role candidate shape")
	}
	for _, forbidden := range []string{"GRANT SELECT ON `agc_seed`.`users` TO 'a_gc_seed'@'%'", "GRANT CREATE ON `agc_seed`.* TO 'a_gc_seed'@'%'", "GRANT DELETE ON `agc_seed`.`system_backup_v2_compact_tombstones` TO 'a_gc_seed'@'%'"} {
		if source.grants(append(append([]string(nil), grants...), forbidden)) == nil {
			t.Fatal("GC role unsafe grant accepted")
		}
	}
	t.Log("PASS GC role seed cases=10 actual_mysql=not_run role_approval=no production_approval=no")
}

// Never print the error or query: CREATE USER contains the ephemeral password.
func aGCRoleSQL(t *testing.T, stage string, err error) {
	t.Helper()
	if err == nil {
		return
	}
	var mysqlError *mysql.MySQLError
	if errors.As(err, &mysqlError) {
		t.Fatalf("GC role SQL stage=%s mysql_errno=%d", stage, mysqlError.Number)
	}
	t.Fatalf("GC role SQL stage=%s failed", stage)
}

func aGCRoleExec(t *testing.T, ctx context.Context, db *sql.DB, stage, query string) {
	t.Helper()
	_, err := db.ExecContext(ctx, query)
	aGCRoleSQL(t, stage, err)
}

type aGCRoleFixture struct {
	ctx      context.Context
	root, db *sql.DB
	cfg      *mysql.Config
	c        DownloadGCEarlyReferenceConfig
	hint     DownloadGCEarlyScope
	user     string
}

func aGCRoleMetadata(t *testing.T, ctx context.Context, db interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) DownloadGCMetadataPins {
	t.Helper()
	var pins []string
	for _, definition := range gcMetadataDefinitions() {
		rows, err := db.QueryContext(ctx, definition.query)
		aGCRoleSQL(t, "metadata-query-"+definition.domain, err)
		var records []string
		for rows.Next() {
			values := make([]string, definition.width)
			args := make([]any, len(values))
			for n := range args {
				args[n] = &values[n]
			}
			aGCRoleSQL(t, "metadata-scan", rows.Scan(args...))
			if len(records) >= 10000 {
				t.Fatal("GC role metadata exceeds component bound")
			}
			records = append(records, string(canonical(values)))
		}
		aGCRoleSQL(t, "metadata-read", rows.Err())
		aGCRoleSQL(t, "metadata-close", rows.Close())
		pins = append(pins, gcMetadataDigest(definition.domain, records))
	}
	return DownloadGCMetadataPins{Tables: pins[0], Columns: pins[1], ForeignKeys: pins[2], Indexes: pins[3]}
}

func aGCRoleGrantPin(t *testing.T, ctx context.Context, db *sql.DB, user string) string {
	t.Helper()
	rows, err := db.QueryContext(ctx, "SHOW GRANTS FOR '"+user+"'@'%'")
	aGCRoleSQL(t, "privileged-grant-observer", err)
	var statements []string
	for rows.Next() {
		var statement string
		aGCRoleSQL(t, "grant-scan", rows.Scan(&statement))
		statements = append(statements, statement)
	}
	aGCRoleSQL(t, "grant-read", rows.Err())
	aGCRoleSQL(t, "grant-close", rows.Close())
	sort.Strings(statements)
	return hash(canonical(statements))
}

func newAGCRoleFixture(t *testing.T, input aDownloadMFAInputs) *aGCRoleFixture {
	t.Helper()
	ctx, root, rootCfg, identity := aDownloadMFADatabase(t, input)
	aGCRoleExec(t, ctx, root, "owned-user-row", "INSERT INTO users(id,username,email,password_hash,role,is_active) VALUES(42,'synthetic-gc-role','gc-role@example.invalid','isolated-gc-role-not-login','admin',TRUE)")
	var entropy [16]byte
	_, err := rand.Read(entropy[:])
	aGCRoleSQL(t, "account-entropy", err)
	user := "a_gc_" + hex.EncodeToString(entropy[:10])
	var secret [32]byte
	_, err = rand.Read(secret[:])
	aGCRoleSQL(t, "credential-entropy", err)
	password := hex.EncodeToString(secret[:])
	aGCRoleExec(t, ctx, root, "create-isolated-user", "CREATE USER '"+user+"'@'%' IDENTIFIED BY '"+password+"'")
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		var server string
		if root.QueryRowContext(cleanup, "SELECT @@server_uuid").Scan(&server) != nil || server != identity.ServerUUID || !regexp.MustCompile(`^a_gc_[a-f0-9]{20}$`).MatchString(user) {
			t.Error("CLEANUP_PENDING GC role account identity")
			return
		}
		if _, err := root.ExecContext(cleanup, "DROP USER '"+user+"'@'%'"); err != nil {
			t.Error("CLEANUP_PENDING GC role account")
			return
		}
		var count int
		if root.QueryRowContext(cleanup, "SELECT COUNT(*) FROM mysql.user WHERE User=? AND Host='%'", user).Scan(&count) != nil || count != 0 {
			t.Error("CLEANUP_PENDING GC role account absence")
			return
		}
		t.Log("CLEANED GC role owned account", user)
	})
	for _, grant := range aGCRoleGrants(identity.Database, user) {
		aGCRoleExec(t, ctx, root, "candidate-isolated-grant", grant)
	}
	cfg := rootCfg.Clone()
	cfg.User, cfg.Passwd, cfg.MultiStatements = user, password, false
	x := &aGCRoleFixture{ctx: ctx, root: root, cfg: cfg, user: user}
	x.db = x.pool(t)
	x.c = DownloadGCEarlyReferenceConfig{Database: identity, Installation: "installation_gc_role_probe", Account: user + "@%", GrantsSHA256: aGCRoleGrantPin(t, ctx, root, user), Metadata: aGCRoleMetadata(t, ctx, root), MaintenanceReceipts: "absent"}
	x.hint = aGCRoleHint(x.c)
	return x
}

func (x *aGCRoleFixture) pool(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("mysql", x.cfg.FormatDSN())
	aGCRoleSQL(t, "restricted-pool", err)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	t.Cleanup(func() { db.Close() })
	aGCRoleSQL(t, "restricted-connect", db.PingContext(x.ctx))
	return db
}

func (x *aGCRoleFixture) source(t *testing.T) *SQLDownloadGCEarlyReferences {
	t.Helper()
	source, err := NewSQLDownloadGCEarlyReferences(x.c)
	aGCRoleSQL(t, "construct-early-component", err)
	return source
}

func (x *aGCRoleFixture) begin(t *testing.T, conn *sql.Conn) *sql.Tx {
	t.Helper()
	tx, err := conn.BeginTx(x.ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	aGCRoleSQL(t, "restricted-begin", err)
	t.Cleanup(func() { tx.Rollback() })
	return tx
}

func (x *aGCRoleFixture) conn(t *testing.T, db *sql.DB) *sql.Conn {
	t.Helper()
	conn, err := db.Conn(x.ctx)
	aGCRoleSQL(t, "restricted-session", err)
	t.Cleanup(func() { conn.Close() })
	return conn
}

func (x *aGCRoleFixture) scope() DownloadRetentionGCScope {
	h := x.hint
	return DownloadRetentionGCScope{Database: h.Database, Installation: h.Installation, WorkerOperation: h.WorkerOperation, PrincipalSHA256: h.PrincipalSHA256, Operation: h.Operation, OperationID: h.OperationID, ActorID: h.ActorID, IntentAuditID: h.IntentAuditID, ResultAuditID: h.ResultAuditID}
}

func aGCRoleDenied(t *testing.T, err error) {
	t.Helper()
	var e *mysql.MySQLError
	if !errors.As(err, &e) || (e.Number != 1142 && e.Number != 1143) {
		// Neither missing data/columns nor constraint failure proves denial.
		t.Fatal("GC role expected actual MySQL table/column permission denial")
	}
}

func TestADownloadGCRoleMySQL(t *testing.T) {
	raw, err := os.ReadFile(os.Getenv("D_PROVIDER_REGISTRATION_DDL"))
	aGCRoleSQL(t, "read-input-capsule", err)
	if hash(raw) != os.Getenv("D_PROVIDER_REGISTRATION_DDL_SHA256") {
		t.Fatal("GC role input pin")
	}
	input, err := decodeADownloadMFAInputs(raw)
	aGCRoleSQL(t, "decode-input-capsule", err)
	for _, name := range aGCRoleCases {
		t.Run(name, func(t *testing.T) {
			x := newAGCRoleFixture(t, input)
			conn := x.conn(t, x.db)
			if got := aGCRoleMetadata(t, x.ctx, conn); !reflect.DeepEqual(got, x.c.Metadata) {
				t.Fatal("restricted metadata differs from privileged observer; candidate role is insufficient")
			}
			source := x.source(t)
			tx := x.begin(t, conn)
			guard, err := source.Lock(x.ctx, tx, x.hint)
			aGCRoleSQL(t, "baseline-early-lock", err)
			if guard == nil {
				t.Fatal("GC role nil baseline guard")
			}
			if strings.Contains(name, "_revoke_") {
				x.revoke(t, name, conn, tx, guard)
				return
			}
			aGCRoleSQL(t, "baseline-recheck", guard.Recheck(x.ctx, tx, x.scope(), time.Now()))
			aGCRoleSQL(t, "baseline-rollback", tx.Rollback())
			switch name {
			case "least_privilege_metadata_and_lock":
				tx = x.begin(t, conn)
				var id int64
				err = tx.QueryRowContext(x.ctx, "SELECT id FROM users WHERE id=42 FOR UPDATE").Scan(&id)
				aGCRoleSQL(t, "column-only-locking-read", err)
				if id != 42 {
					t.Fatal("restricted locking read did not return the owned user row")
				}
				t.Log("OBSERVED restricted metadata parity tables/columns/incoming-FKs/indexes and users.id FOR UPDATE; maintenance=absent full_gc=not_run")
			case "forbidden_data_and_ddl":
				for _, query := range []string{"SELECT password_hash FROM users LIMIT 1", "UPDATE users SET password_hash=password_hash WHERE id=42", "UPDATE system_backup_v2_backups SET id=id WHERE 1=0", "INSERT INTO audit_logs(id) VALUES(1)", "UPDATE audit_logs SET id=id WHERE 1=0", "DELETE FROM system_backup_v2_compact_tombstones WHERE 1=0", "CREATE TABLE gc_role_forbidden(id INT)"} {
					_, denied := conn.ExecContext(x.ctx, query)
					aGCRoleDenied(t, denied)
				}
				t.Log("OBSERVED seven actual MySQL permission denials; no raw error/credential output")
			case "active_role_rejected":
				x.activeRole(t, conn)
			case "cross_schema_restrict_rejected", "cross_schema_cascade_rejected":
				x.foreignReference(t, conn, name == "cross_schema_cascade_rejected")
			case "metadata_drift":
				aGCRoleExec(t, x.ctx, x.root, "owned-metadata-drift", aGCRoleMetadataDriftSQL)
				changed := aGCRoleMetadata(t, x.ctx, x.root)
				if changed.Columns == x.c.Metadata.Columns {
					t.Fatal("owned DDL did not change the privileged column pin")
				}
				tx = x.begin(t, conn)
				if g, e := source.Lock(x.ctx, tx, x.hint); e == nil || g != nil {
					t.Fatal("changed metadata accepted under original privileged pins")
				}
				aGCRoleSQL(t, "drift-rollback", tx.Rollback())
				x.c.Metadata = changed
				tx = x.begin(t, conn)
				_, e := x.source(t).Lock(x.ctx, tx, x.hint)
				aGCRoleSQL(t, "isolated-repin-positive", e)
				t.Log("OBSERVED privileged column metadata drift; original pin rejected; isolated repin accepted")
			default:
				t.Fatal("unknown GC role case")
			}
		})
	}
}

func (x *aGCRoleFixture) revoke(t *testing.T, name string, conn *sql.Conn, tx *sql.Tx, guard *DownloadGCEarlyReferenceGuard) {
	t.Helper()
	objects := map[string]string{
		"table_revoke_old_and_new_sessions":    "SELECT ON `" + x.c.Database.Database + "`.`audit_logs`",
		"column_revoke_old_and_new_sessions":   "SELECT (`id`) ON `" + x.c.Database.Database + "`.`users`",
		"database_revoke_old_and_new_sessions": "LOCK TABLES ON `" + x.c.Database.Database + "`.*",
		"global_revoke_old_and_new_sessions":   "REFERENCES ON *.*",
	}
	object, ok := objects[name]
	if !ok {
		t.Fatal("unknown revoke scope")
	}
	var oldID, sameID, newID uint64
	aGCRoleSQL(t, "original-connection-id", tx.QueryRowContext(x.ctx, "SELECT CONNECTION_ID()").Scan(&oldID))
	recipient := "'" + x.user + "'@'%'"
	aGCRoleExec(t, x.ctx, x.root, "revoke-isolated-candidate", "REVOKE "+object+" FROM "+recipient)
	aGCRoleSQL(t, "same-connection-id", tx.QueryRowContext(x.ctx, "SELECT CONNECTION_ID()").Scan(&sameID))
	if sameID != oldID || guard.Recheck(x.ctx, tx, x.scope(), time.Now()) == nil {
		t.Fatal("old-session guard accepted current revoked grant set")
	}
	fresh := x.pool(t)
	freshConn := x.conn(t, fresh)
	aGCRoleSQL(t, "new-connection-id", freshConn.QueryRowContext(x.ctx, "SELECT CONNECTION_ID()").Scan(&newID))
	if oldID == newID {
		t.Fatal("revoke probe did not create a new server session")
	}
	freshTx := x.begin(t, freshConn)
	if g, err := x.source(t).Lock(x.ctx, freshTx, x.hint); err == nil || g != nil {
		t.Fatal("new-session guard accepted revoked grant set")
	}
	aGCRoleSQL(t, "revoked-new-rollback", freshTx.Rollback())
	if strings.HasPrefix(name, "global_") {
		visible := aGCRoleMetadata(t, x.ctx, freshConn)
		t.Log("OBSERVED post-REFERENCES-revocation metadata_matches_privileged=", reflect.DeepEqual(visible, x.c.Metadata))
	}
	if strings.HasPrefix(name, "column_") || strings.HasPrefix(name, "database_") {
		var id int64
		e := freshConn.QueryRowContext(x.ctx, "SELECT id FROM users WHERE id=42 FOR UPDATE").Scan(&id)
		aGCRoleDenied(t, e)
	}
	// Static global/database privilege caching is deliberately not treated as
	// immediate SQL revocation. The existing transaction must read SHOW GRANTS.
	aGCRoleExec(t, x.ctx, x.root, "restore-isolated-candidate", "GRANT "+object+" TO "+recipient)
	if guard.Recheck(x.ctx, tx, x.scope(), time.Now()) == nil {
		t.Fatal("failed guard revived after regrant")
	}
	aGCRoleSQL(t, "revoked-original-rollback", tx.Rollback())
	postRestore := x.pool(t)
	postTx := x.begin(t, x.conn(t, postRestore))
	_, err := x.source(t).Lock(x.ctx, postTx, x.hint)
	aGCRoleSQL(t, "new-session-after-regrant", err)
	t.Log("OBSERVED original-session and new-session grant denial; failed guard stays failed after regrant; fresh post-restore session succeeds")
}

func (x *aGCRoleFixture) activeRole(t *testing.T, conn *sql.Conn) {
	t.Helper()
	role := x.user + "_r"
	aGCRoleExec(t, x.ctx, x.root, "create-isolated-role", "CREATE ROLE '"+role+"'@'%'")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		var server string
		if x.root.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&server) != nil || server != x.c.Database.ServerUUID || !regexp.MustCompile(`^a_gc_[a-f0-9]{20}_r$`).MatchString(role) {
			t.Error("CLEANUP_PENDING GC role identity")
			return
		}
		if _, err := x.root.ExecContext(ctx, "DROP ROLE '"+role+"'@'%'"); err != nil {
			t.Error("CLEANUP_PENDING GC role")
			return
		}
		var count int
		if x.root.QueryRowContext(ctx, "SELECT COUNT(*) FROM mysql.user WHERE User=? AND Host='%'", role).Scan(&count) != nil || count != 0 {
			t.Error("CLEANUP_PENDING GC role absence")
			return
		}
		t.Log("CLEANED GC role owned role", role)
	})
	aGCRoleExec(t, x.ctx, x.root, "assign-isolated-role", "GRANT '"+role+"'@'%' TO '"+x.user+"'@'%'")
	var before, after string
	aGCRoleSQL(t, "inactive-role", conn.QueryRowContext(x.ctx, "SELECT CURRENT_ROLE()").Scan(&before))
	_, err := conn.ExecContext(x.ctx, "SET ROLE '"+role+"'@'%'")
	aGCRoleSQL(t, "activate-isolated-role", err)
	aGCRoleSQL(t, "active-role", conn.QueryRowContext(x.ctx, "SELECT CURRENT_ROLE()").Scan(&after))
	if before != "NONE" || after == "NONE" || !strings.Contains(after, role) {
		t.Fatal("actual role activation not observed")
	}
	tx := x.begin(t, conn)
	if g, e := x.source(t).Lock(x.ctx, tx, x.hint); e == nil || g != nil {
		t.Fatal("active role accepted")
	}
	t.Log("OBSERVED CURRENT_ROLE activation and component denial; assigned roles also change the pinned direct-grant set")
}

func (x *aGCRoleFixture) foreignReference(t *testing.T, conn *sql.Conn, cascade bool) {
	t.Helper()
	foreign := "agcfk_" + strings.TrimPrefix(x.user, "a_gc_")
	aGCRoleExec(t, x.ctx, x.root, "create-owned-foreign-schema", "CREATE DATABASE `"+foreign+"`")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		var server string
		if x.root.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&server) != nil || server != x.c.Database.ServerUUID || !regexp.MustCompile(`^agcfk_[a-f0-9]{20}$`).MatchString(foreign) {
			t.Error("CLEANUP_PENDING GC foreign schema identity")
			return
		}
		if _, e := x.root.ExecContext(ctx, "DROP DATABASE `"+foreign+"`"); e != nil {
			t.Error("CLEANUP_PENDING GC foreign schema")
			return
		}
		var count int
		if x.root.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=?", foreign).Scan(&count) != nil || count != 0 {
			t.Error("CLEANUP_PENDING GC foreign schema absence")
			return
		}
		t.Log("CLEANED GC role owned foreign schema", foreign)
	})
	var columnType string
	aGCRoleSQL(t, "audit-fk-column-type", x.root.QueryRowContext(x.ctx, "SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='audit_logs' AND COLUMN_NAME='id'").Scan(&columnType))
	if !regexp.MustCompile(`^(int|bigint)(\([0-9]{1,2}\))?( unsigned)?$`).MatchString(columnType) {
		t.Fatal("unsupported audit FK column type")
	}
	rule := "RESTRICT"
	if cascade {
		rule = "CASCADE"
	}
	aGCRoleExec(t, x.ctx, x.root, "create-owned-incoming-fk", "CREATE TABLE `"+foreign+"`.gc_incoming_audit(id INT PRIMARY KEY,audit_id "+columnType+",CONSTRAINT gc_incoming FOREIGN KEY(audit_id) REFERENCES `"+x.c.Database.Database+"`.audit_logs(id) ON DELETE "+rule+") ENGINE=InnoDB")
	old := x.c.Metadata.ForeignKeys
	x.c.Metadata = aGCRoleMetadata(t, x.ctx, x.root)
	if x.c.Metadata.ForeignKeys == old || !reflect.DeepEqual(aGCRoleMetadata(t, x.ctx, conn), x.c.Metadata) {
		t.Fatal("cross-schema incoming FK absent from restricted metadata or privileged observer")
	}
	tx := x.begin(t, conn)
	if g, err := x.source(t).Lock(x.ctx, tx, x.hint); err == nil || g != nil {
		t.Fatal("foreign-schema reference accepted even after privileged metadata re-pin")
	}
	t.Log("OBSERVED complete cross-schema incoming FK visibility and structural denial after privileged re-pin", rule)
	aGCRoleSQL(t, "foreign-reference-rollback", tx.Rollback())
	aGCRoleExec(t, x.ctx, x.root, "foreign-reference-global-revoke", "REVOKE REFERENCES ON *.* FROM '"+x.user+"'@'%'")
	newConn := x.conn(t, x.pool(t))
	visible := aGCRoleMetadata(t, x.ctx, newConn)
	t.Log("OBSERVED foreign-schema FK pin matches privileged observer after REFERENCES revocation=", visible.ForeignKeys == x.c.Metadata.ForeignKeys)
	tx = x.begin(t, newConn)
	if g, err := x.source(t).Lock(x.ctx, tx, x.hint); err == nil || g != nil {
		t.Fatal("revoked metadata visibility prerequisite accepted")
	}
}
