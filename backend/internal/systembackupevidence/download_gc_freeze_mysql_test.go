//go:build systembackup_mysql

package systembackupevidence

import (
	"context"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// Prerequisite experiment, deliberately separate from Collect and its grants
// policy. Root is only the administrator of the UID-bound disposable fixture.
// BACKUP_ADMIN below is a synthetic account grant, never a production approval.
const dGCFreezeWitnessSQL = `SELECT LOCK_TYPE,LOCK_DURATION,LOCK_STATUS FROM performance_schema.metadata_locks WHERE OWNER_THREAD_ID=? AND OBJECT_TYPE='BACKUP LOCK'`

var dGCFreezeControls = []string{
	"privilege_deny", "transaction_commit", "transaction_rollback", "unlock_no_commit",
	"legal_dml", "multiple_holders", "killed_holder", "pool_reuse", "temporary_shadow_and_fresh_session",
}

type dGCFreezeDDL struct {
	name, prepare, statement, check string
}

// @d@ and @p@ are validated, quoted, newly owned schema identifiers. @u@
// is a validated, newly owned account literal. No SQL comes from the caller.
var dGCFreezeDDLs = []dGCFreezeDDL{
	{"table_create", "", "CREATE TABLE @d@.created_table(id INT PRIMARY KEY)", "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=? AND TABLE_NAME='created_table'"},
	{"table_alter", "CREATE TABLE @d@.altered_table(id INT PRIMARY KEY)", "ALTER TABLE @d@.altered_table ADD COLUMN added INT", "SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME='altered_table' AND COLUMN_NAME='added'"},
	{"table_drop", "CREATE TABLE @d@.dropped_table(id INT PRIMARY KEY)", "DROP TABLE @d@.dropped_table", "SELECT 1-COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=? AND TABLE_NAME='dropped_table'"},
	{"table_rename", "CREATE TABLE @d@.rename_source(id INT PRIMARY KEY)", "RENAME TABLE @d@.rename_source TO @d@.rename_target", "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=? AND TABLE_NAME='rename_target'"},
	{"incoming_foreign_key", "CREATE TABLE @p@.incoming_child(id INT PRIMARY KEY, parent_id INT)", "ALTER TABLE @p@.incoming_child ADD CONSTRAINT incoming_fk FOREIGN KEY(parent_id) REFERENCES @d@.canary(id)", "SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE WHERE REFERENCED_TABLE_SCHEMA=? AND REFERENCED_TABLE_NAME='canary' AND CONSTRAINT_NAME='incoming_fk'"},
	{"procedure_create", "", "CREATE PROCEDURE @d@.created_proc() SELECT 1", "SELECT COUNT(*) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=? AND ROUTINE_NAME='created_proc'"},
	{"procedure_alter", "CREATE PROCEDURE @d@.altered_proc() SELECT 1", "ALTER PROCEDURE @d@.altered_proc COMMENT 'after_freeze'", "SELECT COUNT(*) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=? AND ROUTINE_NAME='altered_proc' AND ROUTINE_COMMENT='after_freeze'"},
	{"procedure_drop", "CREATE PROCEDURE @d@.dropped_proc() SELECT 1", "DROP PROCEDURE @d@.dropped_proc", "SELECT 1-COUNT(*) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=? AND ROUTINE_NAME='dropped_proc'"},
	{"function_create", "", "CREATE FUNCTION @d@.created_func() RETURNS INT DETERMINISTIC NO SQL RETURN 1", "SELECT COUNT(*) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=? AND ROUTINE_NAME='created_func'"},
	{"function_alter", "CREATE FUNCTION @d@.altered_func() RETURNS INT DETERMINISTIC NO SQL RETURN 1", "ALTER FUNCTION @d@.altered_func COMMENT 'after_freeze'", "SELECT COUNT(*) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=? AND ROUTINE_NAME='altered_func' AND ROUTINE_COMMENT='after_freeze'"},
	{"function_drop", "CREATE FUNCTION @d@.dropped_func() RETURNS INT DETERMINISTIC NO SQL RETURN 1", "DROP FUNCTION @d@.dropped_func", "SELECT 1-COUNT(*) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=? AND ROUTINE_NAME='dropped_func'"},
	{"trigger_create", "", "CREATE TRIGGER @d@.created_trigger BEFORE INSERT ON @d@.canary FOR EACH ROW SET NEW.v=NEW.v", "SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=? AND TRIGGER_NAME='created_trigger'"},
	{"trigger_drop", "CREATE TRIGGER @d@.dropped_trigger BEFORE UPDATE ON @d@.canary FOR EACH ROW SET NEW.v=NEW.v", "DROP TRIGGER @d@.dropped_trigger", "SELECT 1-COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=? AND TRIGGER_NAME='dropped_trigger'"},
	{"event_create", "", "CREATE EVENT @d@.created_event ON SCHEDULE AT CURRENT_TIMESTAMP + INTERVAL 1 DAY DISABLE DO SET @d_gc_unused=1", "SELECT COUNT(*) FROM information_schema.EVENTS WHERE EVENT_SCHEMA=? AND EVENT_NAME='created_event' AND STATUS='DISABLED'"},
	{"event_alter", "CREATE EVENT @d@.altered_event ON SCHEDULE AT CURRENT_TIMESTAMP + INTERVAL 1 DAY DISABLE DO SET @d_gc_unused=1", "ALTER EVENT @d@.altered_event COMMENT 'after_freeze'", "SELECT COUNT(*) FROM information_schema.EVENTS WHERE EVENT_SCHEMA=? AND EVENT_NAME='altered_event' AND EVENT_COMMENT='after_freeze'"},
	{"event_drop", "CREATE EVENT @d@.dropped_event ON SCHEDULE AT CURRENT_TIMESTAMP + INTERVAL 1 DAY DISABLE DO SET @d_gc_unused=1", "DROP EVENT @d@.dropped_event", "SELECT 1-COUNT(*) FROM information_schema.EVENTS WHERE EVENT_SCHEMA=? AND EVENT_NAME='dropped_event'"},
	{"view_create", "", "CREATE VIEW @d@.created_view AS SELECT id FROM @d@.canary", "SELECT COUNT(*) FROM information_schema.VIEWS WHERE TABLE_SCHEMA=? AND TABLE_NAME='created_view'"},
	{"view_alter", "CREATE VIEW @d@.altered_view AS SELECT id FROM @d@.canary", "ALTER VIEW @d@.altered_view AS SELECT id,v FROM @d@.canary", "SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME='altered_view' AND COLUMN_NAME='v'"},
	{"view_algorithm", "CREATE ALGORITHM=MERGE VIEW @d@.algorithm_view AS SELECT id FROM @d@.canary", "ALTER ALGORITHM=TEMPTABLE VIEW @d@.algorithm_view AS SELECT id FROM @d@.canary", "SELECT COUNT(*) FROM information_schema.VIEWS WHERE TABLE_SCHEMA=? AND TABLE_NAME='algorithm_view' AND IS_UPDATABLE='NO'"},
	{"view_drop", "CREATE VIEW @d@.dropped_view AS SELECT id FROM @d@.canary", "DROP VIEW @d@.dropped_view", "SELECT 1-COUNT(*) FROM information_schema.VIEWS WHERE TABLE_SCHEMA=? AND TABLE_NAME='dropped_view'"},
	{"account_create", "", "CREATE USER @u@ ACCOUNT LOCK", ""},
	{"account_alter", "", "ALTER USER @u@ ACCOUNT UNLOCK", ""},
	{"account_drop", "", "DROP USER @u@", ""},
	{"account_grant", "", "GRANT SELECT ON @d@.* TO @u@", ""},
	{"account_revoke", "", "REVOKE SELECT ON @d@.* FROM @u@", ""},
}

func dGCFreezeIdentifier(s string) (string, error) {
	if !regexp.MustCompile(`^dgcf_[a-f0-9]{20}(_peer)?$`).MatchString(s) {
		return "", ErrInvalid
	}
	return "`" + s + "`", nil
}

func TestDDownloadGCFreezeMySQLSeed(t *testing.T) {
	t.Run("closed_case_catalog", func(t *testing.T) {
		seen := map[string]bool{}
		for _, c := range dGCFreezeDDLs {
			if seen[c.name] || !regexp.MustCompile(`^[a-z_]+$`).MatchString(c.name) || c.statement == "" || strings.Contains(c.statement, ";") || !strings.HasPrefix(c.name, "account_") && !strings.Contains(c.statement, "@d@") {
				t.Fatal("invalid DDL catalog")
			}
			seen[c.name] = true
			if strings.HasPrefix(c.name, "account_") != strings.Contains(c.statement, "@u@") || c.check != "" && strings.Count(c.check, "?") != 1 {
				t.Fatal("DDL ownership/check binding")
			}
		}
		for _, name := range dGCFreezeControls {
			if seen[name] {
				t.Fatal("duplicate control")
			}
			seen[name] = true
		}
		if len(seen) != 34 {
			t.Fatal("freeze experiment count")
		}
	})
	t.Run("identifier_boundary", func(t *testing.T) {
		for _, name := range []string{"", "clawmanager", "dgcf_0123456789abcdef0123`", "dgcf_0123456789abcdef0123;DROP", "dgcf_0123456789abcdef0123_peer_extra"} {
			if _, err := dGCFreezeIdentifier(name); err == nil {
				t.Fatal("unsafe schema accepted")
			}
		}
		for _, name := range []string{"dgcf_0123456789abcdef0123", "dgcf_0123456789abcdef0123_peer"} {
			if got, err := dGCFreezeIdentifier(name); err != nil || got != "`"+name+"`" {
				t.Fatal("owned schema rejected")
			}
		}
	})
	t.Run("witness_boundary", func(t *testing.T) {
		if !dGCFreezeWitness([][3]string{{"SHARED", "EXPLICIT", "GRANTED"}}, true) || dGCFreezeWitness(nil, true) || dGCFreezeWitness([][3]string{{"SHARED", "EXPLICIT", "PENDING"}}, true) || dGCFreezeWitness([][3]string{{"SHARED", "TRANSACTION", "GRANTED"}}, true) || dGCFreezeWitness([][3]string{{"INTENTION_EXCLUSIVE", "STATEMENT", "GRANTED"}}, false) || dGCFreezeWitness([][3]string{{"SHARED", "EXPLICIT", "GRANTED"}, {"SHARED", "EXPLICIT", "GRANTED"}}, true) {
			t.Fatal("ambiguous or wrong lock witness accepted")
		}
		if !dGCFreezeWitness([][3]string{{"INTENTION_EXCLUSIVE", "TRANSACTION", "PENDING"}}, false) {
			t.Fatal("waiter witness rejected")
		}
	})
	t.Log("PASS freeze prerequisite seed cases=34 actual_mysql=not_run full_gc=not_run freeze_adapter=not_wired role_approval=no production_approval=no")
}

// Exactly one ticket on the exact mapped process. Waiter duration is observed,
// not assumed; different DDL paths may choose different durations.
func dGCFreezeWitness(rows [][3]string, holder bool) bool {
	if len(rows) != 1 {
		return false
	}
	if holder {
		return rows[0] == [3]string{"SHARED", "EXPLICIT", "GRANTED"}
	}
	return rows[0][0] == "INTENTION_EXCLUSIVE" && rows[0][2] == "PENDING" && (rows[0][1] == "STATEMENT" || rows[0][1] == "TRANSACTION" || rows[0][1] == "EXPLICIT")
}

func dGCFreezeOK(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	var me *mysql.MySQLError
	if errors.As(err, &me) {
		t.Fatalf("freeze experiment SQL error number=%d (details redacted)", me.Number)
	}
	t.Fatal("freeze experiment connection/context error (details redacted)")
}

type dGCFreezeFixture struct {
	ctx                                                   context.Context
	admin                                                 *sql.DB
	cfg                                                   *mysql.Config
	db, peer, user, denied, target, password, server, uid string
	createdSchemas                                        map[string]bool
	createdUsers                                          map[string]bool
	threads                                               map[int64]int64
}

func newDGCFreezeFixture(t *testing.T) *dGCFreezeFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	t.Cleanup(cancel)
	admin := downloadAuditProbeDatabase(t, ctx)
	capsule, err := os.Open(os.Getenv("D_PROVIDER_REGISTRATION_DDL"))
	dGCFreezeOK(t, err)
	raw, err := io.ReadAll(io.LimitReader(capsule, 65537))
	dGCFreezeOK(t, err)
	dGCFreezeOK(t, capsule.Close())
	if len(raw) > 65536 || hash(raw) != os.Getenv("D_PROVIDER_REGISTRATION_DDL_SHA256") || hash(raw) != hash(aDownloadMFASeed) {
		t.Fatal("freeze fixture capsule differs from binary-pinned inputs")
	}
	input, err := decodeADownloadMFAInputs(raw)
	dGCFreezeOK(t, err)
	var ledger []string
	rows, err := admin.QueryContext(ctx, "SELECT filename FROM schema_migrations ORDER BY filename")
	dGCFreezeOK(t, err)
	for rows.Next() {
		var name string
		dGCFreezeOK(t, rows.Scan(&name))
		ledger = append(ledger, name)
	}
	dGCFreezeOK(t, rows.Err())
	dGCFreezeOK(t, rows.Close())
	if !reflect.DeepEqual(ledger, input.Files) {
		t.Fatal("freeze fixture formal migration ledger differs")
	}
	var entropy [26]byte
	_, err = rand.Read(entropy[:])
	dGCFreezeOK(t, err)
	nonce := hex.EncodeToString(entropy[:10])
	f := &dGCFreezeFixture{ctx: ctx, admin: admin, db: "dgcf_" + nonce, peer: "dgcf_" + nonce + "_peer", user: "dgcf_" + nonce + "_b", denied: "dgcf_" + nonce + "_n", target: "dgcf_" + nonce + "_t", password: hex.EncodeToString(entropy[10:]), uid: os.Getenv("D_INVARIANT_NAMESPACE_UID"), createdSchemas: map[string]bool{}, createdUsers: map[string]bool{}, threads: map[int64]int64{}}
	var version, instrument string
	dGCFreezeOK(t, admin.QueryRowContext(ctx, "SELECT @@server_uuid,VERSION()").Scan(&f.server, &version))
	if !strings.HasPrefix(version, "8.4.") {
		t.Fatal("freeze experiment requires MySQL 8.4")
	}
	dGCFreezeOK(t, admin.QueryRowContext(ctx, "SELECT ENABLED FROM performance_schema.setup_instruments WHERE NAME='wait/lock/metadata/sql/mdl'").Scan(&instrument))
	if instrument != "YES" {
		t.Fatal("metadata lock instrument unavailable; not enabled by probe")
	}
	t.Cleanup(func() { f.cleanup(t) })
	for _, name := range []string{f.db, f.peer} {
		q, _ := dGCFreezeIdentifier(name)
		f.exec(t, "CREATE DATABASE "+q)
		// Do not drop an unmarked schema if setup failed partway through.
		f.createdSchemas[name] = false
		f.exec(t, "CREATE TABLE "+q+".freeze_owner(uid VARCHAR(36) PRIMARY KEY,server_uuid VARCHAR(36))")
		f.exec(t, "INSERT INTO "+q+".freeze_owner VALUES(?,?)", f.uid, f.server)
		f.createdSchemas[name] = true
	}
	q, _ := dGCFreezeIdentifier(f.db)
	f.exec(t, "CREATE TABLE "+q+".canary(id INT PRIMARY KEY,v INT NOT NULL) ENGINE=InnoDB")
	f.exec(t, "INSERT INTO "+q+".canary VALUES(1,0),(2,0)")
	for _, user := range []string{f.user, f.denied, f.target} {
		f.exec(t, "CREATE USER '"+user+"'@'%' IDENTIFIED BY '"+f.password+"'")
		f.createdUsers[user] = true
	}
	for _, user := range []string{f.user, f.denied} {
		f.exec(t, "GRANT SELECT,INSERT,UPDATE,DELETE,CREATE TEMPORARY TABLES ON "+q+".* TO '"+user+"'@'%'")
	}
	f.exec(t, "GRANT BACKUP_ADMIN ON *.* TO '"+f.user+"'@'%'")
	f.cfg = mysql.NewConfig()
	f.cfg.User = f.user
	f.cfg.Passwd = f.password
	f.cfg.Net = "tcp"
	host := os.Getenv("D_INVARIANT_MYSQL_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	f.cfg.Addr = net.JoinHostPort(host, "3306")
	f.cfg.DBName = f.db
	f.cfg.ParseTime = true
	f.cfg.Loc = time.UTC
	f.cfg.Timeout = 5 * time.Second
	f.cfg.ReadTimeout = 12 * time.Second
	f.cfg.WriteTimeout = 12 * time.Second
	f.cfg.Params = map[string]string{"time_zone": "'+00:00'", "lock_wait_timeout": "5"}
	t.Logf("FREEZE_FIXTURE mysql=%s formal_migrations=%d synthetic_accounts=yes production_approval=no", version, len(ledger))
	return f
}

func (f *dGCFreezeFixture) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	_, err := f.admin.ExecContext(f.ctx, q, args...)
	dGCFreezeOK(t, err)
}
func (f *dGCFreezeFixture) pool(t *testing.T, user string, idle int) *sql.DB {
	t.Helper()
	cfg := f.cfg.Clone()
	cfg.User = user
	db, err := sql.Open("mysql", cfg.FormatDSN())
	dGCFreezeOK(t, err)
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(idle)
	t.Cleanup(func() { dGCFreezeOK(t, db.Close()) })
	return db
}
func (f *dGCFreezeFixture) conn(t *testing.T, db *sql.DB) (*sql.Conn, int64) {
	t.Helper()
	c, err := db.Conn(f.ctx)
	dGCFreezeOK(t, err)
	t.Cleanup(func() { _ = c.Raw(func(any) error { return driver.ErrBadConn }); _ = c.Close() })
	var id int64
	var server, database, account, role, zone string
	dGCFreezeOK(t, c.QueryRowContext(f.ctx, "SELECT CONNECTION_ID(),@@server_uuid,DATABASE(),CURRENT_USER(),CURRENT_ROLE(),@@session.time_zone").Scan(&id, &server, &database, &account, &role, &zone))
	if id <= 0 || server != f.server || database != f.db || role != "NONE" || zone != "+00:00" || account != f.user+"@%" && account != f.denied+"@%" {
		t.Fatal("freeze session identity changed")
	}
	f.pinThread(t, id)
	return c, id
}

// Pin while the session is alive. An orphan ticket must remain observable
// after threads drops its row; disappearance of that row is not unlock proof.
func (f *dGCFreezeFixture) pinThread(t *testing.T, id int64) {
	t.Helper()
	var thread int64
	dGCFreezeOK(t, f.admin.QueryRowContext(f.ctx, "SELECT THREAD_ID FROM performance_schema.threads WHERE PROCESSLIST_ID=?", id).Scan(&thread))
	if id <= 0 || thread <= 0 {
		t.Fatal("invalid process/thread identity")
	}
	if previous, ok := f.threads[id]; ok && previous != thread {
		t.Fatal("process/thread mapping changed")
	}
	f.threads[id] = thread
}
func (f *dGCFreezeFixture) tickets(t *testing.T, id int64) [][3]string {
	t.Helper()
	thread, ok := f.threads[id]
	if !ok || thread <= 0 {
		t.Fatal("unbound backup-lock owner thread")
	}
	rows, err := f.admin.QueryContext(f.ctx, dGCFreezeWitnessSQL, thread)
	dGCFreezeOK(t, err)
	defer rows.Close()
	var out [][3]string
	for rows.Next() {
		var r [3]string
		dGCFreezeOK(t, rows.Scan(&r[0], &r[1], &r[2]))
		out = append(out, r)
	}
	dGCFreezeOK(t, rows.Err())
	return out
}
func (f *dGCFreezeFixture) held(t *testing.T, id int64) {
	t.Helper()
	if !dGCFreezeWitness(f.tickets(t, id), true) {
		t.Fatal("exact session has no single granted explicit backup lock")
	}
}
func (f *dGCFreezeFixture) released(t *testing.T, id int64) {
	t.Helper()
	if len(f.tickets(t, id)) != 0 {
		t.Fatal("exact session backup lock remains")
	}
}
func (f *dGCFreezeFixture) command(t *testing.T, c *sql.Conn, q string) {
	t.Helper()
	_, err := c.ExecContext(f.ctx, q)
	dGCFreezeOK(t, err)
}
func (f *dGCFreezeFixture) holder(t *testing.T) (*sql.Conn, int64) {
	t.Helper()
	c, id := f.conn(t, f.pool(t, f.user, 0))
	f.command(t, c, "LOCK INSTANCE FOR BACKUP")
	f.held(t, id)
	return c, id
}
func (f *dGCFreezeFixture) value(t *testing.T, id int) int {
	t.Helper()
	q, _ := dGCFreezeIdentifier(f.db)
	var n int
	dGCFreezeOK(t, f.admin.QueryRowContext(f.ctx, "SELECT v FROM "+q+".canary WHERE id=?", id).Scan(&n))
	return n
}

func (f *dGCFreezeFixture) blockedDDL(t *testing.T, tc dGCFreezeDDL) {
	t.Helper()
	d, _ := dGCFreezeIdentifier(f.db)
	p, _ := dGCFreezeIdentifier(f.peer)
	u := "'" + f.target + "'@'%'"
	if tc.name == "account_create" {
		u = "'" + f.user + "_c'@'%'"
	}
	r := strings.NewReplacer("@d@", d, "@p@", p, "@u@", u)
	if tc.prepare != "" {
		f.exec(t, r.Replace(tc.prepare))
	}
	// Independently prepare account cases; a failed predecessor cannot make a
	// later case pass by producing an unrelated SQL error.
	if strings.HasPrefix(tc.name, "account_") && tc.name != "account_create" {
		f.exec(t, "DROP USER IF EXISTS "+u)
		f.exec(t, "CREATE USER "+u+" ACCOUNT LOCK")
		if tc.name == "account_revoke" {
			f.exec(t, "GRANT SELECT ON "+d+".* TO "+u)
		}
	}
	c, id := f.holder(t)
	waiter, err := f.admin.Conn(f.ctx)
	dGCFreezeOK(t, err)
	defer waiter.Close()
	_, err = waiter.ExecContext(f.ctx, "SET SESSION lock_wait_timeout=5")
	dGCFreezeOK(t, err)
	var wid int64
	dGCFreezeOK(t, waiter.QueryRowContext(f.ctx, "SELECT CONNECTION_ID()").Scan(&wid))
	f.pinThread(t, wid)
	ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := waiter.ExecContext(ctx, r.Replace(tc.statement)); done <- err }()
	// Always stop and reap the waiter before returning from a failed test.
	completed := false
	defer func() {
		cancel()
		if !completed {
			<-done
		}
	}()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for !dGCFreezeWitness(f.tickets(t, wid), false) {
		select {
		case err := <-done:
			completed = true
			dGCFreezeOK(t, err)
			t.Fatal("DDL completed without exact pending backup-lock witness")
		case <-deadline.C:
			t.Fatal("no exact pending backup-lock witness before bounded deadline")
		case <-tick.C:
		}
	}
	f.held(t, id)
	t.Logf("FREEZE_WAIT holder_connection=%d waiter_connection=%d holder_thread=%d waiter_thread=%d holder=SHARED/EXPLICIT/GRANTED waiter=INTENTION_EXCLUSIVE/PENDING case=%s", id, wid, f.threads[id], f.threads[wid], tc.name)
	f.command(t, c, "UNLOCK INSTANCE")
	f.released(t, id)
	err = <-done
	completed = true
	dGCFreezeOK(t, err)
	f.released(t, wid)
	if tc.check != "" {
		var n int
		dGCFreezeOK(t, f.admin.QueryRowContext(f.ctx, tc.check, f.db).Scan(&n))
		if n != 1 {
			t.Fatal("released DDL did not produce expected metadata")
		}
	}
	if tc.name == "account_create" {
		f.createdUsers[f.user+"_c"] = true
	}
	if strings.HasPrefix(tc.name, "account_") {
		user := f.target
		if tc.name == "account_create" {
			user = f.user + "_c"
		}
		var n int
		query := "SELECT COUNT(*) FROM mysql.user WHERE User=? AND Host='%'"
		expected := 1
		switch tc.name {
		case "account_drop":
			expected = 0
		case "account_alter":
			query += " AND account_locked='N'"
		case "account_grant", "account_revoke":
			query = "SELECT COUNT(*) FROM information_schema.SCHEMA_PRIVILEGES WHERE GRANTEE=CONCAT(CHAR(39),?,CHAR(39),'@',CHAR(39),'%',CHAR(39)) AND TABLE_SCHEMA='" + f.db + "' AND PRIVILEGE_TYPE='SELECT'"
			if tc.name == "account_revoke" {
				expected = 0
			}
		}
		dGCFreezeOK(t, f.admin.QueryRowContext(f.ctx, query, user).Scan(&n))
		if n != expected {
			t.Fatal("released account statement effect differs")
		}
	}
}

func TestDDownloadGCFreezeMySQL(t *testing.T) {
	f := newDGCFreezeFixture(t)
	for _, tc := range dGCFreezeDDLs {
		t.Run(tc.name, func(t *testing.T) { f.blockedDDL(t, tc) })
	}
	t.Run("privilege_deny", func(t *testing.T) {
		c, id := f.conn(t, f.pool(t, f.denied, 0))
		_, err := c.ExecContext(f.ctx, "LOCK INSTANCE FOR BACKUP")
		var me *mysql.MySQLError
		if !errors.As(err, &me) || me.Number != 1227 {
			t.Fatal("missing BACKUP_ADMIN did not deny with native 1227")
		}
		f.released(t, id)
	})
	for _, commit := range []bool{true, false} {
		name := "transaction_rollback"
		if commit {
			name = "transaction_commit"
		}
		t.Run(name, func(t *testing.T) {
			f.exec(t, "UPDATE `"+f.db+"`.canary SET v=0 WHERE id=1")
			c, id := f.holder(t)
			tx, err := c.BeginTx(f.ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			dGCFreezeOK(t, err)
			defer tx.Rollback()
			_, err = tx.ExecContext(f.ctx, "UPDATE canary SET v=17 WHERE id=1")
			dGCFreezeOK(t, err)
			if commit {
				err = tx.Commit()
			} else {
				err = tx.Rollback()
			}
			dGCFreezeOK(t, err)
			f.held(t, id)
			want := 0
			if commit {
				want = 17
			}
			if f.value(t, 1) != want {
				t.Fatal("transaction canary differs")
			}
			f.command(t, c, "UNLOCK INSTANCE")
			f.released(t, id)
		})
	}
	t.Run("unlock_no_commit", func(t *testing.T) {
		f.exec(t, "UPDATE `"+f.db+"`.canary SET v=0 WHERE id=1")
		c, id := f.holder(t)
		tx, err := c.BeginTx(f.ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
		dGCFreezeOK(t, err)
		defer tx.Rollback()
		_, err = tx.ExecContext(f.ctx, "UPDATE canary SET v=23 WHERE id=1")
		dGCFreezeOK(t, err)
		_, err = tx.ExecContext(f.ctx, "UNLOCK INSTANCE")
		dGCFreezeOK(t, err)
		f.released(t, id)
		dGCFreezeOK(t, tx.Rollback())
		if f.value(t, 1) != 0 {
			t.Fatal("UNLOCK implicitly committed canary")
		}
	})
	t.Run("legal_dml", func(t *testing.T) {
		c, id := f.holder(t)
		f.exec(t, "UPDATE `"+f.db+"`.canary SET v=31 WHERE id=2")
		if f.value(t, 2) != 31 {
			t.Fatal("legal DML lost")
		}
		f.held(t, id)
		f.command(t, c, "UNLOCK INSTANCE")
		f.released(t, id)
	})
	t.Run("multiple_holders", func(t *testing.T) {
		a, aid := f.holder(t)
		b, bid := f.holder(t)
		if aid == bid {
			t.Fatal("holders share a physical connection")
		}
		f.command(t, a, "UNLOCK INSTANCE")
		f.released(t, aid)
		f.held(t, bid)
		f.command(t, b, "UNLOCK INSTANCE")
		f.released(t, bid)
	})
	t.Run("killed_holder", func(t *testing.T) {
		f.exec(t, "UPDATE `"+f.db+"`.canary SET v=0 WHERE id=1")
		c, id := f.holder(t)
		tx, err := c.BeginTx(f.ctx, nil)
		dGCFreezeOK(t, err)
		defer tx.Rollback()
		_, err = tx.ExecContext(f.ctx, "UPDATE canary SET v=43 WHERE id=1")
		dGCFreezeOK(t, err)
		// Identity was obtained directly from the exact owned account connection.
		f.exec(t, "KILL CONNECTION "+strconv.FormatInt(id, 10))
		if c.PingContext(f.ctx) == nil {
			t.Fatal("killed holder still usable")
		}
		deadline := time.Now().Add(3 * time.Second)
		for len(f.tickets(t, id)) != 0 {
			if time.Now().After(deadline) {
				t.Fatal("killed holder backup lock remains")
			}
			time.Sleep(10 * time.Millisecond)
		}
		if f.value(t, 1) != 0 {
			t.Fatal("killed holder writes did not roll back")
		}
	})
	t.Run("pool_reuse", func(t *testing.T) {
		db := f.pool(t, f.user, 1)
		db.SetMaxOpenConns(1)
		c, id := f.conn(t, db)
		f.command(t, c, "LOCK INSTANCE FOR BACKUP")
		f.held(t, id)
		f.command(t, c, "UNLOCK INSTANCE")
		f.released(t, id)
		dGCFreezeOK(t, c.Close())
		next, nid := f.conn(t, db)
		if nid != id {
			t.Fatal("known pool-return control did not reuse exact session")
		}
		f.released(t, nid)
		dGCFreezeOK(t, next.Close())
	})
	t.Run("temporary_shadow_and_fresh_session", func(t *testing.T) {
		db := f.pool(t, f.user, 1)
		db.SetMaxOpenConns(1)
		c, id := f.conn(t, db)
		f.command(t, c, "LOCK INSTANCE FOR BACKUP")
		f.held(t, id)
		f.command(t, c, "CREATE TEMPORARY TABLE canary(id INT PRIMARY KEY,v INT NOT NULL)")
		f.command(t, c, "INSERT INTO canary VALUES(1,99)")
		f.command(t, c, "SET @d_gc_pool_canary=77")
		f.command(t, c, "SET SESSION lock_wait_timeout=7")
		f.held(t, id)
		f.command(t, c, "UNLOCK INSTANCE")
		dGCFreezeOK(t, c.Close())
		next, nid := f.conn(t, db)
		var shadow, variable, wait int
		dGCFreezeOK(t, next.QueryRowContext(f.ctx, "SELECT v,@d_gc_pool_canary,@@session.lock_wait_timeout FROM canary WHERE id=1").Scan(&shadow, &variable, &wait))
		if nid != id || shadow != 99 || variable != 77 || wait != 7 {
			t.Fatal("stale pooled session control not reproduced")
		}
		f.released(t, nid)
		if err := next.Raw(func(any) error { return driver.ErrBadConn }); !errors.Is(err, driver.ErrBadConn) {
			t.Fatal("physical discard contract changed")
		}
		_ = next.Close()
		fresh, fid := f.conn(t, db)
		var clean int
		var missing sql.NullInt64
		dGCFreezeOK(t, fresh.QueryRowContext(f.ctx, "SELECT v,@d_gc_pool_canary,@@session.lock_wait_timeout FROM canary WHERE id=1").Scan(&clean, &missing, &wait))
		if fid == id || clean != f.value(t, 1) || missing.Valid || wait != 5 {
			t.Fatal("physical discard did not produce a clean fresh session")
		}
		f.released(t, fid)
	})
	t.Log("PASS freeze prerequisite cases=34 scope=synthetic full_gc=not_run freeze_adapter=not_wired role_approval=no human_mfa=no provider_read=no production_approval=no")
}

func (f *dGCFreezeFixture) cleanup(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var server string
	if f.admin.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&server) != nil || server != f.server {
		t.Error("CLEANUP_PENDING freeze fixture server identity")
		return
	}
	// Accounts are exact unpredictable names created after the parent UID check.
	for user := range f.createdUsers {
		if !regexp.MustCompile(`^dgcf_[a-f0-9]{20}_[bnt](_c)?$`).MatchString(user) {
			t.Error("CLEANUP_PENDING freeze account identity")
			continue
		}
		if _, err := f.admin.ExecContext(ctx, "DROP USER IF EXISTS '"+user+"'@'%'"); err != nil {
			t.Error("CLEANUP_PENDING freeze account " + user)
		}
	}
	for _, name := range []string{f.peer, f.db} {
		marked, created := f.createdSchemas[name]
		if !created {
			continue
		}
		q, err := dGCFreezeIdentifier(name)
		if err != nil || !marked {
			t.Error("CLEANUP_PENDING freeze unmarked schema " + name)
			continue
		}
		var uid, pin string
		if f.admin.QueryRowContext(ctx, "SELECT uid,server_uuid FROM "+q+".freeze_owner").Scan(&uid, &pin) != nil || uid != f.uid || pin != server {
			t.Error("CLEANUP_PENDING freeze schema marker " + name)
			continue
		}
		if _, err = f.admin.ExecContext(ctx, "DROP DATABASE "+q); err != nil {
			t.Error("CLEANUP_PENDING freeze schema " + name)
			continue
		}
		var n int
		if f.admin.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=?", name).Scan(&n) != nil || n != 0 {
			t.Error("CLEANUP_PENDING freeze schema absence " + name)
		}
	}
}
