package systembackupexecution

import (
	"context"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/worker"
	"github.com/go-sql-driver/mysql"
)

// Actual local MySQL table ACL/session/RR/export checks. The deliberately
// minimal empty business schemas exercise scope admission, not original DDL,
// full business constraints, physical source consistency or TLS deployment.
func TestDeploymentFiniteBusinessSourceAndActualCaptureMySQL(t *testing.T) {
	testDeploymentFiniteBusinessSourceMySQL(t, false)
}

func TestDeploymentLatestMigratedSchemaFiniteBusinessSourceMySQL(t *testing.T) {
	testDeploymentFiniteBusinessSourceMySQL(t, true)
}

func testDeploymentFiniteBusinessSourceMySQL(t *testing.T, originalDDL bool) {
	if originalDDL {
		testLatestMigratedSourceMySQL(t)
		return
	}
	path := os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS")
	if path == "" {
		t.Skip("requires disposable local MySQL")
	}
	var cred struct {
		Host           string
		Port           int
		User, Password string
	}
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &cred) != nil || cred.Host != "127.0.0.1" {
		t.Fatal("local source fixture credentials unavailable")
	}
	clear(raw)
	config := mysql.NewConfig()
	config.User, config.Passwd = cred.User, cred.Password
	cred.Password = ""
	config.Net = "tcp"
	config.Addr = cred.Host + ":" + strconv.Itoa(cred.Port)
	config.ParseTime = true
	admin, err := sql.Open("mysql", config.FormatDSN())
	config.Passwd = ""
	if err != nil {
		t.Fatal("local fixture admin unavailable")
	}
	defer admin.Close()
	var id [8]byte
	rand.Read(id[:])
	name := "ad_d_src_" + hex.EncodeToString(id[:])
	user := name
	var password [24]byte
	rand.Read(password[:])
	pass := hex.EncodeToString(password[:])
	clear(password[:])
	if _, err = admin.Exec("CREATE DATABASE `" + name + "`"); err != nil {
		t.Fatal("local source schema create failed")
	}
	defer admin.Exec("DROP DATABASE `" + name + "`")
	if _, err = admin.Exec("CREATE USER '" + user + "'@'127.0.0.1' IDENTIFIED BY '" + pass + "'"); err != nil {
		t.Fatal("local source account create failed")
	}
	defer admin.Exec("DROP USER '" + user + "'@'127.0.0.1'")
	for _, table := range domain.BusinessCaptureTables() {
		if _, err = admin.Exec("CREATE TABLE `" + name + "`.`" + table + "` (id BIGINT NOT NULL PRIMARY KEY) ENGINE=InnoDB"); err != nil {
			t.Fatal("local business scope table fixture failed")
		}
		if _, err = admin.Exec("GRANT SELECT ON `" + name + "`.`" + table + "` TO '" + user + "'@'127.0.0.1'"); err != nil {
			t.Fatal("local finite source grant failed")
		}
	}
	if _, err = admin.Exec("CREATE TABLE `" + name + "`.system_backup_v2_configs (id BIGINT PRIMARY KEY, secret_value TEXT) ENGINE=InnoDB"); err != nil {
		t.Fatal("owned control-row fixture", err)
	}
	if _, err = admin.Exec("INSERT INTO `" + name + "`.system_backup_v2_configs VALUES(1,'local-control-row-must-remain-unreadable')"); err != nil {
		t.Fatal(err)
	}
	owner, grantDatabase, projection, census, installCensus := installLockedSourceCensusFixture(t, admin, name, user, id)
	defer admin.Exec("DROP USER '" + owner + "'@'127.0.0.1'")
	partialRevokes := census.PartialRevokes
	if _, err = admin.Exec("INSERT INTO `" + name + "`.users VALUES(1)"); err != nil {
		t.Fatal(err)
	}
	config.User, config.Passwd, config.DBName = user, pass, name
	pass = ""
	connector, err := mysql.NewConnector(config)
	if err != nil {
		t.Fatal("local source connector unavailable")
	}
	trace := &censusTraceConnector{Connector: connector}
	reader := sql.OpenDB(trace)
	config.Passwd = ""
	defer reader.Close()
	reader.SetMaxOpenConns(1)
	// This nearby name matches the unescaped source schema's '_' pattern.
	// The original quoting helper must keep even the locked definer out of it.
	collision := strings.Replace(name, "src_", "srcx", 1)
	if _, e := admin.Exec("CREATE DATABASE `" + collision + "`"); e != nil {
		t.Fatal("owned nearby schema", e)
	}
	defer admin.Exec("DROP DATABASE `" + collision + "`")
	if _, e := admin.Exec("CREATE TABLE `" + collision + "`.scope_secret (id BIGINT PRIMARY KEY)"); e != nil {
		t.Fatal(e)
	}
	if _, e := admin.Exec("CREATE DEFINER='" + owner + "'@'127.0.0.1' PROCEDURE `" + name + "`.source_scope_probe() READS SQL DATA SQL SECURITY DEFINER SELECT * FROM `" + collision + "`.scope_secret"); e != nil {
		t.Fatal(e)
	}
	probe, e := admin.Query("CALL `" + name + "`.source_scope_probe()")
	if e == nil {
		probe.Close()
		t.Fatal("source definer schema GRANT leaked into underscore-nearby database")
	}
	if _, e := admin.Exec("DROP PROCEDURE `" + name + "`.source_scope_probe"); e != nil {
		t.Fatal(e)
	}
	if _, e := reader.Query("SELECT * FROM `" + collision + "`.scope_secret"); e == nil {
		t.Fatal("collector source rows escaped exact original schema")
	}
	var uuid string
	if admin.QueryRow("SELECT @@server_uuid").Scan(&uuid) != nil {
		t.Fatal("source server identity unavailable")
	}
	s := DeploymentService{Config: DeploymentConfig{CaptureScope: "six-part", SourceUser: user, SourceDatabase: name, SourceServerUUID: uuid}, Source: reader}
	s.captureMaterials = &productionCaptureMaterials{Operations: map[string]productionCaptureOperation{"capture-database": {Request: worker.Request{Database: &worker.DatabaseSpec{Name: name, ServerUUID: uuid, SourceScope: domain.BusinessTableSourceScope, SchemaCensus: &census}}}}}
	ctx := context.Background()
	check := func() error { return s.checkSourceIdentity(ctx, reader) }
	if err = check(); err != nil {
		t.Fatal("service finite source admission", err)
	}
	wrongMode := census
	wrongMode.PartialRevokes = !partialRevokes
	if domain.CheckBusinessSchemaCensus(ctx, reader, wrongMode) == nil {
		t.Fatal("original schema grant mode drift accepted")
	}
	tx, err := reader.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.checkSourceIdentity(ctx, tx); err != nil {
		t.Fatal("same authenticated source RR", err)
	}
	tx.Rollback()
	checks := 0
	snapshot, err := domain.CaptureBusinessSourceGuarded(ctx, reader, domain.Limits{MaxRows: 1000, MaxBytes: 32 << 20}, name, uuid, func(context.Context) error { checks++; return nil }, census)
	if err != nil || len(snapshot.Tables) != len(domain.BusinessCaptureTables()) || checks < 10 {
		t.Fatal("actual finite-source original shared export", err, len(snapshot.Tables), checks)
	}
	if _, err = reader.Exec("UPDATE users SET id=2 WHERE id=1"); err == nil {
		t.Fatal("source role could write business data")
	}
	if _, err = reader.Exec("SELECT * FROM system_backup_v2_configs"); err == nil {
		t.Fatal("source census privilege disclosed control rows")
	}
	if _, err = reader.Exec("UPDATE system_backup_v2_configs SET id=2"); err == nil {
		t.Fatal("source census privilege could write control rows")
	}
	for _, statement := range []string{"CREATE TABLE forbidden_ddl (id BIGINT)", "CREATE TRIGGER forbidden_trigger BEFORE INSERT ON users FOR EACH ROW SET NEW.id=NEW.id", "CREATE EVENT forbidden_event ON SCHEDULE EVERY 1 DAY DISABLE DO SELECT 1", "DROP PROCEDURE " + domain.SchemaCensusRoutine, "UPDATE mysql.global_grants SET WITH_GRANT_OPTION='Y'"} {
		if _, err := reader.Exec(statement); err == nil {
			t.Fatal("collector gained source DDL/privilege writes")
		}
	}
	for _, mode := range []string{"missing", "control", "write", "database-wildcard"} {
		t.Run(mode, func(t *testing.T) {
			var undo string
			switch mode {
			case "missing":
				_, err = admin.Exec("REVOKE SELECT ON `" + name + "`.skill_blobs FROM '" + user + "'@'127.0.0.1'")
				undo = "GRANT SELECT ON `" + name + "`.skill_blobs TO '" + user + "'@'127.0.0.1'"
			case "control":
				_, err = admin.Exec("GRANT SELECT ON `" + name + "`.system_backup_v2_configs TO '" + user + "'@'127.0.0.1'")
				undo = "REVOKE SELECT ON `" + name + "`.system_backup_v2_configs FROM '" + user + "'@'127.0.0.1'"
			case "write":
				_, err = admin.Exec("GRANT UPDATE ON `" + name + "`.users TO '" + user + "'@'127.0.0.1'")
				undo = "REVOKE UPDATE ON `" + name + "`.users FROM '" + user + "'@'127.0.0.1'"
			case "database-wildcard":
				_, err = admin.Exec("GRANT SELECT ON " + grantDatabase + ".* TO '" + user + "'@'127.0.0.1'")
				undo = "REVOKE SELECT ON " + grantDatabase + ".* FROM '" + user + "'@'127.0.0.1'"
			}
			if err != nil {
				t.Fatal("local ACL fault setup failed")
			}
			defer admin.Exec(undo)
			if check() == nil {
				t.Fatal("service accepted non-finite source authority")
			}
			bad, err := domain.CaptureBusinessSourceGuarded(ctx, reader, domain.Limits{MaxRows: 1000, MaxBytes: 32 << 20}, name, uuid, func(context.Context) error { return nil }, census)
			if err == nil || len(bad.Tables) != 0 {
				t.Fatal("worker accepted non-finite source authority", err)
			}
		})
	}
	for _, kind := range []string{"ungranted-table", "view", "trigger", "procedure", "function", "event", "census-definition", "role"} {
		t.Run(kind, func(t *testing.T) {
			var statement, undo, object string
			switch kind {
			case "ungranted-table":
				object = "instance_unreviewed_payload"
				statement = "CREATE TABLE `" + name + "`." + object + " (id BIGINT PRIMARY KEY) ENGINE=InnoDB"
				undo = "DROP TABLE `" + name + "`." + object
			case "view":
				object = "source_unreviewed_view"
				statement = "CREATE VIEW `" + name + "`." + object + " AS SELECT id FROM `" + name + "`.users"
				undo = "DROP VIEW `" + name + "`." + object
			case "trigger":
				object = "source_unreviewed_trigger"
				statement = "CREATE TRIGGER `" + name + "`." + object + " BEFORE INSERT ON `" + name + "`.users FOR EACH ROW SET NEW.id=NEW.id"
				undo = "DROP TRIGGER `" + name + "`." + object
			case "procedure":
				object = "source_unreviewed_routine"
				statement = "CREATE PROCEDURE `" + name + "`." + object + "() SELECT 1"
				undo = "DROP PROCEDURE `" + name + "`." + object
			case "function":
				object = "source_unreviewed_function"
				statement = "CREATE FUNCTION `" + name + "`." + object + "() RETURNS INT DETERMINISTIC NO SQL RETURN 1"
				undo = "DROP FUNCTION `" + name + "`." + object
			case "event":
				object = "source_unreviewed_event"
				statement = "CREATE EVENT `" + name + "`." + object + " ON SCHEDULE EVERY 1 DAY DISABLE DO SELECT 1"
				undo = "DROP EVENT `" + name + "`." + object
			case "census-definition":
				if _, e := admin.Exec("DROP PROCEDURE `" + name + "`.`" + domain.SchemaCensusRoutine + "`"); e != nil {
					t.Fatal(e)
				}
				statement = "CREATE DEFINER='" + owner + "'@'127.0.0.1' PROCEDURE `" + name + "`.`" + domain.SchemaCensusRoutine + "`() READS SQL DATA SQL SECURITY DEFINER SELECT 'users' AS object_name,'BASE TABLE' AS object_type,'InnoDB' AS engine"
				defer installCensus()
			case "role":
				role := user + "_role"
				if _, e := admin.Exec("CREATE ROLE '" + role + "'@'127.0.0.1'"); e != nil {
					t.Fatal("owned role setup", e)
				}
				defer admin.Exec("DROP ROLE '" + role + "'@'127.0.0.1'")
				if _, e := admin.Exec("GRANT SELECT ON `" + name + "`.users TO '" + role + "'@'127.0.0.1'"); e != nil {
					t.Fatal(e)
				}
				statement = "GRANT '" + role + "'@'127.0.0.1' TO '" + user + "'@'127.0.0.1'"
				undo = "REVOKE '" + role + "'@'127.0.0.1' FROM '" + user + "'@'127.0.0.1'"
			}
			if _, err := admin.Exec(statement); err != nil {
				t.Fatal("owned schema/role fault setup", err)
			}
			if undo != "" {
				defer admin.Exec(undo)
			}
			if object != "" {
				var visible int
				rows, queryErr := reader.Query("CALL `" + domain.SchemaCensusRoutine + "`()")
				if queryErr == nil {
					for rows.Next() {
						var n, k, e string
						if err := rows.Scan(&n, &k, &e); err != nil {
							t.Fatal(err)
						}
						if n == object {
							visible++
						}
					}
					queryErr = rows.Err()
					rows.Close()
				}
				if queryErr != nil || visible != 1 {
					t.Fatal("source-owner metadata census did not reveal ungranted schema object", visible, queryErr)
				}
			}
			if kind == "ungranted-table" {
				var filtered int
				if reader.QueryRow("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?", object).Scan(&filtered) != nil || filtered != 0 {
					t.Fatal("fixture no longer reproduces ACL-filtered information_schema")
				}
			}
			if check() == nil {
				t.Fatal("actual service accepted unsupported complete census")
			}
			bad, err := domain.CaptureBusinessSourceGuarded(ctx, reader, domain.Limits{MaxRows: 1000, MaxBytes: 32 << 20}, name, uuid, func(context.Context) error { return nil }, census)
			if err == nil || len(bad.Tables) != 0 {
				t.Fatal("actual worker returned rows despite unsupported schema/role", err)
			}
		})
	}
	for _, privilege := range []string{"EVENT", "TRIGGER", "SHOW_ROUTINE", "SELECT", "SHOW VIEW", "definer-role"} {
		t.Run("definer-capability-"+privilege, func(t *testing.T) {
			var undo string
			if privilege == "definer-role" {
				role := owner + "_role"
				if _, e := admin.Exec("CREATE ROLE '" + role + "'@'127.0.0.1'"); e != nil {
					t.Fatal(e)
				}
				defer admin.Exec("DROP ROLE '" + role + "'@'127.0.0.1'")
				if _, e := admin.Exec("GRANT '" + role + "'@'127.0.0.1' TO '" + owner + "'@'127.0.0.1'"); e != nil {
					t.Fatal(e)
				}
				undo = "REVOKE '" + role + "'@'127.0.0.1' FROM '" + owner + "'@'127.0.0.1'"
			} else {
				scope := grantDatabase + ".*"
				if privilege == "SHOW_ROUTINE" {
					scope = "*.*"
				}
				if _, e := admin.Exec("REVOKE " + privilege + " ON " + scope + " FROM '" + owner + "'@'127.0.0.1'"); e != nil {
					t.Fatal("owned definer metadata capability revoke", e)
				}
				undo = "GRANT " + privilege + " ON " + scope + " TO '" + owner + "'@'127.0.0.1'"
			}
			defer admin.Exec(undo)
			// No unsupported object is needed: even an apparently empty or
			// completely known census must fail its own live metadata canary.
			rows, e := reader.Query("CALL `" + domain.SchemaCensusRoutine + "`()")
			if e == nil {
				var n, k, v string
				if !rows.Next() || rows.Scan(&n, &k, &v) != nil || n != "__census_capability__" || k != "CENSUS_INCOMPLETE" {
					rows.Close()
					t.Fatal("definer capability loss did not invalidate empty-census canary")
				}
				rows.Close()
			}
			if check() == nil {
				t.Fatal("service trusted incomplete definer metadata visibility")
			}
			bad, e := domain.CaptureBusinessSourceGuarded(ctx, reader, domain.Limits{MaxRows: 1000, MaxBytes: 32 << 20}, name, uuid, func(context.Context) error { return nil }, census)
			if e == nil || len(bad.Tables) != 0 {
				t.Fatal("incomplete definer returned source snapshot", e)
			}
		})
	}
	for _, fault := range []string{"definer-event-revoked", "definer-routine-revoked", "definition-replaced", "foreign-database", "extra-projection"} {
		t.Run("during-capture-"+fault, func(t *testing.T) {
			checks := 0
			if fault == "definer-event-revoked" {
				defer admin.Exec("GRANT EVENT ON " + grantDatabase + ".* TO '" + owner + "'@'127.0.0.1'")
			} else if fault == "definer-routine-revoked" {
				defer admin.Exec("GRANT SHOW_ROUTINE ON *.* TO '" + owner + "'@'127.0.0.1'")
			} else {
				defer installCensus()
			}
			bad, e := domain.CaptureBusinessSourceGuarded(ctx, reader, domain.Limits{MaxRows: 1000, MaxBytes: 32 << 20}, name, uuid, func(context.Context) error {
				checks++
				if checks != 10 {
					return nil
				}
				if fault == "definer-event-revoked" {
					if _, e := admin.Exec("REVOKE EVENT ON " + grantDatabase + ".* FROM '" + owner + "'@'127.0.0.1'"); e != nil {
						t.Fatal(e)
					}
					return nil
				}
				if fault == "definer-routine-revoked" {
					if _, e := admin.Exec("REVOKE SHOW_ROUTINE ON *.* FROM '" + owner + "'@'127.0.0.1'"); e != nil {
						t.Fatal(e)
					}
					return nil
				}
				if _, e := admin.Exec("DROP PROCEDURE `" + name + "`.`" + domain.SchemaCensusRoutine + "`"); e != nil {
					t.Fatal(e)
				}
				body := "SELECT 'users','BASE TABLE','InnoDB'"
				if fault == "foreign-database" {
					body = "SELECT TABLE_NAME,TABLE_TYPE,COALESCE(ENGINE,'') FROM information_schema.TABLES WHERE TABLE_SCHEMA='mysql'"
				}
				if fault == "extra-projection" {
					body = "SELECT 'users','BASE TABLE','InnoDB','unexpected'"
				}
				if _, e := admin.Exec("CREATE DEFINER='" + owner + "'@'127.0.0.1' PROCEDURE `" + name + "`.`" + domain.SchemaCensusRoutine + "`() READS SQL DATA SQL SECURITY DEFINER " + body); e != nil {
					t.Fatal(e)
				}
				if _, e := admin.Exec("GRANT EXECUTE ON PROCEDURE `" + name + "`.`" + domain.SchemaCensusRoutine + "` TO '" + user + "'@'127.0.0.1'"); e != nil {
					t.Fatal(e)
				}
				return nil
			}, census)
			if e == nil || len(bad.Tables) != 0 || checks < 10 {
				t.Fatal("mid-capture original census change returned usable source", e, checks)
			}
		})
	}
	for _, fault := range []string{"foreign-database", "filtered-body", "extra-statement", "side-effect"} {
		t.Run("updated-pin-cannot-authorize-"+fault, func(t *testing.T) {
			defer installCensus()
			originalSpec := *s.captureMaterials.Operations["capture-database"].Request.Database.SchemaCensus
			defer func() {
				*s.captureMaterials.Operations["capture-database"].Request.Database.SchemaCensus = originalSpec
			}()
			body := "BEGIN " + projection + "; END"
			switch fault {
			case "foreign-database":
				body = "BEGIN SELECT TABLE_NAME,TABLE_TYPE,COALESCE(ENGINE,'') FROM information_schema.TABLES WHERE TABLE_SCHEMA='mysql'; END"
			case "filtered-body":
				body = strings.Replace(body, "WHERE TABLE_SCHEMA='"+name+"'", "WHERE TABLE_SCHEMA='"+name+"' AND TABLE_NAME<>'instance_unreviewed_payload'", 1)
			case "extra-statement":
				body = "BEGIN " + projection + "; SELECT 'unexpected'; END"
			case "side-effect":
				if _, e := admin.Exec("GRANT UPDATE ON `" + name + "`.system_backup_v2_configs TO '" + owner + "'@'127.0.0.1'"); e != nil {
					t.Fatal(e)
				}
				defer admin.Exec("REVOKE UPDATE ON `" + name + "`.system_backup_v2_configs FROM '" + owner + "'@'127.0.0.1'")
				body = "BEGIN UPDATE `" + name + "`.system_backup_v2_configs SET secret_value='side-effect'; " + projection + "; END"
			}
			if _, e := admin.Exec("DROP PROCEDURE `" + name + "`.`" + domain.SchemaCensusRoutine + "`"); e != nil {
				t.Fatal(e)
			}
			if _, e := admin.Exec("CREATE DEFINER='" + owner + "'@'127.0.0.1' PROCEDURE `" + name + "`.`" + domain.SchemaCensusRoutine + "`() READS SQL DATA SQL SECURITY DEFINER " + body); e != nil {
				t.Fatal(e)
			}
			for _, account := range []string{owner, user} {
				if _, e := admin.Exec("GRANT EXECUTE ON PROCEDURE `" + name + "`.`" + domain.SchemaCensusRoutine + "` TO '" + account + "'@'127.0.0.1'"); e != nil {
					t.Fatal(e)
				}
			}
			var changed string
			if admin.QueryRow("SELECT ROUTINE_DEFINITION FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=? AND ROUTINE_NAME=?", name, domain.SchemaCensusRoutine).Scan(&changed) != nil {
				t.Fatal("changed original metadata unavailable")
			}
			badSpec := census
			badSpec.DefinitionSHA256 = hash([]byte(changed))
			*s.captureMaterials.Operations["capture-database"].Request.Database.SchemaCensus = badSpec
			calls := trace.calls.Load()
			if check() == nil {
				t.Fatal("same labels and updated external pin bypassed reviewed census SQL")
			}
			bad, e := domain.CaptureBusinessSourceGuarded(ctx, reader, domain.Limits{MaxRows: 1000, MaxBytes: 32 << 20}, name, uuid, func(context.Context) error { return nil }, badSpec)
			if e == nil || len(bad.Tables) != 0 || trace.calls.Load() != calls {
				t.Fatal("unreviewed original routine executed or returned usable rows", e)
			}
			var value string
			if admin.QueryRow("SELECT secret_value FROM `"+name+"`.system_backup_v2_configs WHERE id=1").Scan(&value) != nil || value != "local-control-row-must-remain-unreadable" {
				t.Fatal("rejected routine changed source control row")
			}
		})
	}
	checks = 0
	bad, err := domain.CaptureBusinessSourceGuarded(ctx, reader, domain.Limits{MaxRows: 1000, MaxBytes: 32 << 20}, name, uuid, func(context.Context) error {
		checks++
		if checks == 10 {
			_, e := admin.Exec("REVOKE SELECT ON `" + name + "`.users FROM '" + user + "'@'127.0.0.1'")
			if e != nil {
				t.Fatal("mid-RR source revocation failed")
			}
		}
		return nil
	}, census)
	if err == nil || len(bad.Tables) != 0 || checks < 10 {
		t.Fatal("revoked original role returned usable source rows", err)
	}
}

type censusTraceConnector struct {
	driver.Connector
	calls     atomic.Int64
	lastQuery atomic.Value
}

func (c *censusTraceConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &censusTraceConn{Conn: conn, trace: c}, nil
}

type censusTraceConn struct {
	driver.Conn
	trace *censusTraceConnector
}

func (c *censusTraceConn) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, options)
}
func (c *censusTraceConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.trace.lastQuery.Store(query)
	if strings.HasPrefix(query, "CALL ") {
		c.trace.calls.Add(1)
	}
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
}

func installLockedSourceCensusFixture(t *testing.T, admin *sql.DB, name, user string, id [8]byte) (owner, grantDatabase, projection string, census domain.SchemaCensusSpec, installCensus func()) {
	t.Helper()
	var err error
	owner = "ad_d_cen_" + hex.EncodeToString(id[:])
	if _, err = admin.Exec("CREATE USER '" + owner + "'@'127.0.0.1' ACCOUNT LOCK"); err != nil {
		t.Fatal("owned locked census definer", err)
	}
	grantConn, e := admin.Conn(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	grantDatabase, e = domain.QuotedGrantDatabase(context.Background(), grantConn, name)
	grantConn.Close()
	if e != nil {
		t.Fatal("original exact schema GRANT quoting", e)
	}
	var partialRevokes bool
	if admin.QueryRow("SELECT @@GLOBAL.partial_revokes").Scan(&partialRevokes) != nil {
		t.Fatal("source grant mode unavailable")
	}
	t.Logf("actual local source partial_revokes=%v; underscore schema grants use original quoting", partialRevokes)
	for _, statement := range []string{"GRANT SELECT, SHOW VIEW, TRIGGER, EVENT ON " + grantDatabase + ".* TO '" + owner + "'@'127.0.0.1'", "GRANT SHOW_ROUTINE ON *.* TO '" + owner + "'@'127.0.0.1'", "GRANT SELECT ON mysql.global_grants TO '" + owner + "'@'127.0.0.1'", "GRANT SELECT ON mysql.role_edges TO '" + owner + "'@'127.0.0.1'", "GRANT SHOW_ROUTINE ON *.* TO '" + user + "'@'127.0.0.1'"} {
		if _, err = admin.Exec(statement); err != nil {
			t.Fatal("owned census metadata capability setup failed")
		}
	}
	projection, err = domain.SchemaCensusProjection(name, owner+"@127.0.0.1", partialRevokes)
	if err != nil {
		t.Fatal(err)
	}
	installCensus = func() {
		t.Helper()
		admin.Exec("DROP PROCEDURE IF EXISTS `" + name + "`.`" + domain.SchemaCensusRoutine + "`")
		if _, err := admin.Exec("CREATE DEFINER='" + owner + "'@'127.0.0.1' PROCEDURE `" + name + "`.`" + domain.SchemaCensusRoutine + "`() READS SQL DATA SQL SECURITY DEFINER BEGIN " + projection + "; END"); err != nil {
			t.Fatal("owned source-owner census installation", err)
		}
		for _, account := range []string{owner, user} {
			if _, err := admin.Exec("GRANT EXECUTE ON PROCEDURE `" + name + "`.`" + domain.SchemaCensusRoutine + "` TO '" + account + "'@'127.0.0.1'"); err != nil {
				t.Fatal("finite original census EXECUTE", err)
			}
		}
	}
	installCensus()
	var definition, definer string
	if admin.QueryRow("SELECT ROUTINE_DEFINITION,DEFINER FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=? AND ROUTINE_NAME=?", name, domain.SchemaCensusRoutine).Scan(&definition, &definer) != nil {
		t.Fatal("original source-owner census identity unavailable")
	}
	census = domain.SchemaCensusSpec{Version: domain.SchemaCensusVersion, Definer: definer, DefinitionSHA256: hash([]byte(definition)), PartialRevokes: partialRevokes}
	return
}
