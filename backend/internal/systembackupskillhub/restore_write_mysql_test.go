package systembackupskillhub

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	mysql "github.com/go-sql-driver/mysql"
)

// Opt-in only. Requires a disposable local MySQL server with CREATE DATABASE,
// CREATE USER and GRANT privileges. It creates unique resources, never opens
// application schemas, and removes only resources it successfully created.
func TestSQLRestorerMySQLRoundTrip(t *testing.T) {
	dsn := os.Getenv("CLAWMANAGER_SKILLHUB_TEST_MYSQL_ADMIN_DSN")
	if dsn == "" {
		t.Skip("set CLAWMANAGER_SKILLHUB_TEST_MYSQL_ADMIN_DSN for a disposable local MySQL server")
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal("invalid test DSN")
	}
	host, _, err := net.SplitHostPort(cfg.Addr)
	if err != nil || cfg.Net != "tcp" || (host != "127.0.0.1" && host != "localhost" && host != "::1") {
		t.Fatal("test DSN must use a loopback TCP server")
	}
	cfg.DBName = ""
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 15 * time.Second
	cfg.WriteTimeout = 15 * time.Second
	if cfg.Params == nil {
		cfg.Params = map[string]string{}
	}
	cfg.Params["time_zone"] = "'+00:00'"
	cfg.MultiStatements = false
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	open := func(config mysql.Config) *sql.DB {
		t.Helper()
		db, err := sql.Open("mysql", config.FormatDSN())
		if err != nil {
			t.Fatal("could not open test connection")
		}
		t.Cleanup(func() { db.Close() })
		if err := db.PingContext(ctx); err != nil {
			t.Fatal("test MySQL server is unavailable")
		}
		return db
	}
	admin := open(*cfg)
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		t.Fatal("test identity generation failed")
	}
	suffix := hex.EncodeToString(random)
	database := "skillhub_test_" + suffix
	exec := func(db *sql.DB, query string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, query, args...); err != nil {
			t.Fatal("isolated MySQL fixture setup failed")
		}
	}
	cleanup := func(query string) {
		t.Cleanup(func() {
			cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cleanCancel()
			if _, err := admin.ExecContext(cleanCtx, query); err != nil {
				t.Error("isolated MySQL fixture cleanup failed")
			}
		})
	}
	exec(admin, "CREATE DATABASE `"+database+"` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
	cleanup("DROP DATABASE `" + database + "`")
	setupCfg := *cfg
	setupCfg.DBName = database
	setupCfg.MultiStatements = true
	setup := open(setupCfg)
	exec(setup, "CREATE TABLE users (id INT PRIMARY KEY) ENGINE=InnoDB; CREATE TABLE instances (id INT PRIMARY KEY, instance_mode VARCHAR(30), runtime_type VARCHAR(30)) ENGINE=InnoDB; CREATE TABLE instance_commands (id INT PRIMARY KEY, instance_id INT, status VARCHAR(30), error_message TEXT, command_type VARCHAR(60)) ENGINE=InnoDB")
	for _, name := range []string{"008_add_skill_management.sql", "023_add_skill_hub.sql", "039_add_skill_package_materialize.sql"} {
		raw, err := os.ReadFile(filepath.Join("..", "db", "migrations", name))
		if err != nil {
			t.Fatal("migration fixture unavailable")
		}
		exec(setup, string(raw))
	}
	// Stronger cyclic FKs make insertion ordering and deferred references real.
	exec(setup, "ALTER TABLE skills ADD CONSTRAINT sh_test_current FOREIGN KEY (current_version_id) REFERENCES skill_versions(id), ADD CONSTRAINT sh_test_scan FOREIGN KEY (last_scan_result_id) REFERENCES skill_scan_results(id)")
	exec(setup, "ALTER TABLE skill_blobs ADD CONSTRAINT sh_test_blob_scan FOREIGN KEY (last_scan_result_id) REFERENCES skill_scan_results(id)")
	exec(setup, "CREATE TABLE skillhub_test_fence (id INT PRIMARY KEY, generation INT NOT NULL) ENGINE=InnoDB; INSERT INTO skillhub_test_fence VALUES (1,1); INSERT INTO users VALUES (11),(12); INSERT INTO instances VALUES (17,'lite','gateway'),(18,'lite','gateway')")
	principal := func(prefix, privileges string) (*sql.DB, string) {
		t.Helper()
		user := prefix + suffix
		passwordBytes := make([]byte, 24)
		if _, err := rand.Read(passwordBytes); err != nil {
			t.Fatal("test credential generation failed")
		}
		password := hex.EncodeToString(passwordBytes)
		// All interpolated SQL identifiers and credentials are generated hex strings.
		exec(admin, "CREATE USER '"+user+"'@'%' IDENTIFIED BY '"+password+"'")
		cleanup("DROP USER '" + user + "'@'%'")
		exec(admin, "GRANT "+privileges+" ON `"+database+"`.* TO '"+user+"'@'%'")
		config := *cfg
		config.DBName = database
		config.User = user
		config.Passwd = password
		return open(config), user
	}
	writeDB, writeUser := principal("shw_", "SELECT, INSERT, UPDATE")
	readDB, readUser := principal("shr_", "SELECT")
	request := restoreRequestFixture()
	request.Source = cloneRows(request.Source)
	// The checked-in source migrations use second-precision TIMESTAMP.
	for _, table := range tables(request.Source) {
		for i := 0; i < table.rows.Len(); i++ {
			row := table.rows.Index(i)
			for j := 0; j < row.NumField(); j++ {
				field := row.Field(j)
				if field.Kind() == reflect.Pointer {
					if field.IsNil() {
						continue
					}
					field = field.Elem()
				}
				if field.Type() == reflect.TypeOf(time.Time{}) {
					field.Set(reflect.ValueOf(field.Interface().(time.Time).Truncate(time.Second)))
				}
			}
		}
	}
	writeProof := &mysqlFixtureAuthority{database: database, user: writeUser, request: cloneRestoreRequest(request)}
	writer := SQLRestorer{DB: writeDB, Authority: writeProof}
	// Migration seeds must be reconciled explicitly by the test target owner.
	if err := writer.Restore(ctx, request); !errors.Is(err, ErrTargetOccupied) {
		t.Fatalf("seed target was not refused: %v", err)
	}
	exec(setup, "DELETE FROM skill_hub_tags")
	writeProof.rejectFinal = true
	if err := writer.Restore(ctx, request); !errors.Is(err, ErrRestoreAuthority) {
		t.Fatalf("final-fence rejection=%v", err)
	}
	for _, table := range tables(Rows{}) {
		var count int
		if err := setup.QueryRowContext(ctx, "SELECT COUNT(*) FROM `"+table.name+"`").Scan(&count); err != nil || count != 0 {
			t.Fatal("transaction rollback left partial Skill Hub rows")
		}
	}
	writeProof.rejectFinal = false
	if err := writer.Restore(ctx, request); err != nil {
		t.Fatalf("isolated restore failed: %v", err)
	}
	readProof := &mysqlFixtureAuthority{database: database, user: readUser, request: cloneRestoreRequest(request)}
	verifier := SQLRestoreVerifier{DB: readDB, Authority: readProof}
	if err := verifier.Verify(ctx, request); err != nil {
		t.Fatalf("independent SELECT-only verification failed: %v", err)
	}
	if _, err := readDB.ExecContext(ctx, "UPDATE skills SET name=name WHERE id=-1"); err == nil {
		t.Fatal("reader principal unexpectedly has UPDATE permission")
	}
	if err := writer.Restore(ctx, request); !errors.Is(err, ErrTargetOccupied) {
		t.Fatal("repeat restore modified committed target")
	}
	exec(setup, "UPDATE skills SET visibility='public' WHERE id=110")
	if err := verifier.Verify(ctx, request); !errors.Is(err, ErrMismatch) {
		t.Fatalf("real target drift was not rejected: %v", err)
	}
}

// This test-only authority verifies the generated target/principal, fixed
// request and local test fence. It is deliberately NOT a production proof
// adapter or substitute for B's resource/checkpoint authentication.
type mysqlFixtureAuthority struct {
	database, user string
	request        RestoreRequest
	rejectFinal    bool
}

func (a *mysqlFixtureAuthority) check(ctx context.Context, q ReadOnlyQueries, r RestoreRequest, lock bool) error {
	if !reflect.DeepEqual(r, a.request) {
		return errors.New("test request changed")
	}
	var database, user string
	if err := q.QueryRowContext(ctx, "SELECT DATABASE(), CURRENT_USER()").Scan(&database, &user); err != nil {
		return err
	}
	if database != a.database || strings.Split(user, "@")[0] != a.user {
		return errors.New("test target identity mismatch")
	}
	statement := "SELECT generation FROM skillhub_test_fence WHERE id=1"
	if lock {
		statement += " FOR UPDATE"
	}
	var generation int
	if err := q.QueryRowContext(ctx, statement).Scan(&generation); err != nil {
		return err
	}
	if generation != 1 || a.rejectFinal && lock {
		return errors.New("test fence unavailable")
	}
	return nil
}
func (a *mysqlFixtureAuthority) VerifyTargetWrite(ctx context.Context, q ReadOnlyQueries, r RestoreRequest) error {
	return a.check(ctx, q, r, false)
}
func (a *mysqlFixtureAuthority) RecheckTargetWrite(ctx context.Context, q ReadOnlyQueries, r RestoreRequest) error {
	return a.check(ctx, q, r, true)
}
func (a *mysqlFixtureAuthority) VerifyTargetRead(ctx context.Context, q ReadOnlyQueries, r RestoreRequest) error {
	return a.check(ctx, q, r, false)
}
func (a *mysqlFixtureAuthority) RecheckTargetRead(ctx context.Context, q ReadOnlyQueries, r RestoreRequest) error {
	return a.check(ctx, q, r, false)
}
