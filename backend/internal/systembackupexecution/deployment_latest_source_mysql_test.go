package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	appdb "clawreef/internal/db"
	root "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/schemaobjects"
	"clawreef/internal/systembackup/worker"
	d "clawreef/internal/systembackupdispatch"
	"github.com/go-sql-driver/mysql"
	corev1 "k8s.io/api/core/v1"
)

func testLatestMigratedSourceMySQL(t *testing.T) {
	t.Helper()
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
		t.Fatal("local original-schema fixture credentials unavailable")
	}
	clear(raw)
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd, cfg.Net, cfg.Addr = cred.User, cred.Password, "tcp", cred.Host+":"+strconv.Itoa(cred.Port)
	cred.Password = ""
	cfg.ParseTime = true
	cfg.Params = map[string]string{"time_zone": "'+00:00'"}
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal("local original-schema admin unavailable")
	}
	defer admin.Close()
	var id [8]byte
	rand.Read(id[:])
	name := "ad_d_full_" + hex.EncodeToString(id[:])
	user := name
	if _, err = admin.Exec("CREATE DATABASE `" + name + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"); err != nil {
		t.Fatal("owned original-schema database create failed")
	}
	defer admin.Exec("DROP DATABASE `" + name + "`")
	cfg.DBName = name
	original, err := sql.Open("mysql", cfg.FormatDSN())
	cfg.Passwd = ""
	if err != nil {
		t.Fatal("local original migration pool unavailable")
	}
	defer original.Close()
	catalog, err := appdb.EmbeddedMigrationCatalog()
	if err != nil {
		t.Fatal(err)
	}
	var uuid string
	if original.QueryRow("SELECT @@server_uuid").Scan(&uuid) != nil {
		t.Fatal("original migration server unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err = appdb.ApplyPinnedMigrations(ctx, original, appdb.MigrationTarget{ServerUUID: uuid, Database: name, CatalogSHA256: catalog.Hash}); err != nil {
		t.Fatal("actual original migration runner", err)
	}
	original.SetMaxOpenConns(1)
	if _, err = original.Exec("SET SESSION sql_mode=''"); err != nil {
		t.Fatal("owned zero-date fixture session mode", err)
	}
	if _, err = original.Exec("INSERT INTO northbound_auth_challenges(challenge_id,nonce_hash,key_id,expires_at,created_at,updated_at) VALUES(?,?,?,'0000-00-00 00:00:00.000000','2026-10-31 01:02:03.123456','2026-10-31 01:02:03.654321')", "named-source-challenge", strings.Repeat("a", 64), ""); err != nil {
		t.Fatal("actual original datetime/zero-date fixture", err)
	}
	if _, err = original.Exec("INSERT INTO gateway_keys(key_id,key_prefix,token_hash,key_type,name,budget_limit,budget_spent) VALUES(?,?,?,?,?,'9876543210.12345678','0.00000001')", "named-source-key", "named-source-prefix", strings.Repeat("f", 64), "user", "named original source key fixture"); err != nil {
		t.Fatal("actual original precision/credential fixture", err)
	}
	var ledger int
	if original.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&ledger) != nil || ledger != len(catalog.Filenames) {
		t.Fatal("full original ledger/catalog mismatch")
	}
	rows, err := original.Query("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_TYPE='BASE TABLE' ORDER BY TABLE_NAME")
	if err != nil {
		t.Fatal(err)
	}
	actual := map[string]bool{}
	for rows.Next() {
		var table string
		if rows.Scan(&table) != nil {
			t.Fatal("original schema names")
		}
		actual[table] = true
	}
	if rows.Err() != nil {
		t.Fatal("original schema names EOF")
	}
	rows.Close()
	known, excluded := map[string]bool{}, map[string]bool{}
	for _, n := range domain.BusinessCaptureTables() {
		known[n] = true
	}
	for _, n := range schemaobjects.ExcludedControlTables() {
		excluded[n] = true
	}
	for table := range actual {
		if !known[table] && !excluded[table] {
			t.Fatalf("unclassified actual migrated table: %s", table)
		}
	}
	for _, table := range []string{"gateway_image_artifacts", "gateway_image_jobs", "gateway_key_budget_ledger", "gateway_key_budget_reservations", "gateway_keys", "iei_session_revocations", "llm_model_user_grants", "northbound_admin_settings", "northbound_auth_challenges", "northbound_caller_policies", "northbound_owner_records", "northbound_sessions", "northbound_settings_audit", "routing_classifier_settings"} {
		policy, ok := root.Policy(table)
		if !actual[table] || !known[table] || excluded[table] || !ok || policy.BackupStrategy != "mysql_dump" {
			t.Fatal("real business/secret/config table was omitted or reclassified", table)
		}
	}
	var password [24]byte
	rand.Read(password[:])
	pass := hex.EncodeToString(password[:])
	clear(password[:])
	if _, err = admin.Exec("CREATE USER '" + user + "'@'127.0.0.1' IDENTIFIED BY '" + pass + "'"); err != nil {
		t.Fatal("owned original source reader create failed")
	}
	defer admin.Exec("DROP USER '" + user + "'@'127.0.0.1'")
	selected := 0
	for _, table := range domain.BusinessCaptureTables() {
		if actual[table] {
			selected++
			if _, err = admin.Exec("GRANT SELECT ON `" + name + "`.`" + table + "` TO '" + user + "'@'127.0.0.1'"); err != nil {
				t.Fatal("finite original present-table SELECT failed")
			}
		}
	}
	owner, _, _, census, _ := installLockedSourceCensusFixture(t, admin, name, user, id)
	defer admin.Exec("DROP USER '" + owner + "'@'127.0.0.1'")
	cfg.User, cfg.Passwd = user, pass
	// Match the actual worker: retain raw zero dates/DECIMAL/BIGINT bytes.
	cfg.ParseTime = false
	pass = ""
	connector, e := mysql.NewConnector(cfg)
	if e != nil {
		t.Fatal("source connector")
	}
	trace := &censusTraceConnector{Connector: connector}
	reader := sql.OpenDB(trace)
	cfg.Passwd = ""
	if err != nil {
		t.Fatal("actual original source reader unavailable")
	}
	defer reader.Close()
	s := DeploymentService{Config: DeploymentConfig{CaptureScope: "six-part", SourceUser: user, SourceDatabase: name, SourceServerUUID: uuid}, Source: reader, captureMaterials: &productionCaptureMaterials{Operations: map[string]productionCaptureOperation{"capture-database": {Request: worker.Request{Database: &worker.DatabaseSpec{Name: name, ServerUUID: uuid, SourceScope: domain.BusinessTableSourceScope, SchemaCensus: &census}}}}}}
	if err = s.checkSourceIdentity(ctx, reader); err != nil {
		t.Fatal("actual full original schema service admission", err)
	}
	captureSchema, err := domain.ObserveBusinessCaptureSchema(ctx, reader, census)
	if err != nil {
		t.Fatal("actual complete schema identity", err)
	}
	actualCatalog, e := domain.Catalog(ctx, reader)
	if e != nil {
		t.Fatal("original catalog metadata", e)
	}
	for _, table := range actualCatalog {
		if table.Engine != "InnoDB" || len(table.PrimaryKey) == 0 || len(table.Columns) == 0 {
			t.Fatalf("unsupported actual table metadata %s engine=%s primary_columns=%d columns=%d", table.Name, table.Engine, len(table.PrimaryKey), len(table.Columns))
		}
	}
	checks := 0
	snapshot, err := domain.CaptureBusinessSourceGuarded(ctx, reader, domain.Limits{MaxRows: 100000, MaxBytes: 32 << 20}, name, uuid, func(context.Context) error { checks++; return nil }, census)
	if err != nil || len(snapshot.Tables) != selected || checks < 10 {
		t.Fatal("full original-schema shared capture", err, len(snapshot.Tables), selected, checks, trace.lastQuery.Load())
	}
	if domain.VerifyBusinessCapturedSnapshot(snapshot, captureSchema) != nil {
		t.Fatal("actual capture and independently observed schema diverged")
	}
	var challenge, key bool
	for _, table := range snapshot.Tables {
		for _, row := range table.Rows {
			if table.Name == "northbound_auth_challenges" && row["challenge_id"].String() == "named-source-challenge" {
				challenge = true
				if !bytes.Equal(row["expires_at"].Bytes, []byte("0000-00-00 00:00:00.000000")) || row["created_at"].String() != "2026-10-31 01:02:03.123456" || row["updated_at"].String() != "2026-10-31 01:02:03.654321" || row["key_id"].Null || len(row["key_id"].Bytes) != 0 || !row["source_ip"].Null {
					t.Fatal("raw date/microsecond/NULL/empty source values changed")
				}
			}
			if table.Name == "gateway_keys" && row["key_id"].String() == "named-source-key" {
				key = true
				if row["budget_limit"].String() != "9876543210.12345678" || row["budget_spent"].String() != "0.00000001" || row["token_hash"].String() != strings.Repeat("f", 64) {
					t.Fatal("raw precision or encrypted credential source cell changed")
				}
			}
		}
	}
	if !challenge || !key {
		t.Fatal("actual nonempty original authentication/key tables omitted")
	}
	for _, table := range snapshot.Tables {
		if !actual[table.Name] || excluded[table.Name] || len(table.Columns) == 0 {
			t.Fatal("captured unknown/control or schema-less table")
		}
		var count int
		if original.QueryRow("SELECT COUNT(*) FROM `"+table.Name+"`").Scan(&count) != nil || count != len(table.Rows) {
			t.Fatal("actual original table rows were omitted", table.Name)
		}
	}
	if _, err = reader.Query("SELECT * FROM system_backup_v2_configs"); err == nil {
		t.Fatal("original metadata control rows became readable")
	}
	for _, mode := range []string{"valid", "missing-table", "schema-changed", "policy", "control-table", "suffix", "count"} {
		t.Run("actual-original-SQL-evidence-"+mode, func(t *testing.T) {
			options := &consumerFixtureOptions{PartName: "users_instances_database", Category: "users_instances", RequestedParts: []string{"mysql"}, JobDeadlineSeconds: 60}
			options.PrepareSource = func(_ *os.Root, i *worker.Invocation) {
				expectedSchema := captureSchema
				if mode == "policy" {
					expectedSchema.PolicySHA256 = strings.Repeat("0", 64)
				}
				i.Request.Operation = "capture-database"
				i.WorkspacePath = ""
				i.Request.RuntimePolicy = nil
				i.Request.WorkBuddyIdentity = nil
				i.Request.MaxFiles, i.Request.MaxFileBytes = 0, 0
				i.Request.MaxArchiveBytes, i.Request.MaxCompressedBytes = 32<<20, 32<<20
				i.FormalCapture.MaxFrames = 64
				i.Request.Database = &worker.DatabaseSpec{Name: name, ServerUUID: uuid, Address: cfg.Addr, TLSServerName: "named-source-tls-fixture", RootCA: []byte("named source CA; this already-open raw SQL pool does not exercise TLS"), SourceScope: domain.BusinessTableSourceScope, SchemaCensus: &census, CaptureSchema: &expectedSchema, MaxRows: 100000, MaxMemoryBytes: 32 << 20}
				i.Request.Binding.Path = "users_instances_database"
				i.ProviderKey.Request.Context.Part = "users_instances_database"
			}
			options.Configure = func(i *worker.Invocation, _ *sql.DB, _ *sql.DB, a d.Authority) {
				i.FormalCapture.SourceConfigSHA256 = a.ConfigSHA256
			}
			options.ConfigureWorkload = func(r *kube.JobRequest) { r.Source = corev1.Volume{}; r.SourceSubPath = "" }
			options.FormalMaterials = &kube.FormalJobMaterials{ConfigMap: "original-source-sql-materials", Inputs: []kube.FormalInputMount{{Volume: "formal-source-sql", Kind: "Secret", Name: "original-source-sql", Directory: "/run/backup/materials/source-sql", Items: []corev1.KeyToPath{{Key: "credential", Path: "credential.json"}}}}}
			options.RewriteCandidate = func(_ *os.Root, i worker.Invocation, r worker.FormalCaptureResult, k *candidateContentUnwrapper) (*os.Root, worker.FormalCaptureResult) {
				return forgeActualSQLSnapshotCandidate(t, i, r, k, snapshot, mode)
			}
			owner, service, _, db, a, j, _, _, refresh := newConsumerMySQLFixtureOptions(t, options)
			if owner.Gate.Records.Keys != service.Forward {
				t.Fatal("original SQL custody identity replaced")
			}
			refresh()
			ref, e := owner.Evidence(context.Background(), a, j)
			var results, evidence int
			if db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE result_sha256 IS NOT NULL").Scan(&results) != nil || db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_evidence").Scan(&evidence) != nil {
				t.Fatal("original result counts")
			}
			if mode == "valid" {
				if e != nil || ref == nil || results != 1 || evidence != 1 {
					t.Fatal("actual original shared SQL content did not pass independent evidence", e)
				}
			} else if e == nil || ref != nil || results != 0 || evidence != 0 {
				t.Fatal("valid AEAD bad SQL body produced original evidence", mode, e)
			}
		})
	}
	// Whole-schema runtime variants remain optional only while original feature
	// facts allow it; an active observed Linux Lite WorkBuddy needs both UID tables.
	var userID int
	if original.QueryRow("SELECT id FROM users ORDER BY id LIMIT 1").Scan(&userID) != nil {
		t.Fatal("original migrated nonempty user seed unavailable")
	}
	result, e := original.Exec("INSERT INTO instances(user_id,name,type,instance_mode,runtime_type,runtime_variant,os_type) VALUES(?,'source-wb-feature-fixture','workbuddy','lite','gateway','linux','linux')", userID)
	if e != nil {
		t.Fatal("original feature row fixture", e)
	}
	instanceID, e := result.LastInsertId()
	if e != nil {
		t.Fatal(e)
	}
	if s.checkSourceIdentity(ctx, reader) == nil {
		t.Fatal("active original WorkBuddy silently omitted UID schemas")
	}
	bad, e := domain.CaptureBusinessSourceGuarded(ctx, reader, domain.Limits{MaxRows: 100000, MaxBytes: 32 << 20}, name, uuid, func(context.Context) error { return nil }, census)
	if e == nil || len(bad.Tables) != 0 {
		t.Fatal("active missing-UID feature yielded source rows", e)
	}
	if _, e = original.Exec("DELETE FROM instances WHERE id=?", instanceID); e != nil {
		t.Fatal(e)
	}
	// Existing optional historical rows cannot be hidden by an absent SELECT.
	if _, e = original.Exec("CREATE TABLE workbuddy_browser_grants (id BIGINT UNSIGNED PRIMARY KEY, source_value VARBINARY(64)) ENGINE=InnoDB"); e != nil {
		t.Fatal("named original optional history variant", e)
	}
	if _, e = original.Exec("INSERT INTO workbuddy_browser_grants VALUES(18446744073709551615,?)", []byte{0, 255, 'h', 0}); e != nil {
		t.Fatal(e)
	}
	if s.checkSourceIdentity(ctx, reader) == nil {
		t.Fatal("actual optional table hidden by absent SELECT")
	}
	missingOptional, e := domain.CaptureBusinessSourceGuarded(ctx, reader, domain.Limits{MaxRows: 100000, MaxBytes: 32 << 20}, name, uuid, func(context.Context) error { return nil }, census)
	if e == nil || len(missingOptional.Tables) != 0 {
		t.Fatal("worker hid actual optional table behind ACL", e)
	}
	if _, e = original.Exec("GRANT SELECT ON `" + name + "`.workbuddy_browser_grants TO '" + user + "'@'127.0.0.1'"); e != nil {
		t.Fatal(e)
	}
	optional, e := domain.CaptureBusinessSourceGuarded(ctx, reader, domain.Limits{MaxRows: 100000, MaxBytes: 32 << 20}, name, uuid, func(context.Context) error { return nil }, census)
	if e != nil || len(optional.Tables) != selected+1 {
		t.Fatal("actual granted optional history was omitted", e)
	}
	var rawHistory bool
	for _, table := range optional.Tables {
		if table.Name == "workbuddy_browser_grants" {
			if len(table.Rows) != 1 || table.Rows[0]["id"].String() != "18446744073709551615" || !bytes.Equal(table.Rows[0]["source_value"].Bytes, []byte{0, 255, 'h', 0}) {
				t.Fatal("raw unsigned BIGINT or NUL/binary history changed")
			}
			rawHistory = true
		}
	}
	if !rawHistory {
		t.Fatal("original optional historical row omitted")
	}
	var originalSettings bool
	for _, table := range snapshot.Tables {
		if table.Name == "northbound_admin_settings" && len(table.Rows) > 0 {
			originalSettings = true
		}
	}
	if !originalSettings {
		t.Fatal("original nonempty datetime/settings seed was not captured")
	}
	t.Logf("actual source ledger=%d base_tables=%d captured_business_tables=%d excluded_control_tables=%d", ledger, len(actual), selected, len(actual)-selected)
}
