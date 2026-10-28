//go:build systembackup_mysql

package systembackupbusinessa

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	appdb "clawreef/internal/db"
	"github.com/go-sql-driver/mysql"
)

// This is a migrated-column/FK/transaction probe with synthetic source proofs.
// Its writer and read authority are test fixtures, not B's production adapters.
func TestABusinessRestoreRowsMySQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	run, uid := os.Getenv("D_INVARIANT_RUN"), os.Getenv("D_INVARIANT_NAMESPACE_UID")
	pin := os.Getenv("A_BUSINESS_CATALOG_SHA256")
	if !regexp.MustCompile(`^sbk-mig-[0-9]{12}-[0-9a-f]{4}$`).MatchString(run) ||
		!regexp.MustCompile(`^[a-f0-9-]{36}$`).MatchString(uid) || !hashPattern.MatchString(pin) ||
		os.Getenv("MYSQL_ROOT_PASSWORD") == "" {
		t.Fatal("run-owned MySQL identity, catalog pin and credential required")
	}
	catalog, err := appdb.EmbeddedMigrationCatalog()
	if err != nil || catalog.Hash != pin {
		t.Fatal("business probe embedded migration catalog differs from this run")
	}
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd = "root", os.Getenv("MYSQL_ROOT_PASSWORD")
	cfg.Net, cfg.DBName, cfg.ParseTime, cfg.Loc = "tcp", "clawmanager", true, time.UTC
	host := os.Getenv("D_INVARIANT_MYSQL_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	cfg.Addr = net.JoinHostPort(host, "3306")
	cfg.Params = map[string]string{"time_zone": "'+00:00'"}
	cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = 10*time.Second, 60*time.Second, 60*time.Second
	cfg.Logger = &mysql.NopLogger{}
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal("open isolated MySQL admin connection")
	}
	defer admin.Close()
	var gotRun, gotUID, uuid, actualUUID string
	if err := admin.QueryRowContext(ctx, "SELECT run_namespace,namespace_uid,server_uuid FROM d_invariant_run_marker WHERE id=1").Scan(&gotRun, &gotUID, &uuid); err != nil {
		t.Fatal("read isolated run marker")
	}
	if err := admin.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&actualUUID); err != nil || gotRun != run || gotUID != uid || uuid != actualUUID {
		t.Fatal("isolated run identity mismatch")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal("random run identity unavailable")
	}
	nonce := hex.EncodeToString(random[:])
	databaseName, readerName := "abiz_"+nonce[:16], "abizr_"+nonce[:16]
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE `"+databaseName+"`"); err != nil {
		t.Fatal("create run-owned business database")
	}
	cfg.DBName = databaseName
	database, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal("open run-owned business database")
	}
	defer database.Close()
	owned, readerCreated := false, false
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		var a, b, c, d, e string
		if admin.QueryRowContext(cleanup, "SELECT run_namespace,namespace_uid,server_uuid FROM d_invariant_run_marker WHERE id=1").Scan(&a, &b, &c) != nil || a != run || b != uid || c != uuid ||
			admin.QueryRowContext(cleanup, "SELECT @@server_uuid").Scan(&d) != nil || d != uuid || !owned ||
			database.QueryRowContext(cleanup, "SELECT owner_nonce FROM a_business_restore_probe_owner WHERE id=1").Scan(&e) != nil || e != nonce {
			t.Error("CLEANUP_PENDING A business restore identity db=" + databaseName + " reader=" + readerName)
			return
		}
		if readerCreated {
			if _, err := admin.ExecContext(cleanup, "DROP USER '"+readerName+"'@'%'"); err != nil {
				t.Error("CLEANUP_PENDING A business SELECT-only account")
				return
			}
			var count int
			if admin.QueryRowContext(cleanup, "SELECT COUNT(*) FROM mysql.user WHERE user=? AND host='%'", readerName).Scan(&count) != nil || count != 0 {
				t.Error("CLEANUP_PENDING A business reader absence")
				return
			}
			t.Log("CLEANED A business SELECT-only account")
		}
		if _, err := admin.ExecContext(cleanup, "DROP DATABASE `"+databaseName+"`"); err != nil {
			t.Error("CLEANUP_PENDING A business restore database")
			return
		}
		var count int
		if admin.QueryRowContext(cleanup, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=?", databaseName).Scan(&count) != nil || count != 0 {
			t.Error("CLEANUP_PENDING A business restore database absence")
			return
		}
		t.Log("CLEANED A business restore run-owned database")
	}()
	if _, err := database.ExecContext(ctx, "CREATE TABLE a_business_restore_probe_owner (id INT PRIMARY KEY,owner_nonce CHAR(32) NOT NULL) ENGINE=InnoDB"); err != nil {
		t.Fatal("create database ownership marker")
	}
	if _, err := database.ExecContext(ctx, "INSERT INTO a_business_restore_probe_owner VALUES (1,?)", nonce); err != nil {
		t.Fatal("bind database ownership marker")
	}
	owned = true
	if err := appdb.ApplyPinnedMigrations(ctx, database, appdb.MigrationTarget{ServerUUID: uuid, Database: databaseName, CatalogSHA256: pin}); err != nil {
		t.Fatal("fresh pinned business database migration failed")
	}
	var migrationCount int
	if database.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations").Scan(&migrationCount) != nil || migrationCount != len(catalog.Filenames) {
		t.Fatal("business database migration ledger incomplete")
	}
	// The official fresh migration seeds an admin/quota. Remove only those
	// test-install rows in our random database; no application is started here.
	for _, table := range []string{"user_quotas", "users"} {
		if _, err := database.ExecContext(ctx, "DELETE FROM `"+table+"`"); err != nil {
			t.Fatal("remove run-owned bootstrap seed")
		}
	}
	scope, binding, input, proof := businessRestoreFixture(t)
	if database.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&binding.TargetNow) != nil {
		t.Fatal("read target database UTC clock")
	}
	proof.wantBinding = cloneBusinessRestoreBinding(binding)
	rows, err := NormalizeBusinessForRestore(ctx, scope, binding, input, businessRestoreTestProofs(proof))
	if err != nil {
		t.Fatal("normalize migrated-database fixture")
	}
	cases := businessSQLCases(t, rows)
	metadata := businessSQLMetadata(t, ctx, database, cases)
	businessSQLCounts(t, ctx, database, scope, 0)
	var fkCount int
	if database.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND REFERENCED_TABLE_NAME IS NOT NULL AND TABLE_NAME IN ('user_quotas','instance_gateway_token_aliases','northbound_sessions','northbound_caller_policies')").Scan(&fkCount) != nil || fkCount != 5 {
		t.Fatal("five formal A foreign-key edges missing or changed")
	}
	// A failing write at the end must roll back all fifteen tables and the B
	// instance fixture, even though MySQL rolls back only the failing statement.
	err = writeBusinessSQLFixture(ctx, database, cases, true)
	if !businessMySQLError(err, 1062) {
		t.Fatal("expected duplicate-key rollback injection")
	}
	businessSQLCounts(t, ctx, database, scope, 0)
	var instanceCount int
	if database.QueryRowContext(ctx, "SELECT COUNT(*) FROM instances").Scan(&instanceCount) != nil || instanceCount != 0 {
		t.Fatal("failed batch left a B instance fixture")
	}
	if err := writeBusinessSQLFixture(ctx, database, cases, false); err != nil {
		t.Fatal("write full migrated fifteen-table batch")
	}
	businessSQLRoundtrip(t, ctx, database, cases, metadata)
	t.Log("PASS A business fifteen-table complete-column roundtrip and rollback")
	for _, statement := range []string{
		"UPDATE user_quotas SET user_id=999999 WHERE id=109",
		"UPDATE instance_gateway_token_aliases SET instance_id=999999 WHERE id=120",
		"UPDATE northbound_sessions SET user_id=999999 WHERE id=118",
		"UPDATE northbound_caller_policies SET user_id=999999 WHERE user_id=107",
		"UPDATE northbound_caller_policies SET updated_by=999999 WHERE user_id=107",
	} {
		tx, err := database.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal("begin FK negative transaction")
		}
		_, failure := tx.ExecContext(ctx, statement)
		rollback := tx.Rollback()
		if !businessMySQLError(failure, 1452) || rollback != nil {
			t.Fatal("formal FK did not reject invalid target reference")
		}
	}
	for _, column := range []string{"username", "email"} {
		tx, err := database.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal("begin collation negative transaction")
		}
		copyRow := cloneBusinessSQLRow(cases[0])
		copyRow.values["id"] = 999993
		copyRow.values["username"], copyRow.values["email"] = "unique-user", "unique@example.invalid"
		copyRow.values[column] = strings.ToUpper(cases[0].values[column].(string))
		failure := insertBusinessSQLRow(ctx, tx, copyRow)
		rollback := tx.Rollback()
		if !businessMySQLError(failure, 1062) || rollback != nil {
			t.Fatal("migrated collation/unique key failed to reject collision")
		}
	}
	businessSQLRoundtrip(t, ctx, database, cases, metadata)
	t.Log("PASS A business formal FK and collation uniqueness rejection")
	// The reader gets table-level SELECT only: no control-table, source DB,
	// write, DDL, grant-option or global privileges are provided.
	var readerSecret [32]byte
	if _, err := rand.Read(readerSecret[:]); err != nil {
		t.Fatal("independent reader credential unavailable")
	}
	password := hex.EncodeToString(readerSecret[:])
	defer func() {
		for i := range readerSecret {
			readerSecret[i] = 0
		}
	}()
	if _, err := admin.ExecContext(ctx, "CREATE USER '"+readerName+"'@'%' IDENTIFIED BY '"+password+"'"); err != nil {
		t.Fatal("create isolated SELECT-only reader")
	}
	readerCreated = true
	allowed := append(scope.Tables(), "a_business_restore_probe_owner")
	for _, table := range allowed {
		if _, err := admin.ExecContext(ctx, "GRANT SELECT ON `"+databaseName+"`.`"+table+"` TO '"+readerName+"'@'%'"); err != nil {
			t.Fatal("grant isolated table-level SELECT")
		}
	}
	readerCfg := cfg.Clone()
	readerCfg.User, readerCfg.Passwd = readerName, password
	reader, err := sql.Open("mysql", readerCfg.FormatDSN())
	if err != nil {
		t.Fatal("open SELECT-only reader")
	}
	defer reader.Close()
	for _, statement := range []string{"UPDATE users SET is_active=TRUE WHERE id=107", "DELETE FROM users WHERE id=107", "INSERT INTO users (id,username,email,password_hash) VALUES (999993,'denied','denied@example.invalid','disabled')", "CREATE TABLE forbidden_write (id INT)"} {
		if _, err := reader.ExecContext(ctx, statement); !businessSQLPermissionDenied(err) {
			t.Fatal("SELECT-only credential did not deny mutation/DDL")
		}
	}
	for _, statement := range []string{"SELECT COUNT(*) FROM clawmanager.users", "SELECT COUNT(*) FROM schema_migrations"} {
		var denied int
		if err := reader.QueryRowContext(ctx, statement).Scan(&denied); !businessSQLPermissionDenied(err) {
			t.Fatal("SELECT-only credential can read outside its table scope")
		}
	}
	readProof := &businessSQLReadProof{database: databaseName, uuid: uuid, account: readerName, nonce: nonce,
		registry: scope.registrySHA, schema: scope.schemaSHA, evidence: binding.Dump.EvidenceRef,
		counts: cloneSourceSnapshot(binding.Dump.Snapshot), allowed: allowed}
	verifier := businessReportSQLVerifier{SQLRestoreVerifier: SQLRestoreVerifier{DB: reader, Proof: readProof}, t: t}
	checks, err := verifier.VerifyRestoreTarget(ctx, scope, binding.Dump.Snapshot, binding.Dump.EvidenceRef)
	if err != nil || len(checks.Users) != 11 || len(checks.AIGateway) != 14 || readProof.calls != 2 {
		t.Fatal("real SELECT-only twenty-five-check verification failed")
	}

	// Same row counts and inert-state checks must not hide cost drift. Each
	// injection is restored before continuing in this run-owned database.
	originalCost := rows.Gateway.Costs[0]
	if !t.Run("cost_snapshot_concurrent_commit", func(t *testing.T) {
		businessCostSnapshotConcurrentCommit(t, ctx, readerCfg, reader, database, scope, binding.Dump.Snapshot, originalCost, uuid, nonce)
	}) {
		t.Fatal("concurrent cost snapshot probe failed")
	}
	for _, mutation := range []struct{ name, set string }{
		{"money", "estimated_cost=estimated_cost+0.00000001"},
		{"tokens", "total_tokens=total_tokens+1"},
		{"currency_case", "currency='usd'"},
		{"actual_NULL", "actual_cost=NULL"},
	} {
		t.Run("cost_aggregate_"+mutation.name, func(t *testing.T) {
			if _, err := database.ExecContext(ctx, "UPDATE cost_records SET "+mutation.set+" WHERE id=?", originalCost.ID); err != nil {
				t.Fatal("inject cost drift", err)
			}
			got, err := verifier.VerifyRestoreTarget(ctx, scope, binding.Dump.Snapshot, binding.Dump.EvidenceRef)
			if !errors.Is(err, ErrRestoreNormalizationMismatch) || len(got.AIGateway) != 14 {
				t.Error("real same-count aggregate drift accepted", err)
			} else {
				for _, check := range allCategoryChecks(got) {
					if check.ID == "ai_gateway.restore_cost_aggregates" {
						if check.Status != "failed" {
							t.Error("aggregate mismatch missing")
						}
					} else if check.Status != "passed" {
						t.Error("same-count drift changed unrelated check", check.ID)
					}
				}
			}
			if _, err := database.ExecContext(ctx, "UPDATE cost_records SET estimated_cost=?,total_tokens=?,currency=?,actual_cost=? WHERE id=?", originalCost.EstimatedCost, originalCost.TotalTokens, originalCost.Currency, originalCost.ActualCost, originalCost.ID); err != nil {
				t.Fatal("restore cost fixture", err)
			}
		})
	}
	if t.Failed() {
		t.Fatal("cost aggregate SQL drift checks failed")
	}
	if !t.Run("report_record_deleted", func(t *testing.T) {
		businessReportRecordDeletion(t, ctx, database, verifier, scope, binding.Dump.Snapshot, binding.Dump.EvidenceRef, cases)
	}) {
		t.Fatal("record-deletion report probe failed")
	}
	if _, err := database.ExecContext(ctx, "UPDATE enterprise_auth_settings SET ldap_bind_password_ciphertext=NULL WHERE id=101"); err != nil {
		t.Fatal("inject NULL/inheritance mismatch")
	}
	checks, err = verifier.VerifyRestoreTarget(ctx, scope, binding.Dump.Snapshot, binding.Dump.EvidenceRef)
	if !errors.Is(err, ErrRestoreNormalizationMismatch) {
		t.Fatal("SQL NULL incorrectly treated as explicit LDAP clear")
	}
	if _, err := database.ExecContext(ctx, "UPDATE enterprise_auth_settings SET ldap_bind_password_ciphertext='' WHERE id=101"); err != nil {
		t.Fatal("restore explicit clear")
	}
	readProof.failFinal = true
	checks, err = verifier.VerifyRestoreTarget(ctx, scope, binding.Dump.Snapshot, binding.Dump.EvidenceRef)
	if err == nil || len(checks.Users) != 0 || len(checks.AIGateway) != 0 {
		t.Fatal("failed final read proof returned partial checks")
	}
	readProof.failFinal = false
	t.Log("PASS A business SELECT-only permissions, NULL mismatch and final-proof rollback")
	// Exercise nullable row fields in a second full transaction, then compare
	// every SQL column including NULL-versus-empty and exact DECIMAL values.
	clearBusinessSQLFixture(t, ctx, database, cases)
	input.CallerPolicies[0].UpdatedBy = nil
	input.EnterpriseAuth[0].LDAPAdminGroupDNs = nil
	input.NorthboundSessions[0].PreviousRefreshTokenHash = nil
	input.NorthboundSessions[0].LastIP = nil
	input.NorthboundSessions[0].UserAgent = nil
	input.Models[0].Description = nil
	input.Models[0].ProviderModelsJSON = nil
	input.Gateway.CostSources[0].ActualCost = nil
	binding.Dump.Snapshot.CostAggregateSHA256, err = costSourceAggregateHash(input.Gateway.CostSources)
	if err != nil {
		t.Fatal(err)
	}
	proof.wantBinding = cloneBusinessRestoreBinding(binding)
	input.Gateway.InvocationSources[0].RequestPayloadPresent = false
	input.Gateway.InvocationSources[0].ResponsePayloadPresent = false
	input.Gateway.InvocationSources[0].ErrorMessagePresent = false
	input.Gateway.AuditSources[0].DetailsPresent = false
	input.Aliases[0].LastUsedAt = nil
	proof.wantInput = cloneBusinessRestoreInput(input)
	rows, err = NormalizeBusinessForRestore(ctx, scope, binding, input, businessRestoreTestProofs(proof))
	if err != nil {
		t.Fatal("normalize nullable batch")
	}
	cases = businessSQLCases(t, rows)
	if err := writeBusinessSQLFixture(ctx, database, cases, false); err != nil {
		t.Fatal("write nullable full batch")
	}
	businessSQLRoundtrip(t, ctx, database, cases, metadata)
	readProof.counts = cloneSourceSnapshot(binding.Dump.Snapshot)
	checks, err = verifier.VerifyRestoreTarget(ctx, scope, binding.Dump.Snapshot, binding.Dump.EvidenceRef)
	if err != nil || len(checks.AIGateway) != 14 {
		t.Fatal("nullable cost aggregate verification failed", err)
	}
	t.Log("PASS A business SQL NULL preservation and exact decimal roundtrip")
	clearBusinessSQLFixture(t, ctx, database, cases)
	// A bounded volume test, not the cross-owner large-smoke.v1 release gate.
	for i := 0; i < 1000; i++ {
		source := input.Users[0]
		source.ID = 1000 + i
		source.Username = fmt.Sprintf("source-%04d", i)
		source.Email = fmt.Sprintf("source-%04d@example.invalid", i)
		input.Users = append(input.Users, source)
		input.Gateway.Users = append(input.Gateway.Users, UserRestoreMapping{SourceID: source.ID, TargetID: 10000 + i, TargetUsername: fmt.Sprintf("target-%04d", i), TargetEmail: fmt.Sprintf("target-%04d@example.invalid", i)})
		quota := input.Quotas[0]
		quota.ID = 1000 + i
		quota.UserID = source.ID
		input.Quotas = append(input.Quotas, quota)
		input.QuotaMappings = append(input.QuotaMappings, UserQuotaRestoreMapping{SourceID: quota.ID, TargetID: 10000 + i})
		input.QuotaCapacities[10000+i] = input.QuotaCapacities[107]
	}
	counts := businessRestoreSourceCounts(input)
	for i := range binding.Dump.Snapshot.Tables {
		binding.Dump.Snapshot.Tables[i].Rows = int64(counts[binding.Dump.Snapshot.Tables[i].Table])
	}
	proof.wantBinding = cloneBusinessRestoreBinding(binding)
	proof.wantInput = cloneBusinessRestoreInput(input)
	rows, err = NormalizeBusinessForRestore(ctx, scope, binding, input, businessRestoreTestProofs(proof))
	if err != nil {
		t.Fatal("normalize bounded-volume batch")
	}
	cases = businessSQLCases(t, rows)
	if err := writeBusinessSQLFixture(ctx, database, cases, false); err != nil {
		t.Fatal("write bounded-volume batch")
	}
	businessSQLRoundtrip(t, ctx, database, cases, metadata)
	readProof.counts = cloneSourceSnapshot(binding.Dump.Snapshot)
	if _, err := verifier.VerifyRestoreTarget(ctx, scope, binding.Dump.Snapshot, binding.Dump.EvidenceRef); err != nil {
		t.Fatal("bounded-volume SELECT-only verification failed")
	}
	t.Log("PASS A business bounded-volume users=1001 quotas=1001 other_tables=1; full large-smoke.v1 not claimed")
}

type businessSQLRow struct {
	table  string
	values map[string]any
}
type businessSQLColumn struct {
	name, kind string
	precision  sql.NullInt64
}

// The pinned migration owns this generated column. It must never appear in
// INSERT values, but complete-column readback must still check its value.
func businessSQLReadValues(row businessSQLRow) map[string]any {
	values := cloneBusinessSQLRow(row).values
	if row.table == "users" {
		values["local_username_key"] = nil
		if row.values["auth_provider"] == "local" {
			values["local_username_key"] = row.values["username"]
		}
	}
	return values
}

func businessSQLColumnCovered(row businessSQLRow, name, extra string) bool {
	extra = strings.ToUpper(extra)
	generated := strings.Contains(extra, "STORED GENERATED") || strings.Contains(extra, "VIRTUAL GENERATED")
	if row.table == "users" && name == "local_username_key" {
		_, writable := row.values[name]
		return !writable && extra == "STORED GENERATED"
	}
	_, writable := row.values[name]
	return writable && !generated
}

func businessSQLCases(t *testing.T, rows BusinessRestoreRows) []businessSQLRow {
	t.Helper()
	sets := []struct {
		table string
		rows  any
	}{
		{"users", rows.Users}, {"user_quotas", rows.Quotas}, {"enterprise_auth_settings", rows.EnterpriseAuth},
		{"northbound_auth_challenges", rows.Challenges}, {"northbound_sessions", rows.NorthboundSessions},
		{"northbound_caller_policies", rows.CallerPolicies}, {"llm_models", rows.Models}, {"risk_rules", rows.Rules},
		{"instance_gateway_token_aliases", rows.Aliases}, {"chat_sessions", rows.Gateway.Sessions},
		{"model_invocations", rows.Gateway.Invocations}, {"audit_events", rows.Gateway.Audits},
		{"cost_records", rows.Gateway.Costs}, {"risk_hits", rows.Gateway.RiskHits}, {"chat_messages", rows.Gateway.Messages},
	}
	var cases []businessSQLRow
	for _, set := range sets {
		slice := reflect.ValueOf(set.rows)
		for i := 0; i < slice.Len(); i++ {
			v := slice.Index(i)
			typ := v.Type()
			fields := map[string]any{}
			for j := 0; j < v.NumField(); j++ {
				field := typ.Field(j)
				// These db tags describe joined users columns in the read DTO,
				// not columns owned by northbound_caller_policies.
				if set.table == "northbound_caller_policies" && (field.Name == "Username" || field.Name == "Email") {
					continue
				}
				name := strings.Split(field.Tag.Get("db"), ",")[0]
				if name == "-" {
					continue
				}
				if name == "" {
					switch typ.Name() {
					case "NormalizedUserQuota", "NormalizedLLMModel", "NormalizedGatewayAlias", "NormalizedCostRecord":
						name = businessSQLColumnName(field.Name)
					default:
						continue
					}
				}
				if !regexp.MustCompile(`^[a-z][a-z0-9_]*$`).MatchString(name) {
					t.Fatal("unsafe fixture column")
				}
				if _, duplicate := fields[name]; duplicate {
					t.Fatal("duplicate fixture column")
				}
				fields[name] = v.Field(j).Interface()
			}
			cases = append(cases, businessSQLRow{set.table, fields})
		}
	}
	return cases
}

func businessSQLColumnName(name string) string {
	var out strings.Builder
	for i, c := range []byte(name) {
		upper := c >= 'A' && c <= 'Z'
		if i > 0 && upper && ((name[i-1] >= 'a' && name[i-1] <= 'z') || (i+1 < len(name) && name[i+1] >= 'a' && name[i+1] <= 'z')) {
			out.WriteByte('_')
		}
		if upper {
			c += 'a' - 'A'
		}
		out.WriteByte(c)
	}
	return out.String()
}

func businessSQLMetadata(t *testing.T, ctx context.Context, database *sql.DB, cases []businessSQLRow) map[string][]businessSQLColumn {
	t.Helper()
	metadata := map[string][]businessSQLColumn{}
	for _, row := range cases {
		if _, seen := metadata[row.table]; seen {
			continue
		}
		result, err := database.QueryContext(ctx, "SELECT COLUMN_NAME,DATA_TYPE,DATETIME_PRECISION,EXTRA FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? ORDER BY ORDINAL_POSITION", row.table)
		if err != nil {
			t.Fatal("inspect migrated business columns")
		}
		var columns []businessSQLColumn
		for result.Next() {
			var column businessSQLColumn
			var extra string
			if result.Scan(&column.name, &column.kind, &column.precision, &extra) != nil {
				result.Close()
				t.Fatal("scan column metadata")
			}
			if !businessSQLColumnCovered(row, column.name, extra) {
				result.Close()
				t.Fatal("uncovered migrated column: " + row.table + "." + column.name)
			}
			columns = append(columns, column)
		}
		if err := errors.Join(result.Err(), result.Close()); err != nil {
			t.Fatalf("inspect migrated columns for %s: %v", row.table, err)
		}
		if expected := businessSQLReadValues(row); len(columns) != len(expected) {
			for _, column := range columns {
				delete(expected, column.name)
			}
			var missing []string
			for name := range expected {
				missing = append(missing, name)
			}
			sort.Strings(missing)
			t.Fatalf("incomplete migrated-column closure: table=%s actual=%d expected=%d missing=%v", row.table, len(columns), len(businessSQLReadValues(row)), missing)
		}
		metadata[row.table] = columns
	}
	if len(metadata) != 15 {
		t.Fatal("fifteen-table SQL metadata scope required")
	}
	return metadata
}

func insertBusinessSQLRow(ctx context.Context, tx *sql.Tx, row businessSQLRow) error {
	var columns []string
	for column := range row.values {
		columns = append(columns, column)
	}
	sort.Strings(columns)
	var args []any
	for _, column := range columns {
		args = append(args, row.values[column])
	}
	quoted := "`" + strings.Join(columns, "`,`") + "`"
	_, err := tx.ExecContext(ctx, "INSERT INTO `"+row.table+"` ("+quoted+") VALUES ("+strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")+")", args...)
	return err
}

func writeBusinessSQLFixture(ctx context.Context, database *sql.DB, cases []businessSQLRow, fail bool) error {
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	instanceWritten := false
	for _, row := range cases {
		if row.table != "users" && !instanceWritten {
			_, err = tx.ExecContext(ctx, "INSERT INTO instances (id,user_id,name,type,runtime_type,status,cpu_cores,memory_gb,disk_gb,os_type,os_version,access_token) VALUES (108,107,'fixture-instance','ubuntu','shell','stopped',1,1,1,'linux','fixture',NULL)")
			if err != nil {
				return err
			}
			instanceWritten = true
		}
		if err := insertBusinessSQLRow(ctx, tx, row); err != nil {
			return err
		}
	}
	if fail {
		return insertBusinessSQLRow(ctx, tx, cases[0])
	}
	return tx.Commit()
}

func cloneBusinessSQLRow(row businessSQLRow) businessSQLRow {
	copy := businessSQLRow{table: row.table, values: map[string]any{}}
	for k, v := range row.values {
		copy.values[k] = v
	}
	return copy
}

func businessSQLCounts(t *testing.T, ctx context.Context, database *sql.DB, scope *CaptureScope, want int) {
	t.Helper()
	for _, table := range scope.tables {
		var count int
		if database.QueryRowContext(ctx, "SELECT COUNT(*) FROM `"+table+"`").Scan(&count) != nil || count != want {
			t.Fatal("unexpected run-owned row count for " + table)
		}
	}
}

func clearBusinessSQLFixture(t *testing.T, ctx context.Context, database *sql.DB, cases []businessSQLRow) {
	t.Helper()
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal("begin clearing run-owned fixture")
	}
	defer tx.Rollback()
	seen := map[string]bool{}
	for i := len(cases) - 1; i >= 0; i-- {
		table := cases[i].table
		if table == "users" || seen[table] {
			continue
		}
		seen[table] = true
		if _, err := tx.ExecContext(ctx, "DELETE FROM `"+table+"`"); err != nil {
			t.Fatal("clear run-owned child table")
		}
	}
	for _, table := range []string{"instances", "users"} {
		if _, err := tx.ExecContext(ctx, "DELETE FROM `"+table+"`"); err != nil {
			t.Fatal("clear run-owned parent table")
		}
	}
	if tx.Commit() != nil {
		t.Fatal("commit clearing run-owned fixture")
	}
}

func businessSQLRoundtrip(t *testing.T, ctx context.Context, database *sql.DB, cases []businessSQLRow, metadata map[string][]businessSQLColumn) {
	t.Helper()
	for _, row := range cases {
		expected := businessSQLReadValues(row)
		columns := metadata[row.table]
		var names []string
		for _, column := range columns {
			names = append(names, "`"+column.name+"`")
		}
		key := "id"
		if row.table == "northbound_caller_policies" {
			key = "user_id"
		}
		actual := make([]any, len(columns))
		dest := make([]any, len(columns))
		for i := range actual {
			dest[i] = &actual[i]
		}
		if err := database.QueryRowContext(ctx, "SELECT "+strings.Join(names, ",")+" FROM `"+row.table+"` WHERE `"+key+"`=?", row.values[key]).Scan(dest...); err != nil {
			t.Fatal("read normalized row: " + row.table)
		}
		for i, column := range columns {
			if !businessSQLValueEqual(expected[column.name], actual[i], column) {
				t.Fatal("SQL roundtrip mismatch: " + row.table + "." + column.name)
			}
		}
	}
}

func businessSQLValueEqual(expected, actual any, column businessSQLColumn) bool {
	v := reflect.ValueOf(expected)
	for v.IsValid() && v.Kind() == reflect.Pointer {
		if v.IsNil() {
			v = reflect.Value{}
			break
		}
		v = v.Elem()
	}
	if !v.IsValid() {
		return actual == nil
	}
	expected = v.Interface()
	if actual == nil {
		return false
	}
	if want, ok := expected.(time.Time); ok {
		got, ok := actual.(time.Time)
		if !ok {
			return false
		}
		precision := int64(0)
		if column.precision.Valid {
			precision = column.precision.Int64
		}
		unit := time.Second
		for i := int64(0); i < precision; i++ {
			unit /= 10
		}
		return want.UTC().Truncate(unit).Equal(got.UTC())
	}
	text := func(value any) string {
		switch value := value.(type) {
		case []byte:
			return string(value)
		case string:
			return value
		case bool:
			if value {
				return "1"
			}
			return "0"
		default:
			return fmt.Sprint(value)
		}
	}
	if column.kind == "json" {
		var a, b any
		da := json.NewDecoder(strings.NewReader(text(expected)))
		db := json.NewDecoder(strings.NewReader(text(actual)))
		da.UseNumber()
		db.UseNumber()
		return da.Decode(&a) == nil && db.Decode(&b) == nil && reflect.DeepEqual(a, b)
	}
	return text(expected) == text(actual)
}

func businessMySQLError(err error, code uint16) bool {
	var mysqlError *mysql.MySQLError
	return errors.As(err, &mysqlError) && mysqlError.Number == code
}

func businessSQLPermissionDenied(err error) bool {
	return businessMySQLError(err, 1044) || businessMySQLError(err, 1142)
}

type businessSQLReadProof struct {
	database, uuid, account, nonce, registry, schema, evidence string
	counts                                                     SourceSnapshot
	allowed                                                    []string
	calls                                                      int
	failFinal                                                  bool
}

func (p *businessSQLReadProof) check(ctx context.Context, tx *sql.Tx, registry, schema, evidence string) error {
	p.calls++
	if registry != p.registry || schema != p.schema || evidence != p.evidence {
		return errors.New("fixture read binding mismatch")
	}
	var database, uuid, account, nonce string
	if tx.QueryRowContext(ctx, "SELECT DATABASE(),@@server_uuid,CURRENT_USER()").Scan(&database, &uuid, &account) != nil || database != p.database || uuid != p.uuid || account != p.account+"@%" ||
		tx.QueryRowContext(ctx, "SELECT owner_nonce FROM a_business_restore_probe_owner WHERE id=1").Scan(&nonce) != nil || nonce != p.nonce {
		return errors.New("fixture read identity mismatch")
	}
	grantee := "'" + p.account + "'@'%'"
	var extra int
	for _, query := range []string{"SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES WHERE GRANTEE=? AND PRIVILEGE_TYPE<>'USAGE'", "SELECT COUNT(*) FROM information_schema.SCHEMA_PRIVILEGES WHERE GRANTEE=?"} {
		if tx.QueryRowContext(ctx, query, grantee).Scan(&extra) != nil || extra != 0 {
			return errors.New("reader has broad privileges")
		}
	}
	rows, err := tx.QueryContext(ctx, "SELECT TABLE_SCHEMA,TABLE_NAME,PRIVILEGE_TYPE,IS_GRANTABLE FROM information_schema.TABLE_PRIVILEGES WHERE GRANTEE=?", grantee)
	if err != nil {
		return errors.New("reader grant query failed")
	}
	defer rows.Close()
	remaining := map[string]bool{}
	for _, table := range p.allowed {
		remaining[table] = true
	}
	for rows.Next() {
		var db, table, privilege, grantable string
		if rows.Scan(&db, &table, &privilege, &grantable) != nil || db != p.database || !remaining[table] || privilege != "SELECT" || grantable != "NO" {
			return errors.New("reader grant scope mismatch")
		}
		delete(remaining, table)
	}
	if errors.Join(rows.Err(), rows.Close()) != nil || len(remaining) != 0 {
		return errors.New("reader grants incomplete")
	}
	return nil
}

func (p *businessSQLReadProof) VerifyReadOnlyTarget(ctx context.Context, tx *sql.Tx, registry, schema string, counts SourceSnapshot, evidence string) error {
	if !reflect.DeepEqual(counts, p.counts) {
		return errors.New("fixture expected counts mismatch")
	}
	return p.check(ctx, tx, registry, schema, evidence)
}
func (p *businessSQLReadProof) RecheckReadOnlyTarget(ctx context.Context, tx *sql.Tx, registry, schema, evidence string) error {
	if err := p.check(ctx, tx, registry, schema, evidence); err != nil {
		return err
	}
	if p.failFinal {
		return errors.New("fixture final read authority rejected")
	}
	return nil
}

// Offline seed validates the same fixture/column builder without any MySQL.
func TestABusinessRestoreMySQLSeed(t *testing.T) {
	scope, binding, input, proof := businessRestoreFixture(t)
	rows, err := NormalizeBusinessForRestore(context.Background(), scope, binding, input, businessRestoreTestProofs(proof))
	if err != nil {
		t.Fatal(err)
	}
	cases := businessSQLCases(t, rows)
	if len(cases) != 15 {
		t.Fatal("fifteen SQL cases required")
	}
	t.Run("caller-policy-table-columns-only", func(t *testing.T) {
		joined := rows
		joined.CallerPolicies = append(rows.CallerPolicies[:0:0], rows.CallerPolicies...)
		joined.CallerPolicies[0].Username = "joined-user"
		joined.CallerPolicies[0].Email = "joined@example.invalid"
		var found bool
		for _, row := range businessSQLCases(t, joined) {
			if row.table != "northbound_caller_policies" {
				continue
			}
			found = true
			want := []string{"user_id", "enabled", "scopes_json", "created_at", "updated_at", "updated_by"}
			if len(row.values) != len(want) || len(businessSQLReadValues(row)) != len(want) {
				t.Fatal("caller-policy SQL projection includes joined or DTO-only columns")
			}
			for _, name := range want {
				if _, ok := row.values[name]; !ok || !businessSQLColumnCovered(row, name, "") {
					t.Fatalf("caller-policy table column missing: %s", name)
				}
			}
			for _, name := range []string{"username", "email", "scopes", "unexpected_column"} {
				if businessSQLColumnCovered(row, name, "") {
					t.Fatalf("caller-policy non-table column accepted: %s", name)
				}
			}
		}
		if !found {
			t.Fatal("caller-policy fixture missing")
		}
	})

	t.Run("generated-username-column", func(t *testing.T) {
		user := cloneBusinessSQLRow(cases[0])
		if _, writable := user.values["local_username_key"]; writable {
			t.Fatal("generated username key must never be inserted")
		}
		if !businessSQLValueEqual(businessSQLReadValues(user)["local_username_key"], user.values["username"], businessSQLColumn{}) {
			t.Fatal("local generated username key differs from target username")
		}
		user.values["auth_provider"] = "ldap"
		if !businessSQLValueEqual(businessSQLReadValues(user)["local_username_key"], nil, businessSQLColumn{}) {
			t.Fatal("non-local generated username key must be SQL NULL")
		}
		for _, check := range []struct {
			name, extra string
			want        bool
		}{
			{"local_username_key", "STORED GENERATED", true},
			{"local_username_key", "", false},
			{"local_username_key", "VIRTUAL GENERATED", false},
			{"username", "", true},
			{"created_at", "DEFAULT_GENERATED", true},
			{"updated_at", "DEFAULT_GENERATED on update CURRENT_TIMESTAMP", true},
			{"username", "STORED GENERATED", false},
			{"unexpected_generated", "STORED GENERATED", false},
			{"unexpected_writable", "", false},
		} {
			if businessSQLColumnCovered(user, check.name, check.extra) != check.want {
				t.Fatalf("incorrect column closure for %s with %s", check.name, check.extra)
			}
		}
		user.values["local_username_key"] = "forbidden write"
		if businessSQLColumnCovered(user, "local_username_key", "STORED GENERATED") {
			t.Fatal("generated column became writable")
		}
	})
	seen := map[string]bool{}
	for _, row := range cases {
		if _, ok := tables[row.table]; !ok || seen[row.table] || len(row.values) == 0 {
			t.Fatal("invalid closed SQL fixture set")
		}
		seen[row.table] = true
	}
	for field, want := range map[string]string{"ID": "id", "APIKeySecretRef": "api_key_secret_ref", "MaxCPUCores": "max_cpu_cores", "ProviderModelsJSON": "provider_models_json"} {
		if businessSQLColumnName(field) != want {
			t.Fatal("SQL column acronym mapping differs")
		}
	}
	if !businessSQLValueEqual(quotaInt(2), int64(2), businessSQLColumn{}) || businessSQLValueEqual((*string)(nil), "", businessSQLColumn{}) ||
		!businessSQLValueEqual(`["one","two"]`, []byte(`["one", "two"]`), businessSQLColumn{kind: "json"}) || businessSQLValueEqual("0.00000001", []byte("0.00000002"), businessSQLColumn{kind: "decimal"}) {
		t.Fatal("SQL comparison loses NULL/JSON/decimal semantics")
	}
	var total, readTotal int
	for _, row := range cases {
		total += len(row.values)
		readTotal += len(businessSQLReadValues(row))
	}
	t.Log("PASS A business fifteen-table offline seed writable_columns=" + strconv.Itoa(total) + " read_columns=" + strconv.Itoa(readTotal) + " real_mysql=not_run")
}
