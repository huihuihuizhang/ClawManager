//go:build systembackup_mysql

package systembackupcontroller

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"clawreef/internal/systembackupread"
	"github.com/go-sql-driver/mysql"
)

type healthProbeInputs struct {
	Kind       string   `json:"kind"`
	DDL        string   `json:"health_ddl"`
	DDLSHA     string   `json:"health_ddl_sha256"`
	Fixture    string   `json:"fixture_sql"`
	FixtureSHA string   `json:"fixture_sha256"`
	Catalog    string   `json:"catalog_sha256"`
	Migrations []string `json:"migration_files"`
}

func healthDigest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func healthStatementCount(text string) int {
	var statements strings.Builder
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			statements.WriteString(line)
			statements.WriteByte('\n')
		}
	}
	return strings.Count(statements.String(), ";")
}

func decodeHealthProbeInputs(raw []byte) (healthProbeInputs, error) {
	var value healthProbeInputs
	if len(raw) > 262144 {
		return value, errors.New("health probe capsule too large")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return value, errors.New("capsule object required")
	}
	allowed := map[string]bool{"kind": true, "health_ddl": true, "health_ddl_sha256": true, "fixture_sql": true, "fixture_sha256": true, "catalog_sha256": true, "migration_files": true}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return value, err
		}
		name, ok := key.(string)
		if !ok || !allowed[name] || seen[name] {
			return value, errors.New("unknown or duplicate capsule key")
		}
		seen[name] = true
		var field json.RawMessage
		if err := d.Decode(&field); err != nil {
			return value, err
		}
	}
	if _, err = d.Token(); err != nil {
		return value, err
	}
	var extra any
	if len(seen) != len(allowed) || d.Decode(&extra) != io.EOF {
		return value, errors.New("incomplete or trailing capsule")
	}
	if err = json.Unmarshal(raw, &value); err != nil {
		return value, err
	}
	if value.Kind != "d_control_health_probe_inputs.v1" || value.Catalog != ContractMigrationCatalogHash || len(value.Migrations) != ContractMigrationCatalogFileCount ||
		healthDigest([]byte(value.DDL)) != value.DDLSHA || healthDigest([]byte(value.Fixture)) != value.FixtureSHA ||
		healthStatementCount(value.DDL) != 1 || !strings.Contains(value.DDL, "CREATE TABLE system_backup_v2_control_health (") ||
		healthStatementCount(value.Fixture) != 2 || !strings.Contains(value.Fixture, "INSERT INTO system_backup_v2_configs (") || !strings.Contains(value.Fixture, "INSERT INTO system_backup_v2_installation_state (") {
		return healthProbeInputs{}, errors.New("capsule source/catalog pins differ")
	}
	for i, name := range value.Migrations {
		if !regexp.MustCompile(`^[0-9]{3}_[A-Za-z0-9_]+\.sql$`).MatchString(name) || i > 0 && value.Migrations[i-1] >= name {
			return healthProbeInputs{}, errors.New("invalid exact migration filenames")
		}
	}
	return value, nil
}

func healthProbeCapsule(t *testing.T) healthProbeInputs {
	t.Helper()
	path := os.Getenv("D_CONTROL_HEALTH_INPUTS")
	var raw []byte
	var err error
	if path != "" {
		f, e := os.Open(path)
		healthMust(t, e)
		defer f.Close()
		raw, err = io.ReadAll(io.LimitReader(f, 262145))
		healthMust(t, err)
		if healthDigest(raw) != os.Getenv("D_CONTROL_HEALTH_INPUTS_SHA256") {
			t.Fatal("actual capsule hash mismatch")
		}
	} else {
		ddl, e := os.ReadFile("../../../docs/system-backup-d-control-health-proposal-20261016.sql")
		healthMust(t, e)
		fixture, e := os.ReadFile("../../../scripts/system-backup-controller-enabled-fixture.mysql.sql")
		healthMust(t, e)
		ddl = []byte(strings.ReplaceAll(strings.ReplaceAll(string(ddl), "\r\n", "\n"), "\r", "\n"))
		fixture = []byte(strings.ReplaceAll(strings.ReplaceAll(string(fixture), "\r\n", "\n"), "\r", "\n"))
		entries, e := os.ReadDir("../db/migrations")
		healthMust(t, e)
		names := []string{}
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
				names = append(names, entry.Name())
			}
		}
		slices.Sort(names)
		raw, err = json.Marshal(healthProbeInputs{Kind: "d_control_health_probe_inputs.v1", DDL: string(ddl), DDLSHA: healthDigest(ddl), Fixture: string(fixture), FixtureSHA: healthDigest(fixture), Catalog: ContractMigrationCatalogHash, Migrations: names})
		healthMust(t, err)
	}
	value, err := decodeHealthProbeInputs(raw)
	healthMust(t, err)
	return value
}

func TestDControlHealthMySQLSeed(t *testing.T) {
	input := healthProbeCapsule(t)
	t.Run("current_config_switch_fixture", func(t *testing.T) {
		query, err := healthNextConfigFixture(input.Fixture)
		healthMust(t, err)
		if healthStatementCount(query) != 1 || strings.Contains(query, "INSERT INTO system_backup_v2_installation_state") || !strings.Contains(query, ") VALUES (\n  @installation_id,\n  2,\n") {
			t.Fatal("config switch fixture must insert only an existing version 2 target")
		}
		if _, err := healthNextConfigFixture(strings.Replace(input.Fixture, "  @installation_id,\n  1,", "  @installation_id,\n  3,", 1)); err == nil {
			t.Fatal("changed fixture version silently accepted")
		}
	})
	raw, err := json.Marshal(input)
	healthMust(t, err)
	for _, tc := range []struct {
		name   string
		change func([]byte) []byte
	}{
		{"duplicate", func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"kind":`), []byte(`"kind":"duplicate","kind":`), 1)
		}},
		{"unknown", func(b []byte) []byte { return append([]byte(`{"unreviewed":true,`), b[1:]...) }},
		{"trailing", func(b []byte) []byte { return append(b, []byte(`{}`)...) }},
		{"DDL drift", func(b []byte) []byte {
			return bytes.Replace(b, []byte("CREATE TABLE system_backup_v2_control_health"), []byte("CREATE TABLE other_health"), 1)
		}},
		{"fixture drift", func(b []byte) []byte {
			return bytes.Replace(b, []byte("d-isolated-smoke"), []byte("other-isolated-smoke"), 1)
		}},
		{"budget", func([]byte) []byte { return make([]byte, 262145) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeHealthProbeInputs(tc.change(bytes.Clone(raw))); err == nil {
				t.Fatal("invalid capsule accepted")
			}
		})
	}
	t.Log("PASS control health capsule/seed only; real_mysql=not_run")
}

func healthNextConfigFixture(fixture string) (string, error) {
	config, _, ok := strings.Cut(fixture, "\nINSERT INTO system_backup_v2_installation_state (")
	const values = ") VALUES (\n  @installation_id,\n  1,\n"
	if !ok || strings.Count(config, values) != 1 || healthStatementCount(config) != 1 {
		return "", errors.New("config switch fixture shape differs")
	}
	return strings.Replace(config, values, ") VALUES (\n  @installation_id,\n  2,\n", 1), nil
}

func healthMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func healthProbeDB(t *testing.T, ctx context.Context) (*sql.DB, *mysql.Config) {
	t.Helper()
	run, uid := os.Getenv("D_INVARIANT_RUN"), os.Getenv("D_INVARIANT_NAMESPACE_UID")
	if !regexp.MustCompile(`^sbk-mig-[0-9]{12}-[0-9a-f]{4}$`).MatchString(run) || !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(uid) {
		t.Fatal("fresh run namespace/UID required")
	}
	host, password := os.Getenv("D_INVARIANT_MYSQL_HOST"), os.Getenv("MYSQL_ROOT_PASSWORD")
	if host == "" {
		host = "127.0.0.1"
	}
	if net.ParseIP(host) == nil || strings.Contains(host, ":") || password == "" {
		t.Fatal("isolated IPv4 database credentials required")
	}
	cfg := mysql.NewConfig()
	cfg.User = "root"
	cfg.Passwd = password
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(host, "3306")
	cfg.DBName = "clawmanager"
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.MultiStatements = true
	cfg.Params = map[string]string{"time_zone": "'+00:00'"}
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 15 * time.Second
	cfg.WriteTimeout = 15 * time.Second
	db, err := sql.Open("mysql", cfg.FormatDSN())
	healthMust(t, err)
	t.Cleanup(func() { db.Close() })
	var gotRun, gotUID, pinned, actual string
	healthMust(t, db.QueryRowContext(ctx, "SELECT run_namespace,namespace_uid,server_uuid FROM d_invariant_run_marker WHERE id=1").Scan(&gotRun, &gotUID, &pinned))
	healthMust(t, db.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&actual))
	if gotRun != run || gotUID != uid || pinned != actual {
		t.Fatal("database is outside exact owned run")
	}
	return db, cfg
}

type healthSQLScope struct {
	installation string
	revoked      bool
}

func (s *healthSQLScope) AuthorizeRead(context.Context, *sql.Tx) (string, error) {
	return s.installation, nil
}
func (s *healthSQLScope) RecheckRead(context.Context, *sql.Tx, string) error {
	if s.revoked {
		return systembackupread.ErrDenied
	}
	return nil
}

func healthStateBytes(t *testing.T, ctx context.Context, db *sql.DB, installation string) string {
	t.Helper()
	rows, err := db.QueryContext(ctx, "SELECT * FROM system_backup_v2_installation_state WHERE origin_installation_id=?", installation)
	healthMust(t, err)
	defer rows.Close()
	columns, err := rows.Columns()
	healthMust(t, err)
	if !rows.Next() {
		t.Fatal("installation missing")
	}
	values := make([]any, len(columns))
	dest := make([]any, len(columns))
	for i := range values {
		dest[i] = &values[i]
	}
	healthMust(t, rows.Scan(dest...))
	if rows.Next() {
		t.Fatal("duplicate installation")
	}
	healthMust(t, rows.Err())
	raw, err := json.Marshal(struct {
		Columns []string
		Values  []any
	}{columns, values})
	healthMust(t, err)
	return healthDigest(raw)
}

func healthOwnedFixture(t *testing.T, ctx context.Context, db *sql.DB, input healthProbeInputs) string {
	t.Helper()
	var nonce [10]byte
	_, err := rand.Read(nonce[:])
	healthMust(t, err)
	id := "installation_dhealth_" + hex.EncodeToString(nonce[:])
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		for _, table := range []string{"system_backup_v2_control_health", "system_backup_v2_installation_state", "system_backup_v2_configs"} {
			if _, e := db.ExecContext(cleanup, "DELETE FROM "+table+" WHERE origin_installation_id=?", id); e != nil {
				t.Errorf("CLEANUP_PENDING health fixture=%s table=%s: %v", id, table, e)
				return
			}
			var n int
			if e := db.QueryRowContext(cleanup, "SELECT COUNT(*) FROM "+table+" WHERE origin_installation_id=?", id).Scan(&n); e != nil || n != 0 {
				t.Errorf("CLEANUP_PENDING health fixture=%s table=%s count=%d", id, table, n)
				return
			}
		}
		t.Log("CLEANED control health owned installation/config/observation", id)
	})
	conn, err := db.Conn(ctx)
	healthMust(t, err)
	defer conn.Close()
	_, err = conn.ExecContext(ctx, "SET @installation_id=?", id)
	healthMust(t, err)
	_, err = conn.ExecContext(ctx, input.Fixture)
	healthMust(t, err)
	return id
}

func healthRead(t *testing.T, ctx context.Context, db *sql.DB, id string) systembackupread.ControlHealthSnapshot {
	t.Helper()
	reader, err := systembackupread.NewReader(db, &healthSQLScope{installation: id})
	healthMust(t, err)
	value, err := reader.ReadControlHealth(ctx)
	healthMust(t, err)
	return value
}

func healthExpectFence(t *testing.T, token ControlHealthWriter, err error) {
	t.Helper()
	if !errors.Is(err, ErrControlHealthFence) || token != (ControlHealthWriter{}) {
		t.Fatal("expected zero fenced result", err)
	}
}

// Run only in the existing fresh namespace harness. These are actual SQL/CAS
// and transaction reads with a synthetic read scope, not production admission.
func TestDControlHealthMySQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	input := healthProbeCapsule(t)
	db, cfg := healthProbeDB(t, ctx)
	rows, err := db.QueryContext(ctx, "SELECT filename FROM schema_migrations ORDER BY filename")
	healthMust(t, err)
	var applied []string
	for rows.Next() {
		var name string
		healthMust(t, rows.Scan(&name))
		applied = append(applied, name)
	}
	healthMust(t, rows.Err())
	rows.Close()
	if !slices.Equal(applied, input.Migrations) {
		t.Fatal("actual ledger differs from full current catalog")
	}
	var exists int
	healthMust(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='system_backup_v2_control_health'").Scan(&exists))
	if exists != 0 {
		t.Fatal("refusing an existing health table")
	}
	_, err = db.ExecContext(ctx, input.DDL)
	healthMust(t, err)
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		var n int
		if e := db.QueryRowContext(cleanup, "SELECT COUNT(*) FROM system_backup_v2_control_health").Scan(&n); e != nil || n != 0 {
			t.Errorf("CLEANUP_PENDING candidate health table rows=%d: %v", n, e)
			return
		}
		if _, e := db.ExecContext(cleanup, "DROP TABLE system_backup_v2_control_health"); e != nil {
			t.Errorf("CLEANUP_PENDING candidate health table: %v", e)
		} else {
			t.Log("CLEANED candidate control health table")
		}
	}()
	store := ControlHealthStore{DB: db}
	probe := ReadinessProbeSet{SQLUTCReadinessProbe{DB: db}, SQLClaimReadinessProbe{DB: db}, SQLDeadlineAlertReadinessProbe{DB: db}}
	t.Run("initial_observe_takeover_read", func(t *testing.T) {
		id := healthOwnedFixture(t, ctx, db, input)
		before := healthStateBytes(t, ctx, db, id)
		defer func() {
			if healthStateBytes(t, ctx, db, id) != before {
				t.Error("health writes changed installation state")
			}
		}()
		writer, err := store.BeginWriter(ctx, id, 1, "health:leader-a", 0)
		healthMust(t, err)
		value := healthRead(t, ctx, db, id)
		if value.ControllerHealth() != "unknown" || value.DatabaseHealth() != "unknown" {
			t.Fatal("leader start manufactured health")
		}
		writer, err = store.Observe(ctx, writer, ControlLoopResult{}, probe)
		healthMust(t, err)
		value = healthRead(t, ctx, db, id)
		if value.ControllerHealth() != "healthy" || value.DatabaseHealth() != "healthy" {
			t.Fatal("actual completed result missing")
		}
		writer, err = store.Observe(ctx, writer, ControlLoopResult{Err: errors.New("synthetic failed control pass")}, probe)
		healthMust(t, err)
		value = healthRead(t, ctx, db, id)
		if value.ControllerHealth() != "degraded" || value.DatabaseHealth() != "healthy" {
			t.Fatal("controller and database were conflated")
		}
		writer, err = store.Observe(ctx, writer, ControlLoopResult{}, ReadinessProbeFunc(func(context.Context) error { return errors.New("synthetic failed DB probe") }))
		healthMust(t, err)
		value = healthRead(t, ctx, db, id)
		if value.ControllerHealth() != "healthy" || value.DatabaseHealth() != "degraded" {
			t.Fatal("database probe failure hidden")
		}
		newWriter, err := store.BeginWriter(ctx, id, 1, "health:leader-b", writer.epoch)
		healthMust(t, err)
		if newWriter.epoch != 2 || newWriter.sequence != 0 {
			t.Fatal("takeover receipt differs")
		}
		token, err := store.Observe(ctx, writer, ControlLoopResult{}, probe)
		healthExpectFence(t, token, err)
		value = healthRead(t, ctx, db, id)
		if value.ControllerHealth() != "unknown" {
			t.Fatal("old leader overwrote new generation")
		}
		scope := &healthSQLScope{installation: id, revoked: true}
		reader, err := systembackupread.NewReader(db, scope)
		healthMust(t, err)
		if value, err := reader.ReadControlHealth(ctx); !errors.Is(err, systembackupread.ErrDenied) || value != (systembackupread.ControlHealthSnapshot{}) {
			t.Fatal("revoked scope returned health", err)
		}
	})
	t.Run("concurrent_epoch_cas", func(t *testing.T) {
		id := healthOwnedFixture(t, ctx, db, input)
		before := healthStateBytes(t, ctx, db, id)
		_, err := store.BeginWriter(ctx, id, 1, "health:initial", 0)
		healthMust(t, err)
		type outcome struct {
			token ControlHealthWriter
			err   error
		}
		results := make(chan outcome, 2)
		start := make(chan struct{})
		for _, owner := range []string{"health:takeover-a", "health:takeover-b"} {
			go func(owner string) {
				<-start
				token, err := store.BeginWriter(ctx, id, 1, owner, 1)
				results <- outcome{token, err}
			}(owner)
		}
		close(start)
		won := 0
		for i := 0; i < 2; i++ {
			got := <-results
			if got.err == nil {
				won++
				if got.token.epoch != 2 {
					t.Fatal("unexpected takeover epoch")
				}
			} else {
				healthExpectFence(t, got.token, got.err)
			}
		}
		if won != 1 {
			t.Fatal("concurrent takeover had multiple/no winners", won)
		}
		if healthStateBytes(t, ctx, db, id) != before {
			t.Fatal("takeover changed installation")
		}
	})
	t.Run("concurrent_observation_cas", func(t *testing.T) {
		id := healthOwnedFixture(t, ctx, db, input)
		before := healthStateBytes(t, ctx, db, id)
		writer, err := store.BeginWriter(ctx, id, 1, "health:leader", 0)
		healthMust(t, err)
		type outcome struct {
			token ControlHealthWriter
			err   error
		}
		results := make(chan outcome, 2)
		start := make(chan struct{})
		for i := 0; i < 2; i++ {
			go func() {
				<-start
				token, err := store.Observe(ctx, writer, ControlLoopResult{}, probe)
				results <- outcome{token, err}
			}()
		}
		close(start)
		won := 0
		for i := 0; i < 2; i++ {
			got := <-results
			if got.err == nil {
				won++
				if got.token.sequence != 1 {
					t.Fatal("unexpected observation sequence")
				}
			} else {
				healthExpectFence(t, got.token, got.err)
			}
		}
		var sequence uint64
		healthMust(t, db.QueryRowContext(ctx, "SELECT observation_sequence FROM system_backup_v2_control_health WHERE origin_installation_id=?", id).Scan(&sequence))
		if won != 1 || sequence != 1 {
			t.Fatal("concurrent observation was not single CAS", won, sequence)
		}
		if healthStateBytes(t, ctx, db, id) != before {
			t.Fatal("observation changed installation")
		}
	})
	t.Run("expiry_timezone_and_current_config", func(t *testing.T) {
		id := healthOwnedFixture(t, ctx, db, input)
		writer, err := store.BeginWriter(ctx, id, 1, "health:leader", 0)
		healthMust(t, err)
		// Backdate a valid observation using this fixture's configured TTL.
		// A fixed 30-second window is corrupt when the interval is 5 seconds;
		// the reader correctly returns unavailable instead of stale for it.
		result, err := db.ExecContext(ctx, `UPDATE system_backup_v2_control_health h
JOIN system_backup_v2_configs c ON c.origin_installation_id=h.origin_installation_id AND c.version=h.config_version
SET h.observed_at=TIMESTAMPADD(SECOND,-(3*c.controller_reconcile_interval_seconds+1),UTC_TIMESTAMP(6)),
    h.expires_at=TIMESTAMPADD(SECOND,-1,UTC_TIMESTAMP(6))
WHERE h.origin_installation_id=?`, id)
		healthMust(t, err)
		changed, err := result.RowsAffected()
		healthMust(t, err)
		if changed != 1 {
			t.Fatal("expired fixture did not update exactly one observation", changed)
		}
		var lifetime, configuredLifetime int64
		healthMust(t, db.QueryRowContext(ctx, `SELECT TIMESTAMPDIFF(MICROSECOND,h.observed_at,h.expires_at),
3*c.controller_reconcile_interval_seconds*1000000
FROM system_backup_v2_control_health h JOIN system_backup_v2_configs c
ON c.origin_installation_id=h.origin_installation_id AND c.version=h.config_version
WHERE h.origin_installation_id=?`, id).Scan(&lifetime, &configuredLifetime))
		if lifetime != configuredLifetime {
			t.Fatal("expired fixture TTL differs from current config", lifetime, configuredLifetime)
		}
		value := healthRead(t, ctx, db, id)
		if value.ControllerHealth() != "stale" || value.DatabaseHealth() != "stale" {
			t.Fatal("expired observation appeared fresh")
		}
		token, err := store.Observe(ctx, writer, ControlLoopResult{}, probe)
		healthExpectFence(t, token, err)
		nonUTC, err := mysql.ParseDSN(cfg.FormatDSN())
		healthMust(t, err)
		nonUTC.Params["time_zone"] = "'+01:00'"
		wrongClock, err := sql.Open("mysql", nonUTC.FormatDSN())
		healthMust(t, err)
		defer wrongClock.Close()
		token, err = (ControlHealthStore{DB: wrongClock}).BeginWriter(ctx, id, 1, "health:wrong-clock", 1)
		healthExpectFence(t, token, err)
		writer, err = store.BeginWriter(ctx, id, 1, "health:restart", 1)
		healthMust(t, err)
		// Switch to a real second config; the active-config FK forbids 999.
		configSQL, err := healthNextConfigFixture(input.Fixture)
		healthMust(t, err)
		conn, err := db.Conn(ctx)
		healthMust(t, err)
		_, err = conn.ExecContext(ctx, "SET @installation_id=?", id)
		if err == nil {
			_, err = conn.ExecContext(ctx, configSQL)
		}
		closeErr := conn.Close()
		healthMust(t, err)
		healthMust(t, closeErr)
		// An intentionally changed fixture's current-config pointer must also
		// fence health writes. Compare the complete state after this fixture
		// mutation, so a writer cannot hide additional installation changes.
		_, err = db.ExecContext(ctx, "UPDATE system_backup_v2_installation_state SET active_config_version=2 WHERE origin_installation_id=?", id)
		healthMust(t, err)
		before := healthStateBytes(t, ctx, db, id)
		token, err = store.Observe(ctx, writer, ControlLoopResult{}, probe)
		healthExpectFence(t, token, err)
		reader, err := systembackupread.NewReader(db, &healthSQLScope{installation: id})
		healthMust(t, err)
		if value, err := reader.ReadControlHealth(ctx); err == nil || value != (systembackupread.ControlHealthSnapshot{}) {
			t.Fatal("old-config observation returned partial health")
		}
		if healthStateBytes(t, ctx, db, id) != before {
			t.Fatal("fenced current-config write changed installation")
		}
	})
	t.Run("actual_constraints_and_fk", func(t *testing.T) {
		id := healthOwnedFixture(t, ctx, db, input)
		before := healthStateBytes(t, ctx, db, id)
		_, err := store.BeginWriter(ctx, id, 1, "health:leader", 0)
		healthMust(t, err)
		for _, query := range []string{
			"UPDATE system_backup_v2_control_health SET writer_epoch=0 WHERE origin_installation_id=?",
			"UPDATE system_backup_v2_control_health SET writer_epoch=9007199254740992 WHERE origin_installation_id=?",
			"UPDATE system_backup_v2_control_health SET writer_owner='' WHERE origin_installation_id=?",
			"UPDATE system_backup_v2_control_health SET controller_health='healthy' WHERE origin_installation_id=?",
			"UPDATE system_backup_v2_control_health SET expires_at=observed_at WHERE origin_installation_id=?",
		} {
			_, err := db.ExecContext(ctx, query, id)
			var mysqlErr *mysql.MySQLError
			if !errors.As(err, &mysqlErr) || mysqlErr.Number != 3819 {
				t.Fatal("actual CHECK was not enforced", err)
			}
		}
		for _, table := range []string{"system_backup_v2_installation_state", "system_backup_v2_configs"} {
			_, err := db.ExecContext(ctx, "DELETE FROM "+table+" WHERE origin_installation_id=?", id)
			var mysqlErr *mysql.MySQLError
			if !errors.As(err, &mysqlErr) || mysqlErr.Number != 1451 {
				t.Fatal("actual FK did not restrict deletion", err)
			}
		}
		if healthStateBytes(t, ctx, db, id) != before {
			t.Fatal("constraint probes changed installation")
		}
	})
	t.Run("committed_reply_loss_poisoned_observer", func(t *testing.T) {
		id := healthOwnedFixture(t, ctx, db, input)
		before := healthStateBytes(t, ctx, db, id)
		lossConfig, err := mysql.ParseDSN(cfg.FormatDSN())
		healthMust(t, err)
		lossConfig.InterpolateParams = true
		connector, err := mysql.NewConnector(lossConfig)
		healthMust(t, err)
		loss := &healthReplyConnector{Connector: connector}
		lossDB := sql.OpenDB(loss)
		defer lossDB.Close()
		lossStore := ControlHealthStore{DB: lossDB}
		writer, err := lossStore.BeginWriter(ctx, id, 1, "health:reply-loss", 0)
		healthMust(t, err)
		observer, err := NewControlHealthObserver(lossStore, writer, probe)
		healthMust(t, err)
		if err := observer.Observe(ctx, ControlLoopResult{}); !errors.Is(err, ErrControlHealthFence) {
			t.Fatal("lost committed reply escaped", err)
		}
		if loss.lost.Load() != 1 {
			t.Fatal("actual successful SQL reply was not intercepted")
		}
		if err := observer.Observe(ctx, ControlLoopResult{}); !errors.Is(err, ErrControlHealthFence) {
			t.Fatal("poisoned observer resumed")
		}
		if loss.calls.Load() != 1 {
			t.Fatal("unknown reply caused SQL retry")
		}
		var sequence uint64
		healthMust(t, db.QueryRowContext(ctx, "SELECT observation_sequence FROM system_backup_v2_control_health WHERE origin_installation_id=?", id).Scan(&sequence))
		if sequence != 1 || healthRead(t, ctx, db, id).ControllerHealth() != "healthy" {
			t.Fatal("independent read did not find one committed observation")
		}
		if healthStateBytes(t, ctx, db, id) != before {
			t.Fatal("reply-loss path changed installation")
		}
	})
	t.Run("completed_control_loop_and_fenced_stop", func(t *testing.T) {
		id := healthOwnedFixture(t, ctx, db, input)
		before := healthStateBytes(t, ctx, db, id)
		writer, err := store.BeginWriter(ctx, id, 1, "health:loop", 0)
		healthMust(t, err)
		observer, err := NewControlHealthObserver(store, writer, probe)
		healthMust(t, err)
		var order []string
		loop := ControlLoop{Guard: SQLUTCReadinessProbe{DB: db}, GateRecovery: recordedGateRecoveryPass{order: &order}, KillSwitch: recordedKillSwitchPass{order: &order}, Deadline: recordedDeadlinePass{order: &order}, Interval: DefaultReconcile, Observer: observer}
		healthMust(t, loop.runOnce(ctx))
		if healthRead(t, ctx, db, id).ControllerHealth() != "healthy" {
			t.Fatal("actual loop result was not recorded")
		}
		_, err = store.BeginWriter(ctx, id, 1, "health:new-loop", 1)
		healthMust(t, err)
		ticks := make(chan time.Time, 2)
		ticks <- time.Now()
		ticks <- time.Now()
		close(ticks)
		if err := loop.runWithTicks(ctx, ticks); !errors.Is(err, ErrControlHealthFence) {
			t.Fatal("fenced loop continued", err)
		}
		if len(order) != 6 {
			t.Fatal("loop ran a second pass after health fence", order)
		}
		if healthRead(t, ctx, db, id).ControllerHealth() != "unknown" {
			t.Fatal("old loop overwrote new epoch")
		}
		if healthStateBytes(t, ctx, db, id) != before {
			t.Fatal("loop observation changed installation")
		}
	})
	t.Logf("PASS D control health actual SQL candidate; cases=7 catalog=%s migrations=%d synthetic_read_scope=yes fixture_root_grants=yes production_approval=no", input.Catalog, len(input.Migrations))
}

// Intercept exactly one reply after a real autocommitted MySQL UPDATE. This
// simulates reply loss, not a database rollback or a network retry.
type healthReplyConnector struct {
	driver.Connector
	lost  atomic.Int32
	calls atomic.Int32
}

func (c *healthReplyConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return healthReplyConn{Conn: conn, owner: c}, nil
}

type healthReplyConn struct {
	driver.Conn
	owner *healthReplyConnector
}

func (c healthReplyConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	executor, ok := c.Conn.(driver.ExecerContext)
	if !ok {
		return nil, errors.New("actual MySQL ExecContext required")
	}
	result, err := executor.ExecContext(ctx, query, args)
	if err != nil {
		return result, err
	}
	if query == controlHealthRecordSQL {
		c.owner.calls.Add(1)
		n, err := result.RowsAffected()
		if err != nil {
			return nil, err
		}
		if n == 1 && c.owner.lost.CompareAndSwap(0, 1) {
			return nil, fmt.Errorf("synthetic loss after actual autocommitted health UPDATE")
		}
	}
	return result, nil
}
