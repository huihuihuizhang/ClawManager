package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	appdb "clawreef/internal/db"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	mysql "github.com/go-sql-driver/mysql"
)

// Real direct-grant/probe protocol only. No task, readiness, C, worker, provider,
// acceptance success or terminal receipt is constructed. Config and alert rows
// below are private DATA samples under the complete versioned production DDL.
func TestAPublicationAlertGrantsActualMySQL(t *testing.T) {
	file, expectedUUID := os.Getenv("A_SIGNING_MYSQL_CREDENTIALS_FILE"), os.Getenv("A_SIGNING_MYSQL_SERVER_UUID")
	if file == "" || expectedUUID == "" {
		t.Skip("requires explicitly pinned owned local TLS SQL credentials and UUID")
	}
	if !filepath.IsAbs(file) {
		t.Fatal("owned credential path must be absolute")
	}
	var credential struct {
		Host, User, Password, CAFile, TLSServerName, ServerUUID string
		Port                                                    int
	}
	raw, err := os.ReadFile(file)
	if err != nil || json.Unmarshal(raw, &credential) != nil || credential.Host != "127.0.0.1" || credential.ServerUUID != expectedUUID || credential.Port < 1 || credential.TLSServerName == "" {
		t.Fatal("owned local TLS identity unavailable")
	}
	clear(raw)
	pem, err := os.ReadFile(credential.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("owned TLS CA unavailable")
	}
	var nonce [8]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	run := hex.EncodeToString(nonce[:])
	schema, installation, tlsName := "ad_a_alert_"+run, "installation_a_alert_"+run, "a-alert-"+run
	if err = mysql.RegisterTLSConfig(tlsName, &tls.Config{RootCAs: roots, ServerName: credential.TLSServerName, MinVersion: tls.VersionTLS13}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mysql.DeregisterTLSConfig(tlsName) })
	config := mysql.NewConfig()
	config.User, config.Passwd, config.Net, config.Addr = credential.User, credential.Password, "tcp", net.JoinHostPort(credential.Host, strconv.Itoa(credential.Port))
	config.ParseTime, config.Loc, config.TLSConfig = true, time.UTC, tlsName
	config.Params = map[string]string{"time_zone": "'+00:00'"}
	config.Timeout, config.ReadTimeout, config.WriteTimeout = 5*time.Second, 15*time.Second, 15*time.Second
	credential.Password = ""
	admin, err := sql.Open("mysql", config.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var uuid string
	if admin.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&uuid) != nil || uuid != expectedUUID {
		admin.Close()
		t.Fatal("actual SQL UUID mismatch")
	}
	if _, err = admin.ExecContext(ctx, "CREATE DATABASE `"+schema+"`"); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.DBName = schema
	owner, err := sql.Open("mysql", config.FormatDSN())
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	users := []string{}
	pools := []*sql.DB{}
	markerReady := false
	t.Cleanup(func() {
		for _, pool := range pools {
			_ = pool.Close()
		}
		defer admin.Close()
		defer owner.Close()
		var actual, marker string
		if !markerReady || admin.QueryRow("SELECT @@server_uuid").Scan(&actual) != nil || actual != expectedUUID || owner.QueryRow("SELECT run_id FROM _a_alert_owner").Scan(&marker) != nil || marker != run {
			t.Error("refuse cleanup: owned nonce/UUID marker mismatch")
			return
		}
		for _, user := range users {
			if _, err := admin.Exec("DROP USER '" + user + "'@'127.0.0.1'"); err != nil {
				t.Error(err)
			}
		}
		if _, err := admin.Exec("DROP DATABASE `" + schema + "`"); err != nil {
			t.Error(err)
		}
	})
	if _, err = owner.ExecContext(ctx, "CREATE TABLE _a_alert_owner(run_id CHAR(16) PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	if _, err = owner.ExecContext(ctx, "INSERT INTO _a_alert_owner VALUES(?)", run); err != nil {
		t.Fatal(err)
	}
	markerReady = true
	catalog, err := appdb.EmbeddedMigrationCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if err = appdb.ApplyPinnedMigrations(ctx, owner, appdb.MigrationTarget{ServerUUID: expectedUUID, Database: schema, CatalogSHA256: catalog.Hash}); err != nil {
		t.Fatal(err)
	}
	aAlertSeedConfigData(t, ctx, owner, installation)
	if _, err = owner.ExecContext(ctx, `INSERT INTO system_backup_v2_alert_states(origin_installation_id,rule_key,matrix_key,task_type,task_purpose,config_version) VALUES(?,'publication-grant-probe','all','backup','acceptance',1)`, installation); err != nil {
		t.Fatal(err)
	}
	if _, err = owner.ExecContext(ctx, "CREATE TABLE a_alert_ddl_canary(id INT PRIMARY KEY) ENGINE=InnoDB"); err != nil {
		t.Fatal(err)
	}
	t.Log("fresh permission-only SQL coordinates", schema, expectedUUID, credential.Port, "migration catalog", catalog.Hash)
	assertNoAuthority := func(t *testing.T) {
		t.Helper()
		for _, table := range []string{"system_backup_v2_backups", "system_backup_v2_execution_readiness", "system_backup_v2_execution_records", "system_backup_v2_job_send_intents", "system_backup_v2_kek_bindings"} {
			var count int
			if owner.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&count) != nil || count != 0 {
				t.Fatal("permission test created task/provider/readiness state", table, count)
			}
		}
	}
	assertNoAuthority(t)
	for _, test := range []struct {
		name, suffix, omitted string
		control, publication  bool
	}{
		{"publication", "p", "", false, true}, {"control-evidence-publication", "c", "", true, true},
		{"publication-missing-insert", "pi", "INSERT", false, true}, {"publication-missing-update", "pu", "UPDATE", false, true},
		{"control-publication-missing-insert", "ci", "INSERT", true, true}, {"control-publication-missing-update", "cu", "UPDATE", true, true},
		{"capture-only-control-evidence", "cap", "", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			user := "a_al_" + run + "_" + test.suffix
			var secret [24]byte
			if _, err := rand.Read(secret[:]); err != nil {
				t.Fatal(err)
			}
			password := hex.EncodeToString(secret[:])
			clear(secret[:])
			if _, err := admin.ExecContext(ctx, "CREATE USER '"+user+"'@'127.0.0.1' IDENTIFIED BY '"+password+"'"); err != nil {
				t.Fatal(err)
			}
			users = append(users, user)
			var grants []string
			var err error
			if test.control {
				grants, err = c.ControlEvidenceGrantSQL(schema, user, "127.0.0.1", false, true, test.publication, test.publication)
			} else {
				grants, err = c.PublicationGrantSQL(schema, user, "127.0.0.1", false, true, true)
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, grant := range grants {
				if _, err = admin.ExecContext(ctx, grant); err != nil {
					t.Fatal("official role application", err)
				}
			}
			if test.omitted != "" {
				if _, err = admin.ExecContext(ctx, "REVOKE "+test.omitted+" ON `"+schema+"`.`system_backup_v2_alert_states` FROM '"+user+"'@'127.0.0.1'"); err != nil {
					t.Fatal(err)
				}
			}
			principalConfig := config.Clone()
			principalConfig.User, principalConfig.Passwd = user, password
			password = ""
			pool, err := sql.Open("mysql", principalConfig.FormatDSN())
			principalConfig.Passwd = ""
			if err != nil {
				t.Fatal(err)
			}
			pools = append(pools, pool)
			defer pool.Close()
			var statusName, cipher, protocol string
			if pool.QueryRowContext(ctx, "SHOW SESSION STATUS LIKE 'Ssl_cipher'").Scan(&statusName, &cipher) != nil || cipher == "" {
				t.Fatal("actual principal TLS missing")
			}
			if pool.QueryRowContext(ctx, "SHOW SESSION STATUS LIKE 'Ssl_version'").Scan(&statusName, &protocol) != nil || protocol != "TLSv1.3" {
				t.Fatal("actual principal TLS protocol changed")
			}
			before := aAlertWholeRows(t, ctx, owner)
			probe := func() error {
				if test.control {
					return (c.SQLControlEvidenceGrantProbe{DB: pool, Schema: schema, User: user, Runtime: true, ProviderPermits: test.publication, Publication: test.publication}).Check(ctx)
				}
				return (c.SQLPublicationGrantProbe{DB: pool, Schema: schema, User: user, Runtime: true, ProviderPermits: true}).Check(ctx)
			}
			probeErr := probe()
			if test.omitted != "" {
				if probeErr == nil || !strings.Contains(probeErr.Error(), "lacks "+test.omitted+" privilege on system_backup_v2_alert_states") {
					t.Fatal("production startup probe did not reject missing exact verb", probeErr)
				}
				assertNoAuthority(t)
			} else if probeErr != nil {
				t.Fatal("official generated role rejected by actual production probe", probeErr)
			}
			rows, err := pool.QueryContext(ctx, "SHOW GRANTS")
			if err != nil {
				t.Fatal(err)
			}
			alertGrant := ""
			for rows.Next() {
				var grant string
				if rows.Scan(&grant) != nil {
					t.Fatal("SHOW GRANTS scan")
				}
				if strings.Contains(grant, "`.`system_backup_v2_alert_states`") {
					alertGrant = grant
				}
			}
			if err = rows.Err(); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			if err = rows.Close(); err != nil {
				t.Fatal(err)
			}
			t.Log("actual direct alert grant", alertGrant)
			if test.omitted == "" && test.publication {
				if !strings.HasPrefix(alertGrant, "GRANT SELECT, INSERT, UPDATE ON ") {
					t.Fatal("publication alert privileges are not exact S/I/U", alertGrant)
				}
				tx, err := pool.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				upsert := `INSERT INTO system_backup_v2_alert_states(origin_installation_id,rule_key,matrix_key,task_type,task_purpose,config_version) VALUES(?,'publication-grant-probe','all','backup','acceptance',1) ON DUPLICATE KEY UPDATE id=id`
				if _, err = tx.ExecContext(ctx, upsert, installation); err != nil {
					t.Fatal("actual original-shape upsert", err)
				}
				if _, err = tx.ExecContext(ctx, `INSERT INTO system_backup_v2_alert_states(origin_installation_id,rule_key,matrix_key,task_type,task_purpose,config_version) VALUES(?,'publication-grant-probe-new','all','backup','acceptance',1)`, installation); err != nil {
					t.Fatal("actual insert", err)
				}
				result, err := tx.ExecContext(ctx, `UPDATE system_backup_v2_alert_states SET row_version=row_version+1 WHERE origin_installation_id=? AND rule_key='publication-grant-probe'`, installation)
				if err != nil {
					t.Fatal("actual update", err)
				}
				if n, _ := result.RowsAffected(); n != 1 {
					t.Fatal("actual update did not affect exact private row", n)
				}
				if err = tx.Rollback(); err != nil {
					t.Fatal(err)
				}
			}
			if !test.publication {
				if !strings.HasPrefix(alertGrant, "GRANT SELECT ON ") {
					t.Fatal("capture-only control evidence gained alert write", alertGrant)
				}
				_, err = pool.ExecContext(ctx, `UPDATE system_backup_v2_alert_states SET row_version=row_version WHERE origin_installation_id=?`, installation)
				aAlertMustDeny(t, err)
				_, err = pool.ExecContext(ctx, `INSERT INTO system_backup_v2_alert_states(origin_installation_id,rule_key,config_version) VALUES(?,'capture-write-denied',1)`, installation)
				aAlertMustDeny(t, err)
			}
			for _, query := range []string{"UPDATE system_backup_v2_configs SET config_sha256=config_sha256 WHERE FALSE", "UPDATE audit_logs SET id=id WHERE FALSE", "INSERT INTO audit_logs SELECT * FROM audit_logs WHERE FALSE", "UPDATE users SET id=id WHERE FALSE", "CREATE TABLE a_alert_forbidden_ddl(id INT)", "DROP TABLE a_alert_ddl_canary"} {
				_, err = pool.ExecContext(ctx, query)
				aAlertMustDeny(t, err)
			}
			if !bytes.Equal(before, aAlertWholeRows(t, ctx, owner)) {
				t.Fatal("permission probe/rolled-back transaction changed persistent alert rows")
			}
			assertNoAuthority(t)
		})
	}
}

func aAlertMustDeny(t *testing.T, err error) {
	t.Helper()
	var native *mysql.MySQLError
	if !errors.As(err, &native) || (native.Number != 1142 && native.Number != 1143) {
		t.Fatal("expected actual MySQL table/column privilege denial", err)
	}
}

func aAlertWholeRows(t *testing.T, ctx context.Context, db *sql.DB) []byte {
	t.Helper()
	rows, err := db.QueryContext(ctx, "SELECT * FROM system_backup_v2_alert_states ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	out := []json.RawMessage{}
	for rows.Next() {
		values := make([]sql.RawBytes, len(columns))
		dest := make([]any, len(values))
		for n := range values {
			dest[n] = &values[n]
		}
		if rows.Scan(dest...) != nil {
			t.Fatal("whole alert row scan")
		}
		raw, err := json.Marshal(values)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, raw)
	}
	if rows.Err() != nil {
		t.Fatal(rows.Err())
	}
	raw, err := json.Marshal(struct {
		Columns []string
		Rows    []json.RawMessage
	}{columns, out})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func aAlertSeedConfigData(t *testing.T, ctx context.Context, db *sql.DB, installation string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "system-backup", "v12", "admin-control-redacted-examples.json"))
	if err != nil {
		t.Fatal(err)
	}
	var example struct {
		Request struct {
			Config map[string]any `json:"config"`
		} `json:"config_update_request"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&example) != nil {
		t.Fatal("config DATA example")
	}
	values := example.Request.Config
	canonical, err := ce.Canonical(values)
	if err != nil {
		t.Fatal(err)
	}
	flat := map[string]any{"origin_installation_id": installation, "version": 1, "config_sha256": hash(canonical), "config_size_bytes": len(canonical), "canonical_config_json": canonical, "created_by": "1", "change_reason": "private grant protocol DATA only"}
	for _, name := range []string{"enabled", "alert_profile", "minimum_recovery_points"} {
		flat[name] = values[name]
	}
	for _, group := range []string{"durations", "capacity", "concurrency", "preflight_limits"} {
		for name, value := range values[group].(map[string]any) {
			if group == "preflight_limits" {
				name = "preflight_" + name
			}
			flat[name] = value
		}
	}
	for _, entry := range values["registries"].([]any) {
		r := entry.(map[string]any)
		kind := r["registry_kind"].(string)
		flat[kind+"_registry_version"], flat[kind+"_registry_sha256"] = r["version"], r["sha256"]
	}
	for _, entry := range values["references"].([]any) {
		r := entry.(map[string]any)
		kind := r["purpose"].(string)
		flat[kind+"_identity_hash"], flat[kind+"_ref_version"] = r["identity_hash"], r["version"]
	}
	columns := make([]string, 0, len(flat))
	for name := range flat {
		columns = append(columns, name)
	}
	sort.Strings(columns)
	args := make([]any, 0, len(columns))
	for _, name := range columns {
		value := flat[name]
		if n, ok := value.(json.Number); ok {
			value = n.String()
		}
		args = append(args, value)
	}
	query := "INSERT INTO system_backup_v2_configs(" + strings.Join(columns, ",") + ") VALUES(" + strings.TrimSuffix(strings.Repeat("?,", len(columns)), ",") + ")"
	if _, err = db.ExecContext(ctx, query, args...); err != nil {
		t.Fatal(fmt.Errorf("private config DATA seed: %w", err))
	}
}
