package domain_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clawreef/internal/ownerrecords"
	"clawreef/internal/repository"
	"clawreef/internal/systembackup/domain"
	resources "clawreef/internal/systembackupresources"
)

func northboundNativeDeclarations() resources.NorthboundRestoreDeclarations {
	return resources.NorthboundRestoreDeclarations{ExternalNodePort: 0, AllowedLiteTypes: []string{"openclaw", "hermes", "opencode", "deepseek-harness", "workbuddy"}, AllowedProTypes: []string{"openclaw", "hermes", "opencode", "deepseek-harness", "workbuddy"}, Limits: map[string]resources.NorthboundRestoreRange{
		"challenge_ttl_seconds": {15, 600}, "access_token_ttl_seconds": {60, 86400}, "refresh_token_ttl_seconds": {3600, 2592000}, "core_request_timeout_seconds": {5, 120},
		"challenge_rate_per_minute": {1, 10000}, "login_rate_per_minute": {1, 10000}, "account_login_rate_per_minute": {1, 10000}, "create_rate_per_minute": {1, 10000}, "query_rate_per_minute": {1, 100000}, "share_rate_per_minute": {1, 10000},
		"max_pending_operations": {1, 1000}, "operation_tick_milliseconds": {100, 60000}, "operation_lease_seconds": {5, 600}, "operation_max_attempts": {1, 20},
		"lite_memory_gb": {1, 128}, "lite_disk_gb": {1, 2048}, "pro_memory_gb": {1, 512}, "pro_disk_gb": {1, 4096}, "workbuddy_pro_memory_gb": {1, 512}, "workbuddy_pro_disk_gb": {1, 4096},
		"lite_cpu_cores": {10, 6400}, "pro_cpu_cores": {10, 9999}, "workbuddy_pro_cpu_cores": {10, 9999},
	}}
}
func northboundNativeBudget() resources.NorthboundRestoreBudget {
	return resources.NorthboundRestoreBudget{Rows: 1000, Bytes: 8 << 20}
}

func northboundNativeMigrations(f *gatewayNative, db *sql.DB) {
	// Only these empty supporting tables are named small fixtures. All 35/6/56
	// owner columns come from the complete, unchanged real migration files.
	for _, q := range []string{
		"CREATE TABLE teams(id INT PRIMARY KEY,user_id INT) ENGINE=InnoDB",
		"CREATE TABLE custom_team_templates(id INT PRIMARY KEY,user_id INT) ENGINE=InnoDB",
		"CREATE TABLE northbound_operations(id INT PRIMARY KEY,operation_id VARCHAR(128),status VARCHAR(24)) ENGINE=InnoDB",
	} {
		f.exec(db, q)
	}
	for _, name := range []string{"057_add_northbound_admin_settings.sql", "058_enable_deepseek_harness_pro.sql", "066_add_runtime_upgrade_fence.sql", "067_add_northbound_owner_records.sql", "077_add_northbound_owner_teams.sql"} {
		raw, e := os.ReadFile(filepath.Join("..", "..", "db", "migrations", name))
		if e != nil {
			f.t.Fatal("trusted complete Northbound migration unavailable")
		}
		f.exec(db, string(raw))
	}
}
func northboundNativeSetup(t *testing.T) (*gatewayNative, *sql.DB) {
	f := newGatewayNative(t)
	var core []domain.Table
	for _, table := range f.seed.Tables {
		if strings.HasPrefix(table.Name, "gateway_") {
			continue
		}
		if table.Name == "instances" {
			table.Columns = append(table.Columns, domain.Column{Name: "owner", Type: "varchar(255)", Nullable: true})
			for _, r := range table.Rows {
				r["owner"] = domain.Text("Private Fixture Owner")
			}
		}
		core = append(core, table)
	}
	f.seed.Tables = core
	f.policy.Dependencies = map[string]domain.TableAdapter{}
	f.source = "nb_source_" + f.nonce[:16]
	db := f.schema(f.source)
	northboundNativeMigrations(f, db)
	for _, table := range core {
		var cols, marks []string
		for _, c := range table.Columns {
			cols = append(cols, "`"+c.Name+"`")
			marks = append(marks, "?")
		}
		for _, r := range table.Rows {
			var args []any
			for _, c := range table.Columns {
				if r[c.Name].Null {
					args = append(args, nil)
				} else {
					args = append(args, r[c.Name].Bytes)
				}
			}
			f.exec(db, "INSERT INTO `"+table.Name+"`("+strings.Join(cols, ",")+") VALUES("+strings.Join(marks, ",")+")", args...)
		}
	}
	sess := f.upper(f.source, "root", "")
	repo := repository.NewNorthboundRepository(sess)
	f.exec(db, "UPDATE northbound_admin_settings SET version=77,updated_by=1")
	settings, e := repo.GetAdminSettings()
	if e != nil {
		t.Fatal("real source settings repository read")
	}
	settings.APIEnabled = true
	settings.OwnerTeamsEnabled = true
	settings.OwnerTeamCreationUserID = 4
	updated, e := repo.UpdateAdminSettings(f.ctx, settings, 77, 4)
	if e != nil || !updated {
		t.Fatal("real source CAS update")
	}
	updated, e = repo.UpdateAdminSettings(f.ctx, settings, 77, 4)
	if e != nil || updated {
		t.Fatal("real stale source CAS accepted")
	}
	var audits int
	var version string
	if db.QueryRowContext(f.ctx, "SELECT COUNT(*) FROM northbound_settings_audit").Scan(&audits) != nil || audits != 0 || db.QueryRowContext(f.ctx, "SELECT version FROM northbound_admin_settings WHERE id=1").Scan(&version) != nil || version != "78" {
		t.Fatal("legitimate source update without audit was not created")
	}
	store := &ownerrecords.Store{Session: sess}
	identity, e := store.Bind(f.ctx, 7)
	if e != nil || identity == nil {
		t.Fatal("real owner Bind producer", e)
	}
	at := time.Date(2026, 9, 3, 1, 2, 3, 0, time.UTC)
	applied, e := store.Apply(f.ctx, *identity, ownerrecords.Fact{Type: "invocation", Source: "restore_fixture", SourceID: "original-private-source", SessionID: "private-session", At: at, Prompt: 2, Completion: 3, Tokens: 5})
	if e != nil || !applied {
		t.Fatal("real owner Apply producer", e)
	}
	report, e := store.Report(f.ctx, identity.Owner, "month", "2026-09-01", time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC), true)
	if e != nil || report == nil || report.Revision == 0 || len(report.SavedRevisions) == 0 {
		t.Fatal("real owner saved Report producer", e)
	}
	f.exec(db, "INSERT INTO instances(id,user_id,owner,type,instance_mode,runtime_type,runtime_variant,os_type,status) VALUES(8,4,'historical deleted owner','openclaw','lite','gateway','linux','linux','stopped')")
	historical, e := store.Bind(f.ctx, 8)
	if e != nil || historical == nil {
		t.Fatal("real historical binding producer", e)
	}
	applied, e = store.Apply(f.ctx, *historical, ownerrecords.Fact{Type: "invocation", Source: "restore_fixture", SourceID: "historical-deleted-instance", At: at, Tokens: 7})
	if e != nil || !applied {
		t.Fatal("real historical usage producer", e)
	}
	if e = repository.NewInstanceRepository(sess).Delete(8); e != nil {
		t.Fatal("actual instance deletion history", e)
	}
	var retained, remaining int
	if db.QueryRowContext(f.ctx, "SELECT COUNT(*) FROM northbound_owner_records WHERE instance_id=8").Scan(&retained) != nil || retained < 2 || db.QueryRowContext(f.ctx, "SELECT COUNT(*) FROM instances WHERE id=8").Scan(&remaining) != nil || remaining != 0 {
		t.Fatal("actual deleted-instance owner history was not retained")
	}
	sess.Close()
	// Boundary rows follow all auto-increment producers. Source schema/rows are
	// recaptured from actual SQL; this in-memory row is only input fixture data.
	owner := domain.NorthboundOwnerNativeRowForTest()
	var cols, marks []string
	var args []any
	for name, cell := range owner {
		cols = append(cols, "`"+name+"`")
		marks = append(marks, "?")
		if cell.Null {
			args = append(args, nil)
		} else {
			args = append(args, cell.Bytes)
		}
	}
	f.exec(db, "INSERT INTO northbound_owner_records("+strings.Join(cols, ",")+") VALUES("+strings.Join(marks, ",")+")", args...)
	f.exec(db, "UPDATE northbound_admin_settings SET version=9223372036854775807")
	t.Log("real repository source CAS78 with no audit; real owner Bind/Apply/saved Report producers completed before capture; unsigned-max bitmap/deleted instance/DECIMAL boundary fixture added")
	return f, db
}

func northboundNativeAddAudits(f *gatewayNative, db *sql.DB) {
	sess := f.upper(f.source, "root", "")
	repo := repository.NewNorthboundRepository(sess)
	if repo.RecordSettingsAudit(f.ctx, 4, "api_key.update", nil, map[string]any{"user_id": 4, "key_id": 7, "private": "original audit body"}) != nil {
		f.t.Fatal("real heterogeneous source audit producer")
	}
	f.exec(db, "INSERT INTO users(id,username,password_hash,role,is_active) VALUES(99,'deleted-actor','owned','user','1')")
	if repo.RecordSettingsAudit(f.ctx, 99, "certificate.prepare", map[string]any{"dns_names": []string{"private.example.invalid"}}, nil) != nil {
		f.t.Fatal("real deleted actor audit producer")
	}
	f.exec(db, "DELETE FROM users WHERE id=99")
	f.exec(db, "INSERT INTO northbound_settings_audit(id,actor_user_id,action,before_json,after_json,created_at) VALUES(9223372036854775807,NULL,'settings.update',NULL,'null','2026-01-02 03:04:05.000007')")
	sess.Close()
}

func northboundNativeObserve(ctx context.Context, db *sql.DB, name, uuid string) (*resources.NorthboundTargetObservation, error) {
	return resources.ObserveNorthboundRestoreTarget(ctx, db, resources.NorthboundRestoreScope{Database: name, ServerUUID: uuid}, northboundNativeDeclarations(), northboundNativeBudget())
}
func northboundNativeAdapters(s domain.Snapshot) map[string]domain.TableAdapter {
	out := map[string]domain.TableAdapter{}
	for _, t := range s.Tables {
		normalizer := ""
		switch t.Name {
		case "northbound_admin_settings":
			normalizer = domain.NorthboundSettings077Normalizer
		case "northbound_settings_audit":
			normalizer = domain.NorthboundAudit057Normalizer
		case "northbound_owner_records":
			normalizer = domain.NorthboundOwner067Normalizer
		}
		if normalizer == "" {
			continue
		}
		a := domain.TableAdapter{SchemaSHA256: domain.SchemaDigest(t), Normalizer: normalizer, Columns: map[string]string{}}
		for _, c := range t.Columns {
			a.Columns[c.Name] = "preserve"
		}
		out[t.Name] = a
	}
	return out
}
