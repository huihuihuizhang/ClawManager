package domain_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"clawreef/internal/repository"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	resources "clawreef/internal/systembackupresources"
)

func northboundRawRows(t *testing.T, ctx context.Context, db *sql.DB, table domain.Table) []domain.Row {
	t.Helper()
	var cols []string
	for _, c := range table.Columns {
		cols = append(cols, "`"+c.Name+"`")
	}
	rows, e := db.QueryContext(ctx, "SELECT "+strings.Join(cols, ",")+" FROM `"+table.Name+"` ORDER BY `id`")
	if e != nil {
		t.Fatal("independent complete owner SQL read")
	}
	defer rows.Close()
	var out []domain.Row
	for rows.Next() {
		values := make([]any, len(cols))
		dest := make([]any, len(cols))
		for i := range values {
			dest[i] = &values[i]
		}
		if rows.Scan(dest...) != nil {
			t.Fatal("independent owner raw cell scan")
		}
		r := domain.Row{}
		for i, value := range values {
			c := domain.Cell{}
			switch v := value.(type) {
			case nil:
				c.Null = true
			case []byte:
				c.Bytes = append([]byte(nil), v...)
			case int64:
				c = domain.Text(strconv.FormatInt(v, 10))
			case uint64:
				c = domain.Text(strconv.FormatUint(v, 10))
			case string:
				c = domain.Text(v)
			default:
				t.Fatal("lossy owner SQL representation")
			}
			r[table.Columns[i].Name] = c
		}
		out = append(out, r)
	}
	if rows.Err() != nil {
		t.Fatal("independent owner read iteration")
	}
	return out
}
func northboundReadback(t *testing.T, f *gatewayNative, db *sql.DB, source domain.Snapshot, targetVersion string) {
	t.Helper()
	for _, name := range []string{"northbound_admin_settings", "northbound_settings_audit", "northbound_owner_records"} {
		table := nativeGatewayTable(source, name)
		actual := northboundRawRows(t, f.ctx, db, table)
		if len(actual) != len(table.Rows) {
			t.Fatal("owner raw row count differs", name)
		}
		for i, original := range table.Rows {
			for column, want := range original {
				if name == "northbound_admin_settings" {
					switch column {
					case "api_enabled", "owner_teams_enabled", "external_node_port":
						want = domain.Text("0")
					case "require_explicit_callers":
						want = domain.Text("1")
					case "version":
						want = domain.Text(targetVersion)
					}
				}
				if name == "northbound_settings_audit" && (column == "before_json" || column == "after_json") && !want.Null {
					want = domain.Text(`"[REDACTED]"`)
				}
				got := actual[i][column]
				if want.Null != got.Null || !bytes.Equal(want.Bytes, got.Bytes) {
					t.Fatalf("independent actual raw cell differs table=%s column=%s", name, column)
				}
			}
		}
	}
}
func northboundRollback(t *testing.T, f *gatewayNative, db *sql.DB, version string) {
	t.Helper()
	var users, owner, audit int
	var actor sql.NullInt64
	var actualVersion string
	if db.QueryRowContext(f.ctx, "SELECT COUNT(*) FROM users WHERE id=1 AND username='admin' AND password_hash='bootstrap'").Scan(&users) != nil || users != 1 || db.QueryRowContext(f.ctx, "SELECT COUNT(*) FROM northbound_owner_records").Scan(&owner) != nil || owner != 0 || db.QueryRowContext(f.ctx, "SELECT COUNT(*) FROM northbound_settings_audit").Scan(&audit) != nil || audit != 0 || db.QueryRowContext(f.ctx, "SELECT version,updated_by FROM northbound_admin_settings WHERE id=1").Scan(&actualVersion, &actor) != nil || actualVersion != version || !actor.Valid || actor.Int64 != 1 {
		t.Fatal("failed restore did not retain bootstrap and original owner rows")
	}
}
func northboundConcurrentLocks(t *testing.T, f *gatewayNative, db *sql.DB) {
	t.Helper()
	conn, e := db.Conn(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	if _, e = conn.ExecContext(f.ctx, "SET SESSION innodb_lock_wait_timeout=1"); e != nil {
		t.Fatal("actual concurrent lock timeout setup")
	}
	for _, q := range []string{"UPDATE northbound_admin_settings SET version=version+1 WHERE id=1 AND version=1", "INSERT INTO northbound_settings_audit(id,actor_user_id,action,created_at) VALUES(19,NULL,'concurrent.probe',UTC_TIMESTAMP(6))"} {
		if _, e = conn.ExecContext(f.ctx, q); nativeImageMySQLNumber(e) != 1205 {
			t.Fatal("second real SQL session was not excluded by current singleton/audit range locks", e)
		}
	}
	t.Log("second actual SQL session: concurrent version CAS and empty-audit-range INSERT both denied with real1205 while the common SERIALIZABLE restore TX holds locks")
}

func TestNorthboundPublicWorkerActualTLSMySQL(t *testing.T) {
	f, sourceAdmin := northboundNativeSetup(t)
	store, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	key := bytes.Repeat([]byte{96}, 32)
	binding := staging.Binding{BackupID: "owned-northbound-" + f.nonce, Attempt: "1", Path: "mysql/source", CaptureContextHash: strings.Repeat("a", 64), EnvelopeID: "owned-northbound-dek"}
	spec := worker.DatabaseSpec{Address: f.cfg.Addr, Name: f.source, ServerUUID: f.uuid, TLSServerName: "gateway-restore-native.local", RootCA: f.ca, MaxRows: 1000, MaxMemoryBytes: 8 << 20}
	sourceUser := "nbs_" + f.nonce[:12]
	source := f.principal(sourceUser, f.source, "SELECT")
	capture := worker.Request{Version: worker.Version, Operation: "capture-database", Database: &spec, Deadline: time.Now().Add(2 * time.Minute), ArtifactName: "northbound-empty-audit.enc", MaxArchiveBytes: 8 << 20, MaxCompressedBytes: 8 << 20, Binding: binding}
	captureCheck := func(ctx context.Context, purpose string, r worker.Request) error {
		if purpose == "" || r.Operation != "capture-database" || r.Binding != binding || r.Database.Name != f.source {
			return errors.New("owned Northbound source scope differs")
		}
		return f.observe(ctx, f.source, sourceUser)
	}
	emptyCapture, e := worker.RunDatabase(f.ctx, capture, worker.DatabaseEnvironment{Database: source, Staging: store, Key: key, Check: captureCheck})
	if e != nil {
		t.Fatal("actual public source with legal settings/no-audit", e)
	}
	emptySource, e := domain.CaptureSource(f.ctx, source, domain.Limits{MaxRows: 1000, MaxBytes: 8 << 20}, f.source, f.uuid)
	if e != nil {
		t.Fatal("actual independent no-audit observation", e)
	}
	northboundNativeAddAudits(f, sourceAdmin)
	capture.ArtifactName = "northbound-full-audit.enc"
	fullCapture, e := worker.RunDatabase(f.ctx, capture, worker.DatabaseEnvironment{Database: source, Staging: store, Key: key, Check: captureCheck})
	if e != nil {
		t.Fatal("actual public heterogeneous source capture", e)
	}
	fullSource, e := domain.CaptureSource(f.ctx, source, domain.Limits{MaxRows: 1000, MaxBytes: 8 << 20}, f.source, f.uuid)
	if e != nil {
		t.Fatal("actual complete owner observation", e)
	}
	if len(nativeGatewayTable(fullSource, "northbound_owner_records").Columns) != 56 || len(nativeGatewayTable(fullSource, "northbound_admin_settings").Columns) != 35 || len(nativeGatewayTable(fullSource, "northbound_settings_audit").Columns) != 6 {
		t.Fatal("actual migrations did not produce exact closed owner columns")
	}
	northboundNativeBridgeBoundaries(t, f, fullSource)
	f.revoke(source, sourceUser)
	sourceAdmin.Close()
	for index, mode := range []string{"missing-observation", "same-version-content-drift", "version-drift", "evidence-failure", "cancel-before-commit", "success-empty-audit", "success-full-audit", "success-absent-settings", "success-target-version5"} {
		t.Run(mode, func(t *testing.T) {
			name := "cm_drill_nb_" + strconv.Itoa(index) + "_" + f.nonce[:16]
			admin := f.schema(name)
			defer admin.Close()
			northboundNativeMigrations(f, admin)
			f.exec(admin, "INSERT INTO users(id,username,password_hash,role,is_active) VALUES(1,'admin','bootstrap','admin','1')")
			f.exec(admin, "UPDATE northbound_admin_settings SET updated_by=1")
			targetVersion := "2"
			if mode == "success-absent-settings" {
				f.exec(admin, "DELETE FROM northbound_admin_settings WHERE id=1")
				targetVersion = "1"
			}
			if mode == "success-target-version5" {
				f.exec(admin, "UPDATE northbound_admin_settings SET version=5 WHERE id=1")
				targetVersion = "6"
			}
			writerUser, readerUser := "nbw"+strconv.Itoa(index)+"_"+f.nonce[:12], "nbr"+strconv.Itoa(index)+"_"+f.nonce[:12]
			writer := f.principal(writerUser, name, "SELECT,INSERT,UPDATE,DELETE")
			reader := f.principal(readerUser, name, "SELECT")
			defer writer.Close()
			defer reader.Close()
			observation, e := northboundNativeObserve(f.ctx, reader, name, f.uuid)
			if e != nil {
				t.Fatal("actual independently read-only target observation", e)
			}
			beforeVersion := "1"
			if mode == "same-version-content-drift" {
				f.exec(admin, "UPDATE northbound_admin_settings SET core_request_timeout_seconds=29 WHERE id=1")
			}
			if mode == "version-drift" {
				sess := f.upper(name, "root", "")
				repo := repository.NewNorthboundRepository(sess)
				item, e := repo.GetAdminSettings()
				if e != nil {
					t.Fatal(e)
				}
				changed, e := repo.UpdateAdminSettings(f.ctx, item, 1, 1)
				sess.Close()
				if e != nil || !changed {
					t.Fatal("actual concurrent target CAS")
				}
				beforeVersion = "2"
			}
			evidence, e := os.OpenRoot(t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			defer evidence.Close()
			r := capture
			r.Operation = "restore-database"
			r.ArtifactName = ""
			r.PolicyVersion = "owned-northbound-057-067-077"
			r.Receipt = fullCapture.Receipt
			observed := fullSource
			if mode == "success-empty-audit" {
				r.Receipt = emptyCapture.Receipt
				observed = emptySource
			}
			d := spec
			d.Name = name
			d.Dependencies = northboundNativeAdapters(observed)
			d.Placements = f.policy.Placements
			d.EvidenceName = "northbound-expected.enc"
			d.EvidenceBinding = binding
			d.EvidenceBinding.Path = "mysql/expected"
			r.Database = &d
			child, cancel := context.WithCancel(f.ctx)
			defer cancel()
			check := func(ctx context.Context, purpose string, r worker.Request) error {
				if purpose == "" || r.Operation != "restore-database" || r.Binding != binding || r.Database.Name != name {
					return errors.New("owned Northbound restore scope differs")
				}
				if e := f.observe(ctx, name, writerUser); e != nil {
					return e
				}
				if purpose == "before-evidence" && mode == "evidence-failure" {
					evidence.Close()
				}
				if purpose == "before-evidence" && mode == "success-full-audit" {
					northboundConcurrentLocks(t, f, admin)
				}
				if purpose == "before-database-commit" && mode == "cancel-before-commit" {
					cancel()
				}
				return ctx.Err()
			}
			if mode == "missing-observation" {
				observation = nil
			}
			result, e := worker.RunDatabase(child, r, worker.DatabaseEnvironment{Database: writer, Staging: store, Evidence: evidence, Key: key, Check: check, NorthboundTarget: observation})
			if !strings.HasPrefix(mode, "success-") {
				if e == nil {
					t.Fatal("failed owner restore accepted")
				}
				northboundRollback(t, f, admin, beforeVersion)
				t.Log("public failure retained bootstrap, original settings and empty audit/owner tables")
				return
			}
			if e != nil || !result.Quarantined {
				t.Fatal("actual public owner restore", e)
			}
			northboundReadback(t, f, reader, observed, targetVersion)
			// The source and bootstrap both use ID1. The original was actually
			// deleted (SET NULL) before this source administrator was inserted.
			var password string
			if reader.QueryRowContext(f.ctx, "SELECT password_hash FROM users WHERE id=1").Scan(&password) != nil || password == "bootstrap" {
				t.Fatal("source administrator with same bootstrap ID not restored")
			}
			staleQuery := "UPDATE northbound_admin_settings SET version=version+1 WHERE id=1 AND version=1"
			if mode == "success-absent-settings" {
				staleQuery = "UPDATE northbound_admin_settings SET version=version+1 WHERE id=1 AND version=0"
			}
			stale, e := admin.ExecContext(f.ctx, staleQuery)
			if e != nil {
				t.Fatal(e)
			}
			affected, e := stale.RowsAffected()
			if e != nil || affected != 0 {
				t.Fatal("stale real CAS changed restored settings")
			}
			f.revoke(writer, writerUser)
			verify := r
			verify.Operation = "verify-database"
			verify.Receipt = result.Evidence
			verify.Binding = d.EvidenceBinding
			v := d
			v.EvidenceName = ""
			v.Placements = nil
			verify.Database = &v
			runNorthboundNativeVerifyChild(t, f, verify, key, evidence.Name(), readerUser)
			f.exec(admin, "UPDATE northbound_owner_records SET version=0 WHERE id=18446744073709551615")
			if _, e = worker.RunDatabase(f.ctx, verify, worker.DatabaseEnvironment{Database: reader, Staging: evidence, Key: key, Check: func(ctx context.Context, _ string, r worker.Request) error {
				return f.observe(ctx, r.Database.Name, readerUser)
			}}); e == nil {
				t.Fatal("fresh expected full raw-cell verification ignored changed bitmap")
			}
			t.Log("public capture/one-TX CAS+audit+owner restore/new-process SELECT-only verify; 35/6/56 actual raw columns, uint64/NULL/DECIMAL/private history, source-max version -> actual observed target+1/absence1, same-ID bootstrap and stale CAS rejection PASS")
		})
	}
}

func northboundNativeBridgeBoundaries(t *testing.T, f *gatewayNative, source domain.Snapshot) {
	t.Helper()
	name := "cm_drill_nb_boundary_" + f.nonce[:16]
	db := f.schema(name)
	defer db.Close()
	northboundNativeMigrations(f, db)
	f.exec(db, "INSERT INTO users(id,username,password_hash,role,is_active) VALUES(1,'admin','bootstrap','admin','1')")
	f.exec(db, "UPDATE northbound_admin_settings SET updated_by=1")
	observation, e := northboundNativeObserve(f.ctx, db, name, f.uuid)
	if e != nil {
		t.Fatal(e)
	}
	original, e := domain.NorthboundNativeBridgeSourceForTest(f.ctx, source)
	if e != nil {
		t.Fatal(e)
	}
	external, e := db.BeginTx(f.ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = resources.PrepareNorthboundRestoreInTransaction(f.ctx, external, observation, original, northboundNativeBudget()); e == nil {
		t.Fatal("arbitrary actual READ COMMITTED TX accepted")
	}
	external.Rollback()
	conn, e := db.Conn(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	tx, bound, e := resources.BeginNorthboundRestoreTransaction(f.ctx, conn, observation)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	p, e := resources.PrepareNorthboundRestoreInTransaction(f.ctx, tx, bound, original, northboundNativeBudget())
	if e != nil {
		t.Fatal("actual boundary prepare", e)
	}
	other, e := db.BeginTx(f.ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	if p.CheckBefore(f.ctx, other, resources.NorthboundRestoreScope{Database: name, ServerUUID: f.uuid}) == nil {
		t.Fatal("actual different TX reused candidate")
	}
	other.Rollback()
	if p.CheckBefore(f.ctx, tx, resources.NorthboundRestoreScope{Database: name, ServerUUID: "other-uuid"}) == nil {
		t.Fatal("other UUID reused candidate")
	}
	changed := original
	changed.Audit = resources.NorthboundRestoreTable{Columns: append([]string(nil), original.Audit.Columns...), Rows: append([]map[string]*string(nil), original.Audit.Rows...)}
	changed.Audit.Rows[0] = map[string]*string{}
	for name, value := range original.Audit.Rows[0] {
		changed.Audit.Rows[0][name] = value
	}
	different := `{"different":"raw-audit-same-redaction"}`
	changed.Audit.Rows[0]["after_json"] = &different
	if p.MatchesSource(changed) == nil {
		t.Fatal("actual prepared candidate accepted another original audit with same target redaction")
	}
	if _, e = tx.ExecContext(f.ctx, "UPDATE northbound_admin_settings SET updated_by=NULL WHERE id=1"); e != nil {
		t.Fatal(e)
	}
	if resources.ApplyNorthboundSettingsCAS(f.ctx, tx, p, p.SettingsProjection()) == nil || resources.DeleteNorthboundBootstrapInTransaction(f.ctx, tx, p) == nil {
		t.Fatal("manual actor NULL accepted as actual user deletion")
	}
	tx.Rollback()
	northboundRollback(t, f, db, "1")
	t.Log(fmt.Sprintf("actual scoped bridge: arbitrary READ COMMITTED, different TX/UUID, original raw audit drift and manual actor NULL all refused; real rollback retained bootstrap in %s", name))
}
