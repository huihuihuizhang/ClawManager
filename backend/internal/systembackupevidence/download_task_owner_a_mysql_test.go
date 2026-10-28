//go:build systembackup_mysql

package systembackupevidence

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// These rows exercise the published task schema and the actual SQL owner
// adapter. They are isolated test tasks, never historical production backfill.
type aTaskOwnerSQLSeed struct {
	kind, table, id, statement string
	args                       []any
}

func aTaskOwnerSQLSeeds(installation string, created, deadline time.Time, snapshot []byte) []aTaskOwnerSQLSeed {
	const tail = "11111111-2222-4333-8444-555555555555"
	common := "public_id,origin_installation_id,actor_type,actor_id,endpoint,idempotency_key,request_hash,request_id,config_version,config_snapshot_json,config_snapshot_size_bytes,config_snapshot_sha256,deadline_at,created_at"
	values := "?,?,'admin','42','OwnerSQLProbe',?,REPEAT('a',64),'owner-sql-probe',1,?,?,?,?,?"
	backup := "sbk_" + tail
	rows := []aTaskOwnerSQLSeed{
		{"backup", "system_backup_v2_backups", backup, "INSERT INTO system_backup_v2_backups(" + common + ",source_orchestrator,source_profile,matrix_key,runner,requested_parts,artifact_read_identity_hash,artifact_read_ref_version,artifact_ca_identity_hash,artifact_ca_ref_version,target_class,target_risks,target_failure_domain_id) VALUES(" + values + ",'kubernetes','single-node','k8s-single-node','k8s','mysql',REPEAT('b',64),'fixture-v1',REPEAT('c',64),'fixture-v1','dr-ready-external','','isolated')", nil},
		{"drill", "system_backup_v2_restore_drills", "sdr_" + tail, "INSERT INTO system_backup_v2_restore_drills(" + common + ",source_artifact_type,source_public_id,target_profile,restore_target_config_ref,restore_target_config_hash,cleanup_policy) VALUES(" + values + ",'backup',?,'single-node','isolated-target',REPEAT('d',64),'delete-on-success')", nil},
		{"preflight", "system_backup_v2_preflights", "spf_" + tail, "INSERT INTO system_backup_v2_preflights(" + common + ",source_artifact_type,source_public_id,target_profile,restore_target_config_ref,restore_target_config_hash,artifact_compatibility) VALUES(" + values + ",'backup',?,'single-node','isolated-target',REPEAT('d',64),'supported')", nil},
		{"artifact_verify", "system_backup_v2_artifact_verifications", "sav_" + tail, "INSERT INTO system_backup_v2_artifact_verifications(" + common + ",verification_scope,source_artifact_type,source_public_id,artifact_state_before,artifact_state_after,unusable_reason_before,unusable_reason_after) VALUES(" + values + ",'health','backup',?,'staging','staging','not_committed','not_committed')", nil},
	}
	for n := range rows {
		r := &rows[n]
		r.args = []any{r.id, installation, "owner-sql-probe-" + r.kind, snapshot, len(snapshot), hash(snapshot), deadline, created}
		if r.kind != "backup" {
			r.args = append(r.args, backup)
		}
	}
	return rows
}

func TestASQLTaskDownloadOwnersMySQLSeed(t *testing.T) {
	input, err := decodeADownloadMFAInputs(aDownloadMFASeed)
	if err != nil {
		t.Fatal(err)
	}
	p := aDownloadMFAPinnedFixture(t, input)
	seen := map[string]bool{}
	for _, row := range aTaskOwnerSQLSeeds("installation_test", time.Unix(1, 0), time.Unix(2, 0), p.db.config.CanonicalJSON()) {
		if seen[row.kind] || strings.Count(row.statement, "?") != len(row.args) || !strings.HasPrefix(row.statement, "INSERT INTO "+row.table+"(") || len(row.args[2].(string)) < 16 || len(row.args[2].(string)) > 128 {
			t.Fatal("invalid independent task SQL seed", row.kind)
		}
		seen[row.kind] = true
	}
	if len(seen) != 4 {
		t.Fatal("missing task owner kind")
	}
	t.Log("PASS SQL task owner seed; actual_mysql=not_run production_tasks=no")
}

type aTaskOwnerMySQLFixture struct {
	*aDownloadMFAFixture
	owners *SQLTaskDownloadOwners
	row    aTaskOwnerSQLSeed
}

func newATaskOwnerMySQLFixture(t *testing.T, input aDownloadMFAInputs, kind string) *aTaskOwnerMySQLFixture {
	t.Helper()
	f := newADownloadMFAFixture(t, input)
	x := &aTaskOwnerMySQLFixture{aDownloadMFAFixture: f}
	for _, row := range aTaskOwnerSQLSeeds(f.svc.InstallationID, f.initial.CreatedAt.Add(-time.Minute), f.initial.OwnerDeadline, f.admissionPinnedFixture.db.config.CanonicalJSON()) {
		_, err := f.db.ExecContext(f.ctx, row.statement, row.args...)
		mustSQL(t, err)
		if row.kind == kind {
			x.row = row
		}
	}
	if x.row.kind == "" {
		t.Fatal("unknown SQL task owner")
	}
	i := &f.initial.Manifest.Identity
	i.OwnerType, i.OwnerID = kind, x.row.id
	key, err := keyFor("evidence", *i)
	mustSQL(t, err)
	f.initial.Ref.RelativeKey = key
	_, err = f.db.ExecContext(f.ctx, "UPDATE system_backup_v2_evidence SET owner_target_type=?,owner_target_public_id=?,storage_relative_key=?,storage_relative_key_hash=? WHERE public_id=?", kind, x.row.id, key, hash([]byte(key)), i.ID)
	mustSQL(t, err)
	// Remove the older suites' synthetic owner source: no code in this probe
	// can accidentally fall back to its visibility/deadline callback.
	_, err = f.db.ExecContext(f.ctx, "DROP TABLE synthetic_download_mfa_owner")
	mustSQL(t, err)
	registry := SQLRegistry{DB: f.db, Installation: i.Installation, ServerUUID: f.identity.ServerUUID, Database: f.identity.Database}
	x.owners, err = NewSQLTaskDownloadOwners(SQLTaskDownloadOwnersConfig{Registry: registry, Sessions: f.environment.config.Sessions, RegistryDirectory: f.configuration.RegistryDirectory})
	mustSQL(t, err)
	t.Cleanup(func() {
		// Owner reads/locks are not nonce, Operation, claim or audit grants.
		// Transaction cleanup registered by preview runs before this check.
		for _, table := range []string{"system_backup_v2_operations", "system_backup_v2_strong_auth_nonces"} {
			var count int
			if e := f.db.QueryRowContext(f.ctx, "SELECT COUNT(*) FROM "+table).Scan(&count); e != nil || count != 0 {
				t.Error("owner reader acquired mutation effects", table, count, e)
			}
		}
		var audits, claims int
		if e := f.db.QueryRowContext(f.ctx, "SELECT COUNT(*) FROM audit_logs WHERE user_id=42").Scan(&audits); e != nil || audits != f.audits {
			t.Error("owner reader wrote audit", audits, e)
		}
		if e := f.db.QueryRowContext(f.ctx, "SELECT COUNT(*) FROM system_backup_v2_evidence WHERE claim_owner IS NOT NULL OR claim_expires_at IS NOT NULL").Scan(&claims); e != nil || claims != 0 {
			t.Error("owner reader created claim", claims, e)
		}
	})
	return x
}

func (x *aTaskOwnerMySQLFixture) preview(t *testing.T) (*sql.Tx, Record, error) {
	t.Helper()
	tx, err := x.db.BeginTx(x.ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	mustSQL(t, err)
	t.Cleanup(func() { tx.Rollback() })
	r, err := x.owners.Preview(x.ctx, tx, x.svc.InstallationID, x.env.actor, x.initial.Manifest.Identity.ID)
	return tx, r, err
}

func (x *aTaskOwnerMySQLFixture) observeBlockedWrite(t *testing.T, hold *sql.Tx, table, query string, args ...any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(x.ctx, 8*time.Second)
	defer cancel()
	done := make(chan error, 1)
	drained := false
	go func() {
		_, err := x.db.ExecContext(ctx, query, args...)
		done <- err
	}()
	// Always release and drain before database cleanup, including assertion
	// failure; a timeout alone is not evidence of an actual InnoDB lock wait.
	defer func() {
		hold.Rollback()
		if !drained {
			<-done
		}
	}()
	until := time.Now().Add(3 * time.Second)
	observed := false
	for time.Now().Before(until) {
		var count int
		err := x.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM performance_schema.data_lock_waits w JOIN performance_schema.data_locks l ON l.ENGINE_LOCK_ID=w.REQUESTING_ENGINE_LOCK_ID WHERE l.OBJECT_SCHEMA=? AND l.OBJECT_NAME=?`, x.identity.Database, table).Scan(&count)
		mustSQL(t, err)
		if count > 0 {
			observed = true
			break
		}
		select {
		case err := <-done:
			drained = true
			t.Fatal("competing writer did not wait for original owner/reference", err)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !observed {
		t.Fatal("actual owner/reference lock wait not observed")
	}
	mustSQL(t, hold.Rollback())
	err := <-done
	drained = true
	if err != nil {
		t.Fatal("writer did not finish after original transaction released", err)
	}
	t.Log("OBSERVED actual SQL owner/reference lock wait", table)
}

func TestASQLTaskDownloadOwnersMySQL(t *testing.T) {
	raw, err := os.ReadFile(os.Getenv("D_PROVIDER_REGISTRATION_DDL"))
	mustSQL(t, err)
	if hash(raw) != os.Getenv("D_PROVIDER_REGISTRATION_DDL_SHA256") {
		t.Fatal("SQL owner capsule pin")
	}
	input, err := decodeADownloadMFAInputs(raw)
	mustSQL(t, err)
	for _, name := range []string{"backup", "drill", "preflight", "artifact_verify", "wrong_installation", "revoked_actor", "changed_original_deadline", "unknown_reference_column", "missing_reference_column", "original_owner_lock", "empty_reference_range"} {
		t.Run(name, func(t *testing.T) {
			// Each isolated case owns its setup error. A failed DDL in an earlier
			// case must not prevent later lock probes from reaching their SQL.
			var err error
			kind := name
			if kind != "drill" && kind != "preflight" && kind != "artifact_verify" {
				kind = "backup"
			}
			x := newATaskOwnerMySQLFixture(t, input, kind)
			switch name {
			case "wrong_installation":
				// Keep the evidence-installation FK enabled. First create the
				// unrelated installation and its required config snapshot;
				// the concrete owner still belongs to the original installation.
				values := aDownloadMFAConfigCells(x.admissionPinnedFixture)
				values["origin_installation_id"] = "installation_other"
				rows, e := x.db.QueryContext(x.ctx, "SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='system_backup_v2_configs' ORDER BY ORDINAL_POSITION")
				mustSQL(t, e)
				var columns []string
				var args []any
				for rows.Next() {
					var column string
					mustSQL(t, rows.Scan(&column))
					if value, ok := values[column]; ok {
						columns = append(columns, column)
						args = append(args, value)
					}
				}
				mustSQL(t, rows.Err())
				mustSQL(t, rows.Close())
				_, err = x.db.ExecContext(x.ctx, "INSERT INTO system_backup_v2_configs("+strings.Join(columns, ",")+") VALUES("+strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")+")", args...)
				mustSQL(t, err)
				_, err = x.db.ExecContext(x.ctx, "INSERT INTO system_backup_v2_installation_state(origin_installation_id,active_config_version,last_effective_enabled_transition_at,matrix_key) VALUES('installation_other',1,UTC_TIMESTAMP(6),'k8s-cluster')")
				mustSQL(t, err)
				_, err = x.db.ExecContext(x.ctx, "UPDATE system_backup_v2_evidence SET origin_installation_id='installation_other' WHERE public_id=?", x.initial.Manifest.Identity.ID)
			case "revoked_actor":
				_, err = x.db.ExecContext(x.ctx, "UPDATE users SET is_active=FALSE WHERE id=42")
			case "unknown_reference_column":
				_, err = x.db.ExecContext(x.ctx, "CREATE TABLE system_owner_probe_extra(id BIGINT PRIMARY KEY,evidence_public_id CHAR(40)) ENGINE=InnoDB")
			case "missing_reference_column":
				if !regexp.MustCompile(`^amfa_[a-f0-9]{32}$`).MatchString(x.identity.Database) {
					t.Fatal("negative schema fixture requires its owned database")
				}
				// Only this disposable negative-schema fixture drops the exact
				// dependent CHECK and temporarily rebuilds its named FK. MySQL
				// 8.4 cannot rename this FK column with ALGORITHM=INPLACE.
				// Keep FK checks enabled and restore the same RESTRICT edge before
				// exercising the actual owner reader. Production DDL is unchanged.
				_, err = x.db.ExecContext(x.ctx, "ALTER TABLE system_backup_v2_dependency_health DROP CHECK sbv2_chk_sb_dependency_evidence")
				mustSQL(t, err)
				_, err = x.db.ExecContext(x.ctx, "ALTER TABLE system_backup_v2_dependency_health DROP FOREIGN KEY sbv2_fk_sb_dependency_evidence")
				mustSQL(t, err)
				_, err = x.db.ExecContext(x.ctx, "ALTER TABLE system_backup_v2_dependency_health RENAME COLUMN evidence_id TO hidden_reference, ALGORITHM=COPY")
				mustSQL(t, err)
				_, err = x.db.ExecContext(x.ctx, "ALTER TABLE system_backup_v2_dependency_health ADD CONSTRAINT sbv2_fk_sb_dependency_evidence FOREIGN KEY (hidden_reference) REFERENCES system_backup_v2_evidence(id) ON DELETE RESTRICT, ALGORITHM=COPY")
				mustSQL(t, err)
				var original, hidden, foreignKey, sessionChecks, globalChecks int
				mustSQL(t, x.db.QueryRowContext(x.ctx, `SELECT
					(SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='system_backup_v2_dependency_health' AND COLUMN_NAME='evidence_id'),
					(SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='system_backup_v2_dependency_health' AND COLUMN_NAME='hidden_reference'),
					(SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE k JOIN information_schema.REFERENTIAL_CONSTRAINTS r ON r.CONSTRAINT_SCHEMA=k.CONSTRAINT_SCHEMA AND r.TABLE_NAME=k.TABLE_NAME AND r.CONSTRAINT_NAME=k.CONSTRAINT_NAME WHERE k.TABLE_SCHEMA=DATABASE() AND k.TABLE_NAME='system_backup_v2_dependency_health' AND k.CONSTRAINT_NAME='sbv2_fk_sb_dependency_evidence' AND k.COLUMN_NAME='hidden_reference' AND k.REFERENCED_TABLE_SCHEMA=DATABASE() AND k.REFERENCED_TABLE_NAME='system_backup_v2_evidence' AND k.REFERENCED_COLUMN_NAME='id' AND r.DELETE_RULE='RESTRICT'),
					@@session.foreign_key_checks, @@global.foreign_key_checks`).Scan(&original, &hidden, &foreignKey, &sessionChecks, &globalChecks))
				if original != 0 || hidden != 1 || foreignKey != 1 || sessionChecks != 1 || globalChecks != 1 {
					t.Fatal("missing reference fixture did not preserve its renamed FK")
				}
				t.Log("OBSERVED missing reference fixture renamed column with FK retained")
			}
			mustSQL(t, err)
			tx, r, err := x.preview(t)
			if name == "wrong_installation" || name == "revoked_actor" || name == "unknown_reference_column" || name == "missing_reference_column" {
				if err == nil {
					t.Fatal("unavailable actual owner/metadata was accepted")
				}
				return
			}
			mustSQL(t, err)
			if r.Manifest.Identity != x.initial.Manifest.Identity || !r.OwnerDeadline.Equal(x.initial.OwnerDeadline) || !r.CreatedAt.Equal(x.initial.CreatedAt) {
				t.Fatal("preview replaced the persisted original identity/deadline")
			}
			if name == "changed_original_deadline" {
				_, err = tx.ExecContext(x.ctx, "UPDATE "+x.row.table+" SET deadline_at=deadline_at+INTERVAL 1 SECOND WHERE public_id=?", x.row.id)
				mustSQL(t, err)
				if x.owners.LockOwnerReferences(x.ctx, tx, r) == nil {
					t.Fatal("changed original deadline acquired authority")
				}
				return
			}
			mustSQL(t, x.owners.LockOwnerReferences(x.ctx, tx, r))
			mustSQL(t, x.owners.Recheck(x.ctx, tx, x.env.actor, r))
			switch name {
			case "original_owner_lock":
				x.observeBlockedWrite(t, tx, x.row.table, "UPDATE "+x.row.table+" SET row_version=row_version+1 WHERE public_id=?", x.row.id)
			case "empty_reference_range":
				var id int64
				mustSQL(t, tx.QueryRowContext(x.ctx, "SELECT id FROM system_backup_v2_evidence WHERE public_id=?", r.Manifest.Identity.ID).Scan(&id))
				x.observeBlockedWrite(t, tx, "system_backup_v2_dependency_health", `INSERT INTO system_backup_v2_dependency_health(dependency_kind,identity_hash,identity_version,owner_target_type,owner_target_public_id,observed_health,health_reason,checked_at,expires_at,evidence_id,evidence_sha256) VALUES('evidence',REPEAT('a',64),'owner-probe','backup',?,'healthy','none',UTC_TIMESTAMP(6),UTC_TIMESTAMP(6)+INTERVAL 1 HOUR,?,?)`, x.row.id, id, r.Manifest.Identity.ContentHash)
			}
			if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
				t.Fatal(err)
			}
		})
	}
	if !t.Failed() {
		t.Log("PASS actual SQL task owner cases=11 owner_adapter=SQLTaskDownloadOwners production_tasks=no provider_read=no production_approval=no")
	}
}
