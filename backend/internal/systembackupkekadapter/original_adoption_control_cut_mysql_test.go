//go:build systembackup_mysql

package systembackupkekadapter

import (
	controller "clawreef/internal/systembackupcontroller"
	reg "clawreef/internal/systembackupkekregistry"
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"
)

// Real disposable MySQL/range locks/full177 schema/control-row staging. Physical
// proof signatures use explicit model fixtures; this test does NOT adopt or
// prove a genuine B/C fence/history. Root alone executes and cleans artifacts.
func TestOriginalAdoptionControlCutMySQLAccountsExactOwnRowsAndRejectsDrift(t *testing.T) {
	if os.Getenv("A_SIGNING_MYSQL_CREDENTIALS_FILE") == "" || os.Getenv("A_SIGNING_MYSQL_SERVER_UUID") == "" {
		t.Fatal("explicit independently pinned disposable MySQL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	db, identity := censusOriginalMySQL(t, ctx)
	installation := "installation_original_control_cut"
	if _, e := db.ExecContext(ctx, `INSERT INTO system_backup_config_versions(version,config_json,actor_id) VALUES (1,'{"nonempty_original_control":true}',1)`); e != nil {
		t.Fatal(e)
	}
	if _, e := db.ExecContext(ctx, `INSERT INTO system_backup_v2_evidence(public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,inline_payload,content_checksum,content_size_bytes,media_type,encryption,redaction_classification,observed_health,expires_at) VALUES ('sev_fixture_old_source','system',?,'diagnostic','inline','{}',?,2,'application/json','none','internal','healthy',TIMESTAMPADD(MINUTE,10,UTC_TIMESTAMP(6)))`, installation, coveragePayloadSHA([]byte("{}"))); e != nil {
		t.Fatal(e)
	}
	// A raw historical child row is intentionally retained even though it would
	// need semantic classification before REAL adoption. Census cannot omit it.
	if _, e := db.ExecContext(ctx, `INSERT INTO system_backup_v2_evidence_chunks(evidence_id,chunk_index,plaintext_offset,plaintext_length,plaintext_sha256,object_frame_offset,object_frame_length,ciphertext_sha256,gcm_nonce,gcm_tag) SELECT id,0,0,1,?,0,1,?,'n','t' FROM system_backup_v2_evidence WHERE public_id='sev_fixture_old_source'`, strings.Repeat("a", 64), strings.Repeat("b", 64)); e != nil {
		t.Fatal(e)
	}
	for _, fault := range []string{"unchanged", "owned-row-default-change", "new-unowned-control", "original-source-change", "owned-chunk-insert", "old-chunk-change"} {
		t.Run(fault, func(t *testing.T) {
			// Gate setup is a declared SQL model fixture, not a physical hold.
			var now time.Time
			var account string
			if e := db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6),CURRENT_USER()").Scan(&now, &account); e != nil {
				t.Fatal(e)
			}
			claim := controller.OriginalAdoptionReservation{Version: controller.OriginalAdoptionReservationVersion, OperationID: strings.Repeat("a", 32), ReservationID: strings.Repeat("b", 32), InstallationID: installation, ServerUUID: identity.ServerUUID, Database: identity.Database, Scope: controller.CaptureGateScope, GateOwner: "adoption:" + strings.Repeat("a", 32), GateGeneration: 4, AcquisitionEpoch: 5, AcquisitionRowVersion: 10, Phase: controller.GateHeld, WriterID: "deployment/test/original", ControlKind: "original-stopped-native", SourceWritersSHA256: strings.Repeat("c", 64), NativeRequestSHA256: strings.Repeat("d", 64), NotBefore: now.Add(-time.Microsecond), ExpiresAt: now.Add(time.Minute)}
			_, e := db.ExecContext(ctx, `INSERT INTO system_backup_v2_maintenance_locks(origin_installation_id,scope,gate_state,generation,fencing_token,lock_owner,heartbeat_at,lock_ttl_seconds,lease_expires_at,gate_acquisition_timeout_seconds,quiesce_max_hold_seconds,acquiring_started_at,held_at,acquisition_deadline_at,absolute_hold_deadline_at,state_changed_at,row_version,created_at,updated_at) VALUES (?,?,'held',4,6,?,?,180,?,10,120,?,?,?,?,?,11,?,?) ON DUPLICATE KEY UPDATE heartbeat_at=VALUES(heartbeat_at),lease_expires_at=VALUES(lease_expires_at),acquiring_started_at=VALUES(acquiring_started_at),held_at=VALUES(held_at),acquisition_deadline_at=VALUES(acquisition_deadline_at),absolute_hold_deadline_at=VALUES(absolute_hold_deadline_at),state_changed_at=VALUES(state_changed_at)`, installation, controller.CaptureGateScope, claim.GateOwner, now, now.Add(180*time.Second), now, now, now.Add(10*time.Second), now.Add(120*time.Second), now, now, now)
			if e != nil {
				t.Fatal(e)
			}
			pin := controller.OriginalAdoptionDatabasePin{ServerUUID: identity.ServerUUID, Database: identity.Database, Account: account}
			ro, e := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
			if e != nil {
				t.Fatal(e)
			}
			if p, e := controller.LockOriginalAdoptionReservation(ctx, ro, pin, claim); e != nil || p == nil {
				ro.Rollback()
				t.Fatal("native MySQL rejected permitted FOR SHARE in READ ONLY tx")
			}
			if ro.Rollback() != nil {
				t.Fatal("readonly share rollback")
			}
			preflight, e := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if e != nil {
				t.Fatal(e)
			}
			if _, e := controller.LockOriginalAdoptionReservation(ctx, preflight, pin, claim); e != nil {
				preflight.Rollback()
				t.Fatal("native lock-capable preflight", e)
			}
			if preflight.Rollback() != nil {
				t.Fatal("preflight rollback unconfirmed")
			}
			scanner, e := NewSQLCoverageCensus(db, identity, installation)
			if e != nil {
				t.Fatal(e)
			}
			observed, e := scanner.Observe(ctx)
			if e != nil {
				t.Fatal(e)
			}
			pins, records := originalControlBatchFixture(t, observed)
			original, e := scanner.BeginOriginalTransaction(ctx)
			if e != nil {
				t.Fatal(e)
			}
			defer original.Tx().Rollback()
			gate, e := controller.LockOriginalAdoptionReservation(ctx, original.Tx(), pin, claim)
			if e != nil {
				t.Fatal(e)
			}
			cut, e := scanner.PrepareOriginalAdoptionControlCut(ctx, original, observed, pins, time.Now().Add(45*time.Second))
			if e != nil {
				t.Fatal(e)
			}
			defer cut.Abort()
			if e = cut.Stage(ctx, records); e != nil {
				t.Fatal("exact own17 controls failed source reconciliation", e)
			}
			bound, _, e := (reg.SQLStore{}).Bind(ctx, original.Tx(), installation)
			if e != nil {
				t.Fatal(e)
			}
			if _, e := bound.CompleteScan(ctx); e == nil {
				t.Fatal("own17 controls became complete history")
			}
			if e := bound.AdoptCoverage(ctx, nil); e == nil {
				t.Fatal("missing genuine PreparedCoverage accepted")
			}
			switch fault {
			case "owned-row-default-change":
				_, e = original.Tx().ExecContext(ctx, "UPDATE system_backup_v2_evidence SET row_version=row_version+1 WHERE public_id=?", pins.Adoption.Source.RecordID)
			case "new-unowned-control":
				_, e = original.Tx().ExecContext(ctx, `INSERT INTO system_backup_v2_evidence(public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,inline_payload,content_checksum,content_size_bytes,media_type,encryption,redaction_classification,observed_health,expires_at) SELECT 'sev_fixture_unowned','system',?,'diagnostic','inline',inline_payload,content_checksum,content_size_bytes,'application/json','none','internal','healthy',expires_at FROM system_backup_v2_evidence WHERE public_id=?`, installation, pins.Adoption.Source.RecordID)
			case "original-source-change":
				_, e = original.Tx().ExecContext(ctx, `UPDATE system_backup_config_versions SET config_json='{"changed_original":true}' WHERE version=1`)
			case "owned-chunk-insert":
				_, e = original.Tx().ExecContext(ctx, `INSERT INTO system_backup_v2_evidence_chunks(evidence_id,chunk_index,plaintext_offset,plaintext_length,plaintext_sha256,object_frame_offset,object_frame_length,ciphertext_sha256,gcm_nonce,gcm_tag) SELECT id,0,0,1,?,0,1,?,'n','t' FROM system_backup_v2_evidence WHERE public_id=?`, strings.Repeat("e", 64), strings.Repeat("f", 64), pins.Adoption.Source.RecordID)
			case "old-chunk-change":
				_, e = original.Tx().ExecContext(ctx, `UPDATE system_backup_v2_evidence_chunks SET gcm_tag='different' WHERE evidence_id=(SELECT id FROM system_backup_v2_evidence WHERE public_id='sev_fixture_old_source')`)
			}
			if e != nil {
				t.Fatal(e)
			}
			e = cut.Recheck(ctx)
			if (fault == "unchanged") != (e == nil) {
				t.Fatal("own-control boundary drift decision", fault, e)
			}
			if fault != "unchanged" && cut.Recheck(ctx) == nil {
				t.Fatal("poisoned cut recovered into success")
			}
			if e := original.Tx().QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); e != nil || gate.Recheck(ctx, original.Tx(), now) != nil {
				t.Fatal("original current gate changed", e)
			}
			if e = cut.Abort(); e != nil {
				t.Fatal("SQL rollback unconfirmed", e)
			}
			var count int
			if e = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_evidence WHERE owner_target_public_id=?", installation).Scan(&count); e != nil || count != 1 {
				t.Fatal("rolled-back test controls persisted", count, e)
			}
		})
	}
}
