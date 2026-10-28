package systembackupcontroller

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	"clawreef/internal/systembackup/flow"
	b "clawreef/internal/systembackup/publicadapter"
	d "clawreef/internal/systembackupdispatch"
	"github.com/go-sql-driver/mysql"
)

func recoveryInventoryFixture() ([]b.FrozenWriter, []recoveryParticipant, []recoveryWriterReceipt) {
	s := flow.State{UID: "original-source-uid", Generation: 7, Running: true, Checkpoint: "original-source-state"}
	raw, _ := json.Marshal(d.WriterState{UID: s.UID, Generation: s.Generation, Running: s.Running, Checkpoint: s.Checkpoint})
	return []b.FrozenWriter{{ID: "source", Original: s}}, []recoveryParticipant{{ID: "source", Generation: 3, State: "running", Result: "succeeded", Checkpoint: sql.NullString{String: recordHash(raw), Valid: true}}}, []recoveryWriterReceipt{{ID: "source", Original: raw, Digest: recordHash(raw), Resumed: true}}
}

func TestRecoveryInventoryDoesNotTreatLostPauseAsUntouched(t *testing.T) {
	frozen, physical, receipts := recoveryInventoryFixture()
	if _, e := validateRecoveryInventory(3, frozen, physical, receipts, true); e != nil {
		t.Fatal(e)
	}
	// Former NOT EXISTS-only selection calls this untouched even though the
	// independent physical receipt proves it was paused. Both entry and final
	// release must now retain protection, rather than acknowledge a fake resume.
	for _, final := range []bool{false, true} {
		if _, e := validateRecoveryInventory(3, frozen, physical, nil, final); e == nil {
			t.Fatal("lost pause became untouched", final)
		}
	}
	physical[0].State, physical[0].Result = "pausing", "none"
	if _, e := validateRecoveryInventory(3, frozen, physical, nil, false); e == nil {
		t.Fatal("lost pre-ACK stop became untouched")
	}
}

func TestRecoveryIntentWitnessAndReleaseUseRealSQL(t *testing.T) {
	port := os.Getenv("TEST_SYSTEM_BACKUP_MYSQL_PORT")
	if port == "" {
		t.Skip("requires disposable localhost MySQL")
	}
	cfg := mysql.NewConfig()
	cfg.User = "root"
	cfg.Net = "tcp"
	cfg.Addr = "127.0.0.1:" + port
	cfg.DBName = "mysql"
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	db, e := sql.Open("mysql", cfg.FormatDSN())
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, stop := context.WithTimeout(context.Background(), 20*time.Second)
	defer stop()
	// Connection-local tables exercise the production transaction queries without
	// creating an application installation or touching persistent source tables.
	for _, q := range []string{
		"CREATE TEMPORARY TABLE system_backup_v2_runtime_captures(task_public_id VARCHAR(40),application_scope VARCHAR(128),gate_generation BIGINT,registry_sha256 CHAR(64),writers_json BLOB) ENGINE=InnoDB",
		"CREATE TEMPORARY TABLE system_backup_participants(scope VARCHAR(128),participant_id VARCHAR(128),generation BIGINT,state VARCHAR(16),resume_result VARCHAR(16),checkpoint_hash CHAR(64) NULL,updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6)) ENGINE=InnoDB",
		"CREATE TEMPORARY TABLE system_backup_v2_runtime_writers(task_public_id VARCHAR(40),writer_id VARCHAR(128),original_json BLOB,original_sha256 CHAR(64),resumed BOOLEAN,paused BOOLEAN DEFAULT FALSE) ENGINE=InnoDB",
		"CREATE TEMPORARY TABLE system_backup_v2_events(origin_installation_id VARCHAR(128),target_type VARCHAR(32),target_public_id VARCHAR(40),event_type VARCHAR(128),level VARCHAR(16),message TEXT,request_id VARCHAR(128)) ENGINE=InnoDB",
	} {
		if _, e = db.ExecContext(ctx, q); e != nil {
			t.Fatal(e)
		}
	}
	frozen, _, receipts := recoveryInventoryFixture()
	raw, _ := json.Marshal(frozen)
	a := d.Authority{TaskPublicID: "sbk_recovery_fixture", MaintenanceFencingToken: 3}
	if _, e = db.ExecContext(ctx, "INSERT INTO system_backup_v2_runtime_captures VALUES(?,'proof',3,?,?)", a.TaskPublicID, recordHash(raw), raw); e != nil {
		t.Fatal(e)
	}
	if _, e = db.ExecContext(ctx, "INSERT INTO system_backup_participants(scope,participant_id,generation,state,resume_result) VALUES('proof','source',3,'pausing','none')"); e != nil {
		t.Fatal(e)
	}
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = stampPauseWitnessTx(ctx, tx, "proof", 3, "source", receipts[0].Digest); e != nil {
		tx.Rollback()
		t.Fatal(e)
	}
	if e = tx.Rollback(); e != nil {
		t.Fatal(e)
	}
	var checkpoint sql.NullString
	if e = db.QueryRowContext(ctx, "SELECT checkpoint_hash FROM system_backup_participants").Scan(&checkpoint); e != nil || checkpoint.Valid {
		t.Fatal("rolled-back pause witness survived", e)
	}
	tx, e = db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = stampPauseWitnessTx(ctx, tx, "proof", 3, "source", receipts[0].Digest); e != nil {
		tx.Rollback()
		t.Fatal(e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	tx, e = db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	_, e = recoveryInventoryTx(ctx, tx, a, "proof", false)
	tx.Rollback()
	if e == nil {
		t.Fatal("missing pre-ACK intent released source")
	}
	tx, e = db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	_, e = reconcileRecoveryInventoryTx(ctx, tx, a, "proof", false, true)
	if e != nil {
		tx.Rollback()
		t.Fatal("original intent could not be reconstructed", e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	var paused, resumed bool
	if e = db.QueryRowContext(ctx, "SELECT paused,resumed FROM system_backup_v2_runtime_writers").Scan(&paused, &resumed); e != nil || paused || resumed {
		t.Fatal("intent repair fabricated a stop or recovery ACK", e)
	}
	tx, e = db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	_, e = recoveryInventoryTx(ctx, tx, a, "proof", true)
	tx.Rollback()
	if e == nil {
		t.Fatal("reconstructed intent alone released source")
	}
	if _, e = db.ExecContext(ctx, "UPDATE system_backup_v2_runtime_writers SET resumed=TRUE"); e != nil {
		t.Fatal(e)
	}
	if _, e = db.ExecContext(ctx, "UPDATE system_backup_participants SET state='running',resume_result='succeeded'"); e != nil {
		t.Fatal(e)
	}
	tx, e = db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	_, e = recoveryInventoryTx(ctx, tx, a, "proof", true)
	tx.Rollback()
	if e != nil {
		t.Fatal("complete original recovery refused", e)
	}
}

func TestRecoveryInventoryPreservesUntouchedAndOriginallyStoppedWriters(t *testing.T) {
	frozen, physical, _ := recoveryInventoryFixture()
	frozen[0].Original.Running = false
	physical[0].Checkpoint = sql.NullString{}
	physical[0].State, physical[0].Result = "pausing", "none"
	ids, e := validateRecoveryInventory(3, frozen, physical, nil, false)
	if e != nil || len(ids) != 1 || ids[0] != "source" {
		t.Fatal("untouched source cannot be released", e, ids)
	}
	physical[0].State, physical[0].Result = "running", "succeeded"
	if _, e = validateRecoveryInventory(3, frozen, physical, nil, true); e != nil {
		t.Fatal("untouched final source rejected", e)
	}
	if frozen[0].Original.Running {
		t.Fatal("stopped source changed to running")
	}
}

func TestRecoveryInventoryRejectsIncompleteOrForeignFacts(t *testing.T) {
	for _, fault := range []string{"missing_member", "foreign_member", "epoch", "duplicate_frozen", "duplicate_receipt", "wrong_original", "wrong_digest", "missing_resume", "physical_unconfirmed", "checkpoint"} {
		t.Run(fault, func(t *testing.T) {
			frozen, physical, receipts := recoveryInventoryFixture()
			switch fault {
			case "missing_member":
				physical = nil
			case "foreign_member":
				physical[0].ID = "other-source"
			case "epoch":
				physical[0].Generation++
			case "duplicate_frozen":
				frozen = append(frozen, frozen[0])
				physical = append(physical, physical[0])
			case "duplicate_receipt":
				receipts = append(receipts, receipts[0])
			case "wrong_original":
				receipts[0].Original = []byte(`{"UID":"foreign"}`)
				receipts[0].Digest = recordHash(receipts[0].Original)
			case "wrong_digest":
				receipts[0].Digest = "wrong"
			case "missing_resume":
				receipts[0].Resumed = false
			case "physical_unconfirmed":
				physical[0].State = "paused"
			case "checkpoint":
				physical[0].Checkpoint.String = "wrong"
			}
			if _, e := validateRecoveryInventory(3, frozen, physical, receipts, true); e == nil {
				t.Fatal("unsafe recovery released", fault)
			}
		})
	}
}
