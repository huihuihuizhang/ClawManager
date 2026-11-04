//go:build systembackup_mysql

package systembackupkekadapter

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	kms "clawreef/internal/systembackupkms"
)

// Native full-schema transaction/row/default/EOF test. Signatures are declared
// protocol fixtures; native Vault/actual B/C source ownership is not simulated.
func TestRuntimeInstalledSQLSnapshotMySQLRejectsEveryUnknownOrChangedRow(t *testing.T) {
	if os.Getenv("A_SIGNING_MYSQL_CREDENTIALS_FILE") == "" || os.Getenv("A_SIGNING_MYSQL_SERVER_UUID") == "" {
		t.Fatal("pinned disposable MySQL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	db, identity := censusOriginalMySQL(t, ctx)
	original, public, key := ownerRecordFixture(t)
	defer clear(key)
	raw, signature := signOwner(original, key)
	imports := []OriginalRuntimeCapabilityImport{}
	for n, operation := range []kms.Operation{kms.Generate, kms.Unwrap, kms.Unwrap} {
		record, pin, private := providerCapabilityFixture(t, original.Binding, operation)
		record.Source.RecordID = fmt.Sprintf("sev_11111111-0000-4000-8000-%012x", n+1)
		pin.Source = record.Source
		evidence := signCapabilityFixture(t, record, private)
		clear(private)
		imports = append(imports, OriginalRuntimeCapabilityImport{Raw: evidence.raw, Pin: pin, Operation: operation})
	}
	writer, e := NewInstallationAuthorityWriter(db, original.Binding.InstallationID, identity, public)
	if e != nil {
		t.Fatal(e)
	}
	tx, e := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		t.Fatal(e)
	}
	saved, e := writer.StageInitialRuntimeAuthoritiesWithSnapshot(ctx, tx, raw, signature, imports, time.Now().UTC())
	if e != nil {
		tx.Rollback()
		t.Fatal("actual complete staging snapshot", e)
	}
	if tx.Commit() != nil {
		t.Fatal("commit")
	}
	if saved.FenceAfter != saved.FenceBefore+1 || len(saved.Rows) != 3 || len(saved.Columns) != 40 || saved.Evidence.Rows != 3 || saved.Chunks.Rows != 0 {
		t.Fatal("incomplete actual SQL receipt")
	}
	for _, mode := range []string{"unchanged", "changed-default", "changed-timestamp", "extra-row", "extra-chunk", "changed-mapping", "wrong-installation"} {
		t.Run(mode, func(t *testing.T) {
			tx, e := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback()
			installation := original.Binding.InstallationID
			switch mode {
			case "changed-default":
				_, e = tx.ExecContext(ctx, `UPDATE system_backup_v2_evidence SET next_reconcile_at=UTC_TIMESTAMP(6) WHERE public_id=?`, imports[0].Pin.Source.RecordID)
			case "changed-timestamp":
				_, e = tx.ExecContext(ctx, `UPDATE system_backup_v2_evidence SET created_at=TIMESTAMPADD(SECOND,-1,created_at) WHERE public_id=?`, imports[0].Pin.Source.RecordID)
			case "extra-row":
				_, e = tx.ExecContext(ctx, `INSERT INTO system_backup_v2_evidence(public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,inline_payload,content_checksum,content_size_bytes,media_type,encryption,redaction_classification,observed_health,expires_at) VALUES ('sev_22222222-0000-4000-8000-000000000001','system',?,'diagnostic','inline','{}',?,2,'application/json','none','internal','healthy',TIMESTAMPADD(MINUTE,1,UTC_TIMESTAMP(6)))`, installation, coveragePayloadSHA([]byte("{}")))
			case "extra-chunk":
				_, e = tx.ExecContext(ctx, `INSERT INTO system_backup_v2_evidence_chunks(evidence_id,chunk_index,plaintext_offset,plaintext_length,plaintext_sha256,object_frame_offset,object_frame_length,ciphertext_sha256,gcm_nonce,gcm_tag) SELECT id,0,0,1,?,0,1,?,UNHEX(REPEAT('00',12)),UNHEX(REPEAT('00',16)) FROM system_backup_v2_evidence WHERE public_id=?`, coveragePayloadSHA([]byte("x")), coveragePayloadSHA([]byte("y")), imports[0].Pin.Source.RecordID)
			case "changed-mapping":
				revoked := original
				revoked.GenerateRevoked = true
				b, s := signOwner(revoked, key)
				_, e = tx.ExecContext(ctx, `UPDATE system_backup_installation_kek_authority SET signed_record=?,signature=? WHERE installation_id=?`, b, s, installation)
			case "wrong-installation":
				installation = "installation_foreign"
			}
			if e != nil {
				t.Fatal("actual counterexample setup", e)
			}
			actual, e := ReadRuntimeInstalledSQLSnapshotTx(ctx, tx, identity, installation, raw, signature, imports, true)
			accepted := e == nil && SameRuntimeInstalledSQLRows(saved, actual)
			if accepted != (mode == "unchanged") {
				t.Fatalf("wrong full-row/EOF comparison: %v", e)
			}
			if tx.Rollback() != nil {
				t.Fatal("rollback")
			}
		})
	}

	for _, mode := range []string{"own17-only", "changed-own-default", "new-unowned-row"} {
		t.Run(mode, func(t *testing.T) {
			scanner, e := NewSQLCoverageCensus(db, identity, original.Binding.InstallationID)
			if e != nil {
				t.Fatal(e)
			}
			observed, e := scanner.Observe(ctx)
			if e != nil {
				t.Fatal(e)
			}
			pins, records := originalControlBatchFixture(t, observed)
			originalTx, e := scanner.BeginOriginalTransaction(ctx)
			if e != nil {
				t.Fatal(e)
			}
			defer originalTx.Tx().Rollback()
			cut, e := scanner.PrepareOriginalAdoptionControlCut(ctx, originalTx, observed, pins, time.Now().Add(45*time.Second))
			if e != nil {
				t.Fatal(e)
			}
			defer cut.Abort()
			if cut.Stage(ctx, records) != nil {
				t.Fatal("actual original own17 stage")
			}
			if _, e := ReadRuntimeInstalledSQLSnapshotTx(ctx, originalTx.Tx(), identity, original.Binding.InstallationID, raw, signature, imports, true); e == nil {
				t.Fatal("20 rows accepted without original cut")
			}
			if mode == "changed-own-default" {
				if _, e := originalTx.Tx().ExecContext(ctx, `UPDATE system_backup_v2_evidence SET next_reconcile_at=UTC_TIMESTAMP(6) WHERE public_id=?`, pins.Adoption.Source.RecordID); e != nil {
					t.Fatal(e)
				}
			}
			if mode == "new-unowned-row" {
				if _, e := originalTx.Tx().ExecContext(ctx, `INSERT INTO system_backup_v2_evidence(public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,inline_payload,content_checksum,content_size_bytes,media_type,encryption,redaction_classification,observed_health,expires_at) VALUES ('sev_33333333-0000-4000-8000-000000000001','system',?,'diagnostic','inline','{}',?,2,'application/json','none','internal','healthy',TIMESTAMPADD(MINUTE,1,UTC_TIMESTAMP(6)))`, original.Binding.InstallationID, coveragePayloadSHA([]byte("{}"))); e != nil {
					t.Fatal(e)
				}
			}
			actual, e := ReadRuntimeInstalledSQLSnapshotTx(ctx, originalTx.Tx(), identity, original.Binding.InstallationID, raw, signature, imports, true, cut)
			accepted := e == nil && SameRuntimeInstalledSQLRows(saved, actual)
			if accepted != (mode == "own17-only") {
				t.Fatalf("wrong original transaction/cut source accounting: %v", e)
			}
		})
	}
	// No signed staging receipt can turn a rolled-back batch into installed data.
	tx, e = db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM system_backup_v2_evidence WHERE evidence_type='capability_snapshot'`); e != nil {
		tx.Rollback()
		t.Fatal(e)
	}
	if _, e = ReadRuntimeInstalledSQLSnapshotTx(ctx, tx, identity, original.Binding.InstallationID, raw, signature, imports, true); e == nil {
		tx.Rollback()
		t.Fatal("missing actual installed rows accepted")
	}
	if tx.Rollback() != nil {
		t.Fatal("restore original fixture")
	}
}
