//go:build systembackup_mysql

package systembackupkekadapter

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"clawreef/internal/migrationcatalog"
	reg "clawreef/internal/systembackupkekregistry"
)

// This exercises the actual original SQL source and KEK fence in ONE native
// transaction. It does not construct external-snapshot/backfill/adoption
// receipts or claim that a SQL census is complete coverage. The existing helper
// installs the full current catalog in a marked, disposable local schema.
func TestBootstrapOriginalSQLSourceAndKEKFenceMySQL(t *testing.T) {
	if os.Getenv("A_SIGNING_MYSQL_CREDENTIALS_FILE") == "" || os.Getenv("A_SIGNING_MYSQL_SERVER_UUID") == "" {
		t.Fatal("independently pinned disposable local MySQL is mandatory; missing inputs are not a passed/ skipped integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if migrationcatalog.ReviewedFileCount != 177 {
		t.Fatal("this source/fence integration requires the reviewed complete 177-file catalog")
	}
	db, identity := censusOriginalMySQL(t, ctx)
	var authorityTables int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('system_backup_minio_owner_heads','system_backup_minio_owner_grants','system_backup_minio_owner_refs','system_backup_signing_resource_heads','system_backup_signing_resource_grants')`).Scan(&authorityTables); err != nil || authorityTables != 5 {
		t.Fatal("full catalog authority tables were not actually installed", err)
	}
	const installation = "installation_original_source_fence"
	if _, err := db.ExecContext(ctx, `INSERT INTO system_backup_config_versions(version,config_json,actor_id) VALUES (1,'{"original_source":"nonempty"}',1)`); err != nil {
		t.Fatal("nonempty original source setup", err)
	}
	scanner, err := NewSQLCoverageCensus(db, identity, installation)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := scanner.Observe(ctx)
	if err != nil {
		t.Fatal("full current catalog must have an explicit reviewed census disposition for every source/control table", err)
	}
	found := false
	for _, table := range observed.Facts().Tables {
		if table.Table == "system_backup_config_versions" {
			found = table.Rows == 1
		}
	}
	if !found {
		t.Fatal("actual nonempty legacy source absent from original census")
	}
	// Only this actual observation can produce SQL witnesses. The other three
	// witness kinds and historical adoption are deliberately not synthesized.
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	for _, partition := range []reg.Partition{reg.RetainedArtifacts, reg.InflightAndUnknownWrites, reg.HoldsAndCatalog, reg.RestoreAndPrune} {
		source := reg.SourceRecord{SourceID: "original_sql_test_owner", RecordID: "sev_original_sql_" + string(partition), RecordVersion: "v1"}
		signed, pin, err := observed.SignOriginalSQLWitness(ctx, partition, source, "v1", "snapshot-v1", "fence-v1", observed.Facts().ObservedAt.Add(time.Minute), key)
		if err != nil {
			t.Fatal("actual original SQL witness", partition, err)
		}
		if len(signed.Record) == 0 || len(signed.Signature) != ed25519.SignatureSize || pin.Kind != "original_sql_census" || pin.Partition != partition {
			t.Fatal("SQL witness lost its actual purpose/partition")
		}
		if _, err := authenticateCoverageWitness(coverageEnvelopeForNativeSource(t, signed, observed.Facts().ObservedAt.Add(time.Minute)), pin, time.Now().UTC()); err != nil {
			t.Fatal("actual producer witness did not authenticate", err)
		}
	}
	// Initialize only the real registry fence. This creates no coverage receipt.
	initial, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer initial.Rollback()
	if _, _, err = (reg.SQLStore{}).Bind(ctx, initial, installation); err != nil {
		t.Fatal(err)
	}
	if err = initial.Commit(); err != nil {
		t.Fatal(err)
	}
	expected, err := (reg.SQLStore{}).ReadSnapshot(ctx, db, installation)
	if err != nil {
		t.Fatal(err)
	}
	original, err := scanner.BeginOriginalTransaction(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tx := original.Tx()
	defer tx.Rollback()
	locked, err := scanner.LockOriginalSources(ctx, original, observed)
	if err != nil {
		t.Fatal("original source ranges before KEK fence", err)
	}
	bound, snapshot, err := (reg.SQLStore{}).Bind(ctx, tx, installation)
	if err != nil || !reg.SameSnapshotFacts(snapshot.Facts(), expected) {
		t.Fatal("same original transaction did not retain exact source/fence facts", err)
	}
	if err := locked.Recheck(ctx, tx); err != nil {
		t.Fatal("unchanged source under actual KEK fence", err)
	}
	if _, err := bound.CompleteScan(ctx); !errors.Is(err, reg.ErrKEKCoverage) {
		t.Fatal("actual SQL observation/fence substituted for missing complete coverage", err)
	}
	var blockerID uint64
	if err := tx.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&blockerID); err != nil {
		t.Fatal(err)
	}
	writer, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Release the lock owner before rolling back the blocked writer, also on
	// Fatal, so cleanup does not wait while retaining its own blocker locks.
	defer func() { tx.Rollback(); writer.Rollback() }()
	var writerID uint64
	if err := writer.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&writerID); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() {
		result, err := writer.ExecContext(ctx, `UPDATE system_backup_v2_kek_fences SET epoch=epoch+1 WHERE installation_id=?`, installation)
		if err == nil {
			if n, e := result.RowsAffected(); e != nil || n != 1 {
				err = errors.New("same original fence writer did not update exactly one row")
			}
		}
		finished <- err
	}()
	waiting := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		select {
		case err := <-finished:
			t.Fatal("competing actual fence writer completed while original source transaction held the fence", err)
		default:
		}
		var count uint64
		err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM performance_schema.data_lock_waits w
			JOIN performance_schema.data_locks r ON r.ENGINE=w.ENGINE AND r.ENGINE_LOCK_ID=w.REQUESTING_ENGINE_LOCK_ID
			JOIN performance_schema.data_locks b ON b.ENGINE=w.ENGINE AND b.ENGINE_LOCK_ID=w.BLOCKING_ENGINE_LOCK_ID
			JOIN performance_schema.threads rt ON rt.THREAD_ID=w.REQUESTING_THREAD_ID
			JOIN performance_schema.threads bt ON bt.THREAD_ID=w.BLOCKING_THREAD_ID
			WHERE r.OBJECT_SCHEMA=? AND r.OBJECT_NAME='system_backup_v2_kek_fences' AND b.OBJECT_SCHEMA=r.OBJECT_SCHEMA AND b.OBJECT_NAME=r.OBJECT_NAME
			AND rt.PROCESSLIST_ID=? AND bt.PROCESSLIST_ID=? AND r.LOCK_TYPE='RECORD' AND r.LOCK_STATUS='WAITING' AND b.LOCK_STATUS='GRANTED'`, identity.Database, writerID, blockerID).Scan(&count)
		if err != nil {
			t.Fatal("actual fence lock-wait observation", err)
		}
		if count > 0 {
			waiting = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !waiting {
		t.Fatal("exact competing writer was not observed waiting on the original fence")
	}
	if err := locked.Recheck(ctx, tx); err != nil {
		t.Fatal("same original source changed while competing fence writer waited", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE system_backup_config_versions SET config_json='{"original_source":"changed_in_original_tx"}' WHERE version=1`); err != nil {
		t.Fatal(err)
	}
	if err := locked.Recheck(ctx, tx); err == nil {
		t.Fatal("same-transaction source mutation survived the original locked census")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal("SAME actual writer failed after the original source/fence owner released", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("same fence writer remained blocked after release")
	}
	if err := writer.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := locked.Recheck(ctx, tx); err == nil {
		t.Fatal("closed original source transaction remained usable")
	}
}

// Transport only: the signed bytes above came from the actual private census
// producer. No fixture constructs witness facts or signs arbitrary receipts.
func coverageEnvelopeForNativeSource(t *testing.T, signed SignedCoverageOwnerRecord, until time.Time) capabilityEvidence {
	t.Helper()
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return capabilityEvidence{raw: raw, until: until}
}
