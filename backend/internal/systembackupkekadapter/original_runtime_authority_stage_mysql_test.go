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

// Real disposable full-schema MySQL transaction test. Signing inputs are
// explicitly controlled protocol fixtures, NOT proof of native Vault ACLs or a
// real installation. Existing pinned migration/owned cleanup helper is reused.
func TestOriginalRuntimeAuthorityBatchMySQLAtomicAndRejectsCounterexamples(t *testing.T) {
	if os.Getenv("A_SIGNING_MYSQL_CREDENTIALS_FILE") == "" || os.Getenv("A_SIGNING_MYSQL_SERVER_UUID") == "" {
		t.Fatal("pinned disposable MySQL credentials/UUID required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	db, identity := censusOriginalMySQL(t, ctx)
	original, public, key := ownerRecordFixture(t)
	defer clear(key)
	for index, mode := range []string{"missing-proof", "wrong-installation", "wrong-database", "expired", "revoked", "wrong-signature", "rollback", "commit"} {
		t.Run(mode, func(t *testing.T) {
			r := original
			now := time.Now().UTC()
			database := identity
			installation := r.Binding.InstallationID
			if mode == "wrong-installation" {
				installation = "installation_foreign"
			}
			if mode == "wrong-database" {
				database.Database += "_foreign"
			}
			if mode == "expired" {
				r.Until = now.Add(-time.Second)
			}
			if mode == "revoked" {
				r.GenerateRevoked = true
			}
			raw, signature := signOwner(r, key)
			if mode == "wrong-signature" {
				signature[0] ^= 1
			}
			records := []OriginalRuntimeCapabilityImport{}
			for n, operation := range []kms.Operation{kms.Generate, kms.Unwrap, kms.Unwrap} {
				record, pin, private := providerCapabilityFixture(t, r.Binding, operation)
				record.Source.RecordID = fmt.Sprintf("sev_%08x-0000-4000-8000-%012x", index+1, n+1)
				pin.Source = record.Source
				evidence := signCapabilityFixture(t, record, private)
				clear(private)
				records = append(records, OriginalRuntimeCapabilityImport{Raw: evidence.raw, Pin: pin, Operation: operation})
			}
			if mode == "missing-proof" {
				records = records[:2]
			}
			writer, e := NewInstallationAuthorityWriter(db, installation, database, public)
			if e != nil {
				t.Fatal(e)
			}
			tx, e := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if e != nil {
				t.Fatal(e)
			}
			e = writer.StageInitialRuntimeAuthorities(ctx, tx, raw, signature, records, now)
			valid := mode == "rollback" || mode == "commit"
			if (e == nil) != valid {
				tx.Rollback()
				t.Fatalf("wrong SQL staging result: %v", e)
			}
			if mode == "commit" {
				if tx.Commit() != nil {
					t.Fatal("commit")
				}
			} else if tx.Rollback() != nil {
				t.Fatal("rollback")
			}
			var authority, history, evidence, fences uint64
			for query, dest := range map[string]*uint64{`SELECT COUNT(*) FROM system_backup_installation_kek_authority`: &authority, `SELECT COUNT(*) FROM system_backup_installation_kek_authority_history`: &history, `SELECT COUNT(*) FROM system_backup_v2_evidence WHERE evidence_type='capability_snapshot'`: &evidence, `SELECT COUNT(*) FROM system_backup_v2_kek_fences`: &fences} {
				if db.QueryRowContext(ctx, query).Scan(dest) != nil {
					t.Fatal("exact readback")
				}
			}
			if mode != "commit" {
				if authority != 0 || history != 0 || evidence != 0 || fences != 0 {
					t.Fatal("rejection/rollback left partial authority")
				}
				return
			}
			if authority != 1 || history != 1 || evidence != 3 || fences != 1 {
				t.Fatal("missing exact committed batch")
			}
			caps, e := NewSQLProviderCapabilityPreparation(db, identity, original.Binding.InstallationID, records[0].Pin, records[1].Pin)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = caps.PrepareCapabilities(ctx, original.Binding); e != nil {
				t.Fatal("unchanged original SQL capability reader", e)
			}
			replay, e := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if e != nil {
				t.Fatal(e)
			}
			if writer.StageInitialRuntimeAuthorities(ctx, replay, raw, signature, records, time.Now().UTC()) == nil {
				replay.Rollback()
				t.Fatal("initial batch replaced existing authority")
			}
			if replay.Rollback() != nil {
				t.Fatal("replay rollback")
			}
		})
	}
}
