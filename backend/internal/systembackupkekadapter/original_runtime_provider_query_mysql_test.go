//go:build systembackup_mysql

package systembackupkekadapter

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	kms "clawreef/internal/systembackupkms"
	mysql "github.com/go-sql-driver/mysql"
)

// Real separate-transaction visibility and native1205 waiting. Signing inputs
// are declared protocol fixtures, not original installer/Vault/B/C authority.
func TestRuntimeProviderQueryMySQLWaitsForOriginalCommitOrRollback(t *testing.T) {
	if os.Getenv("A_SIGNING_MYSQL_CREDENTIALS_FILE") == "" || os.Getenv("A_SIGNING_MYSQL_SERVER_UUID") == "" {
		t.Fatal("pinned disposable MySQL required")
	}
	for _, commit := range []bool{false, true} {
		t.Run(fmt.Sprintf("commit_%t", commit), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			db, identity := censusOriginalMySQL(t, ctx)
			record, public, key := ownerRecordFixture(t)
			defer clear(key)
			raw, signature := signOwner(record, key)
			imports := []OriginalRuntimeCapabilityImport{}
			for n, operation := range []kms.Operation{kms.Generate, kms.Unwrap, kms.Unwrap} {
				cap, pin, private := providerCapabilityFixture(t, record.Binding, operation)
				cap.Source.RecordID = fmt.Sprintf("sev_55555555-0000-4000-8000-%012x", n+1)
				pin.Source = cap.Source
				evidence := signCapabilityFixture(t, cap, private)
				clear(private)
				imports = append(imports, OriginalRuntimeCapabilityImport{Raw: evidence.raw, Pin: pin, Operation: operation})
			}
			writer, e := NewInstallationAuthorityWriter(db, record.Binding.InstallationID, identity, public)
			if e != nil {
				t.Fatal(e)
			}
			original, e := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if e != nil {
				t.Fatal(e)
			}
			defer original.Rollback()
			saved, e := writer.StageInitialRuntimeAuthoritiesWithSnapshot(ctx, original, raw, signature, imports, time.Now().UTC())
			if e != nil {
				t.Fatal(e)
			}
			query, e := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if e != nil {
				t.Fatal(e)
			}
			defer query.Rollback()
			var originalConnection, queryConnection uint64
			if original.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&originalConnection) != nil || query.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&queryConnection) != nil || originalConnection == queryConnection {
				t.Fatal("query reused original transaction/connection")
			}
			if _, e = query.ExecContext(ctx, "SET SESSION innodb_lock_wait_timeout=1"); e != nil {
				t.Fatal(e)
			}
			var epoch uint64
			e = query.QueryRowContext(ctx, `SELECT epoch FROM system_backup_v2_kek_fences WHERE installation_id=? FOR SHARE`, record.Binding.InstallationID).Scan(&epoch)
			var native *mysql.MySQLError
			if !errors.As(e, &native) || native.Number != 1205 {
				t.Fatal("query failed to wait on actual in-flight writer", e)
			}
			if query.Rollback() != nil {
				t.Fatal("query rollback")
			}
			if commit {
				e = original.Commit()
			} else {
				e = original.Rollback()
			}
			if e != nil {
				t.Fatal(e)
			}
			resolved, e := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if e != nil {
				t.Fatal(e)
			}
			defer resolved.Rollback()
			actual, e := QueryRuntimeInstalledSQLSnapshotTx(ctx, resolved, identity, record.Binding.InstallationID, raw, signature, imports)
			confirmed := e == nil && SameRuntimeInstalledSQLRows(saved, actual)
			if confirmed != commit {
				t.Fatalf("wrong original commit readback: %v", e)
			}
			if resolved.Rollback() != nil {
				t.Fatal("readback rollback")
			}
		})
	}
}
