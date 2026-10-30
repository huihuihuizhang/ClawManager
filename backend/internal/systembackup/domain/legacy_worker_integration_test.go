package domain_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"testing"

	legacy "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
)

// The archive reaches the real public worker's legacy decoder, then stops at
// the independent target-isolation grant. No source/target query is required.
func TestPublicWorkerAuthenticatesLegacySQLBeforeTargetAccess(t *testing.T) {
	tables, err := legacy.BuiltinSchema()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"explicit-legacy", "wrong-format", "incomplete-scope"} {
		t.Run(mode, func(t *testing.T) {
			f := newWorkerFixture(t)
			var plain bytes.Buffer
			enc := json.NewEncoder(&plain)
			write := func(record legacy.SQLRecord) {
				if err := enc.Encode(record); err != nil {
					t.Fatal(err)
				}
			}
			write(legacy.SQLRecord{Kind: "mysql_rows_v1"})
			empty := sha256.Sum256(nil)
			for i, table := range tables {
				if mode == "incomplete-scope" && i == 0 {
					continue
				}
				write(legacy.SQLRecord{Kind: "table", Table: &table})
				write(legacy.SQLRecord{Kind: "end_table", SHA256: hex.EncodeToString(empty[:])})
			}
			write(legacy.SQLRecord{Kind: "end"})
			f.restore.Database.InputFormat = legacy.LegacyTeamSQLFormat
			if mode == "wrong-format" {
				f.restore.Database.InputFormat = ""
			}
			receipt, err := staging.SealFile(context.Background(), f.store, "legacy.enc", f.key, f.restore.Binding, func(dst io.Writer) error {
				return staging.Compress(dst, func(w io.Writer) error { _, e := io.Copy(w, &plain); return e })
			})
			if err != nil {
				t.Fatal(err)
			}
			f.restore.Receipt = receipt
			isolationReached := false
			_, err = f.restoreData(func(_ context.Context, point string, _ worker.Request) error {
				if point == "database-isolation" {
					isolationReached = true
					return errors.New("independent target grant unavailable")
				}
				return nil
			})
			if err == nil || isolationReached != (mode == "explicit-legacy") || f.sql.Writes() != 0 || f.sql.SourceWrites() != 0 || f.sql.Commits() != 0 {
				t.Fatal("legacy decode/isolation boundary violated", isolationReached, err)
			}
		})
	}
}
