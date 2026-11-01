package domain_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
)

// Named SQL driver observations only; this does not establish physical target
// isolation. The public worker still authenticates its actual encrypted input.
func TestGatewayImagePublicWorkerEmptyHoldRejectsBeforeDMLAndLegitimateEmptyPasses(t *testing.T) {
	for _, mode := range []string{"empty-orphan-hold", "empty-no-hold"} {
		t.Run(mode, func(t *testing.T) {
			f := newWorkerFixture(t)
			f.sql.Close()
			f.sql = domain.NewTestGatewayImageSQLFixture(mode)
			t.Cleanup(f.sql.Close)
			f.restore.Database.Dependencies = f.sql.Policy.Dependencies
			observed, observeErr := domain.CaptureSource(context.Background(), f.sql.Source, domain.Limits{MaxRows: 100, MaxBytes: 1 << 20}, "source", "fixture-server")
			if observeErr != nil {
				t.Fatal("fixture source catalog observation", observeErr)
			}
			for _, table := range observed.Tables {
				if adapter, ok := f.restore.Database.Dependencies[table.Name]; ok {
					adapter.SchemaSHA256 = domain.SchemaDigest(table)
					f.restore.Database.Dependencies[table.Name] = adapter
				}
			}
			observer := f.sql.Verifier()
			defer observer.Close()
			checks := 0
			check := func(ctx context.Context, purpose string, r worker.Request) error {
				checks++
				db := observer
				if r.Operation == "capture-database" {
					db = f.sql.Source
				}
				var name, uuid string
				if purpose == "" || db.QueryRowContext(ctx, "SELECT DATABASE(), @@server_uuid").Scan(&name, &uuid) != nil || name != r.Database.Name || uuid != r.Database.ServerUUID {
					return errors.New("named fixture SQL identity rejected")
				}
				return ctx.Err()
			}
			captured, e := worker.RunDatabase(context.Background(), f.capture, worker.DatabaseEnvironment{Database: f.sql.Source, Staging: f.store, Key: f.key, Check: check})
			if e != nil || f.sql.SourceWrites() != 0 {
				t.Fatal("actual public capture", e)
			}
			f.restore.Receipt = captured.Receipt
			f.sql.Source.Close()
			before, _ := domain.Digest(f.sql.Snapshot())
			result, e := worker.RunDatabase(context.Background(), f.restore, worker.DatabaseEnvironment{Database: f.sql.Target, Staging: f.store, Evidence: f.evidence, Key: f.key, Check: check})
			if mode == "empty-orphan-hold" {
				after, _ := domain.Digest(f.sql.Snapshot())
				if e == nil || f.sql.Writes() != 0 || f.sql.Commits() != 0 || before != after || checks < 3 {
					t.Fatal("orphan hold did not reject before common worker SQL DML/COMMIT", e)
				}
				t.Log("exact root counterexample: empty image rows + image_pending -> actual public capture/restore refusal; target snapshot unchanged, DML=0 COMMIT=0 PASS")
				return
			}
			if e != nil || !result.Quarantined || f.sql.Commits() != 1 {
				t.Fatal("legitimate empty image/no image_pending rejected", e)
			}
			verify := f.restore
			verify.Operation = "verify-database"
			verify.Binding = verify.Database.EvidenceBinding
			verify.Receipt = result.Evidence
			d := *verify.Database
			d.Placements = nil
			d.Configs = nil
			d.EvidenceName = ""
			d.Dependencies = nil
			verify.Database = &d
			verifier := f.sql.Verifier()
			defer verifier.Close()
			writes := f.sql.Writes()
			if v, e := worker.RunDatabase(context.Background(), verify, worker.DatabaseEnvironment{Database: verifier, Staging: f.evidence, Key: f.key, Check: check}); e != nil || !v.Verified || f.sql.Writes() != writes {
				t.Fatal("legitimate empty independent public verify", e)
			}
			t.Log("legitimate empty images without image_pending: actual public capture/restore/independent SELECT-only verify PASS")
		})
	}
}

func TestGatewayImagePublicWorkerNonemptyAndEmptyObjectReceipts(t *testing.T) {
	for _, mode := range []string{"nonempty", "job-only-emptyobjects"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			f := newWorkerFixture(t)
			f.sql.Close()
			f.sql = domain.NewTestGatewayImageSQLFixture(mode)
			t.Cleanup(f.sql.Close)
			f.restore.Database.Dependencies = f.sql.Policy.Dependencies
			observed, e := domain.CaptureSource(ctx, f.sql.Source, domain.Limits{MaxRows: 100, MaxBytes: 1 << 20}, "source", "fixture-server")
			if e != nil {
				t.Fatal(e)
			}
			for _, table := range observed.Tables {
				if a, ok := f.restore.Database.Dependencies[table.Name]; ok {
					a.SchemaSHA256 = domain.SchemaDigest(table)
					f.restore.Database.Dependencies[table.Name] = a
				}
			}
			observer := f.sql.Verifier()
			defer observer.Close()
			check := func(ctx context.Context, purpose string, r worker.Request) error {
				db := observer
				if r.Operation == "capture-database" {
					db = f.sql.Source
				}
				var name, uuid string
				if purpose == "" || db.QueryRowContext(ctx, "SELECT DATABASE(), @@server_uuid").Scan(&name, &uuid) != nil || name != r.Database.Name || uuid != r.Database.ServerUUID {
					return errors.New("named image SQL fixture identity rejected")
				}
				return ctx.Err()
			}
			captured, e := worker.RunDatabase(ctx, f.capture, worker.DatabaseEnvironment{Database: f.sql.Source, Staging: f.store, Key: f.key, Check: check})
			if e != nil {
				t.Fatal("public image SQL capture", e)
			}
			f.restore.Receipt = captured.Receipt
			original, _, raw := domain.GatewayImageNativeSeedForTest()
			id := ""
			for _, table := range original.Tables {
				if table.Name == "gateway_image_artifacts" {
					id = table.Rows[0]["id"].String()
				}
			}
			if mode == "job-only-emptyobjects" {
				id = ""
			}
			bucket := "cm-restore-" + strings.Repeat("6", 32)
			objects := domain.GatewayImageProtocolForTest(t, bucket, id, raw)
			refs := []domain.GatewayImageObjectRef{}
			if id != "" {
				refs = append(refs, objects.Ref)
			}
			imageBinding := f.capture.Binding
			imageBinding.Path = "images/source"
			objectCapture, e := domain.CaptureGatewayImageObjects(ctx, objects.Source, observed, refs, f.store, "images.enc", f.key, imageBinding)
			if e != nil {
				t.Fatal("actual SDK image capture", e)
			}
			images, e := domain.RestoreGatewayImageObjects(ctx, observed, f.store, objectCapture, f.key, imageBinding, objects.Writer, objects.Reader, f.restore.Database.Name, f.restore.Database.ServerUUID, bucket, "2026-11-01T00:00:00Z")
			if e != nil {
				t.Fatal("actual SDK image restore", e)
			}
			f.sql.Source.Close()
			// Missing concrete material is refused before SQL DML, despite valid
			// encrypted SQL. A serialized DTO cannot substitute for this receipt.
			if _, e := worker.RunDatabase(ctx, f.restore, worker.DatabaseEnvironment{Database: f.sql.Target, Staging: f.store, Evidence: f.evidence, Key: f.key, Check: check}); e == nil || f.sql.Writes() != 0 || f.sql.Commits() != 0 {
				t.Fatal("missing image receipt wrote SQL")
			}
			var imageEvidence staging.Receipt
			restored, e := worker.RunDatabase(ctx, f.restore, worker.DatabaseEnvironment{Database: f.sql.Target, Staging: f.store, Evidence: f.evidence, Key: f.key, Check: check, GatewayImages: images, GatewayImageEvidenceRecorded: func(ctx context.Context, r staging.Receipt) error { imageEvidence = r; return ctx.Err() }})
			if e != nil || !restored.Quarantined || imageEvidence.Name == "" || f.sql.Commits() != 1 {
				t.Fatal("public image SQL restore/evidence", e)
			}
			f.sql.Target.Close()
			verify := f.restore
			verify.Operation = "verify-database"
			verify.Binding = verify.Database.EvidenceBinding
			verify.Receipt = restored.Evidence
			d := *verify.Database
			d.Placements = nil
			d.Configs = nil
			d.Dependencies = nil
			d.EvidenceName = ""
			verify.Database = &d
			verifier := f.sql.Verifier()
			defer verifier.Close()
			writes := f.sql.Writes()
			if _, e := worker.RunDatabase(ctx, verify, worker.DatabaseEnvironment{Database: verifier, Staging: f.evidence, Key: f.key, Check: check, GatewayImages: images}); e == nil {
				t.Fatal("old process receipt reused instead of encrypted fresh Open")
			}
			env := worker.DatabaseEnvironment{Database: verifier, Staging: f.evidence, Key: f.key, Check: check, GatewayImageReader: objects.FreshReader(), GatewayImageEvidence: imageEvidence}
			if result, e := worker.RunDatabase(ctx, verify, env); e != nil || !result.Verified || f.sql.Writes() != writes {
				t.Fatal("public fresh reader/actual expected SQL and image evidence", e)
			}
			for _, fault := range []string{"wrong-SQL-receipt", "wrong-SQL-binding", "wrong-image-receipt", "corrupt-actual-SQL-entity", "changed-non-image-SQL-cell", "changed-non-image-cell-with-matching-reference"} {
				badRequest, badEnv := verify, env
				switch fault {
				case "wrong-SQL-receipt":
					badRequest.Receipt.SHA256 = strings.Repeat("b", 64)
				case "wrong-SQL-binding":
					badRequest.Binding.Attempt = "2"
				case "wrong-image-receipt":
					badEnv.GatewayImageEvidence.SHA256 = strings.Repeat("c", 64)
				case "corrupt-actual-SQL-entity":
					raw, e := f.evidence.ReadFile(verify.Receipt.Name)
					if e != nil {
						t.Fatal(e)
					}
					raw[len(raw)-1] ^= 1
					if f.evidence.WriteFile("corrupt-sql.enc", raw, 0600) != nil {
						t.Fatal("owned corrupt cipher fixture")
					}
					sum := sha256.Sum256(raw)
					badRequest.Receipt = staging.Receipt{Name: "corrupt-sql.enc", Size: int64(len(raw)), SHA256: hex.EncodeToString(sum[:])}
					clear(raw)
				case "changed-non-image-SQL-cell", "changed-non-image-cell-with-matching-reference":
					snapshot := f.sql.Snapshot()
					for _, table := range snapshot.Tables {
						if table.Name == "users" {
							table.Rows[0]["username"] = domain.Text("forged-other-domain-cell")
						}
					}
					badRequest.Receipt, e = staging.SealFile(ctx, f.evidence, strings.ToLower(fault)+".enc", f.key, verify.Binding, func(w io.Writer) error {
						return staging.Compress(w, func(plain io.Writer) error { return domain.Encode(plain, snapshot) })
					})
					if e != nil {
						t.Fatal(e)
					}
					if fault == "changed-non-image-cell-with-matching-reference" {
						imageBinding := verify.Binding
						imageBinding.Path += "/gateway-images"
						badEnv.GatewayImageEvidence, e = domain.ForgeGatewayImageSQLReferenceForTest(ctx, f.evidence, imageEvidence, f.key, imageBinding, badRequest.Receipt, "changed-sql-reference.images")
						if e != nil {
							t.Fatal(e)
						}
					}
				}
				if _, e := worker.RunDatabase(ctx, badRequest, badEnv); e == nil || f.sql.Writes() != writes {
					t.Fatal("public verify accepted mismatched SQL/image evidence", fault, e)
				}
			}
			t.Log("actual public worker: nonserialized real object receipt, encrypted SQL+image evidence, fresh SDK reader Open, SELECT-only SQL readback, old-pointer/missing-receipt/wrong-descriptor/binding/non-image-cell refusal PASS; mode=", mode)
		})
	}
}
