package domain_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"clawreef/internal/services"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
)

func nativeImageMigrations(f *gatewayNative, dbName string) {
	c := f.cfg.Clone()
	c.DBName = dbName
	c.MultiStatements = true
	db := f.open(c)
	for _, name := range []string{"072_add_gateway_image_artifacts.sql", "073_add_gateway_image_jobs.sql", "074_add_image_analytics_outbox.sql"} {
		raw, e := os.ReadFile(filepath.Join("..", "..", "db", "migrations", name))
		if e != nil {
			f.t.Fatal("trusted image migration unavailable")
		}
		f.exec(db, string(raw))
	}
	db.Close()
}
func seedNativeImageRows(f *gatewayNative, dbName string) {
	c := f.cfg.Clone()
	c.DBName = dbName
	db := f.open(c)
	defer db.Close()
	for _, table := range f.seed.Tables {
		var columns, marks []string
		for _, column := range table.Columns {
			columns = append(columns, "`"+column.Name+"`")
			marks = append(marks, "?")
		}
		for _, row := range table.Rows {
			var args []any
			for _, column := range table.Columns {
				cell := row[column.Name]
				if cell.Null {
					args = append(args, nil)
				} else if cell.Bytes == nil {
					args = append(args, []byte{})
				} else {
					args = append(args, cell.Bytes)
				}
			}
			f.exec(db, "INSERT INTO `"+table.Name+"`("+joinImageNative(columns)+") VALUES("+joinImageNative(marks)+")", args...)
		}
	}
}
func joinImageNative(parts []string) string {
	out := ""
	for n, s := range parts {
		if n > 0 {
			out += ","
		}
		out += s
	}
	return out
}

func TestGatewayImagePublicWorkerActualTLSMySQL(t *testing.T) {
	f := newGatewayNative(t)
	sourceSeed, policy, raw := domain.GatewayImageNativeSeedForTest()
	f.seed, f.policy = sourceSeed, policy
	for _, table := range f.seed.Tables {
		if table.Name == "gateway_image_artifacts" {
			table.Rows[0]["expires_at"] = domain.Text("2027-01-01 00:00:00")
		}
	}
	f.source = "gw_image_source_" + f.nonce[:16]
	sourceAdmin := f.schema(f.source)
	nativeImageMigrations(f, f.source)
	seedNativeImageRows(f, f.source)
	seedArtifact := nativeGatewayTable(f.seed, "gateway_image_artifacts").Rows[0]
	historyHash := sha256.Sum256([]byte(f.nonce + "success"))
	historyObjects := domain.GatewayImageProtocolForTest(t, "cm-restore-"+hex.EncodeToString(historyHash[:16]), seedArtifact["id"].String(), raw)
	nativeImageHistorySequences(t, f, historyObjects)
	sourceUser := "gwis_" + f.nonce[:12]
	source := f.principal(sourceUser, f.source, "SELECT")
	observed, e := domain.CaptureSource(f.ctx, source, domain.Limits{MaxRows: 1000, MaxBytes: 8 << 20}, f.source, f.uuid)
	if e != nil {
		t.Fatal("actual image source snapshot")
	}
	latest := time.Time{}
	for _, name := range []string{"gateway_keys", "gateway_image_jobs"} {
		for _, row := range nativeGatewayTable(observed, name).Rows {
			at, err := time.Parse("2006-01-02 15:04:05.999999", row["updated_at"].String())
			if err != nil {
				t.Fatal("actual updated-at clock")
			}
			if at.After(latest) {
				latest = at
			}
		}
	}
	var frozen time.Time
	for {
		var dbTime string
		if f.admin.QueryRowContext(f.ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&dbTime) != nil {
			t.Fatal("actual DB time")
		}
		frozen, e = time.Parse("2006-01-02 15:04:05.999999", dbTime)
		if e != nil {
			t.Fatal("actual DB time format")
		}
		if !frozen.Before(latest) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	for name, a := range f.policy.Dependencies {
		a.SchemaSHA256 = domain.SchemaDigest(nativeGatewayTable(observed, name))
		a.InterruptedAt = frozen.UTC().Format(time.RFC3339Nano)
		f.policy.Dependencies[name] = a
	}
	store, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	key := bytes.Repeat([]byte{87}, 32)
	binding := staging.Binding{BackupID: "native-image-" + f.nonce, Attempt: "1", Path: "mysql/domain", CaptureContextHash: hex.EncodeToString(bytes.Repeat([]byte{97}, 32)), EnvelopeID: "owned-image-native-key"}
	spec := worker.DatabaseSpec{Address: f.cfg.Addr, Name: f.source, ServerUUID: f.uuid, TLSServerName: "gateway-restore-native.local", RootCA: f.ca, MaxRows: 1000, MaxMemoryBytes: 8 << 20}
	capture := worker.Request{Version: worker.Version, Operation: "capture-database", Database: &spec, Deadline: time.Now().Add(2 * time.Minute), ArtifactName: "native-image-sql.enc", MaxArchiveBytes: 8 << 20, MaxCompressedBytes: 8 << 20, Binding: binding}
	captured, e := worker.RunDatabase(f.ctx, capture, worker.DatabaseEnvironment{Database: source, Staging: store, Key: key, Check: func(ctx context.Context, purpose string, r worker.Request) error {
		if r.Operation != "capture-database" || r.Binding != binding || r.Database.Name != f.source || purpose == "" {
			return errors.New("owned image capture binding rejected")
		}
		return f.observe(ctx, f.source, sourceUser)
	}})
	if e != nil {
		t.Fatal("actual public image SQL capture")
	}
	f.revoke(source, sourceUser)
	sourceAdmin.Close()
	artifact := nativeGatewayTable(observed, "gateway_image_artifacts").Rows[0]
	id := artifact["id"].String()
	for index, mode := range []string{"missing-receipt", "wrong-AAD", "wrong-length", "evidence-record-failure", "cancel-before-commit", "success"} {
		name := "cm_drill_image_" + strconv.Itoa(index) + "_" + f.nonce[:16]
		admin := f.schema(name)
		nativeImageMigrations(f, name)
		f.exec(admin, "INSERT INTO users(id,username,password_hash,role,is_active) VALUES(999,'admin','bootstrap','admin','1')")
		writerUser, readerUser := "gwiw"+strconv.Itoa(index)+"_"+f.nonce[:12], "gwir"+strconv.Itoa(index)+"_"+f.nonce[:12]
		writer := f.principal(writerUser, name, "SELECT,INSERT,DELETE")
		reader := f.principal(readerUser, name, "SELECT")
		sum := sha256.Sum256([]byte(f.nonce + mode))
		bucket := "cm-restore-" + hex.EncodeToString(sum[:16])
		body := raw
		if mode == "wrong-AAD" {
			body = domain.GatewayImageCipherForTest(observed, []byte("PNG!"), "img_wrong_associated_identity")
		}
		if mode == "wrong-length" {
			body = domain.GatewayImageCipherForTest(observed, []byte("FIVE!"), id)
		}
		objects := domain.GatewayImageProtocolForTest(t, bucket, id, body)
		if mode == "success" {
			objects = historyObjects
		}
		if mode == "success" {
			// A real owner Load succeeds from SQL+fixed-version object bytes.
			ss := f.upper(f.source, "root", "")
			svc, err := services.NewGatewayImageArtifactService(ss, objects.SourceStorage)
			ownerKey := int(9223372036854775806)
			if err != nil {
				t.Fatal("actual source artifact service")
			}
			loaded, err := svc.Load(f.ctx, services.ImageArtifactOwner{UserID: 4, GatewayKeyID: &ownerKey}, id)
			if err != nil || loaded == nil || !bytes.Equal(loaded.Data, []byte("PNG!")) {
				t.Fatal("actual source owner Load positive control")
			}
			ss.Close()
		}
		imageBinding := binding
		imageBinding.Path = "images/source/" + strconv.Itoa(index)
		imageCapture, captureErr := domain.CaptureGatewayImageObjects(f.ctx, objects.Source, observed, []domain.GatewayImageObjectRef{objects.Ref}, store, "native-images-"+strconv.Itoa(index)+".enc", key, imageBinding)
		var images *domain.GatewayImageReceipt
		if mode == "wrong-AAD" || mode == "wrong-length" {
			if captureErr == nil || objects.Puts() != 0 {
				t.Fatal("bad actual image bytes admitted target PUT", mode)
			}
		} else {
			if captureErr != nil {
				t.Fatal("actual image capture", captureErr)
			}
			if mode != "missing-receipt" {
				images, e = domain.RestoreGatewayImageObjects(f.ctx, observed, store, imageCapture, key, imageBinding, objects.Writer, objects.Reader, name, f.uuid, bucket, frozen.UTC().Format(time.RFC3339Nano))
				if e != nil {
					t.Fatal("actual object restore", e)
				}
			}
		}
		if images != nil {
			catalog, err := domain.Catalog(f.ctx, writer)
			if err != nil {
				t.Fatal("actual target image catalog", err)
			}
			p := f.policy
			p.GatewayImages = images
			if _, err := domain.Normalize(f.ctx, observed, catalog, p); err != nil {
				for _, table := range catalog {
					if a, ok := p.Dependencies[table.Name]; ok {
						t.Logf("adapter diagnostic %s source-pin=%t target-pin=%t", table.Name, a.SchemaSHA256 == domain.SchemaDigest(nativeGatewayTable(observed, table.Name)), a.SchemaSHA256 == domain.SchemaDigest(table))
					}
				}
				t.Fatal("actual image Normalize preflight rejected", err)
			}
		}
		evidence, e := os.OpenRoot(t.TempDir())
		if e != nil {
			t.Fatal(e)
		}
		defer evidence.Close()
		restore := capture
		restore.Operation = "restore-database"
		restore.ArtifactName = ""
		restore.Receipt = captured.Receipt
		restore.PolicyVersion = "owned-image-074"
		d := spec
		d.Name = name
		d.Dependencies = f.policy.Dependencies
		d.Placements = f.policy.Placements
		d.EvidenceName = "image-expected.enc"
		d.EvidenceBinding = binding
		d.EvidenceBinding.Path = "mysql/expected/" + strconv.Itoa(index)
		restore.Database = &d
		child, cancel := context.WithCancel(f.ctx)
		commitReached := false
		lastPhase := ""
		var imageEvidence staging.Receipt
		check := func(ctx context.Context, purpose string, r worker.Request) error {
			lastPhase = purpose
			if r.Database.Name != name || r.Database.ServerUUID != f.uuid || r.Binding != binding || purpose == "" {
				return errors.New("owned image restore binding rejected")
			}
			if e := f.observe(ctx, name, writerUser); e != nil {
				return e
			}
			if purpose == "before-database-commit" {
				commitReached = true
				if mode == "cancel-before-commit" {
					cancel()
				}
			}
			return ctx.Err()
		}
		restored, restoreErr := worker.RunDatabase(child, restore, worker.DatabaseEnvironment{Database: writer, Staging: store, Evidence: evidence, Key: key, Check: check, GatewayImages: images, GatewayImageEvidenceRecorded: func(ctx context.Context, r staging.Receipt) error {
			imageEvidence = r
			if mode == "evidence-record-failure" {
				return errors.New("owned image evidence custody unavailable")
			}
			return ctx.Err()
		}})
		cancel()
		f.revoke(writer, writerUser)
		if mode != "success" {
			if restoreErr == nil {
				t.Fatal("failed image operation committed", mode)
			}
			var bootstrap, rows int
			if reader.QueryRowContext(f.ctx, "SELECT (SELECT COUNT(*) FROM users WHERE id=999),(SELECT COUNT(*) FROM gateway_keys)+(SELECT COUNT(*) FROM gateway_key_budget_reservations)+(SELECT COUNT(*) FROM gateway_key_budget_ledger)+(SELECT COUNT(*) FROM gateway_image_artifacts)+(SELECT COUNT(*) FROM gateway_image_jobs)").Scan(&bootstrap, &rows) != nil || bootstrap != 1 || rows != 0 {
				t.Fatal("actual image failure rollback/bootstrap", mode)
			}
			if (mode == "missing-receipt" || mode == "wrong-AAD" || mode == "wrong-length") && objects.Puts() != 0 {
				t.Fatal("missing/bad image material wrote target objects", mode)
			}
			if mode == "evidence-record-failure" && (imageEvidence.Name == "" || commitReached) {
				t.Fatalf("evidence fault did not reach actual sealed material; last phase=%s error=%v", lastPhase, restoreErr)
			}
			if mode == "cancel-before-commit" && !commitReached {
				t.Fatal("cancel fault before actual commit boundary")
			}
			t.Logf("actual native case=%s: bootstrap=1 five owner tables=0; writer sessions=0/login3118; target object PUTs=%d; owned object residues retained through SQL rollback PASS", mode, objects.Puts())
			continue
		}
		if restoreErr != nil || !restored.Quarantined || imageEvidence.Name == "" || !commitReached {
			t.Fatal("actual native image restore/evidence", restoreErr)
		}
		if objects.RevokeWriter() != nil {
			t.Fatal("actual object writer revocation")
		}
		verify := restore
		verify.Operation = "verify-database"
		verify.Binding = d.EvidenceBinding
		verify.Receipt = restored.Evidence
		vd := d
		vd.Dependencies = nil
		vd.Placements = nil
		vd.EvidenceName = ""
		verify.Database = &vd
		verifyCheck := func(ctx context.Context, purpose string, r worker.Request) error {
			if r.Operation != "verify-database" || r.Binding != vd.EvidenceBinding || r.Database.Name != name || purpose == "" {
				return errors.New("owned image verify binding rejected")
			}
			return f.observe(ctx, name, readerUser)
		}
		if _, e := worker.RunDatabase(f.ctx, verify, worker.DatabaseEnvironment{Database: reader, Staging: evidence, Key: key, Check: verifyCheck, GatewayImages: images}); e == nil {
			t.Fatal("old image pointer accepted for verify")
		}
		if result, e := worker.RunDatabase(f.ctx, verify, worker.DatabaseEnvironment{Database: reader, Staging: evidence, Key: key, Check: verifyCheck, GatewayImageReader: objects.FreshReader(), GatewayImageEvidence: imageEvidence}); e != nil || !result.Verified {
			t.Fatal("actual native fresh image verify", e)
		}
		// A separate process receives encrypted files/references and read-only
		// clients only, never the old in-process receipt. Implemented below.
		runNativeImageVerifyChild(t, f, verify, key, evidence.Name(), readerUser, imageEvidence, objects.ReaderSettings)
		before, e := domain.CaptureSource(f.ctx, reader, domain.Limits{MaxRows: 1000, MaxBytes: 8 << 20}, name, f.uuid)
		if e != nil {
			t.Fatal("native before owner checks")
		}
		validateNativeImageRawCells(t, observed, before)
		operator := f.upper(name, "root", "")
		svc, e := services.NewGatewayImageArtifactService(operator, domain.GatewayImageTargetStorageForTest(images))
		if e != nil {
			t.Fatal("actual target owner service")
		}
		ownerKey := int(9223372036854775806)
		if loaded, e := svc.Load(f.ctx, services.ImageArtifactOwner{UserID: 4, GatewayKeyID: &ownerKey}, id); !errors.Is(e, services.ErrImageArtifactUnavailable) || loaded != nil {
			t.Fatal("restored artifact still served")
		}
		if e := services.NewGatewayImageJobService(operator, nil).Recover(f.ctx); e != nil {
			t.Fatal("actual recovery did not remain inert")
		}
		operator.Close()
		after, e := domain.CaptureSource(f.ctx, reader, domain.Limits{MaxRows: 1000, MaxBytes: 8 << 20}, name, f.uuid)
		if e != nil {
			t.Fatal("native after owner checks")
		}
		a, _ := domain.Digest(before)
		b, _ := domain.Digest(after)
		if a != b {
			t.Fatal("actual owner Load/Recover changed rows/hold/money")
		}
		for _, statement := range []string{"UPDATE gateway_image_jobs SET settled=settled WHERE 1=0", "DELETE FROM gateway_image_artifacts WHERE 1=0"} {
			_, e := reader.ExecContext(f.ctx, statement)
			if nativeImageMySQLNumber(e) != 1142 {
				t.Fatal("actual image reader DML was not1142")
			}
		}
		t.Log("actual native success: current072/073/074 SQL; retained raw hold/amount/key; ready=0, running->unknown and replay flags disabled without settlement; source owner Load positive/target refusal; real Recover no row changes; actual1142; fresh process public verification PASS")
	}
	t.Log("scope: actual isolated TLS MySQL + TLS/SigV4 versioned protocol fixture (not native S3/MinIO); no fullC/source authorization or all-consumer physical target isolation qualification")
}
