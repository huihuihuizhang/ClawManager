package domain_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
)

func jointEightOpenSQL(t *testing.T, ctx context.Context, root *os.Root, receipt staging.Receipt, key []byte, binding staging.Binding) domain.Snapshot {
	t.Helper()
	file, e := staging.OpenFile(ctx, root, receipt)
	if e != nil {
		t.Fatal("joint actual SQL file identity", e)
	}
	defer file.Close()
	var out domain.Snapshot
	e = staging.ConsumeCompressed(ctx, file, key, binding, 8<<20, 8<<20, func(r io.Reader) error {
		var err error
		out, err = domain.Decode(r, domain.Limits{MaxRows: 1000, MaxBytes: 8 << 20})
		return err
	})
	if e != nil {
		jointEightClear(out)
		t.Fatal("joint actual SQL AEAD/gzip/EOF", e)
	}
	jointEightRequireNonempty(t, out)
	return out
}
func jointEightSealSQL(t *testing.T, ctx context.Context, root *os.Root, name string, key []byte, binding staging.Binding, s domain.Snapshot) staging.Receipt {
	t.Helper()
	receipt, e := staging.SealFile(ctx, root, name, key, binding, func(w io.Writer) error {
		return staging.Compress(w, func(plain io.Writer) error { return domain.Encode(plain, s) })
	})
	if e != nil {
		t.Fatal("joint controlled SQL artifact", e)
	}
	return receipt
}

func jointEightReadCustody(t *testing.T, ctx context.Context, root *os.Root, receipt staging.Receipt) staging.Receipt {
	t.Helper()
	file, e := staging.OpenFile(ctx, root, receipt)
	if e != nil {
		t.Fatal("joint actual durable custody file", e)
	}
	defer file.Close()
	var out staging.Receipt
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&out) != nil {
		t.Fatal("joint custody descriptor decode")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		t.Fatal("joint custody descriptor trailing bytes")
	}
	return out
}
func jointEightFreezeAdapters(t *testing.T, f *gatewayNative, s domain.Snapshot) string {
	t.Helper()
	latest := time.Time{}
	for _, name := range []string{"gateway_keys", "gateway_image_jobs"} {
		for _, row := range nativeGatewayTable(s, name).Rows {
			at, e := time.Parse("2006-01-02 15:04:05.999999", row["updated_at"].String())
			if e != nil {
				t.Fatal("joint actual source clock", e)
			}
			if at.After(latest) {
				latest = at
			}
		}
	}
	var frozen time.Time
	for {
		var raw string
		if f.admin.QueryRowContext(f.ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&raw) != nil {
			t.Fatal("joint actual freeze clock")
		}
		var e error
		frozen, e = time.Parse("2006-01-02 15:04:05.999999", raw)
		if e != nil {
			t.Fatal(e)
		}
		if !frozen.Before(latest) {
			break
		}
		select {
		case <-f.ctx.Done():
			t.Fatal(f.ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	at := frozen.UTC().Format(time.RFC3339Nano)
	for name, a := range f.policy.Dependencies {
		a.SchemaSHA256 = domain.SchemaDigest(nativeGatewayTable(s, name))
		a.InterruptedAt = at
		f.policy.Dependencies[name] = a
	}
	for name, a := range northboundNativeAdapters(s) {
		f.policy.Dependencies[name] = a
	}
	if len(f.policy.Dependencies) != 8 {
		t.Fatal("joint exact8 named adapters required")
	}
	return at
}

// Read through a separate SQL connection, not CaptureSource on cm_drill or a
// Store projection. Actual table metadata and every PK/cell are included.
func jointEightReadTarget(t *testing.T, ctx context.Context, db *sql.DB) domain.Snapshot {
	t.Helper()
	catalog, e := domain.Catalog(ctx, db)
	if e != nil {
		t.Fatal("joint independent target catalog", e)
	}
	out := domain.Snapshot{Version: domain.Version}
	for _, table := range catalog {
		var cols, pk []string
		for _, c := range table.Columns {
			cols = append(cols, "`"+c.Name+"`")
		}
		for _, c := range table.PrimaryKey {
			pk = append(pk, "`"+c+"`")
		}
		if len(cols) == 0 || len(pk) == 0 {
			t.Fatal("joint closed target projection")
		}
		rows, e := db.QueryContext(ctx, "SELECT "+strings.Join(cols, ",")+" FROM `"+table.Name+"` ORDER BY "+strings.Join(pk, ","))
		if e != nil {
			t.Fatal("joint independent raw SELECT", e)
		}
		for rows.Next() {
			values := make([]any, len(cols))
			dest := make([]any, len(cols))
			for i := range values {
				dest[i] = &values[i]
			}
			if rows.Scan(dest...) != nil {
				rows.Close()
				t.Fatal("joint raw scan")
			}
			row := domain.Row{}
			for i, value := range values {
				cell := domain.Cell{}
				switch v := value.(type) {
				case nil:
					cell.Null = true
				case []byte:
					cell.Bytes = append([]byte(nil), v...)
				case string:
					cell = domain.Text(v)
				case int64:
					cell = domain.Text(strconv.FormatInt(v, 10))
				case uint64:
					cell = domain.Text(strconv.FormatUint(v, 10))
				default:
					rows.Close()
					t.Fatal("joint raw representation lost precision")
				}
				row[table.Columns[i].Name] = cell
			}
			table.Rows = append(table.Rows, row)
		}
		if rows.Err() != nil {
			rows.Close()
			t.Fatal("joint raw iteration")
		}
		if rows.Close() != nil {
			t.Fatal("joint raw close")
		}
		out.Tables = append(out.Tables, table)
	}
	return out
}
func jointEightSame(t *testing.T, a, b domain.Snapshot) {
	t.Helper()
	first, e := domain.Digest(a)
	if e != nil {
		t.Fatal(e)
	}
	second, e := domain.Digest(b)
	if e != nil || first != second {
		t.Fatal("joint complete SQL state differs")
	}
}

func jointEightImageOnlyDigest(t *testing.T, s domain.Snapshot) string {
	t.Helper()
	projection := domain.Snapshot{Version: domain.Version}
	for _, table := range s.Tables {
		if table.Name == "gateway_image_artifacts" || table.Name == "gateway_image_jobs" {
			projection.Tables = append(projection.Tables, table)
		}
	}
	if len(projection.Tables) != 2 {
		t.Fatal("joint image-only control projection incomplete")
	}
	digest, e := domain.Digest(projection)
	if e != nil {
		t.Fatal(e)
	}
	return digest
}

func jointEightRequireCrossDomainChange(t *testing.T, original, changed domain.Snapshot) {
	t.Helper()
	jointEightRequireNonempty(t, changed)
	a, e := domain.Digest(original)
	if e != nil {
		t.Fatal(e)
	}
	b, e := domain.Digest(changed)
	if e != nil || a == b || jointEightImageOnlyDigest(t, original) != jointEightImageOnlyDigest(t, changed) {
		t.Fatal("joint mismatch did not change the complete SQL digest while preserving the image-only projection")
	}
}

func jointEightReadback(t *testing.T, source, actual domain.Snapshot, frozen string) {
	t.Helper()
	jointEightRequireNonempty(t, source)
	jointEightRequireNonempty(t, actual)
	at, e := time.Parse(time.RFC3339Nano, frozen)
	if e != nil {
		t.Fatal(e)
	}
	marker := domain.Text(at.Format("2006-01-02 15:04:05"))
	for _, name := range jointEightTables {
		before, after := nativeGatewayTable(source, name), nativeGatewayTable(actual, name)
		if domain.SchemaDigest(before) != domain.SchemaDigest(after) || len(before.Rows) != len(after.Rows) {
			t.Fatal("joint owner schema/row loss", name)
		}
		key := func(row domain.Row) string {
			var s []string
			for _, c := range before.PrimaryKey {
				s = append(s, row[c].String())
			}
			return strings.Join(s, "\x00")
		}
		byPK := map[string]domain.Row{}
		for _, r := range after.Rows {
			if byPK[key(r)] != nil {
				t.Fatal("joint duplicate PK")
			}
			byPK[key(r)] = r
		}
		for _, row := range before.Rows {
			got := byPK[key(row)]
			if len(got) != len(row) {
				t.Fatal("joint missing raw row", name)
			}
			changedJob := row["state"].String() == "running" || row["state"].String() == "preparing" || row["settled"].String() != "1" || row["analytics_recorded"].String() != "1"
			for column, want := range row {
				switch name {
				case "gateway_keys":
					if row["status"].String() != "revoked" {
						switch column {
						case "status":
							want = domain.Text("revoked")
						case "revoked_at", "updated_at":
							want = marker
						case "revoked_by_user_id":
							want = domain.Cell{Null: true}
						case "revocation_reason":
							want = domain.Text("isolated restore: source credential disabled")
						}
					}
				case "gateway_image_artifacts":
					if column == "ready" {
						want = domain.Text("0")
					}
				case "gateway_image_jobs":
					switch column {
					case "state":
						if want.String() == "running" {
							want = domain.Text("unknown")
						}
						if want.String() == "preparing" {
							want = domain.Text("failed")
						}
					case "settled", "analytics_recorded":
						want = domain.Text("1")
					case "updated_at":
						if changedJob {
							want = marker
						}
					}
				case "northbound_admin_settings":
					switch column {
					case "api_enabled", "owner_teams_enabled", "external_node_port":
						want = domain.Text("0")
					case "require_explicit_callers":
						want = domain.Text("1")
					case "version":
						want = domain.Text("6")
					}
				case "northbound_settings_audit":
					if (column == "before_json" || column == "after_json") && !want.Null {
						want = domain.Text(`"[REDACTED]"`)
					}
				}
				cell, ok := got[column]
				if !ok || cell.Null != want.Null || !bytes.Equal(cell.Bytes, want.Bytes) {
					t.Fatal("joint independent full raw cell mismatch", name, column)
				}
			}
		}
	}
}

func jointEightActualTransaction(t *testing.T, f *gatewayNative, user, name string) {
	t.Helper()
	var transactions, modified int64
	if f.admin.QueryRowContext(f.ctx, "SELECT COUNT(*),COALESCE(MAX(t.trx_rows_modified),0) FROM information_schema.innodb_trx t JOIN information_schema.PROCESSLIST p ON t.trx_mysql_thread_id=p.ID WHERE p.USER=? AND p.DB=?", user, name).Scan(&transactions, &modified) != nil || transactions != 1 || modified < 8 {
		t.Fatal("joint writes were not observed in one real active SQL transaction")
	}
}

// The server is a fresh exclusive fixture. Measure explicit COMMIT commands
// only around RunDatabase, after the target observation's read-only TX ended
// and before any credential DDL or fresh verification transaction begins.
func jointEightCommitCount(t *testing.T, f *gatewayNative) uint64 {
	t.Helper()
	var name, value string
	if f.admin.QueryRowContext(f.ctx, "SHOW GLOBAL STATUS LIKE 'Com_commit'").Scan(&name, &value) != nil || name != "Com_commit" {
		t.Fatal("joint actual COMMIT counter unavailable")
	}
	n, e := strconv.ParseUint(value, 10, 64)
	if e != nil {
		t.Fatal(e)
	}
	return n
}

func TestJointEightPublicWorkerActualTLSMySQL(t *testing.T) {
	f, sourceAdmin, objects := jointEightSetup(t)
	stage, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer stage.Close()
	key := bytes.Repeat([]byte{104}, 32)
	defer clear(key)
	binding := staging.Binding{BackupID: "joint-eight-" + f.nonce, Attempt: "1", Path: "mysql/source", CaptureContextHash: strings.Repeat("a", 64), EnvelopeID: "owned-joint-eight-dek"}
	spec := worker.DatabaseSpec{Address: f.cfg.Addr, Name: f.source, ServerUUID: f.uuid, TLSServerName: "gateway-restore-native.local", RootCA: f.ca, MaxRows: 1000, MaxMemoryBytes: 8 << 20}
	sourceUser := "j8s_" + f.nonce[:12]
	sourceDB := f.principal(sourceUser, f.source, "SELECT")
	capture := worker.Request{Version: worker.Version, Operation: "capture-database", Database: &spec, Deadline: time.Now().Add(2 * time.Minute), ArtifactName: "joint-eight-source.enc", MaxArchiveBytes: 8 << 20, MaxCompressedBytes: 8 << 20, Binding: binding}
	captured, e := worker.RunDatabase(f.ctx, capture, worker.DatabaseEnvironment{Database: sourceDB, Staging: stage, Key: key, Check: func(ctx context.Context, phase string, r worker.Request) error {
		if phase == "" || r.Operation != "capture-database" || r.Binding != binding || r.Database.Name != f.source {
			return errors.New("joint source invocation differs")
		}
		return f.observe(ctx, f.source, sourceUser)
	}})
	if e != nil {
		t.Fatal("joint public8-table capture", e)
	}
	// This exact SQL entity, including all8 nonempty owners, is authenticated
	// before it is supplied to immutable image-material capture and later PUT.
	original := jointEightOpenSQL(t, f.ctx, stage, captured.Receipt, key, binding)
	defer jointEightClear(original)
	independent, e := domain.CaptureSource(f.ctx, sourceDB, domain.Limits{MaxRows: 1000, MaxBytes: 8 << 20}, f.source, f.uuid)
	if e != nil {
		t.Fatal(e)
	}
	jointEightSame(t, original, independent)
	jointEightClear(independent)
	frozen := jointEightFreezeAdapters(t, f, original)
	imageBinding := binding
	imageBinding.Path = "images/source"
	imageMaterial, e := domain.CaptureGatewayImageObjects(f.ctx, objects.Source, original, []domain.GatewayImageObjectRef{objects.Ref}, stage, "joint-eight-images.enc", key, imageBinding)
	if e != nil {
		t.Fatal("joint actual fixed-version image capture bound to full SQL", e)
	}
	if objects.RevokeSource(f.ctx) != nil {
		t.Fatal("joint source object principals not actually revoked")
	}
	f.revoke(sourceDB, sourceUser)
	sourceAdmin.Close()
	for index, mode := range []string{"success", "evidence-custody-failure", "cancel-before-commit", "changed-Northbound-source"} {
		t.Run(mode, func(t *testing.T) {
			name := "cm_drill_joint_" + strconv.Itoa(index) + "_" + f.nonce[:16]
			admin := f.schema(name)
			defer admin.Close()
			nativeImageMigrations(f, name)
			northboundNativeMigrations(f, admin)
			f.exec(admin, "INSERT INTO users(id,username,password_hash,role,is_active) VALUES(1,'admin','bootstrap','admin','1')")
			f.exec(admin, "UPDATE northbound_admin_settings SET version=5,updated_by=1")
			writerUser, readerUser := "j8w"+strconv.Itoa(index)+"_"+f.nonce[:12], "j8r"+strconv.Itoa(index)+"_"+f.nonce[:12]
			writer := f.principal(writerUser, name, "SELECT,INSERT,UPDATE,DELETE")
			defer writer.Close()
			reader := f.principal(readerUser, name, "SELECT")
			defer reader.Close()
			before := jointEightReadTarget(t, f.ctx, reader)
			defer jointEightClear(before)
			observation, e := northboundNativeObserve(f.ctx, reader, name, f.uuid)
			if e != nil {
				t.Fatal(e)
			}
			sum := sha256.Sum256([]byte(f.nonce + mode))
			bucket := "cm-restore-" + hex.EncodeToString(sum[:16])
			target := objects.NewTarget(bucket)
			images, e := domain.RestoreGatewayImageObjects(f.ctx, original, stage, imageMaterial, key, imageBinding, target.Writer, target.Reader, name, f.uuid, bucket, frozen)
			if e != nil {
				t.Fatal("joint actual target object PUT/readback", e)
			}
			initialInventory, e := domain.JointEightInventoryForTest(f.ctx, target.Reader, bucket, original, objects.Ref)
			if e != nil || len(initialInventory) != 1 {
				t.Fatal("joint actual target immutable inventory", e)
			}
			evidence, e := os.OpenRoot(t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			defer evidence.Close()
			custodyRoot, e := os.OpenRoot(t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			defer custodyRoot.Close()
			if mode == "evidence-custody-failure" {
				if e = custodyRoot.Close(); e != nil {
					t.Fatal(e)
				}
			}
			r := capture
			r.Operation = "restore-database"
			r.ArtifactName = ""
			r.Receipt = captured.Receipt
			r.PolicyVersion = "joint-eight-current"
			d := spec
			d.Name = name
			d.Dependencies = f.policy.Dependencies
			d.Placements = f.policy.Placements
			d.EvidenceName = "joint-eight-expected.enc"
			d.EvidenceBinding = binding
			d.EvidenceBinding.Path = "mysql/expected/" + strconv.Itoa(index)
			r.Database = &d
			if mode == "changed-Northbound-source" {
				changed := jointEightClone(t, original)
				defer jointEightClear(changed)
				// Both source versions normalize to target6. An image-only or
				// normalized-row digest would miss this source-history change.
				if nativeGatewayTable(changed, "northbound_admin_settings").Rows[0]["version"].String() != "9223372036854775807" {
					t.Fatal("joint original source version boundary missing")
				}
				nativeGatewayTable(changed, "northbound_admin_settings").Rows[0]["version"] = domain.Text("41")
				jointEightRequireCrossDomainChange(t, original, changed)
				r.Receipt = jointEightSealSQL(t, f.ctx, stage, "joint-changed-source.enc", key, binding, changed)
			}
			child, cancel := context.WithCancel(f.ctx)
			defer cancel()
			beforeEvidence, commitBoundary := false, false
			var imageEvidence staging.Receipt
			var custodyEvidence staging.Receipt
			check := func(ctx context.Context, phase string, request worker.Request) error {
				if phase == "" || request.Binding != binding || request.Database.Name != name || request.Operation != "restore-database" {
					return errors.New("joint restore invocation differs")
				}
				if e := f.observe(ctx, name, writerUser); e != nil {
					return e
				}
				if phase == "before-evidence" {
					beforeEvidence = true
					jointEightActualTransaction(t, f, writerUser, name)
				}
				if phase == "before-database-commit" {
					commitBoundary = true
					if mode == "cancel-before-commit" {
						cancel()
					}
				}
				return ctx.Err()
			}
			commitsBefore := jointEightCommitCount(t, f)
			result, restoreErr := worker.RunDatabase(child, r, worker.DatabaseEnvironment{Database: writer, Staging: stage, Evidence: evidence, Key: key, Check: check, NorthboundTarget: observation, GatewayImages: images, GatewayImageEvidenceRecorded: func(ctx context.Context, receipt staging.Receipt) error {
				imageEvidence = receipt
				// Public metadata only. This actual durable file output happens
				// after both encrypted evidence seals and before SQL COMMIT. The
				// failure case writes through an actually closed own root.
				var e error
				custodyEvidence, e = staging.WriteUnpublishedFile(ctx, custodyRoot, "joint-image-custody.json", func(w io.Writer) error { return json.NewEncoder(w).Encode(receipt) })
				return e
			}})
			commitsAfter := jointEightCommitCount(t, f)
			cancel()
			f.revoke(writer, writerUser)
			if mode != "success" {
				if restoreErr == nil || commitsAfter != commitsBefore {
					t.Fatal("joint negative restore committed", mode)
				}
				after := jointEightReadTarget(t, f.ctx, reader)
				jointEightSame(t, before, after)
				jointEightClear(after)
				if mode == "changed-Northbound-source" && (beforeEvidence || commitBoundary || imageEvidence.Name != "") {
					t.Fatal("joint changed full source reached SQL/evidence boundary")
				}
				if mode == "evidence-custody-failure" && (!beforeEvidence || commitBoundary || imageEvidence.Name == "" || custodyEvidence.Name != "") {
					t.Fatal("joint custody fault did not occur after real8-table writes and actual sealed image evidence")
				}
				if mode == "cancel-before-commit" && (!beforeEvidence || !commitBoundary || imageEvidence.Name == "" || custodyEvidence.Name == "") {
					t.Fatal("joint cancellation missed real commit boundary")
				}
				if mode == "cancel-before-commit" && jointEightReadCustody(t, f.ctx, custodyRoot, custodyEvidence) != imageEvidence {
					t.Fatal("joint canceled SQL lost its actual unaccepted custody descriptor")
				}
				remaining, e := domain.JointEightInventoryForTest(f.ctx, target.Reader, bucket, original, objects.Ref)
				if e != nil || len(remaining) != 1 || remaining[0] != initialInventory[0] {
					t.Fatal("joint SQL rollback lost or changed owned immutable object residue", e)
				}
				if target.RevokeWriter(f.ctx) != nil {
					t.Fatal("joint failed-case object writer still authorized")
				}
				t.Log("complete SQL state/bootstrap/settings and all8 owner tables rolled back; actual object version/GET/GCM inventory retained for custody until fixture teardown; no runner object deletion/activation")
				return
			}
			if restoreErr != nil || !result.Quarantined || !beforeEvidence || !commitBoundary || imageEvidence.Name == "" || custodyEvidence.Name == "" || commitsAfter != commitsBefore+1 {
				t.Fatal("joint public8-table restore/expected evidence/exactly1 COMMIT", restoreErr)
			}
			persisted := jointEightReadCustody(t, f.ctx, custodyRoot, custodyEvidence)
			if persisted != imageEvidence {
				t.Fatal("joint actual custody descriptor differs from sealed image evidence")
			}
			imageEvidence = persisted
			actual := jointEightReadTarget(t, f.ctx, reader)
			defer jointEightClear(actual)
			jointEightReadback(t, original, actual, frozen)
			if target.RevokeWriter(f.ctx) != nil {
				t.Fatal("joint actual object writer revocation")
			}
			verify := r
			verify.Operation = "verify-database"
			verify.Binding = d.EvidenceBinding
			verify.Receipt = result.Evidence
			vd := d
			vd.Dependencies = nil
			vd.Placements = nil
			vd.EvidenceName = ""
			verify.Database = &vd
			// Authenticate the exact expected SQL and require every owner nonempty
			// BEFORE a fresh process gets files plus independent readers only.
			expected := jointEightOpenSQL(t, f.ctx, evidence, result.Evidence, key, verify.Binding)
			defer jointEightClear(expected)
			// Use a distinct child-only SELECT principal; the parent's independent
			// reader stays open under readerUser and cannot confuse physical-ID
			// observations for Com_select in the child.
			childReaderUser := "j8c" + strconv.Itoa(index) + "_" + f.nonce[:12]
			bootstrapChild := f.principal(childReaderUser, name, "SELECT")
			bootstrapChild.Close()
			until := time.Now().Add(3 * time.Second)
			for {
				var sessions int
				if f.admin.QueryRowContext(f.ctx, "SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE USER=?", childReaderUser).Scan(&sessions) != nil {
					t.Fatal("joint child bootstrap session census")
				}
				if sessions == 0 {
					break
				}
				if time.Now().After(until) {
					t.Fatal("joint child bootstrap connection did not actually exit")
				}
				time.Sleep(10 * time.Millisecond)
			}
			runJointEightNativeChild(t, f, verify, key, evidence.Name(), childReaderUser, imageEvidence, target.ReaderSettings, false)
			t.Run("changed-Northbound-expected-with-matching-descriptor", func(t *testing.T) {
				changed := jointEightClone(t, expected)
				defer jointEightClear(changed)
				rows := nativeGatewayTable(changed, "northbound_owner_records").Rows
				last := rows[len(rows)-1]
				if last["id"].String() != "18446744073709551615" || last["version"].String() != "18446744073709551615" {
					t.Fatal("joint bitmap counterexample did not select actual unsigned-max row")
				}
				last["version"] = domain.Text("0")
				jointEightRequireCrossDomainChange(t, expected, changed)
				bad := verify
				bad.Receipt = jointEightSealSQL(t, f.ctx, evidence, "joint-changed-expected.enc", key, bad.Binding, changed)
				metadataBinding := bad.Binding
				metadataBinding.Path += "/gateway-images"
				badMetadata, e := domain.ForgeGatewayImageSQLReferenceForTest(f.ctx, evidence, imageEvidence, key, metadataBinding, bad.Receipt, "joint-changed-reference.images")
				if e != nil {
					t.Fatal("joint controlled actual metadata reference change", e)
				}
				runJointEightNativeChild(t, f, bad, key, evidence.Name(), childReaderUser, badMetadata, target.ReaderSettings, true)
				after := jointEightReadTarget(t, f.ctx, reader)
				jointEightSame(t, actual, after)
				jointEightClear(after)
			})
			t.Log("all8 nonempty in ONE public SQL capture/source digest, ONE observed common restore TX, actual immutable image versions, encrypted full expected SQL/image evidence and fresh process all-cell verify; actual3159/3118/1142; source/cross-domain digest counterexamples included")
		})
	}
	archived := jointEightOpenSQL(t, f.ctx, stage, captured.Receipt, key, binding)
	jointEightSame(t, original, archived)
	jointEightClear(archived)
}
