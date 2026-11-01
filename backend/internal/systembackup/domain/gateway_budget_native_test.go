package domain_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"clawreef/internal/repository"
	"clawreef/internal/services"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
)

func nativeGatewayTable(s domain.Snapshot, name string) domain.Table {
	for _, t := range s.Tables {
		if t.Name == name {
			return t
		}
	}
	return domain.Table{}
}

func TestGatewayBudgetPublicWorkerActualTLSMySQL(t *testing.T) {
	f := newGatewayNative(t)
	t.Setenv("GATEWAY_KEY_PEPPER", "owned-disposable-native-pepper-"+f.nonce)
	f.source = "gw_source_" + f.nonce[:16]
	sourceAdmin := f.schema(f.source)
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	oldKeyToken := "cmk_live_gk_original_1_" + hex.EncodeToString(secret[:])
	oldAlias := "owned-original-alias-" + f.nonce
	keys := nativeGatewayTable(f.seed, "gateway_keys")
	keys.Rows[0]["token_hash"], keys.Rows[0]["key_prefix"] = domain.Text(repository.GatewayKeyTokenHash(oldKeyToken)), domain.Text(repository.GatewayKeyTokenPrefix(oldKeyToken))
	keys.Rows[0]["expires_at"], keys.Rows[0]["budget_spent"] = domain.Cell{Null: true}, domain.Text("123.00000001")
	// A genuinely pending settlement without a ledger is distinct from the
	// matching pending+ledger idempotence history and from an expired reserve.
	for n := range f.seed.Tables {
		if f.seed.Tables[n].Name == "gateway_key_budget_reservations" {
			original := f.seed.Tables[n].Rows[1]
			row := domain.Row{}
			for k, v := range original {
				row[k] = v
			}
			row["reservation_id"] = domain.Text("pending-needs-ledger")
			f.seed.Tables[n].Rows = append(f.seed.Tables[n].Rows, row)
		}
	}
	for _, table := range f.seed.Tables {
		var names, marks []string
		for _, column := range table.Columns {
			names = append(names, "`"+column.Name+"`")
			marks = append(marks, "?")
		}
		for _, row := range table.Rows {
			var args []any
			for _, column := range table.Columns {
				cell := row[column.Name]
				if cell.Null {
					args = append(args, nil)
				} else {
					args = append(args, cell.Bytes)
				}
			}
			f.exec(sourceAdmin, "INSERT INTO `"+table.Name+"`("+strings.Join(names, ",")+") VALUES("+strings.Join(marks, ",")+")", args...)
		}
	}
	seedNativeGatewayAttributionHistory(t, f, sourceAdmin)
	// Real repository/service authentication, not DTO IsUsable assertions.
	sourceSession := f.upper(f.source, "root", "")
	sourceKeys := repository.NewGatewayKeyRepository(sourceSession)
	sourceInstances := repository.NewInstanceRepository(sourceSession)
	keyService := services.NewGatewayKeyService(sourceKeys, sourceInstances, nil)
	if key, err := keyService.Resolve(oldKeyToken); err != nil || key == nil {
		t.Fatal("old key positive control did not authenticate")
	}
	if instance, err := sourceInstances.GetByAccessToken("source-token"); err != nil || instance == nil {
		t.Fatal("old instance token positive control")
	}
	aliasWriter, ok := sourceInstances.(interface {
		UpsertGatewayTokenAlias(context.Context, int, string, time.Time) error
	})
	if !ok {
		t.Fatal("actual instance repository does not expose its alias writer")
	}
	if aliasWriter.UpsertGatewayTokenAlias(f.ctx, 7, oldAlias, time.Now().UTC().Add(time.Hour)) != nil {
		t.Fatal("owned alias seed")
	}
	if instance, err := sourceInstances.GetByAccessToken(oldAlias); err != nil || instance == nil {
		t.Fatal("old alias positive control")
	}
	t.Log("real source authentication positive controls: gateway key, instance token, gateway token alias PASS")
	sourceSession.Close()
	sourceUser := "gws_" + f.nonce[:12]
	source := f.principal(sourceUser, f.source, "SELECT")
	observed, err := domain.CaptureSource(f.ctx, source, domain.Limits{MaxRows: 1000, MaxBytes: 8 << 20}, f.source, f.uuid)
	if err != nil {
		t.Fatal("actual source capture")
	}
	// Freeze an actual DB time no earlier than the captured source timestamp;
	// rounded TIMESTAMP(0) writes may lie just past the current whole second.
	latest := time.Time{}
	for _, row := range nativeGatewayTable(observed, "gateway_keys").Rows {
		at, err := time.Parse("2006-01-02 15:04:05", row["updated_at"].String())
		if err != nil {
			t.Fatal("native timestamp representation")
		}
		if at.After(latest) {
			latest = at
		}
	}
	var frozen time.Time
	for {
		var raw string
		if f.admin.QueryRowContext(f.ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&raw) != nil {
			t.Fatal("owned DB time")
		}
		frozen, err = time.Parse("2006-01-02 15:04:05.999999", raw)
		if err != nil {
			t.Fatal("DB clock parse")
		}
		if !frozen.Before(latest) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	for name, adapter := range f.policy.Dependencies {
		adapter.SchemaSHA256 = domain.SchemaDigest(nativeGatewayTable(observed, name))
		adapter.InterruptedAt = frozen.UTC().Format(time.RFC3339Nano)
		f.policy.Dependencies[name] = adapter
	}
	store, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	key := bytes.Repeat([]byte{93}, 32)
	binding := staging.Binding{BackupID: "gateway-native-" + f.nonce, Attempt: "1", Path: "mysql/domain", CaptureContextHash: strings.Repeat("a", 64), EnvelopeID: "owned-gateway-key"}
	spec := worker.DatabaseSpec{Address: f.cfg.Addr, Name: f.source, ServerUUID: f.uuid, TLSServerName: "gateway-restore-native.local", RootCA: f.ca, MaxRows: 1000, MaxMemoryBytes: 8 << 20}
	capture := worker.Request{Version: worker.Version, Operation: "capture-database", Database: &spec, Deadline: time.Now().Add(2 * time.Minute), ArtifactName: "gateway-source.enc", MaxArchiveBytes: 8 << 20, MaxCompressedBytes: 8 << 20, Binding: binding}
	captureCheck := func(ctx context.Context, purpose string, r worker.Request) error {
		if r.Operation != "capture-database" || r.Binding != binding || r.Database == nil || r.Database.Name != f.source || r.Database.ServerUUID != f.uuid || purpose == "" {
			return errors.New("owned native capture binding rejected")
		}
		return f.observe(ctx, f.source, sourceUser)
	}
	captured, err := worker.RunDatabase(f.ctx, capture, worker.DatabaseEnvironment{Database: source, Staging: store, Key: key, Check: captureCheck})
	if err != nil || captured.Rows < 12 {
		t.Fatal("public native capture")
	}
	source.Close()
	f.exec(f.admin, "ALTER USER '"+sourceUser+"'@'127.0.0.1' ACCOUNT LOCK")
	sourceAdmin.Close()
	for index, mode := range []string{"success", "evidence-failure", "cancel-before-commit", "credential-revoked"} {
		name := "cm_drill_gw_" + strconv.Itoa(index) + "_" + f.nonce[:16]
		targetAdmin := f.schema(name)
		f.exec(targetAdmin, "INSERT INTO users(id,username,password_hash,role,is_active) VALUES(999,'admin','bootstrap','admin','1')")
		writerUser := "gww" + strconv.Itoa(index) + "_" + f.nonce[:12]
		readerUser := "gwr" + strconv.Itoa(index) + "_" + f.nonce[:12]
		writer := f.principal(writerUser, name, "SELECT,INSERT,DELETE")
		reader := f.principal(readerUser, name, "SELECT")
		// Actual common SQL preflight with an observed fixture identity. Missing
		// owner selection is rejected while the target is still entirely blank.
		badPolicy := f.policy
		badPolicy.Dependencies = map[string]domain.TableAdapter{}
		for k, v := range f.policy.Dependencies {
			badPolicy.Dependencies[k] = v
		}
		delete(badPolicy.Dependencies, "gateway_key_budget_ledger")
		target := domain.DrillTarget{Database: name, ServerUUID: f.uuid, CheckIsolation: func(ctx context.Context) error { return f.observe(ctx, name, writerUser) }}
		if domain.PreflightRestoreDrill(f.ctx, writer, target, observed, badPolicy) == nil {
			t.Fatal("missing owner adapter passed native preflight")
		}
		var untouched int
		if targetAdmin.QueryRowContext(f.ctx, "SELECT COUNT(*) FROM gateway_keys").Scan(&untouched) != nil || untouched != 0 {
			t.Fatal("rejected preflight wrote native target")
		}
		evidence, err := os.OpenRoot(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer evidence.Close()
		restore := capture
		restore.Operation = "restore-database"
		restore.PolicyVersion = "owned-gateway-budget-055"
		restore.ArtifactName = ""
		restore.Receipt = captured.Receipt
		d := spec
		d.Name = name
		d.Dependencies = f.policy.Dependencies
		d.Placements = f.policy.Placements
		d.EvidenceName = "gateway-expected.enc"
		d.EvidenceBinding = binding
		d.EvidenceBinding.Path = "mysql/expected"
		restore.Database = &d
		child, cancel := context.WithCancel(f.ctx)
		checks := 0
		evidenceReached, commitReached := false, false
		check := func(ctx context.Context, purpose string, r worker.Request) error {
			checks++
			if r.Operation != "restore-database" || r.Binding != binding || r.Database == nil || r.Database.Name != name || r.Database.ServerUUID != f.uuid {
				return errors.New("owned native restore binding rejected")
			}
			if err := f.observe(ctx, name, writerUser); err != nil {
				return err
			}
			if purpose == "before-evidence" {
				evidenceReached = true
				if mode == "evidence-failure" {
					evidence.Close()
				}
			}
			if purpose == "before-database-commit" {
				commitReached = true
			}
			if mode == "cancel-before-commit" && purpose == "before-database-commit" {
				cancel()
			}
			if mode == "credential-revoked" && purpose == "before-database-commit" {
				f.exec(f.admin, "ALTER USER '"+writerUser+"'@'127.0.0.1' ACCOUNT LOCK")
				return f.observe(ctx, name, writerUser)
			}
			return ctx.Err()
		}
		restored, err := worker.RunDatabase(child, restore, worker.DatabaseEnvironment{Database: writer, Staging: store, Evidence: evidence, Key: key, Check: check})
		cancel()
		f.revoke(writer, writerUser)
		if checks < 2 {
			t.Fatal("public restore did not execute observed checks")
		}
		if mode != "success" {
			if !evidenceReached || (mode != "evidence-failure" && !commitReached) {
				t.Fatal("failure did not reach actual evidence/commit boundary", mode)
			}
			if err == nil {
				t.Fatal("failed native restore committed", mode)
			}
			var users, keys, reservations, ledger int
			if reader.QueryRowContext(f.ctx, "SELECT (SELECT COUNT(*) FROM users WHERE id=999),(SELECT COUNT(*) FROM gateway_keys),(SELECT COUNT(*) FROM gateway_key_budget_reservations),(SELECT COUNT(*) FROM gateway_key_budget_ledger)").Scan(&users, &keys, &reservations, &ledger) != nil || users != 1 || keys != 0 || reservations != 0 || ledger != 0 {
				t.Fatal("whole native rollback failed", mode)
			}
			validateNativeGatewayHistoryRollback(t, f, reader, mode)
			t.Logf("actual public native case=%s: reached evidence=%t commit=%t; rollback bootstrap=1 keys=0 reservations=0 ledger=0; writer physical sessions=0 and fresh login=3118 PASS", mode, evidenceReached, commitReached)
			continue
		}
		if err != nil || !restored.Quarantined || restored.Verified {
			t.Fatal("public native restore failed")
		}
		verify := restore
		verify.Operation = "verify-database"
		verify.Binding = d.EvidenceBinding
		verify.Receipt = restored.Evidence
		vd := d
		vd.Dependencies = nil
		vd.Placements = nil
		vd.Configs = nil
		vd.EvidenceName = ""
		verify.Database = &vd
		verifyCheck := func(ctx context.Context, purpose string, r worker.Request) error {
			if r.Operation != "verify-database" || r.Binding != d.EvidenceBinding || r.Database == nil || r.Database.Name != name {
				return errors.New("owned verifier binding rejected")
			}
			return f.observe(ctx, name, readerUser)
		}
		verified, err := worker.RunDatabase(f.ctx, verify, worker.DatabaseEnvironment{Database: reader, Staging: evidence, Key: key, Check: verifyCheck})
		if err != nil || !verified.Verified {
			t.Fatal("independent native SELECT-only readback")
		}
		validateNativeGatewayHistory(t, f, reader, name, readerUser, oldKeyToken, oldAlias, observed)
		// Only AFTER successful readback, a trusted fixture operator deliberately
		// invokes the unsafe getter as a positive counterexample on this target.
		operator := f.upper(name, "root", "")
		if _, err := repository.NewGatewayKeyRepository(operator).GetBudgetUsage(f.ctx, 9223372036854775806); err != nil {
			t.Fatal("real write-capable getter counterexample failed")
		}
		operator.Close()
		var remaining, ledger int
		if reader.QueryRowContext(f.ctx, "SELECT (SELECT COUNT(*) FROM gateway_key_budget_reservations),(SELECT COUNT(*) FROM gateway_key_budget_ledger)").Scan(&remaining, &ledger) != nil || remaining != 0 || ledger != 3 {
			t.Fatal("unsafe getter did not really mutate revoked key history")
		}
		if result, err := worker.RunDatabase(f.ctx, verify, worker.DatabaseEnvironment{Database: reader, Staging: evidence, Key: key, Check: verifyCheck}); err == nil || result.Verified {
			t.Fatal("readback accepted getter-induced reconciliation")
		}
		t.Log("actual public native case=success: capture -> restore -> writer physical sessions=0/fresh login=3118 -> independent SELECT-only verify PASS")
		t.Log("preserved counterexample: real GetBudgetUsage with trusted write-capable fixture operator still changes revoked-key history: reservations 3->0, ledger 2->3; subsequent public verifier rejects PASS")
	}
	t.Log("native scope: real TLS/current gateway DDL and private core fixtures; not fullC source authentication, cluster isolation, image object proof or final qualification")
	t.Log("fixture observation boundary: UUID/nonce/specified account lock only; it does not inventory other consumer accounts or existing writer sessions and is not a physical target isolation proof")
}
