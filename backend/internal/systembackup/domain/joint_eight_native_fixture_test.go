package domain_test

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"clawreef/internal/ownerrecords"
	"clawreef/internal/repository"
	"clawreef/internal/services"
	"clawreef/internal/systembackup/domain"
)

var jointEightTables = []string{"gateway_keys", "gateway_key_budget_reservations", "gateway_key_budget_ledger", "gateway_image_artifacts", "gateway_image_jobs", "northbound_admin_settings", "northbound_settings_audit", "northbound_owner_records"}

func jointEightRequireNonempty(t *testing.T, s domain.Snapshot) {
	t.Helper()
	for _, name := range jointEightTables {
		table := nativeGatewayTable(s, name)
		if len(table.Columns) == 0 || len(table.Rows) == 0 {
			t.Fatal("joint cohort omitted or emptied owner table", name)
		}
	}
}
func jointEightClone(t *testing.T, s domain.Snapshot) domain.Snapshot {
	t.Helper()
	raw, e := json.Marshal(s)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(raw)
	var out domain.Snapshot
	if json.Unmarshal(raw, &out) != nil {
		t.Fatal("joint snapshot clone")
	}
	return out
}
func jointEightClear(s domain.Snapshot) {
	for _, table := range s.Tables {
		for _, row := range table.Rows {
			for _, cell := range row {
				clear(cell.Bytes)
			}
		}
	}
}

func jointEightSetup(t *testing.T) (*gatewayNative, *sql.DB, domain.JointEightObjectFixture) {
	f := newGatewayNative(t)
	seed, policy, raw := domain.GatewayImageNativeSeedForTest()
	f.seed, f.policy = seed, policy
	for i := range f.seed.Tables {
		table := &f.seed.Tables[i]
		if table.Name == "instances" {
			table.Columns = append(table.Columns, domain.Column{Name: "owner", Type: "varchar(255)", Nullable: true})
			for _, row := range table.Rows {
				row["owner"] = domain.Text("Joint Private Owner")
			}
		}
		if table.Name == "gateway_image_artifacts" {
			table.Rows[0]["expires_at"] = domain.Text("2027-01-01 00:00:00")
		}
	}
	f.source = "joint_source_" + f.nonce[:16]
	db := f.schema(f.source)
	nativeImageMigrations(f, f.source)
	northboundNativeMigrations(f, db)
	seedNativeImageRows(f, f.source)
	id := nativeGatewayTable(f.seed, "gateway_image_artifacts").Rows[0]["id"].String()
	sum := sha256.Sum256([]byte("joint-source-realm-" + f.nonce))
	objects := domain.JointEightObjectsForTest(t, "cm-restore-"+hex.EncodeToString(sum[:16]), id, raw)
	clear(raw)
	sess := f.upper(f.source, "root", "")
	defer sess.Close()
	repo := repository.NewNorthboundRepository(sess)
	f.exec(db, "UPDATE northbound_admin_settings SET version=77,updated_by=1")
	settings, e := repo.GetAdminSettings()
	if e != nil {
		t.Fatal("joint source actual settings read", e)
	}
	settings.APIEnabled = true
	settings.OwnerTeamsEnabled = true
	settings.OwnerTeamCreationUserID = 4
	updated, e := repo.UpdateAdminSettings(f.ctx, settings, 77, 4)
	if e != nil || !updated {
		t.Fatal("joint source actual settings CAS", e)
	}
	updated, e = repo.UpdateAdminSettings(f.ctx, settings, 77, 4)
	if e != nil || updated {
		t.Fatal("joint stale source CAS accepted")
	}
	var auditCount int
	if db.QueryRowContext(f.ctx, "SELECT COUNT(*) FROM northbound_settings_audit").Scan(&auditCount) != nil || auditCount != 0 {
		t.Fatal("joint legal audit-free source update not established")
	}
	store := &ownerrecords.Store{Session: sess}
	at := time.Date(2026, 9, 3, 1, 2, 3, 0, time.UTC)
	identity, e := store.Bind(f.ctx, 7)
	if e != nil || identity == nil {
		t.Fatal("joint actual owner Bind", e)
	}
	if ok, e := store.Apply(f.ctx, *identity, ownerrecords.Fact{Type: "invocation", Source: "joint_fixture", SourceID: "joint-original-source", SessionID: "joint-private-session", At: at, Prompt: 2, Completion: 3, Tokens: 5}); e != nil || !ok {
		t.Fatal("joint actual owner Apply", e)
	}
	report, e := store.Report(f.ctx, identity.Owner, "month", "2026-09-01", time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC), true)
	if e != nil || report == nil || report.Revision == 0 || len(report.SavedRevisions) == 0 {
		t.Fatal("joint actual saved owner report", e)
	}
	// Create historical instance8 exactly ONCE, attach BOTH owner facts and an
	// image/key/budget chain, then use ONE actual repository deletion. No ID
	// remapping, deleting history, or emptying any of the8 owner tables.
	f.exec(db, "INSERT INTO instances(id,user_id,owner,type,instance_mode,runtime_type,runtime_variant,os_type,status) VALUES(8,4,'joint historical owner','openclaw','lite','gateway','linux','linux','stopped')")
	historical, e := store.Bind(f.ctx, 8)
	if e != nil || historical == nil {
		t.Fatal("joint historical owner Bind", e)
	}
	if ok, e := store.Apply(f.ctx, *historical, ownerrecords.Fact{Type: "invocation", Source: "joint_fixture", SourceID: "joint-deleted-instance", At: at, Tokens: 7}); e != nil || !ok {
		t.Fatal("joint historical owner Apply", e)
	}
	f.exec(db, "INSERT INTO gateway_keys(id,key_id,key_prefix,token_hash,key_type,name,owner_user_id,instance_id) VALUES(205,'gk_joint_205','cmk_joint',REPEAT('d',64),'managed_instance','joint history',4,8)")
	keyID, instanceID := 205, 8
	imageOwner := services.ImageArtifactOwner{UserID: 4, InstanceID: &instanceID, GatewayKeyID: &keyID}
	budget := services.NewGatewayBudgetService(repository.NewGatewayKeyRepository(sess))
	jobs := services.NewGatewayImageJobService(sess, budget)
	requestHash := sha256.Sum256([]byte("joint-history-request"))
	claimed, winner, e := jobs.Claim(f.ctx, &services.ImageJob{RequestID: "joint-history-delete", ScopeHash: services.ImageJobScope(imageOwner), IdempotencyHash: services.ImageIdempotencyHash("joint-history-delete"), RequestHash: hex.EncodeToString(requestHash[:]), UserID: 4, InstanceID: &instanceID, GatewayKeyID: &keyID, ModelID: 3, Estimate: 0.2})
	if e != nil || !winner || claimed == nil {
		t.Fatal("joint actual image Claim", e)
	}
	lease, e := budget.Reserve(f.ctx, keyID, 0.2)
	if e != nil || lease == nil {
		t.Fatal("joint actual image Reserve", e)
	}
	if jobs.Arm(f.ctx, claimed.RequestID, lease) != nil || jobs.Finish(f.ctx, claimed.RequestID, "completed", 0.2, nil, "") != nil || jobs.Settle(f.ctx, claimed.RequestID) != nil {
		t.Fatal("joint actual image Arm/Finish/Settle")
	}
	if repository.NewInstanceRepository(sess).Delete(8) != nil {
		t.Fatal("joint actual single historical instance deletion")
	}
	var ownerHistory, instances, keys, reservations, ledger int
	var oldKey int64
	var oldReservation string
	if db.QueryRowContext(f.ctx, "SELECT (SELECT COUNT(*) FROM northbound_owner_records WHERE instance_id=8),(SELECT COUNT(*) FROM instances WHERE id=8),(SELECT COUNT(*) FROM gateway_keys WHERE id=205),(SELECT COUNT(*) FROM gateway_key_budget_reservations WHERE gateway_key_id=205),(SELECT COUNT(*) FROM gateway_key_budget_ledger WHERE gateway_key_id=205)").Scan(&ownerHistory, &instances, &keys, &reservations, &ledger) != nil || ownerHistory < 2 || instances != 0 || keys != 0 || reservations != 0 || ledger != 0 {
		t.Fatal("joint actual shared deletion closure")
	}
	if db.QueryRowContext(f.ctx, "SELECT gateway_key_id,reservation_id FROM gateway_image_jobs WHERE request_id='joint-history-delete' AND state='completed' AND settled=1").Scan(&oldKey, &oldReservation) != nil || oldKey != 205 || oldReservation != lease.ReservationID {
		t.Fatal("joint historical image job lost literal IDs")
	}
	jointEightGC(t, f, objects)
	northboundNativeAddAudits(f, db)
	// Last owner insert follows all actual auto-increment producers.
	boundary := domain.NorthboundOwnerNativeRowForTest()
	defer func() {
		for _, c := range boundary {
			clear(c.Bytes)
		}
	}()
	var cols, marks []string
	var args []any
	for name, cell := range boundary {
		cols = append(cols, "`"+name+"`")
		marks = append(marks, "?")
		if cell.Null {
			args = append(args, nil)
		} else {
			args = append(args, cell.Bytes)
		}
	}
	f.exec(db, "INSERT INTO northbound_owner_records("+strings.Join(cols, ",")+") VALUES("+strings.Join(marks, ",")+")", args...)
	f.exec(db, "UPDATE northbound_admin_settings SET version=9223372036854775807")
	service, e := services.NewGatewayImageArtifactService(sess, objects.SourceStorage)
	if e != nil {
		t.Fatal(e)
	}
	ownerKey := int(9223372036854775806)
	loaded, e := service.Load(f.ctx, services.ImageArtifactOwner{UserID: 4, GatewayKeyID: &ownerKey}, id)
	if e != nil || loaded == nil || !bytes.Equal(loaded.Data, []byte("PNG!")) {
		t.Fatal("joint real source immutable image Load", e)
	}
	clear(loaded.Data)
	return f, db, objects
}

func jointEightGC(t *testing.T, f *gatewayNative, objects domain.JointEightObjectFixture) {
	t.Helper()
	sess := f.upper(f.source, "root", "")
	defer sess.Close()
	owner := services.ImageArtifactOwner{UserID: 4}
	jobs := services.NewGatewayImageJobService(sess, nil)
	hash := sha256.Sum256([]byte("joint-gc-request"))
	job, winner, e := jobs.Claim(f.ctx, &services.ImageJob{RequestID: "joint-history-gc", ScopeHash: services.ImageJobScope(owner), IdempotencyHash: services.ImageIdempotencyHash("joint-history-gc"), RequestHash: hex.EncodeToString(hash[:]), UserID: 4, ModelID: 3})
	if e != nil || !winner || job == nil || jobs.Arm(f.ctx, job.RequestID, nil) != nil {
		t.Fatal("joint real GC job producer", e)
	}
	artifacts, e := services.NewGatewayImageArtifactService(sess, objects.SourceOperatorStorage)
	if e != nil {
		t.Fatal(e)
	}
	id, e := artifacts.Save(f.ctx, owner, 3, job.RequestID, "image/png", []byte("JOINT-GC-ORIGINAL"))
	if e != nil {
		t.Fatal("joint actual artifact Save", e)
	}
	loaded, e := artifacts.Load(f.ctx, owner, id)
	if e != nil || loaded == nil || !bytes.Equal(loaded.Data, []byte("JOINT-GC-ORIGINAL")) {
		t.Fatal("joint actual GC artifact Load", e)
	}
	clear(loaded.Data)
	raw, e := json.Marshal(map[string]any{"created": time.Now().Unix(), "artifact_ids": []string{id}})
	if e != nil {
		t.Fatal(e)
	}
	body := string(raw)
	clear(raw)
	if jobs.Finish(f.ctx, job.RequestID, "completed", 0, &body, "") != nil || jobs.Settle(f.ctx, job.RequestID) != nil {
		t.Fatal("joint actual GC Finish/Settle")
	}
	c := f.cfg.Clone()
	c.DBName = f.source
	db := f.open(c)
	defer db.Close()
	f.exec(db, "UPDATE gateway_image_artifacts SET expires_at='2020-01-01 00:00:00' WHERE id=?", id)
	if artifacts.PurgeExpired(f.ctx) != nil || objects.SourceDeletes() != 1 {
		t.Fatal("joint actual GC signed DELETE")
	}
	var count int
	var preserved string
	if db.QueryRowContext(f.ctx, "SELECT COUNT(*) FROM gateway_image_artifacts WHERE id=?", id).Scan(&count) != nil || count != 0 || db.QueryRowContext(f.ctx, "SELECT result_metadata FROM gateway_image_jobs WHERE request_id=?", job.RequestID).Scan(&preserved) != nil || preserved != body {
		t.Fatal("joint GC retained metadata mismatch")
	}
}
