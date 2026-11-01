package domain_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"clawreef/internal/repository"
	"clawreef/internal/services"
	"clawreef/internal/systembackup/domain"
)

// Exercise the real producer/delete/GC sequence before capture. The tiny core
// schema remains a fixture, but 050/052/066/072/073/074 and these owner methods
// are unchanged production code, not hand-inserted orphan/tombstone assertions.
func nativeImageHistorySequences(t *testing.T, f *gatewayNative, objects domain.GatewayImageProtocolFixture) {
	t.Helper()
	session := f.upper(f.source, "root", "")
	defer session.Close()
	adminCfg := f.cfg.Clone()
	adminCfg.DBName = f.source
	adminCfg.MultiStatements = true
	admin := f.open(adminCfg)
	defer admin.Close()
	raw, e := os.ReadFile(filepath.Join("..", "..", "db", "migrations", "066_add_runtime_upgrade_fence.sql"))
	if e != nil {
		t.Fatal("trusted instance-delete fence schema")
	}
	f.exec(admin, string(raw))
	f.exec(admin, "INSERT INTO instances(id,user_id,status) VALUES(8,4,'stopped')")
	f.exec(admin, "INSERT INTO gateway_keys(id,key_id,key_prefix,token_hash,key_type,name,owner_user_id,instance_id) VALUES(205,'gk_history_205','cmk_history',REPEAT('d',64),'managed_instance','native history',4,8)")
	keyID, instanceID := 205, 8
	owner := services.ImageArtifactOwner{UserID: 4, InstanceID: &instanceID, GatewayKeyID: &keyID}
	budget := services.NewGatewayBudgetService(repository.NewGatewayKeyRepository(session))
	jobs := services.NewGatewayImageJobService(session, budget)
	hash := sha256.Sum256([]byte("native-original-image-request"))
	claimed, winner, e := jobs.Claim(f.ctx, &services.ImageJob{RequestID: "native-history-key-delete", ScopeHash: services.ImageJobScope(owner), IdempotencyHash: services.ImageIdempotencyHash("native-history-key-delete"), RequestHash: hex.EncodeToString(hash[:]), UserID: 4, InstanceID: &instanceID, GatewayKeyID: &keyID, ModelID: 3, Estimate: 0.2})
	if e != nil || !winner || claimed == nil {
		t.Fatal("actual historical image Claim")
	}
	lease, e := budget.Reserve(f.ctx, keyID, 0.2)
	if e != nil || lease == nil {
		t.Fatal("actual historical image Reserve")
	}
	if jobs.Arm(f.ctx, claimed.RequestID, lease) != nil || jobs.Finish(f.ctx, claimed.RequestID, "completed", 0.2, nil, "") != nil || jobs.Settle(f.ctx, claimed.RequestID) != nil {
		t.Fatal("actual historical image Arm/Finish/Settle")
	}
	if repository.NewInstanceRepository(session).Delete(instanceID) != nil {
		t.Fatal("actual InstanceRepository.Delete")
	}
	var keys, reservations, ledger int
	var settled bool
	var oldKey int64
	var oldReservation string
	if admin.QueryRowContext(f.ctx, "SELECT (SELECT COUNT(*) FROM gateway_keys WHERE id=205),(SELECT COUNT(*) FROM gateway_key_budget_reservations WHERE gateway_key_id=205),(SELECT COUNT(*) FROM gateway_key_budget_ledger WHERE gateway_key_id=205)").Scan(&keys, &reservations, &ledger) != nil || keys != 0 || reservations != 0 || ledger != 0 {
		t.Fatal("actual instance cascade did not remove key/budget rows")
	}
	if admin.QueryRowContext(f.ctx, "SELECT settled,gateway_key_id,reservation_id FROM gateway_image_jobs WHERE request_id='native-history-key-delete'").Scan(&settled, &oldKey, &oldReservation) != nil || !settled || oldKey != 205 || oldReservation != lease.ReservationID {
		t.Fatal("actual deleted-key tombstone lost source attribution")
	}
	gcOwner := services.ImageArtifactOwner{UserID: 4}
	gcJobs := services.NewGatewayImageJobService(session, nil)
	if job, winner, e := gcJobs.Claim(f.ctx, &services.ImageJob{RequestID: "native-history-gc", ScopeHash: services.ImageJobScope(gcOwner), IdempotencyHash: services.ImageIdempotencyHash("native-history-gc"), RequestHash: hex.EncodeToString(hash[:]), UserID: 4, ModelID: 3}); e != nil || !winner || job == nil {
		t.Fatal("actual GC tombstone Claim")
	}
	if gcJobs.Arm(f.ctx, "native-history-gc", nil) != nil {
		t.Fatal("actual keyless image Arm")
	}
	artifacts, e := services.NewGatewayImageArtifactService(session, objects.SourceOperatorStorage)
	if e != nil {
		t.Fatal("actual GC owner service")
	}
	id, e := artifacts.Save(f.ctx, gcOwner, 3, "native-history-gc", "image/png", []byte("GC-ORIGINAL!"))
	if e != nil {
		t.Fatal("actual artifact Save")
	}
	if got, e := artifacts.Load(f.ctx, gcOwner, id); e != nil || got == nil || !bytes.Equal(got.Data, []byte("GC-ORIGINAL!")) {
		t.Fatal("actual saved artifact Load")
	}
	metadata, _ := json.Marshal(map[string]any{"created": time.Now().Unix(), "artifact_ids": []string{id}})
	text := string(metadata)
	if gcJobs.Finish(f.ctx, "native-history-gc", "completed", 0, &text, "") != nil || gcJobs.Settle(f.ctx, "native-history-gc") != nil {
		t.Fatal("actual GC image Finish/Settle")
	}
	f.exec(admin, "UPDATE gateway_image_artifacts SET expires_at='2020-01-01 00:00:00' WHERE id=?", id)
	if artifacts.PurgeExpired(f.ctx) != nil || objects.SourceDeletes() != 1 {
		t.Fatal("actual PurgeExpired did not delete source object through signed SDK")
	}
	var remaining int
	var saved string
	if admin.QueryRowContext(f.ctx, "SELECT COUNT(*) FROM gateway_image_artifacts WHERE id=?", id).Scan(&remaining) != nil || remaining != 0 || admin.QueryRowContext(f.ctx, "SELECT result_metadata FROM gateway_image_jobs WHERE request_id='native-history-gc'").Scan(&saved) != nil || saved != text {
		t.Fatal("GC tombstone lost its literal deleted artifact ID")
	}
	t.Log("real source history sequence: Claim/Reserve/Arm/Finish/Settle -> InstanceRepository.Delete -> key/reservation/ledger CASCADE with job IDs retained; real Save/Load/Finish/Settle/expiry/PurgeExpired -> signed object DELETE + artifact row deletion while job metadata unchanged PASS")
}
