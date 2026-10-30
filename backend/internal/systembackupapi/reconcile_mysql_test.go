package systembackupapi

import (
	"crypto/tls"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	read "clawreef/internal/systembackupread"
)

// The SQL/auth/idempotency lane is real. Synthetic encrypted-record metadata
// deliberately does not claim native recovery, publication or restored data.
func TestOriginalReconciliationRealSQLPreservesOwnershipAndCancellation(t *testing.T) {
	db, w := submissionMySQL(t)
	h, operator, viewer := liveAdmissionHTTP(t, db, w)
	r := httptest.NewRequest("POST", "/api/v1/admin/system-backups", strings.NewReader(`{}`))
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Authorization", "Bearer "+operator)
	r.Header.Set("Idempotency-Key", "create-original-reconcile-001")
	r.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	h.Create(res, r, read.BackupTask, "reconcile-test")
	if res.Code != 202 {
		t.Fatal(res.Code, res.Body.String())
	}
	var id string
	if err := db.QueryRow("SELECT public_id FROM system_backup_v2_backups").Scan(&id); err != nil {
		t.Fatal(err)
	}
	actions := func(token string) RecoveryActions {
		t.Helper()
		r := httptest.NewRequest("GET", "/api/v1/admin/system-backups/"+id+"/recovery-actions", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		res := httptest.NewRecorder()
		h.RecoveryActions(res, r, id, "test")
		if res.Code != 200 {
			t.Fatal(res.Code, res.Body.String())
		}
		var a RecoveryActions
		if json.Unmarshal(res.Body.Bytes(), &a) != nil {
			t.Fatal("bad actions")
		}
		return a
	}
	if a := actions(operator); a.CanReconcile || a.Reason != "capture_retry_not_supported" {
		t.Fatal(a)
	}
	for _, q := range []string{
		`UPDATE system_backup_v2_backups SET status='capturing',started_at=UTC_TIMESTAMP(6),maintenance_lock_owner=public_id,maintenance_fencing_token=7,controller_owner='live-original-owner',controller_lease_expires_at=TIMESTAMPADD(SECOND,600,UTC_TIMESTAMP(6)),next_reconcile_at=TIMESTAMPADD(SECOND,600,UTC_TIMESTAMP(6)),row_version=row_version+1`,
		`INSERT INTO system_backup_v2_attempts(target_type,target_public_id,attempt_no,phase,status,started_at) SELECT 'backup',public_id,1,'capture','running',UTC_TIMESTAMP(6) FROM system_backup_v2_backups`,
		`INSERT INTO system_backup_v2_runtime_captures(task_public_id,application_scope,gate_generation,acquire_token,registry_sha256,writers_json,acquire_until,hold_until) SELECT public_id,'installation',7,8,REPEAT('a',64),'[]',TIMESTAMPADD(SECOND,60,UTC_TIMESTAMP(6)),TIMESTAMPADD(SECOND,300,UTC_TIMESTAMP(6)) FROM system_backup_v2_backups`,
		`INSERT INTO system_backup_v2_execution_records(origin_installation_id,task_public_id,attempt_no,phase,record_kind,payload_sha256,key_ref,sealed_payload) SELECT origin_installation_id,public_id,1,'capture','plan',REPEAT('a',64),'unit-metadata-only','not-a-native-receipt' FROM system_backup_v2_backups`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if a := actions(operator); !a.CanReconcile {
		t.Fatal(a)
	}
	if a := actions(viewer); a.CanReconcile || a.Reason != "permission_denied" {
		t.Fatal(a)
	}
	send := func(token, key string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/v1/admin/system-backups/"+id+"/reconcile", strings.NewReader(`{}`))
		r.TLS = &tls.ConnectionState{}
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Idempotency-Key", key)
		r.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		h.Reconcile(res, r, id, "test")
		return res
	}
	if res := send(viewer, "deny-original-reconcile-001"); res.Code != 403 {
		t.Fatal("viewer operated", res.Code, res.Body.String())
	}
	var before, after, version uint64
	if err := db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_attempts").Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT row_version FROM system_backup_v2_backups").Scan(&version); err != nil {
		t.Fatal(err)
	}
	res = send(operator, "same-original-reconcile-001")
	if res.Code != 202 {
		t.Fatal(res.Code, res.Body.String())
	}
	var first read.OperationDTO
	if json.Unmarshal(res.Body.Bytes(), &first) != nil || first.OperationType != "capture_reconcile" {
		t.Fatal(res.Body.String())
	}
	var owner, status string
	var actualVersion uint64
	var stillLive bool
	if err := db.QueryRow("SELECT controller_owner,status,row_version,controller_lease_expires_at>UTC_TIMESTAMP(6) AND next_reconcile_at>UTC_TIMESTAMP(6) FROM system_backup_v2_backups").Scan(&owner, &status, &actualVersion, &stillLive); err != nil || owner != "live-original-owner" || status != "capturing" || version != actualVersion || !stillLive {
		t.Fatal("live owner disturbed", owner, status, err)
	}
	if _, err := db.Exec("UPDATE system_backup_v2_backups SET status='canceling',can_cancel=FALSE,controller_lease_expires_at=TIMESTAMPADD(SECOND,-1,UTC_TIMESTAMP(6))"); err != nil {
		t.Fatal(err)
	}
	if res = send(operator, "cancel-original-reconcile-001"); res.Code != 202 {
		t.Fatal(res.Code, res.Body.String())
	}
	var due bool
	if err := db.QueryRow("SELECT status,next_reconcile_at<=UTC_TIMESTAMP(6) FROM system_backup_v2_backups").Scan(&status, &due); err != nil || status != "canceling" || !due {
		t.Fatal("cancellation replayed capture", status, due, err)
	}
	if _, err := db.Exec("UPDATE system_backup_v2_backups SET status='canceled',failure_category='canceled_by_actor',finished_at=UTC_TIMESTAMP(6),controller_owner=NULL,controller_lease_expires_at=NULL"); err != nil {
		t.Fatal(err)
	}
	if res = send(operator, "same-original-reconcile-001"); res.Code != 202 {
		t.Fatal("accepted operation lost", res.Code, res.Body.String())
	}
	var replay read.OperationDTO
	json.Unmarshal(res.Body.Bytes(), &replay)
	if replay.PublicID != first.PublicID {
		t.Fatal("second operation on replay")
	}
	if a := actions(operator); a.CanReconcile || a.Reason != "canceled_task_cannot_retry" {
		t.Fatal(a)
	}
	if res = send(operator, "new-canceled-reconcile-001"); res.Code != 503 {
		t.Fatal("canceled task restarted", res.Code)
	}
	lookup := httptest.NewRequest("POST", "/api/v1/admin/system-backups/"+id+"/reconcile", strings.NewReader(`{"lookup_only":true}`))
	lookup.TLS = &tls.ConnectionState{}
	lookup.Header.Set("Authorization", "Bearer "+operator)
	lookup.Header.Set("Idempotency-Key", "not-created-lookup-only-001")
	lookup.Header.Set("Content-Type", "application/json")
	res = httptest.NewRecorder()
	h.Reconcile(res, lookup, id, "test")
	if res.Code != 404 {
		t.Fatal("lookup created an operation", res.Code, res.Body.String())
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_attempts").Scan(&after); err != nil || before != after {
		t.Fatal("new attempt created", before, after, err)
	}
}
