//go:build systembackup_mysql

package systembackupevidence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

// Extends A's actual task-row probe through D's admission/provider/result
// composition. The published task/reference tables and every transaction are
// actual MySQL. Task contents, issuer, capacity and provider transport are
// explicitly test inputs; these cases grant no production authority.
type dTaskOwnerDownloadChainFixture struct {
	*aAdmissionMySQLFixture
	concrete *SQLTaskDownloadOwners
	row      aTaskOwnerSQLSeed
}

func dTaskOwnerEncryptedObject(t *testing.T, kind string) (Prepared, []byte, []byte, testKeys) {
	t.Helper()
	old, plain, _, keys := fixture(t, 8193)
	i := old.Manifest().Identity
	for _, row := range aTaskOwnerSQLSeeds(i.Installation, time.Unix(1, 0), time.Unix(2, 0), []byte(`{}`)) {
		if row.kind == kind {
			i.OwnerType, i.OwnerID = row.kind, row.id
		}
	}
	if i.OwnerType != kind {
		t.Fatal("unknown task encryption owner", kind)
	}
	var object bytes.Buffer
	p, err := Prepare(context.Background(), i, old.Manifest().Key, source(plain), testRedactor{}, keys, &object)
	mustSQL(t, err)
	return p, plain, object.Bytes(), keys
}

func TestDTaskOwnerDownloadChainMySQLSeed(t *testing.T) {
	t.Run("current_config_fk", func(t *testing.T) {
		input, err := decodeADownloadMFAInputs(aDownloadMFASeed)
		mustSQL(t, err)
		p := aDownloadMFAPinnedFixture(t, input)
		rows := dTaskOwnerChainSQLSeeds(t, p.initial.Manifest.Identity.Installation, p.initial.CreatedAt, p.initial.OwnerDeadline, p.db.config.CanonicalJSON())
		for _, row := range rows {
			if strings.Count(row.statement, "?") != len(row.args) || !strings.Contains(row.statement, "'owner-sql-probe',2,") || !bytes.Equal(row.args[3].([]byte), p.db.config.CanonicalJSON()) || row.args[5] != p.db.config.SHA256() {
				t.Fatal("current task config FK does not bind the exact snapshot", row.kind)
			}
		}
	})
	for _, kind := range []string{"backup", "drill", "preflight", "artifact_verify"} {
		t.Run(kind, func(t *testing.T) {
			p, plain, object, keys := dTaskOwnerEncryptedObject(t, kind)
			m := p.Manifest()
			key, err := keyFor("evidence", m.Identity)
			mustSQL(t, err)
			r := Ref{Identity: strings.Repeat("a", 64), Version: "v1", RelativeKey: key, ImmutableVersion: "v1"}
			store := &testStore{data: object, present: true, info: ObjectInfo{Version: "v1", SHA256: hash(object), Size: int64(len(object))}}
			got, err := OpenRange(context.Background(), m, r, store, keys, 0, int64(len(plain)-1))
			mustSQL(t, err)
			defer wipe(got)
			if !bytes.Equal(got, plain) || m.Identity.OwnerType != kind {
				t.Fatal("owner-specific encrypted object did not roundtrip", kind)
			}
			// Merely changing the stored owner must not work: encryption AAD
			// has to have been generated for the actual original task identity.
			m.Identity.OwnerID = strings.Replace(m.Identity.OwnerID, "11111111", "22222222", 1)
			if body, err := OpenRange(context.Background(), m, r, store, keys, 0, 0); err == nil || len(body) != 0 {
				t.Fatal("encrypted object accepted a replaced original owner")
			}
		})
	}
	t.Log("PASS task owner chain seed; actual_mysql=not_run provider_transport=synthetic")
}

func dTaskOwnerChainSQLSeeds(t *testing.T, installation string, created, deadline time.Time, snapshot []byte) []aTaskOwnerSQLSeed {
	t.Helper()
	rows := aTaskOwnerSQLSeeds(installation, created, deadline, snapshot)
	for n := range rows {
		// The admission fixture retains original v1 with a historical HMAC
		// config and installs the current canonical bytes as v2. Keep the
		// task's real four-column config FK bound to that exact v2 snapshot.
		const original = "'owner-sql-probe',1,"
		if strings.Count(rows[n].statement, original) != 1 {
			t.Fatal("task seed config-version location changed")
		}
		rows[n].statement = strings.Replace(rows[n].statement, original, "'owner-sql-probe',2,", 1)
	}
	return rows
}

func newDTaskOwnerDownloadChainFixture(t *testing.T, input aDownloadMFAInputs, kind string) *dTaskOwnerDownloadChainFixture {
	t.Helper()
	x := newAAdmissionMySQLFixture(t, input)
	f := &dTaskOwnerDownloadChainFixture{aAdmissionMySQLFixture: x}
	db := x.aDownloadMFAFixture.db
	for _, row := range dTaskOwnerChainSQLSeeds(t, x.registry.Installation, x.initial.CreatedAt.Add(-time.Minute), x.initial.OwnerDeadline, x.admissionPinnedFixture.db.config.CanonicalJSON()) {
		_, err := db.ExecContext(x.ctx, row.statement, row.args...)
		mustSQL(t, err)
		if row.kind == kind {
			f.row = row
		}
	}
	if f.row.kind == "" {
		t.Fatal("unknown actual task owner")
	}
	p, plain, object, keys := dTaskOwnerEncryptedObject(t, kind)
	r := x.initial
	r.Manifest = p.Manifest()
	var err error
	r.Ref.RelativeKey, err = keyFor("evidence", r.Manifest.Identity)
	mustSQL(t, err)
	m := r.Manifest
	_, err = db.ExecContext(x.ctx, `UPDATE system_backup_v2_evidence SET owner_target_type=?,owner_target_public_id=?,storage_relative_key=?,storage_relative_key_hash=?,object_checksum=?,object_size_bytes=?,chunk_count=?,chunk_list_root=?,envelope_hash=? WHERE public_id=?`, kind, f.row.id, r.Ref.RelativeKey, hash([]byte(r.Ref.RelativeKey)), m.ObjectHash, m.ObjectSize, len(m.Chunks), m.ChunkRoot, m.EnvelopeHash, m.Identity.ID)
	mustSQL(t, err)
	var evidenceID int64
	mustSQL(t, db.QueryRowContext(x.ctx, "SELECT id FROM system_backup_v2_evidence WHERE public_id=?", m.Identity.ID).Scan(&evidenceID))
	_, err = db.ExecContext(x.ctx, "DELETE FROM system_backup_v2_evidence_chunks WHERE evidence_id=?", evidenceID)
	mustSQL(t, err)
	for _, chunk := range m.Chunks {
		nonce, e := base64.RawURLEncoding.DecodeString(chunk.Nonce)
		mustSQL(t, e)
		tag, e := base64.RawURLEncoding.DecodeString(chunk.Tag)
		mustSQL(t, e)
		_, err = db.ExecContext(x.ctx, `INSERT INTO system_backup_v2_evidence_chunks(evidence_id,chunk_index,plaintext_offset,plaintext_length,plaintext_sha256,object_frame_offset,object_frame_length,ciphertext_sha256,gcm_nonce,gcm_tag) VALUES(?,?,?,?,?,?,?,?,?,?)`, evidenceID, chunk.Index, chunk.PlainOffset, chunk.PlainLength, chunk.PlainHash, chunk.FrameOffset, chunk.FrameLength, chunk.CipherHash, nonce, tag)
		mustSQL(t, err)
	}
	// Physically remove the old synthetic fallback before rebuilding every
	// reader, admission, post-commit policy and independent result service.
	_, err = db.ExecContext(x.ctx, "DROP TABLE synthetic_download_mfa_owner")
	mustSQL(t, err)
	f.concrete, err = NewSQLTaskDownloadOwners(SQLTaskDownloadOwnersConfig{Registry: x.registry, Sessions: x.environment.config.Sessions, RegistryDirectory: x.environment.config.RegistryDirectory})
	mustSQL(t, err)
	x.registry = f.concrete.Registry()
	x.initial, x.plain, x.object, x.keys = r, plain, object, keys
	config := x.environment.config
	config.Owners = f.concrete
	x.environment, err = NewPinnedDownloadAdmissionEnvironment(config)
	mustSQL(t, err)
	x.targets, err = NewPinnedSensitiveDownloadProofTargets(x.registry, x.environment)
	mustSQL(t, err)
	x.admission, err = NewDownloadAdmissionService(x.registry, x.secret, x.environment)
	mustSQL(t, err)
	resultConfig := x.results.c
	resultConfig.Registry, resultConfig.Owners = x.registry, f.concrete
	x.results, err = NewSQLDownloadResults(resultConfig)
	mustSQL(t, err)
	x.authority.c.Registry = x.registry
	x.store.testStore = &testStore{data: object, present: true, info: ObjectInfo{Version: r.Ref.ImmutableVersion, SHA256: hash(object), Size: int64(len(object))}}
	// Keep the original proof times/nonce and synthetic issuer; bind its
	// signature to the new owner-specific manifest without another OTP step.
	bound, err := BindSensitiveDownloadRequest(x.env.actor, m, x.request.Header)
	mustSQL(t, err)
	binding, err := bound.ProofBinding("issuer-transaction")
	mustSQL(t, err)
	proof := x.proof
	proof.Payload.RequestHash, proof.Payload.IdempotencyKey = binding.RequestHash, binding.IdempotencyKey
	payload, err := sec.CanonicalPayload(proof.Payload)
	mustSQL(t, err)
	proof.Signature.Value = base64.RawURLEncoding.EncodeToString(ed25519.Sign(x.signer.key, []byte(proof.Signature.ProtectedHeader+"."+base64.RawURLEncoding.EncodeToString(payload))))
	x.proof = proof
	x.setProof(t, proof)
	x.refreshReport(t)
	return f
}

func TestDTaskOwnerDownloadChainMySQL(t *testing.T) {
	raw, err := os.ReadFile(os.Getenv("D_PROVIDER_REGISTRATION_DDL"))
	mustSQL(t, err)
	if hash(raw) != os.Getenv("D_PROVIDER_REGISTRATION_DDL_SHA256") {
		t.Fatal("actual task chain capsule pin")
	}
	input, err := decodeADownloadMFAInputs(raw)
	mustSQL(t, err)
	for _, kind := range []string{"backup", "drill", "preflight", "artifact_verify"} {
		for _, mode := range []string{"http_result", "late_owner_rollback"} {
			t.Run(kind+"_"+mode, func(t *testing.T) {
				f := newDTaskOwnerDownloadChainFixture(t, input, kind)
				db := f.aDownloadMFAFixture.db
				if mode == "late_owner_rollback" {
					// Actual InnoDB trigger changes the already locked owner in
					// the admission transaction after its intent audit is written.
					_, err := db.ExecContext(f.ctx, "CREATE TRIGGER d_task_owner_late_change AFTER INSERT ON audit_logs FOR EACH ROW BEGIN IF NEW.action='system_backup.evidence_download.intent' THEN UPDATE "+f.row.table+" SET deadline_at=deadline_at+INTERVAL 1 SECOND WHERE public_id='"+f.row.id+"'; END IF; END")
					mustSQL(t, err)
					c, err := f.admission.Admit(f.request)
					if c != nil || err == nil {
						t.Fatal("late actual owner change committed admission")
					}
					f.requireRows(t, 0, 0, false)
					var until time.Time
					mustSQL(t, db.QueryRowContext(f.ctx, "SELECT deadline_at FROM "+f.row.table+" WHERE public_id=?", f.row.id).Scan(&until))
					if !until.Equal(f.initial.OwnerDeadline) {
						t.Fatal("actual owner change escaped admission rollback")
					}
					return
				}
				failures := 0
				service := Service{Registry: f.registry, Store: f.store, Keys: DownloadKeys{Authority: f.authority, Keys: f.keys}, Failure: func(context.Context, string, string) { failures++ }}
				h, err := newAdmittedDownloadHandler(f.admission, f.authority, f.results, service, Handler{Auth: f.authority, Service: service})
				mustSQL(t, err)
				w := admittedWriter()
				h.ServeHTTP(w, f.request)
				var operation string
				mustSQL(t, db.QueryRowContext(f.ctx, "SELECT public_id FROM system_backup_v2_operations").Scan(&operation))
				if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), f.plain) || w.Header().Get("X-System-Backup-Operation-Id") != operation || len(f.store.scopes) != 3 || failures != 0 {
					t.Fatal("actual task owner/HTTP/provider/result composition", kind, w.Code, len(f.store.scopes), failures)
				}
				f.requireRows(t, 1, 1, true)
			})
		}
	}
	for _, mode := range []string{"revoked_result", "result_link_rollback"} {
		t.Run(mode, func(t *testing.T) {
			f := newDTaskOwnerDownloadChainFixture(t, input, "backup")
			db := f.aDownloadMFAFixture.db
			c := f.admitted(t)
			if mode == "result_link_rollback" {
				_, err := db.ExecContext(f.ctx, "CREATE TRIGGER d_task_result_link_reject BEFORE INSERT ON system_backup_v2_download_result_receipts FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='task result link probe rejection'")
				mustSQL(t, err)
				if f.results.Finish(f.ctx, c, DownloadResultObservation{Outcome: "interrupted"}) == nil {
					t.Fatal("failed actual task result link committed")
				}
				f.requireRows(t, 1, 0, false)
				return
			}
			ctx, cancel, err := f.authority.BindCommittedDownload(f.ctx, c)
			mustSQL(t, err)
			defer cancel()
			mustSQL(t, f.authority.CheckCommittedDownload(ctx, c))
			_, err = db.ExecContext(f.ctx, "UPDATE users SET is_active=FALSE WHERE id=42")
			mustSQL(t, err)
			if f.authority.CheckCommittedDownload(ctx, c) == nil {
				t.Fatal("revoked task reader retained provider authority")
			}
			f.result(t, c)
		})
	}
	for _, mode := range []string{"existing_task_reference_lock", "empty_event_reference_lock"} {
		t.Run(mode, func(t *testing.T) {
			f := newDTaskOwnerDownloadChainFixture(t, input, "backup")
			db := f.aDownloadMFAFixture.db
			if mode == "existing_task_reference_lock" {
				_, err := db.ExecContext(f.ctx, "UPDATE system_backup_v2_preflights SET verifier_report_evidence_public_id=?,verifier_report_evidence_sha256=?", f.initial.Manifest.Identity.ID, f.initial.Manifest.Identity.ContentHash)
				mustSQL(t, err)
			}
			tx, err := db.BeginTx(f.ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			mustSQL(t, err)
			defer tx.Rollback()
			r, err := f.concrete.Preview(f.ctx, tx, f.registry.Installation, f.env.actor, f.initial.Manifest.Identity.ID)
			mustSQL(t, err)
			mustSQL(t, f.concrete.LockOwnerReferences(f.ctx, tx, r))
			mustSQL(t, f.concrete.Recheck(f.ctx, tx, f.env.actor, r))
			if mode == "existing_task_reference_lock" {
				f.observeExactBlockedWrite(t, tx, "system_backup_v2_preflights", "UPDATE system_backup_v2_preflights SET verifier_report_evidence_public_id=NULL,verifier_report_evidence_sha256=NULL")
			} else {
				f.observeExactBlockedWrite(t, tx, "system_backup_v2_events", `INSERT INTO system_backup_v2_events(origin_installation_id,target_type,target_public_id,event_type,level,message,details_present,detail_evidence_public_id) VALUES(?,'backup',?,'evidence_changed','info','isolated task owner reference probe',TRUE,?)`, f.registry.Installation, f.row.id, f.initial.Manifest.Identity.ID)
			}
			f.requireRows(t, 0, 0, false)
		})
	}
	t.Log("PASS actual SQL task owner download chain cases=12 owner_adapter=SQLTaskDownloadOwners provider_transport=synthetic production_approval=no")
}

func (f *dTaskOwnerDownloadChainFixture) observeExactBlockedWrite(t *testing.T, hold *sql.Tx, table, query string, args ...any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.ctx, 8*time.Second)
	defer cancel()
	var holderID, writerID int64
	mustSQL(t, hold.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&holderID))
	peer, err := f.aDownloadMFAFixture.db.Conn(ctx)
	mustSQL(t, err)
	defer peer.Close()
	mustSQL(t, peer.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&writerID))
	writer, err := peer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	mustSQL(t, err)
	defer writer.Rollback()
	done := make(chan error, 1)
	go func() {
		_, e := writer.ExecContext(ctx, query, args...)
		if e == nil {
			e = writer.Rollback()
		}
		done <- e
	}()
	drained := false
	defer func() {
		hold.Rollback()
		cancel()
		if !drained {
			<-done
		}
	}()
	observed := false
	limit := time.Now().Add(3 * time.Second)
	for time.Now().Before(limit) {
		var count int
		mustSQL(t, f.aDownloadMFAFixture.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM performance_schema.data_lock_waits w
JOIN performance_schema.data_locks r ON r.ENGINE=w.ENGINE AND r.ENGINE_LOCK_ID=w.REQUESTING_ENGINE_LOCK_ID
JOIN performance_schema.data_locks b ON b.ENGINE=w.ENGINE AND b.ENGINE_LOCK_ID=w.BLOCKING_ENGINE_LOCK_ID
JOIN performance_schema.threads p ON p.THREAD_ID=r.THREAD_ID
JOIN performance_schema.threads h ON h.THREAD_ID=b.THREAD_ID
WHERE r.OBJECT_SCHEMA=? AND r.OBJECT_NAME=? AND p.PROCESSLIST_ID=? AND h.PROCESSLIST_ID=?`, f.identity.Database, table, writerID, holderID).Scan(&count))
		if count > 0 {
			observed = true
			break
		}
		select {
		case e := <-done:
			drained = true
			t.Fatal("exact competing writer completed before owner/ref release", e)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !observed {
		t.Fatal("exact owner/ref InnoDB wait was not observed")
	}
	mustSQL(t, hold.Rollback())
	err = <-done
	drained = true
	mustSQL(t, err)
	t.Log(fmt.Sprintf("OBSERVED exact task reference lock table=%s holder=%d writer=%d writer_rolled_back=yes", table, holderID, writerID))
}
