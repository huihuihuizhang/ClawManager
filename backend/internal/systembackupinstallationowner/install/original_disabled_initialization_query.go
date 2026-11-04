package install

import (
	"bytes"
	"context"
	"database/sql"
	"strconv"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
	pd "clawreef/internal/systembackupproducer"
)

// QueryOriginalDisabledUnverified authenticates afresh, then ONLY reads this
// deterministic original operation. No Sources are reconstructed and no send,
// missing row, absent COMMIT or expired health can be converted into success.
// This remains usable without the original live actors after a lost reply.
func (i *Installer) QueryOriginalDisabledUnverified(ctx context.Context, password []byte, enrollment EnrollmentPin, files RequestFiles) (OriginalDisabledInitializationReceipt, error) {
	var zero OriginalDisabledInitializationReceipt
	if i == nil || ctx == nil || ctx.Err() != nil {
		return zero, ErrInstall
	}
	op, e := i.authenticate(ctx, password)
	if e != nil || op.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	r, e := readRequest(i, files)
	if e != nil {
		return zero, ErrInstall
	}
	defer r.observer.Close()
	plan, e := r.config.DisabledInitializationPlan(r.grant)
	if e != nil {
		return zero, ErrInstall
	}
	tx, e := i.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if e != nil {
		return zero, ErrCommitUnknown
	}
	defer tx.Rollback()
	if originalDisabledSQLSession(ctx, tx) != nil {
		return zero, ErrInstall
	}
	// Locking reads settle the original initialization COMMIT before inspecting
	// its immutable receipt. The same global prefix precedes admin/head locks.
	if originalDisabledConfigPrefix(ctx, tx, r.grant.InstallationID, false) != nil {
		return zero, ErrCommitUnknown
	}
	now, e := op.lockAdmin(ctx, tx)
	if e != nil {
		return zero, ErrInstall
	}
	head, e := op.current(ctx, tx, false)
	if e != nil || !originalDisabledAuthority(r, head, now) {
		return zero, ErrInstall
	}
	requestSHA, operation, e := originalDisabledIdentity(i, enrollment, r, head)
	if e != nil {
		return zero, ErrInstall
	}
	record, e := originalDisabledReadRecord(ctx, tx, requestSHA, false)
	if e != nil {
		return zero, ErrCommitUnknown
	}
	if record.Operation != operation || record.RequestSHA256 != requestSHA || record.InstallationID != r.grant.InstallationID || record.ConfigSHA256 != r.config.SHA256() || record.Head != head.cas || string(record.Domain.Scope.ServerUUID) != i.plan.Target.ServerUUID || string(record.Domain.Scope.Database) != i.plan.Target.Database {
		return zero, ErrCommitUnknown
	}
	var domain pd.DomainRecord
	found, e := pd.ReadOriginalSharedRecord(ctx, tx, record.Domain.Scope, pd.RecordKey{}, &domain)
	if e != nil || !found || originalObjectSHA(domain) != originalObjectSHA(record.Domain) {
		return zero, ErrCommitUnknown
	}
	// Receipt is locked AFTER domain, BEFORE the shared KEK fence/index.
	again, e := originalDisabledReadRecord(ctx, tx, requestSHA, true)
	if e != nil || originalObjectSHA(again) != originalObjectSHA(record) {
		return zero, ErrCommitUnknown
	}
	var evidenceRowID uint64
	if tx.QueryRowContext(ctx, "SELECT id FROM system_backup_v2_evidence WHERE public_id=? FOR SHARE", originalDisabledEvidenceID(requestSHA)).Scan(&evidenceRowID) != nil || evidenceRowID == 0 {
		return zero, ErrCommitUnknown
	}
	if originalDisabledOneConfig(ctx, tx, r.grant, plan) != nil || originalDisabledReadOperation(ctx, tx, r.grant.UserID, r.grant.IdempotencyKey, record) != nil {
		return zero, ErrCommitUnknown
	}
	snapshot, e := (reg.SQLStore{}).ReadExistingSnapshotInView(ctx, tx, record.InstallationID)
	if e != nil || snapshot.Epoch != record.Epoch || originalDisabledSnapshotSHA(snapshot) != record.SnapshotSHA256 || originalDisabledNoAdmission(ctx, tx, record.InstallationID) != nil {
		return zero, ErrCommitUnknown
	}
	if r.recheck(i) != nil {
		return zero, ErrInstall
	}
	last, e := i.database(ctx, tx, minTime(op.until, minTime(r.end, minTime(head.head.Until, head.record.Until))))
	if e != nil || last.Before(now) || !originalDisabledAuthority(r, head, last) || !last.Before(record.RetainUntil) {
		return zero, ErrInstall
	}
	if tx.Rollback() != nil {
		return zero, ErrCommitUnknown
	}
	result := originalDisabledReceipt(record)
	result.Result.Replayed = true
	raw, e := canonical(record)
	if e != nil {
		return zero, ErrCommitUnknown
	}
	result.Evidence = OriginalDisabledInitializationEvidence{PublicID: originalDisabledEvidenceID(requestSHA), ContentSHA256: hash(raw), RowID: evidenceRowID, ContentSizeBytes: uint64(len(raw)), RowVersion: 1, ChunkCount: 0, InlineJSON: raw}
	return result, nil
}

func originalDisabledReadRecord(ctx context.Context, tx *sql.Tx, requestSHA string, lock bool) (originalDisabledInitializationRecord, error) {
	var record originalDisabledInitializationRecord
	if !digestPattern.MatchString(requestSHA) {
		return record, ErrInstall
	}
	suffix := ""
	if lock {
		suffix = " FOR SHARE"
	}
	var id, size, version, chunks uint64
	var raw []byte
	var checksum string
	var expires, created, updated time.Time
	err := tx.QueryRowContext(ctx, `SELECT id,inline_payload,content_checksum,content_size_bytes,expires_at,created_at,updated_at,row_version,chunk_count FROM system_backup_v2_evidence WHERE public_id=? AND owner_target_type='system' AND evidence_type='diagnostic' AND storage_state='inline' AND media_type='application/json' AND encryption='none' AND redaction_classification='internal' AND observed_health='unknown' AND evidence_failure_code='none' AND schema_version='system-backup-evidence.v1' AND storage_provider_role IS NULL AND storage_identity_hash IS NULL AND storage_ref_version IS NULL AND storage_relative_key IS NULL AND storage_relative_key_hash IS NULL AND storage_immutable_version IS NULL AND kek_identity_hash IS NULL AND kek_version IS NULL AND claim_owner IS NULL AND claim_expires_at IS NULL`+suffix, originalDisabledEvidenceID(requestSHA)).Scan(&id, &raw, &checksum, &size, &expires, &created, &updated, &version, &chunks)
	if err != nil || id == 0 || len(raw) == 0 || len(raw) > 8192 || uint64(len(raw)) != size || hash(raw) != checksum || version != 1 || chunks != 0 || decodeExact(raw, &record) != nil || !originalDisabledRecordValid(record) || record.RequestSHA256 != requestSHA || !expires.Equal(record.RetainUntil) || !created.Equal(record.FinishedAt) || !updated.Equal(record.FinishedAt) {
		return originalDisabledInitializationRecord{}, ErrCommitUnknown
	}
	// The owner public ID is checked independently, not inferred from payload.
	var owner string
	if tx.QueryRowContext(ctx, "SELECT owner_target_public_id FROM system_backup_v2_evidence WHERE id=?"+suffix, id).Scan(&owner) != nil || owner != record.InstallationID {
		return originalDisabledInitializationRecord{}, ErrCommitUnknown
	}
	if lock {
		rows, e := tx.QueryContext(ctx, "SELECT chunk_index FROM system_backup_v2_evidence_chunks WHERE evidence_id=? ORDER BY chunk_index FOR SHARE", id)
		if e != nil {
			return originalDisabledInitializationRecord{}, ErrCommitUnknown
		}
		found := rows.Next()
		e = rows.Err()
		extra := rows.NextResultSet()
		closed := rows.Close()
		if found || e != nil || extra || closed != nil {
			return originalDisabledInitializationRecord{}, ErrCommitUnknown
		}
	}
	return record, nil
}

func originalDisabledReadOperation(ctx context.Context, tx *sql.Tx, userID int64, key string, r originalDisabledInitializationRecord) error {
	raw, e := canonical(r)
	if e != nil {
		return ErrCommitUnknown
	}
	var id, evidence uint64
	var evidenceSHA string
	err := tx.QueryRowContext(ctx, `SELECT id,redacted_response_evidence_id,redacted_response_sha256 FROM system_backup_v2_operations WHERE public_id=? AND origin_installation_id=? AND operation_type='config_update' AND target_type='system' AND target_public_id=? AND actor_type='admin' AND actor_id=? AND endpoint=? AND idempotency_key=? AND request_hash=? AND status='succeeded' AND result_config_version=1 AND http_status=201 AND row_version=1 AND schema_version='system-backup-operation.v1' AND retryable=FALSE AND failure_category='none' AND failure_message IS NULL AND result_resource_public_id IS NULL AND external_action_public_ids_canonical_json=? AND external_action_public_ids_size_bytes=2 AND external_action_public_ids_sha256=? AND started_at=? AND finished_at=? AND created_at=? AND updated_at=? AND deadline_at=? FOR SHARE`, r.Operation, r.InstallationID, r.InstallationID, strconv.FormatInt(userID, 10), OriginalDisabledInitializationEndpoint, key, r.RequestSHA256, []byte("[]"), hash([]byte("[]")), r.StartedAt, r.FinishedAt, r.StartedAt, r.FinishedAt, r.DeadlineAt).Scan(&id, &evidence, &evidenceSHA)
	if err != nil || id == 0 || evidence == 0 || evidenceSHA != hash(raw) {
		return ErrCommitUnknown
	}
	var publicID string
	if tx.QueryRowContext(ctx, "SELECT public_id FROM system_backup_v2_evidence WHERE id=? FOR SHARE", evidence).Scan(&publicID) != nil || publicID != originalDisabledEvidenceID(r.RequestSHA256) {
		return ErrCommitUnknown
	}
	for _, phase := range []string{"intent", "result"} {
		rows, e := tx.QueryContext(ctx, "SELECT details FROM audit_logs WHERE user_id=? AND action=? AND resource_type='system_backup' AND details=? FOR SHARE", userID, "system_backup.disabled_unverified_initialize."+phase, string(raw))
		if e != nil {
			return ErrCommitUnknown
		}
		var got []byte
		if !rows.Next() || rows.Scan(&got) != nil || !bytes.Equal(got, raw) || rows.Next() || rows.Err() != nil || rows.NextResultSet() || rows.Close() != nil {
			rows.Close()
			return ErrCommitUnknown
		}
	}
	return nil
}
