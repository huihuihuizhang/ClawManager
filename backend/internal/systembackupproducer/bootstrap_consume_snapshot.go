package systembackupproducer

import (
	"context"
	"database/sql"
	"reflect"
	"time"
)

// These queries have fixed identifiers and only already-held keys/ranges. The
// full rows preserve manifest/locator/chunk and flattened config bytes, even
// fields which are not part of the small ResultEvidence projection. Snapshots
// carry no permission and never appear in the public result or errors.
const bootstrapEvidenceSnapshotSQL = "SELECT * FROM system_backup_v2_evidence WHERE public_id=? FOR UPDATE"
const bootstrapChunksSnapshotSQL = "SELECT * FROM system_backup_v2_evidence_chunks WHERE evidence_id=? ORDER BY chunk_index FOR UPDATE"
const bootstrapConfigSnapshotSQL = "SELECT * FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=1 FOR UPDATE"
const bootstrapInstallationSnapshotSQL = "SELECT * FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR UPDATE"
const bootstrapOperationSnapshotSQL = "SELECT * FROM system_backup_v2_operations WHERE public_id=? FOR UPDATE"
const bootstrapAuditSnapshotSQL = "SELECT * FROM audit_logs WHERE id=? FOR UPDATE"

type bootstrapSQLSnapshot struct {
	query   string
	args    []any
	columns []string
	rows    [][]any
}

func readBootstrapSnapshot(ctx context.Context, read ReadSQL, query string, args []any, limit int) (bootstrapSQLSnapshot, error) {
	s := bootstrapSQLSnapshot{query: query, args: append([]any(nil), args...)}
	rows, err := read.QueryContext(ctx, query, args...)
	if err != nil {
		return s, ErrUnavailable
	}
	defer rows.Close()
	s.columns, err = rows.Columns()
	if err != nil || len(s.columns) == 0 || len(s.columns) > 256 {
		return s, ErrInvalid
	}
	seen := map[string]bool{}
	for _, name := range s.columns {
		if name == "" || seen[name] {
			return s, ErrInvalid
		}
		seen[name] = true
	}
	bytes := 0
	for rows.Next() {
		if len(s.rows) >= limit {
			return s, ErrInvalid
		}
		values := make([]any, len(s.columns))
		dest := make([]any, len(values))
		for i := range values {
			dest[i] = &values[i]
		}
		if rows.Scan(dest...) != nil {
			return s, ErrUnavailable
		}
		for i, value := range values {
			switch v := value.(type) {
			case []byte:
				bytes += len(v)
				values[i] = append([]byte(nil), v...)
			case string:
				bytes += len(v)
			case nil, int64, uint64, float64, bool, time.Time:
			default:
				return s, ErrInvalid
			}
			if bytes > 2*1024*1024 {
				return s, ErrInvalid
			}
		}
		s.rows = append(s.rows, values)
	}
	if rows.Err() != nil || rows.Close() != nil {
		return s, ErrUnavailable
	}
	return s, nil
}

func (s bootstrapSQLSnapshot) value(name string) any {
	if len(s.rows) != 1 {
		return nil
	}
	for i, column := range s.columns {
		if column == name {
			return s.rows[0][i]
		}
	}
	return nil
}

func (s bootstrapSQLSnapshot) hasColumns(names ...string) bool {
	for _, name := range names {
		found := false
		for _, column := range s.columns {
			if column == name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func bootstrapSQLText(actual any, expected string) bool {
	var value sql.NullString
	return value.Scan(actual) == nil && value.Valid && value.String == expected
}
func bootstrapSQLCounter(actual any, expected Counter) bool {
	var value sql.NullInt64
	want, err := expected.SQLInt64()
	return err == nil && value.Scan(actual) == nil && value.Valid && value.Int64 == want
}
func bootstrapSQLTimestamp(actual any, expected Timestamp) bool {
	var value sql.NullTime
	want, err := expected.Time()
	return err == nil && value.Scan(actual) == nil && value.Valid && validDBTime(value.Time) && value.Time.Equal(want)
}

func (p *bootstrapConsumptionPolicy) captureEvidence(ctx context.Context, f ResultFacts) error {
	r, e := f.Receipt.Request, *f.Evidence
	s, err := readBootstrapSnapshot(ctx, p.tx, bootstrapEvidenceSnapshotSQL, []any{string(r.Evidence.EvidenceID)}, 1)
	if err != nil {
		return err
	}
	if len(s.rows) != 1 {
		return ErrConflict
	}
	if !s.hasColumns("claim_owner", "claim_expires_at", "inline_payload", "chunk_list_root", "envelope_hash", "media_type", "created_at") {
		return ErrConflict
	}
	wants := map[string]string{"schema_version": "system-backup-evidence.v1", "public_id": string(r.Evidence.EvidenceID), "owner_target_type": r.Evidence.OwnerType, "owner_target_public_id": string(r.Evidence.OwnerID), "evidence_type": r.Evidence.EvidenceType, "storage_state": "ready", "evidence_failure_code": "none", "storage_provider_role": "evidence", "storage_identity_hash": string(r.Evidence.StoreIdentityHash), "storage_ref_version": string(r.Evidence.StoreRefVersion), "storage_relative_key_hash": string(r.Evidence.RelativeKeyHash), "storage_relative_key": string(f.History.RelativeKey), "content_checksum": string(r.Evidence.ContentHash), "object_checksum": string(r.Evidence.ObjectHash), "redaction_classification": r.Evidence.Classification, "encryption": "envelope_v1", "envelope_framing_version": "system-backup-evidence-envelope.v1", "kek_identity_hash": string(r.Evidence.KEKIdentityHash), "kek_version": string(r.Evidence.KEKVersion)}
	for key, value := range wants {
		if !bootstrapSQLText(s.value(key), value) {
			return ErrConflict
		}
	}
	if r.Evidence.ImmutableVersion == nil || !bootstrapSQLText(s.value("storage_immutable_version"), string(*r.Evidence.ImmutableVersion)) || !bootstrapSQLCounter(s.value("row_version"), e.RowVersion) || !bootstrapSQLCounter(s.value("content_size_bytes"), r.Evidence.ContentBytes) || !bootstrapSQLCounter(s.value("object_size_bytes"), r.Evidence.ObjectBytes) || !bootstrapSQLTimestamp(s.value("expires_at"), e.RetentionExpiresAt) || !bootstrapSQLTimestamp(s.value("protected_until"), e.ProtectedUntil) || s.value("claim_owner") != nil || s.value("claim_expires_at") != nil || s.value("inline_payload") != nil {
		return ErrConflict
	}
	var id, count, size sql.NullInt64
	if id.Scan(s.value("id")) != nil || !id.Valid || id.Int64 <= 0 || count.Scan(s.value("chunk_count")) != nil || !count.Valid || count.Int64 < 1 || count.Int64 > 1024 || size.Scan(s.value("plaintext_chunk_size_bytes")) != nil || !size.Valid || size.Int64 != 1048576 {
		return ErrConflict
	}
	chunks, err := readBootstrapSnapshot(ctx, p.tx, bootstrapChunksSnapshotSQL, []any{id.Int64}, 1024)
	if err != nil {
		return err
	}
	if int64(len(chunks.rows)) != count.Int64 {
		return ErrConflict
	}
	if !chunks.hasColumns("chunk_index", "plaintext_offset", "plaintext_length", "plaintext_sha256", "object_frame_offset", "object_frame_length", "ciphertext_sha256", "gcm_nonce", "gcm_tag") {
		return ErrConflict
	}
	for i, row := range chunks.rows {
		var index sql.NullInt64
		for j, column := range chunks.columns {
			if column == "chunk_index" && (index.Scan(row[j]) != nil || !index.Valid || index.Int64 != int64(i)) {
				return ErrConflict
			}
		}
	}
	p.snapshots = append(p.snapshots, s, chunks)
	return nil
}

func (p *bootstrapConsumptionPolicy) captureBootstrapRows(ctx context.Context) error {
	for _, query := range []string{bootstrapConfigSnapshotSQL, bootstrapInstallationSnapshotSQL} {
		s, err := readBootstrapSnapshot(ctx, p.tx, query, []any{string(p.request.Scope.Installation)}, 1)
		if err != nil {
			return err
		}
		if len(s.rows) != 1 {
			return ErrConflict
		}
		p.snapshots = append(p.snapshots, s)
	}
	op, err := readBootstrapSnapshot(ctx, p.tx, bootstrapOperationSnapshotSQL, []any{p.operationID()}, 1)
	if err != nil {
		return err
	}
	if len(op.rows) != 1 {
		return ErrConflict
	}
	for key, value := range map[string]string{"public_id": p.operationID(), "origin_installation_id": string(p.request.Scope.Installation), "operation_type": "config_update", "target_type": "system", "target_public_id": string(p.request.Scope.Installation), "actor_type": "admin", "actor_id": string(p.request.ActorID), "endpoint": p.request.Endpoint, "idempotency_key": p.request.IdempotencyKey, "request_hash": string(p.hash), "status": "succeeded", "external_action_public_ids_canonical_json": "[]", "external_action_public_ids_sha256": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"} {
		if !bootstrapSQLText(op.value(key), value) {
			return ErrConflict
		}
	}
	for key, value := range map[string]Counter{"result_config_version": "1", "http_status": "201", "external_action_public_ids_size_bytes": "2"} {
		if !bootstrapSQLCounter(op.value(key), value) {
			return ErrConflict
		}
	}
	p.snapshots = append(p.snapshots, op)
	if !p.facts.Replayed {
		for _, id := range []int64{p.facts.Write.IntentAuditID, p.facts.Write.ResultAuditID} {
			audit, err := readBootstrapSnapshot(ctx, p.tx, bootstrapAuditSnapshotSQL, []any{id}, 1)
			if err != nil {
				return err
			}
			if len(audit.rows) != 1 {
				return ErrConflict
			}
			p.snapshots = append(p.snapshots, audit)
		}
	}
	return nil
}

func (p *bootstrapConsumptionPolicy) verifySnapshots(ctx context.Context, read ReadSQL) error {
	for _, expected := range p.snapshots {
		actual, err := readBootstrapSnapshot(ctx, read, expected.query, expected.args, len(expected.rows)+1)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(actual.columns, expected.columns) || len(actual.rows) != len(expected.rows) {
			return ErrConflict
		}
		for i, row := range actual.rows {
			for j, value := range row {
				if !bootstrapSnapshotValueEqual(expected.rows[i][j], value) {
					return ErrConflict
				}
			}
		}
	}
	return nil
}

func bootstrapSnapshotValueEqual(expected, actual any) bool {
	if stamp, ok := expected.(time.Time); ok {
		value, ok := actual.(time.Time)
		return ok && validDBTime(value) && stamp.Equal(value)
	}
	return reflect.DeepEqual(expected, actual)
}
