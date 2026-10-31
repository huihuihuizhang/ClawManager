package systembackupcontrolevidence

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// Fixed projections deliberately omit actor/user IDs, IPs, free-form messages,
// details, config/candidate blobs, credentials, tokens and provider responses.
// Individual source identities are one-way hashes and never enter the sidecar.
func ProjectionColumns() map[string][]string {
	return map[string][]string{
		"task_terminal":       {"kind", "public_id_sha256", "status", "failure_category", "row_version"},
		"operation_terminal":  {"operation_type", "public_id_sha256", "status", "failure_category", "row_version"},
		"event":               {"event_type", "level", "task_status", "target_type", "target_public_id_sha256"},
		"audit":               {"action_sha256", "resource_type_sha256"},
		"promotion":           {"public_id_sha256", "record_status", "matrix_key", "row_version"},
		"dependency_health":   {"dependency_kind", "identity_hash", "observed_health", "health_reason", "row_version"},
		"provider_capability": {"provider_role", "provider_identity_hash", "capability_code", "status", "capability_reason_code", "row_version"},
		"alert_state":         {"rule_key_sha256", "alert_state", "consecutive_anomaly_count", "row_version"},
		"installation_state":  {"active_config_version", "last_effective_enabled", "monitoring_armed", "monitoring_armed_reason", "row_version"},
	}
}

type snapshotQuery struct {
	query string
	args  []any
}

func collectionFailure(group, stage string) error {
	return fmt.Errorf("control evidence %s/%s: %w", group, stage, ErrInvalid)
}

func snapshotQueries(expected Expected, start, end time.Time) map[string]snapshotQuery {
	installation, version := expected.Installation, expected.ConfigSHA256
	window := func(installation string) []any { return []any{installation, start, end} }
	taskSQL := ""
	taskArgs := []any{}
	for i, table := range []string{"system_backup_v2_backups", "system_backup_v2_restore_drills", "system_backup_v2_preflights", "system_backup_v2_artifact_verifications"} {
		if i > 0 {
			taskSQL += " UNION ALL "
		}
		taskSQL += `SELECT id,finished_at AS recorded_at,JSON_OBJECT('kind',task_type,'public_id_sha256',SHA2(public_id,256),'status',status,'failure_category',failure_category,'row_version',row_version) AS projected FROM ` + table + ` WHERE origin_installation_id=? AND status IN ('succeeded','failed','canceled') AND finished_at>=? AND finished_at<=?`
		taskArgs = append(taskArgs, window(installation)...)
	}
	taskSQL = "SELECT id,recorded_at,projected FROM (" + taskSQL + ") original_terminal_rows ORDER BY recorded_at,projected,id LIMIT 641"
	return map[string]snapshotQuery{
		"task_terminal":       {taskSQL, taskArgs},
		"operation_terminal":  {`SELECT id,finished_at,JSON_OBJECT('operation_type',operation_type,'public_id_sha256',SHA2(public_id,256),'status',status,'failure_category',failure_category,'row_version',row_version) FROM system_backup_v2_operations WHERE origin_installation_id=? AND status IN ('succeeded','failed','canceled') AND finished_at>=? AND finished_at<=? ORDER BY finished_at,id LIMIT 641`, window(installation)},
		"event":               {`SELECT id,created_at,JSON_OBJECT('event_type',event_type,'level',level,'task_status',task_status,'target_type',target_type,'target_public_id_sha256',SHA2(target_public_id,256)) FROM system_backup_v2_events WHERE origin_installation_id=? AND created_at>=? AND created_at<=? ORDER BY created_at,id LIMIT 641`, window(installation)},
		"audit":               {`SELECT id,created_at,JSON_OBJECT('action_sha256',SHA2(action,256),'resource_type_sha256',SHA2(resource_type,256)) FROM audit_logs WHERE (JSON_UNQUOTE(JSON_EXTRACT(details,'$.origin_installation_id'))=? OR JSON_UNQUOTE(JSON_EXTRACT(details,'$.installation_id'))=?) AND action LIKE 'system_backup.%' AND created_at>=? AND created_at<=? ORDER BY created_at,id LIMIT 641`, []any{installation, installation, start, end}},
		"promotion":           {`SELECT id,updated_at,JSON_OBJECT('public_id_sha256',SHA2(public_id,256),'record_status',record_status,'matrix_key',matrix_key,'row_version',row_version) FROM system_backup_v2_promotions WHERE origin_installation_id=? AND updated_at>=? AND updated_at<=? ORDER BY updated_at,id LIMIT 641`, window(installation)},
		"dependency_health":   {`SELECT h.id,h.checked_at,JSON_OBJECT('dependency_kind',h.dependency_kind,'identity_hash',h.identity_hash,'observed_health',h.observed_health,'health_reason',h.health_reason,'row_version',h.row_version) FROM system_backup_v2_dependency_health h WHERE ((h.owner_target_type='system' AND h.owner_target_public_id=?) OR (h.owner_target_type='backup' AND EXISTS(SELECT 1 FROM system_backup_v2_backups b WHERE b.public_id=h.owner_target_public_id AND b.origin_installation_id=?)) OR (h.owner_target_type='promotion' AND EXISTS(SELECT 1 FROM system_backup_v2_promotions p WHERE p.public_id=h.owner_target_public_id AND p.origin_installation_id=?))) AND h.checked_at>=? AND h.checked_at<=? ORDER BY h.checked_at,h.id LIMIT 641`, []any{installation, installation, installation, start, end}},
		"provider_capability": {`SELECT p.id,p.checked_at,JSON_OBJECT('provider_role',p.provider_role,'provider_identity_hash',p.provider_identity_hash,'capability_code',p.capability_code,'status',p.status,'capability_reason_code',p.capability_reason_code,'row_version',p.row_version) FROM system_backup_v2_provider_capabilities p WHERE EXISTS(SELECT 1 FROM system_backup_v2_configs cfg WHERE cfg.origin_installation_id=? AND cfg.config_sha256=? AND ((p.provider_role='artifact' AND p.provider_identity_hash=cfg.artifact_write_identity_hash AND p.provider_ref_version=cfg.artifact_write_ref_version) OR (p.provider_role='catalog' AND p.provider_identity_hash=cfg.catalog_append_identity_hash AND p.provider_ref_version=cfg.catalog_append_ref_version) OR (p.provider_role='evidence' AND p.provider_identity_hash=cfg.evidence_store_identity_hash AND p.provider_ref_version=cfg.evidence_store_ref_version))) AND p.checked_at>=? AND p.checked_at<=? ORDER BY p.checked_at,p.id LIMIT 641`, []any{installation, version, start, end}},
		"alert_state":         {`SELECT id,updated_at,JSON_OBJECT('rule_key_sha256',SHA2(rule_key,256),'alert_state',alert_state,'consecutive_anomaly_count',consecutive_anomaly_count,'row_version',row_version) FROM system_backup_v2_alert_states WHERE origin_installation_id=? AND updated_at>=? AND updated_at<=? ORDER BY updated_at,id LIMIT 641`, window(installation)},
		"installation_state":  {`SELECT id,CAST(? AS DATETIME(6)),JSON_OBJECT('active_config_version',active_config_version,'last_effective_enabled',last_effective_enabled,'monitoring_armed',monitoring_armed,'monitoring_armed_reason',monitoring_armed_reason,'row_version',row_version) FROM system_backup_v2_installation_state WHERE origin_installation_id=? ORDER BY id LIMIT 641`, []any{end, installation}},
	}
}

// CollectSQL belongs inside the caller's concrete original live capture
// guard/RR transaction. It neither authorizes nor commits. Missing tables,
// unexpected projections, over-budget groups or inconsistent clocks fail;
// nothing is silently truncated, rediscovered or treated as empty on error.
func CollectSQL(ctx context.Context, tx *sql.Tx, expected Expected, windowSeconds uint32, excluded []string, source RegisteredEvidence) (Snapshot, error) {
	if ctx == nil || ctx.Err() != nil || tx == nil || !ValidScope(expected.Scope) || windowSeconds < 1 || windowSeconds > 86400 {
		return Snapshot{}, ErrInvalid
	}
	var end time.Time
	var installation string
	// This first NONLOCKING read establishes the same original RR view used by
	// every group. The SQL clock and original installation identity share it.
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6),origin_installation_id FROM system_backup_v2_installation_state WHERE origin_installation_id=?", expected.Installation).Scan(&end, &installation) != nil || installation != expected.Installation {
		return Snapshot{}, ErrInvalid
	}
	end = end.UTC()
	start := end.Add(-time.Duration(windowSeconds) * time.Second)
	out := Snapshot{Expected: expected, Start: start, End: end, Generated: end, ExcludedControlObjects: append([]string(nil), excluded...), SourceExclusion: source, Groups: map[string][]TimedDigest{}}
	queries, columns := snapshotQueries(expected, start, end), ProjectionColumns()
	for _, name := range groups {
		query := queries[name]
		rows, err := tx.QueryContext(ctx, query.query, query.args...)
		if err != nil {
			return Snapshot{}, collectionFailure(name, "query")
		}
		records := []TimedDigest{}
		for rows.Next() {
			var id uint64
			var at time.Time
			var raw []byte
			if rows.Scan(&id, &at, &raw) != nil || id == 0 || len(raw) > 4096 {
				rows.Close()
				return Snapshot{}, collectionFailure(name, "scan")
			}
			if len(records) >= MaxGroupRecords {
				rows.Close()
				return Snapshot{}, ErrCapacity
			}
			var fields map[string]json.RawMessage
			if json.Unmarshal(raw, &fields) != nil || len(fields) != len(columns[name]) {
				rows.Close()
				return Snapshot{}, collectionFailure(name, "projection")
			}
			for _, column := range columns[name] {
				if _, ok := fields[column]; !ok {
					rows.Close()
					return Snapshot{}, collectionFailure(name, "column")
				}
			}
			// SQL JSON whitespace is normalized once; no free-form body is retained.
			projected, err := Canonical(fields)
			clear(raw)
			if err != nil {
				rows.Close()
				return Snapshot{}, collectionFailure(name, "canonical")
			}
			canonical, err := Canonical(struct {
				Group      string          `json:"group"`
				At         time.Time       `json:"recorded_at"`
				Projection json.RawMessage `json:"projection"`
			}{name, at.UTC(), projected})
			clear(projected)
			if err != nil || at.Before(start) || at.After(end) {
				rows.Close()
				return Snapshot{}, collectionFailure(name, "window")
			}
			records = append(records, TimedDigest{At: at.UTC(), SHA256: SHA256(canonical)})
			clear(canonical)
		}
		readErr := rows.Err()
		closeErr := rows.Close()
		if readErr != nil || closeErr != nil {
			return Snapshot{}, collectionFailure(name, "end")
		}
		out.Groups[name] = records
	}
	if ctx.Err() != nil {
		return Snapshot{}, ErrInvalid
	}
	return out, nil
}

func LoadRegisteredSQL(ctx context.Context, tx *sql.Tx, scope Scope, ref EvidenceRef) (RegisteredEvidence, error) {
	var out RegisteredEvidence
	var payload []byte
	var size int
	var checksum string
	if tx == nil || !ValidScope(scope) || !validRef(ref) {
		return out, ErrInvalid
	}
	err := tx.QueryRowContext(ctx, `SELECT public_id,owner_target_type,owner_target_public_id,evidence_type,inline_payload,content_checksum,content_size_bytes FROM system_backup_v2_evidence WHERE public_id=? AND evidence_type='verifier_report' AND storage_state='inline' AND observed_health='healthy' AND encryption='none' AND evidence_failure_code='none' AND expires_at>UTC_TIMESTAMP(6) AND ((owner_target_type='backup' AND owner_target_public_id=?) OR (owner_target_type='system' AND owner_target_public_id=?)) FOR SHARE`, ref.PublicID, scope.Backup, scope.Installation).Scan(&out.PublicID, &out.OwnerType, &out.OwnerID, &out.Type, &payload, &checksum, &size)
	if err != nil || size < 2 || size > 8192 || len(payload) != size || checksum != ref.SHA256 || SHA256(payload) != checksum {
		return RegisteredEvidence{}, ErrInvalid
	}
	canonical, err := Canonical(json.RawMessage(payload))
	if err != nil || !bytes.Equal(canonical, payload) {
		return RegisteredEvidence{}, ErrInvalid
	}
	out.SHA256 = checksum
	out.Payload = bytes.Clone(payload)
	return out, nil
}

// RegisterSQL joins the SAME authorized caller transaction. Exact duplicates
// are read back; neither expiry nor body can be refreshed on retry. Prepared
// bytes must not escape on rollback/unknown commit.
func RegisterSQL(ctx context.Context, tx *sql.Tx, scope Scope, entries []RegisteredEvidence, until time.Time) error {
	if tx == nil || !ValidScope(scope) || len(entries) == 0 || len(entries) > 256 || !time.Now().Before(until) {
		return ErrInvalid
	}
	for _, entry := range entries {
		existing, err := LoadRegisteredSQL(ctx, tx, scope, reference(entry))
		if err == nil {
			if existing.OwnerType != entry.OwnerType || existing.OwnerID != entry.OwnerID || existing.Type != entry.Type || !bytes.Equal(existing.Payload, entry.Payload) {
				return ErrInvalid
			}
			continue
		}
		var count int
		if tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_evidence WHERE public_id=?", entry.PublicID).Scan(&count) != nil || count != 0 {
			return ErrInvalid
		}
		if entry.OwnerType != "backup" || entry.OwnerID != scope.Backup || entry.Type != "verifier_report" || !validRef(reference(entry)) || len(entry.Payload) > 8192 || SHA256(entry.Payload) != entry.SHA256 {
			return ErrInvalid
		}
		// origin_installation_id is added by original 117; both the original 096
		// baseline and fully migrated deployments retain the same owner binding.
		var hasOrigin int
		if tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='system_backup_v2_evidence' AND COLUMN_NAME='origin_installation_id'").Scan(&hasOrigin) != nil {
			return ErrInvalid
		}
		columns, values := "", ""
		args := []any{}
		if hasOrigin == 1 {
			columns = "origin_installation_id,"
			values = "?,"
			args = append(args, scope.Installation)
		}
		args = append(args, entry.PublicID, scope.Backup, []byte(entry.Payload), entry.SHA256, len(entry.Payload), until.UTC().Truncate(time.Microsecond))
		_, err = tx.ExecContext(ctx, "INSERT INTO system_backup_v2_evidence("+columns+"public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,inline_payload,content_checksum,content_size_bytes,media_type,encryption,redaction_classification,observed_health,expires_at) VALUES("+values+"?,'backup',?,'verifier_report','inline',?,?,?,'application/json','none','internal','healthy',?)", args...)
		if err != nil {
			return ErrInvalid
		}
		actual, err := LoadRegisteredSQL(ctx, tx, scope, reference(entry))
		if err != nil || !bytes.Equal(actual.Payload, entry.Payload) {
			return ErrInvalid
		}
	}
	return nil
}
