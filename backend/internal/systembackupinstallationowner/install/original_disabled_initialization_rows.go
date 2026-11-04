package install

import (
	"context"
	"database/sql"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

type originalDisabledMetadataReservation struct {
	ctx                   context.Context
	tx                    *sql.Tx
	report                sec.CapacityReport
	capacity, cost, floor int64
	sample                time.Time
}

func originalDisabledReserveMetadata(ctx context.Context, tx *sql.Tx, report sec.CapacityReport, capacity, cost int64) (*originalDisabledMetadataReservation, error) {
	if capacity <= 0 || cost <= 0 || cost > 1048576 || report.AllocatedBytes < 0 || report.AvailableBytes < 0 || report.AllocatedBytes > capacity || cost > capacity {
		return nil, ErrInstall
	}
	reserve := (capacity + 19) / 20
	if reserve < 67108864 {
		reserve = 67108864
	}
	if report.AvailableBytes < capacity+reserve+cost {
		return nil, ErrInstall
	}
	if _, e := tx.ExecContext(ctx, "INSERT IGNORE INTO system_backup_v2_metadata_reservations(id,sample_at,reserved_bytes) VALUES (1,?,0)", report.ObservedAt); e != nil {
		return nil, ErrInstall
	}
	r := &originalDisabledMetadataReservation{ctx: ctx, tx: tx, report: report, capacity: capacity, cost: cost}
	var outstanding int64
	if tx.QueryRowContext(ctx, "SELECT sample_at,reserved_bytes FROM system_backup_v2_metadata_reservations WHERE id=1 FOR UPDATE").Scan(&r.sample, &outstanding) != nil || r.sample.IsZero() || report.ObservedAt.Before(r.sample) || outstanding < 0 || outstanding > capacity-cost || report.AllocatedBytes > capacity-outstanding-cost {
		return nil, ErrInstall
	}
	if originalExactlyOne(tx.ExecContext(ctx, "UPDATE system_backup_v2_metadata_reservations SET reserved_bytes=reserved_bytes+? WHERE id=1 AND sample_at=? AND reserved_bytes=?", cost, r.sample, outstanding)) != nil {
		return nil, ErrInstall
	}
	r.floor = outstanding + cost
	return r, nil
}

func (r *originalDisabledMetadataReservation) recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if r == nil || tx == nil || tx != r.tx || !consumerSameContext(ctx, r.ctx) || ctx.Err() != nil || !originalC1CapacityFresh(r.report, now) {
		return ErrInstall
	}
	var sample time.Time
	var reserved int64
	if tx.QueryRowContext(ctx, "SELECT sample_at,reserved_bytes FROM system_backup_v2_metadata_reservations WHERE id=1 FOR UPDATE").Scan(&sample, &reserved) != nil || !sample.Equal(r.sample) || reserved < r.floor || reserved > r.capacity-r.report.AllocatedBytes {
		return ErrInstall
	}
	return nil
}

func originalDisabledEvidenceID(requestSHA string) string {
	return "sev_" + requestSHA[:8] + "-" + requestSHA[8:12] + "-4" + requestSHA[13:16] + "-8" + requestSHA[17:20] + "-" + requestSHA[20:32]
}

func originalDisabledRecordValid(r originalDisabledInitializationRecord) bool {
	return r.Version == originalDisabledInitializationVersion && digestPattern.MatchString(r.RequestSHA256) && digestPattern.MatchString(r.ConfigSHA256) && digestPattern.MatchString(r.SnapshotSHA256) && digestPattern.MatchString(r.C1HistorySHA256) && digestPattern.MatchString(r.InventorySHA256) && r.Epoch > 0 && r.Head.HeadRevision == 1 && r.Head.State == "active" && r.Domain.State == "open" && r.Domain.Admission.Unconfigured != nil && r.Domain.Admission.Configured == nil && string(r.Domain.Scope.Installation) == r.InstallationID && r.CurrentHealth == "unknown" && r.HistoricalReferences == "authenticated_original_history" && r.KEKAdmission == "absent" && !r.StartedAt.IsZero() && !r.FinishedAt.Before(r.StartedAt) && r.FinishedAt.Before(r.DeadlineAt) && r.RetainUntil.After(r.FinishedAt)
}

// Private data writer: all actual authentication and locks belong to the sole
// Installer entry. No KEK admission/fence/domain/health/task SQL is emitted.
func originalDisabledWriteRows(ctx context.Context, tx *sql.Tx, g sec.OfflineBootstrapGrant, plan sec.DisabledInitializationPlan, r originalDisabledInitializationRecord) error {
	if tx == nil || !originalDisabledRecordValid(r) || g.InstallationID != r.InstallationID || g.ConfigSHA256 != r.ConfigSHA256 || len(plan.Columns) != len(plan.Values) || len(plan.Columns) < 10 {
		return ErrInstall
	}
	raw, e := canonical(r)
	if e != nil || len(raw) > 8192 {
		return ErrInstall
	}
	digest := hash(raw)
	actor := strconv.FormatInt(g.UserID, 10)
	audit := func(phase string) error {
		result, e := tx.ExecContext(ctx, "INSERT INTO audit_logs(user_id,action,resource_type,details) VALUES (?,?,'system_backup',?)", g.UserID, "system_backup.disabled_unverified_initialize."+phase, string(raw))
		return originalExactlyOne(result, e)
	}
	if audit("intent") != nil {
		return ErrInstall
	}
	marks := strings.TrimSuffix(strings.Repeat("?,", len(plan.Columns)), ",")
	if originalExactlyOne(tx.ExecContext(ctx, "INSERT INTO system_backup_v2_configs ("+strings.Join(plan.Columns, ",")+") VALUES ("+marks+")", plan.Values...)) != nil {
		return ErrInstall
	}
	if originalExactlyOne(tx.ExecContext(ctx, "INSERT INTO system_backup_v2_installation_state(origin_installation_id,active_config_version,last_effective_enabled,last_effective_enabled_transition_at,matrix_key) VALUES (?,1,FALSE,?,?)", g.InstallationID, r.FinishedAt, g.MatrixKey)) != nil {
		return ErrInstall
	}
	result, e := tx.ExecContext(ctx, `INSERT INTO system_backup_v2_evidence(public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,inline_payload,content_checksum,content_size_bytes,media_type,encryption,redaction_classification,observed_health,expires_at,created_at,updated_at) VALUES (?,'system',?,'diagnostic','inline',?,?,?,'application/json','none','internal','unknown',?,?,?)`, originalDisabledEvidenceID(r.RequestSHA256), g.InstallationID, raw, digest, len(raw), r.RetainUntil, r.FinishedAt, r.FinishedAt)
	if originalExactlyOne(result, e) != nil {
		return ErrInstall
	}
	evidenceID, e := result.LastInsertId()
	if e != nil || evidenceID < 1 {
		return ErrInstall
	}
	if originalExactlyOne(tx.ExecContext(ctx, `INSERT INTO system_backup_v2_operations(public_id,origin_installation_id,operation_type,target_type,target_public_id,actor_type,actor_id,endpoint,idempotency_key,request_hash,external_action_public_ids_canonical_json,external_action_public_ids_size_bytes,external_action_public_ids_sha256,status,result_config_version,http_status,redacted_response_evidence_id,redacted_response_sha256,deadline_at,started_at,finished_at,created_at,updated_at) VALUES (?,?,'config_update','system',?,'admin',?,?,?,?,?,2,?,'succeeded',1,201,?,?,?,?,?,?,?)`, r.Operation, g.InstallationID, g.InstallationID, actor, OriginalDisabledInitializationEndpoint, g.IdempotencyKey, r.RequestSHA256, []byte("[]"), hash([]byte("[]")), evidenceID, digest, r.DeadlineAt, r.StartedAt, r.FinishedAt, r.StartedAt, r.FinishedAt)) != nil {
		return ErrInstall
	}
	if e = audit("result"); e != nil {
		return e
	}
	return nil
}

func originalDisabledOneConfig(ctx context.Context, tx *sql.Tx, g sec.OfflineBootstrapGrant, plan sec.DisabledInitializationPlan) error {
	var version uint64
	var enabled bool
	var matrix string
	if tx.QueryRowContext(ctx, "SELECT active_config_version,last_effective_enabled,matrix_key FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR SHARE", g.InstallationID).Scan(&version, &enabled, &matrix) != nil || version != 1 || enabled || matrix != g.MatrixKey {
		return ErrInstall
	}
	rows, e := tx.QueryContext(ctx, "SELECT "+strings.Join(plan.Columns, ",")+" FROM system_backup_v2_configs WHERE origin_installation_id=? ORDER BY version FOR SHARE", g.InstallationID)
	if e != nil {
		return ErrInstall
	}
	defer rows.Close()
	if !rows.Next() {
		return ErrInstall
	}
	values := make([]any, len(plan.Columns))
	dest := make([]any, len(values))
	for n := range values {
		dest[n] = &values[n]
	}
	if rows.Scan(dest...) != nil {
		return ErrInstall
	}
	for n, value := range values {
		if bytesValue, ok := value.([]byte); ok {
			value = string(bytesValue)
		}
		wanted := plan.Values[n]
		if b, ok := wanted.([]byte); ok {
			wanted = string(b)
		}
		if plan.Columns[n] == "enabled" {
			if value != false && fmt.Sprint(value) != "0" {
				return ErrInstall
			}
			continue
		}
		if plan.Columns[n] == "source_size_safety_factor" {
			a, ok := new(big.Rat).SetString(fmt.Sprint(value))
			b, valid := new(big.Rat).SetString(fmt.Sprint(wanted))
			if !ok || !valid || a.Cmp(b) != 0 {
				return ErrInstall
			}
			continue
		}
		if fmt.Sprint(value) != fmt.Sprint(wanted) {
			return ErrInstall
		}
	}
	if rows.Next() || rows.Err() != nil || rows.NextResultSet() || rows.Close() != nil {
		return ErrInstall
	}
	return nil
}
