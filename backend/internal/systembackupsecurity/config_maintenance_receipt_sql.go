package systembackupsecurity

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

var errConfigMaintenanceReceiptMissing = errors.New("config_maintenance_receipt_missing")

// A negative observation also has a database-clock bound. Preserve it without
// releasing a usable receipt, so a caller cannot overlook clock regression
// after the loader's internal full-row scan.
type configMaintenanceReceiptAbsence struct{ observedAt time.Time }

func (configMaintenanceReceiptAbsence) Error() string {
	return errConfigMaintenanceReceiptMissing.Error()
}
func (configMaintenanceReceiptAbsence) Unwrap() error { return errConfigMaintenanceReceiptMissing }

const configMaintenanceReceiptColumnsSHA256 = "a0e7e03cdcad769f5e4588118bb8629696d3f8c066183351744cd8d8ba08a328"
const configMaintenanceReceiptSelect = "SELECT * FROM system_backup_v2_config_maintenance_receipts WHERE target_server_uuid=? AND target_database=? AND origin_installation_id=? AND maintenance_actor_sha256=? AND action='config_canonical_backfill' AND idempotency_key=? FOR UPDATE"
const configMaintenanceReceiptInsert = `INSERT INTO system_backup_v2_config_maintenance_receipts (schema_version,receipt_id,target_server_uuid,target_database,origin_installation_id,maintenance_actor_sha256,action,idempotency_key,request_sha256,grant_identity_sha256,grant_version,config_version,original_config_sha256,original_config_size_bytes,expected_row_sha256,source_provenance_sha256,schema_sha256,catalog_sha256,migration_sha256,wrote,intent_audit_id,result_audit_id,redacted_response_canonical_json,redacted_response_sha256,redacted_response_size_bytes,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

// Pure SQL storage candidate for 082. The caller must first authorize its
// maintenance/write or observation purpose, establish lock order/capacity and
// authenticate source/grant pins. Nothing here signs grants or commits a tx.
type configMaintenanceReceiptSnapshot struct {
	tx         *sql.Tx
	id         string
	policy     configMaintenanceReceiptPolicy
	raw        []byte
	observedAt time.Time
	row        lockedConfigBackfillRow
	audits     configMaintenanceAuditPair
}

// Keep the original anchor times as well as their IDs and closed semantic
// bodies. A later callback in the SAME transaction can change a locked row;
// merely checking that the replacement times still sort does not freeze it.
type configMaintenanceAuditPair struct {
	requestID          string
	intentAt, resultAt time.Time
}

func (a configMaintenanceAuditPair) same(b configMaintenanceAuditPair) bool {
	return a.requestID == b.requestID && a.intentAt.Equal(b.intentAt) && a.resultAt.Equal(b.resultAt)
}

func (configMaintenanceReceiptSnapshot) MarshalJSON() ([]byte, error) { return nil, ErrConfigMutation }
func (r configMaintenanceReceiptSnapshot) bytes() []byte              { return append([]byte(nil), r.raw...) }

func refreshConfigMaintenanceRow(ctx context.Context, tx *sql.Tx, scope configMaintenanceScope, reference lockedConfigBackfillRow) (lockedConfigBackfillRow, error) {
	zero := lockedConfigBackfillRow{}
	i := scope.identity
	if ctx == nil || ctx.Err() != nil || tx == nil || !scope.valid() || reference.tx != tx || reference.database != scope.database || reference.installation != i.Installation || reference.version != i.Version || reference.rowSHA256 != i.RowSHA || reference.observedAt.IsZero() || int64(len(reference.original)) != i.ConfigSize || registrationHash(string(reference.original)) != i.ConfigSHA || (reference.canonical != configBackfillCanonicalNull && reference.canonical != configBackfillCanonicalOriginal) {
		return zero, ErrRegistrationUnavailable
	}
	fresh, err := readLockedConfigBackfillRow(ctx, tx, scope.database, i.Installation, i.Version, reference.original)
	if err != nil {
		return zero, err
	}
	if fresh.rowID != reference.rowID || fresh.rowSHA256 != reference.rowSHA256 || fresh.observedAt.Before(reference.observedAt) {
		return zero, ErrRegistrationUnavailable
	}
	return fresh, nil
}

func verifyConfigMaintenanceAudit(ctx context.Context, tx *sql.Tx, id int64, scope configMaintenanceScope, receiptID, requestID, phase string, wrote bool, now time.Time) (string, time.Time, error) {
	var user, resource sql.NullInt64
	var action, resourceType string
	var raw []byte
	var created time.Time
	if id < 1 || id > 2147483647 || tx.QueryRowContext(ctx, "SELECT user_id,action,resource_type,resource_id,details,created_at FROM audit_logs WHERE id=? FOR UPDATE", id).Scan(&user, &action, &resourceType, &resource, &raw, &created) != nil || user.Valid || resource.Valid || action != "system_backup.config_canonical_backfill."+phase || resourceType != "system_backup" || !configMaintenanceSQLTime(created) || created.After(now) {
		return "", time.Time{}, ErrRegistrationUnavailable
	}
	canonical, err := canonicalMaintenanceStoredJSON(raw)
	if err != nil {
		return "", time.Time{}, ErrRegistrationUnavailable
	}
	var correlation struct {
		RequestID string `json:"request_id"`
	}
	if json.Unmarshal(canonical, &correlation) != nil || !bootstrapVersion.MatchString(correlation.RequestID) || requestID != "" && correlation.RequestID != requestID {
		return "", time.Time{}, ErrRegistrationUnavailable
	}
	expected, err := canonicalConfigMaintenanceAudit(scope, receiptID, correlation.RequestID, phase, wrote)
	if err != nil || !bytes.Equal(canonical, expected) || ctx.Err() != nil {
		return "", time.Time{}, ErrRegistrationUnavailable
	}
	return correlation.RequestID, created, nil
}
func verifyConfigMaintenanceAuditPair(ctx context.Context, tx *sql.Tx, p configMaintenanceReceiptPolicy) (configMaintenanceAuditPair, error) {
	zero := configMaintenanceAuditPair{}
	if p.intentID == p.resultID {
		return zero, ErrRegistrationUnavailable
	}
	request, created, err := verifyConfigMaintenanceAudit(ctx, tx, p.intentID, p.scope, p.receiptID, p.requestID, "intent", p.wrote, p.createdAt)
	if err != nil {
		return zero, err
	}
	_, resultAt, err := verifyConfigMaintenanceAudit(ctx, tx, p.resultID, p.scope, p.receiptID, request, "result", p.wrote, p.createdAt)
	if err != nil || resultAt.Before(created) {
		return zero, ErrRegistrationUnavailable
	}
	return configMaintenanceAuditPair{requestID: request, intentAt: created, resultAt: resultAt}, nil
}

func stageConfigMaintenanceReceipt(ctx context.Context, tx *sql.Tx, scope configMaintenanceScope, before lockedConfigBackfillRow, receiptID, requestID string, intentID, resultID int64) (configMaintenanceReceiptSnapshot, error) {
	zero := configMaintenanceReceiptSnapshot{}
	after, err := refreshConfigMaintenanceRow(ctx, tx, scope, before)
	if err != nil {
		return zero, err
	}
	if after.canonical != configBackfillCanonicalOriginal {
		return zero, ErrRegistrationUnavailable
	}
	p := configMaintenanceReceiptPolicy{scope: scope, receiptID: receiptID, requestID: requestID, wrote: before.canonical == configBackfillCanonicalNull, intentID: intentID, resultID: resultID, createdAt: after.observedAt}
	raw, err := canonicalConfigMaintenanceReceipt(p)
	if err != nil {
		return zero, err
	}
	audits, err := verifyConfigMaintenanceAuditPair(ctx, tx, p)
	if err != nil {
		return zero, err
	}
	i := scope.identity
	// Own the public buffer separately from the driver's argument storage.
	result, err := tx.ExecContext(ctx, configMaintenanceReceiptInsert, configMaintenanceReceiptSchema, receiptID, i.Server, i.Database, i.Installation, i.Actor, i.Action, scope.key, scope.hash, i.Grant, i.GrantVersion, i.Version, i.ConfigSHA, i.ConfigSize, i.RowSHA, i.ProvenanceSHA, i.SchemaSHA, i.CatalogSHA, i.MigrationSHA, p.wrote, intentID, resultID, append([]byte(nil), raw...), registrationHash(string(raw)), len(raw), p.createdAt)
	if err != nil {
		var duplicate *mysql.MySQLError
		if errors.As(err, &duplicate) && duplicate.Number == 1062 {
			return zero, ErrRegistrationConflict
		}
		return zero, ErrProviderEvidenceStorage
	}
	if !configMutationOne(result, nil) {
		return zero, ErrProviderEvidenceStorage
	}
	id, err := result.LastInsertId()
	if err != nil || id < 1 {
		return zero, ErrProviderEvidenceStorage
	}
	loaded, err := loadConfigMaintenanceReceipt(ctx, tx, scope, after)
	if err != nil || loaded.id != strconv.FormatInt(id, 10) || loaded.policy.receiptID != receiptID || loaded.policy.requestID != requestID || loaded.policy.wrote != p.wrote || loaded.policy.intentID != intentID || loaded.policy.resultID != resultID || !loaded.policy.createdAt.Equal(p.createdAt) || !bytes.Equal(loaded.raw, raw) {
		return zero, ErrRegistrationUnavailable
	}
	if !loaded.audits.same(audits) {
		return zero, ErrRegistrationUnavailable
	}
	return loaded, nil
}

// Require the caller's verified config-row observation before the receipt lock,
// preserving config -> receipt lock order for writes and committed observation.
// A missing row is distinct from a permanent same-key/different-hash conflict.
func loadConfigMaintenanceReceipt(ctx context.Context, tx *sql.Tx, scope configMaintenanceScope, row lockedConfigBackfillRow) (configMaintenanceReceiptSnapshot, error) {
	zero := configMaintenanceReceiptSnapshot{}
	fresh, err := refreshConfigMaintenanceRow(ctx, tx, scope, row)
	if err != nil {
		return zero, err
	}
	if fresh.canonical != row.canonical {
		return zero, ErrRegistrationUnavailable
	}
	i := scope.identity
	rows, err := tx.QueryContext(ctx, configMaintenanceReceiptSelect, i.Server, i.Database, i.Installation, i.Actor, scope.key)
	if err != nil {
		return zero, ErrProviderEvidenceStorage
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil || len(columns) != 27 {
		return zero, ErrRegistrationUnavailable
	}
	columns = append([]string(nil), columns...)
	sorted := append([]string(nil), columns...)
	sort.Strings(sorted)
	if registrationHash(strings.Join(sorted, "\n")) != configMaintenanceReceiptColumnsSHA256 {
		return zero, ErrRegistrationUnavailable
	}
	if !rows.Next() {
		if rows.Err() != nil || rows.Close() != nil || ctx.Err() != nil {
			return zero, ErrRegistrationUnavailable
		}
		return zero, configMaintenanceReceiptAbsence{observedAt: fresh.observedAt}
	}
	values := make([]any, len(columns))
	dest := make([]any, len(columns))
	for n := range values {
		dest[n] = &values[n]
	}
	if rows.Scan(dest...) != nil || rows.Next() || rows.Err() != nil || rows.Close() != nil || ctx.Err() != nil {
		return zero, ErrRegistrationUnavailable
	}
	cell := map[string]any{}
	for n, name := range columns {
		cell[name] = values[n]
	}
	text := func(name string) (string, bool) {
		switch value := cell[name].(type) {
		case string:
			return value, true
		case []byte:
			return string(value), true
		default:
			return "", false
		}
	}
	get := func(name string) string { v, _ := text(name); return v }
	if get("schema_version") != configMaintenanceReceiptSchema || get("target_server_uuid") != i.Server || get("target_database") != i.Database || get("origin_installation_id") != i.Installation || get("maintenance_actor_sha256") != i.Actor || get("action") != "config_canonical_backfill" || get("idempotency_key") != scope.key || !providerHashPattern.MatchString(get("request_sha256")) {
		return zero, ErrRegistrationUnavailable
	}
	if get("request_sha256") != scope.hash {
		return zero, ErrRegistrationConflict
	}
	if fresh.canonical != configBackfillCanonicalOriginal {
		return zero, ErrRegistrationUnavailable
	}
	actual := configMaintenanceIdentity{Server: get("target_server_uuid"), Database: get("target_database"), Installation: get("origin_installation_id"), Actor: get("maintenance_actor_sha256"), Action: get("action"), Grant: get("grant_identity_sha256"), GrantVersion: get("grant_version"), ConfigSHA: get("original_config_sha256"), RowSHA: get("expected_row_sha256"), ProvenanceSHA: get("source_provenance_sha256"), SchemaSHA: get("schema_sha256"), CatalogSHA: get("catalog_sha256"), MigrationSHA: get("migration_sha256")}
	var ok bool
	if actual.Version, ok = backfillLockedInt(cell["config_version"]); !ok {
		return zero, ErrRegistrationUnavailable
	}
	if actual.ConfigSize, ok = backfillLockedInt(cell["original_config_size_bytes"]); !ok || actual != i {
		return zero, ErrRegistrationUnavailable
	}
	var wrote bool
	if value, native := cell["wrote"].(bool); native {
		wrote = value
	} else {
		n, valid := backfillLockedInt(cell["wrote"])
		if !valid || (n != 0 && n != 1) {
			return zero, ErrRegistrationUnavailable
		}
		wrote = n == 1
	}
	intent, valid := backfillLockedInt(cell["intent_audit_id"])
	if !valid {
		return zero, ErrRegistrationUnavailable
	}
	result, valid := backfillLockedInt(cell["result_audit_id"])
	if !valid {
		return zero, ErrRegistrationUnavailable
	}
	created, valid := cell["created_at"].(time.Time)
	if !valid || created.After(fresh.observedAt) {
		return zero, ErrRegistrationUnavailable
	}
	p := configMaintenanceReceiptPolicy{scope: scope, receiptID: get("receipt_id"), wrote: wrote, intentID: intent, resultID: result, createdAt: created}
	audits, err := verifyConfigMaintenanceAuditPair(ctx, tx, p)
	if err != nil {
		return zero, err
	}
	p.requestID = audits.requestID
	expected, err := canonicalConfigMaintenanceReceipt(p)
	if err != nil {
		return zero, ErrRegistrationUnavailable
	}
	raw, valid := text("redacted_response_canonical_json")
	size, sizeOK := backfillLockedInt(cell["redacted_response_size_bytes"])
	if !valid || !sizeOK || size != int64(len(raw)) || size < 2 || size > maxConfigMaintenanceReceiptBytes || registrationHash(raw) != get("redacted_response_sha256") || !bytes.Equal([]byte(raw), expected) {
		return zero, ErrRegistrationUnavailable
	}
	if _, boolean := cell["id"].(bool); boolean {
		return zero, ErrRegistrationUnavailable
	}
	id, valid := backfillLockedText(cell["id"])
	if !valid {
		return zero, ErrRegistrationUnavailable
	}
	number, idErr := strconv.ParseUint(id, 10, 64)
	if idErr != nil || number == 0 || strconv.FormatUint(number, 10) != id {
		return zero, ErrRegistrationUnavailable
	}
	// Re-sample target/clock after all SQL callbacks, preserving the original
	// row/body and leaving final grant/source/capacity admission to the caller.
	last, err := refreshConfigMaintenanceRow(ctx, tx, scope, fresh)
	if err != nil || last.canonical != configBackfillCanonicalOriginal || ctx.Err() != nil {
		return zero, ErrRegistrationUnavailable
	}
	return configMaintenanceReceiptSnapshot{tx: tx, id: id, policy: p, raw: []byte(raw), observedAt: last.observedAt, row: last, audits: audits}, nil
}

func (r configMaintenanceReceiptSnapshot) recheck(ctx context.Context, tx *sql.Tx) error {
	_, err := r.recheckAt(ctx, tx)
	return err
}

func (r configMaintenanceReceiptSnapshot) recheckAt(ctx context.Context, tx *sql.Tx) (time.Time, error) {
	if tx == nil || tx != r.tx || r.id == "" || len(r.raw) < 2 {
		return time.Time{}, ErrRegistrationUnavailable
	}
	actual, err := loadConfigMaintenanceReceipt(ctx, tx, r.policy.scope, r.row)
	if err != nil {
		return time.Time{}, err
	}
	if actual.id != r.id || actual.policy.receiptID != r.policy.receiptID || actual.policy.requestID != r.policy.requestID || actual.policy.wrote != r.policy.wrote || actual.policy.intentID != r.policy.intentID || actual.policy.resultID != r.policy.resultID || !actual.policy.createdAt.Equal(r.policy.createdAt) || !bytes.Equal(actual.raw, r.raw) || actual.observedAt.Before(r.observedAt) {
		return time.Time{}, ErrRegistrationUnavailable
	}
	if !actual.audits.same(r.audits) {
		return time.Time{}, ErrRegistrationUnavailable
	}
	return actual.observedAt, nil
}
