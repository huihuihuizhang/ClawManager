package systembackupsecurity

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"
)

const configMaintenanceReceiptSchema = "system-backup-config-maintenance-receipt.v1"
const configMaintenanceAuditSchema = "system-backup-config-maintenance-audit.v1"
const maxConfigMaintenanceReceiptBytes = 65536

// Internal candidate representation for proposed 082, not a public API or
// authentication/grant format. The caller must independently authenticate the
// stable actor, purpose-specific grant and original archive before using it.
type configMaintenanceIdentity struct {
	Server        string `json:"target_server_uuid"`
	Database      string `json:"target_database"`
	Installation  string `json:"origin_installation_id"`
	Actor         string `json:"maintenance_actor_sha256"`
	Action        string `json:"action"`
	Grant         string `json:"grant_identity_sha256"`
	GrantVersion  string `json:"grant_version"`
	Version       int64  `json:"config_version"`
	ConfigSHA     string `json:"original_config_sha256"`
	ConfigSize    int64  `json:"original_config_size_bytes"`
	RowSHA        string `json:"expected_row_sha256"`
	ProvenanceSHA string `json:"source_provenance_sha256"`
	SchemaSHA     string `json:"schema_sha256"`
	CatalogSHA    string `json:"catalog_sha256"`
	MigrationSHA  string `json:"migration_sha256"`
}
type configMaintenanceScope struct {
	database  DatabaseIdentity
	identity  configMaintenanceIdentity
	key, hash string
	canonical []byte // exact A request; contains reason, never a receipt/audit body
}

func (configMaintenanceScope) MarshalJSON() ([]byte, error) { return nil, ErrConfigMutation }

// trustedDatabase/installation/actor are admission bindings, not request
// claims. Comparing them here does not authenticate their origin or purpose.
func newConfigMaintenanceScope(trustedDatabase DatabaseIdentity, installation, actor, key string, raw []byte) (configMaintenanceScope, error) {
	zero := configMaintenanceScope{}
	if !trustedDatabase.valid() || !configMutationInstallation.MatchString(installation) || !providerHashPattern.MatchString(actor) || !validIdempotencyKey(key) {
		return zero, ErrConfigMutation
	}
	canonical, hash, err := CanonicalConfigMaintenanceRequest(append([]byte(nil), raw...))
	if err != nil {
		return zero, err
	}
	var identity configMaintenanceIdentity
	if json.Unmarshal(canonical, &identity) != nil || identity.Server != trustedDatabase.ServerUUID || identity.Database != trustedDatabase.Database || identity.Installation != installation || identity.Actor != actor {
		return zero, ErrConfigMutation
	}
	return configMaintenanceScope{trustedDatabase, identity, key, hash, canonical}, nil
}
func (s configMaintenanceScope) valid() bool {
	other, err := newConfigMaintenanceScope(s.database, s.identity.Installation, s.identity.Actor, s.key, s.canonical)
	return err == nil && other.identity == s.identity && other.hash == s.hash && bytes.Equal(other.canonical, s.canonical)
}
func (i configMaintenanceIdentity) fields() map[string]any {
	return map[string]any{
		"action": i.Action, "target_server_uuid": i.Server, "target_database": i.Database, "origin_installation_id": i.Installation, "maintenance_actor_sha256": i.Actor,
		"grant_identity_sha256": i.Grant, "grant_version": i.GrantVersion, "config_version": json.Number(fieldsVersion(i.Version)),
		"original_config_sha256": i.ConfigSHA, "original_config_size_bytes": json.Number(fieldsVersion(i.ConfigSize)), "expected_row_sha256": i.RowSHA, "source_provenance_sha256": i.ProvenanceSHA,
		"schema_sha256": i.SchemaSHA, "catalog_sha256": i.CatalogSHA, "migration_sha256": i.MigrationSHA,
	}
}

type configMaintenanceReceiptPolicy struct {
	scope                configMaintenanceScope
	receiptID, requestID string
	wrote                bool
	intentID, resultID   int64
	createdAt            time.Time
}

func configMaintenanceSQLTime(now time.Time) bool {
	_, offset := now.Zone()
	return !now.IsZero() && offset == 0 && now.Year() >= 1000 && now.Year() <= 9999 && now.Nanosecond()%1000 == 0
}
func (p configMaintenanceReceiptPolicy) valid() bool {
	return p.scope.valid() && canonicalMaintenanceServer.MatchString(p.receiptID) && bootstrapVersion.MatchString(p.requestID) && p.intentID > 0 && p.intentID <= 2147483647 && p.resultID > 0 && p.resultID <= 2147483647 && p.intentID != p.resultID && configMaintenanceSQLTime(p.createdAt)
}
func canonicalConfigMaintenanceReceipt(p configMaintenanceReceiptPolicy) ([]byte, error) {
	if !p.valid() {
		return nil, ErrConfigMutation
	}
	fields := p.scope.identity.fields()
	fields["schema_version"] = configMaintenanceReceiptSchema
	fields["request_profile"] = ConfigMaintenanceDigestProfile
	fields["row_identity_profile"] = ConfigBackfillRowProfile
	fields["source_provenance_profile"] = ConfigBackfillProvenanceProfile
	fields["receipt_id"], fields["request_id"] = p.receiptID, p.requestID
	fields["idempotency_key"], fields["request_sha256"] = p.scope.key, p.scope.hash
	fields["wrote"] = p.wrote
	fields["intent_audit_id"], fields["result_audit_id"] = json.Number(fieldsVersion(p.intentID)), json.Number(fieldsVersion(p.resultID))
	fields["created_at"] = p.createdAt.UTC().Format("2006-01-02T15:04:05.000000Z")
	raw, _ := canonicalMaintenanceDigest(fields)
	if len(raw) > maxConfigMaintenanceReceiptBytes {
		return nil, ErrConfigMutation
	}
	return raw, nil
}

// Digest-only audit representation: no original config, legacy author/reason,
// archive locator, proof, token or raw maintenance request is persisted here.
// Its request SHA binds the reason through A's already accepted request format.
func canonicalConfigMaintenanceAudit(scope configMaintenanceScope, receiptID, requestID, phase string, wrote bool) ([]byte, error) {
	if !scope.valid() || !canonicalMaintenanceServer.MatchString(receiptID) || !bootstrapVersion.MatchString(requestID) || (phase != "intent" && phase != "result") {
		return nil, ErrConfigMutation
	}
	fields := scope.identity.fields()
	fields["schema_version"] = configMaintenanceAuditSchema
	fields["request_profile"], fields["row_identity_profile"], fields["source_provenance_profile"] = ConfigMaintenanceDigestProfile, ConfigBackfillRowProfile, ConfigBackfillProvenanceProfile
	fields["receipt_id"], fields["request_id"], fields["phase"] = receiptID, requestID, phase
	fields["idempotency_key"], fields["request_sha256"], fields["wrote"] = scope.key, scope.hash, wrote
	raw, _ := canonicalMaintenanceDigest(fields)
	return raw, nil
}

// MySQL JSON storage may change key order/spacing. Require the exact closed
// semantic object without accepting duplicates, lossy Unicode or extra fields.
func canonicalMaintenanceStoredJSON(raw []byte) ([]byte, error) {
	if len(raw) < 2 || len(raw) > 65536 || !json.Valid(raw) || !providerJSONUnicode(raw) || !providerUniqueJSON(json.NewDecoder(bytes.NewReader(raw))) {
		return nil, ErrConfigMutation
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var fields map[string]any
	if decoder.Decode(&fields) != nil || fields == nil {
		return nil, ErrConfigMutation
	}
	var out strings.Builder
	canonicalMutationJSON(&out, fields)
	return []byte(out.String()), nil
}
