package systembackupsecurity

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
)

// Historical exact FIRST normal-enable lineage. This is NOT session/MFA,
// native readiness, key-use or mutation authority. Each original SQL view
// must obtain its own proof; expired old observations are never renewed.
type OriginalEnabledOnlyLineage struct {
	origin                                               *OriginalEnabledOnlyLineage
	installation, oldSHA, newSHA, operation, fingerprint string
	actor                                                int64
	ctx                                                  context.Context
	view                                                 reg.SQLReadView
	checkedAt                                            time.Time
	version                                              uint64
}

func (*OriginalEnabledOnlyLineage) MarshalJSON() ([]byte, error) { return nil, ErrConfigMutation }
func (p *OriginalEnabledOnlyLineage) Matches(installation, oldSHA string, version uint64, newSHA string) bool {
	return p != nil && p.origin == p && p.ctx != nil && p.ctx.Err() == nil && p.installation == installation && p.oldSHA == oldSHA && p.newSHA == newSHA && p.version == version
}
func (p *OriginalEnabledOnlyLineage) Fingerprint() (string, error) {
	if p == nil || p.origin != p {
		return "", ErrConfigMutation
	}
	return p.fingerprint, nil
}
func (p *OriginalEnabledOnlyLineage) ActorID() (int64, error) {
	if p == nil || p.origin != p {
		return 0, ErrConfigMutation
	}
	return p.actor, nil
}

func ReadOriginalEnabledOnlyLineage(ctx context.Context, view reg.SQLReadView, installation, oldSHA string, currentVersion uint64, currentSHA string) (*OriginalEnabledOnlyLineage, error) {
	if ctx == nil || ctx.Err() != nil || candidateAuthorityNil(view) || !reflect.ValueOf(ctx).Comparable() || !reflect.ValueOf(view).Comparable() || !configMutationInstallation.MatchString(installation) || currentVersion != 2 || !providerHashPattern.MatchString(oldSHA) || !providerHashPattern.MatchString(currentSHA) || oldSHA == currentSHA {
		return nil, ErrRegistrationUnavailable
	}
	var active uint64
	var effective bool
	var stateRV uint64
	if view.QueryRowContext(ctx, "SELECT active_config_version,last_effective_enabled,row_version FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR SHARE", installation).Scan(&active, &effective, &stateRV) != nil || active != 2 || stateRV < 2 {
		return nil, ErrRegistrationUnavailable
	}
	old, e := readEnabledLineageConfig(ctx, view, installation, 1)
	if e != nil {
		return nil, e
	}
	current, e := readEnabledLineageConfig(ctx, view, installation, 2)
	if e != nil {
		return nil, e
	}
	if old.SHA256() != oldSHA || current.SHA256() != currentSHA || ValidateEnableOnlyConfigMutation(ConfigMutationResourceInput{current: old, proposed: current}) != nil {
		return nil, ErrRegistrationUnavailable
	}
	rows, e := view.QueryContext(ctx, `SELECT id,public_id,actor_id,idempotency_key,request_hash,row_version,redacted_response_evidence_id,redacted_response_sha256,created_at,started_at,finished_at,updated_at,deadline_at FROM system_backup_v2_operations WHERE origin_installation_id=? AND operation_type='config_update' AND target_type='system' AND target_public_id=? AND actor_type='admin' AND endpoint=? AND status='succeeded' AND result_config_version=2 AND http_status=200 AND schema_version='system-backup-operation.v1' AND retryable=FALSE AND failure_category='none' AND failure_message IS NULL AND result_resource_public_id IS NULL ORDER BY id`, installation, installation, ConfigUpdateEndpoint)
	if e != nil {
		return nil, ErrRegistrationUnavailable
	}
	defer rows.Close()
	var id, evidenceID uint64
	var actor, checksum string
	var policy ConfigOperationResponsePolicy
	policy.InstallationID, policy.Endpoint, policy.Version = installation, ConfigUpdateEndpoint, 2
	if !rows.Next() || rows.Scan(&id, &policy.OperationPublicID, &actor, &policy.IdempotencyKey, &policy.RequestHash, &policy.RowVersion, &evidenceID, &checksum, &policy.CreatedAt, &policy.StartedAt, &policy.FinishedAt, &policy.UpdatedAt, &policy.DeadlineAt) != nil || rows.Next() || rows.Err() != nil || rows.NextResultSet() || rows.Close() != nil {
		return nil, ErrRegistrationUnavailable
	}
	policy.ActorID, e = strconv.ParseInt(actor, 10, 64)
	if e != nil || policy.ActorID < 1 || strconv.FormatInt(policy.ActorID, 10) != actor || id == 0 || evidenceID == 0 {
		return nil, ErrRegistrationUnavailable
	}
	want, e := CanonicalConfigOperationResponse(policy)
	if e != nil {
		return nil, ErrRegistrationUnavailable
	}
	var response []byte
	var size uint64
	var expires, now time.Time
	if view.QueryRowContext(ctx, `SELECT inline_payload,content_size_bytes,expires_at FROM system_backup_v2_evidence WHERE id=? AND owner_target_type='system' AND owner_target_public_id=? AND evidence_type='diagnostic' AND storage_state='inline' AND encryption='none' AND observed_health='healthy' AND media_type='application/json' AND content_checksum=? AND chunk_count=0 AND claim_owner IS NULL AND claim_expires_at IS NULL`, evidenceID, installation, checksum).Scan(&response, &size, &expires) != nil || size != uint64(len(response)) || checksum != registrationHash(string(response)) || !bytes.Equal(response, want) {
		return nil, ErrRegistrationUnavailable
	}
	var evidenceSchema, evidencePublicID, evidenceFailure, classification string
	var evidenceRV uint64
	var evidenceCreated time.Time
	if view.QueryRowContext(ctx, "SELECT schema_version,public_id,evidence_failure_code,redaction_classification,row_version,created_at FROM system_backup_v2_evidence WHERE id=?", evidenceID).Scan(&evidenceSchema, &evidencePublicID, &evidenceFailure, &classification, &evidenceRV, &evidenceCreated) != nil || evidenceSchema != "system-backup-evidence.v1" || !providerEvidenceID.MatchString(evidencePublicID) || evidenceFailure != "none" || classification != "internal" || evidenceRV < 1 || !evidenceCreated.Equal(policy.FinishedAt) {
		return nil, ErrRegistrationUnavailable
	}
	var external [14]any
	externalDest := make([]any, len(external))
	for n := range external {
		externalDest[n] = &external[n]
	}
	if view.QueryRowContext(ctx, "SELECT storage_provider_role,storage_identity_hash,storage_ref_version,storage_relative_key,storage_relative_key_hash,storage_immutable_version,object_checksum,object_size_bytes,plaintext_chunk_size_bytes,chunk_list_root,envelope_framing_version,kek_identity_hash,kek_version,envelope_hash FROM system_backup_v2_evidence WHERE id=?", evidenceID).Scan(externalDest...) != nil {
		return nil, ErrRegistrationUnavailable
	}
	for _, v := range external {
		if v != nil {
			return nil, ErrRegistrationUnavailable
		}
	}
	chunks, e := view.QueryContext(ctx, "SELECT chunk_index FROM system_backup_v2_evidence_chunks WHERE evidence_id=? ORDER BY chunk_index", evidenceID)
	if e != nil {
		return nil, ErrRegistrationUnavailable
	}
	any := chunks.Next()
	err := chunks.Err()
	extra := chunks.NextResultSet()
	closed := chunks.Close()
	if any || err != nil || extra || closed != nil {
		return nil, ErrRegistrationUnavailable
	}
	binding, observation, e := (reg.SQLStore{}).ReadCommittedInView(ctx, view, installation, policy.OperationPublicID)
	if e != nil || observation.ConfigSHA256 != currentSHA || binding.InstallationID != installation {
		return nil, ErrRegistrationUnavailable
	}
	matched := false
	for _, ref := range old.References() {
		if ref.Purpose == "kek" {
			matched = ref.IdentityHash == binding.ConfigRef.IdentityHash && ref.Version == binding.ConfigRef.Version
		}
	}
	if !matched || view.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || now.Before(policy.FinishedAt) || !now.Before(expires) || ctx.Err() != nil {
		return nil, ErrRegistrationUnavailable
	}
	// Snapshot full typed values/op/committed mapping, not just a refs subset.
	body := struct {
		Old, Current []byte
		Operation    ConfigOperationResponsePolicy
		Binding      reg.Binding
		Observation  reg.AdmissionObservation
	}{old.CanonicalJSON(), current.CanonicalJSON(), policy, binding, observation}
	raw, e := json.Marshal(body)
	if e != nil {
		return nil, e
	}
	p := &OriginalEnabledOnlyLineage{installation: installation, oldSHA: oldSHA, newSHA: currentSHA, operation: policy.OperationPublicID, actor: policy.ActorID, ctx: ctx, view: view, checkedAt: now, version: 2, fingerprint: registrationHash(string(raw))}
	p.origin = p
	return p, nil
}

func readEnabledLineageConfig(ctx context.Context, q reg.SQLReadView, installation string, version int64) (ConfigValues, error) {
	var raw []byte
	var schema, sha string
	var size, rv uint64
	if q.QueryRowContext(ctx, "SELECT schema_version,canonical_config_json,config_sha256,config_size_bytes,row_version FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=?", installation, version).Scan(&schema, &raw, &sha, &size, &rv) != nil || schema != "system-backup-config.v1" || rv < 1 || size != uint64(len(raw)) {
		return ConfigValues{}, ErrRegistrationUnavailable
	}
	c, e := DecodeConfigValues(raw)
	if e != nil || c.SHA256() != sha || !bytes.Equal(c.CanonicalJSON(), raw) {
		return ConfigValues{}, ErrRegistrationUnavailable
	}
	columns, values, e := c.sqlValues(installation, "unused", "unused", version)
	if e != nil {
		return ConfigValues{}, e
	}
	selected := []string{}
	want := []any{}
	for n, column := range columns {
		if n < 4 || column == "created_by" || column == "change_reason" || column == "canonical_config_json" {
			continue
		}
		selected = append(selected, column)
		want = append(want, values[n])
	}
	got := make([]any, len(selected))
	dest := make([]any, len(got))
	for n := range got {
		dest[n] = &got[n]
	}
	if q.QueryRowContext(ctx, "SELECT "+strings.Join(selected, ",")+" FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=?", installation, version).Scan(dest...) != nil {
		return ConfigValues{}, ErrRegistrationUnavailable
	}
	for n, column := range selected {
		if !configMutationCellEqual(column, got[n], want[n], c) {
			return ConfigValues{}, ErrRegistrationUnavailable
		}
	}
	return c, nil
}

// This is the sole authorization-scope DATA accessor for source factories.
// Mint/use in the same actual original SQL view, before it closes. A caller
// cannot move an opaque pointer to another ctx/tx or substitute a hash/Passed.
// Current task authority/native health/old grant Until remain mandatory.
func (p *OriginalEnabledOnlyLineage) AuthorizationConfigSHA256(ctx context.Context, view reg.SQLReadView) (string, error) {
	if p == nil || p.origin != p || ctx == nil || ctx.Err() != nil || !reflect.ValueOf(ctx).Comparable() || !reflect.ValueOf(view).IsValid() || !reflect.ValueOf(view).Comparable() || ctx != p.ctx || view != p.view {
		return "", ErrRegistrationUnavailable
	}
	var now time.Time
	if view.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || now.Before(p.checkedAt) || ctx.Err() != nil {
		return "", ErrRegistrationUnavailable
	}
	return p.oldSHA, nil
}
