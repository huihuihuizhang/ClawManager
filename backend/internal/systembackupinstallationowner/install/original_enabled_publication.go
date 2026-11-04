package install

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

// Concrete current normal enable result, not a serialized scope/Passed DTO.
// Only PrepareOriginalEnabledPublication may create a valid object.
type OriginalEnabledPublication struct {
	mu                sync.Mutex
	failed            bool
	origin            *OriginalEnabledPublication
	operator          *authenticatedOperator
	enrollment        EnrollmentPin
	request           *originalRequest
	initial           HeadCAS
	receipt           BootstrapSourceFilePin
	policy            sec.ConfigOperationResponsePolicy
	original, current []byte
	configSHA         string
	version           uint64
	floor, until      time.Time
}

func (*OriginalEnabledPublication) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (*OriginalEnabledPublication) String() string               { return "AuthenticatedOriginalEnabledPublication" }

// Exact genuine FIRST enable only: current committed v2, retained original v1,
// normal successful config_update Operation+its exact response evidence, and
// every original value unchanged except enabled=false -> true. This reads and
// authenticates; it writes no config, nonce, grant, head or task.
func (i *Installer) PrepareOriginalEnabledPublication(ctx context.Context, password []byte, enrollment EnrollmentPin, receipt BootstrapSourceFilePin, files RequestFiles) (*OriginalEnabledPublication, error) {
	s, e := i.authenticate(ctx, password)
	if e != nil || s.authority(ctx, enrollment) != nil {
		return nil, ErrInstall
	}
	request, e := readRequest(i, files)
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			request.observer.Close()
		}
	}()
	raw, e := readBootstrapSourcePin(receipt, 8192)
	if e != nil {
		return nil, e
	}
	policy, e := sec.DecodeCanonicalConfigOperationResponse(raw)
	if e != nil || policy.InstallationID != i.plan.Target.InstallationID || policy.ActorID != s.userID || policy.Version != 2 || policy.Endpoint != sec.ConfigUpdateEndpoint {
		return nil, ErrInstall
	}
	before, now, e := originalAdoptionAuthoritySnapshot(ctx, s)
	if e != nil || before.cas.State != "active" || !request.matchesDraft(before.record) || !requestWindow(before.record, request, now) {
		return nil, ErrInstall
	}
	p := &OriginalEnabledPublication{operator: s, enrollment: enrollment, request: request, initial: before.cas, receipt: receipt, policy: policy, original: bytes.Clone(request.config.CanonicalJSON()), version: 2, floor: now, until: minTime(before.head.Until, minTime(before.record.Until, request.end))}
	p.origin = p
	if p.read(ctx, true) != nil {
		return nil, ErrInstall
	}
	ok = true
	return p, nil
}
func (p *OriginalEnabledPublication) Close() {
	if p != nil {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.failed = true
		if p.request != nil {
			p.request.observer.Close()
		}
	}
}
func (p *OriginalEnabledPublication) Recheck(ctx context.Context) error {
	if p == nil {
		return ErrInstall
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failed {
		return ErrInstall
	}
	e := p.recheck(ctx)
	if e != nil {
		p.failed = true
	}
	return e
}
func (p *OriginalEnabledPublication) recheck(ctx context.Context) error {
	if p == nil || p.origin != p || p.operator == nil || !p.operator.live(ctx) || p.operator.authority(ctx, p.enrollment) != nil || p.request.recheck(p.operator.installer) != nil {
		return ErrInstall
	}
	return p.read(ctx, false)
}
func (p *OriginalEnabledPublication) read(ctx context.Context, initial bool) error {
	if p == nil || p.origin != p || !p.operator.live(ctx) {
		return ErrInstall
	}
	i := p.operator.installer
	tx, e := i.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return ErrInstall
	}
	defer tx.Rollback()
	now, e := p.operator.lockAdmin(ctx, tx)
	if e != nil || now.Before(p.floor) || !now.Before(p.until) {
		return ErrInstall
	}
	head, e := p.operator.current(ctx, tx, false)
	if e != nil || head.cas != p.initial || !p.request.matchesDraft(head.record) || !requestWindow(head.record, p.request, now) {
		return ErrInstall
	}
	var active uint64
	if tx.QueryRowContext(ctx, `SELECT active_config_version FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR SHARE`, i.plan.Target.InstallationID).Scan(&active) != nil || active != 2 {
		return ErrInstall
	}
	var current []byte
	var sum string
	for _, version := range []uint64{1, 2} {
		var raw []byte
		var sha string
		var size uint64
		var enabled bool
		if tx.QueryRowContext(ctx, `SELECT canonical_config_json,config_sha256,config_size_bytes,enabled FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? FOR SHARE`, i.plan.Target.InstallationID, version).Scan(&raw, &sha, &size, &enabled) != nil || len(raw) < 2 || len(raw) > 262144 || uint64(len(raw)) != size || hash(raw) != sha || enabled != (version == 2) {
			return ErrInstall
		}
		if version == 1 {
			if !bytes.Equal(raw, p.original) || sha != head.record.ConfigSHA256 {
				return ErrInstall
			}
		} else {
			current = bytes.Clone(raw)
			sum = sha
		}
	}
	if originalEnabledOnlyRelation(p.original, current) != nil {
		return ErrInstall
	}
	pol := p.policy
	if pol.UpdatedAt.After(now) {
		return ErrInstall
	}
	var id, evidence int64
	var responseSHA string
	if tx.QueryRowContext(ctx, `SELECT id,redacted_response_evidence_id,redacted_response_sha256 FROM system_backup_v2_operations WHERE public_id=? AND origin_installation_id=? AND operation_type='config_update' AND target_type='system' AND target_public_id=? AND actor_type='admin' AND actor_id=? AND endpoint=? AND idempotency_key=? AND request_hash=? AND schema_version='system-backup-operation.v1' AND result_resource_public_id IS NULL AND retryable=FALSE AND failure_category='none' AND failure_message IS NULL AND status='succeeded' AND result_config_version=2 AND http_status=200 AND row_version=? AND created_at=? AND started_at=? AND finished_at=? AND updated_at=? AND deadline_at=? FOR SHARE`, pol.OperationPublicID, i.plan.Target.InstallationID, i.plan.Target.InstallationID, strconv.FormatInt(pol.ActorID, 10), pol.Endpoint, pol.IdempotencyKey, pol.RequestHash, pol.RowVersion, pol.CreatedAt, pol.StartedAt, pol.FinishedAt, pol.UpdatedAt, pol.DeadlineAt).Scan(&id, &evidence, &responseSHA) != nil || id < 1 || evidence < 1 || responseSHA != p.receipt.SHA256 {
		return ErrInstall
	}
	var response []byte
	var checksum string
	var size uint64
	var expires time.Time
	var evidencePublicID string
	if tx.QueryRowContext(ctx, `SELECT inline_payload,content_checksum,content_size_bytes,expires_at,public_id FROM system_backup_v2_evidence WHERE id=? AND owner_target_type='system' AND owner_target_public_id=? AND evidence_type='diagnostic' AND storage_state='inline' AND observed_health='healthy' AND encryption='none' AND media_type='application/json' AND evidence_failure_code='none' AND schema_version='system-backup-evidence.v1' AND redaction_classification='internal' AND row_version>=1 AND chunk_count=0 AND created_at=? AND storage_provider_role IS NULL AND storage_identity_hash IS NULL AND storage_ref_version IS NULL AND storage_relative_key IS NULL AND storage_relative_key_hash IS NULL AND storage_immutable_version IS NULL AND object_checksum IS NULL AND object_size_bytes IS NULL AND plaintext_chunk_size_bytes IS NULL AND chunk_list_root IS NULL AND envelope_framing_version IS NULL AND kek_identity_hash IS NULL AND kek_version IS NULL AND envelope_hash IS NULL FOR SHARE`, evidence, i.plan.Target.InstallationID, pol.FinishedAt).Scan(&response, &checksum, &size, &expires, &evidencePublicID) != nil || !regexp.MustCompile(`^sev_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(evidencePublicID) || len(response) < 2 || len(response) > 8192 || uint64(len(response)) != size || hash(response) != checksum || checksum != responseSHA || !now.Before(expires) {
		return ErrInstall
	}
	rows, e := tx.QueryContext(ctx, "SELECT chunk_index FROM system_backup_v2_evidence_chunks WHERE evidence_id=? FOR SHARE", evidence)
	if e != nil {
		return ErrInstall
	}
	extra := rows.Next()
	readErr := rows.Err()
	closeErr := rows.Close()
	if extra || readErr != nil || closeErr != nil {
		return ErrInstall
	}
	expected, e := readBootstrapSourcePin(p.receipt, 8192)
	if e != nil || !bytes.Equal(expected, response) {
		return ErrInstall
	}
	tail, e := p.operator.lockAdmin(ctx, tx)
	if e != nil || tail.Before(now) || tail.Before(p.floor) || !tail.Before(p.until) || !tail.Before(expires) || !p.operator.live(ctx) || tx.Rollback() != nil {
		return ErrInstall
	}
	if !initial && (sum != p.configSHA || !bytes.Equal(current, p.current)) {
		return ErrInstall
	}
	p.current = current
	p.configSHA = sum
	p.floor = tail
	return nil
}
func originalEnabledOnlyRelation(original, current []byte) error {
	old, e := sec.DecodeConfigValues(original)
	if e != nil || old.Enabled() {
		return ErrInstall
	}
	next, e := sec.DecodeConfigValues(current)
	if e != nil || !next.Enabled() {
		return ErrInstall
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(next.CanonicalJSON(), &fields) != nil {
		return ErrInstall
	}
	fields["enabled"] = json.RawMessage("false")
	raw, e := json.Marshal(fields)
	if e != nil {
		return ErrInstall
	}
	normalized, e := sec.DecodeConfigValues(raw)
	if e != nil || !bytes.Equal(normalized.CanonicalJSON(), old.CanonicalJSON()) {
		return ErrInstall
	}
	return nil
}
func (p *OriginalEnabledPublication) Configuration(ctx context.Context) ([]byte, uint64, string, error) {
	if p.Recheck(ctx) != nil {
		return nil, 0, "", ErrInstall
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failed {
		return nil, 0, "", ErrInstall
	}
	return bytes.Clone(p.current), p.version, p.configSHA, nil
}
func (p *OriginalEnabledPublication) WriteConfiguration(ctx context.Context, directory string) (BootstrapSourceFilePin, error) {
	raw, _, sha, e := p.Configuration(ctx)
	if e != nil {
		return BootstrapSourceFilePin{}, e
	}
	if writeNewFiles(directory, map[string][]byte{"enabled-config.json": raw}) != nil || p.Recheck(ctx) != nil {
		return BootstrapSourceFilePin{}, ErrInstall
	}
	return BootstrapSourceFilePin{File: filepath.Join(directory, "enabled-config.json"), SHA256: sha}, nil
}
