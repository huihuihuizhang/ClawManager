package systembackupsecurity

import (
	"bytes"
	"context"
	"database/sql"
	"strconv"
	"sync"
	"time"
)

// SQLOperationResponses is the public config mutation response adapter. The
// complete closed Operation fits inline; no provider, KEK or diagnostic
// publication authority is needed to store its exact original success bytes.
type SQLOperationResponses struct {
	db           *sql.DB
	database     DatabaseIdentity
	installation string
	authority    *SQLConfigMutationReplayAuthorizer
}

var _ ConfigMutationResponses = (*SQLOperationResponses)(nil)

func NewSQLOperationResponses(db *sql.DB, database DatabaseIdentity, installation string, sessions *SQLLoginSessions, registryDirectory string) (*SQLOperationResponses, error) {
	if db == nil {
		return nil, ErrRegistrationUnavailable
	}
	a, err := NewSQLConfigMutationReplayAuthorizer(installation, database, sessions, registryDirectory)
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	return &SQLOperationResponses{db, database, installation, a}, nil
}
func (s *SQLOperationResponses) Prepare(ctx context.Context, p ConfigMutationOperationPreparation) (PreparedConfigMutationOperationResponse, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || p.database != s.database || p.installation != s.installation || !time.Now().Before(p.until) {
		return nil, ErrRegistrationUnavailable
	}
	if !configMutationOperationID.MatchString(p.operation) || !providerHashPattern.MatchString(p.hash) || p.version < 2 || p.version > 9007199254740991 || !configOperationResponseTime(p.created) || !p.created.Before(p.until) || p.until.After(p.deadline) || p.retentionSeconds < 1 {
		return nil, ErrRegistrationUnavailable
	}
	return &stagedConfigOperationResponse{plan: p}, nil
}

type stagedConfigOperationResponse struct {
	plan   ConfigMutationOperationPreparation
	mu     sync.Mutex
	tx     *sql.Tx
	id     int64
	policy ConfigOperationResponsePolicy
	raw    []byte
	retain time.Time
}

func (p *stagedConfigOperationResponse) ValidUntil() time.Time { return p.plan.until }
func (p *stagedConfigOperationResponse) Stage(ctx context.Context, tx *sql.Tx, policy ConfigOperationResponsePolicy, raw []byte, retain time.Time) (int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.id != 0 || ctx == nil || ctx.Err() != nil || tx == nil || p.plan.database.check(ctx, tx) != nil {
		return 0, ErrRegistrationUnavailable
	}
	expected, bytesExpected, expiry, err := p.plan.terminal(policy.FinishedAt)
	policyBytes, e := CanonicalConfigOperationResponse(policy)
	if err != nil || e != nil || !bytes.Equal(bytesExpected, raw) || !bytes.Equal(policyBytes, raw) || !expiry.Equal(retain) {
		return 0, ErrRegistrationUnavailable
	}
	now, err := configMutationClock(ctx, tx)
	if err != nil || now.Before(policy.UpdatedAt) || !now.Before(p.plan.until) || !configMutationSessionAt(p.plan.actor, now) {
		return 0, ErrRegistrationUnavailable
	}
	id, err := registrationID("sev_")
	if err != nil {
		return 0, ErrRegistrationUnavailable
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO system_backup_v2_evidence (public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,inline_payload,content_checksum,content_size_bytes,media_type,encryption,redaction_classification,observed_health,expires_at,created_at) SELECT ?,'system',?,'diagnostic','inline',?,?,?,'application/json','none','internal','healthy',?,? WHERE UTC_TIMESTAMP(6)>=? AND UTC_TIMESTAMP(6)<?`, id, p.plan.installation, raw, registrationHash(string(raw)), len(raw), retain.UTC(), policy.FinishedAt.UTC(), policy.FinishedAt.UTC(), p.plan.until.UTC())
	if err != nil {
		return 0, ErrProviderEvidenceStorage
	}
	if !configMutationOne(result, nil) {
		return 0, ErrRegistrationUnavailable
	}
	dbID, err := result.LastInsertId()
	if err != nil || dbID < 1 {
		return 0, ErrProviderEvidenceStorage
	}
	p.tx, p.id, p.policy, p.raw, p.retain = tx, dbID, expected, append([]byte(nil), raw...), retain
	return dbID, nil
}
func (p *stagedConfigOperationResponse) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.id < 1 || p.tx != tx || !now.Before(p.plan.until) {
		return ErrRegistrationUnavailable
	}
	in, err := NewConfigMutationResponseReplayPreparation(ConfigMutationResponseReplayFacts{Database: p.plan.database, Installation: p.plan.installation, Actor: p.plan.actor, Operation: p.plan.operation, Endpoint: p.plan.endpoint, IdempotencyKey: p.plan.key, RequestHash: p.plan.hash, EvidenceID: p.id, ResponseHash: registrationHash(string(p.raw)), Version: p.plan.version, AuthorizedAt: p.plan.created, ValidUntil: p.plan.until})
	if err != nil {
		return ErrRegistrationUnavailable
	}
	snap, err := loadConfigOperationResponse(ctx, tx, in, now)
	if err != nil || !bytes.Equal(snap.raw, p.raw) || !snap.expiry.Equal(p.retain) {
		return ErrRegistrationUnavailable
	}
	return nil
}

type configOperationResponseSnapshot struct {
	policy                 ConfigOperationResponsePolicy
	evidenceID, rowVersion int64
	publicID, checksum     string
	raw                    []byte
	created, expiry        time.Time
}

func equalConfigOperationSnapshots(a, b configOperationResponseSnapshot) bool {
	aBytes, _ := CanonicalConfigOperationResponse(a.policy)
	bBytes, _ := CanonicalConfigOperationResponse(b.policy)
	return len(aBytes) > 0 && bytes.Equal(aBytes, bBytes) && a.evidenceID == b.evidenceID && a.rowVersion == b.rowVersion && a.publicID == b.publicID && a.checksum == b.checksum && bytes.Equal(a.raw, b.raw) && a.created.Equal(b.created) && a.expiry.Equal(b.expiry)
}
func loadConfigOperationResponse(ctx context.Context, tx *sql.Tx, in ConfigMutationResponseReplayPreparation, now time.Time) (configOperationResponseSnapshot, error) {
	f := in.Facts()
	fail := func() (configOperationResponseSnapshot, error) {
		return configOperationResponseSnapshot{}, ErrRegistrationUnavailable
	}
	if ctx == nil || ctx.Err() != nil || tx == nil || now.Before(f.AuthorizedAt) || !now.Before(f.ValidUntil) || !configMutationSessionAt(f.Actor, now) || f.Database.check(ctx, tx) != nil {
		return fail()
	}
	s := configOperationResponseSnapshot{}
	p := &s.policy
	var schema, kind, targetType, targetID, actorType, actorID, status, failure string
	var resultResource, failureMessage sql.NullString
	var retryable bool
	var httpStatus int
	err := tx.QueryRowContext(ctx, `SELECT schema_version,public_id,origin_installation_id,operation_type,target_type,target_public_id,actor_type,actor_id,endpoint,idempotency_key,request_hash,status,result_resource_public_id,result_config_version,retryable,failure_category,failure_message,http_status,row_version,deadline_at,started_at,finished_at,created_at,updated_at,redacted_response_evidence_id,redacted_response_sha256 FROM system_backup_v2_operations WHERE origin_installation_id=? AND actor_type='admin' AND actor_id=? AND endpoint=? AND idempotency_key=? AND public_id=? FOR UPDATE`, f.Installation, strconv.FormatInt(f.Actor.UserID, 10), f.Endpoint, f.IdempotencyKey, f.Operation).Scan(&schema, &p.OperationPublicID, &p.InstallationID, &kind, &targetType, &targetID, &actorType, &actorID, &p.Endpoint, &p.IdempotencyKey, &p.RequestHash, &status, &resultResource, &p.Version, &retryable, &failure, &failureMessage, &httpStatus, &p.RowVersion, &p.DeadlineAt, &p.StartedAt, &p.FinishedAt, &p.CreatedAt, &p.UpdatedAt, &s.evidenceID, &s.checksum)
	if err != nil || schema != "system-backup-operation.v1" || p.OperationPublicID != f.Operation || p.InstallationID != f.Installation || kind != "config_update" || targetType != "system" || targetID != f.Installation || actorType != "admin" || actorID != strconv.FormatInt(f.Actor.UserID, 10) || p.Endpoint != f.Endpoint || p.IdempotencyKey != f.IdempotencyKey || p.RequestHash != f.RequestHash || status != "succeeded" || resultResource.Valid || p.Version != f.Version || retryable || failure != "none" || failureMessage.Valid || httpStatus != 200 || s.evidenceID != f.EvidenceID || s.checksum != f.ResponseHash {
		return fail()
	}
	p.ActorID = f.Actor.UserID
	var ownerType, owner, evidenceType, state, eFailure, health, media, encryption, classification string
	var size, count, id int64
	err = tx.QueryRowContext(ctx, `SELECT id,schema_version,public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,evidence_failure_code,observed_health,inline_payload,content_checksum,content_size_bytes,media_type,encryption,redaction_classification,expires_at,created_at,row_version,chunk_count FROM system_backup_v2_evidence WHERE id=? FOR UPDATE`, f.EvidenceID).Scan(&id, &schema, &s.publicID, &ownerType, &owner, &evidenceType, &state, &eFailure, &health, &s.raw, &s.checksum, &size, &media, &encryption, &classification, &s.expiry, &s.created, &s.rowVersion, &count)
	if err != nil || id != f.EvidenceID || schema != "system-backup-evidence.v1" || !providerEvidenceID.MatchString(s.publicID) || ownerType != "system" || owner != f.Installation || evidenceType != "diagnostic" || state != "inline" || eFailure != "none" || health != "healthy" || size < 2 || size > MaxConfigOperationResponseBytes || size != int64(len(s.raw)) || s.checksum != f.ResponseHash || registrationHash(string(s.raw)) != f.ResponseHash || media != "application/json" || encryption != "none" || classification != "internal" || s.rowVersion < 1 || count != 0 || !s.created.Equal(p.FinishedAt) || !now.Before(s.expiry) {
		return fail()
	}
	expected, err := CanonicalConfigOperationResponse(*p)
	if err != nil || !bytes.Equal(expected, s.raw) || p.UpdatedAt.After(now) {
		return fail()
	}
	// Inline means SQL NULL, not empty external metadata. Keep the parent row
	// locked while proving no chunk rows exist, including an unexpected one.
	var fields [14]any
	dest := make([]any, len(fields))
	for i := range fields {
		dest[i] = &fields[i]
	}
	if tx.QueryRowContext(ctx, `SELECT storage_provider_role,storage_identity_hash,storage_ref_version,storage_relative_key,storage_relative_key_hash,storage_immutable_version,object_checksum,object_size_bytes,plaintext_chunk_size_bytes,chunk_list_root,envelope_framing_version,kek_identity_hash,kek_version,envelope_hash FROM system_backup_v2_evidence WHERE id=? FOR UPDATE`, f.EvidenceID).Scan(dest...) != nil {
		return fail()
	}
	for _, v := range fields {
		if v != nil {
			return fail()
		}
	}
	rows, err := tx.QueryContext(ctx, "SELECT chunk_index FROM system_backup_v2_evidence_chunks WHERE evidence_id=? FOR UPDATE", f.EvidenceID)
	if err != nil {
		return fail()
	}
	extra := rows.Next()
	readErr := rows.Err()
	closeErr := rows.Close()
	if extra || readErr != nil || closeErr != nil || ctx.Err() != nil {
		return fail()
	}
	s.raw = append([]byte(nil), s.raw...)
	return s, nil
}

type configOperationResponseRead struct {
	store    *SQLOperationResponses
	input    ConfigMutationResponseReplayPreparation
	snapshot configOperationResponseSnapshot
	until    time.Time
}

func (r *configOperationResponseRead) Bytes() []byte         { return append([]byte(nil), r.snapshot.raw...) }
func (r *configOperationResponseRead) ValidUntil() time.Time { return r.until }
func (r *configOperationResponseRead) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if ctx == nil || ctx.Err() != nil || tx == nil || !now.Before(r.until) || r.store.authority.AuthorizeReplay(ctx, tx, r.input, now) != nil {
		return ErrRegistrationUnavailable
	}
	s, err := loadConfigOperationResponse(ctx, tx, r.input, now)
	if err != nil || !equalConfigOperationSnapshots(s, r.snapshot) || r.store.authority.AuthorizeReplay(ctx, tx, r.input, now) != nil {
		return ErrRegistrationUnavailable
	}
	return nil
}
func (s *SQLOperationResponses) Read(ctx context.Context, input ConfigMutationResponseReplayPreparation) (PreparedConfigMutationResponseRead, error) {
	f := input.Facts()
	fail := func() (PreparedConfigMutationResponseRead, error) { return nil, ErrRegistrationUnavailable }
	if s == nil || ctx == nil || ctx.Err() != nil || s.authority == nil || f.Database != s.database || f.Installation != s.installation {
		return fail()
	}
	if _, err := NewConfigMutationResponseReplayPreparation(f); err != nil {
		return fail()
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return fail()
	}
	defer tx.Rollback()
	now, err := configMutationClock(ctx, tx)
	if err != nil || s.authority.AuthorizeReplay(ctx, tx, input, now) != nil {
		return fail()
	}
	snap, err := loadConfigOperationResponse(ctx, tx, input, now)
	if err != nil {
		return fail()
	}
	until := f.ValidUntil
	if snap.expiry.Before(until) {
		until = snap.expiry
	}
	r := &configOperationResponseRead{s, input, snap, until}
	now, err = configMutationClock(ctx, tx)
	if err != nil || r.Recheck(ctx, tx, now) != nil {
		return fail()
	}
	if tx.Rollback() != nil {
		return fail()
	}
	return r, nil
}
