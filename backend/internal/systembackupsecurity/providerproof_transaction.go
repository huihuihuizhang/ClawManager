package systembackupsecurity

// D owns this transaction boundary. A's Prepare/Stage functions intentionally
// remain independent of authorization, nonce persistence and commit.
import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"time"
)

const ProviderRegistrationEndpoint = "registerSystemBackupProviderProof"

var (
	ErrRegistrationUnavailable   = errors.New("provider_registration_unavailable")
	ErrRegistrationPermission    = errors.New("permission_denied")
	ErrRegistrationConflict      = errors.New("idempotency_conflict")
	ErrRegistrationCommitUnknown = errors.New("provider_registration_commit_unknown")
)

// RegistrationActor must come from the authenticated session, never the body.
type RegistrationActor struct {
	UserID           int64
	Subject, Session string
	SessionExpiresAt time.Time
	SessionIssuedAt  time.Time
}

type RegistrationConfig struct {
	Version                                                int64
	ProviderRegistryVersion, ProviderRegistrySHA256        string
	StrongAuthRegistryVersion, StrongAuthRegistrySHA256    string
	RBACRegistryVersion, RBACRegistrySHA256                string
	NonceKeyVersion, NonceIdentityHash                     string
	StrongAuthMaxAge, ClockSkew, ProofMaxAge               time.Duration
	EvidenceRetention, ControlRetention, OperationDeadline time.Duration
	CapacityBytes                                          int64
}

// RegistrationAuthority is a server-side boundary, not an HTTP DTO. Each
// method must use the supplied transaction; implementations must not commit.
// Authorize checks the current authenticated session, target visibility and
// system_backup.destructive against the hash-pinned RBAC registry. Load locks
// trusted target metadata and resolves BOTH issuer registries and all required
// HMAC versions; missing mappings/keys fail closed. ReserveCapacity accounts
// for the evidence AND operation/nonce/audit metadata in the same transaction.
// There is deliberately no permissive default implementation.
type RegistrationAuthority interface {
	Authorize(context.Context, *sql.Tx, RegistrationActor, ProviderProofTarget, RegistrationConfig) error
	Load(context.Context, *sql.Tx, RegistrationActor, ProviderProofTarget, RegistrationConfig, []string, time.Time) (ProviderProofRegistrationContext, VerifyConfig, error)
	ReserveCapacity(context.Context, *sql.Tx, RegistrationConfig, int) error
}

type ProviderRegistrationService struct {
	DB             *sql.DB
	InstallationID string
	Authority      RegistrationAuthority
}

type ProviderRegistrationResult struct {
	OperationPublicID string `json:"operation_public_id"`
	EvidencePublicID  string `json:"evidence_public_id"`
	HTTPStatus        int    `json:"http_status"`
	Replayed          bool   `json:"-"`
}

// Register returns success only after Commit. A failed/uncertain commit must
// be retried with the SAME idempotency key/body, never a new evidence request.
// No external provider calls or target-state transitions occur here.
func (s ProviderRegistrationService) Register(ctx context.Context, actor RegistrationActor, raw []byte, proof Proof) (ProviderRegistrationResult, error) {
	empty := ProviderRegistrationResult{}
	if s.DB == nil || s.Authority == nil || actor.UserID <= 0 || actor.Subject == "" || actor.Session == "" ||
		!regexp.MustCompile(`^installation_[A-Za-z0-9._:-]{1,115}$`).MatchString(s.InstallationID) {
		return empty, ErrRegistrationUnavailable
	}
	r, err := DecodeProviderProofRegistration(raw)
	if err != nil {
		return empty, err
	}
	digest, err := ProviderProofRequestSHA256(r)
	if err != nil {
		return empty, err
	}
	// Missing-candidate FOR UPDATE queries below require InnoDB gap locks.
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return empty, ErrProviderEvidenceStorage
	}
	defer tx.Rollback()
	// The nonce UNIQUE constraint is global, including across installations
	// with different active HMAC versions. Serialize registry/nonce admission
	// over the installation rows before loading any key-history snapshot. This
	// also blocks a concurrent config rotation from introducing an unseen key.
	if err = lockRegistrationInstallations(ctx, tx); err != nil {
		return empty, err
	}
	cfg, err := lockRegistrationConfig(ctx, tx, s.InstallationID)
	if err != nil {
		return empty, err
	}
	// Re-check disabled/deleted users even when returning a committed retry.
	var role string
	var active bool
	err = tx.QueryRowContext(ctx, "SELECT role,is_active FROM users WHERE id=? FOR UPDATE", actor.UserID).Scan(&role, &active)
	if errors.Is(err, sql.ErrNoRows) {
		return empty, ErrRegistrationPermission
	}
	if err != nil {
		return empty, ErrProviderEvidenceStorage
	}
	if !active || role != "admin" {
		return empty, ErrRegistrationPermission
	}
	if err = s.Authority.Authorize(ctx, tx, actor, r.Target, cfg); err != nil {
		return empty, registrationBoundaryError(err)
	}
	var previous ProviderRegistrationResult
	var previousHash, status string
	err = tx.QueryRowContext(ctx, `SELECT public_id,result_resource_public_id,http_status,request_hash,status
		FROM system_backup_v2_operations WHERE origin_installation_id=? AND actor_type='admin' AND actor_id=? AND endpoint=? AND idempotency_key=? FOR UPDATE`,
		s.InstallationID, strconv.FormatInt(actor.UserID, 10), ProviderRegistrationEndpoint, r.IdempotencyKey).
		Scan(&previous.OperationPublicID, &previous.EvidencePublicID, &previous.HTTPStatus, &previousHash, &status)
	if err == nil {
		if previousHash != digest {
			return empty, ErrRegistrationConflict
		}
		if status != "succeeded" || previous.HTTPStatus != 201 || !providerEvidenceID.MatchString(previous.EvidencePublicID) {
			return empty, ErrRegistrationUnavailable
		}
		// Authentication/visibility/permission were rechecked. The committed
		// operation is the receipt: expiry of the original proof is irrelevant.
		if err = tx.Commit(); err != nil {
			return empty, ErrRegistrationCommitUnknown
		}
		previous.Replayed = true
		return previous, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return empty, ErrProviderEvidenceStorage
	}
	// Committed retries above need no new proof. A fresh request with no proof
	// has the contract's required classification, before key/nonce loading.
	if reflect.DeepEqual(proof, Proof{}) {
		return empty, &VerificationError{Code: FailureRequired, err: errors.New("strong-auth required")}
	}
	var now time.Time
	var offset int64
	if tx.QueryRowContext(ctx, `SELECT UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))`).Scan(&now, &offset) != nil || now.IsZero() || offset != 0 {
		return empty, ErrProviderEvidenceStorage
	}
	versions, err := retainedNonceVersions(ctx, tx, cfg.NonceKeyVersion, now)
	if err != nil {
		return empty, err
	}
	pc, sc, err := s.Authority.Load(ctx, tx, actor, r.Target, cfg, versions, now)
	if err != nil {
		return empty, registrationBoundaryError(err)
	}
	if pc.Scope.InstallationID != s.InstallationID || pc.RegistryVersion != cfg.ProviderRegistryVersion || pc.RegistrySHA256 != cfg.ProviderRegistrySHA256 ||
		sc.ExpectedAudience == "" || sc.ExpectedSubject != actor.Subject || sc.ExpectedSession != actor.Session || sc.ActiveNonceHMACKeyVersion != cfg.NonceKeyVersion {
		return empty, ErrRegistrationUnavailable
	}
	// Policies and time come only from locked persistent config / DB clock.
	pc.DatabaseNow, pc.MaxAge, pc.ClockSkew, pc.RetainUntil = now, cfg.ProofMaxAge, cfg.ClockSkew, now.Add(cfg.EvidenceRetention)
	sc.Now, sc.MaxAge, sc.ClockSkew, sc.RequiredNonceHMACKeyVersions = now, cfg.StrongAuthMaxAge, cfg.ClockSkew, versions
	vr, err := Verify(proof, RequestBinding{Issuer: proof.Payload.Issuer, Audience: sc.ExpectedAudience, Subject: actor.Subject, Session: actor.Session,
		Endpoint: ProviderRegistrationEndpoint, RequestHash: digest, IdempotencyKey: r.IdempotencyKey}, sc)
	if err != nil {
		return empty, registrationBoundaryError(err)
	}
	for _, candidate := range vr.NonceHMACCandidates {
		var id int64
		err = tx.QueryRowContext(ctx, `SELECT id FROM system_backup_v2_strong_auth_nonces WHERE nonce_hmac=? AND nonce_hmac_key_version=? FOR UPDATE`, candidate.HMAC, candidate.KeyVersion).Scan(&id)
		if err == nil {
			return empty, &VerificationError{Code: FailureReplayed, err: errors.New("nonce already consumed")}
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return empty, ErrProviderEvidenceStorage
		}
	}
	prepared, err := PrepareProviderProofEvidence(r, pc)
	if err != nil {
		return empty, err
	}
	if err = s.Authority.ReserveCapacity(ctx, tx, cfg, prepared.ContentSize()); err != nil {
		return empty, registrationBoundaryError(err)
	}
	opID, err := registrationID("sop_")
	if err != nil {
		return empty, ErrRegistrationUnavailable
	}
	evID, err := registrationID("sev_")
	if err != nil {
		return empty, ErrRegistrationUnavailable
	}
	intentID, err := registrationAudit(ctx, tx, actor.UserID, "system_backup.provider_proof.intent", opID, evID, r.Target, digest)
	if err != nil {
		return empty, err
	}
	if err = StageProviderProofEvidence(ctx, tx, evID, prepared); err != nil {
		return empty, err
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO system_backup_v2_operations
		(public_id,origin_installation_id,operation_type,target_type,target_public_id,actor_type,actor_id,endpoint,idempotency_key,request_hash,
		external_action_public_ids_canonical_json,external_action_public_ids_size_bytes,external_action_public_ids_sha256,status,result_resource_public_id,http_status,deadline_at,started_at,finished_at,created_at)
		VALUES (?,?,'provider_proof_register',?,?,'admin',?,?,?,?,?,2,?,'succeeded',?,201,?,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))`,
		opID, s.InstallationID, r.Target.TargetType, r.Target.TargetPublicID, strconv.FormatInt(actor.UserID, 10), ProviderRegistrationEndpoint, r.IdempotencyKey, digest,
		[]byte("[]"), registrationHash("[]"), evID, now.Add(cfg.OperationDeadline))
	if err != nil {
		return empty, ErrProviderEvidenceStorage
	}
	operationID, err := res.LastInsertId()
	if err != nil || operationID <= 0 {
		return empty, ErrProviderEvidenceStorage
	}
	authAt, expiresAt, err := parseTimes(proof.Payload)
	if err != nil {
		return empty, ErrRegistrationUnavailable
	}
	// The ledger records server-side proof acceptance, not the issuer's signed
	// auth_time (which may be in the future within the configured clock skew).
	// Preserve the original age/expiry ceiling and reject a SQL clock that moved
	// behind the actual verification sample while callbacks/writes were running.
	res, err = tx.ExecContext(ctx, `INSERT INTO system_backup_v2_strong_auth_nonces
		(origin_installation_id,issuer_sha256,subject_sha256,session_sha256,nonce_hmac,nonce_hmac_key_version,endpoint,request_hash,idempotency_key,
		authenticated_at,expires_at,consumed_at,operation_id,audit_log_id,retain_until)
		SELECT ?,?,?,?,?,?,?,?,?,?,?,UTC_TIMESTAMP(6),?,?,?
		WHERE UTC_TIMESTAMP(6)>=? AND UTC_TIMESTAMP(6)<? AND UTC_TIMESTAMP(6)<=?`,
		s.InstallationID, registrationHash(proof.Payload.Issuer), registrationHash(actor.Subject), registrationHash(actor.Session), vr.NonceHMAC, vr.NonceHMACKeyVersion,
		ProviderRegistrationEndpoint, digest, r.IdempotencyKey, now, expiresAt, operationID, intentID, expiresAt.Add(cfg.ControlRetention), now, expiresAt, authAt.Add(cfg.StrongAuthMaxAge).Add(cfg.ClockSkew))
	if err != nil {
		return empty, ErrProviderEvidenceStorage
	}
	count, err := res.RowsAffected()
	if err != nil {
		return empty, ErrProviderEvidenceStorage
	}
	if count != 1 {
		return empty, &VerificationError{Code: FailureExpired, err: errors.New("strong-auth validity ended before consumption")}
	}
	if _, err = registrationAudit(ctx, tx, actor.UserID, "system_backup.provider_proof.succeeded", opID, evID, r.Target, digest); err != nil {
		return empty, err
	}
	if err = tx.Commit(); err != nil {
		return empty, ErrRegistrationCommitUnknown
	}
	return ProviderRegistrationResult{OperationPublicID: opID, EvidencePublicID: evID, HTTPStatus: 201}, nil
}

func registrationBoundaryError(err error) error {
	if err == ErrSensitiveDownloadRequest {
		return ErrSensitiveDownloadRequest
	}
	var auth *VerificationError
	if errors.As(err, &auth) {
		if auth != nil {
			switch auth.Code {
			case FailureRequired, FailureInvalid, FailureInvalidIssuer, FailureExpired, FailureReplayed:
				return &VerificationError{Code: auth.Code, err: errors.New("strong-auth rejected")}
			}
		}
		// A typed error is not permission to publish an arbitrary adapter code.
		// Nil and unknown classifications are unavailable, with no private cause.
		return ErrRegistrationUnavailable
	}
	if errors.Is(err, ErrRegistrationPermission) {
		return ErrRegistrationPermission
	}
	return ErrRegistrationUnavailable
}

func lockRegistrationConfig(ctx context.Context, tx *sql.Tx, installation string) (RegistrationConfig, error) {
	var c RegistrationConfig
	if err := tx.QueryRowContext(ctx, "SELECT active_config_version FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR UPDATE", installation).Scan(&c.Version); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return c, ErrRegistrationUnavailable
		}
		return c, ErrProviderEvidenceStorage
	}
	var authAge, skew, proofAge, evidenceRetention, controlRetention, deadline int64
	err := tx.QueryRowContext(ctx, `SELECT provider_proof_issuers_registry_version,provider_proof_issuers_registry_sha256,
		strong_auth_issuers_registry_version,strong_auth_issuers_registry_sha256,rbac_bindings_registry_version,rbac_bindings_registry_sha256,
		nonce_hmac_ref_version,nonce_hmac_identity_hash,strong_auth_max_age_seconds,strong_auth_clock_skew_seconds,provider_proof_max_age_seconds,evidence_retention_seconds,
		control_metadata_retention_seconds,operation_deadline_seconds,control_metadata_capacity_bytes FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? FOR UPDATE`, installation, c.Version).
		Scan(&c.ProviderRegistryVersion, &c.ProviderRegistrySHA256, &c.StrongAuthRegistryVersion, &c.StrongAuthRegistrySHA256, &c.RBACRegistryVersion, &c.RBACRegistrySHA256,
			&c.NonceKeyVersion, &c.NonceIdentityHash, &authAge, &skew, &proofAge, &evidenceRetention, &controlRetention, &deadline, &c.CapacityBytes)
	if err != nil {
		return c, ErrProviderEvidenceStorage
	}
	if !providerHashPattern.MatchString(c.NonceIdentityHash) || authAge < 60 || authAge > 900 || skew < 0 || skew > 120 || proofAge < 60 || proofAge > 3600 || evidenceRetention < 86400 || evidenceRetention > 31536000 ||
		controlRetention < 2592000 || controlRetention > 157680000 || deadline < 60 || deadline > 86400 || c.CapacityBytes <= 0 {
		return c, ErrRegistrationUnavailable
	}
	c.StrongAuthMaxAge = time.Duration(authAge) * time.Second
	c.ClockSkew = time.Duration(skew) * time.Second
	c.ProofMaxAge = time.Duration(proofAge) * time.Second
	c.EvidenceRetention = time.Duration(evidenceRetention) * time.Second
	c.ControlRetention = time.Duration(controlRetention) * time.Second
	c.OperationDeadline = time.Duration(deadline) * time.Second
	return c, nil
}

func lockRegistrationInstallations(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, "SELECT origin_installation_id FROM system_backup_v2_installation_state ORDER BY origin_installation_id FOR UPDATE")
	if err != nil {
		return ErrProviderEvidenceStorage
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			return ErrProviderEvidenceStorage
		}
		count++
		if count > 10000 {
			return ErrRegistrationUnavailable
		}
	}
	if rows.Err() != nil {
		return ErrProviderEvidenceStorage
	}
	return nil
}

func retainedNonceVersions(ctx context.Context, tx *sql.Tx, active string, now time.Time) ([]string, error) {
	// Retained ledger versions are global because the existing unique nonce
	// constraint is global. Missing key material must never shrink this list.
	rows, err := tx.QueryContext(ctx, `SELECT nonce_hmac_ref_version FROM system_backup_v2_configs
		UNION SELECT nonce_hmac_key_version FROM system_backup_v2_strong_auth_nonces WHERE retain_until>? ORDER BY 1`, now)
	if err != nil {
		return nil, ErrProviderEvidenceStorage
	}
	defer rows.Close()
	var versions []string
	found := false
	for rows.Next() {
		var v string
		if rows.Scan(&v) != nil || v == "" {
			return nil, ErrProviderEvidenceStorage
		}
		versions = append(versions, v)
		found = found || v == active
	}
	if rows.Err() != nil {
		return nil, ErrProviderEvidenceStorage
	}
	if !found {
		return nil, ErrRegistrationUnavailable
	}
	return versions, nil
}

func registrationAudit(ctx context.Context, tx *sql.Tx, user int64, action, op, evidence string, target ProviderProofTarget, digest string) (int64, error) {
	// Closed redacted payload; never include proof/nonce/session/key material.
	details, _ := json.Marshal(struct {
		Operation   string              `json:"operation_public_id"`
		Evidence    string              `json:"evidence_public_id"`
		Target      ProviderProofTarget `json:"target"`
		RequestHash string              `json:"request_hash"`
	}{op, evidence, target, digest})
	result, err := tx.ExecContext(ctx, "INSERT INTO audit_logs (user_id,action,resource_type,details) VALUES (?,?,'system_backup',?)", user, action, string(details))
	if err != nil {
		return 0, ErrProviderEvidenceStorage
	}
	id, err := result.LastInsertId()
	if err != nil || id <= 0 {
		return 0, ErrProviderEvidenceStorage
	}
	return id, nil
}

func registrationHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
func registrationID(prefix string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%s%x-%x-%x-%x-%x", prefix, b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
