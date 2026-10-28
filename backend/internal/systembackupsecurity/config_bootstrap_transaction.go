package systembackupsecurity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	pd "clawreef/internal/systembackupproducer"
)

const BootstrapConfigEndpoint = "bootstrapSystemBackupConfig"

var ErrBootstrapExists = errors.New("bootstrap_already_initialized")

// OfflineBootstrapGrant comes from deployment/operator authorization. It MUST
// NOT be deserialized from an HTTP request. First security_admin authorization
// is an offline operation; the regular HTTP configuration API cannot grant it.
type OfflineBootstrapGrant struct {
	InstallationID, ServerUUID, Database, Username        string
	UserID                                                int64
	MatrixKey, ConfigSHA256, IdempotencyKey, ChangeReason string
}

// BootstrapAdmission is mandatory deployment integration, with no allow-all
// default. Authorize must validate a live, immutable operator grant and RBAC
// (including committed retries). ValidateAndReserve must resolve and validate
// ALL nine registries and twenty typed refs, issuer purpose/key separation,
// retention and nonce keys, and reserve metadata capacity in the supplied tx.
// Network/provider work must be completed before acquiring transaction locks.
// Implementations must neither commit nor substitute placeholder resources.
type BootstrapAdmission interface {
	Authorize(context.Context, *sql.Tx, OfflineBootstrapGrant, BootstrapConfig, time.Time) error
	ValidateAndReserve(context.Context, *sql.Tx, OfflineBootstrapGrant, BootstrapConfig, time.Time) error
}
type ConfigBootstrapService struct {
	DB                *sql.DB
	Admission         BootstrapAdmission
	CanonicalSnapshot bool                       // Isolated candidate path until the column is formally migrated.
	Candidates        *ConfigBootstrapCandidates // Explicit trusted candidate assembly; never an HTTP input.
}
type ConfigBootstrapResult struct {
	OperationPublicID string `json:"operation_public_id"`
	Version           int64  `json:"version"`
	ConfigSHA256      string `json:"config_sha256"`
	Replayed          bool   `json:"replayed"`
}

// Bootstrap creates a disabled config v1, installation state, operation receipt
// and both audits atomically. It never updates an existing installation/config
// and is deliberately not registered on the HTTP listener.
func (s ConfigBootstrapService) Bootstrap(ctx context.Context, g OfflineBootstrapGrant, raw []byte) (ConfigBootstrapResult, error) {
	var zero ConfigBootstrapResult
	c, err := DecodeBootstrapConfig(raw)
	if err != nil {
		return zero, err
	}
	if s.Candidates != nil {
		return s.Candidates.bootstrap(ctx, s.DB, g, c, s.CanonicalSnapshot)
	}
	if candidateAuthorityNil(ctx) || ctx.Err() != nil || s.DB == nil || candidateAuthorityNil(s.Admission) || !validBootstrapGrant(g) || c.SHA256() != g.ConfigSHA256 {
		return zero, ErrRegistrationUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(c.numbers["operation_deadline_seconds"])*time.Second)
	defer cancel()
	return s.bootstrapLegacyPrepared(ctx, g, c)
}

// bootstrapLegacyPrepared keeps the deployment preparation context unchanged.
// The caller creates its one operation deadline before resource preparation;
// all original authorization, locking and final checks still run here.
func (s ConfigBootstrapService) bootstrapLegacyPrepared(ctx context.Context, g OfflineBootstrapGrant, c BootstrapConfig) (ConfigBootstrapResult, error) {
	var zero ConfigBootstrapResult
	if candidateAuthorityNil(ctx) || ctx.Err() != nil || s.DB == nil || candidateAuthorityNil(s.Admission) || !validBootstrapGrant(g) || c.SHA256() != g.ConfigSHA256 {
		return zero, ErrRegistrationUnavailable
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return zero, ErrRegistrationUnavailable
	}
	// Include all grant semantics, not transport formatting, in idempotency.
	binding, _ := json.Marshal(g)
	digest := registrationHash(string(binding))
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return zero, ErrProviderEvidenceStorage
	}
	defer tx.Rollback()
	var server, database string
	var now time.Time
	var offset int64
	if tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))").Scan(&server, &database, &now, &offset) != nil {
		return zero, ErrProviderEvidenceStorage
	}
	if server != g.ServerUUID || database != g.Database || !bootstrapInlineSQLTime(now) || offset != 0 {
		return zero, ErrRegistrationUnavailable
	}
	until := now.Add(time.Duration(c.numbers["operation_deadline_seconds"]) * time.Second)
	// Match the registration transaction lock order. An empty index is still
	// gap-locked under RepeatableRead; deadlock victims retry the same request.
	if err = lockRegistrationInstallations(ctx, tx); err != nil {
		return zero, err
	}
	if err = lockInlineBootstrapConfigs(ctx, tx); err != nil {
		return zero, err
	}
	fence, err := pd.LockBootstrapInlineDomain(ctx, tx, pd.Scope{ServerUUID: pd.ServerUUID(g.ServerUUID), Database: pd.Database(g.Database), Installation: pd.Installation(g.InstallationID)})
	if err != nil {
		return zero, candidateBootstrapError(err)
	}
	if now, err = bootstrapInlineNow(ctx, tx, g, now, until); err != nil {
		return zero, err
	}
	var username, role, provider string
	var active bool
	err = tx.QueryRowContext(ctx, "SELECT username,role,is_active,auth_provider FROM users WHERE id=? FOR UPDATE", g.UserID).Scan(&username, &role, &active, &provider)
	if errors.Is(err, sql.ErrNoRows) {
		return zero, ErrRegistrationPermission
	}
	if err != nil {
		return zero, ErrProviderEvidenceStorage
	}
	if username != g.Username || role != "admin" || !active || provider != "local" {
		return zero, ErrRegistrationPermission
	}
	if err = s.Admission.Authorize(ctx, tx, g, c, now); err != nil {
		return zero, registrationBoundaryError(err)
	}
	actor := strconv.FormatInt(g.UserID, 10)
	var prior ConfigBootstrapResult
	var priorHash, status string
	var httpStatus int
	err = tx.QueryRowContext(ctx, `SELECT public_id,result_config_version,request_hash,status,http_status FROM system_backup_v2_operations
		WHERE origin_installation_id=? AND actor_type='admin' AND actor_id=? AND endpoint=? AND idempotency_key=? FOR UPDATE`, g.InstallationID, actor, BootstrapConfigEndpoint, g.IdempotencyKey).
		Scan(&prior.OperationPublicID, &prior.Version, &priorHash, &status, &httpStatus)
	if err == nil {
		if err = fence.CheckLegacyBranch(ctx, tx, pd.Hash(g.ConfigSHA256), true); err != nil {
			return zero, candidateBootstrapError(err)
		}
		if priorHash != digest {
			return zero, ErrRegistrationConflict
		}
		var configHash, matrix string
		var version int64
		var enabled bool
		if tx.QueryRowContext(ctx, `SELECT c.config_sha256,s.active_config_version,c.enabled,s.matrix_key FROM system_backup_v2_installation_state s
			JOIN system_backup_v2_configs c ON c.origin_installation_id=s.origin_installation_id AND c.version=s.active_config_version
			WHERE s.origin_installation_id=? FOR UPDATE`, g.InstallationID).Scan(&configHash, &version, &enabled, &matrix) != nil {
			return zero, ErrRegistrationUnavailable
		}
		if status != "succeeded" || prior.Version != 1 || httpStatus != 201 || version != 1 || enabled || configHash != g.ConfigSHA256 || matrix != g.MatrixKey {
			return zero, ErrBootstrapExists
		}
		if err = s.finishInlineBootstrap(ctx, tx, g, c, fence, prior.OperationPublicID, digest, now, until); err != nil {
			return zero, err
		}
		if err = tx.Commit(); err != nil {
			return zero, ErrRegistrationCommitUnknown
		}
		prior.ConfigSHA256 = g.ConfigSHA256
		prior.Replayed = true
		return prior, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return zero, ErrProviderEvidenceStorage
	}
	if err = fence.CheckLegacyBranch(ctx, tx, pd.Hash(g.ConfigSHA256), false); err != nil {
		return zero, candidateBootstrapError(err)
	}
	// Reject both a previously initialized installation and orphan config rows.
	for _, q := range []string{"SELECT active_config_version FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR UPDATE", "SELECT version FROM system_backup_v2_configs WHERE origin_installation_id=? ORDER BY version FOR UPDATE"} {
		var version int64
		err = tx.QueryRowContext(ctx, q, g.InstallationID).Scan(&version)
		if err == nil {
			return zero, ErrBootstrapExists
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return zero, ErrProviderEvidenceStorage
		}
	}
	if now, err = bootstrapInlineNow(ctx, tx, g, now, until); err != nil {
		return zero, err
	}
	if err = s.Admission.ValidateAndReserve(ctx, tx, g, c, now); err != nil {
		return zero, registrationBoundaryError(err)
	}
	op, err := registrationID("sop_")
	if err != nil {
		return zero, ErrRegistrationUnavailable
	}
	if err = writeBootstrapConfigRows(ctx, tx, g, c, op, digest, now, s.CanonicalSnapshot); err != nil {
		return zero, err
	}
	if err = s.finishInlineBootstrap(ctx, tx, g, c, fence, op, digest, now, until); err != nil {
		return zero, err
	}
	if err = tx.Commit(); err != nil {
		return zero, ErrRegistrationCommitUnknown
	}
	return ConfigBootstrapResult{OperationPublicID: op, Version: 1, ConfigSHA256: g.ConfigSHA256}, nil
}

func bootstrapInlineSQLTime(now time.Time) bool {
	_, offset := now.Zone()
	return !now.IsZero() && now.Year() >= 1000 && now.Year() <= 9999 && offset == 0 && now.Nanosecond()%1000 == 0
}

func bootstrapInlineNow(ctx context.Context, tx *sql.Tx, g OfflineBootstrapGrant, floor, until time.Time) (time.Time, error) {
	if ctx.Err() != nil {
		return time.Time{}, ErrRegistrationUnavailable
	}
	var server, database string
	var now time.Time
	var offset int64
	if tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))").Scan(&server, &database, &now, &offset) != nil {
		return time.Time{}, ErrProviderEvidenceStorage
	}
	if server != g.ServerUUID || database != g.Database || offset != 0 || !bootstrapInlineSQLTime(now) || now.Before(floor) || !now.Before(until) || ctx.Err() != nil {
		return time.Time{}, ErrRegistrationUnavailable
	}
	return now, nil
}

func lockInlineBootstrapConfigs(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, bootstrapCandidateGlobalConfigSQL)
	if err != nil {
		return ErrProviderEvidenceStorage
	}
	defer rows.Close()
	for rows.Next() {
		var values [7]any
		dest := make([]any, len(values))
		for i := range values {
			dest[i] = &values[i]
		}
		if ctx.Err() != nil || rows.Scan(dest...) != nil {
			return ErrProviderEvidenceStorage
		}
	}
	if rows.Err() != nil || rows.Close() != nil {
		return ErrProviderEvidenceStorage
	}
	return nil
}

// Recheck current independent authorization before fixed SQL readback. This is
// a legacy compatibility path, not authority to consume an unconfigured domain.
// No resource validation/reservation is repeated and no epoch is changed here.
func (s ConfigBootstrapService) finishInlineBootstrap(ctx context.Context, tx *sql.Tx, g OfflineBootstrapGrant, c BootstrapConfig, fence *pd.BootstrapInlineDomainFence, op, hash string, floor, until time.Time) error {
	now, err := bootstrapInlineNow(ctx, tx, g, floor, until)
	if err != nil {
		return err
	}
	if err = s.Admission.Authorize(ctx, tx, g, c, now); err != nil {
		return registrationBoundaryError(err)
	}
	var username, role, provider string
	var active bool
	if tx.QueryRowContext(ctx, "SELECT username,role,is_active,auth_provider FROM users WHERE id=? FOR UPDATE", g.UserID).Scan(&username, &role, &active, &provider) != nil || username != g.Username || role != "admin" || !active || provider != "local" {
		return ErrRegistrationPermission
	}
	var actualOp, actualHash, status string
	var version, httpStatus int64
	if tx.QueryRowContext(ctx, `SELECT public_id,result_config_version,request_hash,status,http_status FROM system_backup_v2_operations WHERE origin_installation_id=? AND actor_type='admin' AND actor_id=? AND endpoint=? AND idempotency_key=? FOR UPDATE`, g.InstallationID, strconv.FormatInt(g.UserID, 10), BootstrapConfigEndpoint, g.IdempotencyKey).Scan(&actualOp, &version, &actualHash, &status, &httpStatus) != nil || actualOp != op || version != 1 || actualHash != hash || status != "succeeded" || httpStatus != 201 {
		return ErrRegistrationConflict
	}
	var configHash, matrix string
	var activeVersion int64
	var enabled bool
	if tx.QueryRowContext(ctx, `SELECT c.config_sha256,s.active_config_version,c.enabled,s.matrix_key FROM system_backup_v2_installation_state s JOIN system_backup_v2_configs c ON c.origin_installation_id=s.origin_installation_id AND c.version=s.active_config_version WHERE s.origin_installation_id=? FOR UPDATE`, g.InstallationID).Scan(&configHash, &activeVersion, &enabled, &matrix) != nil || configHash != g.ConfigSHA256 || activeVersion != 1 || enabled || matrix != g.MatrixKey {
		return ErrBootstrapExists
	}
	if err = verifyBootstrapConfigValues(ctx, tx, g, c, s.CanonicalSnapshot); err != nil {
		return candidateBootstrapError(err)
	}
	if err = fence.Recheck(ctx, tx); err != nil {
		return candidateBootstrapError(err)
	}
	_, err = bootstrapInlineNow(ctx, tx, g, now, until)
	return err
}

// bootstrapConfigWriter permits the original atomic write stage to use a
// guarded caller-owned transaction without exposing Commit or Rollback. It
// performs no authorization or lock acquisition; both belong to its caller.
type bootstrapConfigWriter interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func writeBootstrapConfigRows(ctx context.Context, tx bootstrapConfigWriter, g OfflineBootstrapGrant, c BootstrapConfig, op, digest string, now time.Time, canonicalSnapshot bool) error {
	if _, err := insertBootstrapAudit(ctx, tx, g, op, digest, "intent"); err != nil {
		return err
	}
	if err := writeBootstrapConfigData(ctx, tx, g, c, op, digest, now, canonicalSnapshot); err != nil {
		return err
	}
	_, err := insertBootstrapAudit(ctx, tx, g, op, digest, "result")
	return err
}

func insertBootstrapAudit(ctx context.Context, tx bootstrapConfigWriter, g OfflineBootstrapGrant, op, digest, phase string) (sql.Result, error) {
	details, _ := json.Marshal(map[string]any{"operation_public_id": op, "installation_id": g.InstallationID, "config_sha256": g.ConfigSHA256, "config_version": 1, "request_hash": digest, "authorization": "offline_bootstrap"})
	result, err := tx.ExecContext(ctx, "INSERT INTO audit_logs (user_id,action,resource_type,details) VALUES (?,?,'system_backup',?)", g.UserID, "system_backup.config_bootstrap."+phase, string(details))
	if err != nil {
		return nil, ErrProviderEvidenceStorage
	}
	return result, nil
}

func writeBootstrapConfigData(ctx context.Context, tx bootstrapConfigWriter, g OfflineBootstrapGrant, c BootstrapConfig, op, digest string, now time.Time, canonicalSnapshot bool) error {
	actor := strconv.FormatInt(g.UserID, 10)
	columns, args := c.sqlValues(g.InstallationID, actor, g.ChangeReason)
	if canonicalSnapshot {
		columns, args = c.sqlValuesWithCanonical(g.InstallationID, actor, g.ChangeReason)
	}
	marks := strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")
	if _, err := tx.ExecContext(ctx, "INSERT INTO system_backup_v2_configs ("+strings.Join(columns, ",")+") VALUES ("+marks+")", args...); err != nil {
		return ErrProviderEvidenceStorage
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO system_backup_v2_installation_state
		(origin_installation_id,active_config_version,last_effective_enabled,last_effective_enabled_transition_at,matrix_key)
		VALUES (?,1,FALSE,?,?)`, g.InstallationID, now, g.MatrixKey); err != nil {
		return ErrProviderEvidenceStorage
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO system_backup_v2_operations
		(public_id,origin_installation_id,operation_type,target_type,target_public_id,actor_type,actor_id,endpoint,idempotency_key,request_hash,
		external_action_public_ids_canonical_json,external_action_public_ids_size_bytes,external_action_public_ids_sha256,status,result_config_version,http_status,deadline_at,started_at,finished_at,created_at)
		VALUES (?,?,'config_update','system',?,'admin',?,?,?,?,?,2,?,'succeeded',1,201,?,?,?,?)`,
		op, g.InstallationID, g.InstallationID, actor, BootstrapConfigEndpoint, g.IdempotencyKey, digest, []byte("[]"), registrationHash("[]"), now.Add(time.Duration(c.numbers["operation_deadline_seconds"])*time.Second), now, now, now); err != nil {
		return ErrProviderEvidenceStorage
	}
	return nil
}
func validBootstrapGrant(g OfflineBootstrapGrant) bool {
	return regexp.MustCompile(`^installation_[A-Za-z0-9._:-]{1,115}$`).MatchString(g.InstallationID) &&
		regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(g.ServerUUID) &&
		regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`).MatchString(g.Database) && g.UserID > 0 && len(g.Username) > 0 && len(g.Username) <= 128 &&
		contains([]string{"k8s-cluster", "k3s-cluster", "k8s-single-node", "k3s-single-node"}, g.MatrixKey) && providerHashPattern.MatchString(g.ConfigSHA256) &&
		regexp.MustCompile(`^[A-Za-z0-9._:-]{16,128}$`).MatchString(g.IdempotencyKey) && strings.TrimSpace(g.ChangeReason) != "" && utf8.ValidString(g.ChangeReason) && utf8.RuneCountInString(g.ChangeReason) <= 512
}
