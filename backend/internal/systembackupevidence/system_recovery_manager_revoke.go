package systembackupevidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

const recoveryManagerRevocationVersion = "system-backup-recovery-manager-revocation.v1"

var ErrRecoveryManagerRevocationCommitUnknown = errors.New("recovery_manager_revocation_commit_unknown")

type recoveryManagerRevocationDocument struct {
	SchemaVersion        string    `json:"schema_version"`
	GrantID              string    `json:"grant_id"`
	Scope                pd.Scope  `json:"scope"`
	SuperiorIdentityHash string    `json:"superior_identity_hash"`
	ManagerIdentityHash  string    `json:"manager_identity_hash"`
	ReasonHash           string    `json:"reason_hash"`
	ExpectedRowVersion   int64     `json:"expected_row_version"`
	NotBefore            time.Time `json:"not_before"`
	ExpiresAt            time.Time `json:"expires_at"`
}

// RecoveryManagerRevocationGrant is a deployment-pinned offline superior
// authorization. It can revoke a precise L1b row without possessing the
// management certificate being revoked.
type RecoveryManagerRevocationGrant struct {
	document recoveryManagerRevocationDocument
	path     string
	digest   string
}

func ReadRecoveryManagerRevocationGrant(path, expectedSHA256 string) (*RecoveryManagerRevocationGrant, error) {
	if path == "" || !digestPattern.MatchString(expectedSHA256) {
		return nil, ErrDenied
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrDenied
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 8192 {
		return nil, ErrDenied
	}
	raw, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil || len(raw) == 0 || len(raw) > 8192 {
		return nil, ErrDenied
	}
	want, err := hex.DecodeString(expectedSHA256)
	if err != nil || len(want) != sha256.Size {
		return nil, ErrDenied
	}
	actual := sha256.Sum256(raw)
	if subtle.ConstantTimeCompare(actual[:], want) != 1 {
		return nil, ErrDenied
	}
	var d recoveryManagerRevocationDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&d) != nil || decoder.Decode(new(any)) != io.EOF || !validRecoveryManagerRevocation(d) {
		return nil, ErrDenied
	}
	return &RecoveryManagerRevocationGrant{document: d, path: path, digest: expectedSHA256}, nil
}

func validRecoveryManagerRevocation(d recoveryManagerRevocationDocument) bool {
	if d.SchemaVersion != recoveryManagerRevocationVersion || !recoveryBootstrapID.MatchString(d.GrantID) ||
		!digestPattern.MatchString(d.SuperiorIdentityHash) || !digestPattern.MatchString(d.ManagerIdentityHash) ||
		!digestPattern.MatchString(d.ReasonHash) || d.ExpectedRowVersion < 1 ||
		!systemPeerTime(d.NotBefore) || !systemPeerTime(d.ExpiresAt) || !d.NotBefore.Before(d.ExpiresAt) {
		return false
	}
	_, err := pd.RecoveryScopeKey(d.Scope)
	return err == nil
}

type RecoveryManagerRevocationExternalAuditRecord struct {
	Stage                string `json:"stage"`
	GrantID              string `json:"grant_id"`
	GrantSHA256          string `json:"grant_sha256"`
	SuperiorIdentityHash string `json:"superior_identity_hash"`
	ManagerIdentityHash  string `json:"manager_identity_hash"`
	ScopeKeySHA256       string `json:"scope_key_sha256"`
}

type RecoveryManagerRevocationExternalAudit interface {
	AppendRecoveryManagerRevocationAudit(context.Context, RecoveryManagerRevocationExternalAuditRecord) error
}

type RecoveryManagerRevocationService struct {
	DB                   *sql.DB
	Scope                pd.Scope
	SuperiorIdentityHash string
	GrantPath            string
	GrantSHA256          string
	ExternalAudit        RecoveryManagerRevocationExternalAudit
}

func (s RecoveryManagerRevocationService) Revoke(ctx context.Context, grant *RecoveryManagerRevocationGrant) error {
	if ctx == nil || ctx.Err() != nil || s.DB == nil || nilSystemAdapter(s.ExternalAudit) || grant == nil ||
		!validRecoveryManagerRevocation(grant.document) || grant.document.Scope != s.Scope ||
		grant.document.SuperiorIdentityHash != s.SuperiorIdentityHash ||
		!digestPattern.MatchString(s.SuperiorIdentityHash) || s.GrantPath == "" || !digestPattern.MatchString(s.GrantSHA256) ||
		grant.path != s.GrantPath || grant.digest != s.GrantSHA256 {
		return ErrDenied
	}
	if _, err := ReadRecoveryManagerRevocationGrant(s.GrantPath, s.GrantSHA256); err != nil {
		return ErrDenied
	}
	key, err := pd.RecoveryScopeKey(s.Scope)
	if err != nil {
		return ErrDenied
	}
	identity, err := hex.DecodeString(grant.document.ManagerIdentityHash)
	if err != nil || len(identity) != 32 {
		return ErrDenied
	}
	entry := RecoveryManagerRevocationExternalAuditRecord{Stage: "intent", GrantID: grant.document.GrantID,
		GrantSHA256: grant.digest, SuperiorIdentityHash: grant.document.SuperiorIdentityHash,
		ManagerIdentityHash: grant.document.ManagerIdentityHash, ScopeKeySHA256: hex.EncodeToString(key)}
	if err := s.ExternalAudit.AppendRecoveryManagerRevocationAudit(ctx, entry); err != nil {
		return ErrUnavailable
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return ErrUnavailable
	}
	defer tx.Rollback()
	var server, database string
	var now time.Time
	var offset int64
	if tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))").Scan(&server, &database, &now, &offset) != nil ||
		server != string(s.Scope.ServerUUID) || database != string(s.Scope.Database) || offset != 0 {
		return ErrUnavailable
	}
	if now.Before(grant.document.NotBefore) || !now.Before(grant.document.ExpiresAt) {
		return ErrDenied
	}
	if err := lockRecoveryManagerBootstrapParent(ctx, tx, s.Scope); err != nil {
		return err
	}
	var origin string
	var version int64
	var enabled bool
	var revoked sql.NullTime
	if err := tx.QueryRowContext(ctx, `SELECT origin_installation_id,row_version,enabled,revoked_at
FROM system_backup_v2_recovery_managers WHERE scope_key=? AND management_identity_hash=? FOR UPDATE`, key, identity).
		Scan(&origin, &version, &enabled, &revoked); err != nil {
		return ErrDenied
	}
	if origin != string(s.Scope.Installation) || version != grant.document.ExpectedRowVersion || !enabled || revoked.Valid || version == 1<<63-1 {
		return ErrConflict
	}
	if err := writeRecoveryManagerRevocationAudit(ctx, tx, entry, "intent"); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE system_backup_v2_recovery_managers
SET enabled=FALSE,can_read_fence=FALSE,can_write_fence=FALSE,can_manage_deployment=FALSE,
revoked_at=?,row_version=row_version+1,updated_at=UTC_TIMESTAMP(6)
WHERE scope_key=? AND management_identity_hash=? AND origin_installation_id=? AND row_version=? AND enabled=TRUE AND revoked_at IS NULL`,
		now, key, identity, string(s.Scope.Installation), version)
	if err != nil {
		return ErrUnavailable
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrConflict
	}
	if err := writeRecoveryManagerRevocationAudit(ctx, tx, entry, "result"); err != nil {
		return err
	}
	var finalVersion int64
	var finalEnabled, read, write, manage bool
	var finalRevoked sql.NullTime
	if err := tx.QueryRowContext(ctx, `SELECT row_version,enabled,can_read_fence,can_write_fence,can_manage_deployment,revoked_at
FROM system_backup_v2_recovery_managers WHERE scope_key=? AND management_identity_hash=? FOR UPDATE`, key, identity).
		Scan(&finalVersion, &finalEnabled, &read, &write, &manage, &finalRevoked); err != nil ||
		finalVersion != version+1 || finalEnabled || read || write || manage || !finalRevoked.Valid || !finalRevoked.Time.Equal(now) {
		return ErrDenied
	}
	if err := tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil || !now.Before(grant.document.ExpiresAt) {
		return ErrDenied
	}
	if _, err := ReadRecoveryManagerRevocationGrant(s.GrantPath, s.GrantSHA256); err != nil {
		return ErrDenied
	}
	if err := tx.Commit(); err != nil {
		return ErrRecoveryManagerRevocationCommitUnknown
	}
	entry.Stage = "result"
	if err := s.ExternalAudit.AppendRecoveryManagerRevocationAudit(ctx, entry); err != nil {
		return ErrRecoveryManagerRevocationCommitUnknown
	}
	return nil
}

func writeRecoveryManagerRevocationAudit(ctx context.Context, tx *sql.Tx, entry RecoveryManagerRevocationExternalAuditRecord, stage string) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs(action,resource_type,details)
VALUES (?,'system_backup',JSON_OBJECT('grant_id',?,'grant_sha256',?,'superior_identity_hash',?,'manager_identity_hash',?,'scope_key_sha256',?))`,
		"system_backup.recovery_manager_revocation."+stage, entry.GrantID, entry.GrantSHA256,
		entry.SuperiorIdentityHash, entry.ManagerIdentityHash, entry.ScopeKeySHA256); err != nil {
		return ErrUnavailable
	}
	return nil
}
