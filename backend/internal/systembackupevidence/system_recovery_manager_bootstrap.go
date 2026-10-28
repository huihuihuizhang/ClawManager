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
	"regexp"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

const recoveryManagerBootstrapVersion = "system-backup-recovery-manager-bootstrap.v1"

var recoveryBootstrapID = regexp.MustCompile(`^[A-Za-z0-9._:-]{16,128}$`)

// RecoveryManagerBootstrapGrant is an offline, deployment-pinned authorization
// to create the first L1b management row. It cannot be decoded from an HTTP
// request. The expected file digest must come from the installation operator,
// outside the grant file and outside the business database.
type RecoveryManagerBootstrapGrant struct {
	document recoveryManagerBootstrapDocument
	digest   string
	path     string
}

var ErrRecoveryManagerCommitUnknown = errors.New("recovery_manager_commit_unknown")

type recoveryManagerBootstrapDocument struct {
	SchemaVersion         string    `json:"schema_version"`
	GrantID               string    `json:"grant_id"`
	Scope                 pd.Scope  `json:"scope"`
	BootstrapIdentityHash string    `json:"bootstrap_identity_hash"`
	ManagerIdentityHash   string    `json:"manager_identity_hash"`
	IssuerIdentityHash    string    `json:"issuer_identity_hash"`
	CredentialBindingHash string    `json:"credential_binding_hash"`
	ReasonHash            string    `json:"reason_hash"`
	NotBefore             time.Time `json:"not_before"`
	ExpiresAt             time.Time `json:"expires_at"`
	AuthorizedUntil       time.Time `json:"authorized_until"`
	ReadFence             bool      `json:"read_fence"`
	WriteFence            bool      `json:"write_fence"`
	ManageDeployment      bool      `json:"manage_deployment"`
}

func ReadRecoveryManagerBootstrapGrant(path, expectedSHA256 string) (*RecoveryManagerBootstrapGrant, error) {
	if !digestPattern.MatchString(expectedSHA256) || path == "" {
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
	var d recoveryManagerBootstrapDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&d) != nil || decoder.Decode(new(any)) != io.EOF || !validRecoveryManagerBootstrap(d) {
		return nil, ErrDenied
	}
	return &RecoveryManagerBootstrapGrant{document: d, digest: expectedSHA256, path: path}, nil
}

func validRecoveryManagerBootstrap(d recoveryManagerBootstrapDocument) bool {
	if d.SchemaVersion != recoveryManagerBootstrapVersion || !recoveryBootstrapID.MatchString(d.GrantID) ||
		!digestPattern.MatchString(d.BootstrapIdentityHash) || !digestPattern.MatchString(d.ManagerIdentityHash) ||
		!digestPattern.MatchString(d.IssuerIdentityHash) || !digestPattern.MatchString(d.CredentialBindingHash) ||
		!digestPattern.MatchString(d.ReasonHash) ||
		!systemPeerTime(d.NotBefore) || !systemPeerTime(d.ExpiresAt) || !systemPeerTime(d.AuthorizedUntil) ||
		!d.NotBefore.Before(d.ExpiresAt) || d.AuthorizedUntil.After(d.ExpiresAt) ||
		!d.ReadFence || !d.WriteFence || !d.ManageDeployment {
		return false
	}
	_, err := pd.RecoveryScopeKey(d.Scope)
	return err == nil
}

// RecoveryManagerExternalAudit must be backed by independently reserved,
// durable capacity. The first registration never uses audit_logs alone as its
// break-glass evidence. Implementations must not perform this write inside the
// database transaction or accept a caller-controlled path or destination.
type RecoveryManagerExternalAudit interface {
	AppendRecoveryManagerAudit(context.Context, RecoveryManagerExternalAuditRecord) error
}

type RecoveryManagerExternalAuditRecord struct {
	Stage                 string `json:"stage"`
	GrantID               string `json:"grant_id"`
	GrantSHA256           string `json:"grant_sha256"`
	BootstrapIdentityHash string `json:"bootstrap_identity_hash"`
	ManagerIdentityHash   string `json:"manager_identity_hash"`
	ScopeKeySHA256        string `json:"scope_key_sha256"`
}

type RecoveryManagerBootstrapService struct {
	DB                    *sql.DB
	Scope                 pd.Scope
	BootstrapIdentityHash string
	GrantPath             string
	GrantSHA256           string
	Authenticator         *RecoveryManagerPeerAuthenticator
	ExternalAudit         RecoveryManagerExternalAudit
}

// RegisterFirst is an offline entry point. L0 serializes missing L1a/L1b
// rows; an existing deployment or management row is never overwritten. Both
// business audit rows and the manager insert commit together. An external
// result-audit failure after COMMIT returns an unknown outcome, never a grant.
func (s RecoveryManagerBootstrapService) RegisterFirst(ctx context.Context, peer *RecoveryManagerPeer, grant *RecoveryManagerBootstrapGrant) error {
	if ctx == nil || ctx.Err() != nil || s.DB == nil || s.Authenticator == nil || nilSystemAdapter(s.ExternalAudit) ||
		peer == nil || peer.owner != s.Authenticator || grant == nil || !validRecoveryManagerBootstrap(grant.document) ||
		grant.document.Scope != s.Scope || grant.document.BootstrapIdentityHash != s.BootstrapIdentityHash ||
		!digestPattern.MatchString(s.BootstrapIdentityHash) || grant.path != s.GrantPath || grant.digest != s.GrantSHA256 ||
		s.GrantPath == "" || !digestPattern.MatchString(s.GrantSHA256) {
		return ErrDenied
	}
	key, err := pd.RecoveryScopeKey(s.Scope)
	if err != nil {
		return ErrDenied
	}
	entry := RecoveryManagerExternalAuditRecord{Stage: "intent", GrantID: grant.document.GrantID, GrantSHA256: grant.digest,
		BootstrapIdentityHash: grant.document.BootstrapIdentityHash, ManagerIdentityHash: grant.document.ManagerIdentityHash,
		ScopeKeySHA256: hex.EncodeToString(key)}
	if err := s.ExternalAudit.AppendRecoveryManagerAudit(ctx, entry); err != nil {
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
	if now.Before(grant.document.NotBefore) || !now.Before(grant.document.ExpiresAt) || !now.Before(grant.document.AuthorizedUntil) {
		return ErrDenied
	}
	facts, err := s.Authenticator.Check(ctx, peer, s.Scope, now)
	if err != nil || facts.IdentityHash != grant.document.ManagerIdentityHash ||
		facts.IssuerIdentityHash != grant.document.IssuerIdentityHash ||
		facts.CredentialBindingHash != grant.document.CredentialBindingHash || !now.Before(facts.ExpiresAt) {
		return ErrAuth
	}
	if err := lockRecoveryManagerBootstrapParent(ctx, tx, s.Scope); err != nil {
		return err
	}
	var existing int64
	if err := tx.QueryRowContext(ctx, "SELECT row_version FROM system_backup_v2_recovery_deployments WHERE scope_key=? FOR UPDATE", key).Scan(&existing); !errors.Is(err, sql.ErrNoRows) {
		if err == nil {
			return ErrConflict
		}
		return ErrUnavailable
	}
	rows, err := tx.QueryContext(ctx, "SELECT management_identity_hash FROM system_backup_v2_recovery_managers WHERE scope_key=? ORDER BY management_identity_hash FOR UPDATE", key)
	if err != nil {
		return ErrUnavailable
	}
	if rows.Next() {
		rows.Close()
		return ErrConflict
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil || closeErr != nil {
		return ErrUnavailable
	}
	requestHash := grant.digest
	until := grant.document.AuthorizedUntil
	if facts.ExpiresAt.Before(until) {
		until = facts.ExpiresAt
	}
	for _, stage := range []string{"intent", "result"} {
		if stage == "result" {
			identity, _ := hex.DecodeString(facts.IdentityHash)
			issuer, _ := hex.DecodeString(facts.IssuerIdentityHash)
			credential, _ := hex.DecodeString(facts.CredentialBindingHash)
			if _, err := tx.ExecContext(ctx, `INSERT INTO system_backup_v2_recovery_managers
(scope_key,management_identity_hash,origin_installation_id,issuer_identity_hash,credential_binding_hash,can_read_fence,can_write_fence,can_manage_deployment,enabled,authorized_until,row_version)
VALUES (?,?,?,?,?,TRUE,TRUE,TRUE,TRUE,?,1)`, key, identity, string(s.Scope.Installation), issuer, credential, until); err != nil {
				return ErrUnavailable
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs(action,resource_type,details)
VALUES (?,'system_backup',JSON_OBJECT('grant_id',?,'grant_sha256',?,'bootstrap_identity_hash',?,'manager_identity_hash',?,'scope_key_sha256',?))`,
			"system_backup.recovery_manager_bootstrap."+stage, grant.document.GrantID, requestHash,
			grant.document.BootstrapIdentityHash, facts.IdentityHash, entry.ScopeKeySHA256); err != nil {
			return ErrUnavailable
		}
	}
	if err := tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil || !now.Before(grant.document.ExpiresAt) || !now.Before(until) {
		return ErrDenied
	}
	currentFacts, err := s.Authenticator.Check(ctx, peer, s.Scope, now)
	if err != nil || currentFacts.Scope != facts.Scope || currentFacts.IdentityHash != facts.IdentityHash ||
		currentFacts.IssuerIdentityHash != facts.IssuerIdentityHash ||
		currentFacts.CredentialBindingHash != facts.CredentialBindingHash ||
		!currentFacts.ExpiresAt.Equal(facts.ExpiresAt) {
		return ErrAuth
	}
	var rowOrigin string
	var rowIdentity, rowIssuer, rowCredential []byte
	var rowRead, rowWrite, rowManage, rowEnabled bool
	var rowUntil time.Time
	var rowVersion uint64
	var rowRevoked sql.NullTime
	if err := tx.QueryRowContext(ctx, `SELECT origin_installation_id,management_identity_hash,issuer_identity_hash,credential_binding_hash,
can_read_fence,can_write_fence,can_manage_deployment,enabled,authorized_until,row_version,revoked_at
FROM system_backup_v2_recovery_managers WHERE scope_key=? AND management_identity_hash=? FOR UPDATE`,
		key, mustRecoveryBootstrapHash(facts.IdentityHash)).Scan(&rowOrigin, &rowIdentity, &rowIssuer, &rowCredential,
		&rowRead, &rowWrite, &rowManage, &rowEnabled, &rowUntil, &rowVersion, &rowRevoked); err != nil {
		return ErrUnavailable
	}
	if rowOrigin != string(s.Scope.Installation) || !bytes.Equal(rowIdentity, mustRecoveryBootstrapHash(facts.IdentityHash)) ||
		!bytes.Equal(rowIssuer, mustRecoveryBootstrapHash(facts.IssuerIdentityHash)) ||
		!bytes.Equal(rowCredential, mustRecoveryBootstrapHash(facts.CredentialBindingHash)) ||
		!rowRead || !rowWrite || !rowManage || !rowEnabled || !rowUntil.Equal(until) || rowVersion != 1 || rowRevoked.Valid {
		return ErrDenied
	}
	if _, err := ReadRecoveryManagerBootstrapGrant(s.GrantPath, s.GrantSHA256); err != nil {
		return ErrDenied
	}
	if err := tx.Commit(); err != nil {
		return ErrRecoveryManagerCommitUnknown
	}
	entry.Stage = "result"
	if err := s.ExternalAudit.AppendRecoveryManagerAudit(ctx, entry); err != nil {
		return ErrRecoveryManagerCommitUnknown
	}
	return nil
}

func mustRecoveryBootstrapHash(value string) []byte {
	decoded, _ := hex.DecodeString(value)
	return decoded
}

func lockRecoveryManagerBootstrapParent(ctx context.Context, tx *sql.Tx, scope pd.Scope) error {
	rows, err := tx.QueryContext(ctx, "SELECT origin_installation_id FROM system_backup_v2_installation_state ORDER BY origin_installation_id FOR UPDATE")
	if err != nil {
		return ErrUnavailable
	}
	count, found := 0, false
	for rows.Next() {
		var installation string
		if rows.Scan(&installation) != nil {
			rows.Close()
			return ErrUnavailable
		}
		count++
		if count > 10000 {
			rows.Close()
			return ErrDenied
		}
		found = found || installation == string(scope.Installation)
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil || closeErr != nil || !found {
		return ErrDenied
	}
	var installation string
	if tx.QueryRowContext(ctx, "SELECT origin_installation_id FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR UPDATE", string(scope.Installation)).Scan(&installation) != nil || installation != string(scope.Installation) {
		return ErrDenied
	}
	return nil
}
