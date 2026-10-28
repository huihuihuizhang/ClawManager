package systembackupsecurity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var ErrLoginSessionRejected = errors.New("system_backup_session_rejected")
var ErrLoginSessionUnavailable = errors.New("system_backup_session_unavailable")

// LoginSessionPair is an internal token-issuer callback, never an HTTP DTO.
// CredentialSHA256 is captured from the user snapshot whose password/directory
// credentials were actually verified; refreshing alone cannot replace it.
type LoginSessionPair struct {
	UserID                                          int64  `json:"-"`
	CredentialSHA256                                string `json:"-"`
	AccessToken, RefreshToken, PreviousRefreshToken string `json:"-"`
}

type LoginSessionRecorder interface {
	RecordPair(context.Context, LoginSessionPair) error
}

type SQLLoginSessions struct {
	db           *sql.DB
	identity     DatabaseIdentity
	installation string
	secret       []byte
}

// RevokeUserSessions uses the same database pin as issuance and refresh.
func (s *SQLLoginSessions) RevokeUserSessions(ctx context.Context, userID int) error {
	if s == nil || s.db == nil {
		return ErrLoginSessionUnavailable
	}
	return (SQLTOTPService{DB: s.db, DatabaseIdentity: &s.identity, InstallationID: s.installation}).RevokeUserSessions(ctx, userID)
}

func NewSQLLoginSessions(db *sql.DB, identity DatabaseIdentity, installation string, secret []byte) (*SQLLoginSessions, error) {
	if db == nil || !identity.valid() || !regexp.MustCompile(`^installation_[A-Za-z0-9._:-]{1,115}$`).MatchString(installation) || len(secret) < 32 {
		return nil, ErrLoginSessionUnavailable
	}
	return &SQLLoginSessions{db: db, identity: identity, installation: installation, secret: append([]byte(nil), secret...)}, nil
}

// Close erases this recorder's owned key without closing the caller's DB.
// The owner must drain all users of the recorder before Close.
func (s *SQLLoginSessions) Close() {
	if s == nil {
		return
	}
	for n := range s.secret {
		s.secret[n] = 0
	}
	s.secret = nil
	s.db = nil
}

func (s *SQLLoginSessions) token(raw, kind string) (RegistrationActor, error) {
	if s == nil || len(s.secret) < 32 || len(raw) == 0 || len(raw) > 8192 {
		return RegistrationActor{}, ErrLoginSessionRejected
	}
	var claims struct {
		UserID    int64  `json:"user_id"`
		TokenType string `json:"token_type"`
		jwt.RegisteredClaims
	}
	token, err := jwt.ParseWithClaims(raw, &claims, func(*jwt.Token) (any, error) { return s.secret, nil }, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil || !token.Valid || claims.UserID <= 0 || claims.TokenType != kind || claims.IssuedAt == nil || claims.ExpiresAt == nil || !claims.ExpiresAt.After(claims.IssuedAt.Time) || claims.ID == "" || len(claims.ID) > 128 {
		return RegistrationActor{}, ErrLoginSessionRejected
	}
	return RegistrationActor{UserID: claims.UserID, Subject: "user:" + strconv.FormatInt(claims.UserID, 10), Session: registrationHash(raw), SessionIssuedAt: claims.IssuedAt.Time, SessionExpiresAt: claims.ExpiresAt.Time}, nil
}

// RecordPair is called only after authentication, before returning either token.
// It never grants RBAC permissions or MFA, and does not turn a GET into session
// enrollment. Refresh requires a still-live, credential-bound parent row.
func (s *SQLLoginSessions) RecordPair(ctx context.Context, p LoginSessionPair) error {
	if s == nil || s.db == nil || len(s.secret) < 32 || p.UserID <= 0 || !providerHashPattern.MatchString(p.CredentialSHA256) || ctx == nil || ctx.Err() != nil {
		return ErrLoginSessionRejected
	}
	access, err := s.token(p.AccessToken, "access")
	if err != nil {
		return err
	}
	refresh, err := s.token(p.RefreshToken, "refresh")
	if err != nil {
		return err
	}
	if access.UserID != p.UserID || refresh.UserID != p.UserID || access.Session == refresh.Session || !refresh.SessionExpiresAt.After(access.SessionExpiresAt) {
		return ErrLoginSessionRejected
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return ErrLoginSessionUnavailable
	}
	defer tx.Rollback()
	if s.identity.check(ctx, tx) != nil {
		return ErrLoginSessionUnavailable
	}
	var password, role string
	var active bool
	if tx.QueryRowContext(ctx, "SELECT password_hash,role,is_active FROM users WHERE id=? FOR UPDATE", p.UserID).Scan(&password, &role, &active) != nil {
		return ErrLoginSessionUnavailable
	}
	if !active || !constantString(registrationHash(password), p.CredentialSHA256) {
		return ErrLoginSessionRejected
	}
	// Business users retain their existing login flow; no backup session is
	// created. Promoting a user to admin requires a fresh login, not an old
	// unregistered refresh token.
	if role != "admin" {
		if tx.Commit() != nil {
			return ErrLoginSessionUnavailable
		}
		return nil
	}
	var now time.Time
	var offset int64
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))").Scan(&now, &offset) != nil || offset != 0 || now.IsZero() {
		return ErrLoginSessionUnavailable
	}
	if access.SessionIssuedAt.After(now) || refresh.SessionIssuedAt.After(now) || !now.Before(access.SessionExpiresAt) || !now.Before(refresh.SessionExpiresAt) {
		return ErrLoginSessionRejected
	}
	var revokedBefore time.Time
	err = tx.QueryRowContext(ctx, "SELECT revoked_before FROM system_backup_v2_admin_revocations WHERE origin_installation_id=? AND user_id=? FOR UPDATE", s.installation, p.UserID).Scan(&revokedBefore)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ErrLoginSessionUnavailable
	}
	if err == nil && (!access.SessionIssuedAt.After(revokedBefore) || !refresh.SessionIssuedAt.After(revokedBefore)) {
		return ErrLoginSessionRejected
	}
	if p.PreviousRefreshToken != "" {
		parent, err := s.token(p.PreviousRefreshToken, "refresh")
		if err != nil || parent.UserID != p.UserID || parent.Session == refresh.Session || parent.Session == access.Session {
			return ErrLoginSessionRejected
		}
		if parent.SessionIssuedAt.After(now) || !now.Before(parent.SessionExpiresAt) {
			return ErrLoginSessionRejected
		}
		if _, err = CheckRegistrationSessionUntil(ctx, tx, s.installation, parent); err != nil {
			return ErrLoginSessionRejected
		}
		result, err := tx.ExecContext(ctx, "UPDATE system_backup_v2_admin_sessions SET revoked=TRUE WHERE origin_installation_id=? AND session_sha256=? AND revoked=FALSE", s.installation, parent.Session)
		if err != nil {
			return ErrLoginSessionUnavailable
		}
		n, err := result.RowsAffected()
		if err != nil || n != 1 {
			return ErrLoginSessionRejected
		}
	}
	// These expired authentication rows have no FK dependents. Nonce/audit and
	// revocation ledgers are not deleted. Bound cleanup and live-pair admission.
	if _, err = tx.ExecContext(ctx, "DELETE FROM system_backup_v2_admin_sessions WHERE origin_installation_id=? AND user_id=? AND expires_at<=? LIMIT 256", s.installation, p.UserID, now); err != nil {
		return ErrLoginSessionUnavailable
	}
	var count int
	if tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_admin_sessions WHERE origin_installation_id=? AND user_id=? AND expires_at>? AND revoked=FALSE", s.installation, p.UserID, now).Scan(&count) != nil || count > 254 {
		return ErrLoginSessionUnavailable
	}
	for _, actor := range []RegistrationActor{access, refresh} {
		if _, err = tx.ExecContext(ctx, "INSERT INTO system_backup_v2_admin_sessions(origin_installation_id,session_sha256,user_id,subject,credential_hash,expires_at) VALUES (?,?,?,?,?,?)", s.installation, actor.Session, actor.UserID, actor.Subject, p.CredentialSHA256, actor.SessionExpiresAt.UTC()); err != nil {
			return ErrLoginSessionUnavailable
		}
	}
	action := "system_backup.session.login"
	if p.PreviousRefreshToken != "" {
		action = "system_backup.session.refresh"
	}
	details, _ := json.Marshal(map[string]string{"installation_id": s.installation, "access_session_sha256": access.Session})
	if _, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(user_id,action,resource_type,details) VALUES (?,?,'system_backup',?)", p.UserID, action, string(details)); err != nil {
		return ErrLoginSessionUnavailable
	}
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || !now.Before(access.SessionExpiresAt) || !now.Before(refresh.SessionExpiresAt) || time.Since(now) > 5*time.Second || time.Until(now) > 5*time.Second {
		return ErrLoginSessionRejected
	}
	if tx.Commit() != nil {
		return ErrLoginSessionUnavailable
	}
	if ctx.Err() != nil || !time.Now().Before(access.SessionExpiresAt) {
		return ErrLoginSessionRejected
	}
	return nil
}
