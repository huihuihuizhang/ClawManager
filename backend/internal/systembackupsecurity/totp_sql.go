package systembackupsecurity

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"strconv"
	"time"
)

var ErrTOTPRejected = errors.New("strong_auth_invalid")
var ErrTOTPRateLimited = errors.New("strong_auth_rate_limited")

type SQLTOTPService struct {
	DB *sql.DB
	// Required for enrollment and proof issuance. Check the current pinned
	// security_admin grant on this transaction, not in an earlier HTTP precheck.
	// The callback must not commit or perform network I/O.
	Authorize func(context.Context, *sql.Tx, RegistrationActor) error
	// Required by the runtime loader. Nil is retained for isolated library
	// tests and the existing app-owned logout hook on its own database.
	DatabaseIdentity *DatabaseIdentity
	InstallationID   string
	Box              TOTPSecretBox
	Issuer           StrongAuthProofIssuer
}
type totpState struct {
	seed            []byte
	credential      sql.NullString
	confirmed       bool
	pending, locked sql.NullTime
	lastStep        int64
	failures        int
}

func (s SQLTOTPService) identity(a RegistrationActor) string {
	return s.InstallationID + "/user:" + strconv.FormatInt(a.UserID, 10)
}

// lock authenticates the password against the current database user, and
// persists failed attempts even though the operation returns a rejection.
// The HTTP caller has already authenticated the access JWT independently.
func (s SQLTOTPService) lock(ctx context.Context, a RegistrationActor, password string) (*sql.Tx, totpState, time.Time, string, error) {
	var st totpState
	var now time.Time
	if s.Authorize == nil {
		return nil, st, now, "", ErrRegistrationUnavailable
	}
	if s.DB == nil || s.Box.aead == nil || a.UserID <= 0 || a.Subject != "user:"+strconv.FormatInt(a.UserID, 10) || !providerHashPattern.MatchString(a.Session) || len(password) > 1024 || password == "" {
		return nil, st, now, "", ErrTOTPRejected
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, st, now, "", ErrRegistrationUnavailable
	}
	fail := func(e error) (*sql.Tx, totpState, time.Time, string, error) {
		tx.Rollback()
		return nil, st, now, "", e
	}
	if s.DatabaseIdentity != nil {
		if err = s.DatabaseIdentity.check(ctx, tx); err != nil {
			return fail(err)
		}
	}
	if err = s.Authorize(ctx, tx, a); err != nil {
		return fail(registrationBoundaryError(err))
	}
	var hash, role string
	var active bool
	if tx.QueryRowContext(ctx, "SELECT password_hash,role,is_active FROM users WHERE id=? FOR UPDATE", a.UserID).Scan(&hash, &role, &active) != nil || !active || role != "admin" {
		return fail(ErrTOTPRejected)
	}
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || !a.SessionExpiresAt.After(now) {
		return fail(ErrTOTPRejected)
	}
	var revokedBefore time.Time
	err = tx.QueryRowContext(ctx, "SELECT revoked_before FROM system_backup_v2_admin_revocations WHERE origin_installation_id=? AND user_id=? FOR UPDATE", s.InstallationID, a.UserID).Scan(&revokedBefore)
	if a.SessionIssuedAt.IsZero() || a.SessionIssuedAt.After(now) || err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fail(ErrRegistrationUnavailable)
	}
	if err == nil && !a.SessionIssuedAt.After(revokedBefore) {
		return fail(ErrTOTPRejected)
	}
	if _, err = tx.ExecContext(ctx, "INSERT IGNORE INTO system_backup_v2_totp_credentials(origin_installation_id,user_id) VALUES (?,?)", s.InstallationID, a.UserID); err != nil {
		return fail(ErrRegistrationUnavailable)
	}
	err = tx.QueryRowContext(ctx, `SELECT encrypted_seed,credential_hash,confirmed,pending_until,last_step,failures,locked_until FROM system_backup_v2_totp_credentials WHERE origin_installation_id=? AND user_id=? FOR UPDATE`, s.InstallationID, a.UserID).Scan(&st.seed, &st.credential, &st.confirmed, &st.pending, &st.lastStep, &st.failures, &st.locked)
	if err != nil {
		return fail(ErrRegistrationUnavailable)
	}
	if st.locked.Valid && now.Before(st.locked.Time) {
		return fail(ErrTOTPRateLimited)
	}
	if st.locked.Valid {
		st.failures = 0
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		e := s.reject(ctx, tx, a, st, now)
		return nil, st, now, "", e
	}
	return tx, st, now, registrationHash(hash), nil
}
func (s SQLTOTPService) reject(ctx context.Context, tx *sql.Tx, a RegistrationActor, st totpState, now time.Time) error {
	var until any
	count := st.failures + 1
	if count >= 5 {
		until = now.Add(5 * time.Minute)
	}
	if _, err := tx.ExecContext(ctx, "UPDATE system_backup_v2_totp_credentials SET failures=?,locked_until=? WHERE origin_installation_id=? AND user_id=?", count, until, s.InstallationID, a.UserID); err != nil {
		tx.Rollback()
		return ErrRegistrationUnavailable
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit_logs(user_id,action,resource_type,details) VALUES (?,'system_backup.strong_auth.rejected','system_backup','{}')", a.UserID); err != nil {
		tx.Rollback()
		return ErrRegistrationUnavailable
	}
	if tx.Commit() != nil {
		return ErrRegistrationCommitUnknown
	}
	return ErrTOTPRejected
}

// BeginEnrollment returns the seed ONLY as an enrollment URI over the
// authenticated HTTPS response. It is never included in audit or evidence.
func (s SQLTOTPService) BeginEnrollment(ctx context.Context, a RegistrationActor, password string) (string, error) {
	tx, st, now, credential, err := s.lock(ctx, a, password)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if st.confirmed {
		return "", ErrTOTPRejected
	} // resetting MFA requires a separate recovery procedure.
	if st.pending.Valid && now.Before(st.pending.Time) {
		return "", ErrTOTPRejected
	}
	secret := make([]byte, 20)
	if _, err = rand.Read(secret); err != nil {
		return "", ErrRegistrationUnavailable
	}
	defer wipeSecret(secret)
	sealed, err := s.Box.seal(secret, s.identity(a))
	if err != nil {
		return "", err
	}
	_, err = tx.ExecContext(ctx, "UPDATE system_backup_v2_totp_credentials SET encrypted_seed=?,credential_hash=?,pending_until=?,last_step=-1,failures=0,locked_until=NULL WHERE origin_installation_id=? AND user_id=?", sealed, credential, now.Add(10*time.Minute), s.InstallationID, a.UserID)
	if err != nil {
		return "", ErrRegistrationUnavailable
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(user_id,action,resource_type,details) VALUES (?,'system_backup.strong_auth.enrollment_started','system_backup','{}')", a.UserID); err != nil {
		return "", ErrRegistrationUnavailable
	}
	if tx.Commit() != nil {
		return "", ErrRegistrationCommitUnknown
	}
	return enrollmentURI(secret, a.Subject), nil
}

// VerifyAndIssue consumes a TOTP step under a row lock. The first valid code
// confirms enrollment but does not authorize a mutation: a fresh code must
// then be supplied to issue a request-bound proof.
func (s SQLTOTPService) VerifyAndIssue(ctx context.Context, a RegistrationActor, password, code string, request *ProviderProofRegistration) (Proof, error) {
	var binding *RequestBinding
	if request != nil {
		digest, err := ProviderProofRequestSHA256(*request)
		if err != nil {
			return Proof{}, err
		}
		binding = &RequestBinding{Endpoint: ProviderRegistrationEndpoint, RequestHash: digest, IdempotencyKey: request.IdempotencyKey}
	}
	return s.verifyAndIssue(ctx, a, password, code, binding, false)
}

// No exported method accepts an arbitrary request hash or asserted MFA time.
func (s SQLTOTPService) verifyAndIssue(ctx context.Context, a RegistrationActor, password, code string, binding *RequestBinding, configMutation bool) (Proof, error) {
	return s.verifyAndIssueBounded(ctx, a, password, code, binding, configMutation, nil)
}

func (s SQLTOTPService) verifyAndIssueBounded(ctx context.Context, a RegistrationActor, password, code string, binding *RequestBinding, configMutation bool, bounds *totpProofBounds) (Proof, error) {
	empty := Proof{}
	tx, st, now, credential, err := s.lock(ctx, a, password)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if bounds != nil && (bounds.validate == nil || !now.Before(bounds.until)) {
		return empty, ErrRegistrationUnavailable
	}
	if configMutation {
		if err = s.checkConfigProofSession(ctx, tx, a, now); err != nil {
			return empty, err
		}
	}
	if !st.credential.Valid || !constantString(st.credential.String, credential) || !st.confirmed && (!st.pending.Valid || !now.Before(st.pending.Time)) {
		return empty, s.reject(ctx, tx, a, st, now)
	}
	secret, err := s.Box.open(st.seed, s.identity(a))
	if err != nil {
		return empty, ErrRegistrationUnavailable
	}
	defer wipeSecret(secret)
	step, ok := matchTOTP(secret, code, now, st.lastStep)
	if !ok {
		return empty, s.reject(ctx, tx, a, st, now)
	}
	if !st.confirmed && binding != nil || st.confirmed && binding == nil {
		return empty, ErrTOTPRejected
	}
	var proof Proof
	if binding != nil {
		proof, err = s.Issuer.issue(ctx, a, *binding, now)
		if err != nil {
			return empty, err
		}
	}
	if bounds != nil {
		if err = bounds.validate(ctx, tx, proof, now); err != nil {
			return empty, registrationBoundaryError(err)
		}
	}
	// Never revive a logged-out token. A new login generates a distinct token.
	// Config proof issuance requires an already recorded current login. It may
	// not enroll a missing token or refresh an existing session as a side effect.
	if !configMutation {
		_, err = tx.ExecContext(ctx, `INSERT INTO system_backup_v2_admin_sessions(origin_installation_id,session_sha256,user_id,subject,credential_hash,expires_at) VALUES (?,?,?,?,?,?) ON DUPLICATE KEY UPDATE expires_at=LEAST(expires_at,VALUES(expires_at))`, s.InstallationID, a.Session, a.UserID, a.Subject, credential, a.SessionExpiresAt.UTC())
		if err != nil {
			return empty, ErrRegistrationUnavailable
		}
		if err = CheckRegistrationSession(ctx, tx, s.InstallationID, a); err != nil {
			return empty, err
		}
	}
	_, err = tx.ExecContext(ctx, "UPDATE system_backup_v2_totp_credentials SET confirmed=TRUE,pending_until=NULL,last_step=?,failures=0,locked_until=NULL WHERE origin_installation_id=? AND user_id=?", step, s.InstallationID, a.UserID)
	if err != nil {
		return empty, ErrRegistrationUnavailable
	}
	details, _ := json.Marshal(map[string]bool{"enrollment_confirmed": !st.confirmed, "proof_issued": binding != nil})
	if _, err = tx.ExecContext(ctx, "INSERT INTO audit_logs(user_id,action,resource_type,details) VALUES (?,'system_backup.strong_auth.verified','system_backup',?)", a.UserID, string(details)); err != nil {
		return empty, ErrRegistrationUnavailable
	}
	var finalClock totpProofClock
	if configMutation {
		if finalClock, err = s.finalConfigProofClock(ctx, tx, a, now); err != nil {
			return empty, err
		}
	}
	if bounds != nil && !finalClock.now.Before(bounds.until) {
		return empty, ErrRegistrationUnavailable
	}
	if tx.Commit() != nil {
		return empty, ErrRegistrationCommitUnknown
	}
	// A slow/unknown commit cannot refresh the original authorization or proof
	// lifetime. A consumed step is not automatically retried after this failure.
	if bounds != nil {
		postCommit := finalClock.now.Add(time.Since(finalClock.started))
		if ctx.Err() != nil || !postCommit.Before(bounds.until) || !postCommit.Before(a.SessionExpiresAt) || !postCommit.Before(now.Add(s.Issuer.Lifetime)) {
			return empty, ErrRegistrationUnavailable
		}
	}
	return proof, nil
}

// Called inside the SAME transaction as permission and registration checks.
func CheckRegistrationSession(ctx context.Context, tx *sql.Tx, installation string, a RegistrationActor) error {
	_, err := CheckRegistrationSessionUntil(ctx, tx, installation, a)
	return err
}

// CheckRegistrationSessionUntil also exposes the locked database session expiry
// so a delegated credential cannot outlive a shortened/revoked session.
func CheckRegistrationSessionUntil(ctx context.Context, tx *sql.Tx, installation string, a RegistrationActor) (time.Time, error) {
	var hash string
	if err := tx.QueryRowContext(ctx, "SELECT password_hash FROM users WHERE id=? AND is_active=TRUE AND role='admin' FOR UPDATE", a.UserID).Scan(&hash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return time.Time{}, ErrRegistrationPermission
		}
		return time.Time{}, ErrProviderEvidenceStorage
	}
	var subject, credential string
	var uid int64
	var expires, now time.Time
	var revoked bool
	err := tx.QueryRowContext(ctx, "SELECT user_id,subject,credential_hash,expires_at,revoked,UTC_TIMESTAMP(6) FROM system_backup_v2_admin_sessions WHERE origin_installation_id=? AND session_sha256=? FOR UPDATE", installation, a.Session).Scan(&uid, &subject, &credential, &expires, &revoked, &now)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return time.Time{}, ErrRegistrationPermission
		}
		return time.Time{}, ErrProviderEvidenceStorage
	}
	if revoked || uid != a.UserID || subject != a.Subject || !expires.After(now) || credential != registrationHash(hash) {
		return time.Time{}, ErrRegistrationPermission
	}
	return expires, nil
}
func (s SQLTOTPService) RevokeUserSessions(ctx context.Context, userID int) error {
	if s.DB == nil {
		return ErrRegistrationUnavailable
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return ErrRegistrationUnavailable
	}
	defer tx.Rollback()
	if s.DatabaseIdentity != nil {
		if err = s.DatabaseIdentity.check(ctx, tx); err != nil {
			return err
		}
	}
	var uid int
	if tx.QueryRowContext(ctx, "SELECT id FROM users WHERE id=? FOR UPDATE", userID).Scan(&uid) != nil {
		return ErrRegistrationUnavailable
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO system_backup_v2_admin_revocations(origin_installation_id,user_id,revoked_before) VALUES (?,?,UTC_TIMESTAMP(6)) ON DUPLICATE KEY UPDATE revoked_before=UTC_TIMESTAMP(6)", s.InstallationID, userID)
	if err != nil {
		return ErrRegistrationUnavailable
	}
	_, err = tx.ExecContext(ctx, "UPDATE system_backup_v2_admin_sessions SET revoked=TRUE WHERE origin_installation_id=? AND user_id=?", s.InstallationID, userID)
	if err != nil {
		return ErrRegistrationUnavailable
	}
	if tx.Commit() != nil {
		return ErrRegistrationCommitUnknown
	}
	return nil
}
