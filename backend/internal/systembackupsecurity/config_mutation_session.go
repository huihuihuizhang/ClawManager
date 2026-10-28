package systembackupsecurity

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"
)

// CheckConfigMutationSession implements ConfigMutationAuthoritySources.CheckSession
// for the existing SQL login recorder. actor must already have been authenticated
// from an access token; this method never enrolls or refreshes a session. The
// caller owns tx and must keep its locks through the mutation/replay decision.
func (s *SQLLoginSessions) CheckConfigMutationSession(ctx context.Context, tx *sql.Tx, installation string, actor RegistrationActor, notBefore time.Time) error {
	if s == nil || s.db == nil || !s.identity.valid() || !configMutationInstallation.MatchString(s.installation) ||
		ctx == nil || ctx.Err() != nil || tx == nil || installation != s.installation || notBefore.IsZero() {
		return ErrRegistrationUnavailable
	}
	if actor.UserID < 1 || actor.Subject != "user:"+strconv.FormatInt(actor.UserID, 10) ||
		!providerHashPattern.MatchString(actor.Session) || !configMutationSessionAt(actor, notBefore) {
		return ErrRegistrationPermission
	}
	if err := s.identity.check(ctx, tx); err != nil {
		return ErrRegistrationUnavailable
	}
	// This locks the current admin/password and its credential-bound session.
	// The user lock also serializes the login/revoke paths before either ledger
	// row is read, following their existing per-user locking discipline.
	until, err := CheckRegistrationSessionUntil(ctx, tx, installation, actor)
	if err != nil {
		return registrationBoundaryError(err)
	}
	// The core's final clock guard uses the authenticated token expiry. Requiring
	// the locked database bound to cover it closes the gap when an operator has
	// shortened the database session without changing the already issued JWT.
	if until.Before(actor.SessionExpiresAt) {
		return ErrRegistrationPermission
	}
	var revokedBefore time.Time
	err = tx.QueryRowContext(ctx, "SELECT revoked_before FROM system_backup_v2_admin_revocations WHERE origin_installation_id=? AND user_id=? FOR UPDATE", installation, actor.UserID).Scan(&revokedBefore)
	if err != nil && !errors.Is(err, sql.ErrNoRows) || err == nil && revokedBefore.IsZero() {
		return ErrRegistrationUnavailable
	}
	if err == nil && !actor.SessionIssuedAt.After(revokedBefore) {
		return ErrRegistrationPermission
	}
	// Query after all locks, rather than trusting the earlier caller time or the
	// timestamp read alongside the session. The transaction service performs its
	// own fresh final clock check after every authority callback as well.
	now, err := configMutationClock(ctx, tx)
	if err != nil || now.Before(notBefore) {
		return ErrRegistrationUnavailable
	}
	if !configMutationSessionAt(actor, now) || !now.Before(until) {
		return ErrRegistrationPermission
	}
	return nil
}
