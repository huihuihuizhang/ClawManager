package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// LoginState is the verified snapshot plus the only fields login may update.
// It cannot overwrite a concurrent password change or reactivate an account.
type LoginState struct {
	UserID                                         int
	PasswordHash, AuthProvider, ExpectedRole, Role string
	ExternalID                                     *string
	At                                             time.Time
}

type LoginStateRepository interface{ UpdateLoginState(LoginState) error }

type loginStateSQL interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (r *userRepository) UpdateLoginState(s LoginState) error {
	if s.UserID <= 0 || s.At.IsZero() || (s.Role != "admin" && s.Role != "user") {
		return errors.New("login state conflict")
	}
	provider := s.AuthProvider
	if provider == "" {
		provider = "local"
	}
	if r == nil || r.sess == nil || r.sess.Context() == nil {
		return errors.New("login state unavailable")
	}
	// upper/db's default WARN logger prints SQL arguments on errors and slow
	// queries, including this credential snapshot. Use the same underlying
	// database/sql connection or transaction and context without that logger.
	var executor loginStateSQL
	switch driver := r.sess.Driver().(type) {
	case *sql.DB:
		if driver != nil {
			executor = driver
		}
	case *sql.Tx:
		if driver != nil {
			executor = driver
		}
	}
	if executor == nil {
		return errors.New("login state unavailable")
	}
	ctx := r.sess.Context()
	result, err := executor.ExecContext(ctx, `UPDATE users SET last_login=?,auth_provider=?,role=?
WHERE id=? AND BINARY password_hash=BINARY ? AND auth_provider=? AND role=? AND is_active=TRUE AND BINARY external_id <=> BINARY ?`, s.At, provider, s.Role, s.UserID, s.PasswordHash, s.AuthProvider, s.ExpectedRole, s.ExternalID)
	if err != nil {
		return errors.New("login state unavailable")
	}
	n, err := result.RowsAffected()
	if err != nil || n > 1 {
		return errors.New("login state conflict")
	}
	if n == 0 {
		// MySQL reports changed rows by default. Two logins in the same stored
		// timestamp tick may match without changing anything. Recheck the full
		// credential/identity predicate before treating that as a valid login.
		var count int
		row := executor.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE id=? AND BINARY password_hash=BINARY ? AND auth_provider=? AND role=? AND is_active=TRUE AND BINARY external_id <=> BINARY ?`, s.UserID, s.PasswordHash, provider, s.Role, s.ExternalID)
		if row.Scan(&count) != nil || count != 1 {
			return errors.New("login state conflict")
		}
	}
	return nil
}
