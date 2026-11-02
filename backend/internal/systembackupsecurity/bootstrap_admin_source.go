package systembackupsecurity

import (
	"context"
	"database/sql"
	"errors"
)

type bootstrapAdminRead interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// The original bootstrap only reads this administrator row. A shared locking
// read holds current role/active/provider/name stable until the caller's
// transaction ends, including history and final readback. It acquires the
// same id at the same L2 prefix, before owner head/grant and operation lookup.
// MySQL 8.4 FOR SHARE requires SELECT only; FOR UPDATE unnecessarily requires
// UPDATE/DELETE/LOCK TABLES privileges on the application administrator table.
// No password hash, resource authority, clock or transaction ownership is added.
func lockBootstrapCurrentAdmin(ctx context.Context, q bootstrapAdminRead, grant OfflineBootstrapGrant) error {
	if candidateAuthorityNil(ctx) || ctx.Err() != nil || candidateAuthorityNil(q) {
		return ErrRegistrationPermission
	}
	var username, role, provider string
	var active bool
	e := q.QueryRowContext(ctx, `SELECT username,role,is_active,auth_provider FROM users WHERE id=? FOR SHARE`, grant.UserID).Scan(&username, &role, &active, &provider)
	if errors.Is(e, sql.ErrNoRows) {
		return ErrRegistrationPermission
	}
	if e != nil {
		return ErrProviderEvidenceStorage
	}
	if username != grant.Username || role != "admin" || !active || provider != "local" {
		return ErrRegistrationPermission
	}
	return nil
}
