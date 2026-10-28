package systembackupsecurity

import (
	"context"
	"database/sql"
	"regexp"
)

// DatabaseIdentity binds an installation/user registry to the database that
// was inspected. An identical numeric user ID on another database is not the
// same principal. Each sensitive runtime transaction checks its own connection.
type DatabaseIdentity struct{ ServerUUID, Database string }

func (d DatabaseIdentity) valid() bool {
	return regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(d.ServerUUID) && regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`).MatchString(d.Database)
}

type registrationRowQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (d DatabaseIdentity) check(ctx context.Context, q registrationRowQuery) error {
	var server, database string
	if !d.valid() || q.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE()").Scan(&server, &database) != nil || server != d.ServerUUID || database != d.Database {
		return ErrRegistrationUnavailable
	}
	return nil
}
