package systembackupconfig

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"reflect"
	"regexp"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

var evidenceIDPattern = regexp.MustCompile(`^sev_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var installationIDPattern = regexp.MustCompile(`^installation_[A-Za-z0-9_-]{1,115}$`)

func registrationHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
func wipe(raw []byte) {
	for i := range raw {
		raw[i] = 0
	}
}
func sessionAt(a sec.RegistrationActor, now time.Time) bool {
	return !now.IsZero() && !a.SessionIssuedAt.IsZero() && a.SessionExpiresAt.After(a.SessionIssuedAt) && !a.SessionIssuedAt.After(now) && now.Before(a.SessionExpiresAt)
}
func isNil(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Interface, reflect.Chan:
		return r.IsNil()
	}
	return false
}
func validDatabase(d sec.DatabaseIdentity) bool {
	return regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(d.ServerUUID) && regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`).MatchString(d.Database)
}
func checkDatabase(ctx context.Context, tx *sql.Tx, d sec.DatabaseIdentity) error {
	var server, name string
	if !validDatabase(d) || tx == nil || tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE()").Scan(&server, &name) != nil || server != d.ServerUUID || name != d.Database {
		return sec.ErrRegistrationUnavailable
	}
	return nil
}
func oneRow(r sql.Result, err error) bool {
	if err != nil || r == nil {
		return false
	}
	n, err := r.RowsAffected()
	return err == nil && n == 1
}
