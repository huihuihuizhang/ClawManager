package install

import (
	"context"
	"database/sql"
	"strings"
	"time"

	c "clawreef/internal/systembackupcontroller"
)

// Native identity/permissions check only, never a task or claim. Plan.Target's
// account remains the ORIGINAL bootstrap business account; it is not rewritten
// into the independent public controller's dedicated 48-table SQL principal.
func (i *Installer) checkOriginalRuntimeSQLPeer(ctx context.Context, db *sql.DB, expected string) (string, error) {
	if i == nil || db == nil || ctx == nil || ctx.Err() != nil {
		return "", ErrInstall
	}
	var account, server, database, name, tlsVersion string
	var secure bool
	var now time.Time
	if db.QueryRowContext(ctx, "SELECT CURRENT_USER(),@@server_uuid,DATABASE(),@@require_secure_transport,UTC_TIMESTAMP(6)").Scan(&account, &server, &database, &secure, &now) != nil || !secure || server != i.plan.Target.ServerUUID || database != i.plan.Target.Database || account == i.plan.Target.DatabaseAccount || account == i.plan.InstallerDatabaseAccount || expected != "" && account != expected {
		return "", ErrInstall
	}
	parts := strings.Split(account, "@")
	if len(parts) != 2 || parts[1] == "" || c.ValidateControllerDatabaseUser(parts[0]) != nil || strings.EqualFold(parts[0], "root") {
		return "", ErrInstall
	}
	if db.QueryRowContext(ctx, "SHOW SESSION STATUS LIKE 'Ssl_version'").Scan(&name, &tlsVersion) != nil || name != "Ssl_version" || tlsVersion != "TLSv1.3" {
		return "", ErrInstall
	}
	ownerSelected, ownerErr := i.originalMetadataOwnerProfile(ctx, db, account)
	if ownerErr != nil {
		return "", ErrInstall
	}
	if ownerSelected {
		return account, nil
	}
	selected, e := i.originalRuntimeMetadataProfile(ctx, db, account)
	if e != nil {
		return "", ErrInstall
	}
	if selected {
		return account, nil
	}
	if (c.SQLControlEvidenceGrantProbe{DB: db, Schema: database, User: parts[0], Runtime: true, ProviderPermits: true, Publication: true}).Check(ctx) != nil || ctx.Err() != nil {
		return "", ErrInstall
	}
	return account, nil
}
