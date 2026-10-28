package systembackupevidence

import (
	"context"
	"database/sql"

	sec "clawreef/internal/systembackupsecurity"
)

// Minted only after JWT authentication (or from its known committed admission).
// A plain Actor/session digest supplied to SQLPolicy is not this boundary.
type verifiedDownloadActorKey struct{}
type verifiedDownloadActor struct {
	db                             *sql.DB
	installation, server, database string
	actor                          sec.RegistrationActor
}

func withVerifiedDownloadActor(ctx context.Context, r SQLRegistry, a sec.RegistrationActor) context.Context {
	a.SessionIssuedAt = a.SessionIssuedAt.UTC()
	a.SessionExpiresAt = a.SessionExpiresAt.UTC()
	return context.WithValue(ctx, verifiedDownloadActorKey{}, verifiedDownloadActor{r.DB, r.Installation, r.ServerUUID, r.Database, a})
}
func verifiedDownloadActorFrom(ctx context.Context, r SQLRegistry) (sec.RegistrationActor, bool) {
	if ctx == nil || ctx.Err() != nil {
		return sec.RegistrationActor{}, false
	}
	a, ok := ctx.Value(verifiedDownloadActorKey{}).(verifiedDownloadActor)
	return a.actor, ok && a.db == r.DB && a.installation == r.Installation && a.server == r.ServerUUID && a.database == r.Database
}
