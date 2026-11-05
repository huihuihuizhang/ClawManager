package install

import (
	"context"
	"database/sql"
)

// Exact authenticated owner actions, not generic SQL profile overrides.
func (i *Installer) IssueOriginalPublicationAuthorizationForMinIOMetadata(ctx context.Context, runtimeDB *sql.DB, password []byte, enrollment EnrollmentPin, in OriginalPublicationAuthorizationInputs, issuerPrivate []byte) (OriginalPublicationAuthorizationReceipt, error) {
	actual, close, e := i.originalMetadataOwnerContext(ctx, runtimeDB, password, enrollment)
	if e != nil {
		return OriginalPublicationAuthorizationReceipt{}, e
	}
	defer close()
	return i.IssueOriginalPublicationAuthorization(actual, runtimeDB, password, enrollment, in, issuerPrivate)
}

// Provider preparation is intentionally scoped by the complete production
// entry, before C1 creates context-bound sources. A small Prepare wrapper that
// defers close before returning the pending holder would invalidate it. A
// direct Issue wrapper cannot re-parent an already-created C1 source either.
