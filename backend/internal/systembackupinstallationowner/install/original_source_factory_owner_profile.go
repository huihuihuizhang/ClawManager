package install

import (
	"context"
	"database/sql"
)

// RunOriginalMinIOMetadataSourceFactory authenticates the actual original
// administrator/enrollment first. The actual factory constructor then checks
// the exact native runtime metadata SQL peer under this authenticated profile.
// run is only trusted Go workflow composition: it supplies no authority/proof
// result. The real SourceMaterialIssuer constructor/rechecks and native source
// factory must execute inside this SAME child context before cancellation.
// No context/capability is serialized, cached or returned to a CLI caller.
func (i *Installer) RunOriginalMinIOMetadataSourceFactory(ctx context.Context, db *sql.DB, password []byte, enrollment EnrollmentPin, run func(context.Context) error) error {
	if run == nil {
		return ErrInstall
	}
	actual, close, e := i.originalMetadataOwnerContext(ctx, db, password, enrollment)
	if e != nil {
		return e
	}
	defer close()
	return run(actual)
}
