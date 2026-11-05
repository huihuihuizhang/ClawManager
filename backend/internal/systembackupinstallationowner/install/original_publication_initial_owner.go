package install

import (
	"context"
	"database/sql"
	"time"

	c "clawreef/internal/systembackupcontroller"
	owner "clawreef/internal/systembackupinstallationowner"
)

// Separate original head0 action. The generic active-head issuer is unchanged.
// This scope returns ordinary signed material only, never an opaque C1 source.
func (i *Installer) IssueInitialPublicationAuthorizationForMinIOMetadata(ctx context.Context, runtimeDB *sql.DB, password []byte, enrollment EnrollmentPin, in OriginalPublicationAuthorizationInputs, issuerPrivate []byte) (OriginalPublicationAuthorizationReceipt, error) {
	actual, closeScope, e := i.originalMetadataOwnerContext(ctx, runtimeDB, password, enrollment)
	if e != nil {
		return OriginalPublicationAuthorizationReceipt{}, e
	}
	defer closeScope()
	return i.issueOriginalPublicationAuthorizationAtHead(actual, runtimeDB, password, enrollment, in, issuerPrivate, nil, true)
}

func originalInitialPublicationRequest(i *Installer, op *authenticatedOperator, request *originalRequest, now time.Time) bool {
	if i == nil || op == nil || request == nil || now.IsZero() || now.Before(request.start) || !now.Before(request.end) {
		return false
	}
	g := request.grant
	t := i.plan.Target
	return g.InstallationID == t.InstallationID && g.ServerUUID == t.ServerUUID && g.Database == t.Database && g.UserID == op.userID && g.Username == i.plan.LocalAdminUsername && g.ConfigSHA256 == request.config.SHA256()
}

func originalInitialPublicationBinding(i *Installer, op *authenticatedOperator, g c.ExecutionGrant, record owner.Record, selected BootstrapSourceFilePin, request *originalRequest, now time.Time) error {
	if !originalInitialPublicationRequest(i, op, request, now) || record.Target != (owner.Target{}) || g.ConfigVersion != 1 || g.InstallationID != i.plan.Target.InstallationID || g.ServerUUID != i.plan.Target.ServerUUID || g.Database != i.plan.Target.Database || g.ConfigSHA256 != request.config.SHA256() || selected.File != request.files.ConfigFile || selected.SHA256 != request.files.ConfigFileSHA256 || selected.SHA256 != request.config.SHA256() {
		return ErrInstall
	}
	return nil
}

// Explicit original head0 reader for the concrete provider preparation. It
// verifies the same signed original Request, not a fabricated head1 Record.
func (i *Installer) ReadInitialPublicationRuntimeOwnerInputsForMinIOMetadata(ctx context.Context, password []byte, enrollment EnrollmentPin, pin BootstrapSourceFilePin, files RequestFiles, runtimeDB *sql.DB) (OriginalPublicationRuntimeOwnerInputs, error) {
	actual, closeScope, e := i.originalMetadataOwnerContext(ctx, runtimeDB, password, enrollment)
	if e != nil {
		return OriginalPublicationRuntimeOwnerInputs{}, e
	}
	defer closeScope()
	r, e := readRequest(i, files)
	if e != nil {
		return OriginalPublicationRuntimeOwnerInputs{}, e
	}
	defer r.observer.Close()
	return i.readOriginalPublicationRuntimeOwnerInputsAtHead(actual, password, enrollment, pin, nil, r, runtimeDB)
}
