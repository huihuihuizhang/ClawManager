package install

import (
	"context"
	"database/sql"
	"strings"
	"sync/atomic"

	c "clawreef/internal/systembackupcontroller"
)

type originalMetadataOwnerContextKey struct{}
type originalMetadataOwnerScope struct {
	origin     *originalMetadataOwnerScope
	installer  *Installer
	db         *sql.DB
	ctx        context.Context
	operator   *authenticatedOperator
	enrollment EnrollmentPin
	active     atomic.Bool
}

// Real original Installer authentication/enrollment establishes only this
// explicit SQL PROFILE selection boundary. It is not metadata reader consent.
func (i *Installer) originalMetadataOwnerContext(parent context.Context, db *sql.DB, password []byte, enrollment EnrollmentPin) (context.Context, context.CancelFunc, error) {
	if parent == nil || db == nil {
		return nil, nil, ErrInstall
	}
	scoped, cancel := context.WithCancel(parent)
	proof := &originalMetadataOwnerScope{installer: i, db: db, enrollment: enrollment}
	ctx := context.WithValue(scoped, originalMetadataOwnerContextKey{}, proof)
	op, e := i.authenticate(ctx, password)
	if e != nil {
		cancel()
		return nil, nil, ErrInstall
	}
	if _, _, e = originalRuntimeAuthoritySnapshot(ctx, op, enrollment); e != nil {
		cancel()
		return nil, nil, ErrInstall
	}
	proof.origin = proof
	proof.ctx = ctx
	proof.operator = op
	proof.active.Store(true)
	close := func() { proof.active.Store(false); cancel() }
	return ctx, close, nil
}
func (i *Installer) originalMetadataOwnerProfile(ctx context.Context, db *sql.DB, account string) (bool, error) {
	proof, _ := ctx.Value(originalMetadataOwnerContextKey{}).(*originalMetadataOwnerScope)
	if proof == nil {
		return false, nil
	}
	if proof.origin != proof || !proof.active.Load() || proof.installer != i || proof.db != db || proof.ctx != ctx || proof.operator == nil || !proof.operator.live(ctx) || proof.operator.authority(ctx, proof.enrollment) != nil {
		return false, ErrInstall
	}
	// Actual account/server/TLS checks ran immediately before this branch.
	// No GRANT or new task/key permission is issued here.
	if (c.SQLMinIOMetadataReadGrantProbe{DB: db, Schema: i.plan.Target.Database, User: strings.Split(account, "@")[0], Runtime: true, ProviderPermits: true, Publication: true}).Check(ctx) != nil {
		return true, ErrInstall
	}
	return true, nil
}

// Explicit fresh-v4 original owner action. The unchanged existing producer
// still authenticates all original config/source/native/worker/issuer inputs.
func (i *Installer) IssueOriginalRuntimeExecutionForMinIOMetadata(ctx context.Context, runtimeDB *sql.DB, password []byte, enrollment EnrollmentPin, in OriginalRuntimeExecutionIssueInputs) (OriginalRuntimeExecutionIssueReceipt, error) {
	actual, close, e := i.originalMetadataOwnerContext(ctx, runtimeDB, password, enrollment)
	if e != nil {
		return OriginalRuntimeExecutionIssueReceipt{}, e
	}
	defer close()
	return i.IssueOriginalRuntimeExecution(actual, runtimeDB, password, enrollment, in)
}
