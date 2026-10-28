package systembackupevidence

import (
	"context"
	"net/http"
	"sync/atomic"
)

// RecoveryRuntimeConfig is trusted deployment admission for an independent
// recovery worker. Authority requires the production SQLPolicy and Failure
// sink. No route, scheduler, credentials or permissive policy is created here.
type RecoveryRuntimeConfig struct {
	Authority WriteRecoveryConfig
	S3        S3STSConfig
}

// RecoveryRuntime binds recovery claims and every STS request to the same
// live SQL authority. The host authenticates its pinned mTLS request, then runs
// a bounded batch or individual reconciliation with the returned context.
// Drain in-flight work before Close. Recreate on admitted configuration change.
type RecoveryRuntime struct {
	authority *SQLWriteRecovery
	sts       *S3STSCredentials
	store     *S3Store
	closed    atomic.Bool
}

func NewRecoveryRuntime(c RecoveryRuntimeConfig) (*RecoveryRuntime, error) {
	s, a := c.S3.Store, c.Authority
	if s.Installation != a.Registry.Installation || s.Identity != a.Store.Identity || s.Version != a.Store.Version || s.Root != a.Root || c.S3.Issuer != a.Issuer || c.S3.Audience != a.Audience {
		return nil, ErrInvalid
	}
	authority, err := NewSQLWriteRecovery(a)
	if err != nil {
		return nil, err
	}
	r := &RecoveryRuntime{authority: authority}
	r.sts, err = NewS3STSCredentials(c.S3, authority)
	if err != nil {
		r.Close()
		return nil, err
	}
	// Recovery never proves absence: an ordinary 404 preserves unknown state.
	r.store, err = NewS3Store(s, r.sts, downloadNoAbsence{})
	if err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

func (r *RecoveryRuntime) AuthenticateRequest(req *http.Request) (context.Context, error) {
	if r == nil || r.closed.Load() {
		return nil, ErrUnavailable
	}
	return r.authority.AuthenticateRequest(req)
}

func (r *RecoveryRuntime) Reconcile(ctx context.Context, id string) error {
	if r == nil || r.closed.Load() {
		return ErrUnavailable
	}
	return r.authority.Reconcile(ctx, id, recoveryStatOnly{r.store})
}

func (r *RecoveryRuntime) ReconcileBatch(ctx context.Context, afterID int64, limit int) (RecoveryBatch, error) {
	if r == nil || r.closed.Load() {
		return RecoveryBatch{AfterID: afterID}, ErrUnavailable
	}
	return r.authority.ReconcileBatch(ctx, afterID, limit, recoveryStatOnly{r.store})
}

func (r *RecoveryRuntime) Close() {
	if r != nil && !r.closed.Swap(true) {
		r.store.Close()
		r.sts.Close()
	}
}

// Do not embed S3Store: recovery has no object mutation, body read, absence
// verification or key operation, even through a widened interface assertion.
type recoveryStatOnly struct{ store *S3Store }

func (s recoveryStatOnly) Stat(ctx context.Context, ref Ref) (ObjectInfo, error) {
	return s.store.Stat(ctx, ref)
}
