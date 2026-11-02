package systembackupcontroller

import (
	"context"
	"reflect"
	"sync/atomic"

	d "clawreef/internal/systembackupdispatch"
)

type originalHeldReadScopeKey struct{}
type originalHeldReadScope struct {
	ctx       context.Context
	store     SQLExecutionAuthority
	authority d.Authority
	active    atomic.Bool
}

// OpenOriginalHeldControlReadScope selects only the CURRENT held-capture SQL
// read implementation for ONE original control RPC. It retains no authority,
// rows, result, clock, permit or successful check. Every Bind/Check still reads
// every original field and invokes the original authorization owner afresh.
// Closing the scope disables all retained context copies without cancelling or
// renewing the caller's original context/deadline. Other actions use legacy SQL.
func OpenOriginalHeldControlReadScope(ctx context.Context, store SQLExecutionAuthority, a d.Authority) (context.Context, func(), error) {
	if absentExecutionDependency(ctx) || !reflect.TypeOf(ctx).Comparable() || ctx.Err() != nil || store.DB == nil || !store.DeploymentEnabled || absentExecutionDependency(store.Authorization) || store.ApplicationScope == "" || !validExecutionInput(a, store.InstallationID) || a.TaskType != "backup" || a.Phase != "capture" || a.MaintenanceFencingToken == 0 {
		return nil, nil, ErrExecutionAuthority
	}
	scope := &originalHeldReadScope{store: store, authority: a}
	owned := context.WithValue(ctx, originalHeldReadScopeKey{}, scope)
	scope.ctx = owned
	scope.active.Store(true)
	return owned, func() { scope.active.Store(false) }, nil
}

func useOriginalHeldControlRead(ctx context.Context, store SQLExecutionAuthority, a d.Authority) bool {
	if absentExecutionDependency(ctx) || !reflect.TypeOf(ctx).Comparable() || ctx.Err() != nil {
		return false
	}
	scope, ok := ctx.Value(originalHeldReadScopeKey{}).(*originalHeldReadScope)
	return ok && scope != nil && scope.active.Load() && ctx == scope.ctx && scope.authority == a && sameOriginalExecutionStore(scope.store, store)
}
