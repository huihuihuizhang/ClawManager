package systembackupevidence

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"sync/atomic"
)

var errDownloadGCFinalizationDenied = errors.New("download_gc_finalization_denied")

// Issued by protected work only. Copies share the entire immutable binding and
// one consumption bit; no request/config DTO can supply replacement facts.
type downloadGCWorkFinalizer struct{ state *downloadGCFinalizerState }
type downloadGCFinalizerState struct {
	used      atomic.Bool
	ctx       context.Context
	tx        *sql.Tx
	collector any
	operation string
	check     func(context.Context, *sql.Tx) error
}

func (downloadGCWorkFinalizer) String() string   { return "DownloadGCWorkFinalizer" }
func (downloadGCWorkFinalizer) GoString() string { return "DownloadGCWorkFinalizer" }
func (downloadGCWorkFinalizer) MarshalJSON() ([]byte, error) {
	return nil, errDownloadGCFinalizationDenied
}

func comparableGCIdentity(v any) bool {
	if v == nil {
		return false
	}
	r := reflect.ValueOf(v)
	// A comparable struct type can still hold a slice/map in an interface
	// field. Check the complete dynamic value before any interface equality.
	return r.Comparable() && (r.Kind() != reflect.Ptr || !r.IsNil())
}

// This private issuer is called only after the real protected work succeeds.
// check closes over original guards/facts. It neither creates nor authenticates
// authority: the collector's concrete work is the issuer, never an allow DTO.
func issueDownloadGCFinalizer(ctx context.Context, tx *sql.Tx, collector any, operation string, check func(context.Context, *sql.Tx) error) *downloadGCWorkFinalizer {
	if !comparableGCIdentity(ctx) || !comparableGCIdentity(collector) || reflect.ValueOf(collector).Kind() != reflect.Ptr || tx == nil || operation == "" || check == nil || ctx.Err() != nil {
		return nil
	}
	return &downloadGCWorkFinalizer{state: &downloadGCFinalizerState{ctx: ctx, tx: tx, collector: collector, operation: operation, check: check}}
}

// Consume even a failed attempt. The caller cannot replace the original context
// with a fresh budget, switch tx/collector/scope, or retry through a value copy.
// This method never acquires a connection or ends/retries a transaction.
func (f *downloadGCWorkFinalizer) finish(ctx context.Context, tx *sql.Tx, collector any, operation string) error {
	if f == nil || f.state == nil || !f.state.used.CompareAndSwap(false, true) {
		return errDownloadGCFinalizationDenied
	}
	s := f.state
	if !comparableGCIdentity(ctx) || !comparableGCIdentity(collector) || ctx != s.ctx || tx == nil || tx != s.tx || collector != s.collector || operation != s.operation || s.ctx.Err() != nil || s.check == nil {
		return errDownloadGCFinalizationDenied
	}
	if s.check(s.ctx, s.tx) != nil || s.ctx.Err() != nil {
		return errDownloadGCFinalizationDenied
	}
	return nil
}
