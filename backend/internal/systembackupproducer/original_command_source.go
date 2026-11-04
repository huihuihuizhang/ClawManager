package systembackupproducer

import (
	"context"
	"reflect"
)

// Only Execute's known successful commit creates this original command chain.
// It grants no operation, read, renewal or replay authority; actual source
// consumers still authenticate their original SQL identity and current scope.
type OriginalCommandSource struct {
	origin   *OriginalCommandSource
	issuer   *Lifecycle
	receipt  CommandReceiptRecord
	previous *OriginalCommandSource
}

func (*OriginalCommandSource) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// OriginalCommittedData returns source comparison data from known committed
// Execute calls. It grants no authority and does not replace current SQL reads.
func (s *OriginalCommandSource) OriginalCommittedData() ([]CommandReceiptRecord, error) {
	var out []CommandReceiptRecord
	seen := map[*OriginalCommandSource]bool{}
	for at := s; at != nil; at = at.previous {
		if at.origin != at || at.issuer == nil || seen[at] || len(out) >= 1024 {
			return nil, ErrGuardRequired
		}
		seen[at] = true
		out = append(out, detached(at.receipt))
	}
	if len(out) == 0 {
		return nil, ErrGuardRequired
	}
	return out, nil
}

func (e *Execution) OriginalCommandSource(h *ExecutionHandle) (*OriginalCommandSource, error) {
	if e == nil || e.lifecycle == nil || !e.validHandle(h) || h.commandSource == nil || h.commandSource.origin != h.commandSource || h.commandSource.issuer != e.lifecycle {
		return nil, ErrGuardRequired
	}
	return h.commandSource, nil
}

func (s *OriginalCommandSource) ReadOriginal(ctx context.Context, read ReadSQL) ([]CommandReceiptRecord, error) {
	var out []CommandReceiptRecord
	seen := map[*OriginalCommandSource]bool{}
	for at := s; at != nil; at = at.previous {
		if at.origin != at || at.issuer == nil || seen[at] || len(out) >= 1024 {
			return nil, ErrGuardRequired
		}
		seen[at] = true
		var actual CommandReceiptRecord
		found, e := ReadOriginalSharedRecord(ctx, read, at.receipt.Scope, RecordKey{Hash: at.receipt.ReceiptKeyHash}, &actual)
		if e != nil || !found || !reflect.DeepEqual(actual, at.receipt) {
			return nil, ErrGuardRequired
		}
		out = append(out, detached(actual))
	}
	if len(out) == 0 {
		return nil, ErrGuardRequired
	}
	return out, nil
}
