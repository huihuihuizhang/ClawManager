package systembackupkekadapter

import (
	"context"
	"sync"
	"time"
)

// ProviderPermitTiming is diagnostic DATA, never a receipt or authorization.
// Stage includes its children; Recheck includes its children. Do not sum a
// parent and child. Snapshots include only completed calls and fixed labels.
type ProviderPermitTiming struct {
	Calls, Failures        uint64
	ElapsedNanos, MaxNanos int64
}

type ProviderPermitTimingObserver struct {
	mu   sync.Mutex
	data map[string]ProviderPermitTiming
}
type providerPermitTimingContextKey struct{}

// WithProviderPermitTiming must be installed BEFORE binding an original guard;
// pass the returned SAME context through Bind, Prepare and StageOriginal. It
// neither logs automatically nor retains SQL, requests, identities or material.
func WithProviderPermitTiming(ctx context.Context) (context.Context, *ProviderPermitTimingObserver) {
	o := &ProviderPermitTimingObserver{data: make(map[string]ProviderPermitTiming)}
	return context.WithValue(ctx, providerPermitTimingContextKey{}, o), o
}

func (o *ProviderPermitTimingObserver) Snapshot() map[string]ProviderPermitTiming {
	result := make(map[string]ProviderPermitTiming)
	if o == nil {
		return result
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	for label, value := range o.data {
		result[label] = value
	}
	return result
}

type providerPermitTimer struct {
	observer *ProviderPermitTimingObserver
	label    string
	start    time.Time
}

func startProviderPermitTimer(ctx context.Context, label string) *providerPermitTimer {
	if ctx == nil {
		return nil
	}
	o, _ := ctx.Value(providerPermitTimingContextKey{}).(*ProviderPermitTimingObserver)
	if o == nil {
		return nil
	}
	return &providerPermitTimer{observer: o, label: label, start: time.Now()}
}

func (t *providerPermitTimer) finish(failed bool) {
	if t == nil {
		return
	}
	nanos := time.Since(t.start).Nanoseconds()
	o := t.observer
	o.mu.Lock()
	defer o.mu.Unlock()
	v := o.data[t.label]
	v.Calls++
	if failed {
		v.Failures++
	}
	v.ElapsedNanos += nanos
	if nanos > v.MaxNanos {
		v.MaxNanos = nanos
	}
	o.data[t.label] = v
}
