package install

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// BootstrapSourceReaderAccess is an outside-SQL physical read capability for
// the exact original source association. It grants no terminal admission. Its
// private time bounds start BEFORE any native read, never at completion.
type BootstrapSourceReaderAccess struct {
	mu            sync.Mutex
	origin        *BootstrapSourceReaderAccess
	source        *PreparedBootstrapSourceRegistries
	ctx, physical context.Context
	cancel        context.CancelFunc
	start, until  time.Time
	selected      []BootstrapSourceFilePin
	limits        map[BootstrapSourceFilePin]int64
	failed        atomic.Bool
}

func NewBootstrapSourceReaderAccess(ctx context.Context, source *PreparedBootstrapSourceRegistries) (*BootstrapSourceReaderAccess, error) {
	if source == nil {
		return nil, ErrInstall
	}
	selected := bootstrapSourceFiles(source.record.Source)
	limits := map[BootstrapSourceFilePin]int64{}
	for _, pin := range selected {
		limits[pin] = 262144
	}
	return newBootstrapSourceReaderAccess(ctx, source, selected, limits)
}

func NewBootstrapSourceReaderV2Access(ctx context.Context, source *PreparedBootstrapSourceRegistriesV2) (*BootstrapSourceReaderAccess, error) {
	if source == nil || source.origin != source || source.base == nil {
		return nil, source.reject()
	}
	selected := bootstrapSourceV2Files(source.record.Source)
	limits := map[BootstrapSourceFilePin]int64{}
	for _, pin := range selected {
		limits[pin] = bootstrapSourceV2FileLimit(source.record.Source, pin)
	}
	return newBootstrapSourceReaderAccess(ctx, source.base, selected, limits)
}

func newBootstrapSourceReaderAccess(ctx context.Context, source *PreparedBootstrapSourceRegistries, selected []BootstrapSourceFilePin, limits map[BootstrapSourceFilePin]int64) (*BootstrapSourceReaderAccess, error) {
	if source == nil || source.origin != source {
		return nil, ErrInstall
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	now := time.Now().UTC()
	if source.tx != nil || !consumerSameContext(ctx, source.ctx) || ctx.Err() != nil || now.Before(source.record.NotBefore) || !now.Before(source.record.Until) || source.local(ctx) != nil {
		return nil, ErrInstall
	}
	start := time.Now().UTC().Truncate(time.Microsecond)
	until := start.Add(30 * time.Second)
	if source.record.Until.Before(until) {
		until = source.record.Until
	}
	if deadline, ok := ctx.Deadline(); !ok {
		return nil, ErrInstall
	} else if deadline.Before(until) {
		until = deadline.UTC().Truncate(time.Microsecond)
	}
	if start.Before(source.record.NotBefore) || !start.Before(until) {
		return nil, ErrInstall
	}
	physical, cancel := context.WithDeadline(ctx, until)
	a := &BootstrapSourceReaderAccess{source: source, ctx: ctx, physical: physical, cancel: cancel, start: start, until: until, selected: selected, limits: limits}
	a.origin = a
	return a, nil
}

func (*BootstrapSourceReaderAccess) MarshalJSON() ([]byte, error) { return nil, ErrInstall }

func (a *BootstrapSourceReaderAccess) reject() error {
	if a != nil {
		a.failed.Store(true)
		if a.origin != nil {
			a.origin.failed.Store(true)
		}
	}
	return ErrInstall
}

func (a *BootstrapSourceReaderAccess) current(ctx context.Context) error {
	if a.origin != a || a.failed.Load() || !consumerSameContext(ctx, a.ctx) || ctx.Err() != nil || a.physical.Err() != nil {
		return a.reject()
	}
	p := a.source
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now().UTC()
	if p.tx != nil || now.Before(a.start) || now.Before(p.record.NotBefore) || !now.Before(a.until) || !now.Before(p.record.Until) || p.local(ctx) != nil {
		return a.reject()
	}
	now = time.Now().UTC()
	if now.Before(a.start) || now.Before(p.record.NotBefore) || !now.Before(a.until) || !now.Before(p.record.Until) || ctx.Err() != nil {
		return a.reject()
	}
	return nil
}

// Check must bracket each real native request. An original SQL capability is
// never returned or used here; native time cannot replace SQL SampleTime.
func (a *BootstrapSourceReaderAccess) Check(ctx context.Context) error {
	if a == nil || a.origin != a {
		return a.reject()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.current(ctx) != nil {
		return a.reject()
	}
	for _, pin := range a.selected {
		raw, err := readBootstrapSourcePin(pin, a.limits[pin])
		clear(raw)
		if err != nil {
			return a.reject()
		}
	}
	if a.current(ctx) != nil {
		return a.reject()
	}
	return nil
}

func (a *BootstrapSourceReaderAccess) Read(ctx context.Context, pin BootstrapSourceFilePin) ([]byte, error) {
	if a == nil || a.origin != a {
		return nil, a.reject()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.current(ctx) != nil {
		return nil, a.reject()
	}
	for _, selected := range a.selected {
		if selected != pin {
			continue
		}
		raw, err := readBootstrapSourcePin(pin, a.limits[pin])
		if err != nil || a.current(ctx) != nil {
			clear(raw)
			return nil, a.reject()
		}
		return raw, nil
	}
	return nil, a.reject()
}

func (a *BootstrapSourceReaderAccess) NativeContext(ctx context.Context) (context.Context, error) {
	if a.Check(ctx) != nil {
		return nil, ErrInstall
	}
	return a.physical, nil
}

// Bounds are detached comparison times only, not an observation result or a
// deadline that callers may attach to a terminal. Only B's actual successful
// finite reader may retain them in its own private check.
func (a *BootstrapSourceReaderAccess) Bounds(ctx context.Context) (time.Time, time.Time, error) {
	if a.Check(ctx) != nil {
		return time.Time{}, time.Time{}, ErrInstall
	}
	return a.start, a.until, nil
}

func (a *BootstrapSourceReaderAccess) Close() {
	if a == nil || a.origin != a {
		_ = a.reject()
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.failed.Store(true)
	a.cancel()
}
