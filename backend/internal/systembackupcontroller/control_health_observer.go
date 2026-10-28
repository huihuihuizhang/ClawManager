package systembackupcontroller

import (
	"context"
	"sync"
)

// ControlHealthObserver keeps the committed writer token within one leader's
// loop. Construct only after BeginWriter returns a confirmed receipt. It is a
// candidate integration point; the main controller does not enable the new
// table or extend its grants by constructing this adapter automatically.
type ControlHealthObserver struct {
	mu       sync.Mutex
	store    ControlHealthStore
	writer   ControlHealthWriter
	probe    ReadinessProbe
	poisoned bool
}

func NewControlHealthObserver(store ControlHealthStore, writer ControlHealthWriter, probe ReadinessProbe) (*ControlHealthObserver, error) {
	if store.DB == nil || store.DB != writer.database || writer.epoch == 0 || writer.epoch > maxHealthVersion ||
		writer.sequence >= maxHealthVersion || probe == nil {
		return nil, ErrControlHealthFence
	}
	return &ControlHealthObserver{store: store, writer: writer, probe: probe}, nil
}

func (o *ControlHealthObserver) Observe(ctx context.Context, result ControlLoopResult) error {
	if o == nil || ctx == nil || ctx.Err() != nil {
		return ErrControlHealthFence
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.poisoned || ctx.Err() != nil {
		return ErrControlHealthFence
	}
	next, err := o.store.Observe(ctx, o.writer, result, o.probe)
	if err != nil {
		// In particular an unknown commit cannot be retried with a possibly
		// consumed sequence. A new trusted leader admission is required.
		o.poisoned = true
		o.writer = ControlHealthWriter{}
		return err
	}
	o.writer = next
	return nil
}

var _ ControlLoopObserver = (*ControlHealthObserver)(nil)
