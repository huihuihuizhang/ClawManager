package publicadapter

import (
	"clawreef/internal/systembackup/flow"
	d "clawreef/internal/systembackupdispatch"
	"context"
	"strconv"
)

// An originally stopped instance has no synthetic historical Pod. A positive
// ACK is emitted only after D's concrete P7 roundtrip, never by Guard alone.
type stoppedProWriter struct {
	spec      RuntimeWriterSpec
	authority d.Authority
	deps      RuntimeWriterDependencies
}

func (w *stoppedProWriter) ID() string { return "stopped/" + strconv.Itoa(w.spec.Source.ID) }
func (w *stoppedProWriter) check(ctx context.Context, point string, s flow.State) error {
	if s != w.spec.Stopped || s.Running || w.deps.Callbacks.StoppedProControl == nil {
		return flow.ErrQuiesce
	}
	return writerGuard(ctx, w.deps, w.authority, w.ID(), point, s)
}
func (w *stoppedProWriter) Observe(ctx context.Context) (flow.State, error) {
	return w.spec.Stopped, w.check(ctx, "observe", w.spec.Stopped)
}
func (w *stoppedProWriter) Pause(ctx context.Context, s flow.State) (flow.ACK, error) {
	if err := w.check(ctx, "before-stop", s); err != nil {
		return flow.ACK{}, err
	}
	if err := w.deps.Callbacks.StoppedProControl(ctx, w.authority, w.ID(), "prepare-stopped", s); err != nil {
		return flow.ACK{}, err
	}
	return flow.ACK{UID: s.UID, Generation: s.Generation, Stopped: true}, nil
}
func (w *stoppedProWriter) CheckPaused(ctx context.Context, s flow.State) error {
	if err := w.check(ctx, "check-stopped", s); err != nil {
		return err
	}
	point := "stopped"
	if ctx.Value(sourceRecoveryContext{}) == true {
		point = "recovery-stopped"
	}
	return w.deps.Callbacks.StoppedProControl(ctx, w.authority, w.ID(), point, s)
}
func (w *stoppedProWriter) Resume(ctx context.Context, s flow.State) error {
	if err := w.check(ctx, "before-resume", s); err != nil {
		return err
	}
	return w.deps.Callbacks.StoppedProControl(ctx, w.authority, w.ID(), "recovered-stopped", s)
}
