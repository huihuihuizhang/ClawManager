package quiesce

import (
	"context"
	"errors"
	"testing"
	"time"

	"clawreef/internal/systembackup/flow"
)

type captureJournal struct{ pending []flow.PauseRecord }

func (j *captureJournal) CheckFence(context.Context, flow.Identity) error { return nil }
func (j *captureJournal) CheckRecoveryFence(ctx context.Context, _ flow.Identity, _ string, _ flow.State) error {
	return ctx.Err()
}
func (j *captureJournal) PauseIntent(_ context.Context, _ flow.Identity, id string, s flow.State) error {
	j.pending = append(j.pending, flow.PauseRecord{WriterID: id, Original: s})
	return nil
}
func (j *captureJournal) Paused(context.Context, flow.Identity, string, flow.ACK) error { return nil }
func (j *captureJournal) Resumed(_ context.Context, _ flow.Identity, id string) error {
	for i, p := range j.pending {
		if p.WriterID == id {
			j.pending = append(j.pending[:i], j.pending[i+1:]...)
			break
		}
	}
	return nil
}
func (j *captureJournal) PendingPauses(context.Context, flow.Identity) ([]flow.PauseRecord, error) {
	return append([]flow.PauseRecord(nil), j.pending...), nil
}

type captureCollector struct {
	collect func(context.Context) (flow.Part, error)
}

func (c captureCollector) ID() string                                     { return "fixture" }
func (c captureCollector) Prepare(context.Context) error                  { return nil }
func (c captureCollector) Stop(context.Context) error                     { return nil }
func (c captureCollector) Capture(ctx context.Context) (flow.Part, error) { return c.collect(ctx) }

func TestCaptureWithProAdaptersRecoversAfterCollectorCancellation(t *testing.T) {
	d := newDeploymentFixture(t, 1)
	p := newPodFixture(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	journal := &captureJournal{}
	collected := false
	collector := captureCollector{collect: func(hold context.Context) (flow.Part, error) {
		collected = true
		if len(journal.pending) != 2 {
			t.Fatal("missing original intents")
		}
		for _, entry := range journal.pending {
			var writer flow.Writer = d.writer
			if entry.WriterID == p.writer.ID() {
				writer = p.writer
			}
			if e := writer.CheckPaused(hold, entry.Original); e != nil {
				t.Fatal("collector started without source barrier", e)
			}
		}
		cancel()
		return flow.Part{}, errors.New("collector interrupted")
	}}
	parts, e := flow.Capture(ctx, flow.Request{Identity: flow.Identity{Task: "fixture", Attempt: "1", Phase: "capture", Generation: 1}, HoldUntil: time.Now().Add(time.Second), ResumeTimeout: time.Second, Writers: []flow.Writer{d.writer, p.writer}, Collectors: []flow.Collector{collector}, Journal: journal, DependenciesReady: func(context.Context) error { return nil }})
	if e == nil || len(parts) != 0 || !collected || len(journal.pending) != 0 {
		t.Fatal("cancellation was not compensated", e)
	}
	check := testDeadline(t)
	deployment, e := d.writer.get(check)
	if e != nil || *deployment.Spec.Replicas != 1 {
		t.Fatal("Deployment not recovered", e)
	}
	pod, e := p.writer.get(check)
	if e != nil || pod.UID != "recovered-pod" || p.creates != 1 {
		t.Fatal("Pod not recovered", e)
	}
}

func TestRecoverSourceRebuildsAdapterAfterLostPauseResponse(t *testing.T) {
	f := newPodFixture(t, true)
	ctx := testDeadline(t)
	s, e := f.writer.Observe(ctx)
	if e != nil {
		t.Fatal(e)
	}
	journal := &captureJournal{pending: []flow.PauseRecord{{WriterID: f.writer.ID(), Original: s}}}
	f.delayDelete = true
	if _, e = f.writer.Pause(ctx, s); e == nil {
		t.Fatal("expected lost response")
	}
	// The remote deletion completes after the old controller exits. No ACK was
	// persisted. A rebuilt adapter must recover the recorded original state.
	f.delayDelete = false
	if e = f.remove(ctx, f.writer.Name, f.delayed); e != nil {
		t.Fatal(e)
	}
	rebuilt := *f.writer
	e = flow.RecoverSource(ctx, flow.Identity{Task: "fixture", Attempt: "1", Phase: "capture", Generation: 1}, journal, []flow.Writer{&rebuilt})
	if e != nil || len(journal.pending) != 0 || f.creates != 1 {
		t.Fatal("takeover failed", e)
	}
}
