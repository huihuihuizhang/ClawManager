package flow

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

type fakeWriter struct {
	name                  string
	events                *[]string
	failPause, failResume bool
	failCheck             bool
	resumeCanceled        bool
	original              State
}

func (w *fakeWriter) ID() string                             { return w.name }
func (w *fakeWriter) Observe(context.Context) (State, error) { return w.original, nil }
func (w *fakeWriter) CheckPaused(context.Context, State) error {
	if w.failCheck {
		return ErrQuiesce
	}
	return nil
}
func (w *fakeWriter) Pause(context.Context, State) (ACK, error) {
	*w.events = append(*w.events, "pause:"+w.name)
	if w.failPause {
		return ACK{}, errors.New("uncertain")
	}
	return ACK{w.original.UID, w.original.Generation, true}, nil
}
func (w *fakeWriter) Resume(ctx context.Context, s State) error {
	*w.events = append(*w.events, "resume:"+w.name)
	w.resumeCanceled = ctx.Err() != nil
	if s != w.original || w.failResume {
		return errors.New("resume")
	}
	return nil
}

type fakeCollector struct {
	events                   *[]string
	failPrepare, failCapture bool
	cancel                   context.CancelFunc
}

func (c fakeCollector) ID() string                 { return "workspace" }
func (c fakeCollector) Stop(context.Context) error { return nil }
func (c fakeCollector) Prepare(context.Context) error {
	*c.events = append(*c.events, "prepare")
	if c.failPrepare {
		return errors.New("prepare")
	}
	return nil
}
func (c fakeCollector) Capture(context.Context) (Part, error) {
	*c.events = append(*c.events, "capture")
	if c.cancel != nil {
		c.cancel()
	}
	if c.failCapture {
		return Part{}, errors.New("capture")
	}
	return Part{"workspace", "checkpoint", "immutable-staging"}, nil
}

type fakeJournal struct {
	events       *[]string
	fail         bool
	failRecovery bool
}

func (j fakeJournal) CheckRecoveryFence(context.Context, Identity, string, State) error {
	if j.failRecovery {
		return ErrJournal
	}
	return nil
}

func (j fakeJournal) CheckFence(context.Context, Identity) error {
	if j.fail {
		return errors.New("fence")
	}
	return nil
}
func (j fakeJournal) PauseIntent(_ context.Context, _ Identity, id string, _ State) error {
	*j.events = append(*j.events, "intent:"+id)
	return nil
}
func (j fakeJournal) Paused(_ context.Context, _ Identity, id string, _ ACK) error {
	*j.events = append(*j.events, "ack:"+id)
	return nil
}
func (j fakeJournal) Resumed(_ context.Context, _ Identity, id string) error {
	*j.events = append(*j.events, "resumed:"+id)
	return nil
}
func request(events *[]string) (Request, *fakeWriter, *fakeWriter) {
	a := &fakeWriter{name: "lite", events: events, original: State{UID: "pod-a", Generation: 7, Running: true}}
	b := &fakeWriter{name: "pro", events: events, original: State{UID: "deployment-b", Generation: 3, Running: false}}
	return Request{Identity: Identity{"backup", "attempt", "capture", 4}, HoldUntil: time.Now().Add(time.Minute), ResumeTimeout: time.Second, Writers: []Writer{a, b}, Collectors: []Collector{fakeCollector{events: events}}, Journal: fakeJournal{events: events}, DependenciesReady: func(context.Context) error { return nil }}, a, b
}
func TestCaptureBarrierSealsBeforeResumeAndRestoresOriginalStates(t *testing.T) {
	var events []string
	r, _, _ := request(&events)
	parts, e := Capture(context.Background(), r)
	if e != nil || len(parts) != 1 {
		t.Fatal(e)
	}
	want := []string{"prepare", "intent:lite", "pause:lite", "ack:lite", "intent:pro", "pause:pro", "ack:pro", "capture", "resume:pro", "resumed:pro", "resume:lite", "resumed:lite"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("wrong barrier ordering: %v", events)
	}
}

type stoppingCollector struct {
	fakeCollector
	failStop bool
}

func (c stoppingCollector) Stop(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	*c.events = append(*c.events, "collector-stopped")
	if c.failStop {
		return ErrQuiesce
	}
	return nil
}
func TestCollectorTerminationPrecedesAnySourceResume(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "confirmed", true: "unconfirmed"}[fail], func(t *testing.T) {
			var events []string
			r, _, _ := request(&events)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r.Collectors = []Collector{stoppingCollector{fakeCollector: fakeCollector{events: &events, cancel: cancel}, failStop: fail}}
			parts, e := Capture(ctx, r)
			if e == nil || len(parts) != 0 {
				t.Fatal("canceled capture succeeded")
			}
			stopped, resumed := false, false
			for _, event := range events {
				if event == "collector-stopped" {
					stopped = true
				}
				if event == "resume:lite" || event == "resume:pro" {
					if !stopped || fail {
						t.Fatal("source resumed before proven collector exit")
					}
					resumed = true
				}
			}
			if !stopped || (!fail && !resumed) {
				t.Fatal("cleanup did not use its independent context", events)
			}
		})
	}
}
func TestUncertainPauseCancellationAndResumeFailure(t *testing.T) {
	for _, mode := range []string{"pause", "capture", "cancel", "resume", "prepare", "fence"} {
		t.Run(mode, func(t *testing.T) {
			var events []string
			r, a, b := request(&events)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "pause":
				b.failPause = true
			case "capture":
				r.Collectors = []Collector{fakeCollector{events: &events, failCapture: true}}
			case "cancel":
				r.Collectors = []Collector{fakeCollector{events: &events, cancel: cancel}}
			case "resume":
				b.failResume = true
			case "prepare":
				r.Collectors = []Collector{fakeCollector{events: &events, failPrepare: true}}
			case "fence":
				r.Journal = fakeJournal{events: &events, fail: true}
			}
			parts, e := Capture(ctx, r)
			if e == nil || len(parts) != 0 {
				t.Fatal("failure returned completed parts")
			}
			if a.resumeCanceled || b.resumeCanceled {
				t.Fatal("capture cancellation canceled recovery")
			}
			if mode != "prepare" && mode != "fence" {
				foundA, foundB := false, false
				for _, event := range events {
					foundA = foundA || event == "resume:lite"
					foundB = foundB || event == "resume:pro"
				}
				if !foundA || !foundB {
					t.Fatal("did not compensate all uncertain pauses")
				}
			}
		})
	}
}
