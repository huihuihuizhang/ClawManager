package flow

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

type recoveryJournal struct {
	fakeJournal
	records []PauseRecord
	loadErr bool
	saveErr bool
}

func (j recoveryJournal) PendingPauses(context.Context, Identity) ([]PauseRecord, error) {
	if j.loadErr {
		return nil, ErrJournal
	}
	return j.records, nil
}
func (j recoveryJournal) Resumed(ctx context.Context, id Identity, w string) error {
	if j.saveErr {
		return ErrJournal
	}
	return j.fakeJournal.Resumed(ctx, id, w)
}
func TestRecoveryUsesOriginalIntentsInReverseOrder(t *testing.T) {
	var events []string
	r, a, b := request(&events)
	j := recoveryJournal{fakeJournal: fakeJournal{events: &events}, records: []PauseRecord{{a.ID(), a.original}, {b.ID(), b.original}}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// No successful pause ACK exists. Both uncertain operations must reconcile
	// from their durable original states, including the originally stopped Pro.
	if e := RecoverSource(ctx, r.Identity, j, r.Writers); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(events, []string{"resume:pro", "resumed:pro", "resume:lite", "resumed:lite"}) {
		t.Fatal(events)
	}
}
func TestRecoveryRejectsIncompleteInventoryAndLostAuthority(t *testing.T) {
	for _, mode := range []string{"duplicate", "missing-writer", "identity", "load", "fence", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			var events []string
			r, a, _ := request(&events)
			j := recoveryJournal{fakeJournal: fakeJournal{events: &events}, records: []PauseRecord{{a.ID(), a.original}}}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			switch mode {
			case "duplicate":
				j.records = append(j.records, j.records[0])
			case "missing-writer":
				j.records[0].WriterID = "unregistered"
			case "identity":
				j.records[0].Original.UID = ""
			case "load":
				j.loadErr = true
			case "fence":
				j.failRecovery = true
			case "deadline":
				ctx = context.Background()
			}
			if e := RecoverSource(ctx, r.Identity, j, r.Writers); e == nil || len(events) != 0 {
				t.Fatal("mutated without valid recovery inventory/authority", e, events)
			}
		})
	}
}
func TestRecoveryKeepsFailuresPendingAndContinuesOtherWriters(t *testing.T) {
	var events []string
	r, a, b := request(&events)
	b.failResume = true
	j := recoveryJournal{fakeJournal: fakeJournal{events: &events}, records: []PauseRecord{{a.ID(), a.original}, {b.ID(), b.original}}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e := RecoverSource(ctx, r.Identity, j, r.Writers); !errors.Is(e, ErrResume) {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(events, []string{"resume:pro", "resume:lite", "resumed:lite"}) {
		t.Fatal(events)
	}
	events = nil
	b.failResume = false
	j.saveErr = true
	if e := RecoverSource(ctx, r.Identity, j, r.Writers); !errors.Is(e, ErrJournal) || !errors.Is(e, ErrResume) {
		t.Fatal("lost journal write considered complete", e)
	}
}

type changingCollector struct {
	fakeCollector
	writer *fakeWriter
}

func (c changingCollector) Capture(ctx context.Context) (Part, error) {
	p, e := c.fakeCollector.Capture(ctx)
	c.writer.failCheck = true
	return p, e
}
func TestCaptureRechecksAllWritersAndRequiresRecoveryFence(t *testing.T) {
	for _, mode := range []string{"before-collect", "after-seal", "recovery-fence"} {
		t.Run(mode, func(t *testing.T) {
			var events []string
			r, a, _ := request(&events)
			switch mode {
			case "before-collect":
				a.failCheck = true
			case "after-seal":
				r.Collectors = []Collector{changingCollector{fakeCollector{events: &events}, a}}
			case "recovery-fence":
				r.Journal = fakeJournal{events: &events, failRecovery: true}
			}
			parts, e := Capture(context.Background(), r)
			if e == nil || len(parts) != 0 {
				t.Fatal("invalid barrier reported success")
			}
			for _, event := range events {
				if mode == "before-collect" && event == "capture" {
					t.Fatal("collected after barrier lost")
				}
				if mode == "recovery-fence" && (event == "resume:lite" || event == "resume:pro") {
					t.Fatal("resumed without authority")
				}
			}
		})
	}
}
