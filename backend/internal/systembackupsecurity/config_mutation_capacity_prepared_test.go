package systembackupsecurity

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestConfigMutationCapacityPreparedPinsOriginalReport(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(fmt.Sprint(replace), func(t *testing.T) {
			f := newMutationCapacityFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p, err := f.source.PreparePinned(ctx, 524288)
			if err != nil || f.model.steps != 0 {
				t.Fatal("preparation performed SQL", err)
			}
			if replace {
				f.report.AvailableBytes = 0
				f.write(t)
			} else if err := os.Remove(f.source.reportFile); err != nil {
				t.Fatal(err)
			}
			r, err := p.Reserve(ctx, f.tx, f.source, f.current, f.proposed, f.notBefore)
			if err != nil || r == nil || !r.ValidUntil().Equal(f.notBefore.Add(4*time.Second)) {
				t.Fatal("original report lost", err)
			}
			if err := r.Recheck(ctx, f.tx, f.notBefore); err != nil {
				t.Fatal("recheck reread file", err)
			}
			copy := *p
			if _, err := copy.Reserve(ctx, f.tx, f.source, f.current, f.proposed, f.notBefore); err == nil {
				t.Fatal("copied preparation replayed")
			}
			if _, err := json.Marshal(p); err == nil {
				t.Fatal("preparation serialized")
			}
			if strings.Contains(fmt.Sprintf("%#v", p), f.source.reportFile) {
				t.Fatal("private report path disclosed")
			}
		})
	}
}

func TestConfigMutationCapacityPreparedRejectsBindingAndExpiry(t *testing.T) {
	for _, name := range []string{"context", "source", "transaction", "expiry", "regression"} {
		t.Run(name, func(t *testing.T) {
			f := newMutationCapacityFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p, err := f.source.PreparePinned(ctx, 524288)
			if err != nil {
				t.Fatal(err)
			}
			original := *p
			useCtx, source, tx := ctx, f.source, f.tx
			switch name {
			case "context":
				useCtx = context.WithValue(ctx, struct{}{}, true)
			case "source":
				other := *source
				source = &other
			case "transaction":
				tx = nil
			case "expiry":
				f.model.now = f.report.ObservedAt.Add(5 * time.Second)
			case "regression":
				f.model.now = f.notBefore.Add(-time.Microsecond)
			}
			if _, err := p.Reserve(useCtx, tx, source, f.current, f.proposed, f.notBefore); err == nil {
				t.Fatal("invalid original binding accepted")
			}
			if name == "context" || name == "source" || name == "transaction" {
				if f.model.steps != 0 {
					t.Fatal("invalid binding performed SQL")
				}
			}
			if _, err := original.Reserve(ctx, f.tx, f.source, f.current, f.proposed, f.notBefore); err == nil {
				t.Fatal("failed attempt revived via copy")
			}
		})
	}
}

func TestConfigMutationCapacityPreparedTracksSQLFloorAndPoisonsFailure(t *testing.T) {
	f := newMutationCapacityFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := f.source.PreparePinned(ctx, 524288)
	if err != nil {
		t.Fatal(err)
	}
	f.model.afterUpdate = func() { f.model.now = f.model.now.Add(time.Microsecond) }
	r, err := p.Reserve(ctx, f.tx, f.source, f.current, f.proposed, f.notBefore)
	if err != nil {
		t.Fatal(err)
	}
	bound := r.(*preparedConfigCapacityReservation)
	floor, err := bound.SQLFloor(ctx, f.tx)
	if err != nil || !floor.Equal(f.notBefore.Add(time.Microsecond)) {
		t.Fatal("later capacity SQL sample lost", err)
	}
	copy := *bound
	if copy.Recheck(ctx, f.tx, f.notBefore) == nil {
		t.Fatal("clock regression accepted")
	}
	if bound.Recheck(ctx, f.tx, floor) == nil {
		t.Fatal("failed copy revived original")
	}
	if _, err := bound.SQLFloor(ctx, f.tx); err == nil {
		t.Fatal("poisoned SQL floor exposed")
	}
}
