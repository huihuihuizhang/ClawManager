package quiesce

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Deterministic native-boundary models, NOT field/kernel freeze qualification.
func TestLonghornFreezeStableCounterNormalAndInterruption(t *testing.T) {
	for _, fault := range []string{"", "freeze-call", "freeze-ack-persist", "held-persist", "thaw-call", "released-persist", "changed-counters", "owner-restart"} {
		t.Run(fault, func(t *testing.T) {
			var actions []uint
			counters := longhornExt4WriteCounters{Completed: 4, Sectors: 32}
			v := longhornExt4Volume{freeze: &longhornExt4FreezeCustody{key: "original-key"}}
			v.freeze.ops = &longhornExt4FreezeOps{observe: func(context.Context) (bool, error) { return false, nil }, sample: func(context.Context) (longhornExt4WriteCounters, error) { return counters, nil }, sync: func(int) error { return nil },
				ioctl: func(_ int, request uint) error {
					actions = append(actions, request)
					if fault == "freeze-call" && request == longhornFreezeIOCTL || fault == "thaw-call" && request == longhornThawIOCTL {
						return errors.New("syscall interrupted; result unknown")
					}
					return nil
				}}
			record := longhornExt4Hold{Pin: v.pin, Mechanism: longhornFreezeCounterMechanism, Phase: "prepared", ExpiresAt: time.Now().Add(time.Minute)}
			durable := record
			failed := false
			persist := func(next longhornExt4Hold) error {
				if !failed && (fault == "freeze-ack-persist" && next.Phase == "freeze-acknowledged" || fault == "held-persist" && next.Phase == "held" || fault == "released-persist" && next.Phase == "released") {
					failed = true
					return errors.New("lost persistence acknowledgement")
				}
				durable = next
				return nil
			}
			_, acquireErr := v.freezeAcquire(context.Background(), record, persist)
			if len(actions) != 1 || actions[0] != longhornFreezeIOCTL {
				t.Fatal("not one original freeze dispatch", actions)
			}
			if fault == "freeze-call" {
				if acquireErr == nil || durable.Phase != "freeze-intent" {
					t.Fatal("unknown freeze was promoted")
				}
				if _, err := v.freezeRelease(context.Background(), durable, persist); err == nil || len(actions) != 1 {
					t.Fatal("unknown freeze blindly thawed")
				}
				return
			}
			if fault == "freeze-ack-persist" || fault == "held-persist" {
				if acquireErr == nil {
					t.Fatal("persistence loss ignored")
				}
			} else if acquireErr != nil {
				t.Fatal(acquireErr)
			}
			if fault == "changed-counters" {
				counters.Sectors++
				if _, err := v.freezeRecheck(context.Background(), durable); err == nil {
					t.Fatal("changed data device accepted")
				}
				if _, err := v.freezeRelease(context.Background(), durable, persist); err == nil || len(actions) != 1 {
					t.Fatal("lost hold blindly thawed")
				}
				return
			}
			if fault == "owner-restart" {
				v.freeze = &longhornExt4FreezeCustody{key: "original-key", ops: v.freeze.ops}
				if _, err := v.freezeRecheck(context.Background(), durable); err == nil {
					t.Fatal("journal reconstructed freeze ownership")
				}
				if _, err := v.freezeRelease(context.Background(), durable, persist); err == nil || len(actions) != 1 {
					t.Fatal("restart thawed unknown hold")
				}
				return
			}
			_, releaseErr := v.freezeRelease(context.Background(), durable, persist)
			if len(actions) != 2 || actions[1] != longhornThawIOCTL {
				t.Fatal("not one original recovery thaw", actions)
			}
			if fault == "thaw-call" {
				if releaseErr == nil || durable.Phase != "thaw-intent" {
					t.Fatal("unknown thaw was promoted")
				}
				if _, err := v.freezeRelease(context.Background(), durable, persist); err == nil || len(actions) != 2 {
					t.Fatal("unknown thaw replayed")
				}
				return
			}
			if fault == "released-persist" {
				if releaseErr == nil {
					t.Fatal("unknown persistence promoted")
				}
				if _, err := v.freezeRelease(context.Background(), durable, persist); err != nil || len(actions) != 2 {
					t.Fatal("same owner did not retain successful thaw", err)
				}
			} else if releaseErr != nil {
				t.Fatal(releaseErr)
			}
			if durable.Phase != "released" {
				t.Fatal("original recovery did not close")
			}
			if _, err := v.freezeRelease(context.Background(), durable, persist); err != nil || len(actions) != 2 {
				t.Fatal("original released operation replayed thaw")
			}
		})
	}
}
