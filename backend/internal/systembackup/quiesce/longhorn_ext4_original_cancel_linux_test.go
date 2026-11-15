//go:build linux

package quiesce

import (
	"context"
	"strings"
	"testing"
	"time"
)

func originalLonghornCancellation(t *testing.T) (*longhornExt4Actions, LonghornExt4Source, longhornExt4Volume, LonghornExt4Request) {
	t.Helper()
	a, event := longhornExt4TestJournal(t)
	s := event.Source
	s.Binding.Kind, s.Binding.InstallationID = LonghornExt4Protocol, "installation_original"
	s.Binding.Namespace, s.Binding.NamespaceUID = "tenant", "tenant-uid"
	s.Binding.Node, s.Binding.NodeUID = "node1", "node1-uid"
	s.Binding.OperationID, s.Binding.ReservationID = strings.Repeat("1", 32), strings.Repeat("2", 32)
	s.Binding.InventorySHA256 = strings.Repeat("3", 64)
	// Deliberately expired: independent recovery cannot depend on Forward.
	s.Claim = LonghornExt4Claim{OriginalOperationID: s.Binding.OperationID, OriginalReservationID: s.Binding.ReservationID,
		Owner: "adoption:" + s.Binding.OperationID, MaintenanceOwner: "adoption:" + s.Binding.OperationID,
		EntryRowVersion: 7, LeaseObservedAt: time.Now().Add(-10 * time.Minute).UTC(), LeaseExpiresAt: time.Now().Add(-9 * time.Minute).UTC()}
	s.Binding.ExpiresAt = s.Claim.LeaseExpiresAt
	a.sources = map[string]LonghornExt4Source{longhornExt4SourceKey(s): s}
	v := longhornExt4Volume{pin: s.Pin, freeze: &longhornExt4FreezeCustody{ops: &longhornExt4FreezeOps{
		observe: func(context.Context) (bool, error) { return false, nil },
		ioctl:   func(int, uint) error { t.Fatal("absence authorized a physical syscall"); return ErrNodeObservation },
	}}}
	r := LonghornExt4Request{Version: LonghornExt4Protocol, Action: "release", Binding: s.Binding, Attempt: s.Attempt,
		SourceIdentity: s.Identity, Claim: s.Claim, RegistrationBoundarySHA256: strings.Repeat("4", 64), RecoveryBoundarySHA256: strings.Repeat("5", 64)}
	return a, s, v, r
}

func TestOriginalLonghornRWXRecoveryClosesBeforeDelayedRegister(t *testing.T) {
	a, source, volume, request := originalLonghornCancellation(t)
	key := longhornExt4SourceKey(source)
	event, err := a.closeUnregisteredOriginal(context.Background(), key, source, volume, request)
	if err != nil || event.Hold.Phase != "released" || event.Sequence != 1 {
		t.Fatal("original recovery did not persist the closure", err)
	}
	reader := &longhornExt4Actions{parent: a.parent, directory: a.directory, sources: a.sources}
	reopened, found, err := reader.load(key)
	if err != nil || !found || reopened.Hold.Phase != "released" || reopened.RecoveryBoundarySHA256 != request.RecoveryBoundarySHA256 {
		t.Fatal("closure did not survive native journal reopen", err)
	}
	delayed := request
	delayed.Action, delayed.RecoveryBoundarySHA256 = "register", ""
	if !longhornExt4RequestMatches(reopened.Source, delayed) || longhornExt4RegisterEventMatches(reopened, delayed) {
		t.Fatal("same original delayed register reopened recovery closure")
	}
	if _, err := reader.closeUnregisteredOriginal(context.Background(), key, source, volume, request); err == nil {
		t.Fatal("initial cancellation overwrote an existing event")
	}
	next := source
	next.Claim.EntryRowVersion++
	if longhornExt4RequestMatches(next, request) {
		t.Fatal("original recovery inherited another acquisition")
	}
	if err := reader.checkDeviceObligations(longhornExt4SourceKey(next), next); err != nil {
		t.Fatal("closed original unnecessarily blocked a distinct acquisition", err)
	}
}

func TestOriginalLonghornRWXAbsentClosureRejectsUnknownOrForeignOwnership(t *testing.T) {
	for _, fault := range []string{"no-register-boundary", "no-recovery-boundary", "foreign-claim", "task-claim", "freeze-sent", "freeze-owned", "thaw-sent", "existing-unknown-event", "other-unclosed-device"} {
		t.Run(fault, func(t *testing.T) {
			a, s, v, r := originalLonghornCancellation(t)
			key := longhornExt4SourceKey(s)
			switch fault {
			case "no-register-boundary":
				r.RegistrationBoundarySHA256 = ""
			case "no-recovery-boundary":
				r.RecoveryBoundarySHA256 = ""
			case "foreign-claim":
				r.Claim.EntryRowVersion++
			case "task-claim":
				r.Claim.TaskPublicID = "foreign-task"
			case "freeze-sent":
				v.freeze.freezeSent = true
			case "freeze-owned":
				v.freeze.owned = true
			case "thaw-sent":
				v.freeze.thawSent = true
			case "existing-unknown-event", "other-unclosed-device":
				other := s
				if fault == "other-unclosed-device" {
					other.Claim.EntryRowVersion++
				}
				event := longhornExt4Event{Version: LonghornExt4Protocol, Key: longhornExt4SourceKey(other), Source: other,
					Hold: longhornExt4Hold{Mechanism: longhornFreezeCounterMechanism, Pin: other.Pin, Phase: "freeze-intent", ExpiresAt: longhornExt4ForwardUntil(other.Binding, other.Claim)}}
				if err := a.persist(&event); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := a.closeUnregisteredOriginal(context.Background(), key, s, v, r); err == nil {
				t.Fatal("unknown or foreign operation was converted into released")
			}
		})
	}
}
