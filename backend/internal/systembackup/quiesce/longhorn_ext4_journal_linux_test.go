//go:build linux

package quiesce

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func longhornExt4TestJournal(t *testing.T) (*longhornExt4Actions, longhornExt4Event) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("native journal requires root-owned records")
	}
	dir := t.TempDir()
	owner := &sharedRuntimeNodeOwner{observer: &NodeObserver{key: bytes.Repeat([]byte{7}, 32)}}
	source := LonghornExt4Source{Identity: strings.Repeat("a", 64), Attempt: 1,
		Binding: ObservationBinding{OperationID: "original-operation", Generation: 4, ExpiresAt: time.Date(2026, 11, 7, 12, 5, 0, 0, time.UTC)},
		Claim: LonghornExt4Claim{TaskPublicID: "sbk-original", Owner: "controller-original", MaintenanceOwner: "sbk-original",
			EntryRowVersion: 7, LeaseObservedAt: time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC), LeaseExpiresAt: time.Date(2026, 11, 7, 12, 2, 0, 0, time.UTC)},
		VolumeHandle: "pvc-original",
		Pin:          LonghornExt4NativePin{Device: 2048, DiskSequence: 9}}
	source = longhornExt4StableSource(source)
	key := longhornExt4SourceKey(source)
	a := &longhornExt4Actions{parent: &SharedRuntimeNodeHandler{owner: owner},
		directory: dir, sources: map[string]LonghornExt4Source{key: source}}
	return a, longhornExt4Event{Version: LonghornExt4Protocol, Key: key, Source: source,
		Hold: longhornExt4Hold{Pin: source.Pin, Phase: "prepared", ExpiresAt: longhornExt4ForwardUntil(source.Binding, source.Claim)}}
}

func TestLonghornExt4ClaimReacquisitionCannotAdoptOrReleaseOriginalHold(t *testing.T) {
	a, original := longhornExt4TestJournal(t)
	original.Hold.Phase = "prepared"
	if err := a.persist(&original); err != nil {
		t.Fatal(err)
	}
	oldRequest := LonghornExt4Request{Action: "release", Binding: original.Source.Binding, Attempt: original.Source.Attempt,
		Claim: original.Source.Claim, SourceIdentity: original.Source.Identity}
	if !longhornExt4RequestMatches(original.Source, oldRequest) {
		t.Fatal("original recovery target rejected")
	}
	newSource := original.Source
	// Same task, attempt, volume, operation and controller owner string.
	// A distinct claim acquisition still owns a distinct native operation.
	newSource.Claim.EntryRowVersion++
	newKey := longhornExt4SourceKey(newSource)
	a.sources[newKey] = newSource
	if newKey == original.Key || longhornExt4RequestMatches(newSource, oldRequest) {
		t.Fatal("old release targets new claim")
	}
	if err := a.checkDeviceObligations(newKey, newSource); err == nil {
		t.Fatal("new claim adopted an unclosed old hold")
	}
	original.Hold.Phase = "released"
	if err := a.persist(&original); err != nil {
		t.Fatal(err)
	}
	if err := a.checkDeviceObligations(newKey, newSource); err != nil {
		t.Fatal(err)
	}
	if longhornExt4RequestMatches(newSource, oldRequest) {
		t.Fatal("old release reopened new claim after old closure")
	}
	for _, mutate := range []func(*LonghornExt4Request){
		func(r *LonghornExt4Request) { r.Claim.Owner = "other-controller" },
		func(r *LonghornExt4Request) { r.Claim.TaskPublicID = "other-task" },
		func(r *LonghornExt4Request) { r.Claim.EntryRowVersion++ },
		func(r *LonghornExt4Request) { r.Claim.LeaseExpiresAt = r.Claim.LeaseExpiresAt.Add(time.Second) },
		func(r *LonghornExt4Request) { r.Binding.OperationID = "other-operation" },
		func(r *LonghornExt4Request) { r.Binding.Generation++ },
		func(r *LonghornExt4Request) { r.Attempt++ },
	} {
		request := oldRequest
		mutate(&request)
		if longhornExt4RequestMatches(original.Source, request) {
			t.Fatal("changed claim binding matched original operation")
		}
	}
}

func TestLonghornOriginalInstallationJournalSurvivesExpiryAndSeparatesReacquisition(t *testing.T) {
	a, event := longhornExt4TestJournal(t)
	event.Source.Claim, event.Source.Binding = originalLonghornClaimFixture()
	event.Hold.ExpiresAt = longhornExt4ForwardUntil(event.Source.Binding, event.Source.Claim)
	event.Key = longhornExt4SourceKey(event.Source)
	a.sources = map[string]LonghornExt4Source{event.Key: event.Source}
	event.Hold.Phase = "freeze-intent"
	if err := a.persist(&event); err != nil {
		t.Fatal(err)
	}
	// Reopen the actual MAC-protected journal after the original lease expired.
	reconnected := &longhornExt4Actions{parent: a.parent, directory: a.directory, sources: a.sources}
	got, found, err := reconnected.load(event.Key)
	if err != nil || !found || got.Hold.Phase != "freeze-intent" || got.Source.Claim.TaskPublicID != "" {
		t.Fatal("original installation journal lost or promoted", err)
	}
	release := LonghornExt4Request{Binding: event.Source.Binding, Claim: event.Source.Claim,
		Attempt: event.Source.Attempt, SourceIdentity: event.Source.Identity, Action: "release"}
	if !longhornExt4RequestMatches(got.Source, release) {
		t.Fatal("original expired recovery identity lost")
	}
	for _, mutate := range []func(*LonghornExt4Source){
		func(s *LonghornExt4Source) { s.Claim.EntryRowVersion++ },
		func(s *LonghornExt4Source) { s.Binding.Generation++ },
		func(s *LonghornExt4Source) { s.Binding.FenceEpoch++ },
		func(s *LonghornExt4Source) { s.Claim.TaskPublicID = "task" },
	} {
		next := event.Source
		mutate(&next)
		key := longhornExt4SourceKey(next)
		if key == event.Key || longhornExt4RequestMatches(next, release) {
			t.Fatal("new claim inherited old installation recovery")
		}
		if err := reconnected.checkDeviceObligations(key, next); err == nil {
			t.Fatal("unconfirmed original freeze was bypassed")
		}
	}
}

func TestLonghornExt4JournalRetainsUnconfirmedPhysicalWindow(t *testing.T) {
	a, event := longhornExt4TestJournal(t)
	for _, phase := range []string{"prepared", "ro-intent", "ro-applied", "held", "rw-intent", "released"} {
		event.Hold.Phase = phase
		if err := a.persist(&event); err != nil {
			t.Fatal(err)
		}
		// Reconstruct the action reader, as after a serving-process restart.
		reconnected := &longhornExt4Actions{parent: a.parent, directory: a.directory, sources: a.sources}
		got, found, err := reconnected.load(event.Key)
		if err != nil || !found || got.Hold.Phase != phase || got.Sequence != event.Sequence {
			t.Fatalf("phase %s was lost or promoted: %+v %v", phase, got, err)
		}
		otherTask := strings.Repeat("b", 64)
		err = reconnected.checkDeviceObligations(otherTask, event.Source)
		if (phase == "released") != (err == nil) {
			t.Fatalf("phase %s admitted the wrong next operation: %v", phase, err)
		}
	}
}

func TestLonghornExt4JournalRefusesPartialTamperedAndGappedEvents(t *testing.T) {
	for _, mode := range []string{"partial", "tampered", "gap", "foreign"} {
		t.Run(mode, func(t *testing.T) {
			a, event := longhornExt4TestJournal(t)
			if err := a.persist(&event); err != nil {
				t.Fatal(err)
			}
			files, err := os.ReadDir(a.directory)
			if err != nil || len(files) != 1 {
				t.Fatal(err)
			}
			name := filepath.Join(a.directory, files[0].Name())
			switch mode {
			case "partial":
				if err := os.WriteFile(name, []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			case "tampered":
				raw, err := os.ReadFile(name)
				if err != nil {
					t.Fatal(err)
				}
				raw = bytes.Replace(raw, []byte("prepared"), []byte("released"), 1)
				if err := os.WriteFile(name, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "gap":
				if err := a.persist(&event); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(name); err != nil {
					t.Fatal(err)
				}
			case "foreign":
				foreign := event.Source
				foreign.ProviderPodUID = "replacement-provider"
				a.sources[event.Key] = foreign
			}
			if _, _, err := a.load(event.Key); err == nil {
				t.Fatalf("%s journal admitted", mode)
			}
		})
	}
}
