package systembackupexecution

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	d "clawreef/internal/systembackupdispatch"
	"k8s.io/client-go/kubernetes/fake"
)

type failingLonghornCutOwner struct {
	cuts          []kube.LonghornCaptureCut
	releases      int
	contentCalls  int
	releaseErr    error
	holdErr       error
	releasedInput d.Input
	releasedPlans []plannedLonghornClone
}

func (o *failingLonghornCutOwner) Hold(context.Context, d.Input, []plannedLonghornClone) ([]kube.LonghornCaptureCut, error) {
	return o.cuts, o.holdErr
}
func (o *failingLonghornCutOwner) Release(ctx context.Context, in d.Input, plans []plannedLonghornClone) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	o.releases++
	o.releasedInput, o.releasedPlans = in, plans
	return o.releaseErr
}
func (o *failingLonghornCutOwner) ContentRunner(context.Context, d.Input, plannedLonghornClone, kube.LonghornSnapshotPin) (kube.Runner, error) {
	o.contentCalls++
	return kube.Runner{}, errors.New("unexpected clone admission")
}

func TestLonghornCutSetLossReleasesOriginalCohortBeforeClone(t *testing.T) {
	for _, releaseFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "released", true: "recovery obligation retained"}[releaseFails], func(t *testing.T) {
			lost := errors.New("second original volume lost its hold")
			recoveryFailure := errors.New("original release unconfirmed")
			started := time.Unix(1794000000, 0).UTC()
			owner := &failingLonghornCutOwner{}
			var plans []plannedLonghornClone
			checks := []int{0, 0}
			for index, handle := range []string{"volume-a", "volume-b"} {
				plan := plannedLonghornClone{Original: originalLonghornSource{Handle: handle, ProviderUID: "provider-uid"},
					Snapshot: kube.Identity{Namespace: "system", Name: "snapshot-" + handle, Owner: "task-1"}}
				plans = append(plans, plan)
				source := index
				owner.cuts = append(owner.cuts, kube.LonghornCaptureCut{Target: plan.Snapshot, Pin: plan.Original.pin(),
					Hold: kube.LonghornCaptureHold{StartedAt: started, Recheck: func(context.Context) (time.Time, error) {
						checks[source]++
						if source == 1 {
							return time.Time{}, lost
						}
						return started.Add(time.Second), nil
					}}})
			}
			if releaseFails {
				owner.releaseErr = recoveryFailure
			}
			client := fake.NewSimpleClientset()
			public := &PublicJobOwner{Client: client, longhornCutOwner: owner}
			runner := kube.Runner{CheckFence: func(context.Context) error { return nil }}
			_, err := public.captureLonghornCutSet(context.Background(), d.Input{}, b.Discovery{}, plans, runner)
			if !errors.Is(err, lost) || errors.Is(err, recoveryFailure) != releaseFails ||
				checks[0] != 1 || checks[1] != 1 || owner.releases != 1 || owner.contentCalls != 0 || len(client.Actions()) != 0 {
				t.Fatalf("partial hold entered capture or lost recovery failure: err=%v checks=%v releases=%d contents=%d actions=%v",
					err, checks, owner.releases, owner.contentCalls, client.Actions())
			}
		})
	}
}

func TestLonghornInterruptedAcquireReleasesSameTaskWithIndependentContext(t *testing.T) {
	interrupted := errors.New("acquire response lost")
	releaseUnknown := errors.New("release response lost")
	in := d.Input{Authority: d.Authority{TaskPublicID: "original-task", AttemptNo: 2, MaintenanceFencingToken: 9}}
	plans := []plannedLonghornClone{{Original: originalLonghornSource{Handle: "original-volume", ProviderUID: "original-provider"}}}
	for _, failure := range []error{nil, releaseUnknown} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		storage := &failingLonghornCutOwner{holdErr: interrupted, releaseErr: failure}
		public := &PublicJobOwner{longhornCutOwner: storage}
		_, err := public.captureLonghornCutSet(ctx, in, b.Discovery{}, plans, kube.Runner{})
		if !errors.Is(err, interrupted) || errors.Is(err, releaseUnknown) != (failure != nil) || storage.releases != 1 || storage.releasedInput.Authority != in.Authority || !reflect.DeepEqual(storage.releasedPlans, plans) {
			t.Fatalf("interrupted acquire lost original recovery identity/error: %v, %+v", err, storage)
		}
	}
}
