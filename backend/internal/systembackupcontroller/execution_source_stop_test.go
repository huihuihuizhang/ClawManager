package systembackupcontroller

import (
	"context"
	"errors"
	"reflect"
	"testing"

	d "clawreef/internal/systembackupdispatch"
)

type beforeSourceStopWriters struct {
	d.Ports
	calls   *[]string
	failure error
}

func (p beforeSourceStopWriters) PauseIntent(context.Context, d.Authority, string, d.WriterState) error {
	*p.calls = append(*p.calls, "original-intent-committed")
	return p.failure
}

type beforeSourceStopJobs struct {
	ExecutionJobOwner
	calls         *[]string
	failure       error
	wantAuthority d.Authority
	wantID        string
	wantState     d.WriterState
}

func (p beforeSourceStopJobs) BeforeSourceStop(_ context.Context, a d.Authority, id string, state d.WriterState) error {
	if a != p.wantAuthority || id != p.wantID || state != p.wantState {
		return ErrExecutionRecord
	}
	*p.calls = append(*p.calls, "original-keeper-and-handover")
	return p.failure
}
func TestRuntimeSourceStopWaitsForOriginalIntentAndKeeper(t *testing.T) {
	failure := errors.New("original step unconfirmed")
	a := d.Authority{TaskPublicID: "same-original-task", AttemptNo: 3}
	original := d.WriterState{UID: "old-deployment", Generation: 7, Running: true, Checkpoint: "old-checkpoint"}
	for _, stage := range []string{"success", "intent", "keeper"} {
		t.Run(stage, func(t *testing.T) {
			var calls []string
			writers := beforeSourceStopWriters{calls: &calls}
			jobs := beforeSourceStopJobs{calls: &calls, wantAuthority: a, wantID: "deployment/tenant/original", wantState: original}
			if stage == "intent" {
				writers.failure = failure
			}
			if stage == "keeper" {
				jobs.failure = failure
			}
			err := (ExecutionJobPorts{Ports: writers, Jobs: jobs}).PauseIntent(context.Background(), a, jobs.wantID, original)
			want := []string{"original-intent-committed", "original-keeper-and-handover"}
			if stage == "intent" {
				want = want[:1]
			}
			if !reflect.DeepEqual(calls, want) || errors.Is(err, failure) != (stage != "success") {
				t.Fatalf("calls=%v err=%v", calls, err)
			}
		})
	}
}
