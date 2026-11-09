package systembackupcontroller

import (
	"context"
	"errors"
	"reflect"
	"testing"

	d "clawreef/internal/systembackupdispatch"
)

type storageResumeWriters struct {
	d.Ports
	calls   *[]string
	failure error
}

func (s storageResumeWriters) BeforeResume(context.Context, d.Authority) error {
	*s.calls = append(*s.calls, "collectors-stopped")
	return s.failure
}

type storageResumeJobs struct {
	ExecutionJobOwner
	calls   *[]string
	failure error
}

func (s storageResumeJobs) BeforeSourceResume(context.Context, d.Authority) error {
	*s.calls = append(*s.calls, "storage-recovered")
	return s.failure
}

func TestRuntimeStorageRecoveryPrecedesWriterResume(t *testing.T) {
	for _, stage := range []string{"success", "collectors", "storage"} {
		t.Run(stage, func(t *testing.T) {
			var calls []string
			failure := errors.New("native recovery unconfirmed")
			writers := storageResumeWriters{calls: &calls}
			jobs := storageResumeJobs{calls: &calls}
			if stage == "collectors" {
				writers.failure = failure
			}
			if stage == "storage" {
				jobs.failure = failure
			}
			err := (ExecutionJobPorts{Ports: writers, Jobs: jobs}).BeforeResume(context.Background(), d.Authority{})
			want := []string{"collectors-stopped", "storage-recovered"}
			if stage == "collectors" {
				want = want[:1]
			}
			if !reflect.DeepEqual(calls, want) || errors.Is(err, failure) != (stage != "success") {
				t.Fatalf("resume barrier calls=%v err=%v", calls, err)
			}
		})
	}
}
