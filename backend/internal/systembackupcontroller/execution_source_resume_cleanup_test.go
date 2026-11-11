package systembackupcontroller

import (
	"context"
	"errors"
	"reflect"
	"testing"

	d "clawreef/internal/systembackupdispatch"
)

type resumeCleanupPorts struct {
	d.Ports
	calls *[]string
}

func (p resumeCleanupPorts) Resumed(context.Context, d.Authority, string) error {
	*p.calls = append(*p.calls, "resume-ack")
	return nil
}

type resumeCleanupOwner struct {
	ExecutionJobOwner
	calls     *[]string
	failure   error
	authority d.Authority
}

func (o resumeCleanupOwner) AfterSourceResume(_ context.Context, a d.Authority, id string) error {
	if a != o.authority || id != "deployment/tenant/original" {
		return ErrExecutionRecord
	}
	*o.calls = append(*o.calls, "keeper-cleanup")
	return o.failure
}
func TestKeeperCleanupFailureRetainsResumeObligationForSameTaskRetry(t *testing.T) {
	a := d.Authority{TaskPublicID: "original-task", AttemptNo: 2, MaintenanceFencingToken: 7}
	var calls []string
	failure := errors.New("keeper delete response lost")
	owner := &resumeCleanupOwner{calls: &calls, failure: failure, authority: a}
	ports := ExecutionJobPorts{Ports: resumeCleanupPorts{calls: &calls}, Jobs: owner}
	if err := ports.Resumed(context.Background(), a, "deployment/tenant/original"); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"keeper-cleanup"}) {
		t.Fatal("resume obligation completed before cleanup", calls)
	}
	owner.failure = nil
	if err := ports.Resumed(context.Background(), a, "deployment/tenant/original"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"keeper-cleanup", "keeper-cleanup", "resume-ack"}) {
		t.Fatal(calls)
	}
}
