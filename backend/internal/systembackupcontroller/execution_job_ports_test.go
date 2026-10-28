package systembackupcontroller

import (
	"context"
	"errors"
	"testing"
	"time"

	"clawreef/internal/systembackup/kube"
	d "clawreef/internal/systembackupdispatch"
)

type executionJobOwnerTest struct {
	ExecutionJobOwner
	in                 d.Input
	record             kube.ResourceRecord
	readErr, revokeErr error
	revoked            int
}

func (o *executionJobOwnerTest) Admit(context.Context, d.Authority, d.JobIntent) (d.Input, d.Plan, kube.Runner, error) {
	return o.in, d.Plan{}, kube.Runner{}, nil
}
func (o *executionJobOwnerTest) Read(context.Context, d.Authority, d.JobBinding, bool) (kube.Runner, kube.ResourceRecord, error) {
	return kube.Runner{}, o.record, o.readErr
}
func (o *executionJobOwnerTest) Revoke(context.Context, d.Authority, d.JobBinding) error {
	o.revoked++
	return o.revokeErr
}
func TestExecutionJobsRejectMissingAndTypedNilOwners(t *testing.T) {
	var owner *executionJobOwnerTest
	if _, err := NewExecutionJobPorts(&executionPortsTest{}, owner); err == nil {
		t.Fatal("typed nil owner admitted")
	}
	if _, err := NewExecutionJobPorts(nil, &executionJobOwnerTest{}); err == nil {
		t.Fatal("missing writer ports admitted")
	}
}
func TestExecutionJobsRequireFrozenAuthorityBeforeCreate(t *testing.T) {
	o := &executionJobOwnerTest{}
	ports, _ := NewExecutionJobPorts(&executionPortsTest{}, o)
	if _, err := ports.EnsureJob(context.Background(), d.Authority{TaskPublicID: "original"}, d.JobIntent{}); !errors.Is(err, ErrExecutionAuthority) {
		t.Fatal("foreign authority reached create", err)
	}
}
func TestExecutionJobsStopRequiresOriginalUIDAndRevocation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	binding := d.JobBinding{Namespace: "ns", Name: "job", UID: "original"}
	o := &executionJobOwnerTest{record: kube.ResourceRecord{Intent: kube.ResourceIntent{Kind: "Job", Identity: kube.Identity{Namespace: "ns", Name: "job"}}, UID: "foreign"}}
	ports, _ := NewExecutionJobPorts(&executionPortsTest{}, o)
	if err := ports.StopJob(ctx, d.Authority{}, binding); !errors.Is(err, ErrExecutionAuthority) || o.revoked != 0 {
		t.Fatal("foreign job touched", err)
	}
	o.record.UID = "original"
	o.revokeErr = errors.New("revocation unavailable")
	if err := ports.StopJob(ctx, d.Authority{}, binding); !errors.Is(err, o.revokeErr) || o.revoked != 1 {
		t.Fatal("cleanup ran without revocation", err)
	}
}
func TestExecutionJobsObservationRejectsReplacedUID(t *testing.T) {
	o := &executionJobOwnerTest{record: kube.ResourceRecord{Intent: kube.ResourceIntent{Kind: "Job", Identity: kube.Identity{Namespace: "ns", Name: "job"}}, UID: "foreign"}}
	ports, _ := NewExecutionJobPorts(&executionPortsTest{}, o)
	if _, err := ports.ObserveJob(context.Background(), d.Authority{}, d.JobBinding{Namespace: "ns", Name: "job", UID: "original"}); !errors.Is(err, ErrExecutionAuthority) {
		t.Fatal("replacement job accepted", err)
	}
}
