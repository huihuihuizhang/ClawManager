package systembackupcontroller

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"clawreef/internal/systembackup/kube"
	d "clawreef/internal/systembackupdispatch"
)

type sourceLifecycleWriterTest struct {
	d.Ports
	steps *[]string
	err   error
}

func (w sourceLifecycleWriterTest) PauseIntent(context.Context, d.Authority, string, d.WriterState) error {
	*w.steps = append(*w.steps, "pause intent")
	return w.err
}

func (w sourceLifecycleWriterTest) BeforeResume(context.Context, d.Authority) error {
	*w.steps = append(*w.steps, "recovery fence")
	return w.err
}

type sourceLifecycleOwnerTest struct {
	ExecutionJobOwner
	steps     *[]string
	authority d.Authority
	original  d.WriterState
	err       error
}

func (o sourceLifecycleOwnerTest) BeforeSourceStop(_ context.Context, a d.Authority, id string, s d.WriterState) error {
	if a != o.authority || id != "deployment/tenant/source" || s != o.original {
		return ErrExecutionRecord
	}
	*o.steps = append(*o.steps, "attachment handoff")
	return o.err
}

func (o sourceLifecycleOwnerTest) BeforeSourceResume(_ context.Context, a d.Authority) error {
	if a != o.authority {
		return ErrExecutionRecord
	}
	*o.steps = append(*o.steps, "storage recovery")
	return o.err
}

func TestExecutionJobsGateSourceStopAndResume(t *testing.T) {
	ctx := context.Background()
	a := d.Authority{TaskPublicID: "original-task", AttemptNo: 3}
	original := d.WriterState{UID: "original-deployment", Generation: 7, Running: true}
	failure := errors.New("step unconfirmed")
	for _, tt := range []struct {
		name, first, second string
		run                 func(*ExecutionJobPorts) error
	}{
		{"stop", "pause intent", "attachment handoff", func(p *ExecutionJobPorts) error {
			return p.PauseIntent(ctx, a, "deployment/tenant/source", original)
		}},
		{"resume", "recovery fence", "storage recovery", func(p *ExecutionJobPorts) error {
			return p.BeforeResume(ctx, a)
		}},
	} {
		for _, stage := range []string{"success", "fence fails", "storage fails"} {
			t.Run(tt.name+"/"+stage, func(t *testing.T) {
				var steps []string
				writer := sourceLifecycleWriterTest{steps: &steps}
				owner := sourceLifecycleOwnerTest{steps: &steps, authority: a, original: original}
				want := []string{tt.first, tt.second}
				if stage == "fence fails" {
					writer.err = failure
					want = want[:1]
				}
				if stage == "storage fails" {
					owner.err = failure
				}
				ports, err := NewExecutionJobPorts(writer, owner)
				if err != nil {
					t.Fatal(err)
				}
				err = tt.run(ports)
				if !reflect.DeepEqual(steps, want) || (stage == "success" && err != nil) || (stage != "success" && !errors.Is(err, failure)) {
					t.Fatalf("steps = %v, want %v, error = %v", steps, want, err)
				}
			})
		}
	}
}

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
