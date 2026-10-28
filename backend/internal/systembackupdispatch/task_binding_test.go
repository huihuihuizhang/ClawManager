package systembackupdispatch

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"
)

type bindingRunner struct {
	Runner
	prepares, captures, recoveries int
	plan                           Plan
	seen                           Input
	mutate                         bool
}

func (r *bindingRunner) Prepare(_ context.Context, in Input, _ Ports) (Plan, error) {
	r.prepares++
	if r.mutate {
		in.Backup.RequestedParts[0] = "workspace"
	}
	return r.plan, nil
}
func (r *bindingRunner) Capture(_ context.Context, in Input, p Plan, _ Ports) ([]ModuleResult, error) {
	r.captures++
	r.seen = in
	if !bytes.Equal(p.CanonicalJSON, r.plan.CanonicalJSON) || p.SchemaVersion != r.plan.SchemaVersion || p.SHA256 != r.plan.SHA256 {
		return nil, ErrNotReady
	}
	return []ModuleResult{}, nil
}
func (r *bindingRunner) Recover(_ context.Context, in Input, p Plan, _ Ports) (RecoveryResult, error) {
	r.recoveries++
	r.seen = in
	if !bytes.Equal(p.CanonicalJSON, r.plan.CanonicalJSON) {
		return RecoveryResult{}, ErrNotReady
	}
	return RecoveryResult{}, nil
}
func bindingFixture(t *testing.T) (Input, *bindingRunner, Runner, Plan) {
	t.Helper()
	config := []byte(`{"fixture":true}`)
	in := Input{Authority: Authority{InstallationID: "installation_test", TaskPublicID: "sbk_01234567-89ab-cdef-0123-456789abcdef", TaskType: "backup", RequestID: "request-1", ConfigVersion: 1, ConfigSHA256: taskPlanDigest(config), AttemptNo: 1, Phase: "capture", ClaimOwner: "controller-1", ClaimRowVersion: 3, DeadlineAt: time.Now().UTC().Add(time.Minute)}, ConfigSnapshot: config, ProfileID: "linux", ProfileRevision: "r1", Backup: &BackupSpec{SourceOrchestrator: "kubernetes", SourceProfile: "cluster", MatrixKey: "k8s-cluster", DatasourceTopology: "in_cluster", Runner: "k8s", TaskPurpose: "functional_test", RequestedParts: []string{"mysql"}}}
	raw := []byte(" { \"fixture\": 1 } \n")
	inner := &bindingRunner{plan: Plan{"test-b-plan.v1", raw, taskPlanDigest(raw)}}
	r, err := BindTaskRunner(inner, inner.plan.SchemaVersion)
	if err != nil {
		t.Fatal(err)
	}
	p, err := r.Prepare(context.Background(), in, &testPorts{})
	if err != nil {
		t.Fatal(err)
	}
	return in, inner, r, p
}
func TestTaskBindingPreservesEveryOriginalRunnerByte(t *testing.T) {
	in, inner, r, p := bindingFixture(t)
	if p.SchemaVersion != TaskPlanVersion || p.SHA256 == inner.plan.SHA256 {
		t.Fatal("outer and B identities conflated")
	}
	unwrapped, err := UnwrapTaskPlan(in, p, inner.plan.SchemaVersion)
	if err != nil || !bytes.Equal(unwrapped.CanonicalJSON, inner.plan.CanonicalJSON) {
		t.Fatal("B original bytes changed")
	}
	if _, err := r.Capture(context.Background(), in, p, &testPorts{}); err != nil || inner.captures != 1 {
		t.Fatal("original B plan not called", err)
	}
}
func TestTaskBindingRejectsChangedTaskSpecBeforeRunner(t *testing.T) {
	for _, change := range []string{"purpose", "parts", "profile", "attempt", "config", "deadline"} {
		t.Run(change, func(t *testing.T) {
			in, inner, r, p := bindingFixture(t)
			switch change {
			case "purpose":
				in.Backup.TaskPurpose = "acceptance"
				in.Backup.RequestedParts = []string{"mysql", "redis", "object_storage", "workspace", "deployment_resources", "secret_bundle"}
			case "parts":
				in.Backup.RequestedParts = []string{"workspace"}
			case "profile":
				in.ProfileRevision = "r2"
			case "attempt":
				in.Authority.AttemptNo++
			case "config":
				in.ConfigSnapshot = []byte(`{"changed":true}`)
				in.Authority.ConfigSHA256 = taskPlanDigest(in.ConfigSnapshot)
			case "deadline":
				in.Authority.DeadlineAt = in.Authority.DeadlineAt.Add(time.Second)
			}
			if _, err := r.Capture(context.Background(), in, p, &testPorts{}); err == nil || inner.captures != 0 {
				t.Fatal("changed semantic identity reached B")
			}
			if _, err := r.Recover(context.Background(), in, p, &testPorts{}); err == nil || inner.recoveries != 0 {
				t.Fatal("changed semantic recovery identity reached B")
			}
		})
	}
}
func TestTaskBindingPassesFreshClaimAndRecoveryAuthorityToB(t *testing.T) {
	in, inner, r, p := bindingFixture(t)
	in.Authority.ClaimOwner = "controller-new"
	in.Authority.ClaimRowVersion = 7
	in.Authority.MaintenanceOwner = "gate-new"
	in.Authority.MaintenanceFencingToken = 11
	if _, err := r.Capture(context.Background(), in, p, &testPorts{}); err != nil || inner.seen.Authority != in.Authority {
		t.Fatal("fresh current authority replaced by plan observations")
	}
	if _, err := r.Recover(context.Background(), in, p, &testPorts{}); err != nil || inner.seen.Authority != in.Authority {
		t.Fatal("recovery current scope replaced")
	}
}
func TestTaskBindingRejectsNoncanonicalOrCorruptEnvelopes(t *testing.T) {
	for _, change := range []string{"outer_hash", "inner_hash", "duplicate", "unknown", "version"} {
		t.Run(change, func(t *testing.T) {
			in, inner, r, p := bindingFixture(t)
			switch change {
			case "outer_hash":
				p.CanonicalJSON = append(p.CanonicalJSON, ' ')
			case "duplicate":
				p.CanonicalJSON = append([]byte(`{"schema_version":"system-backup-task-plan.v1",`), p.CanonicalJSON[1:]...)
				p.SHA256 = taskPlanDigest(p.CanonicalJSON)
			case "unknown":
				p.CanonicalJSON = append([]byte(`{"extra":1,`), p.CanonicalJSON[1:]...)
				p.SHA256 = taskPlanDigest(p.CanonicalJSON)
			default:
				var e taskPlanEnvelope
				if json.Unmarshal(p.CanonicalJSON, &e) != nil {
					t.Fatal("fixture")
				}
				if change == "inner_hash" {
					e.InnerBytes = []byte(`{"different":1}`)
				} else {
					e.InnerVersion = "other.v1"
				}
				p.CanonicalJSON, _ = json.Marshal(e)
				p.SHA256 = taskPlanDigest(p.CanonicalJSON)
			}
			if _, err := r.Capture(context.Background(), in, p, &testPorts{}); err == nil || inner.captures != 0 {
				t.Fatal("corrupt envelope reached B")
			}
		})
	}
}
func TestTaskBindingRequiresExplicitSpecAndIsolatesPrepareObservations(t *testing.T) {
	in, inner, r, _ := bindingFixture(t)
	in.Backup = nil
	if _, err := r.Prepare(context.Background(), in, &testPorts{}); err == nil || inner.prepares != 1 {
		t.Fatal("missing spec was defaulted")
	}
	in, inner, r, _ = bindingFixture(t)
	inner.mutate = true
	if _, err := r.Prepare(context.Background(), in, &testPorts{}); err == nil || in.Backup.RequestedParts[0] != "mysql" {
		t.Fatal("mutated discovery input persisted or escaped")
	}
}
