package publicadapter

import (
	"context"
	"testing"
	"time"

	"clawreef/internal/systembackup/flow"

	d "clawreef/internal/systembackupdispatch"
)

func TestDTaskPlanWrapsRealBRunnerAndPreservesBDescribePlan(t *testing.T) {
	f, r, _ := setup(t)
	f.in.Backup = &d.BackupSpec{SourceOrchestrator: "kubernetes", SourceProfile: "cluster", MatrixKey: "k8s-cluster", DatasourceTopology: "in_cluster", Runner: "k8s", TaskPurpose: "functional_test", RequestedParts: []string{"mysql", "workspace"}}
	bound, err := d.BindTaskRunner(r, PlanVersion)
	if err != nil {
		t.Fatal(err)
	}
	p, err := bound.Prepare(context.Background(), f.in, f)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := d.UnwrapTaskPlan(f.in, p, PlanVersion)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DescribePlan(f.in, inner); err != nil {
		t.Fatal("original B materializer bytes not reusable", err)
	}
	if _, err := bound.Capture(context.Background(), f.in, p, f); err != nil {
		t.Fatal(err)
	}
	if f.ensures != 1 || f.reads != 1 {
		t.Fatal("B actual capture adapter was not invoked")
	}
}
func TestDBackupSpecCallbacksReceiveDetachedObservations(t *testing.T) {
	f, r, _ := setup(t)
	f.in.Backup = &d.BackupSpec{TaskPurpose: "functional_test", RequestedParts: []string{"mysql"}}
	r.(*runner).deps.Admission = func(_ context.Context, in d.Input) error {
		in.Backup.TaskPurpose = "forged"
		in.Backup.RequestedParts[0] = "forged"
		return d.ErrNotReady
	}
	if _, err := r.Prepare(context.Background(), f.in, f); err == nil || f.in.Backup.TaskPurpose != "functional_test" || f.in.Backup.RequestedParts[0] != "mysql" {
		t.Fatal("B owner callback mutated D's original task observation")
	}
}

func TestDProfileBuildersCannotChangeOriginalSQLInventoryOrTask(t *testing.T) {
	f, _, _ := setup(t)
	f.in.Backup = &d.BackupSpec{TaskPurpose: "functional_test", RequestedParts: []string{"mysql"}}
	p := linuxFixture(t, f, &sourceFixture{})
	originalParts, originalWriters := p.cfg.BuildParts, p.cfg.BuildWriters
	p.cfg.BuildParts = func(in d.Input, inv SourceInventory, hold time.Time) ([]JobPart, error) {
		parts, err := originalParts(in, inv, hold)
		in.Backup.TaskPurpose = "forged"
		in.Backup.RequestedParts[0] = "forged"
		inv.Users[0] = 99
		inv.Instances[0].ID = 99
		return parts, err
	}
	p.cfg.BuildWriters = func(ctx context.Context, in d.Input, inv SourceInventory, frozen []FrozenWriter) ([]flow.Writer, error) {
		if in.Backup.TaskPurpose != "functional_test" || in.Backup.RequestedParts[0] != "mysql" || inv.Users[0] != 1 {
			t.Fatal("earlier builder changed frozen task/source observation")
		}
		writers, err := originalWriters(ctx, in, inv, frozen)
		in.Backup.RequestedParts[0] = "forged"
		inv.Users[0] = 99
		return writers, err
	}
	x, err := p.Discover(context.Background(), f.in)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.CheckSource(context.Background(), f.in, x); err != nil {
		t.Fatal("builder altered original SQL snapshot", err)
	}
	if _, err := p.BindWriters(context.Background(), f.in, x); err != nil {
		t.Fatal(err)
	}
	if f.in.Backup.TaskPurpose != "functional_test" || f.in.Backup.RequestedParts[0] != "mysql" {
		t.Fatal("builder changed original D task spec")
	}
}
