package publicadapter

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	d "clawreef/internal/systembackupdispatch"
)

func restoreBoundaryTarget(t *testing.T) (d.Authority, RestoreTarget, SourceDatabase) {
	t.Helper()
	f, _, _ := setup(t)
	a := f.in.Authority
	a.TaskType, a.TaskPublicID, a.Phase = "drill", "sdr_11111111-1111-4111-8111-111111111111", "restore"
	source := SourceDatabase{Name: "synthetic_source", ServerUUID: "44444444-4444-4444-8444-444444444444"}
	target := RestoreTarget{SchemaVersion: "system-backup-b-restore-target.v1", Kind: "isolated_drill", InstallationID: a.InstallationID, MatrixKey: "k8s-single-node", Namespace: "cm-drill-b", NamespaceUID: "55555555-5555-4555-8555-555555555555", DatabaseName: "cm_drill_b", DatabaseServerUUID: source.ServerUUID, SchemaSHA256: strings.Repeat("a", 64), AdminPolicy: "replace_bootstrap_with_source_admin", StartPolicy: "stopped_tasks_disabled", IsolationEvidence: RelayEvidence{PublicID: "sev_isolation", SHA256: strings.Repeat("b", 64)}, Storage: []RestoreStorage{
		{SourceMountSHA256: strings.Repeat("c", 64), Kind: "csi", ClaimName: "instance-one", ClaimUID: "11111111-1111-4111-8111-111111111111", PVUID: "22222222-2222-4222-8222-222222222222", WriterProof: RelayEvidence{PublicID: "sev_writer_one", SHA256: strings.Repeat("d", 64)}},
		{SourceMountSHA256: strings.Repeat("e", 64), Kind: "nfs", ClaimName: "team-shared", ClaimUID: "33333333-3333-4333-8333-333333333333", PVUID: "66666666-6666-4666-8666-666666666666", WriterProof: RelayEvidence{PublicID: "sev_writer_two", SHA256: strings.Repeat("f", 64)}},
	}}
	return a, target, source
}

func TestRestoreTargetRejectsAliasedStorageBeforeProof(t *testing.T) {
	for _, collision := range []string{"source-mount", "claim-uid", "claim-name-new-uid", "pv-different-claim"} {
		t.Run(collision, func(t *testing.T) {
			a, target, source := restoreBoundaryTarget(t)
			first, second := target.Storage[0], &target.Storage[1]
			switch collision {
			case "source-mount":
				second.SourceMountSHA256 = first.SourceMountSHA256
			case "claim-uid":
				second.ClaimUID = first.ClaimUID
			case "claim-name-new-uid":
				second.ClaimName = first.ClaimName
			case "pv-different-claim":
				second.PVUID = first.PVUID
			}
			calls := 0
			err := CheckRestoreTarget(context.Background(), a, target, source, targetProofFunc(func(context.Context, d.Authority, RestoreTarget) error { calls++; return nil }))
			if err == nil || calls != 0 {
				t.Fatal("aliased target reached proof owner", err, calls)
			}
		})
	}
}

func TestRestoreTargetProofPhasesAndDetachedStorage(t *testing.T) {
	for _, phase := range []string{"restore", "normalize", "verify"} {
		a, target, source := restoreBoundaryTarget(t)
		a.Phase = phase
		before := append([]RestoreStorage(nil), target.Storage...)
		calls := 0
		err := CheckRestoreTarget(context.Background(), a, target, source, targetProofFunc(func(_ context.Context, got d.Authority, detached RestoreTarget) error {
			calls++
			if got != a || !reflect.DeepEqual(detached, target) {
				t.Fatal("proof received a different authority or target")
			}
			detached.Storage[0].ClaimName = "mutated-by-proof-fixture"
			return nil // Structural fixture only; never dispatched to a writer.
		}))
		if err != nil || calls != 1 || !reflect.DeepEqual(before, target.Storage) {
			t.Fatal("target proof/copy boundary", err)
		}
	}
	a, target, source := restoreBoundaryTarget(t)
	ctx, cancel := context.WithCancel(context.Background())
	err := CheckRestoreTarget(ctx, a, target, source, targetProofFunc(func(context.Context, d.Authority, RestoreTarget) error { cancel(); return nil }))
	if err == nil {
		t.Fatal("cancellation during proof accepted")
	}
	var absent targetProofFunc
	if err := CheckRestoreTarget(context.Background(), a, target, source, absent); !errors.Is(err, d.ErrNotReady) {
		t.Fatal("typed nil proof accepted", err)
	}
}

// Exercise the real public B runner and D wrapper. An admitted-looking sdr
// task and a valid capture plan must never turn capture Recover into restore.
func TestPublicCaptureDispatchCannotExecuteRestoreOrVerify(t *testing.T) {
	for _, wrapper := range []bool{false, true} {
		for _, phase := range []string{"restore", "normalize", "verify"} {
			for _, method := range []string{"prepare", "capture", "recover"} {
				t.Run(strings.Join([]string{phase, method, map[bool]string{false: "B", true: "D-to-B"}[wrapper]}, "/"), func(t *testing.T) {
					f, runner, plan := setup(t)
					if wrapper {
						f.in.Backup = &d.BackupSpec{SourceOrchestrator: "kubernetes", SourceProfile: "cluster", MatrixKey: "k8s-cluster", DatasourceTopology: "in_cluster", Runner: "k8s", TaskPurpose: "functional_test", RequestedParts: []string{"mysql", "workspace"}}
						var err error
						runner, err = d.BindTaskRunner(runner, PlanVersion)
						if err != nil {
							t.Fatal(err)
						}
						plan, err = runner.Prepare(context.Background(), f.in, f)
						if err != nil {
							t.Fatal(err)
						}
					}
					f.in.Authority.TaskType = "drill"
					f.in.Authority.TaskPublicID = "sdr_11111111-1111-4111-8111-111111111111"
					f.in.Authority.Phase = phase
					f.events = nil
					discoveries, binds, reads, checks := f.discoveries, f.binds, f.reads, f.sourceChecks
					dispatch := d.Dispatcher{Runner: runner, Ports: f}
					var err error
					switch method {
					case "prepare":
						_, err = dispatch.Prepare(context.Background(), f.in)
					case "capture":
						_, err = dispatch.Capture(context.Background(), f.in, plan)
					case "recover":
						var result d.RecoveryResult
						result, err = dispatch.Recover(context.Background(), f.in, plan)
						if result.CollectorsStopped || result.WritersResumed || len(result.Evidence) > 0 {
							t.Fatal("rejected drill acquired recovery facts")
						}
					}
					if err == nil || f.discoveries != discoveries || f.binds != binds || f.reads != reads || f.sourceChecks != checks || f.ensures != 0 || len(f.events) != 0 {
						t.Fatal("unsupported drill dispatched source/provider work", err, f.events)
					}
				})
			}
		}
	}
}
