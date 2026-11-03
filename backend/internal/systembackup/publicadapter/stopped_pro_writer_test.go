package publicadapter

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"clawreef/internal/systembackup/flow"
	q "clawreef/internal/systembackup/quiesce"
	d "clawreef/internal/systembackupdispatch"
)

// Callback model only; it does not claim native P7 process or SQL validation.
func stoppedProWriterSpecFixture() RuntimeWriterSpec {
	source := writerTestSource()
	source.Mode, source.Backend, source.Status = "pro", "desktop", "stopped"
	baseline := q.StoppedProBaseline{SourceKey: "stopped/7", RuntimeType: source.Type, InstanceID: 7, UserID: 4, InstanceGeneration: 7, NamespaceUID: "namespace-uid", CurrentConfigSHA256: strings.Repeat("a", 64), Volumes: []q.StoppedProVolume{{NamespaceUID: "namespace-uid", ClaimName: "workspace", ClaimUID: "claim-uid", PVName: "workspace-pv", PVUID: "pv-uid", PVSpecSHA256: strings.Repeat("b", 64), DataNodeUID: "node-uid", UniqueNodeEvidenceSHA256: strings.Repeat("c", 64), HostPath: "/original/workspace"}}}
	raw, _ := json.Marshal(baseline)
	return RuntimeWriterSpec{Source: source, Kind: "stopped", StoppedProBaseline: string(raw), Stopped: flow.State{UID: baseline.SourceKey, Generation: 7, Checkpoint: q.StoppedProBaselineSHA256(baseline)}}
}

func TestStoppedProWriterRequiresNativeCallbackAndIndependentRecovery(t *testing.T) {
	ports, deps := writerTestDeps(t)
	spec := stoppedProWriterSpecFixture()
	phases := []string{}
	deny := true
	deps.Callbacks.StoppedProControl = func(ctx context.Context, a d.Authority, id, phase string, s flow.State) error {
		if a != ports.in.Authority || id != "stopped/7" || s != spec.Stopped {
			return errors.New("scope")
		}
		phases = append(phases, phase)
		if deny {
			return errors.New("native observation unavailable")
		}
		return nil
	}
	w := &stoppedProWriter{spec, ports.in.Authority, deps}
	ctx := context.Background()
	if ack, err := w.Pause(ctx, spec.Stopped); err == nil || ack.Stopped {
		t.Fatal("Guard alone minted stopped ACK")
	}
	deny = false
	if ack, err := w.Pause(ctx, spec.Stopped); err != nil || !ack.Stopped || ack.Generation != 7 {
		t.Fatal(ack, err)
	}
	if err := w.CheckPaused(ctx, spec.Stopped); err != nil {
		t.Fatal(err)
	}
	ports.normal = false
	if err := w.CheckPaused(context.WithValue(ctx, sourceRecoveryContext{}, true), spec.Stopped); err != nil {
		t.Fatal(err)
	}
	if err := w.Resume(ctx, spec.Stopped); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(phases, []string{"prepare-stopped", "prepare-stopped", "stopped", "recovery-stopped", "recovered-stopped"}) {
		t.Fatal(phases)
	}
	before := len(phases)
	ports.recovery = false
	if err := w.Resume(ctx, spec.Stopped); err == nil || len(phases) != before {
		t.Fatal("denied recovery reached native callback")
	}
	changed := spec.Stopped
	changed.Generation++
	if _, err := w.Pause(ctx, changed); err == nil {
		t.Fatal("changed source generation accepted")
	}
}
