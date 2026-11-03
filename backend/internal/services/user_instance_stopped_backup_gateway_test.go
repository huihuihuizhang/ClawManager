package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"clawreef/internal/systembackup/flow"
)

// Controller/node/journal callbacks are explicit orchestration doubles only.
// They do not attest original maintenance authority or native FD/mmap absence.
type stoppedGatewayAgentDouble struct {
	req          RuntimeStoppedBackupRequest
	reserved     RuntimeStoppedBackupObservation
	actions      []string
	wrongObserve bool
}

func (a *stoppedGatewayAgentDouble) StoppedBackupCapabilities(context.Context, string, int) (*RuntimeStoppedBackupCapabilities, error) {
	return nil, errors.New("not used")
}
func (a *stoppedGatewayAgentDouble) InspectStoppedBackup(context.Context, string, RuntimeStoppedBackupIdentity) (RuntimeStoppedBackupInspection, []byte, error) {
	return RuntimeStoppedBackupInspection{Identity: a.req.RuntimeStoppedBackupIdentity, Slot: "slot-0", Scope: RuntimeStoppedBackupScope, State: "stopped_unreserved", CheckpointSHA256: a.req.CheckpointSHA256}, []byte("inspection-data"), nil
}
func (a *stoppedGatewayAgentDouble) StoppedBackupControl(_ context.Context, _ string, action string, _ RuntimeStoppedBackupRequest) (RuntimeStoppedBackupObservation, error) {
	a.actions = append(a.actions, action)
	if action == "complete-kept-stopped" {
		out := a.reserved
		out.Receipt.State = "completed_stopped"
		out.Receipt.ConfirmedAt = time.Now().UTC()
		out.Raw = nil
		return out, errors.New("use completed fixture")
	}
	if a.wrongObserve && action == "observe" {
		out := a.reserved
		out.Raw = append([]byte(" "), out.Raw...)
		return out, nil
	}
	return a.reserved, nil
}

type completedStoppedAgentDouble struct {
	*stoppedGatewayAgentDouble
	done RuntimeStoppedBackupObservation
}

func (a completedStoppedAgentDouble) StoppedBackupControl(ctx context.Context, endpoint, action string, req RuntimeStoppedBackupRequest) (RuntimeStoppedBackupObservation, error) {
	if action == "complete-kept-stopped" {
		a.actions = append(a.actions, action)
		return a.done, nil
	}
	return a.stoppedGatewayAgentDouble.StoppedBackupControl(ctx, endpoint, action, req)
}
func TestOriginallyStoppedFlowWriterKeepsOriginalStateThroughRecovery(t *testing.T) {
	req := stoppedWireRequest()
	agent := &stoppedGatewayAgentDouble{req: req, reserved: stoppedWireReceipt(t, req, "reserved_stopped")}
	native := completedStoppedAgentDouble{agent, stoppedWireReceipt(t, req, "completed_stopped")}
	stages := []string{}
	node := []string{}
	records := []string{}
	w := &BackupStoppedGatewayWriter{Agent: native, Endpoint: "https://original.invalid", Request: req, Guard: func(_ context.Context, stage string, s flow.State) error {
		stages = append(stages, stage)
		if s.Running {
			return errors.New("source was originally stopped")
		}
		return nil
	}, ConfirmStopped: func(_ context.Context, phase string, s flow.State) error { node = append(node, phase); return nil }, Record: func(_ context.Context, stage string, _ RuntimeStoppedBackupRequest, _ []byte) error {
		records = append(records, stage)
		return nil
	}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	s, e := w.Observe(ctx)
	if e != nil || s.Running {
		t.Fatal("original stopped observation", e)
	}
	ack, e := w.Pause(ctx, s)
	if e != nil || !ack.Stopped || ack.Generation != s.Generation {
		t.Fatal("stopped reservation", e)
	}
	if e = w.CheckPaused(ctx, s); e != nil {
		t.Fatal(e)
	}
	if e = w.Resume(ctx, s); e != nil {
		t.Fatal("keep-stopped recovery", e)
	}
	if len(node) < 4 || node[0] != "prepare" || node[len(node)-1] != "recovered-stopped" || len(stages) == 0 || len(records) == 0 {
		t.Fatal("original node/gate/journal callbacks skipped")
	}
	for _, action := range agent.actions {
		if action != "reserve" && action != "observe" && action != "complete-kept-stopped" {
			t.Fatal("running-source command dispatched", action)
		}
	}
}
func TestOriginallyStoppedFlowRequiresRealOwnersAndExactReservedRaw(t *testing.T) {
	req := stoppedWireRequest()
	agent := &stoppedGatewayAgentDouble{req: req, reserved: stoppedWireReceipt(t, req, "reserved_stopped")}
	w := &BackupStoppedGatewayWriter{Agent: agent, Endpoint: "https://original.invalid", Request: req}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, e := w.Observe(ctx); e == nil || len(agent.actions) != 0 {
		t.Fatal("missing original owners accepted")
	}
	w.Guard = func(context.Context, string, flow.State) error { return nil }
	w.ConfirmStopped = func(context.Context, string, flow.State) error { return nil }
	w.Record = func(context.Context, string, RuntimeStoppedBackupRequest, []byte) error { return nil }
	s, e := w.Observe(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = w.Pause(ctx, s); e != nil {
		t.Fatal(e)
	}
	agent.wrongObserve = true
	if e = w.CheckPaused(ctx, s); e == nil {
		t.Fatal("different current Agent raw receipt accepted")
	}
}
