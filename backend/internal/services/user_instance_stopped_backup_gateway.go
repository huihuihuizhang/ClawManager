package services

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"clawreef/internal/systembackup/flow"
)

// BackupStoppedGatewayWriter holds an ORIGINAL already-stopped source without
// ever constructing a PID, successor or restart command. The controller owns
// the actual durable maintenance/collector gate and journal, and installs B's
// independent complete node/FD/mmap/mount verification through ConfirmStopped.
// None of the required original callbacks has a permissive default.
type BackupStoppedGatewayWriter struct {
	Agent          RuntimeAgentStoppedBackupClient
	Endpoint       string
	Request        RuntimeStoppedBackupRequest
	Guard          func(context.Context, string, flow.State) error
	ConfirmStopped func(context.Context, string, flow.State) error
	Record         func(context.Context, string, RuntimeStoppedBackupRequest, []byte) error
	reservedRaw    []byte
}

func (w *BackupStoppedGatewayWriter) ID() string {
	return fmt.Sprintf("gateway/%s/%d", w.Request.PodUID, w.Request.InstanceID)
}
func (w *BackupStoppedGatewayWriter) state() flow.State {
	return flow.State{UID: w.Request.PodUID + "/" + w.Request.GatewayID, Generation: int64(w.Request.Generation), Running: false, Checkpoint: w.Request.CheckpointSHA256}
}
func (w *BackupStoppedGatewayWriter) ready(ctx context.Context, fresh bool) error {
	if w == nil || ctx == nil || ctx.Err() != nil || w.Agent == nil || w.Endpoint == "" || !w.Request.Valid() || w.Guard == nil || w.ConfirmStopped == nil || w.Record == nil || fresh && !time.Now().Before(w.Request.HoldUntil) {
		return flow.ErrNotReady
	}
	if _, ok := ctx.Deadline(); !ok {
		return flow.ErrNotReady
	}
	return nil
}
func (w *BackupStoppedGatewayWriter) Observe(ctx context.Context) (flow.State, error) {
	if w.ready(ctx, true) != nil {
		return flow.State{}, flow.ErrNotReady
	}
	s := w.state()
	if w.Guard(ctx, "observe-original-stopped", s) != nil {
		return flow.State{}, flow.ErrJournal
	}
	i, raw, e := w.Agent.InspectStoppedBackup(ctx, w.Endpoint, w.Request.RuntimeStoppedBackupIdentity)
	if e != nil || i.CheckpointSHA256 != w.Request.CheckpointSHA256 || w.Record(ctx, "stopped-inspection", w.Request, raw) != nil || w.ConfirmStopped(ctx, "prepare", s) != nil || w.Guard(ctx, "observed-original-stopped", s) != nil {
		return flow.State{}, flow.ErrQuiesce
	}
	return s, nil
}
func (w *BackupStoppedGatewayWriter) Pause(ctx context.Context, s flow.State) (flow.ACK, error) {
	if w.ready(ctx, true) != nil || s != w.state() || w.Guard(ctx, "before-stopped-reserve", s) != nil || w.Record(ctx, "stopped-reserve-intent", w.Request, nil) != nil {
		return flow.ACK{}, flow.ErrQuiesce
	}
	o, e := w.Agent.StoppedBackupControl(ctx, w.Endpoint, "reserve", w.Request)
	if e != nil || o.Receipt.State != "reserved_stopped" {
		return flow.ACK{}, flow.ErrQuiesce
	}
	if _, e = DecodeRuntimeStoppedBackupWireObservation(w.Request, "reserve", 200, o.Raw); e != nil {
		return flow.ACK{}, flow.ErrQuiesce
	}
	w.reservedRaw = bytes.Clone(o.Raw)
	if w.Record(ctx, "stopped-reserved", w.Request, o.Raw) != nil || w.CheckPaused(ctx, s) != nil {
		return flow.ACK{}, flow.ErrQuiesce
	}
	return flow.ACK{UID: s.UID, Generation: s.Generation, Stopped: true}, nil
}
func (w *BackupStoppedGatewayWriter) CheckPaused(ctx context.Context, s flow.State) error {
	if w.ready(ctx, true) != nil || s != w.state() || w.Guard(ctx, "check-stopped-reservation", s) != nil {
		return flow.ErrQuiesce
	}
	o, e := w.Agent.StoppedBackupControl(ctx, w.Endpoint, "observe", w.Request)
	if e != nil || o.Receipt.State != "reserved_stopped" || len(w.reservedRaw) == 0 || !bytes.Equal(o.Raw, w.reservedRaw) || w.Record(ctx, "stopped-current", w.Request, o.Raw) != nil || w.ConfirmStopped(ctx, "stopped", s) != nil || w.Guard(ctx, "checked-stopped-reservation", s) != nil {
		return flow.ErrQuiesce
	}
	return nil
}
func (w *BackupStoppedGatewayWriter) Resume(ctx context.Context, s flow.State) error {
	if w.ready(ctx, false) != nil || s != w.state() || w.Guard(ctx, "recover-keep-stopped", s) != nil || w.ConfirmStopped(ctx, "recovery-stopped", s) != nil || w.Record(ctx, "keep-stopped-complete-intent", w.Request, nil) != nil {
		return flow.ErrResume
	}
	// Guard MUST prove all original collectors stopped/revoked and checkpoint
	// recovery current before this release. This operation cannot start a writer.
	o, e := w.Agent.StoppedBackupControl(ctx, w.Endpoint, "complete-kept-stopped", w.Request)
	if e != nil || o.Receipt.State != "completed_stopped" || w.Record(ctx, "kept-stopped-completed", w.Request, o.Raw) != nil {
		return flow.ErrResume
	}
	if _, e = DecodeRuntimeStoppedBackupWireObservation(w.Request, "complete-kept-stopped", 200, o.Raw); e != nil {
		return flow.ErrResume
	}
	i, raw, e := w.Agent.InspectStoppedBackup(ctx, w.Endpoint, w.Request.RuntimeStoppedBackupIdentity)
	if e != nil || i.CheckpointSHA256 != s.Checkpoint || w.Record(ctx, "kept-stopped-final", w.Request, raw) != nil || w.ConfirmStopped(ctx, "recovered-stopped", s) != nil || w.Guard(ctx, "recovered-kept-stopped", s) != nil {
		return flow.ErrResume
	}
	return nil
}

var _ flow.Writer = (*BackupStoppedGatewayWriter)(nil)
