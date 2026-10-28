package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"time"

	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/scope"
)

// BackupGatewayAgent is implemented by the existing Runtime Agent HTTP client.
// Supported agents must prove generation-addressed deletion and stopped-state
// semantics during capability discovery. An HTTP 404 on an unsupported state
// endpoint must never be accepted as a stop acknowledgement.
type BackupGatewayAgent interface {
	GatewayState(context.Context, string, string) (*RuntimeAgentGatewayState, error)
	DeleteGateway(context.Context, string, string) error
	CreateGateway(context.Context, string, RuntimeAgentCreateGatewayRequest) (*RuntimeAgentCreateGatewayResponse, error)
}
type BackupGatewaySource struct {
	Runtime                                                          scope.Runtime
	Endpoint, PodUID, Workspace, RestartRef                          string
	InstanceID, UserID, Generation, ResumeGeneration, UID, GID, Port int
}
type backupGatewayCheckpoint struct {
	Version, PodUID, Workspace, RestartRef, AgentType                string
	InstanceID, UserID, Generation, ResumeGeneration, UID, GID, Port int
}

// BackupGatewayWriter pauses a single Lite gateway without deleting its DB
// binding or freeing the slot. The shared controller fences schedulers, API,
// filesystem/background writers and reserves a NEW generation before Observe.
// Guard validates that immutable source identity and the live capture/recovery
// owner at EVERY boundary, including current Pod UID and endpoint capability.
// ClaimRestart must durably record dispatch and return true exactly once. A
// pending restart may only be reconciled by GET, never blindly repeated.
// Guard at check-resumed/commit-resumed must also prove that the reserved
// generation belongs to this attempt's durable dispatch, not merely match an ID.
type BackupGatewayWriter struct {
	Agent           BackupGatewayAgent
	Source          BackupGatewaySource
	Guard           func(context.Context, string, flow.State) error
	LoadRestart     func(context.Context, string) (RuntimeAgentCreateGatewayRequest, error)
	ClaimRestart    func(context.Context, flow.State) (bool, error)
	CompleteRestart func(context.Context, flow.State, string, int) error
	PollInterval    time.Duration
}

var _ flow.Writer = (*BackupGatewayWriter)(nil)

func (w *BackupGatewayWriter) ID() string {
	return fmt.Sprintf("gateway/%s/%d", w.Source.PodUID, w.Source.InstanceID)
}
func (w *BackupGatewayWriter) gateway(generation int) string {
	return fmt.Sprintf("gw-%d-%d", w.Source.InstanceID, generation)
}
func (w *BackupGatewayWriter) ready(ctx context.Context) error {
	if _, ok := ctx.Deadline(); !ok {
		return flow.ErrNotReady
	}
	s := w.Source
	p, err := scope.PlanRuntime(s.Runtime)
	u, urlErr := url.Parse(s.Endpoint)
	if err != nil || p.Mode != "lite" || urlErr != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || s.PodUID == "" || s.RestartRef == "" || s.InstanceID <= 0 || s.UserID <= 0 || s.Generation <= 0 || s.ResumeGeneration <= s.Generation || s.UID <= 0 || s.GID <= 0 || s.Port < 1 || s.Port > 65535 || !path.IsAbs(s.Workspace) || path.Clean(s.Workspace) != s.Workspace || s.Workspace == "/" || w.Agent == nil || w.Guard == nil || w.LoadRestart == nil || w.ClaimRestart == nil || w.CompleteRestart == nil {
		return flow.ErrNotReady
	}
	return ctx.Err()
}
func (w *BackupGatewayWriter) checkpoint() string {
	s := w.Source
	p, _ := scope.PlanRuntime(s.Runtime)
	b, _ := json.Marshal(backupGatewayCheckpoint{Version: "gateway-quiesce.v1", PodUID: s.PodUID, Workspace: s.Workspace, RestartRef: s.RestartRef, AgentType: p.Type, InstanceID: s.InstanceID, UserID: s.UserID, Generation: s.Generation, ResumeGeneration: s.ResumeGeneration, UID: s.UID, GID: s.GID, Port: s.Port})
	return string(b)
}
func (w *BackupGatewayWriter) validState(s flow.State) bool {
	return s.UID == w.Source.PodUID+"/"+w.gateway(w.Source.Generation) && s.Generation == int64(w.Source.Generation) && s.Checkpoint == w.checkpoint()
}
func (w *BackupGatewayWriter) state(ctx context.Context, generation int) (string, error) {
	s, err := w.Agent.GatewayState(ctx, w.Source.Endpoint, w.gateway(generation))
	if errors.Is(err, ErrRuntimeAgentNotFound) {
		return "absent", nil
	}
	if err != nil || s == nil || s.GatewayID != w.gateway(generation) || s.InstanceID != w.Source.InstanceID || s.Generation != generation {
		return "", flow.ErrQuiesce
	}
	switch s.State {
	case "running", "stopped", "starting", "stopping":
		return s.State, nil
	}
	return "", flow.ErrQuiesce
}
func (w *BackupGatewayWriter) restart(ctx context.Context) (RuntimeAgentCreateGatewayRequest, error) {
	r, err := w.LoadRestart(ctx, w.Source.RestartRef)
	s := w.Source
	p, _ := scope.PlanRuntime(s.Runtime)
	if err != nil || r.InstanceID != s.InstanceID || r.UserID != s.UserID || r.Generation != s.ResumeGeneration || r.AgentType != p.Type || r.WorkspacePath != s.Workspace || r.UID != s.UID || r.GID != s.GID || r.GatewayPort != s.Port || r.UpgradeID != "" {
		return RuntimeAgentCreateGatewayRequest{}, flow.ErrResume
	}
	return r, nil
}
func (w *BackupGatewayWriter) Observe(ctx context.Context) (flow.State, error) {
	if err := w.ready(ctx); err != nil {
		return flow.State{}, err
	}
	s := flow.State{UID: w.Source.PodUID + "/" + w.gateway(w.Source.Generation), Generation: int64(w.Source.Generation), Checkpoint: w.checkpoint()}
	if w.Guard(ctx, "observe", s) != nil {
		return flow.State{}, flow.ErrJournal
	}
	if future, e := w.state(ctx, w.Source.ResumeGeneration); e != nil || future != "absent" {
		return flow.State{}, flow.ErrQuiesce
	}
	state, err := w.state(ctx, w.Source.Generation)
	if err != nil || (state != "running" && state != "stopped" && state != "absent") {
		return flow.State{}, flow.ErrQuiesce
	}
	s.Running = state == "running"
	// Do not stop a healthy source unless its immutable restart material is
	// available and matches the reserved source identity. Never journal secrets.
	if s.Running {
		if _, err = w.restart(ctx); err != nil {
			return flow.State{}, err
		}
	}
	if w.Guard(ctx, "observed", s) != nil {
		return flow.State{}, flow.ErrJournal
	}
	return s, nil
}
func (w *BackupGatewayWriter) Pause(ctx context.Context, s flow.State) (flow.ACK, error) {
	if w.ready(ctx) != nil || !w.validState(s) {
		return flow.ACK{}, flow.ErrQuiesce
	}
	if w.Guard(ctx, "before-stop", s) != nil {
		return flow.ACK{}, flow.ErrJournal
	}
	if future, e := w.state(ctx, w.Source.ResumeGeneration); e != nil || future != "absent" {
		return flow.ACK{}, flow.ErrQuiesce
	}
	state, err := w.state(ctx, w.Source.Generation)
	if err != nil {
		return flow.ACK{}, err
	}
	if !s.Running && state != "stopped" && state != "absent" {
		return flow.ACK{}, flow.ErrQuiesce
	}
	if s.Running && state != "stopped" && state != "absent" {
		if err = w.Agent.DeleteGateway(ctx, w.Source.Endpoint, w.gateway(w.Source.Generation)); err != nil && !errors.Is(err, ErrRuntimeAgentNotFound) {
			return flow.ACK{}, flow.ErrQuiesce
		}
	}
	if err = w.waitStopped(ctx, s, false); err != nil {
		return flow.ACK{}, flow.ErrQuiesce
	}
	if w.CheckPaused(ctx, s) != nil {
		return flow.ACK{}, flow.ErrQuiesce
	}
	return flow.ACK{UID: s.UID, Generation: s.Generation, Stopped: true}, nil
}
func (w *BackupGatewayWriter) waitStopped(ctx context.Context, s flow.State, recovery bool) error {
	point := "check-stopped"
	if recovery {
		point = "recovery-check-stopped"
	}
	return w.poll(ctx, func() (bool, error) {
		if w.Guard(ctx, point, s) != nil {
			return false, flow.ErrJournal
		}
		state, err := w.state(ctx, w.Source.Generation)
		if err != nil {
			return false, err
		}
		return state == "absent" || state == "stopped", nil
	})
}
func (w *BackupGatewayWriter) CheckPaused(ctx context.Context, s flow.State) error {
	if w.ready(ctx) != nil || !w.validState(s) || w.Guard(ctx, "check-stopped", s) != nil {
		return flow.ErrQuiesce
	}
	state, err := w.state(ctx, w.Source.Generation)
	if err != nil || (state != "absent" && state != "stopped") {
		return flow.ErrQuiesce
	}
	// A recovery process appearing during capture invalidates the barrier.
	state, err = w.state(ctx, w.Source.ResumeGeneration)
	if err != nil || state != "absent" {
		return flow.ErrQuiesce
	}
	return nil
}
func (w *BackupGatewayWriter) Resume(ctx context.Context, s flow.State) error {
	if w.ready(ctx) != nil || !w.validState(s) || w.Guard(ctx, "before-resume", s) != nil {
		return flow.ErrResume
	}
	old, err := w.state(ctx, w.Source.Generation)
	if err != nil {
		return flow.ErrResume
	}
	if !s.Running {
		if old != "absent" && old != "stopped" {
			return flow.ErrResume
		}
		current, e := w.state(ctx, w.Source.ResumeGeneration)
		if e != nil || current != "absent" {
			return flow.ErrResume
		}
		return nil
	}
	// Always retire the old gateway before recreating a running source. A late
	// DELETE addresses only the old generation, never this reserved new ID.
	if old != "absent" && old != "stopped" {
		if w.Guard(ctx, "recovery-stop-old", s) != nil {
			return flow.ErrResume
		}
		if e := w.Agent.DeleteGateway(ctx, w.Source.Endpoint, w.gateway(w.Source.Generation)); e != nil && !errors.Is(e, ErrRuntimeAgentNotFound) {
			return flow.ErrResume
		}
	}
	if w.waitStopped(ctx, s, true) != nil {
		return flow.ErrResume
	}
	current, err := w.state(ctx, w.Source.ResumeGeneration)
	if err != nil {
		return flow.ErrResume
	}
	if current == "absent" {
		r, e := w.restart(ctx)
		if e != nil {
			return flow.ErrResume
		}
		if w.Guard(ctx, "before-restart-dispatch", s) != nil {
			return flow.ErrResume
		}
		claimed, e := w.ClaimRestart(ctx, s)
		if e != nil {
			return flow.ErrResume
		}
		if claimed {
			if w.Guard(ctx, "restart-dispatched", s) != nil {
				return flow.ErrResume
			}
			response, e := w.Agent.CreateGateway(ctx, w.Source.Endpoint, r)
			if e == nil && (response == nil || response.GatewayID != w.gateway(w.Source.ResumeGeneration) || response.Port != w.Source.Port) {
				return flow.ErrResume
			}
			// On an uncertain HTTP result, only poll the reserved generation.
		}
	} else if current != "starting" && current != "running" {
		return flow.ErrResume
	}
	if w.poll(ctx, func() (bool, error) {
		if w.Guard(ctx, "check-resumed", s) != nil {
			return false, flow.ErrResume
		}
		state, e := w.state(ctx, w.Source.ResumeGeneration)
		if e != nil {
			return false, e
		}
		if state == "stopped" || state == "stopping" {
			return false, flow.ErrResume
		}
		return state == "running", nil
	}) != nil {
		return flow.ErrResume
	}
	if w.Guard(ctx, "commit-resumed", s) != nil || w.CompleteRestart(ctx, s, w.gateway(w.Source.ResumeGeneration), w.Source.Port) != nil {
		return flow.ErrResume
	}
	return nil
}
func (w *BackupGatewayWriter) poll(ctx context.Context, check func() (bool, error)) error {
	interval := w.PollInterval
	if interval <= 0 || interval > time.Second {
		interval = 100 * time.Millisecond
	}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		done, err := check()
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
