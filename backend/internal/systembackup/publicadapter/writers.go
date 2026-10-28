package publicadapter

import (
	"context"
	"strconv"
	"time"

	"clawreef/internal/services"
	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/quiesce"
	"clawreef/internal/systembackup/scope"
	d "clawreef/internal/systembackupdispatch"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// RuntimeWriterSpec is an admitted immutable profile projection, NOT HTTP
// input. Source must match the frozen SQL projection exactly. RestartRef names
// encrypted original material held by D; no Pod env/Secret enters the plan.
type RuntimeWriterSpec struct {
	Source                     InstanceIdentity
	Kind                       string // gateway, pod, deployment, stopped
	UID, Name, Endpoint        string
	RestartRef                 string
	ResumeGeneration           int // original public reservation; never inferred +1
	UIDNumber, GIDNumber, Port int
	Stopped                    flow.State
}

type RestartObservation struct {
	PodUID, GatewayID string
	Port              int
}

// WriterCallbacks implement D/A's original identity, capability, registry and
// restart journal checks. All calls carry the full current Authority. These
// callbacks never receive a B SQLStore or an independently minted generation.
type WriterCallbacks struct {
	Guard           func(context.Context, d.Authority, string, string, flow.State) error
	LoadGateway     func(context.Context, d.Authority, string, string) (services.RuntimeAgentCreateGatewayRequest, error)
	LoadPod         func(context.Context, d.Authority, string, string) (*corev1.Pod, error)
	ClaimRestart    func(context.Context, d.Authority, string, flow.State) (bool, error)
	CompleteRestart func(context.Context, d.Authority, string, flow.State, RestartObservation) error
	ConfirmStopped  func(context.Context, d.Authority, string, flow.State, []quiesce.PodIdentity) error
	// Deployment completion must also reconcile its actual new source binding;
	// readiness alone or a copied resume annotation is not ownership proof.
	ConfirmResumed func(context.Context, d.Authority, string, flow.State) error
}

type ParticipantSpec struct {
	ID       string
	Original flow.State
}
type RuntimeWriterDependencies struct {
	Ports        d.Ports
	Client       kubernetes.Interface
	Agent        services.BackupGatewayAgent
	Callbacks    WriterCallbacks
	Participants []ParticipantSpec // platform DB/background/external gate proofs
	PollInterval time.Duration
}

// NewRuntimeWriterBuilder is the concrete LinuxProfile.BuildWriters factory.
// Constructors and Bind do not discover resources, issue reservations or mutate
// anything. Existing real Gateway/Pod/DeploymentWriter implementations perform
// physical work only after flow's durable pause intent and current authority.
func NewRuntimeWriterBuilder(specs []RuntimeWriterSpec, deps RuntimeWriterDependencies) (func(context.Context, d.Input, SourceInventory, []FrozenWriter) ([]flow.Writer, error), error) {
	if nilValue(deps.Ports) || deps.Callbacks.Guard == nil || len(deps.Participants) == 0 || len(specs)+len(deps.Participants) > 10000 || deps.PollInterval < 0 || deps.PollInterval > time.Second {
		return nil, d.ErrNotReady
	}
	specs = append([]RuntimeWriterSpec(nil), specs...)
	deps.Participants = append([]ParticipantSpec(nil), deps.Participants...)
	seen := map[int]bool{}
	for _, spec := range specs {
		if spec.Source.ID <= 0 || seen[spec.Source.ID] || validateWriterSpec(spec, deps) != nil {
			return nil, d.ErrNotReady
		}
		seen[spec.Source.ID] = true
	}
	participantIDs := map[string]bool{}
	for _, spec := range deps.Participants {
		if !validParticipant(spec) || participantIDs[spec.ID] {
			return nil, d.ErrNotReady
		}
		participantIDs[spec.ID] = true
	}
	return func(ctx context.Context, in d.Input, inv SourceInventory, frozen []FrozenWriter) ([]flow.Writer, error) {
		if ctx == nil || ctx.Err() != nil || validateInput(in, true) != nil || in.Authority.TaskType != "backup" || len(inv.Instances) != len(specs) {
			return nil, d.ErrNotReady
		}
		actual := map[int]InstanceIdentity{}
		users := map[int]bool{}
		for _, id := range inv.Users {
			if id <= 0 || users[id] {
				return nil, d.ErrNotReady
			}
			users[id] = true
		}
		for _, source := range inv.Instances {
			if _, duplicate := actual[source.ID]; duplicate || !users[source.UserID] {
				return nil, d.ErrNotReady
			}
			actual[source.ID] = source
		}
		writers := make([]flow.Writer, 0, len(specs)+len(deps.Participants))
		for _, participant := range deps.Participants {
			writers = append(writers, &participantWriter{participant, in.Authority, deps})
		}
		for _, spec := range specs {
			if actual[spec.Source.ID] != spec.Source {
				return nil, &Failure{"writer_registry_drift"}
			}
			writers = append(writers, constructRuntimeWriter(in, spec, deps))
		}
		ids := map[string]bool{}
		for _, writer := range writers {
			if ids[writer.ID()] {
				return nil, d.ErrNotReady
			}
			ids[writer.ID()] = true
		}
		if frozen != nil {
			if len(frozen) != len(writers) {
				return nil, d.ErrNotReady
			}
			for _, old := range frozen {
				if !ids[old.ID] {
					return nil, d.ErrNotReady
				}
				delete(ids, old.ID)
			}
		}
		return writers, nil
	}, nil
}

func validParticipant(p ParticipantSpec) bool {
	return p.ID != "" && len(p.ID) <= 256 && p.Original.UID != "" && p.Original.Generation > 0 && !p.Original.Running && p.Original.Checkpoint != ""
}

func validateWriterSpec(s RuntimeWriterSpec, deps RuntimeWriterDependencies) error {
	runtime := scope.Runtime{Type: s.Source.Type, Mode: s.Source.Mode, Backend: s.Source.Backend, Variant: s.Source.Variant, OS: s.Source.OS}
	plan, err := scope.PlanRuntime(runtime)
	if err != nil || s.Source.UserID <= 0 || s.Source.Generation <= 0 {
		return d.ErrNotReady
	}
	c := deps.Callbacks
	switch s.Kind {
	case "stopped":
		if s.Source.Status != "stopped" || !validParticipant(ParticipantSpec{"stopped/" + strconv.Itoa(s.Source.ID), s.Stopped}) || s.Stopped.Generation != int64(s.Source.Generation) {
			return d.ErrNotReady
		}
	case "gateway":
		if plan.Mode != "lite" || s.Source.Status != "running" || nilValue(deps.Agent) || s.UID == "" || s.Source.Pod == "" || s.Source.Namespace == "" || s.Endpoint == "" || s.Source.Workspace == "" || s.RestartRef == "" || s.ResumeGeneration <= s.Source.Generation || s.UIDNumber <= 0 || s.GIDNumber <= 0 || s.Port <= 0 || s.Port > 65535 || c.LoadGateway == nil || c.ClaimRestart == nil || c.CompleteRestart == nil {
			return d.ErrNotReady
		}
	case "pod", "deployment":
		if plan.Mode != "pro" || s.Source.Status != "running" || nilValue(deps.Client) || s.Source.Namespace == "" || s.Name == "" || s.UID == "" || c.ConfirmStopped == nil || c.ConfirmResumed == nil {
			return d.ErrNotReady
		}
		if s.Kind == "pod" && (s.Name != s.Source.Pod || s.RestartRef == "" || c.LoadPod == nil || c.ClaimRestart == nil || c.CompleteRestart == nil) {
			return d.ErrNotReady
		}
	default:
		return d.ErrNotReady
	}
	return nil
}

func writerGuard(ctx context.Context, deps RuntimeWriterDependencies, a d.Authority, id, point string, s flow.State) error {
	if point == "check-stopped" && ctx.Value(sourceRecoveryContext{}) == true {
		point = "recovery-check-stopped"
	}
	var err error
	switch point {
	case "observe", "observed", "before-stop", "check-stopped":
		err = deps.Ports.Check(ctx, a)
	case "before-resume", "recovery-check-stopped", "recovery-stop-old", "before-restart-dispatch", "restart-dispatched", "check-resumed", "commit-resumed", "claim-restart", "complete-restart":
		err = deps.Ports.CheckRecovery(ctx, a, id, state(s))
	default:
		return d.ErrNotReady
	}
	if err != nil {
		return err
	}
	return deps.Callbacks.Guard(ctx, a, id, point, s)
}

func constructRuntimeWriter(in d.Input, spec RuntimeWriterSpec, deps RuntimeWriterDependencies) flow.Writer {
	source, a, c := spec.Source, in.Authority, deps.Callbacks
	runtime := scope.Runtime{Type: source.Type, Mode: source.Mode, Backend: source.Backend, Variant: source.Variant, OS: source.OS}
	if spec.Kind == "stopped" {
		return &participantWriter{ParticipantSpec{"stopped/" + strconv.Itoa(source.ID), spec.Stopped}, a, deps}
	}
	var id string
	guard := func(ctx context.Context, point string, s flow.State) error {
		return writerGuard(ctx, deps, a, id, point, s)
	}
	claim := func(ctx context.Context, s flow.State) (bool, error) {
		if err := guard(ctx, "claim-restart", s); err != nil {
			return false, err
		}
		return c.ClaimRestart(ctx, a, id, s)
	}
	complete := func(ctx context.Context, s flow.State, observation RestartObservation) error {
		if err := guard(ctx, "complete-restart", s); err != nil {
			return err
		}
		return c.CompleteRestart(ctx, a, id, s, observation)
	}
	// Stable annotation for this original public attempt, NOT an authority token.
	fenceID := a.TaskPublicID + "/attempt/" + strconv.FormatUint(a.AttemptNo, 10)
	if spec.Kind == "gateway" {
		w := &services.BackupGatewayWriter{Agent: deps.Agent, Source: services.BackupGatewaySource{Runtime: runtime, Endpoint: spec.Endpoint, PodUID: spec.UID, Workspace: source.Workspace, RestartRef: spec.RestartRef, InstanceID: source.ID, UserID: source.UserID, Generation: source.Generation, ResumeGeneration: spec.ResumeGeneration, UID: spec.UIDNumber, GID: spec.GIDNumber, Port: spec.Port}, Guard: guard, PollInterval: deps.PollInterval,
			LoadRestart: func(ctx context.Context, ref string) (services.RuntimeAgentCreateGatewayRequest, error) {
				return c.LoadGateway(ctx, a, id, ref)
			}, ClaimRestart: claim,
			CompleteRestart: func(ctx context.Context, s flow.State, gateway string, port int) error {
				return complete(ctx, s, RestartObservation{PodUID: spec.UID, GatewayID: gateway, Port: port})
			}}
		id = w.ID()
		return recoveryAwareWriter{w}
	}
	stopped := func(ctx context.Context, s flow.State, pods []quiesce.PodIdentity) error {
		if err := guard(ctx, "check-stopped", s); err != nil {
			return err
		}
		return c.ConfirmStopped(ctx, a, id, s, pods)
	}
	resumed := func(ctx context.Context, s flow.State) error {
		if err := guard(ctx, "check-resumed", s); err != nil {
			return err
		}
		return c.ConfirmResumed(ctx, a, id, s)
	}
	if spec.Kind == "pod" {
		w := &quiesce.PodWriter{Client: deps.Client, Namespace: source.Namespace, Name: spec.Name, UID: spec.UID, InstanceKey: strconv.Itoa(source.ID), FenceID: fenceID, RestartRef: spec.RestartRef, Generation: int64(source.Generation), Runtime: runtime, Guard: guard, PollInterval: deps.PollInterval,
			LoadRestart: func(ctx context.Context, ref string) (*corev1.Pod, error) { return c.LoadPod(ctx, a, id, ref) }, ClaimRestart: claim,
			CompleteRestart: func(ctx context.Context, s flow.State, uid string) error {
				return complete(ctx, s, RestartObservation{PodUID: uid})
			}, ConfirmStopped: stopped, ConfirmResumed: resumed}
		id = w.ID()
		return recoveryAwareWriter{w}
	}
	w := &quiesce.DeploymentWriter{Client: deps.Client, Namespace: source.Namespace, Name: spec.Name, UID: spec.UID, FenceID: fenceID, Runtime: runtime, Guard: guard, ConfirmStopped: stopped, ConfirmResumed: resumed, PollInterval: deps.PollInterval}
	id = w.ID()
	return recoveryAwareWriter{w}
}

type sourceRecoveryContext struct{}
type recoveryAwareWriter struct{ flow.Writer }

func (w recoveryAwareWriter) Resume(ctx context.Context, s flow.State) error {
	// The existing proof callback is shared by CheckPaused and Resume. Mark the
	// call path explicitly; after cancel/deadline it must check recovery authority,
	// never fall back to expired capture permission or a guessed operation mode.
	return w.Writer.Resume(context.WithValue(ctx, sourceRecoveryContext{}, true), s)
}

// participantWriter freezes a reviewed gate-participant identity (Observe) and
// proves it drained at Pause/CheckPaused, or proves an originally stopped
// instance stayed stopped. It never releases the installation gate itself.
type participantWriter struct {
	spec      ParticipantSpec
	authority d.Authority
	deps      RuntimeWriterDependencies
}

func (w *participantWriter) ID() string { return w.spec.ID }
func (w *participantWriter) check(ctx context.Context, point string, original flow.State) error {
	if original != w.spec.Original {
		return flow.ErrQuiesce
	}
	return writerGuard(ctx, w.deps, w.authority, w.ID(), point, original)
}
func (w *participantWriter) Observe(ctx context.Context) (flow.State, error) {
	return w.spec.Original, w.check(ctx, "observe", w.spec.Original)
}
func (w *participantWriter) Pause(ctx context.Context, s flow.State) (flow.ACK, error) {
	return flow.ACK{UID: s.UID, Generation: s.Generation, Stopped: true}, w.check(ctx, "before-stop", s)
}
func (w *participantWriter) CheckPaused(ctx context.Context, s flow.State) error {
	return w.check(ctx, "check-stopped", s)
}
func (w *participantWriter) Resume(ctx context.Context, s flow.State) error {
	return w.check(ctx, "before-resume", s)
}
