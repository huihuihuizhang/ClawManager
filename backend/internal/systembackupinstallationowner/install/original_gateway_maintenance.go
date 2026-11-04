package install

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"time"

	"clawreef/internal/runtimecustody"
	"clawreef/internal/services"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/flow"
	q "clawreef/internal/systembackup/quiesce"
	"clawreef/internal/systembackup/scope"
	"clawreef/internal/systembackup/staging"
	c "clawreef/internal/systembackupcontroller"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// These are original administrator-selected INPUT pins, not signed stop proof.
// Every source is independently resolved against the complete current SQL
// census, real Pod/Node identities, actual Agent protocol and B's native I/O.
type OriginalGatewaySelection struct {
	InstanceID                  int
	WorkspaceRoot, AgentDataDir string
	SourcePaths                 []string
	OriginalCipher, OriginalKey BootstrapSourceFilePin
	OriginalPlainSHA256         string
}

const OriginalGatewaySameIncarnationRecovery = "same-agent-incarnation-original-operation.v1"

var ErrOriginalAgentIncarnationChanged = errors.New("original Agent incarnation unavailable or changed; quarantine retained; original source owner recovery required")

type originalGatewayRow struct {
	RuntimePodID, Port, Generation, PID                                  int
	UID, Pod, Namespace, Endpoint, Workspace, State, Gateway, Deployment string
}

type originalGatewayMaintenance struct {
	owner                            *OriginalWriterMaintenance
	journal                          *originalWriterJournal
	source                           domain.SourceInstance
	selection                        OriginalGatewaySelection
	row                              originalGatewayRow
	agent                            services.RuntimeAgentClient
	native                           *q.GatewayNodeObservationClient
	request                          q.GatewayNodeObservationRequest
	state                            flow.State
	originalWireSHA                  string
	restart                          services.RuntimeAgentCreateGatewayRequest
	proof                            *q.VerifiedGatewayNodeObservation
	boot, anchor                     string
	raw, completion                  []byte
	rawAction                        string
	stopDispatched, resumeDispatched bool
	resumedPID                       int
	recovery                         *originalWriterRecoveryFence
}

type originalWriterRecoveryFence struct {
	operator      *authenticatedOperator
	authorization *OriginalWriterRecoveryAuthorization
	owner         *OriginalWriterMaintenance
	journalSHA    string
}

func (g *originalGatewayMaintenance) ID() string {
	return fmt.Sprintf("gateway/%s/%d", g.row.UID, g.source.ID)
}
func (g *originalGatewayMaintenance) Observe(ctx context.Context) (flow.State, error) {
	if g == nil || g.owner.check(ctx) != nil || g.currentBinding(ctx, false) != nil {
		return flow.State{}, ErrInstall
	}
	return g.state, nil
}

func readOriginalGatewayRow(ctx context.Context, tx *sql.Tx, id int) (originalGatewayRow, error) {
	var r originalGatewayRow
	err := tx.QueryRowContext(ctx, `SELECT p.id,COALESCE(p.pod_uid,''),p.pod_name,p.namespace,p.agent_endpoint,b.gateway_port,b.workspace_path,b.generation,b.state,b.gateway_id,p.deployment_name,COALESCE(b.gateway_pid,0) FROM instance_runtime_bindings b JOIN runtime_pods p ON p.id=b.runtime_pod_id WHERE b.instance_id=? AND p.state='ready' AND p.draining=FALSE FOR SHARE`, id).Scan(&r.RuntimePodID, &r.UID, &r.Pod, &r.Namespace, &r.Endpoint, &r.Port, &r.Workspace, &r.Generation, &r.State, &r.Gateway, &r.Deployment, &r.PID)
	return r, err
}

func (p *OriginalWriterMaintenance) prepareGateway(ctx context.Context, source domain.SourceInstance, s OriginalGatewaySelection, agent services.RuntimeAgentClient, native *q.GatewayNodeObservationClient, j *originalWriterJournal) (*originalGatewayMaintenance, error) {
	plan, err := scope.PlanRuntime(scope.Runtime{Type: source.Type, Mode: source.Mode, Backend: source.Backend, Variant: source.Variant, OS: source.OS})
	if err != nil || plan.Mode != "lite" || source.ID != s.InstanceID || source.Generation <= 0 || source.UserID <= 0 || source.Status != "running" && source.Status != "stopped" || agent == nil || native == nil || j == nil || p.check(ctx) != nil {
		return nil, ErrInstall
	}
	if !path.IsAbs(s.WorkspaceRoot) || path.Clean(s.WorkspaceRoot) != s.WorkspaceRoot || s.WorkspaceRoot == "/" || !path.IsAbs(s.AgentDataDir) || path.Clean(s.AgentDataDir) != s.AgentDataDir || s.AgentDataDir == "/" || len(s.SourcePaths) == 0 {
		return nil, ErrInstall
	}
	tx, err := p.operator.installer.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, ErrInstall
	}
	defer tx.Rollback()
	r, err := readOriginalGatewayRow(ctx, tx, source.ID)
	if err != nil || r.UID == "" || r.RuntimePodID <= 0 || r.Namespace != p.operator.installer.plan.Target.Namespace || r.Generation != source.Generation || r.Workspace != source.Workspace || r.State != source.Status || r.Gateway != fmt.Sprintf("gw-%d-%d", source.ID, source.Generation) || source.Namespace != "" && source.Namespace != r.Namespace || source.Pod != "" && source.Pod != r.Pod || r.Port <= 0 || r.Port > 65535 || source.Status == "running" && r.PID <= 0 || source.Status == "stopped" && r.PID != 0 || tx.Rollback() != nil {
		return nil, ErrInstall
	}
	pod, err := p.operator.installer.kube.CoreV1().Pods(r.Namespace).Get(ctx, r.Pod, metav1.GetOptions{})
	u, urlErr := url.Parse(r.Endpoint)
	if err != nil || urlErr != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).Equal(net.ParseIP(pod.Status.PodIP)) || string(pod.UID) != r.UID || pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning || pod.Spec.HostNetwork || len(pod.Spec.Containers) != 1 || len(pod.Spec.EphemeralContainers) != 0 || len(pod.Status.ContainerStatuses) != 1 || pod.Status.ContainerStatuses[0].State.Running == nil || !pod.Status.ContainerStatuses[0].Ready {
		return nil, ErrInstall
	}
	for _, st := range pod.Status.InitContainerStatuses {
		if st.State.Terminated == nil {
			return nil, ErrInstall
		}
	}
	// Verify the SQL deployment through the actual RS owner UID, never labels.
	if len(pod.OwnerReferences) != 1 || pod.OwnerReferences[0].Kind != "ReplicaSet" || pod.OwnerReferences[0].Controller == nil || !*pod.OwnerReferences[0].Controller {
		return nil, ErrInstall
	}
	rs, err := p.operator.installer.kube.AppsV1().ReplicaSets(r.Namespace).Get(ctx, pod.OwnerReferences[0].Name, metav1.GetOptions{})
	if err != nil || rs.UID != pod.OwnerReferences[0].UID || len(rs.OwnerReferences) != 1 || rs.OwnerReferences[0].Kind != "Deployment" || rs.OwnerReferences[0].Name != r.Deployment {
		return nil, ErrInstall
	}
	dep, err := p.operator.installer.kube.AppsV1().Deployments(r.Namespace).Get(ctx, r.Deployment, metav1.GetOptions{})
	if err != nil || dep.UID != rs.OwnerReferences[0].UID || dep.DeletionTimestamp != nil {
		return nil, ErrInstall
	}
	node, err := p.operator.installer.kube.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
	if err != nil || node.UID == "" {
		return nil, ErrInstall
	}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		return nil, ErrInstall
	}
	reservation := hex.EncodeToString(id[:])
	g := &originalGatewayMaintenance{owner: p, journal: j, source: source, selection: s, row: r, agent: agent, native: native}
	g.request = q.GatewayNodeObservationRequest{AgentPod: q.PodIdentity{Name: pod.Name, UID: string(pod.UID), Node: pod.Spec.NodeName, Containers: []string{pod.Status.ContainerStatuses[0].ContainerID}}, WorkspaceRoot: s.WorkspaceRoot, AgentDataDir: s.AgentDataDir, SourcePaths: append([]string(nil), s.SourcePaths...), Binding: q.ObservationBinding{InstallationID: p.operator.installer.plan.Target.InstallationID, OperationID: p.operation, ReservationID: reservation, InventorySHA256: j.inventory, Namespace: r.Namespace, NamespaceUID: p.operator.installer.plan.Target.NamespaceUID, Node: node.Name, NodeUID: string(node.UID), Generation: uint64(source.Generation), ExpiresAt: p.until.UTC().Truncate(time.Microsecond)}}
	if source.Status == "running" {
		client, ok := agent.(services.RuntimeAgentBackupClient)
		if !ok {
			return nil, ErrInstall
		}
		caps, err := client.BackupCapabilities(ctx, r.Endpoint, r.Port)
		if !services.RuntimeBackupSupportsOriginalOperationRecovery(caps) {
			return nil, ErrInstall
		}
		if err != nil || caps == nil || caps.Protocol != services.RuntimeBackupProtocol || caps.Namespace != r.Namespace || caps.PodUID != r.UID || caps.GatewayPort != r.Port || caps.Scope != services.RuntimeBackupStopScope || !caps.Supported || !caps.DurableReservation || p.gatewayRecoveryMode != OriginalGatewaySameIncarnationRecovery || caps.Slot == "" {
			return nil, ErrInstall
		}
		original, err := p.openOriginalGateway(ctx, source, s)
		if err != nil || original.PodUID != r.UID || original.GatewayPort != r.Port || original.PortRange.Start != r.Port || original.PortRange.End < r.Port || original.PortRange.End > 65535 || original.UID <= 0 || original.GID <= 0 || original.UpgradeID != "" || original.AgentType != plan.Type {
			return nil, ErrInstall
		}
		g.originalWireSHA, err = services.RuntimeBackupRestartDigest(original)
		if err != nil {
			return nil, ErrInstall
		}
		// Reserve the exact successor in the durable original operation journal
		// before any stop. The full factory closes every mutation admission first.
		if source.Generation == int(^uint(0)>>1) {
			return nil, ErrInstall
		}
		original.Generation = source.Generation + 1
		digest, err := services.RuntimeBackupRestartDigest(original)
		if err != nil {
			return nil, ErrInstall
		}
		g.restart = original
		req := services.RuntimeBackupRequest{Protocol: services.RuntimeBackupProtocol, Namespace: r.Namespace, PodUID: r.UID, AgentEpoch: caps.AgentEpoch, OperationID: reservation, RuntimeType: plan.Type, InstanceID: source.ID, UserID: source.UserID, Generation: source.Generation, GatewayID: r.Gateway, GatewayPort: r.Port, ExpectedPID: r.PID, ResumeGeneration: original.Generation, RestartSHA256: digest}
		if !req.Valid() {
			return nil, ErrInstall
		}
		g.request.Running = &req
		g.request.Slot = caps.Slot
		g.request.Binding.Kind = q.GatewayNodeRunning
		stateAgent, ok := agent.(services.BackupGatewayAgent)
		if !ok {
			return nil, ErrInstall
		}
		live, err := stateAgent.GatewayState(ctx, r.Endpoint, r.Gateway)
		if err != nil || live == nil || live.State != "running" || live.GatewayID != r.Gateway || live.InstanceID != source.ID || live.UserID != source.UserID || live.Generation != source.Generation || live.PID != r.PID || live.Port != r.Port {
			return nil, ErrInstall
		}
		future, err := stateAgent.GatewayState(ctx, r.Endpoint, fmt.Sprintf("gw-%d-%d", source.ID, original.Generation))
		if !servicesOriginalNotFound(err) || future != nil {
			return nil, ErrInstall
		}
		checkpoint, _ := json.Marshal(struct {
			Source                                  domain.SourceInstance
			OriginalCipher                          BootstrapSourceFilePin
			OriginalPlainSHA256, OriginalWireSHA256 string
			Request                                 services.RuntimeBackupRequest
		}{source, s.OriginalCipher, s.OriginalPlainSHA256, g.originalWireSHA, req})
		g.state = flow.State{UID: r.UID + "/" + r.Gateway, Generation: int64(source.Generation), Running: true, Checkpoint: string(checkpoint)}
	} else {
		client, ok := agent.(services.RuntimeAgentStoppedBackupClient)
		if !ok {
			return nil, ErrInstall
		}
		caps, err := client.StoppedBackupCapabilities(ctx, r.Endpoint, r.Port)
		if !services.RuntimeStoppedBackupSupportsOriginalOperationRecovery(caps) {
			return nil, ErrInstall
		}
		if err != nil || caps == nil || caps.Protocol != services.RuntimeStoppedBackupProtocol || caps.Namespace != r.Namespace || caps.PodUID != r.UID || caps.GatewayPort != r.Port || !caps.Supported || !caps.DurableReservation || !caps.KeepStoppedComplete || p.gatewayRecoveryMode != OriginalGatewaySameIncarnationRecovery || caps.Scope != services.RuntimeStoppedBackupScope {
			return nil, ErrInstall
		}
		identity := services.RuntimeStoppedBackupIdentity{Protocol: services.RuntimeStoppedBackupProtocol, Namespace: r.Namespace, PodUID: r.UID, AgentEpoch: caps.AgentEpoch, RuntimeType: plan.Type, InstanceID: source.ID, UserID: source.UserID, Generation: source.Generation, GatewayID: r.Gateway, GatewayPort: r.Port}
		inspection, raw, err := client.InspectStoppedBackup(ctx, r.Endpoint, identity)
		if err != nil || inspection.Identity != identity || inspection.State != "stopped_unreserved" || inspection.Scope != services.RuntimeStoppedBackupScope || inspection.Slot != caps.Slot {
			return nil, ErrInstall
		}
		req := services.RuntimeStoppedBackupRequest{RuntimeStoppedBackupIdentity: identity, OperationID: reservation, CheckpointSHA256: inspection.CheckpointSHA256, HoldUntil: g.request.Binding.ExpiresAt}
		if !req.Valid() {
			return nil, ErrInstall
		}
		g.request.Stopped = &req
		g.request.Slot = caps.Slot
		g.request.Binding.Kind = q.GatewayNodeOriginallyStopped
		g.raw = bytes.Clone(raw)
		g.rawAction = "inspect"
		g.state = flow.State{UID: r.UID + "/" + r.Gateway, Generation: int64(source.Generation), Checkpoint: req.CheckpointSHA256}
	}
	if p.check(ctx) != nil || g.currentBinding(ctx, false) != nil {
		return nil, ErrInstall
	}
	return g, nil
}

func servicesOriginalNotFound(err error) bool {
	return errors.Is(err, services.ErrRuntimeAgentNotFound)
}

// This consumer promises only the current Agent incarnation. A false
// AgentRestartReconciliation capability is retained as false, never promoted.
// Every mutation/state boundary proves the original actual epoch/Pod/slot.
func (g *originalGatewayMaintenance) checkIncarnation(ctx context.Context) error {
	if g.owner.gatewayRecoveryMode != OriginalGatewaySameIncarnationRecovery || originalMaintenanceReadCheck(ctx, g.owner, g.recovery) != nil {
		return ErrOriginalAgentIncarnationChanged
	}
	if g.request.Running != nil {
		caps, err := g.agent.(services.RuntimeAgentBackupClient).BackupCapabilities(ctx, g.row.Endpoint, g.row.Port)
		if !services.RuntimeBackupSupportsOriginalOperationRecovery(caps) {
			return ErrOriginalAgentIncarnationChanged
		}
		r := g.request.Running
		if err != nil || caps == nil || caps.AgentEpoch != r.AgentEpoch || caps.PodUID != r.PodUID || caps.Namespace != r.Namespace || caps.Slot != g.request.Slot || caps.GatewayPort != r.GatewayPort || caps.Protocol != r.Protocol || !caps.Supported || !caps.DurableReservation || caps.Scope != services.RuntimeBackupStopScope {
			return ErrOriginalAgentIncarnationChanged
		}
	} else {
		caps, err := g.agent.(services.RuntimeAgentStoppedBackupClient).StoppedBackupCapabilities(ctx, g.row.Endpoint, g.row.Port)
		if !services.RuntimeStoppedBackupSupportsOriginalOperationRecovery(caps) {
			return ErrOriginalAgentIncarnationChanged
		}
		r := g.request.Stopped
		if err != nil || caps == nil || caps.AgentEpoch != r.AgentEpoch || caps.PodUID != r.PodUID || caps.Namespace != r.Namespace || caps.Slot != g.request.Slot || caps.GatewayPort != r.GatewayPort || caps.Protocol != r.Protocol || !caps.Supported || !caps.DurableReservation || !caps.KeepStoppedComplete || caps.Scope != services.RuntimeStoppedBackupScope {
			return ErrOriginalAgentIncarnationChanged
		}
	}
	return nil
}
func (g *originalGatewayMaintenance) backupControl(ctx context.Context, action string, restart *services.RuntimeAgentCreateGatewayRequest) (services.RuntimeBackupObservation, error) {
	if g.recovery != nil && action != "state" && action != "resume" && action != "complete" {
		return services.RuntimeBackupObservation{}, ErrInstall
	}
	if g.checkIncarnation(ctx) != nil {
		return services.RuntimeBackupObservation{}, ErrOriginalAgentIncarnationChanged
	}
	o, err := g.agent.(services.RuntimeAgentBackupClient).BackupControl(ctx, g.row.Endpoint, action, *g.request.Running, restart)
	if g.checkIncarnation(ctx) != nil {
		return o, ErrOriginalAgentIncarnationChanged
	}
	return o, err
}
func (g *originalGatewayMaintenance) stoppedControl(ctx context.Context, action string) (services.RuntimeStoppedBackupObservation, error) {
	if g.recovery != nil && action != "observe" && action != "complete-kept-stopped" {
		return services.RuntimeStoppedBackupObservation{}, ErrInstall
	}
	if g.checkIncarnation(ctx) != nil {
		return services.RuntimeStoppedBackupObservation{}, ErrOriginalAgentIncarnationChanged
	}
	o, err := g.agent.(services.RuntimeAgentStoppedBackupClient).StoppedBackupControl(ctx, g.row.Endpoint, action, *g.request.Stopped)
	if g.checkIncarnation(ctx) != nil {
		return o, ErrOriginalAgentIncarnationChanged
	}
	return o, err
}

func (p *OriginalWriterMaintenance) openOriginalGateway(ctx context.Context, source domain.SourceInstance, s OriginalGatewaySelection) (services.RuntimeAgentCreateGatewayRequest, error) {
	var original services.RuntimeAgentCreateGatewayRequest
	if p.check(ctx) != nil || !digestPattern.MatchString(s.OriginalPlainSHA256) {
		return original, ErrInstall
	}
	cipher, err := readBootstrapSourcePin(s.OriginalCipher, 8<<20)
	if err != nil {
		return original, ErrInstall
	}
	key, err := readBootstrapSourcePin(s.OriginalKey, 32)
	defer clear(key)
	if err != nil || len(key) != 32 {
		return original, ErrInstall
	}
	var plain bytes.Buffer
	defer func() { clear(plain.Bytes()) }()
	binding := runtimecustody.Binding(p.operator.installer.plan.Target.InstallationID, runtimecustody.Identity{InstanceID: source.ID, UserID: source.UserID, Generation: source.Generation, WorkspacePath: source.Workspace}, s.OriginalPlainSHA256)
	if staging.Open(ctx, bytes.NewReader(cipher), &plain, key, binding, 7<<20) != nil || hash(plain.Bytes()) != s.OriginalPlainSHA256 || decodeOriginalWriterMaterialData(plain.Bytes(), &original) != nil || original.InstanceID != source.ID || original.UserID != source.UserID || original.Generation != source.Generation || original.WorkspacePath != source.Workspace {
		return services.RuntimeAgentCreateGatewayRequest{}, ErrInstall
	}
	return original, nil
}

func (g *originalGatewayMaintenance) currentBinding(ctx context.Context, recovered bool) error {
	if originalMaintenanceReadCheck(ctx, g.owner, g.recovery) != nil {
		return ErrInstall
	}
	tx, err := g.owner.operator.installer.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return ErrInstall
	}
	defer tx.Rollback()
	r, err := readOriginalGatewayRow(ctx, tx, g.source.ID)
	if err != nil {
		return ErrInstall
	}
	want := g.row
	if recovered && g.request.Running != nil {
		want.Generation = g.request.Running.ResumeGeneration
		want.Gateway = fmt.Sprintf("gw-%d-%d", g.source.ID, want.Generation)
		want.PID = g.resumedPID
		if want.PID <= 0 {
			return ErrInstall
		}
	}
	if r != want || tx.Rollback() != nil {
		return ErrInstall
	}
	pod, err := g.owner.operator.installer.kube.CoreV1().Pods(g.row.Namespace).Get(ctx, g.row.Pod, metav1.GetOptions{})
	if err != nil || string(pod.UID) != g.row.UID || pod.DeletionTimestamp != nil || pod.Spec.NodeName != g.request.Binding.Node {
		return ErrInstall
	}
	return nil
}

// No JSON/body can supply originalDigest. The optional method is negotiated
// on the concrete B-minted opaque handle only; older observers fail before a
// source stop. B owns the method that reads its authenticated original anchor.
type originalGatewayDigestObservation interface{ OriginalRestartSHA256() string }

func (g *originalGatewayMaintenance) prepareNative(ctx context.Context) error {
	if g.owner.checkCurrentGate(ctx, c.GateAcquiring) != nil || g.anchor != "" {
		return ErrInstall
	}
	g.request.Binding.FenceEpoch = g.owner.token.FencingToken
	g.request.Action = "prepare"
	g.request.Raw = bytes.Clone(g.raw)
	g.request.RawAction = g.rawAction
	proof, err := g.native.ObserveWriter(ctx, g.request, g.state)
	if err != nil {
		return ErrInstall
	}
	if g.state.Running {
		original, ok := any(proof).(originalGatewayDigestObservation)
		if !ok || original.OriginalRestartSHA256() != g.originalWireSHA {
			return ErrInstall
		}
	}
	out := proof.Response()
	g.anchor = out.Anchor
	g.boot = out.BootID
	g.proof = proof
	return g.journal.append(ctx, g.ID(), "native_prepare", &g.state, struct {
		Request     q.GatewayNodeObservationRequest
		Observation q.GatewayNodeObservationResponse
		Selection   OriginalGatewaySelection
	}{g.request, out, g.selection})
}

func (g *originalGatewayMaintenance) nativeCheck(ctx context.Context, phase string) error {
	if g.recovery != nil && (g.recovery.checkReleasing(ctx) != nil || phase != "recovery-stopped" && phase != "recovered" && phase != "recovered-stopped") {
		return ErrInstall
	}
	if g.anchor == "" || len(g.raw) == 0 {
		return ErrInstall
	}
	r := g.request
	r.Action = phase
	r.Anchor = g.anchor
	r.SourcePaths = nil
	r.Raw = bytes.Clone(g.raw)
	r.RawAction = g.rawAction
	r.CompletionRaw = bytes.Clone(g.completion)
	proof, err := g.native.ObserveWriter(ctx, r, g.state)
	if err != nil || proof.Response().BootID != g.boot {
		return ErrInstall
	}
	if err = g.journal.append(ctx, g.ID(), "native_"+phase, &g.state, struct {
		Request     q.GatewayNodeObservationRequest
		Observation q.GatewayNodeObservationResponse
	}{r, proof.Response()}); err != nil {
		return err
	}
	g.proof = proof
	return nil
}

func (g *originalGatewayMaintenance) dispatchStop(ctx context.Context) error {
	s := g.state
	if s != g.state || g.owner.checkCurrentGate(ctx, c.GateAcquiring) != nil || g.currentBinding(ctx, false) != nil || g.anchor == "" || g.stopDispatched {
		return ErrInstall
	}
	if g.journal.append(ctx, g.ID(), "stop_send_unknown", &s, g.request) != nil {
		return ErrInstall
	}
	g.stopDispatched = true
	if g.request.Running != nil {
		o, err := g.backupControl(ctx, "stop", nil)
		if err == nil && !o.Pending && services.ValidateRuntimeBackupReceipt(*g.request.Running, o.Receipt) && o.Receipt.State == "stopped" {
			g.raw = bytes.Clone(o.Raw)
			g.rawAction = "stop"
			if g.journal.append(ctx, g.ID(), "stop_receipt", &s, o.Raw) != nil {
				return ErrInstall
			}
		}
	} else {
		o, err := g.stoppedControl(ctx, "reserve")
		if err == nil {
			g.raw = bytes.Clone(o.Raw)
			g.rawAction = "reserve"
			if g.journal.append(ctx, g.ID(), "reserve_receipt", &s, o.Raw) != nil {
				return ErrInstall
			}
		}
	}
	return nil
}

func (g *originalGatewayMaintenance) Pause(ctx context.Context, s flow.State) (flow.ACK, error) {
	if s != g.state || g.dispatchStop(ctx) != nil {
		return flow.ACK{}, ErrInstall
	}
	// Read state for this exact operation after any uncertain send; never
	// convert 202/timeout into an ACK or dispatch a replacement operation.
	if g.CheckPaused(ctx, s) != nil {
		return flow.ACK{}, ErrInstall
	}
	return flow.ACK{UID: s.UID, Generation: s.Generation, Stopped: true}, nil
}

func (g *originalGatewayMaintenance) CheckPaused(ctx context.Context, s flow.State) error {
	if s != g.state || !g.stopDispatched || g.owner.checkCurrentGate(ctx, c.GateAcquiring, c.GateHeld) != nil || g.currentBinding(ctx, false) != nil {
		return ErrInstall
	}
	if g.request.Running != nil {
		o, err := g.backupControl(ctx, "state", nil)
		if err != nil || o.Pending || !services.ValidateRuntimeBackupReceipt(*g.request.Running, o.Receipt) || o.Receipt.State != "stopped" {
			return ErrInstall
		}
		g.raw = bytes.Clone(o.Raw)
		g.rawAction = "state"
	} else {
		o, err := g.stoppedControl(ctx, "observe")
		if err != nil || o.Receipt.State != "reserved_stopped" {
			return ErrInstall
		}
		g.raw = bytes.Clone(o.Raw)
		g.rawAction = "observe"
	}
	if g.journal.append(ctx, g.ID(), "current_stop_receipt", &s, g.raw) != nil || g.nativeCheck(ctx, "stopped") != nil || g.owner.checkCurrentGate(ctx, c.GateAcquiring, c.GateHeld) != nil {
		return ErrInstall
	}
	return nil
}

// Resume is wired only by the complete holder after its concrete archive
// providers have all stopped. Recovery never uses a caller-provided bool.
func (g *originalGatewayMaintenance) Resume(ctx context.Context, s flow.State) error {
	if s != g.state || g.recovery == nil || g.recovery.owner != g.owner || g.recovery.journalSHA == "" || g.recovery.checkReleasing(ctx) != nil {
		return ErrInstall
	}
	if g.request.Stopped != nil {
		current, err := g.stoppedControl(ctx, "observe")
		if err != nil || current.Receipt.State != "reserved_stopped" && current.Receipt.State != "completed_stopped" {
			return ErrInstall
		}
		g.raw = bytes.Clone(current.Raw)
		g.rawAction = "observe"
		alreadyCompleted := current.Receipt.State == "completed_stopped"
		if alreadyCompleted {
			g.completion = bytes.Clone(current.Raw)
		}
		if !alreadyCompleted && (g.nativeCheck(ctx, "recovery-stopped") != nil || g.journal.append(ctx, g.ID(), "keep_stopped_complete_send_unknown", &s, g.request.Stopped) != nil) {
			return ErrInstall
		}
		client := g.agent.(services.RuntimeAgentStoppedBackupClient)
		o, err := g.stoppedControl(ctx, "complete-kept-stopped")
		if err != nil || o.Receipt.State != "completed_stopped" {
			return ErrInstall
		}
		g.completion = bytes.Clone(o.Raw)
		if g.journal.append(ctx, g.ID(), "kept_stopped_completion", &s, o.Raw) != nil {
			return ErrInstall
		}
		i, raw, err := client.InspectStoppedBackup(ctx, g.row.Endpoint, g.request.Stopped.RuntimeStoppedBackupIdentity)
		if err != nil || i.CheckpointSHA256 != s.Checkpoint || i.State != "stopped_unreserved" {
			return ErrInstall
		}
		g.raw = bytes.Clone(raw)
		g.rawAction = "inspect"
		if g.nativeCheck(ctx, "recovered-stopped") != nil || g.currentBinding(ctx, false) != nil {
			return ErrInstall
		}
		return g.journal.append(ctx, g.ID(), "original_state_restored", &s, nil)
	}
	o, err := g.backupControl(ctx, "state", nil)
	if err != nil || o.Pending || !services.ValidateRuntimeBackupReceipt(*g.request.Running, o.Receipt) {
		return ErrInstall
	}
	if o.Receipt.State == "stopped" {
		g.raw = bytes.Clone(o.Raw)
		g.rawAction = "state"
		if g.resumeDispatched || g.nativeCheck(ctx, "recovery-stopped") != nil || g.journal.append(ctx, g.ID(), "resume_send_unknown", &s, g.request.Running) != nil {
			return ErrInstall
		}
		g.resumeDispatched = true
		o, err = g.backupControl(ctx, "resume", &g.restart)
		if err != nil || o.Pending {
			return ErrInstall
		}
	}
	if !services.ValidateRuntimeBackupReceipt(*g.request.Running, o.Receipt) || o.Receipt.State != "resumed" {
		return ErrInstall
	}
	g.raw = bytes.Clone(o.Raw)
	g.rawAction = "state"
	if g.journal.append(ctx, g.ID(), "resume_receipt", &s, g.raw) != nil || g.nativeCheck(ctx, "recovered") != nil {
		return ErrInstall
	}
	if g.commitRecoveredGateway(ctx, o.Receipt.PID) != nil {
		return ErrCommitUnknown
	}
	if g.journal.append(ctx, g.ID(), "complete_send_unknown", &s, g.request.Running) != nil {
		return ErrInstall
	}
	o, err = g.backupControl(ctx, "complete", nil)
	if err != nil || o.Pending || !services.ValidateRuntimeBackupReceipt(*g.request.Running, o.Receipt) || o.Receipt.State != "resumed" {
		return ErrInstall
	}
	g.raw = bytes.Clone(o.Raw)
	g.rawAction = "complete"
	if g.nativeCheck(ctx, "recovered") != nil || g.currentBinding(ctx, true) != nil {
		return ErrInstall
	}
	return g.journal.append(ctx, g.ID(), "original_state_restored", &s, g.raw)
}

// Exact original row CAS; a failed/unknown commit is settled by readback,
// never by a second Agent start. No future task row or recovery grant exists.
func (g *originalGatewayMaintenance) commitRecoveredGateway(ctx context.Context, pid int) error {
	if pid <= 0 || g.recovery.checkReleasing(ctx) != nil {
		return ErrInstall
	}
	tx, err := g.owner.operator.installer.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return ErrInstall
	}
	defer tx.Rollback()
	if g.recovery == nil || g.recovery.authorization == nil || g.recovery.authorization.set.lockOriginalRecovery(ctx, tx, g.recovery) != nil {
		return ErrInstall
	}
	r, err := readOriginalGatewayRow(ctx, tx, g.source.ID)
	if err != nil {
		return ErrInstall
	}
	want := g.row
	want.Generation = g.request.Running.ResumeGeneration
	want.Gateway = fmt.Sprintf("gw-%d-%d", g.source.ID, want.Generation)
	want.PID = pid
	g.resumedPID = pid
	if r != want {
		if r != g.row {
			return ErrInstall
		}
		result, err := tx.ExecContext(ctx, `UPDATE instance_runtime_bindings SET generation=?,gateway_id=?,gateway_pid=?,state='running' WHERE instance_id=? AND generation=? AND gateway_port=? AND runtime_pod_id=? AND gateway_pid=? AND state='running'`, want.Generation, want.Gateway, pid, g.source.ID, g.row.Generation, g.row.Port, g.row.RuntimePodID, g.row.PID)
		if err != nil {
			return ErrInstall
		}
		n, err := result.RowsAffected()
		if err != nil || n != 1 {
			return ErrInstall
		}
		result, err = tx.ExecContext(ctx, `UPDATE instances SET runtime_generation=? WHERE id=? AND runtime_generation=? AND user_id=? AND status='running'`, want.Generation, g.source.ID, g.source.Generation, g.source.UserID)
		if err != nil {
			return ErrInstall
		}
		n, err = result.RowsAffected()
		if err != nil || n != 1 {
			return ErrInstall
		}
	}
	if g.journal.append(ctx, g.ID(), "source_binding_commit_unknown", &g.state, want) != nil {
		return ErrInstall
	}
	_ = tx.Commit()
	if g.currentBinding(ctx, true) != nil {
		return ErrCommitUnknown
	}
	return g.journal.append(ctx, g.ID(), "source_binding_readback", &g.state, want)
}
