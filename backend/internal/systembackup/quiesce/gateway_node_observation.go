package quiesce

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"time"

	"clawreef/internal/services"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const GatewayNodeObservationProtocol = "gateway-node-observation.v1"
const GatewayNodeRunning = "gateway_isolated_running_source"
const GatewayNodeOriginallyStopped = "gateway_originally_stopped_source"

// Config paths are ORIGINAL independently authenticated Agent configuration
// coordinates inside the exact CRI container, not paths selected by a user.
// D authenticates that configuration/census and the actual Agent transport.
type GatewayNodeObservationRequest struct {
	Version, Action, Nonce            string
	Binding                           ObservationBinding
	Deadline                          time.Time
	AgentPod                          PodIdentity
	Slot, WorkspaceRoot, AgentDataDir string
	Running                           *services.RuntimeBackupRequest
	Stopped                           *services.RuntimeStoppedBackupRequest
	Raw                               []byte
	CompletionRaw                     []byte
	RawAction                         string
	OriginalStateSHA256               string
	SourcePaths                       []string
	Anchor                            string
}
type GatewayNodeObservationResponse struct {
	Version, Action, Nonce, RequestSHA256, OriginalStateSHA256, AgentRawSHA256, CompletionRawSHA256, Anchor, BootID string
	Binding                                                                                                         ObservationBinding
	StartedAt, FinishedAt, ValidUntil                                                                               time.Time
	TasksChecked, Files                                                                                             int
	Facts                                                                                                           []string
}
type gatewayNativeScope struct {
	Monitor   observedProcess
	Init      observedProcess
	Processes []observedProcess
}

func gatewayScopeContains(p observedProcess, scope gatewayNativeScope) bool {
	if scope.Monitor.PID > 0 && p.PID == scope.Monitor.PID && p.Start == scope.Monitor.Start {
		return true
	}
	if scope.Init.PIDNamespace != "" && (p.PIDNamespace == scope.Init.PIDNamespace || p.MountNamespace == scope.Init.MountNamespace) {
		return true
	}
	for _, v := range scope.Processes {
		if p.PID == v.PID && p.Start == v.Start {
			return true
		}
	}
	return false
}

type gatewayNativePin struct{ Device, Inode uint64 }
type gatewayObservationAnchor struct {
	Version                                                       string
	Binding                                                       ObservationBinding
	AgentPod                                                      PodIdentity
	Agent                                                         observedProcess
	Worker                                                        observedProcess
	Slot, WorkspaceRoot, AgentDataDir, OriginalDigest, Checkpoint string
	RequestSHA256                                                 string
	OriginalStateSHA256                                           string
	Paths                                                         []observedPath
	Lock, BookParent, LedgerParent                                gatewayNativePin
	Scope                                                         gatewayNativeScope
	BootID                                                        string
	PreparedTasks, PreparedFiles                                  int
}

func gatewayRequestSHA(r GatewayNodeObservationRequest) string {
	if r.Running != nil {
		return observationDigest(r.Running)
	}
	return observationDigest(r.Stopped)
}
func gatewayOriginalIdentity(r GatewayNodeObservationRequest) (namespace, pod, epoch, operation, runtime string, instance, user, generation int) {
	if r.Running != nil {
		q := r.Running
		return q.Namespace, q.PodUID, q.AgentEpoch, q.OperationID, q.RuntimeType, q.InstanceID, q.UserID, q.Generation
	}
	if r.Stopped != nil {
		q := r.Stopped
		return q.Namespace, q.PodUID, q.AgentEpoch, q.OperationID, q.RuntimeType, q.InstanceID, q.UserID, q.Generation
	}
	return
}
func gatewayDataReceipt(r GatewayNodeObservationRequest) error {
	if (r.Binding.Kind != GatewayNodeOriginallyStopped || r.Action != "recovered-stopped") && len(r.CompletionRaw) != 0 {
		return ErrNodeObservation
	}
	if r.Binding.Kind == GatewayNodeRunning {
		if r.Running == nil || r.Stopped != nil || !r.Running.Valid() {
			return ErrNodeObservation
		}
		if r.Action == "prepare" {
			if len(r.Raw) != 0 || r.RawAction != "" {
				return ErrNodeObservation
			}
			return nil
		}
		if r.RawAction != "state" && r.RawAction != "stop" && r.RawAction != "complete" {
			return ErrNodeObservation
		}
		o, e := services.DecodeRuntimeBackupWireObservation(*r.Running, r.RawAction, http.StatusOK, r.Raw)
		if e != nil || o.Pending {
			return ErrNodeObservation
		}
		wanted := "stopped"
		if r.Action == "recovered" {
			wanted = "resumed"
		}
		if o.Receipt.State != wanted {
			return ErrNodeObservation
		}
		return nil
	}
	if r.Binding.Kind != GatewayNodeOriginallyStopped || r.Stopped == nil || r.Running != nil || !r.Stopped.Valid() {
		return ErrNodeObservation
	}
	if r.Action == "prepare" || r.Action == "recovered-stopped" {
		var inspection services.RuntimeStoppedBackupInspection
		fields, e := gatewayExactFields(r.Raw, []string{"identity", "slot", "confirmation_scope", "checkpoint_sha256", "state"})
		if e != nil {
			return e
		}
		if _, e = gatewayExactFields(fields["identity"], gatewayStoppedIdentityFields()); e != nil {
			return e
		}
		if r.RawAction != "inspect" || gatewayStrictJSON(r.Raw, &inspection) != nil || inspection.Identity != r.Stopped.RuntimeStoppedBackupIdentity || inspection.State != "stopped_unreserved" || inspection.Scope != services.RuntimeStoppedBackupScope || inspection.Slot != r.Slot || inspection.CheckpointSHA256 != r.Stopped.CheckpointSHA256 {
			return ErrNodeObservation
		}
		if r.Action == "recovered-stopped" {
			if _, e := services.DecodeRuntimeStoppedBackupWireObservation(*r.Stopped, "complete-kept-stopped", 200, r.CompletionRaw); e != nil {
				return ErrNodeObservation
			}
		} else if len(r.CompletionRaw) != 0 {
			return ErrNodeObservation
		}
		return nil
	}
	if r.RawAction != "reserve" && r.RawAction != "observe" {
		return ErrNodeObservation
	}
	// Recovery may occur after the original hold. Strictly decode the original
	// persisted receipt without presenting it as a fresh Agent observe response.
	var receipt services.RuntimeStoppedBackupReceipt
	fields, e := gatewayExactFields(r.Raw, []string{"request", "slot", "confirmation_scope", "state", "checkpoint_sha256", "confirmed_at"})
	if e != nil {
		return e
	}
	if _, e = gatewayExactFields(fields["request"], append(gatewayStoppedIdentityFields(), "operation_id", "checkpoint_sha256", "hold_until")); e != nil {
		return e
	}
	if gatewayStrictJSON(r.Raw, &receipt) != nil || observationDigest(receipt.Request) != observationDigest(r.Stopped) || receipt.State != "reserved_stopped" || receipt.Scope != services.RuntimeStoppedBackupScope || receipt.Slot != r.Slot || receipt.CheckpointSHA256 != r.Stopped.CheckpointSHA256 || receipt.ConfirmedAt.IsZero() {
		return ErrNodeObservation
	}
	return nil
}
func gatewayStoppedIdentityFields() []string {
	return []string{"protocol", "namespace", "pod_uid", "agent_epoch", "runtime_type", "instance_id", "user_id", "generation", "gateway_id", "gateway_port"}
}
func gatewayExactFields(b []byte, names []string) (map[string]json.RawMessage, error) {
	if len(b) == 0 || len(b) > 64<<10 {
		return nil, ErrNodeObservation
	}
	if _, e := jsoncanonicalizer.Transform(b); e != nil {
		return nil, ErrNodeObservation
	}
	var f map[string]json.RawMessage
	if json.Unmarshal(b, &f) != nil || len(f) != len(names) {
		return nil, ErrNodeObservation
	}
	for _, name := range names {
		if len(f[name]) == 0 || bytes.Equal(bytes.TrimSpace(f[name]), []byte("null")) {
			return nil, ErrNodeObservation
		}
	}
	return f, nil
}
func gatewayStrictJSON(b []byte, v any) error {
	if len(b) == 0 || len(b) > 64<<10 {
		return ErrNodeObservation
	}
	if _, e := jsoncanonicalizer.Transform(b); e != nil {
		return ErrNodeObservation
	}
	return observationJSON(bytes.NewReader(b), v)
}
func (o *NodeObserver) sealGateway(a gatewayObservationAnchor) (string, error) {
	b, e := json.Marshal(a)
	if e != nil || len(b) > 192<<10 {
		return "", ErrNodeObservation
	}
	h := hmac.New(sha256.New, o.key)
	h.Write([]byte(GatewayNodeObservationProtocol + "\x00"))
	h.Write(b)
	return base64.RawURLEncoding.EncodeToString(b) + "." + hex.EncodeToString(h.Sum(nil)), nil
}
func (o *NodeObserver) openGateway(token string) (gatewayObservationAnchor, error) {
	var a gatewayObservationAnchor
	p := strings.Split(token, ".")
	if len(p) != 2 || len(token) > 256<<10 {
		return a, ErrNodeObservation
	}
	b, e := base64.RawURLEncoding.DecodeString(p[0])
	if e != nil {
		return a, ErrNodeObservation
	}
	signature, e := hex.DecodeString(p[1])
	if e != nil {
		return a, ErrNodeObservation
	}
	h := hmac.New(sha256.New, o.key)
	h.Write([]byte(GatewayNodeObservationProtocol + "\x00"))
	h.Write(b)
	if !hmac.Equal(signature, h.Sum(nil)) || json.Unmarshal(b, &a) != nil || a.Version != GatewayNodeObservationProtocol {
		return a, ErrNodeObservation
	}
	return a, nil
}
func (o *NodeObserver) ObserveGateway(ctx context.Context, r GatewayNodeObservationRequest) (GatewayNodeObservationResponse, error) {
	var out GatewayNodeObservationResponse
	if o == nil || len(o.key) != 32 || ctx == nil || ctx.Err() != nil {
		return out, ErrNodeObservation
	}
	now := time.Now().UTC()
	deadline, ok := ctx.Deadline()
	b := r.Binding
	recovery := r.Action == "recovery-stopped" || r.Action == "recovered-stopped" || r.Action == "recovered"
	ns, pod, _, op, runtime, _, _, generation := gatewayOriginalIdentity(r)
	// The controller's original durable operation may be a UUID/public task ID;
	// Agent's 16-byte operation is its existing per-source reservation identity.
	// Bind BOTH; never replace the real controller operation with its wire hash.
	if !ok || gatewayObservationFacts(b.Kind, r.Action) == nil || r.Version != GatewayNodeObservationProtocol || !validObservationHash(r.Nonce) || !validObservationHash(r.OriginalStateSHA256) || b.Node != o.Node || b.NodeUID != o.NodeUID || b.Namespace != ns || b.OperationID == "" || b.NamespaceUID == "" || b.InstallationID == "" || b.ReservationID != op || b.Generation != uint64(generation) || !validObservationHash(b.InventorySHA256) || r.AgentPod.UID != pod || !validObservationPods([]PodIdentity{r.AgentPod}, o.Node) || len(r.AgentPod.Containers) != 1 || !now.Before(r.Deadline) || r.Deadline.After(now.Add(15*time.Second)) || deadline.After(r.Deadline) || b.ExpiresAt.IsZero() || (!recovery && !r.Deadline.Before(b.ExpiresAt)) || !absoluteObservationPath(r.WorkspaceRoot) || !absoluteObservationPath(r.AgentDataDir) || r.WorkspaceRoot == "/" || r.AgentDataDir == "/" || runtime == "" || strings.ContainsAny(runtime, "/\\.\x00\r\n") || gatewayDataReceipt(r) != nil {
		return out, ErrNodeObservation
	}
	if r.Stopped != nil && !b.ExpiresAt.Equal(r.Stopped.HoldUntil) {
		return out, ErrNodeObservation
	}
	if o.hostIdentity(ctx) != nil {
		return out, observationFailure("host_visibility")
	}
	var a gatewayObservationAnchor
	var err error
	if r.Action == "prepare" {
		if r.Anchor != "" || len(r.SourcePaths) == 0 || len(r.SourcePaths) > 128 {
			return out, ErrNodeObservation
		}
		a, err = o.prepareGateway(ctx, r)
		if err == nil {
			out.Anchor, err = o.sealGateway(a)
		}
		out.TasksChecked = a.PreparedTasks
		out.Files = a.PreparedFiles
	} else {
		if len(r.SourcePaths) != 0 {
			return out, ErrNodeObservation
		}
		a, err = o.openGateway(r.Anchor)
		if err == nil && (observationDigest(a.Binding) != observationDigest(b) || !reflect.DeepEqual(a.AgentPod, r.AgentPod) || a.RequestSHA256 != gatewayRequestSHA(r) || a.OriginalStateSHA256 != r.OriginalStateSHA256 || a.Slot != r.Slot || a.WorkspaceRoot != r.WorkspaceRoot || a.AgentDataDir != r.AgentDataDir || a.BootID != o.BootID) {
			err = ErrNodeObservation
		}
		if err == nil {
			out.TasksChecked, out.Files, err = o.checkGateway(ctx, r, a)
		}
		out.Anchor = r.Anchor
	}
	if err != nil {
		return GatewayNodeObservationResponse{}, err
	}
	if ctx.Err() != nil || o.hostIdentity(ctx) != nil || !time.Now().Before(r.Deadline) {
		return GatewayNodeObservationResponse{}, ErrNodeObservation
	}
	out.Version = r.Version
	out.Action = r.Action
	out.Nonce = r.Nonce
	out.RequestSHA256 = observationDigest(r)
	out.OriginalStateSHA256 = r.OriginalStateSHA256
	out.AgentRawSHA256 = observationRawDigest(r.Raw)
	out.CompletionRawSHA256 = observationRawDigest(r.CompletionRaw)
	out.Binding = b
	out.BootID = o.BootID
	out.StartedAt = now
	out.FinishedAt = time.Now().UTC()
	out.ValidUntil = r.Deadline
	out.Facts = gatewayObservationFacts(r.Binding.Kind, r.Action)
	if out.Facts == nil {
		return GatewayNodeObservationResponse{}, ErrNodeObservation
	}
	return out, nil
}
func observationRawDigest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func gatewayObservationFacts(kind, action string) []string {
	if kind == GatewayNodeRunning {
		switch action {
		case "prepare":
			return []string{"agent_container_running", "original_gateway_monitor_and_private_init_observed", "original_source_mounts_observed"}
		case "stopped", "recovery-stopped":
			return []string{"agent_container_running", "original_gateway_scopes_absent", "original_v1_reservation_native_current", "no_observed_unexpected_source_writer"}
		case "recovered":
			return []string{"agent_container_running", "original_gateway_scopes_absent", "actual_reserved_successor_scopes_running", "source_mounts_unchanged"}
		}
	}
	if kind == GatewayNodeOriginallyStopped {
		switch action {
		case "prepare":
			return []string{"agent_container_running", "original_stopped_checkpoint_native_current", "no_observed_source_writer"}
		case "stopped", "recovery-stopped":
			return []string{"agent_container_running", "original_v2_reservation_native_current", "original_stopped_checkpoint_unchanged", "no_observed_source_writer"}
		case "recovered-stopped":
			return []string{"agent_container_running", "original_v2_completion_native_current", "original_generation_kept_stopped", "no_observed_source_writer"}
		}
	}
	return nil
}
