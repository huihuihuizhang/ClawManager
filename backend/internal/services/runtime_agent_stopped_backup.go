package services

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const RuntimeStoppedBackupProtocol = "isolated-stopped-backup.v2"
const RuntimeStoppedBackupScope = "instance_stopped_writer_reservation"

type RuntimeStoppedBackupIdentity struct {
	Protocol    string `json:"protocol"`
	Namespace   string `json:"namespace"`
	PodUID      string `json:"pod_uid"`
	AgentEpoch  string `json:"agent_epoch"`
	RuntimeType string `json:"runtime_type"`
	InstanceID  int    `json:"instance_id"`
	UserID      int    `json:"user_id"`
	Generation  int    `json:"generation"`
	GatewayID   string `json:"gateway_id"`
	GatewayPort int    `json:"gateway_port"`
}

func (i RuntimeStoppedBackupIdentity) Valid() bool {
	return i.Protocol == RuntimeStoppedBackupProtocol && i.Namespace != "" && i.PodUID != "" && stopTokenValid(i.AgentEpoch) && i.RuntimeType != "" && i.InstanceID > 0 && i.UserID > 0 && i.Generation > 0 && i.GatewayID == fmt.Sprintf("gw-%d-%d", i.InstanceID, i.Generation) && i.GatewayPort > 0 && i.GatewayPort <= 65535
}

type RuntimeStoppedBackupRequest struct {
	RuntimeStoppedBackupIdentity
	OperationID      string    `json:"operation_id"`
	CheckpointSHA256 string    `json:"checkpoint_sha256"`
	HoldUntil        time.Time `json:"hold_until"`
}

func (r RuntimeStoppedBackupRequest) Valid() bool {
	_, offset := r.HoldUntil.Zone()
	return r.RuntimeStoppedBackupIdentity.Valid() && stopTokenValid(r.OperationID) && len(r.CheckpointSHA256) == 64 && runtimeStoppedHex(r.CheckpointSHA256) && !r.HoldUntil.IsZero() && offset == 0 && r.HoldUntil.Nanosecond()%1000 == 0
}
func runtimeStoppedHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func runtimeStoppedRequestEqual(a, b RuntimeStoppedBackupRequest) bool {
	return a.RuntimeStoppedBackupIdentity == b.RuntimeStoppedBackupIdentity && a.OperationID == b.OperationID && a.CheckpointSHA256 == b.CheckpointSHA256 && a.HoldUntil.Equal(b.HoldUntil)
}

type RuntimeStoppedBackupCapabilities struct {
	Protocol                   string `json:"protocol"`
	Namespace                  string `json:"namespace"`
	PodUID                     string `json:"pod_uid"`
	AgentEpoch                 string `json:"agent_epoch"`
	Slot                       string `json:"slot"`
	GatewayPort                int    `json:"gateway_port"`
	Scope                      string `json:"confirmation_scope"`
	Supported                  bool   `json:"supported"`
	DurableReservation         bool   `json:"durable_reservation"`
	KeepStoppedComplete        bool   `json:"keep_stopped_complete"`
	AgentRestartReconciliation bool   `json:"agent_restart_reconciliation"`
	RecoveryScope              string `json:"recovery_scope"`
	AgentRestartPolicy         string `json:"agent_restart_policy"`
}
type RuntimeStoppedBackupInspection struct {
	Identity         RuntimeStoppedBackupIdentity `json:"identity"`
	Slot             string                       `json:"slot"`
	Scope            string                       `json:"confirmation_scope"`
	CheckpointSHA256 string                       `json:"checkpoint_sha256"`
	State            string                       `json:"state"`
}
type RuntimeStoppedBackupReceipt struct {
	Request          RuntimeStoppedBackupRequest `json:"request"`
	Slot             string                      `json:"slot"`
	Scope            string                      `json:"confirmation_scope"`
	State            string                      `json:"state"`
	CheckpointSHA256 string                      `json:"checkpoint_sha256"`
	ConfirmedAt      time.Time                   `json:"confirmed_at"`
}
type RuntimeStoppedBackupObservation struct {
	Receipt RuntimeStoppedBackupReceipt
	Raw     []byte
}

// Separate additive capability. Legacy/v1/PID0/resumed receipts cannot satisfy
// it. It never grants maintenance authority or proves external process/FD/mmap
// absence: actual original gate and B node observation remain mandatory.
type RuntimeAgentStoppedBackupClient interface {
	StoppedBackupCapabilities(context.Context, string, int) (*RuntimeStoppedBackupCapabilities, error)
	InspectStoppedBackup(context.Context, string, RuntimeStoppedBackupIdentity) (RuntimeStoppedBackupInspection, []byte, error)
	StoppedBackupControl(context.Context, string, string, RuntimeStoppedBackupRequest) (RuntimeStoppedBackupObservation, error)
}

func decodeRuntimeStoppedWire(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > 64<<10 || !utf8.Valid(raw) {
		return ErrRuntimeStopReceiptMismatch
	}
	if _, e := jsoncanonicalizer.Transform(raw); e != nil {
		return ErrRuntimeStopReceiptMismatch
	}
	if decodeRuntimeBackup(raw, out) != nil {
		return ErrRuntimeStopReceiptMismatch
	}
	return nil
}
func (c *runtimeAgentHTTPClient) StoppedBackupCapabilities(ctx context.Context, endpoint string, port int) (*RuntimeStoppedBackupCapabilities, error) {
	if port < 1 || port > 65535 {
		return nil, ErrRuntimeStopUnconfirmed
	}
	raw, status, e := c.backupHTTP(ctx, endpoint, http.MethodGet, "/v2/backup-stopped/capabilities?gateway_port="+strconv.Itoa(port), nil)
	var caps RuntimeStoppedBackupCapabilities
	if e != nil || status != 200 || decodeRuntimeStoppedWire(raw, &caps) != nil || caps.Protocol != RuntimeStoppedBackupProtocol || caps.Scope != RuntimeStoppedBackupScope || !caps.Supported || !caps.DurableReservation || !caps.KeepStoppedComplete || caps.GatewayPort != port || caps.Namespace == "" || caps.PodUID == "" || caps.Slot == "" || !stopTokenValid(caps.AgentEpoch) {
		return nil, ErrRuntimeStopUnconfirmed
	}
	if _, e := runtimeBackupWireObject(raw, []string{"protocol", "namespace", "pod_uid", "agent_epoch", "slot", "gateway_port", "confirmation_scope", "supported", "durable_reservation", "keep_stopped_complete", "agent_restart_reconciliation"}, []string{"recovery_scope", "agent_restart_policy"}); e != nil {
		return nil, ErrRuntimeStopReceiptMismatch
	}
	return &caps, nil
}
func (c *runtimeAgentHTTPClient) InspectStoppedBackup(ctx context.Context, endpoint string, identity RuntimeStoppedBackupIdentity) (RuntimeStoppedBackupInspection, []byte, error) {
	var out RuntimeStoppedBackupInspection
	if !identity.Valid() {
		return out, nil, ErrRuntimeStopUnconfirmed
	}
	raw, status, e := c.backupHTTP(ctx, endpoint, http.MethodPost, "/v2/backup-stopped/inspect", identity)
	if e != nil || status != 200 || decodeRuntimeStoppedWire(raw, &out) != nil || out.Identity != identity || out.Scope != RuntimeStoppedBackupScope || out.Slot == "" || out.State != "stopped_unreserved" || len(out.CheckpointSHA256) != 64 || !runtimeStoppedHex(out.CheckpointSHA256) {
		return RuntimeStoppedBackupInspection{}, nil, ErrRuntimeStopReceiptMismatch
	}
	fields, e := runtimeBackupWireObject(raw, []string{"identity", "slot", "confirmation_scope", "checkpoint_sha256", "state"}, nil)
	if e != nil {
		return RuntimeStoppedBackupInspection{}, nil, ErrRuntimeStopReceiptMismatch
	}
	if _, e = runtimeBackupWireObject(fields["identity"], []string{"protocol", "namespace", "pod_uid", "agent_epoch", "runtime_type", "instance_id", "user_id", "generation", "gateway_id", "gateway_port"}, nil); e != nil {
		return RuntimeStoppedBackupInspection{}, nil, ErrRuntimeStopReceiptMismatch
	}
	return out, bytes.Clone(raw), nil
}
func (c *runtimeAgentHTTPClient) StoppedBackupControl(ctx context.Context, endpoint, action string, req RuntimeStoppedBackupRequest) (RuntimeStoppedBackupObservation, error) {
	var out RuntimeStoppedBackupObservation
	if !req.Valid() {
		return out, ErrRuntimeStopUnconfirmed
	}
	switch action {
	case "reserve", "observe":
		if !time.Now().Before(req.HoldUntil) {
			return out, ErrRuntimeStopUnconfirmed
		}
	case "complete-kept-stopped":
	default:
		return out, ErrRuntimeStopUnconfirmed
	}
	raw, status, e := c.backupHTTP(ctx, endpoint, http.MethodPost, "/v2/backup-stopped/"+action, req)
	if e != nil {
		return out, e
	}
	return DecodeRuntimeStoppedBackupWireObservation(req, action, status, raw)
}

// DATA-only exact raw verification. Actual authenticated live Agent transport,
// original maintenance authority and independent node proof stay mandatory.
func DecodeRuntimeStoppedBackupWireObservation(req RuntimeStoppedBackupRequest, action string, status int, raw []byte) (RuntimeStoppedBackupObservation, error) {
	var out RuntimeStoppedBackupObservation
	if !req.Valid() || status != 200 || decodeRuntimeStoppedWire(raw, &out.Receipt) != nil {
		return out, ErrRuntimeStopUnconfirmed
	}
	if action != "reserve" && action != "observe" && action != "complete-kept-stopped" {
		return out, ErrRuntimeStopUnconfirmed
	}
	fields, e := runtimeBackupWireObject(raw, []string{"request", "slot", "confirmation_scope", "state", "checkpoint_sha256", "confirmed_at"}, nil)
	if e != nil {
		return RuntimeStoppedBackupObservation{}, e
	}
	if _, e = runtimeBackupWireObject(fields["request"], []string{"protocol", "namespace", "pod_uid", "agent_epoch", "runtime_type", "instance_id", "user_id", "generation", "gateway_id", "gateway_port", "operation_id", "checkpoint_sha256", "hold_until"}, nil); e != nil {
		return RuntimeStoppedBackupObservation{}, e
	}
	r := out.Receipt
	wanted := "reserved_stopped"
	if action == "complete-kept-stopped" {
		wanted = "completed_stopped"
	}
	if !runtimeStoppedRequestEqual(r.Request, req) || r.Scope != RuntimeStoppedBackupScope || r.State != wanted || r.Slot == "" || r.CheckpointSHA256 != req.CheckpointSHA256 || r.ConfirmedAt.IsZero() || action != "complete-kept-stopped" && !time.Now().Before(req.HoldUntil) {
		return RuntimeStoppedBackupObservation{}, ErrRuntimeStopReceiptMismatch
	}
	out.Raw = bytes.Clone(raw)
	return out, nil
}

var _ RuntimeAgentStoppedBackupClient = (*runtimeAgentHTTPClient)(nil)
