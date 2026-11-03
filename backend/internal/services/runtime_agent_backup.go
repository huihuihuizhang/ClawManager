package services

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const RuntimeBackupProtocol = "isolated-backup.v1"
const RuntimeBackupStopScope = "instance_pid_namespaces_and_mounts"

type RuntimeBackupCapabilities struct {
	Protocol                   string `json:"protocol"`
	Namespace                  string `json:"namespace"`
	PodUID                     string `json:"pod_uid"`
	AgentEpoch                 string `json:"agent_epoch"`
	Slot                       string `json:"slot"`
	GatewayPort                int    `json:"gateway_port"`
	Scope                      string `json:"confirmation_scope"`
	Supported                  bool   `json:"supported"`
	DurableReservation         bool   `json:"durable_reservation"`
	AgentRestartReconciliation bool   `json:"agent_restart_reconciliation"`
	RecoveryScope              string `json:"recovery_scope"`
	AgentRestartPolicy         string `json:"agent_restart_policy"`
}

type RuntimeBackupRequest struct {
	Protocol         string `json:"protocol"`
	Namespace        string `json:"namespace"`
	PodUID           string `json:"pod_uid"`
	AgentEpoch       string `json:"agent_epoch"`
	OperationID      string `json:"operation_id"`
	RuntimeType      string `json:"runtime_type"`
	InstanceID       int    `json:"instance_id"`
	UserID           int    `json:"user_id"`
	Generation       int    `json:"generation"`
	GatewayID        string `json:"gateway_id"`
	GatewayPort      int    `json:"gateway_port"`
	ExpectedPID      int    `json:"expected_pid"`
	ResumeGeneration int    `json:"resume_generation"`
	RestartSHA256    string `json:"restart_sha256"`
}

func (r RuntimeBackupRequest) Valid() bool {
	h, err := hex.DecodeString(r.RestartSHA256)
	return r.Protocol == RuntimeBackupProtocol && r.Namespace != "" && r.PodUID != "" && stopTokenValid(r.AgentEpoch) && stopTokenValid(r.OperationID) && err == nil && len(h) == 32 && hex.EncodeToString(h) == r.RestartSHA256 && r.RuntimeType != "" && r.InstanceID > 0 && r.UserID > 0 && r.Generation > 0 && r.ResumeGeneration > r.Generation && r.ExpectedPID > 0 && r.GatewayPort > 0 && r.GatewayPort <= 65535 && r.GatewayID == fmt.Sprintf("gw-%d-%d", r.InstanceID, r.Generation)
}

type RuntimeBackupReceipt struct {
	Request     RuntimeBackupRequest `json:"request"`
	State       string               `json:"state"`
	Scope       string               `json:"confirmation_scope"`
	PID         int                  `json:"pid,omitempty"`
	ConfirmedAt time.Time            `json:"confirmed_at"`
}

// Raw retains the exact authenticated response bytes for D's transaction and
// digest checks. A 202 response is Pending, never a stop or resume receipt.
type RuntimeBackupObservation struct {
	Receipt RuntimeBackupReceipt
	Raw     []byte
	Pending bool
}

func ValidateRuntimeBackupReceipt(req RuntimeBackupRequest, receipt RuntimeBackupReceipt) bool {
	return req.Valid() && receipt.Request == req && receipt.Scope == RuntimeBackupStopScope && !receipt.ConfirmedAt.IsZero() && ((receipt.State == "stopped" && receipt.PID == 0) || (receipt.State == "resumed" && receipt.PID > 0))
}

// Additive native protocol; neither legacy DELETE nor process-group stop can
// satisfy this interface's positive writer-tree and durable-reservation proof.
type RuntimeAgentBackupClient interface {
	BackupCapabilities(context.Context, string, int) (*RuntimeBackupCapabilities, error)
	BackupControl(context.Context, string, string, RuntimeBackupRequest, *RuntimeAgentCreateGatewayRequest) (RuntimeBackupObservation, error)
}

// The field order and omission rules match Agent gateway.CreateGatewayRequest
// in isolated-backup.v1. The legacy services DTO has a different field order;
// its ciphertext/material digest must not be used as this wire digest.
func RuntimeBackupRestartDigest(r RuntimeAgentCreateGatewayRequest) (string, error) {
	native := struct {
		PodUID              string                `json:"pod_uid,omitempty"`
		SecurityProfile     string                `json:"security_profile,omitempty"`
		InstanceID          int                   `json:"instance_id"`
		UserID              int                   `json:"user_id"`
		AgentType           string                `json:"agent_type"`
		WorkspacePath       string                `json:"workspace_path"`
		ProjectRelativePath string                `json:"project_relative_path,omitempty"`
		GatewayPort         int                   `json:"gateway_port,omitempty"`
		PortRange           RuntimeAgentPortRange `json:"port_range"`
		UID                 int                   `json:"uid"`
		GID                 int                   `json:"gid"`
		CPUCores            float64               `json:"cpu_cores"`
		MemoryMB            int                   `json:"memory_mb"`
		DiskQuotaMB         int                   `json:"disk_quota_mb"`
		Generation          int                   `json:"generation"`
		RequestID           string                `json:"request_id,omitempty"`
		UpgradeID           string                `json:"upgrade_id,omitempty"`
		Environment         map[string]string     `json:"environment,omitempty"`
		Env                 map[string]string     `json:"env,omitempty"`
	}{r.PodUID, r.SecurityProfile, r.InstanceID, r.UserID, r.AgentType, r.WorkspacePath, r.ProjectRelativePath, r.GatewayPort, r.PortRange, r.UID, r.GID, r.CPUCores, r.MemoryMB, r.DiskQuotaMB, r.Generation, r.RequestID, r.UpgradeID, r.Environment, r.Env}
	raw, err := json.Marshal(native)
	if err != nil {
		return "", err
	}
	defer clear(raw)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:]), nil
}

func (c *runtimeAgentHTTPClient) backupHTTP(ctx context.Context, endpoint, method, path string, body any) ([]byte, int, error) {
	if ctx == nil || c.upgradeHTTPClient == nil || c.controlToken == "" {
		return nil, 0, ErrRuntimeStopUnconfirmed
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, 0, ErrRuntimeStopUnconfirmed
	}
	var payload []byte
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		defer clear(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(endpoint, "/")+path, bytes.NewReader(payload))
	if err != nil {
		return nil, 0, ErrRuntimeStopUnconfirmed
	}
	req.Header.Set("X-ClawManager-Control-Token", c.controlToken)
	req.Header.Set("Content-Type", "application/json")
	client := *c.upgradeHTTPClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, ErrRuntimeStopUnconfirmed
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 202 {
		return nil, resp.StatusCode, ErrRuntimeStopUnconfirmed
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (64<<10)+1))
	if err != nil || len(raw) > 64<<10 {
		return nil, resp.StatusCode, ErrRuntimeStopUnconfirmed
	}
	return raw, resp.StatusCode, nil
}

func decodeRuntimeBackup(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing backup response")
	}
	return nil
}

func (c *runtimeAgentHTTPClient) BackupCapabilities(ctx context.Context, endpoint string, port int) (*RuntimeBackupCapabilities, error) {
	if port <= 0 || port > 65535 {
		return nil, ErrRuntimeStopUnconfirmed
	}
	raw, status, err := c.backupHTTP(ctx, endpoint, "GET", "/v1/backup/capabilities?gateway_port="+strconv.Itoa(port), nil)
	var caps RuntimeBackupCapabilities
	if err != nil || status != 200 || decodeRuntimeBackup(raw, &caps) != nil || caps.Protocol != RuntimeBackupProtocol || caps.Scope != RuntimeBackupStopScope || !caps.Supported || !caps.DurableReservation || caps.Namespace == "" || caps.PodUID == "" || caps.Slot == "" || caps.GatewayPort != port || !stopTokenValid(caps.AgentEpoch) {
		return nil, ErrRuntimeStopUnconfirmed
	}
	return &caps, nil
}

func (c *runtimeAgentHTTPClient) BackupControl(ctx context.Context, endpoint, action string, req RuntimeBackupRequest, restart *RuntimeAgentCreateGatewayRequest) (RuntimeBackupObservation, error) {
	var zero RuntimeBackupObservation
	if !req.Valid() {
		return zero, ErrRuntimeStopUnconfirmed
	}
	var body any = req
	switch action {
	case "stop", "state", "complete":
		if restart != nil {
			return zero, ErrRuntimeStopUnconfirmed
		}
	case "resume":
		if restart == nil {
			return zero, ErrRuntimeStopUnconfirmed
		}
		hash, err := RuntimeBackupRestartDigest(*restart)
		if err != nil || hash != req.RestartSHA256 {
			return zero, ErrRuntimeStopReceiptMismatch
		}
		body = struct {
			Request RuntimeBackupRequest             `json:"request"`
			Restart RuntimeAgentCreateGatewayRequest `json:"restart"`
		}{req, *restart}
	default:
		return zero, ErrRuntimeStopUnconfirmed
	}
	raw, status, err := c.backupHTTP(ctx, endpoint, "POST", "/v1/backup/"+action, body)
	if err != nil {
		return zero, err
	}
	if status == 202 {
		var pending struct {
			State string `json:"state"`
		}
		if (action != "resume" && action != "state") || decodeRuntimeBackup(raw, &pending) != nil || pending.State != "resuming" {
			return zero, ErrRuntimeStopReceiptMismatch
		}
		return RuntimeBackupObservation{Pending: true}, nil
	}
	var receipt RuntimeBackupReceipt
	if decodeRuntimeBackup(raw, &receipt) != nil || !ValidateRuntimeBackupReceipt(req, receipt) || (action == "stop" && receipt.State != "stopped") || ((action == "resume" || action == "complete") && receipt.State != "resumed") {
		return zero, ErrRuntimeStopReceiptMismatch
	}
	return RuntimeBackupObservation{Receipt: receipt, Raw: raw}, nil
}
