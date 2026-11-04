package services

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"
)

const RuntimeSharedBackupProtocol = "shared-container-freeze.v1"

// Exact Agent ABI. These structs are comparison/continuity data, NOT original
// SQL authority, cgroup-frozen evidence, flush evidence or an opaque source hold.
type RuntimeSharedBackupIdentity struct {
	Protocol, Namespace, PodUID, Deployment, AgentEpoch, OperationID, InventorySHA256 string
}
type RuntimeSharedBackupEntry struct {
	GatewayID, RuntimeType, OriginalState, RequestSHA256, PIDStartTicks string
	InstanceID, UserID, Generation, Port, PID                           int
}
type RuntimeSharedNativeState struct {
	Version                                                      string
	Identity                                                     RuntimeSharedBackupIdentity
	Phase, OriginalSHA256, JournalSHA256, JournalPath, GuardPath string
	AgentPID                                                     int
	AgentStartTicks, PIDNamespace, MountNamespace, BootID        string
	Entries                                                      []RuntimeSharedBackupEntry
	Sequence                                                     uint64
	PreparedAt, UpdatedAt                                        time.Time
}
type RuntimeSharedBackupCapabilities struct {
	Protocol, Namespace, PodUID, Deployment, AgentEpoch, AgentStartTicks, GuardPath, JournalDirectory string
	AgentPID                                                                                          int
	Supported, DurableReservation, AgentRestartReconciliation                                         bool
}

type RuntimeSharedBackupCallbacks struct{ client *runtimeAgentHTTPClient }

// Uses only the actual existing private HTTP client/credential constructor.
// A DTO or caller implementation of RuntimeAgentClient cannot supply this path.
func NewRuntimeSharedBackupCallbacks(client RuntimeAgentClient) (*RuntimeSharedBackupCallbacks, error) {
	c, ok := client.(*runtimeAgentHTTPClient)
	if !ok || c == nil || c.httpClient == nil || c.controlToken == "" {
		return nil, ErrRuntimeAgentUnsupported
	}
	return &RuntimeSharedBackupCallbacks{client: c}, nil
}

func sharedRuntimeDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func sharedRuntimeHex(value string, n int) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == n && hex.EncodeToString(raw) == value
}
func SharedRuntimeOriginalSHA(state RuntimeSharedNativeState) string {
	raw, _ := json.Marshal(struct {
		Identity                                              RuntimeSharedBackupIdentity
		AgentPID                                              int
		AgentStartTicks, PIDNamespace, MountNamespace, BootID string
		Entries                                               []RuntimeSharedBackupEntry
	}{state.Identity, state.AgentPID, state.AgentStartTicks, state.PIDNamespace, state.MountNamespace, state.BootID, state.Entries})
	return sharedRuntimeDigest(raw)
}

func validSharedRuntimeIdentity(id RuntimeSharedBackupIdentity) bool {
	return id.Protocol == RuntimeSharedBackupProtocol && id.Namespace != "" && id.PodUID != "" && id.Deployment != "" && sharedRuntimeHex(id.AgentEpoch, 16) && sharedRuntimeHex(id.OperationID, 16) && sharedRuntimeHex(id.InventorySHA256, 32)
}

func (c *RuntimeSharedBackupCallbacks) call(ctx context.Context, endpoint, method, route string, body any, out any) ([]byte, error) {
	if c == nil || c.client == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrRuntimeAgentUnsupported
	}
	var input io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, ErrRuntimeAgentConflict
		}
		input = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(endpoint, "/")+route, input)
	if err != nil {
		return nil, ErrRuntimeAgentUnsupported
	}
	req.Header.Set("X-ClawManager-Control-Token", c.client.controlToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// EXACTLY one request. Unknown response never retries prepare/resume/complete.
	response, err := c.client.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return nil, ErrRuntimeAgentConflict
	}
	if response.StatusCode != http.StatusOK {
		return nil, ErrRuntimeAgentConflict
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if !sharedRuntimeUniqueJSON(raw) || d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return nil, ErrRuntimeAgentConflict
	}
	return raw, nil
}

func (c *RuntimeSharedBackupCallbacks) Capabilities(ctx context.Context, endpoint string) (RuntimeSharedBackupCapabilities, []byte, error) {
	var value RuntimeSharedBackupCapabilities
	raw, err := c.call(ctx, endpoint, http.MethodGet, "/v1/shared-backup/capabilities", nil, &value)
	if err != nil {
		return value, nil, err
	}
	if value.Namespace == "" || value.PodUID == "" || value.Deployment == "" || value.Protocol != RuntimeSharedBackupProtocol || !value.Supported || !value.DurableReservation || value.AgentRestartReconciliation || value.AgentPID <= 0 || value.AgentStartTicks == "" || !sharedRuntimeHex(value.AgentEpoch, 16) || !path.IsAbs(value.GuardPath) || !path.IsAbs(value.JournalDirectory) {
		return RuntimeSharedBackupCapabilities{}, nil, ErrRuntimeAgentUnsupported
	}
	return value, raw, nil
}

func (c *RuntimeSharedBackupCallbacks) Transition(ctx context.Context, endpoint, action string, id RuntimeSharedBackupIdentity) (RuntimeSharedNativeState, []byte, error) {
	var state RuntimeSharedNativeState
	if !validSharedRuntimeIdentity(id) || (action != "prepare" && action != "state" && action != "resume" && action != "complete") {
		return state, nil, ErrRuntimeAgentUnsupported
	}
	raw, err := c.call(ctx, endpoint, http.MethodPost, "/v1/shared-backup/"+action, id, &state)
	if err != nil {
		return state, nil, err
	}
	if state.Version != "shared-runtime-native-state.v1" || state.Identity != id || state.AgentPID <= 0 || state.Entries == nil || state.PIDNamespace == "" || state.MountNamespace == "" || state.BootID == "" || state.PreparedAt.IsZero() || state.UpdatedAt.Before(state.PreparedAt) || !regexp.MustCompile(`^[0-9]+$`).MatchString(state.AgentStartTicks) || state.Sequence == 0 || !sharedRuntimeHex(state.JournalSHA256, 32) || state.OriginalSHA256 != SharedRuntimeOriginalSHA(state) || !path.IsAbs(state.JournalPath) || !path.IsAbs(state.GuardPath) || (state.Phase != "reserved" && state.Phase != "resumed" && state.Phase != "completed") {
		return RuntimeSharedNativeState{}, nil, ErrRuntimeAgentConflict
	}
	if (action == "resume" && state.Phase != "resumed" && state.Phase != "completed") || (action == "complete" && state.Phase != "completed") {
		return RuntimeSharedNativeState{}, nil, ErrRuntimeAgentConflict
	}
	seen := map[string]bool{}
	for _, entry := range state.Entries {
		if entry.GatewayID == "" || entry.RuntimeType == "" || entry.PID < 0 || (entry.OriginalState != "running" && entry.OriginalState != "stopped" && entry.OriginalState != "error") || seen[entry.GatewayID] || entry.InstanceID <= 0 || entry.UserID <= 0 || entry.Generation <= 0 || entry.Port <= 0 || entry.Port > 65535 || !sharedRuntimeHex(entry.RequestSHA256, 32) || (entry.PID > 0 && !regexp.MustCompile(`^[1-9][0-9]*$`).MatchString(entry.PIDStartTicks)) || (entry.PID == 0 && entry.PIDStartTicks != "") || (entry.OriginalState == "running" && entry.PID <= 0) {
			return RuntimeSharedNativeState{}, nil, ErrRuntimeAgentConflict
		}
		seen[entry.GatewayID] = true
	}
	return state, raw, nil
}
