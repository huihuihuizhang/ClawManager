package quiesce

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"reflect"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// RecheckOriginalGatewayAgentPod joins an actual original Pod observation to
// this same authenticated, capture-stopped Gateway observation. It is neither
// a startup decoder nor a publisher/consumer classification.
//
// The caller must obtain pod from its actual original API observation and
// retain its original hold/capability checks before and after use. In
// particular, Pod image/status/spec DATA does not become a native image,
// argv/executable, loaded-service or continuous-hold attestation here.
func (v *VerifiedGatewayNodeObservation) RecheckOriginalGatewayAgentPod(
	ctx context.Context,
	original GatewayNodeObservationRequest,
	boot string,
	pod *corev1.Pod,
	now time.Time,
) (time.Time, error) {
	if v == nil || ctx == nil || ctx.Err() != nil || pod == nil ||
		original.Action != "stopped" ||
		(original.Binding.Kind != GatewayNodeRunning && original.Binding.Kind != GatewayNodeOriginallyStopped) ||
		original.Anchor == "" || original.Anchor != v.response.Anchor ||
		!now.Before(original.Binding.ExpiresAt) || !time.Now().Before(original.Binding.ExpiresAt) ||
		gatewayDataReceipt(original) != nil {
		return time.Time{}, ErrNodeObservation
	}
	_, _, _, _, runtime, _, _, _ := gatewayOriginalIdentity(original)
	if runtime != "openclaw" && runtime != "hermes" {
		return time.Time{}, ErrNodeObservation
	}
	if v.Recheck(ctx, original.Binding, original.Action, boot,
		original.OriginalStateSHA256, observationRawDigest(original.Raw),
		observationRawDigest(original.CompletionRaw), now) != nil {
		return time.Time{}, ErrNodeObservation
	}

	// Parse ONLY the anchor stored inside the genuine opaque response. Caller
	// token parsing or a public response DTO cannot mint this receiver. The
	// client's concrete verified TLS exchange is the provenance; this client
	// does not have the Node's private HMAC key.
	parts := strings.Split(v.response.Anchor, ".")
	if len(parts) != 2 || len(v.response.Anchor) > 256<<10 {
		return time.Time{}, ErrNodeObservation
	}
	sig, err := hex.DecodeString(parts[1])
	if err != nil || len(sig) != 32 || hex.EncodeToString(sig) != parts[1] {
		return time.Time{}, ErrNodeObservation
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(raw) > 192<<10 {
		return time.Time{}, ErrNodeObservation
	}
	var anchor gatewayObservationAnchor
	if observationJSON(strings.NewReader(string(raw)), &anchor) != nil ||
		anchor.Version != GatewayNodeObservationProtocol ||
		observationDigest(anchor.Binding) != observationDigest(original.Binding) ||
		!reflect.DeepEqual(anchor.AgentPod, original.AgentPod) ||
		anchor.RequestSHA256 != gatewayRequestSHA(original) ||
		anchor.OriginalStateSHA256 != original.OriginalStateSHA256 ||
		anchor.BootID == "" || anchor.BootID != boot ||
		anchor.Slot != original.Slot ||
		anchor.WorkspaceRoot != original.WorkspaceRoot || anchor.AgentDataDir != original.AgentDataDir ||
		anchor.Agent.PID <= 1 || anchor.Agent.Start == "" ||
		anchor.Agent.PIDNamespace == "" || anchor.Agent.MountNamespace == "" || anchor.Agent.Cgroup == "" ||
		anchor.Worker.PID <= 1 || anchor.Worker.Start == "" ||
		len(anchor.Paths) == 0 || len(original.SourcePaths) != len(anchor.Paths) {
		return time.Time{}, ErrNodeObservation
	}
	paths := append([]string(nil), original.SourcePaths...)
	sort.Strings(paths)
	for i, path := range paths {
		if !absoluteObservationPath(path) || path == "/" ||
			(i > 0 && gatewayOriginalSourcePathsOverlap(path, paths[i-1])) ||
			path != anchor.Paths[i].Path {
			return time.Time{}, ErrNodeObservation
		}
	}

	// This narrow join never silently covers init/ephemeral containers or
	// sidecars. Their startup/service semantics require their own decoder and
	// native actor association even when a completed init container is listed.
	p := pod.DeepCopy()
	id := anchor.AgentPod
	if !validObservationPods([]PodIdentity{id}, original.Binding.Node) ||
		len(id.Containers) != 1 ||
		p.Namespace != original.Binding.Namespace || p.Name != id.Name ||
		string(p.UID) != id.UID || p.Spec.NodeName != id.Node ||
		p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning ||
		len(p.Spec.InitContainers) != 0 || len(p.Status.InitContainerStatuses) != 0 ||
		len(p.Spec.EphemeralContainers) != 0 || len(p.Status.EphemeralContainerStatuses) != 0 ||
		len(p.Spec.Containers) != 1 || len(p.Status.ContainerStatuses) != 1 {
		return time.Time{}, ErrNodeObservation
	}
	status := p.Status.ContainerStatuses[0]
	if p.Spec.Containers[0].Name == "" || status.Name != p.Spec.Containers[0].Name ||
		status.ContainerID != id.Containers[0] || status.State.Running == nil ||
		status.State.Terminated != nil || status.State.Waiting != nil {
		return time.Time{}, ErrNodeObservation
	}
	if v.Recheck(ctx, original.Binding, original.Action, boot,
		original.OriginalStateSHA256, observationRawDigest(original.Raw),
		observationRawDigest(original.CompletionRaw), now) != nil {
		return time.Time{}, ErrNodeObservation
	}
	return v.response.ValidUntil, nil
}

// Both paths were validated as clean absolute POSIX paths by the caller.
// Keep this data-only comparison portable: Linux native source-coordinate
// helpers are excluded from the Windows installer and must not be borrowed.
func gatewayOriginalSourcePathsOverlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, strings.TrimSuffix(b, "/")+"/") || strings.HasPrefix(b, strings.TrimSuffix(a, "/")+"/")
}
