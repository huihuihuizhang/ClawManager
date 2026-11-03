package quiesce

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

const StoppedProObservationProtocol = "stopped-pro-current-baseline.v1"

// These are correlation DATA from D's authenticated original Installer/API
// census. Node observes the physical paths; it cannot turn these fields into
// Kubernetes authority, unique-volume ownership, a held gate or history proof.
type StoppedProVolume struct {
	NamespaceUID, ClaimName, ClaimUID, PVName, PVUID, PVSpecSHA256 string
	DataNodeUID, UniqueNodeEvidenceSHA256, HostPath                string
}
type StoppedProBaseline struct {
	SourceKey, RuntimeType                 string
	InstanceID, UserID, InstanceGeneration uint64
	NamespaceUID, CurrentConfigSHA256      string
	// Empty UID means no controller exists NOW, not a fabricated old object.
	ControllerUID, ControllerSpecSHA256 string
	ControllerGeneration                int64
	ControllerReplicas                  int32
	Volumes                             []StoppedProVolume
}
type StoppedProNodeObservationRequest struct {
	Version, Action, Nonce                                                    string
	Binding                                                                   ObservationBinding
	OriginalReservationIdentitySHA256, OriginalStateSHA256, NativeScopeSHA256 string
	Baseline                                                                  StoppedProBaseline
	Deadline                                                                  time.Time
	Anchor                                                                    string
}
type StoppedProNodeObservationResponse struct {
	Version, Action, Nonce, RequestSHA256, Anchor, BootID                                     string
	Binding                                                                                   ObservationBinding
	BaselineSHA256, OriginalReservationIdentitySHA256, OriginalStateSHA256, NativeScopeSHA256 string
	StartedAt, FinishedAt, ValidUntil                                                         time.Time
	TasksChecked, Files, ContainersChecked, SandboxesChecked                                  int
	CRIObservationSHA256                                                                      string
}
type stoppedProAnchor struct {
	Version, BootID                                                                           string
	Binding                                                                                   ObservationBinding
	BaselineSHA256, OriginalReservationIdentitySHA256, OriginalStateSHA256, NativeScopeSHA256 string
	Paths                                                                                     []observedPath
}

// Stable scope DATA for D's NativeRequestSHA256. It deliberately excludes the
// reservation hash, transport nonce/deadline and anchor, preventing self-hashing.
func StoppedProNativeScopeSHA256(r StoppedProNodeObservationRequest) string {
	return observationDigest(struct {
		Version             string
		Binding             ObservationBinding
		Baseline            StoppedProBaseline
		OriginalStateSHA256 string
	}{StoppedProObservationProtocol, r.Binding, r.Baseline, r.OriginalStateSHA256})
}
func stoppedProBaselinePaths(r StoppedProNodeObservationRequest) ([]string, error) {
	b := r.Baseline
	if b.SourceKey == "" || b.RuntimeType == "" || b.InstanceID == 0 || b.UserID == 0 || b.InstanceGeneration == 0 || b.InstanceGeneration != r.Binding.Generation || b.NamespaceUID != r.Binding.NamespaceUID || !validObservationHash(b.CurrentConfigSHA256) || len(b.Volumes) == 0 || len(b.Volumes) > 128 {
		return nil, ErrNodeObservation
	}
	if b.ControllerReplicas != 0 {
		return nil, ErrNodeObservation
	}
	if b.ControllerUID == "" {
		if b.ControllerGeneration != 0 || b.ControllerSpecSHA256 != "" {
			return nil, ErrNodeObservation
		}
	} else if b.ControllerGeneration <= 0 || !validObservationHash(b.ControllerSpecSHA256) {
		return nil, ErrNodeObservation
	}
	var paths []string
	seen := map[string]bool{}
	for _, v := range b.Volumes {
		if v.NamespaceUID != b.NamespaceUID || v.ClaimName == "" || v.ClaimUID == "" || v.PVName == "" || v.PVUID == "" || !validObservationHash(v.PVSpecSHA256) || v.DataNodeUID != r.Binding.NodeUID || !validObservationHash(v.UniqueNodeEvidenceSHA256) || !absoluteObservationPath(v.HostPath) || v.HostPath == "/" || seen[v.HostPath] {
			return nil, ErrNodeObservation
		}
		for _, old := range paths {
			if v.HostPath == old || strings.HasPrefix(v.HostPath, old+"/") || strings.HasPrefix(old, v.HostPath+"/") {
				return nil, ErrNodeObservation
			}
		}
		seen[v.HostPath] = true
		paths = append(paths, v.HostPath)
	}
	return paths, nil
}
func (o *NodeObserver) sealStoppedPro(a stoppedProAnchor) (string, error) {
	b, e := json.Marshal(a)
	if e != nil || len(b) > 192<<10 {
		return "", ErrNodeObservation
	}
	h := hmac.New(sha256.New, o.key)
	h.Write([]byte(StoppedProObservationProtocol + "\x00"))
	h.Write(b)
	return base64.RawURLEncoding.EncodeToString(b) + "." + hex.EncodeToString(h.Sum(nil)), nil
}
func (o *NodeObserver) openStoppedPro(token string) (stoppedProAnchor, error) {
	var a stoppedProAnchor
	p := strings.Split(token, ".")
	if len(p) != 2 || len(token) > 256<<10 {
		return a, ErrNodeObservation
	}
	b, e := base64.RawURLEncoding.DecodeString(p[0])
	if e != nil {
		return a, ErrNodeObservation
	}
	sig, e := hex.DecodeString(p[1])
	if e != nil {
		return a, ErrNodeObservation
	}
	h := hmac.New(sha256.New, o.key)
	h.Write([]byte(StoppedProObservationProtocol + "\x00"))
	h.Write(b)
	if !hmac.Equal(sig, h.Sum(nil)) || json.Unmarshal(b, &a) != nil || a.Version != StoppedProObservationProtocol {
		return a, ErrNodeObservation
	}
	return a, nil
}
func (o *NodeObserver) ObserveStoppedPro(ctx context.Context, r StoppedProNodeObservationRequest) (StoppedProNodeObservationResponse, error) {
	var out StoppedProNodeObservationResponse
	if o == nil || len(o.key) != 32 || ctx == nil || ctx.Err() != nil {
		return out, ErrNodeObservation
	}
	now := time.Now().UTC()
	d, ok := ctx.Deadline()
	b := r.Binding
	recovery := r.Action == "recovery-stopped" || r.Action == "recovered-stopped"
	if !ok || r.Version != StoppedProObservationProtocol || b.Kind != StoppedProObservationProtocol || !validObservationHash(r.Nonce) || !validObservationHash(r.OriginalStateSHA256) || !validObservationHash(r.OriginalReservationIdentitySHA256) || !validObservationHash(b.InventorySHA256) || b.Node != o.Node || b.NodeUID != o.NodeUID || b.InstallationID == "" || b.OperationID == "" || b.ReservationID == "" || b.Namespace == "" || b.NamespaceUID == "" || b.Generation == 0 || b.ExpiresAt.IsZero() || !now.Before(r.Deadline) || r.Deadline.After(now.Add(15*time.Second)) || d.After(r.Deadline) || !recovery && !r.Deadline.Before(b.ExpiresAt) {
		return out, ErrNodeObservation
	}
	if r.Action != "prepare" && r.Action != "stopped" && !recovery {
		return out, ErrNodeObservation
	}
	p, e := stoppedProBaselinePaths(r)
	if e != nil {
		return out, e
	}
	if !validObservationHash(r.NativeScopeSHA256) || r.NativeScopeSHA256 != StoppedProNativeScopeSHA256(r) {
		return out, ErrNodeObservation
	}
	if o.hostIdentity(ctx) != nil {
		return out, observationFailure("host_visibility")
	}
	paths, e := o.paths(ctx, p)
	if e != nil {
		return out, observationFailure("source_mount")
	}
	a := stoppedProAnchor{Version: r.Version, BootID: o.BootID, Binding: b, BaselineSHA256: observationDigest(r.Baseline), OriginalReservationIdentitySHA256: r.OriginalReservationIdentitySHA256, OriginalStateSHA256: r.OriginalStateSHA256, Paths: paths}
	a.NativeScopeSHA256 = r.NativeScopeSHA256
	if r.Action == "prepare" {
		if r.Anchor != "" {
			return out, ErrNodeObservation
		}
	} else {
		original, e := o.openStoppedPro(r.Anchor)
		if e != nil || observationDigest(original) != observationDigest(a) {
			return out, observationFailure("stopped_pro_baseline_drift")
		}
	}
	out.TasksChecked, out.Files, out.ContainersChecked, out.SandboxesChecked, out.CRIObservationSHA256, e = o.stoppedProNative(ctx, a)
	if e != nil {
		return StoppedProNodeObservationResponse{}, e
	}
	if r.Action == "prepare" {
		out.Anchor, e = o.sealStoppedPro(a)
		if e != nil {
			return StoppedProNodeObservationResponse{}, e
		}
	} else {
		out.Anchor = r.Anchor
	}
	if ctx.Err() != nil || o.hostIdentity(ctx) != nil || !time.Now().Before(r.Deadline) {
		return StoppedProNodeObservationResponse{}, ErrNodeObservation
	}
	out.Version = r.Version
	out.Action = r.Action
	out.Nonce = r.Nonce
	out.RequestSHA256 = observationDigest(r)
	out.BootID = o.BootID
	out.Binding = b
	out.BaselineSHA256 = a.BaselineSHA256
	out.OriginalReservationIdentitySHA256 = r.OriginalReservationIdentitySHA256
	out.OriginalStateSHA256 = r.OriginalStateSHA256
	out.NativeScopeSHA256 = r.NativeScopeSHA256
	out.StartedAt = now
	out.FinishedAt = time.Now().UTC()
	out.ValidUntil = r.Deadline
	return out, nil
}
