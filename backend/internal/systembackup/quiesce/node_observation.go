package quiesce

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"reflect"
	"sort"
	"strings"
	"time"
)

var ErrNodeObservation = errors.New("node observation unavailable or inconclusive")

type NodeObservationFailure struct{ Stage string }

func (e NodeObservationFailure) Error() string { return "node observation inconclusive: " + e.Stage }
func (e NodeObservationFailure) Unwrap() error { return ErrNodeObservation }
func observationFailure(stage string) error    { return NodeObservationFailure{Stage: stage} }

const NodeObservationWholePodColdCut = "whole_pod_cold_cut"

// ObservationBinding is an exact reference to A/D's EXISTING reservation. The
// observer neither creates that reservation nor attests that it is still held.
// Its consumer must authenticate the complete census and check the original
// shared lock, all admission paths and the recovery authority independently.
type ObservationBinding struct {
	Kind                                                        string
	InstallationID, OperationID, ReservationID, InventorySHA256 string
	Namespace, NamespaceUID, Node, NodeUID                      string
	// FenceEpoch is the exact original acquisition epoch, including legal zero.
	// Current held-gate ownership is independently verified by D.
	Generation, FenceEpoch uint64
	ExpiresAt              time.Time
}

type NodeObservationRequest struct {
	Version, Action, Nonce string
	// For whole_pod_cold_cut, Binding.Generation is D's ORIGINAL SQL gate
	// generation. It is not a Deployment, Pod or Agent successor generation.
	Binding     ObservationBinding
	Deadline    time.Time
	Pods        []PodIdentity
	SourcePaths []string
	Anchor      string
	// RecoveredPods are the actual replacement identities from D's original
	// recovery ledger. Observing them does not authorize or perform a restart.
	RecoveredPods []PodIdentity
	// On recovered only, repeat the original SQL gate generation exactly.
	// D separately authenticates the actual source recovery and journal.
	RecoveredGeneration uint64
	// Complete current API membership is explicit (including a proved empty
	// collection) in the two scoped reconciliation phases.
	RecoveryAffectedPods   []PodIdentity `json:",omitempty"`
	RecoverySnapshotSHA256 string        `json:",omitempty"`
}

type NodeObservationResponse struct {
	Version, Action, Nonce, RequestSHA256, Anchor string
	Binding                                       ObservationBinding
	BootID                                        string
	StartedAt, FinishedAt, ValidUntil             time.Time
	Processes, Files, TasksChecked                int
	// Facts describe a bounded observation only, never a durable writer fence.
	Facts []string
}

type observedProcess struct {
	PID                                  int
	Start                                string
	PIDNamespace, MountNamespace, Cgroup string
}
type observedPath struct {
	Path          string
	Device, Inode uint64
	Mount         string
}
type nodeObservationAnchor struct {
	Binding    ObservationBinding
	Pods       []PodIdentity
	Paths      []observedPath
	Processes  []observedProcess
	BootID     string
	PreparedAt time.Time
}

// NodeObserver has no lifecycle, mutation, reservation or permissive proof
// callback. CRICommand is the concrete, deployment-pinned native reader.
type NodeObserver struct {
	Node, NodeUID, MachineID, BootID string
	HostRoot, HostProc               string
	CRI                              CRICommand
	key                              []byte
}

func NewNodeObserver(node, uid, machine, boot, root, proc string, cri CRICommand, key []byte) (*NodeObserver, error) {
	if node == "" || uid == "" || machine == "" || boot == "" || !absoluteObservationPath(root) || !absoluteObservationPath(proc) || len(key) != 32 || !absoluteObservationPath(cri.Binary) || !strings.HasPrefix(cri.Endpoint, "unix:///") {
		return nil, ErrNodeObservation
	}
	return &NodeObserver{Node: node, NodeUID: uid, MachineID: machine, BootID: boot, HostRoot: root, HostProc: proc, CRI: cri, key: append([]byte(nil), key...)}, nil
}

func absoluteObservationPath(p string) bool {
	return strings.HasPrefix(p, "/") && path.Clean(p) == p && !strings.ContainsAny(p, "\x00\r\n\\")
}
func observationDigest(v any) string {
	b, _ := json.Marshal(v)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
func validObservationHash(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && strings.ToLower(s) == s
}
func (o *NodeObserver) seal(a nodeObservationAnchor) (string, error) {
	b, e := json.Marshal(a)
	if e != nil || len(b) > 192<<10 {
		return "", ErrNodeObservation
	}
	h := hmac.New(sha256.New, o.key)
	h.Write(b)
	return base64.RawURLEncoding.EncodeToString(b) + "." + hex.EncodeToString(h.Sum(nil)), nil
}
func (o *NodeObserver) open(token string) (nodeObservationAnchor, error) {
	var a nodeObservationAnchor
	p := strings.Split(token, ".")
	if len(p) != 2 || len(token) > 256<<10 {
		return a, ErrNodeObservation
	}
	b, e := base64.RawURLEncoding.DecodeString(p[0])
	if e != nil {
		return a, ErrNodeObservation
	}
	s, e := hex.DecodeString(p[1])
	if e != nil {
		return a, ErrNodeObservation
	}
	h := hmac.New(sha256.New, o.key)
	h.Write(b)
	if !hmac.Equal(s, h.Sum(nil)) || json.Unmarshal(b, &a) != nil {
		return a, ErrNodeObservation
	}
	return a, nil
}
func validObservationPods(pods []PodIdentity, node string) bool {
	if len(pods) == 0 || len(pods) > 128 {
		return false
	}
	seen := map[string]bool{}
	for _, p := range pods {
		if p.Node != node || p.Name == "" || p.UID == "" || len(p.Containers) == 0 || len(p.Containers) > 64 || seen["pod:"+p.UID] {
			return false
		}
		seen["pod:"+p.UID] = true
		for _, c := range p.Containers {
			x := strings.Split(c, "://")
			if len(x) != 2 || (x[0] != "containerd" && x[0] != "cri-o") || !criID.MatchString(x[1]) || seen[c] {
				return false
			}
			seen[c] = true
		}
	}
	return true
}
func (o *NodeObserver) Observe(ctx context.Context, r NodeObservationRequest) (NodeObservationResponse, error) {
	var result NodeObservationResponse
	now := time.Now().UTC()
	b := r.Binding
	deadline, ok := ctx.Deadline()
	if o == nil || len(o.key) != 32 || !ok || ctx.Err() != nil || b.Kind != NodeObservationWholePodColdCut || r.Version != "node-observation.v1" || !validObservationHash(r.Nonce) || b.Node != o.Node || b.NodeUID != o.NodeUID || b.InstallationID == "" || b.OperationID == "" || b.ReservationID == "" || b.Namespace == "" || b.NamespaceUID == "" || b.Generation == 0 || b.ExpiresAt.IsZero() || !validObservationHash(b.InventorySHA256) || !now.Before(r.Deadline) || r.Deadline.After(now.Add(15*time.Second)) || deadline.After(r.Deadline) || (!nodeObservationRecoveryAction(r.Action) && !r.Deadline.Before(b.ExpiresAt)) || !validObservationPods(r.Pods, o.Node) {
		return result, ErrNodeObservation
	}
	if !nodeObservationPhaseDataValid(r, o.Node) {
		return result, ErrNodeObservation
	}
	if e := o.hostIdentity(ctx); e != nil {
		return result, observationFailure("host_visibility")
	}
	var a nodeObservationAnchor
	var err error
	switch r.Action {
	case "prepare":
		if r.Anchor != "" || len(r.SourcePaths) == 0 || len(r.SourcePaths) > 128 || len(r.RecoveredPods) != 0 || r.RecoveredGeneration != 0 {
			return result, ErrNodeObservation
		}
		sorted := append([]string(nil), r.SourcePaths...)
		sort.Strings(sorted)
		for i, p := range sorted {
			if !absoluteObservationPath(p) || p == "/" || (i > 0 && (p == sorted[i-1] || strings.HasPrefix(p, sorted[i-1]+"/"))) {
				return result, ErrNodeObservation
			}
		}
		a = nodeObservationAnchor{Binding: b, Pods: r.Pods, BootID: o.BootID, PreparedAt: now}
		a.Paths, err = o.paths(ctx, sorted)
		if err != nil {
			return result, observationFailure("source_mount")
		}
		a.Processes, err = o.running(ctx, b, r.Pods, a.Paths)
		if err != nil {
			return result, observationFailure("original_cri_process")
		}
		a.Processes, err = o.originalScopes(ctx, a)
		if err != nil {
			return result, observationFailure("original_scope")
		}
		if len(a.Processes) == 0 {
			return result, ErrNodeObservation
		}
		r.Anchor, err = o.seal(a)
		if err != nil {
			return result, err
		}
		result.Facts = []string{"original_running_cri_processes_observed", "source_mount_identities_observed"}
	case "recovery-source-stopped", "recovery-reconciled":
		a, err = o.originalNodeObservationAnchor(r, now)
		if err != nil {
			return result, ErrNodeObservation
		}
		var reconciled originalRecoveryNativeResult
		reconciled, err = o.reconcileOriginalRecovery(ctx, r, a)
		if err != nil {
			return NodeObservationResponse{}, err
		}
		result.Processes = reconciled.Processes
		result.TasksChecked = reconciled.Tasks
		result.Files = reconciled.Files
		result.Facts = originalRecoveryFacts(r.Action)
	case "stopped", "recovery-stopped", "recovered":
		if len(r.SourcePaths) != 0 {
			return result, ErrNodeObservation
		}
		a, err = o.originalNodeObservationAnchor(r, now)
		if err != nil {
			return result, ErrNodeObservation
		}
		p := make([]string, len(a.Paths))
		for i, x := range a.Paths {
			p[i] = x.Path
		}
		current, e := o.paths(ctx, p)
		if e != nil || !reflect.DeepEqual(current, a.Paths) {
			return result, ErrNodeObservation
		}
		if (CRIProver{Node: o.Node, Inspector: o.CRI}).Confirm(ctx, a.Pods) != nil {
			return result, observationFailure("original_cri_exit")
		}
		if r.Action == "stopped" || r.Action == "recovery-stopped" {
			if len(r.RecoveredPods) != 0 || r.RecoveredGeneration != 0 {
				return result, ErrNodeObservation
			}
			result.TasksChecked, result.Files, err = o.stopped(ctx, a)
			result.Facts = []string{"original_cri_containers_exited", "original_process_scopes_absent", "no_observed_writable_source_fd_or_shared_mmap", "source_mount_identities_unchanged"}
		} else {
			if r.RecoveredGeneration != b.Generation || !validObservationPods(r.RecoveredPods, o.Node) {
				return result, ErrNodeObservation
			}
			for _, old := range a.Pods {
				for _, next := range r.RecoveredPods {
					if old.UID == next.UID {
						return result, ErrNodeObservation
					}
				}
			}
			var recovered []observedProcess
			recovered, err = o.running(ctx, b, r.RecoveredPods, a.Paths)
			result.Processes = len(recovered)
			// Original scope absence remains required during recovery; writable
			// handles of the newly running writers are expected at this phase.
			if err == nil {
				result.TasksChecked, _, err = o.scan(ctx, a, nil)
			}
			result.Facts = []string{"original_cri_containers_exited", "original_process_scopes_absent", "replacement_cri_processes_running", "source_mount_identities_unchanged"}
		}
		if err != nil {
			return NodeObservationResponse{}, err
		}
	default:
		return result, ErrNodeObservation
	}
	if ctx.Err() != nil || o.hostIdentity(ctx) != nil || !time.Now().Before(r.Deadline) {
		return NodeObservationResponse{}, ErrNodeObservation
	}
	// Request digest always covers the caller's original bytes-as-typed, whose
	// prepare Anchor was empty. The returned token is a separate observation.
	requestForHash := r
	if r.Action == "prepare" {
		requestForHash.Anchor = ""
	}
	result.Version = r.Version
	result.Action = r.Action
	result.Nonce = r.Nonce
	result.RequestSHA256 = observationDigest(requestForHash)
	result.Anchor = r.Anchor
	result.Binding = b
	result.BootID = o.BootID
	result.StartedAt = now
	result.FinishedAt = time.Now().UTC()
	result.ValidUntil = r.Deadline
	if r.Action == "prepare" {
		result.Processes = len(a.Processes)
	}
	return result, nil
}
