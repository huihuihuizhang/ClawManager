package systembackupcontroller

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"time"

	b "clawreef/internal/systembackup/publicadapter"
	q "clawreef/internal/systembackup/quiesce"
	d "clawreef/internal/systembackupdispatch"
)

type runtimeSharedWholeNode struct {
	Request  q.NodeObservationRequest
	Prepared q.NodeObservationResponse
}

// First original PauseIntent has committed, and NO physical writer has yet
// paused. Pin genuine cold Pod scopes while they still run. Shared Agent Pods
// are deliberately excluded: their complete exact-container scope is supplied
// later through native SharedFrozenScopes, never through cold absence claims.
func (o *SQLRuntimeControl) prepareSharedWholeNodes(ctx context.Context, a d.Authority) error {
	book, _, err := o.readSharedTaskBook(ctx, a, false)
	if err != nil {
		return err
	}
	if len(book.Nodes) != 0 {
		if len(book.Nodes) != len(o.cfg.Shared.Nodes) {
			return ErrExecutionRecoveryRequired
		}
		return nil
	}
	if o.cfg.Shared.WholeNode == nil {
		return ErrExecutionRecoveryRequired
	}
	var raw []byte
	var generation, epoch uint64
	var until time.Time
	if o.cfg.Gate.Authority.DB.QueryRowContext(ctx, `SELECT writers_json,gate_generation,acquire_token,hold_until FROM system_backup_v2_runtime_captures WHERE task_public_id=? AND gate_generation=?`, a.TaskPublicID, a.MaintenanceFencingToken).Scan(&raw, &generation, &epoch, &until) != nil {
		return ErrExecutionRecord
	}
	var writers []b.FrozenWriter
	if json.Unmarshal(raw, &writers) != nil {
		return ErrExecutionRecord
	}
	sharedIDs := map[string]bool{}
	for _, source := range book.Definition.Sources {
		if source.Mode != "lite" {
			continue
		}
		uid := "unbound"
		for _, g := range book.Definition.Groups {
			for _, m := range g.Members {
				if m.Source.ID == source.ID {
					uid = g.Key
				}
			}
		}
		sharedIDs[sharedRuntimeWriterID(b.RuntimeWriterSpec{UID: uid, Source: source})] = true
	}
	for _, g := range book.Definition.Groups {
		if len(g.Members) == 0 {
			sharedIDs["shared-agent/"+g.Key] = true
		}
	}
	pods := map[string][]q.PodIdentity{}
	for _, writer := range writers {
		if sharedIDs[writer.ID] || o.cfg.ParticipantChecks[writer.ID] != nil || !writer.Original.Running {
			continue
		}
		var checkpoint struct {
			Namespace string
			Process   q.PodIdentity
			Pods      []q.PodIdentity
		}
		if json.Unmarshal([]byte(writer.Original.Checkpoint), &checkpoint) != nil || checkpoint.Namespace != o.cfg.Namespace {
			return ErrExecutionRecord
		}
		actual := checkpoint.Pods
		if checkpoint.Process.UID != "" {
			actual = []q.PodIdentity{checkpoint.Process}
		}
		if len(actual) == 0 {
			return ErrExecutionRecord
		}
		for _, pod := range actual {
			if pod.Node == "" || len(pod.Containers) == 0 {
				return ErrExecutionRecord
			}
			pods[pod.Node] = append(pods[pod.Node], pod)
		}
	}
	for _, node := range o.cfg.Shared.Nodes {
		cold := pods[node.Name]
		// The existing prepare profile requires a positive cold set. Do not
		// replace this with a shared Pod or a made-up originally-empty proof.
		if len(cold) == 0 {
			return ErrExecutionRecoveryRequired
		}
		sort.Slice(cold, func(i, j int) bool { return cold[i].UID < cold[j].UID })
		for i := 1; i < len(cold); i++ {
			if cold[i].UID == cold[i-1].UID {
				return ErrExecutionRecord
			}
		}
		reservation := recordHash(mustSharedJSON([]string{q.NodeObservationWholePodColdCut, a.InstallationID, a.TaskPublicID, strconv.FormatUint(a.AttemptNo, 10), node.UID, book.Definition.InventorySHA256}))[:32]
		r := q.NodeObservationRequest{Action: "prepare", Binding: q.ObservationBinding{Kind: q.NodeObservationWholePodColdCut, InstallationID: a.InstallationID, OperationID: a.TaskPublicID, ReservationID: reservation, InventorySHA256: book.Definition.InventorySHA256, Namespace: o.cfg.Namespace, NamespaceUID: o.cfg.Shared.NamespaceUID, Node: node.Name, NodeUID: node.UID, Generation: generation, FenceEpoch: epoch, ExpiresAt: until}, Pods: cold, SourcePaths: append([]string(nil), node.Paths...)}
		proof, err := o.cfg.Shared.WholeNode.ObserveVerified(ctx, r)
		if err != nil {
			return err
		}
		response := proof.Response()
		r.Anchor = response.Anchor
		if err := o.sharedBookChange(ctx, a, false, func(current *runtimeSharedBook) error {
			current.Nodes = append(current.Nodes, runtimeSharedWholeNode{Request: r, Prepared: response})
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

// Lifecycle checks finish first. The existing readonly observer independently
// opens the same actual native owner anchors, checks complete peers and scans
// the whole host before any shared writer exemption is accepted.
func (o *SQLRuntimeControl) checkSharedWholeNodes(ctx context.Context, a d.Authority, frame *runtimeSharedHeldFrame) error {
	book, _, err := o.readSharedTaskBook(ctx, a, false)
	if err != nil || len(book.Nodes) != len(o.cfg.Shared.Nodes) {
		return ErrExecutionRecoveryRequired
	}
	for _, node := range book.Nodes {
		r := node.Request
		r.Action = "stopped"
		r.SourcePaths = nil
		r.SharedFrozenScopes = []q.SharedRuntimeFrozenScope{}
		for _, proof := range frame.proofs {
			scope, err := proof.FrozenScope()
			if err != nil {
				return err
			}
			if scope.Binding.Node == r.Binding.Node {
				r.SharedFrozenScopes = append(r.SharedFrozenScopes, scope)
			}
		}
		sort.Slice(r.SharedFrozenScopes, func(i, j int) bool {
			return r.SharedFrozenScopes[i].AgentPod.UID < r.SharedFrozenScopes[j].AgentPod.UID
		})
		if len(r.SharedFrozenScopes) == 0 {
			return ErrExecutionRecoveryRequired
		}
		proof, err := o.cfg.Shared.WholeNode.ObserveVerified(ctx, r)
		if err != nil {
			return err
		}
		frame.whole = append(frame.whole, proof)
		frame.wholeRequests = append(frame.wholeRequests, r)
		frame.wholeBoot = append(frame.wholeBoot, node.Prepared.BootID)
	}
	return nil
}
