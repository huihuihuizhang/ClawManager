package systembackupcontroller

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"time"

	"clawreef/internal/services"
	"clawreef/internal/systembackup/flow"
	b "clawreef/internal/systembackup/publicadapter"
	q "clawreef/internal/systembackup/quiesce"
	d "clawreef/internal/systembackupdispatch"
)

func (o *SQLRuntimeControl) sharedBookChange(ctx context.Context, a d.Authority, recovery bool, fn func(*runtimeSharedBook) error) error {
	book, previous, err := o.readSharedTaskBook(ctx, a, recovery)
	if err != nil {
		return err
	}
	if err := fn(&book); err != nil {
		return err
	}
	return o.writeSharedTaskBook(ctx, a, recovery, book, previous)
}

func (o *SQLRuntimeControl) sharedAgentCall(ctx context.Context, a d.Authority, index int, action string, recovery bool) error {
	book, _, err := o.readSharedTaskBook(ctx, a, recovery)
	if err != nil || index < 0 || index >= len(book.Actors) {
		return ErrExecutionRecord
	}
	actor := book.Actors[index]
	identity := services.RuntimeSharedBackupIdentity{Protocol: services.RuntimeSharedBackupProtocol, Namespace: actor.Group.Namespace, PodUID: actor.Group.Pod.UID, Deployment: actor.Group.Deployment, AgentEpoch: actor.Group.Capabilities.AgentEpoch, OperationID: actor.Group.OperationID, InventorySHA256: book.Definition.InventorySHA256}
	key := "agent/" + action
	if actor.Sent[key] && action != "complete" {
		action = "state"
	} else {
		if err := o.sharedBookChange(ctx, a, recovery, func(current *runtimeSharedBook) error {
			current.Actors[index].Sent[key] = true
			current.Stage = key + "-send-unknown"
			return nil
		}); err != nil {
			return err
		}
	}
	client, err := services.NewRuntimeSharedBackupCallbacks(o.cfg.Shared.Agent)
	if err != nil {
		return err
	}
	state, raw, err := client.Transition(ctx, actor.Group.Endpoint, action, identity)
	if err != nil {
		return ErrExecutionCommitUnknown
	}
	if actor.Agent != nil && state.OriginalSHA256 != actor.Agent.OriginalSHA256 {
		return ErrExecutionRecord
	}
	if key == "agent/prepare" {
		if state.Phase != "reserved" || len(state.Entries) != len(actor.Group.Members) {
			return ErrExecutionRecord
		}
		seen := map[int]bool{}
		for _, entry := range state.Entries {
			matched := false
			for _, member := range actor.Group.Members {
				r, s := member.Binding, member.Source
				if entry.InstanceID == s.ID {
					matched = entry.UserID == s.UserID && entry.RuntimeType == s.Type && entry.Generation == s.Generation && entry.OriginalState == s.Status && entry.GatewayID == r.Gateway && entry.Port == r.Port && entry.PID == r.PID
				}
			}
			if !matched || seen[entry.InstanceID] {
				return ErrExecutionRecord
			}
			seen[entry.InstanceID] = true
		}
	}
	return o.sharedBookChange(ctx, a, recovery, func(current *runtimeSharedBook) error {
		if current.Actors[index].Agent == nil {
			current.Actors[index].Agent = &state
			current.Actors[index].AgentRaw = bytes.Clone(raw)
		}
		if recovery {
			current.Actors[index].Request.Current = &state
			current.Actors[index].Request.CurrentRaw = bytes.Clone(raw)
		}
		current.Stage = key + "-observed"
		return nil
	})
}

func (o *SQLRuntimeControl) sharedNodeCall(ctx context.Context, a d.Authority, index int, action string, recovery bool) (*q.VerifiedSharedRuntimeNodeObservation, error) {
	book, _, err := o.readSharedTaskBook(ctx, a, recovery)
	if err != nil || index < 0 || index >= len(book.Actors) {
		return nil, ErrExecutionRecord
	}
	actor := book.Actors[index]
	request := actor.Request
	request.Action = action
	if action != "recovered" && action != "complete" {
		request.Current = nil
		request.CurrentRaw = nil
	}
	if recovery {
		// This is the existing actual all-readers-stopped SQL boundary, checked
		// again by Recovery.CheckTx in every original journal transaction.
		if err := o.sharedCollectorsStopped(ctx, a); err != nil {
			return nil, err
		}
		var boundary struct {
			Writers    []byte
			StoppedAt  time.Time
			Generation uint64
			Registry   string
		}
		if err := o.cfg.Gate.Authority.DB.QueryRowContext(ctx, `SELECT writers_json,collectors_stopped_at,gate_generation,registry_sha256 FROM system_backup_v2_runtime_captures WHERE task_public_id=? AND gate_generation=? AND collectors_stopped_at IS NOT NULL`, a.TaskPublicID, a.MaintenanceFencingToken).Scan(&boundary.Writers, &boundary.StoppedAt, &boundary.Generation, &boundary.Registry); err != nil {
			return nil, err
		}
		request.RecoveryBoundarySHA256 = recordHash(mustSharedJSON(boundary))
	}
	recoveryBoundary := request.RecoveryBoundarySHA256
	mutating := action == "prepare" || action == "freeze" || action == "thaw" || action == "complete"
	key := "node/" + action
	if mutating && actor.Sent[key] {
		request.Action = "state"
		request.Current = nil
		request.CurrentRaw = nil
		request.RecoveryBoundarySHA256 = ""
	} else if mutating {
		if err := o.sharedBookChange(ctx, a, recovery, func(current *runtimeSharedBook) error {
			current.Actors[index].Sent[key] = true
			current.Stage = key + "-send-unknown"
			return nil
		}); err != nil {
			return nil, err
		}
	}
	proof, _, err := o.cfg.Shared.Native.Transition(ctx, request)
	if err != nil {
		return nil, ErrExecutionCommitUnknown
	}
	if action == "complete" && request.Action == "state" && proof.Response().Phase == "completed" {
		// Readback confirmed original closure. Verify that already completed
		// record idempotently; do not create another native reservation/close.
		request = actor.Request
		request.Action = "complete"
		request.RecoveryBoundarySHA256 = recoveryBoundary
		proof, _, err = o.cfg.Shared.Native.Transition(ctx, request)
		if err != nil {
			return nil, ErrExecutionCommitUnknown
		}
	}
	response := proof.Response()
	if err := o.sharedBookChange(ctx, a, recovery, func(current *runtimeSharedBook) error {
		current.Actors[index].Last = &response
		if action == "prepare" {
			current.Actors[index].Request.Anchor = response.Anchor
		}
		if current.Stage != "all-recovered" {
			current.Stage = key + "-observed"
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return proof, nil
}

// Whole-Pod reservation/freeze is dispatched ONCE for the complete persisted
// task cohort before returning any member ACK. No original source generation,
// request or process is reconstructed or incremented.
func (o *SQLRuntimeControl) sharedPauseAll(ctx context.Context, a d.Authority) error {
	book, _, err := o.readSharedTaskBook(ctx, a, false)
	if err != nil {
		return err
	}
	if book.Stage == "all-frozen" {
		return nil
	}
	var generation, epoch uint64
	var until time.Time
	if err := o.cfg.Gate.Authority.DB.QueryRowContext(ctx, `SELECT gate_generation,acquire_token,hold_until FROM system_backup_v2_runtime_captures WHERE task_public_id=? AND gate_generation=?`, a.TaskPublicID, a.MaintenanceFencingToken).Scan(&generation, &epoch, &until); err != nil {
		return err
	}
	// Persist complete member/empty-Agent intent BEFORE the first reservation.
	if err := o.sharedBookChange(ctx, a, false, func(current *runtimeSharedBook) error { current.Stage = "all-members-pause-intent"; return nil }); err != nil {
		return err
	}
	for index := range book.Actors {
		if err := o.sharedAgentCall(ctx, a, index, "prepare", false); err != nil {
			return err
		}
		current, _, err := o.readSharedTaskBook(ctx, a, false)
		if err != nil {
			return err
		}
		actor := current.Actors[index]
		g := actor.Group
		if actor.Agent == nil {
			return ErrExecutionRecord
		}
		request := q.SharedRuntimeNodeRequest{Binding: q.ObservationBinding{Kind: q.SharedRuntimeNodeKind, InstallationID: a.InstallationID, OperationID: a.TaskPublicID, ReservationID: g.OperationID, InventorySHA256: current.Definition.InventorySHA256, Namespace: g.Namespace, NamespaceUID: o.cfg.Shared.NamespaceUID, Node: g.Pod.Node, NodeUID: g.NodeUID, Generation: generation, FenceEpoch: epoch, ExpiresAt: until}, AgentPod: g.Pod, WorkspaceRoot: g.WorkspaceRoot, AgentDataDir: g.AgentDataDir, Original: *actor.Agent, OriginalRaw: bytes.Clone(actor.AgentRaw), SourcePaths: append([]string(nil), g.Paths...)}
		if err := o.sharedBookChange(ctx, a, false, func(next *runtimeSharedBook) error {
			if next.Actors[index].Request.Anchor == "" {
				next.Actors[index].Request = request
			}
			return nil
		}); err != nil {
			return err
		}
		proof, err := o.sharedNodeCall(ctx, a, index, "prepare", false)
		if err != nil || proof.Response().Phase != "prepared" {
			return ErrExecutionRecoveryRequired
		}
	}
	if err := o.sharedBookChange(ctx, a, false, func(current *runtimeSharedBook) error {
		for i := range current.Actors {
			peers := []q.SharedRuntimeNodePeer{}
			for _, other := range current.Actors {
				if other.Group.Pod.Node == current.Actors[i].Group.Pod.Node {
					peers = append(peers, q.SharedRuntimeNodePeer{PodUID: other.Group.Pod.UID, OriginalSHA256: other.Agent.OriginalSHA256, Anchor: other.Request.Anchor})
				}
			}
			sort.Slice(peers, func(i, j int) bool { return peers[i].PodUID < peers[j].PodUID })
			current.Actors[i].Request.Peers = peers
		}
		return nil
	}); err != nil {
		return err
	}
	for index := range book.Actors {
		proof, err := o.sharedNodeCall(ctx, a, index, "freeze", false)
		if err != nil || proof.Response().Phase != "frozen" {
			return ErrExecutionRecoveryRequired
		}
	}
	return o.sharedBookChange(ctx, a, false, func(current *runtimeSharedBook) error { current.Stage = "all-frozen"; return nil })
}

type runtimeSharedHeldFrame struct {
	whole         []*q.VerifiedNodeObservation
	wholeRequests []q.NodeObservationRequest
	wholeBoot     []string
	book          runtimeSharedBook
	proofs        []*q.VerifiedSharedRuntimeNodeObservation
}

func (o *SQLRuntimeControl) sharedCheckAll(ctx context.Context, a d.Authority) (*runtimeSharedHeldFrame, error) {
	book, _, err := o.readSharedTaskBook(ctx, a, false)
	if err != nil || book.Stage == "defined" {
		return nil, ErrExecutionRecoveryRequired
	}
	frame := &runtimeSharedHeldFrame{book: book}
	for index := range book.Actors {
		proof, err := o.sharedNodeCall(ctx, a, index, "check-frozen", false)
		if err != nil || proof.Response().Action != "check-frozen" {
			return nil, ErrExecutionRecoveryRequired
		}
		frame.proofs = append(frame.proofs, proof)
	}
	if err := o.checkSharedWholeNodes(ctx, a, frame); err != nil {
		return nil, err
	}
	return frame, nil
}

func (frame *runtimeSharedHeldFrame) recheck(ctx context.Context, now time.Time) error {
	if frame == nil || len(frame.proofs) == 0 || len(frame.proofs) != len(frame.book.Actors) {
		return ErrExecutionRecoveryRequired
	}
	if len(frame.whole) == 0 || len(frame.whole) != len(frame.wholeRequests) {
		return ErrExecutionRecoveryRequired
	}
	for i, proof := range frame.whole {
		if proof.Recheck(ctx, frame.wholeRequests[i].Binding, "stopped", frame.wholeBoot[i], now) != nil {
			return ErrExecutionRecoveryRequired
		}
	}
	for i, proof := range frame.proofs {
		r := frame.book.Actors[i].Request
		if proof.Recheck(ctx, r.Binding, "check-frozen", r.Original.BootID, r.Original.OriginalSHA256, r.Anchor, q.SharedRuntimeNodeCohortSHA(r), q.SharedRuntimeNodeSourcePathsSHA(r), now) != nil {
			return ErrExecutionRecoveryRequired
		}
	}
	return nil
}

func (o *SQLRuntimeControl) sharedRestoreAll(ctx context.Context, a d.Authority) error {
	if err := o.sharedCollectorsStopped(ctx, a); err != nil {
		return err
	}
	book, _, err := o.readSharedTaskBook(ctx, a, true)
	if err != nil {
		return err
	}
	// Resolve every original send-unknown before assembling a recovery peer
	// set. A partial prepare has no freeze yet, but its real native obligations
	// must still be queried and retained before any actor is thawed.
	for i, actor := range book.Actors {
		if actor.Agent == nil && actor.Sent["agent/prepare"] {
			if o.sharedAgentCall(ctx, a, i, "prepare", true) != nil {
				return ErrExecutionRecoveryRequired
			}
		}
		if actor.Sent["node/prepare"] && actor.Request.Anchor == "" {
			if _, err := o.sharedNodeCall(ctx, a, i, "prepare", true); err != nil {
				return ErrExecutionRecoveryRequired
			}
		}
	}
	if err := o.sharedBookChange(ctx, a, true, func(current *runtimeSharedBook) error {
		for i := range current.Actors {
			if current.Actors[i].Request.Anchor == "" || len(current.Actors[i].Request.Peers) != 0 {
				continue
			}
			peers := []q.SharedRuntimeNodePeer{}
			for _, other := range current.Actors {
				if other.Request.Anchor != "" && other.Agent != nil && other.Group.Pod.Node == current.Actors[i].Group.Pod.Node {
					peers = append(peers, q.SharedRuntimeNodePeer{PodUID: other.Group.Pod.UID, OriginalSHA256: other.Agent.OriginalSHA256, Anchor: other.Request.Anchor})
				}
			}
			sort.Slice(peers, func(i, j int) bool { return peers[i].PodUID < peers[j].PodUID })
			current.Actors[i].Request.Peers = peers
		}
		return nil
	}); err != nil {
		return err
	}
	book, _, err = o.readSharedTaskBook(ctx, a, true)
	if err != nil {
		return err
	}
	failed := false
	for i, actor := range book.Actors {
		if actor.Agent == nil {
			if actor.Sent["agent/prepare"] {
				if err := o.sharedAgentCall(ctx, a, i, "prepare", true); err != nil {
					failed = true
					continue
				}
				current, _, err := o.readSharedTaskBook(ctx, a, true)
				if err != nil {
					failed = true
					continue
				}
				actor = current.Actors[i]
			} else {
				continue
			}
		}
		if actor.Sent["node/prepare"] && actor.Request.Anchor == "" {
			proof, err := o.sharedNodeCall(ctx, a, i, "prepare", true)
			if err != nil || proof.Response().Anchor == "" {
				failed = true
				continue
			}
			current, _, err := o.readSharedTaskBook(ctx, a, true)
			if err != nil {
				failed = true
				continue
			}
			actor = current.Actors[i]
		}
		if actor.Request.Anchor != "" {
			proof, err := o.sharedNodeCall(ctx, a, i, "thaw", true)
			if err != nil || (proof.Response().Phase != "thawed" && proof.Response().Phase != "recovered" && proof.Response().Phase != "completed") {
				failed = true
				continue
			}
		}
		if err := o.sharedAgentCall(ctx, a, i, "resume", true); err != nil {
			failed = true
			continue
		}
		current, _, err := o.readSharedTaskBook(ctx, a, true)
		if err != nil {
			failed = true
			continue
		}
		phase := current.Actors[i].Request.Current.Phase
		if phase == "resumed" && actor.Request.Anchor != "" {
			if proof, err := o.sharedNodeCall(ctx, a, i, "recovered", true); err != nil || proof.Response().Phase != "recovered" {
				failed = true
				continue
			}
		} else if phase != "completed" && phase != "resumed" {
			failed = true
			continue
		}
		if err := o.sharedAgentCall(ctx, a, i, "complete", true); err != nil {
			failed = true
			continue
		}
		if actor.Request.Anchor != "" {
			if proof, err := o.sharedNodeCall(ctx, a, i, "complete", true); err != nil || proof.Response().Phase != "completed" {
				failed = true
				continue
			}
		}
	}
	if failed {
		return ErrExecutionRecoveryRequired
	}
	if err := o.sharedBookChange(ctx, a, true, func(current *runtimeSharedBook) error { current.Stage = "all-recovered"; return nil }); err != nil {
		return err
	}
	return o.completeSharedRuntimeControls(ctx, a)
}

// Read ONLY the actual boundary written by the existing Job/collector owner.
// A Runtime callback cannot manufacture collectors_stopped_at itself.
func (o *SQLRuntimeControl) sharedCollectorsStopped(ctx context.Context, a d.Authority) error {
	if err := o.cfg.Gate.Recovery.Check(ctx, a); err != nil {
		return err
	}
	var stopped sql.NullTime
	var unresolved int
	err := o.cfg.Gate.Authority.DB.QueryRowContext(ctx, `SELECT collectors_stopped_at,(SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND create_dispatched=TRUE AND (stopped_at IS NULL OR revoked=FALSE)) FROM system_backup_v2_runtime_captures WHERE task_public_id=? AND gate_generation=?`, a.TaskPublicID, a.TaskPublicID, a.MaintenanceFencingToken).Scan(&stopped, &unresolved)
	if err != nil || !stopped.Valid || unresolved != 0 {
		return ErrExecutionRecoveryRequired
	}
	return nil
}

func (o *SQLRuntimeControl) completeSharedRuntimeControls(ctx context.Context, a d.Authority) error {
	book, _, err := o.readSharedTaskBook(ctx, a, true)
	if err != nil || book.Stage != "all-recovered" {
		return ErrExecutionRecoveryRequired
	}
	return o.transaction(ctx, a, true, func(tx *sql.Tx) error {
		for _, source := range book.Definition.Sources {
			if source.Mode != "lite" {
				continue
			}
			current, err := sourceRow(ctx, tx, source.ID)
			if err != nil || current != source {
				return ErrExecutionRecord
			}
		}
		rows, err := tx.QueryContext(ctx, `SELECT writer_id,spec_json FROM system_backup_v2_runtime_controls WHERE task_public_id=? AND attempt_no=? FOR UPDATE`, a.TaskPublicID, a.AttemptNo)
		if err != nil {
			return err
		}
		var ids []string
		for rows.Next() {
			var id string
			var raw []byte
			var spec b.RuntimeWriterSpec
			if rows.Scan(&id, &raw) != nil || json.Unmarshal(raw, &spec) != nil {
				rows.Close()
				return ErrExecutionRecord
			}
			if spec.Kind == "shared" {
				ids = append(ids, id)
			}
		}
		if rows.Err() != nil || rows.Close() != nil {
			return ErrExecutionRecord
		}
		for _, id := range ids {
			if _, err := tx.ExecContext(ctx, `UPDATE system_backup_v2_runtime_controls SET restart_completed=TRUE,resumed_json=?,row_version=row_version+1 WHERE task_public_id=? AND attempt_no=? AND writer_id=?`, mustSharedJSON(book), a.TaskPublicID, a.AttemptNo, id); err != nil {
				return err
			}
		}
		return nil
	})
}

// These writers are created by the REAL RuntimeControl.BuildWriters shared
// branch. Every member keeps its own original source state; all callbacks use
// one persisted complete physical cohort, including empty-manager Agents.
type sharedTaskWriter struct {
	owner     *SQLRuntimeControl
	authority d.Authority
	id        string
	original  flow.State
}

func (w *sharedTaskWriter) ID() string { return w.id }
func (w *sharedTaskWriter) Observe(ctx context.Context) (flow.State, error) {
	if err := w.owner.cfg.Gate.Check(ctx, w.authority); err != nil {
		return flow.State{}, err
	}
	return w.original, nil
}
func (w *sharedTaskWriter) Pause(ctx context.Context, s flow.State) (flow.ACK, error) {
	if s != w.original {
		return flow.ACK{}, ErrExecutionRecord
	}
	if err := w.owner.sharedPauseAll(ctx, w.authority); err != nil {
		return flow.ACK{}, err
	}
	return flow.ACK{UID: s.UID, Generation: s.Generation, Stopped: true}, nil
}
func (w *sharedTaskWriter) CheckPaused(ctx context.Context, s flow.State) error {
	if s != w.original {
		return ErrExecutionRecord
	}
	frame, err := w.owner.sharedCheckAll(ctx, w.authority)
	if err != nil {
		return err
	}
	return frame.recheck(ctx, time.Now().UTC())
}
func (w *sharedTaskWriter) Resume(ctx context.Context, s flow.State) error {
	if s != w.original || w.owner.cfg.Gate.CheckRecovery(ctx, w.authority, w.id, d.WriterState(s)) != nil {
		return ErrExecutionRecoveryRequired
	}
	return w.owner.sharedRestoreAll(ctx, w.authority)
}

func (o *SQLRuntimeControl) buildSharedTaskWriters(ctx context.Context, in d.Input, inv b.SourceInventory, frozen []b.FrozenWriter) ([]flow.Writer, error) {
	var specs []b.RuntimeWriterSpec
	read := func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT spec_json FROM system_backup_v2_runtime_controls WHERE task_public_id=? AND attempt_no=? ORDER BY instance_id`, in.Authority.TaskPublicID, in.Authority.AttemptNo)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			var spec b.RuntimeWriterSpec
			if rows.Scan(&raw) != nil || json.Unmarshal(raw, &spec) != nil {
				return ErrExecutionRecord
			}
			specs = append(specs, spec)
		}
		return rows.Err()
	}
	err := o.transaction(ctx, in.Authority, false, read)
	if err != nil && frozen != nil {
		specs = nil
		err = o.transaction(ctx, in.Authority, true, read)
	}
	if err != nil {
		return nil, err
	}
	if len(specs) == 0 && frozen == nil {
		specs, err = o.Prepare(ctx, in.Authority)
		if err != nil {
			return nil, err
		}
	}
	if len(specs) != len(inv.Instances) {
		return nil, ErrExecutionRecord
	}
	actual := map[int]b.InstanceIdentity{}
	for _, s := range inv.Instances {
		actual[s.ID] = s
	}
	var legacy []b.RuntimeWriterSpec
	var writers []flow.Writer
	var legacyInv = b.SourceInventory{Database: inv.Database, ServerUUID: inv.ServerUUID, Users: inv.Users}
	for _, spec := range specs {
		if actual[spec.Source.ID] != spec.Source {
			return nil, ErrExecutionRecord
		}
		if spec.Kind == "shared" {
			writers = append(writers, &sharedTaskWriter{o, in.Authority, runtimeWriterID(spec), spec.Stopped})
		} else {
			legacy = append(legacy, spec)
			legacyInv.Instances = append(legacyInv.Instances, spec.Source)
		}
	}
	book, _, err := o.readSharedTaskBook(ctx, in.Authority, frozen != nil)
	if err != nil {
		return nil, err
	}
	copyOwner := *o
	copyOwner.cfg = o.cfg
	for _, g := range book.Definition.Groups {
		if len(g.Members) == 0 {
			id := "shared-agent/" + g.Key
			state := flow.State{UID: g.Key, Generation: g.Generation, Running: true, Checkpoint: recordHash(mustSharedJSON(g))}
			writers = append(writers, &sharedTaskWriter{o, in.Authority, id, state})
			copyOwner.cfg.AdditionalWriterIDs = append(append([]string{}, copyOwner.cfg.AdditionalWriterIDs...), id)
		}
	}
	for _, spec := range specs {
		if spec.Kind == "shared" {
			copyOwner.cfg.AdditionalWriterIDs = append(append([]string{}, copyOwner.cfg.AdditionalWriterIDs...), runtimeWriterID(spec))
		}
	}
	deps, err := copyOwner.Dependencies(ctx, in.Authority, legacy)
	if err != nil {
		return nil, err
	}
	builder, err := b.NewRuntimeWriterBuilder(legacy, deps)
	if err != nil {
		return nil, err
	}
	var legacyFrozen []b.FrozenWriter
	if frozen != nil {
		legacyFrozen = []b.FrozenWriter{}
		ids := map[string]bool{}
		for _, w := range writers {
			ids[w.ID()] = true
		}
		for _, w := range frozen {
			if !ids[w.ID] {
				legacyFrozen = append(legacyFrozen, w)
			}
		}
	}
	old, err := builder(ctx, in, legacyInv, legacyFrozen)
	if err != nil {
		return nil, err
	}
	writers = append(old, writers...)
	if frozen != nil {
		if len(frozen) != len(writers) {
			return nil, ErrExecutionRecord
		}
		ids := map[string]bool{}
		for _, w := range writers {
			ids[w.ID()] = true
		}
		for _, w := range frozen {
			if !ids[w.ID] {
				return nil, ErrExecutionRecord
			}
			delete(ids, w.ID)
		}
	}
	return writers, nil
}
