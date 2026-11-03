package install

import (
	"context"
	"reflect"

	q "clawreef/internal/systembackup/quiesce"
)

// These are the actual source-side dispatch intents in the original actors.
// All are durable BEFORE dispatch; control/gate transitions are not silently
// counted as source mutations. New source operations must join this closed set.
func originalSourceMutationIntent(action string) bool {
	switch action {
	case "scale_zero_send_unknown", "restore_replicas_send_unknown",
		"delete_original_pod_send_unknown", "create_original_pod_send_unknown",
		"cancel_delayed_pod_delete_send_unknown", "stop_send_unknown",
		"resume_send_unknown", "complete_send_unknown", "keep_stopped_complete_send_unknown",
		"source_binding_commit_unknown":
		return true
	}
	return false
}

type originalRecoveryMutationBoundary struct {
	journal                       *originalWriterJournal
	epoch, sequence, lastMutation uint64
	tail                          string
}

// Called under the genuine set mutex after every restore callback returned.
// Inspect verifies the actual custody files, not an in-memory declared hash.
// While closed, appendReceipt refuses every source-side dispatch intent. Old
// capture is already permanently invalidated by the fresh A authorization.
func (j *originalWriterJournal) closeOriginalSourceMutations(ctx context.Context) (*originalRecoveryMutationBoundary, error) {
	if j == nil {
		return nil, ErrInstall
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed || j.root == nil {
		return nil, ErrInstall
	}
	observed, err := j.inspect(ctx, j.operation, j.inventory)
	if err != nil || observed.TailSHA256 != j.tail || uint64(len(observed.Records)) != j.sequence {
		return nil, ErrInstall
	}
	var last uint64
	for _, record := range observed.Records {
		if originalSourceMutationIntent(record.Action) {
			last = record.Sequence
		}
	}
	if last != j.lastSourceMutation {
		return nil, ErrInstall
	}
	// Repeating final read-only observations after a short native window expires
	// keeps source mutation permanently closed; it never repeats restore sends.
	if !j.recoveryClosed {
		j.recoveryBoundary++
	}
	j.recoveryClosed = true
	return &originalRecoveryMutationBoundary{j, j.recoveryBoundary, j.sequence, last, j.tail}, nil
}

func (j *originalWriterJournal) originalSourceMutationsClosed() bool {
	if j == nil {
		return false
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.recoveryClosed
}

func (b *originalRecoveryMutationBoundary) recheckLocal() error {
	if b == nil || b.journal == nil {
		return ErrInstall
	}
	j := b.journal
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed || !j.recoveryClosed || b.epoch != j.recoveryBoundary || b.lastMutation != j.lastSourceMutation || b.sequence > j.sequence || !digestPattern.MatchString(b.tail) {
		return ErrInstall
	}
	return nil
}

type originalRecoveryMutationFact struct {
	Sequence                   uint64
	Writer, Action, DataSHA256 string
}

type originalRecoveryFactsRecord struct {
	Version, Operation, InventorySHA256, JournalPrefixSHA256 string
	JournalPrefixSequence, LastSourceMutationSequence        uint64
	ClosedMutationEpoch                                      uint64
	Binding                                                  q.ObservationBinding
	AnchorSHA256                                             string
	Original, Affected, Current                              []q.PodIdentity
	Peers                                                    []originalRecoveryPeerPin
	Mutations                                                []originalRecoveryMutationFact
}

// Private proof bookkeeping retains the exact original request and real peer
// observations. This struct cannot be supplied through a public DTO/caller.
type originalRecoveryNodeFacts struct {
	set      *PreparedOriginalWriterSet
	node     *originalWholeNodeScope
	boundary *originalRecoveryMutationBoundary
	peers    originalRecoveryPeerSnapshot
	request  q.NodeObservationRequest
	sequence uint64
	sha256   string
}

func (s *PreparedOriginalWriterSet) persistOriginalRecoveryFacts(ctx context.Context, node *originalWholeNodeScope, request q.NodeObservationRequest, peers originalRecoveryPeerSnapshot, boundary *originalRecoveryMutationBoundary) (*originalRecoveryNodeFacts, error) {
	if s == nil || s.origin != s || node == nil || node.set != s || node.prepare == nil || request.Binding != node.request.Binding || request.Anchor != node.prepare.Response().Anchor || request.RecoveredGeneration != s.owner.token.Generation || !reflect.DeepEqual(request.RecoveredPods, peers.Pods) || request.RecoverySnapshotSHA256 != "" {
		return nil, ErrInstall
	}
	if request.Action != "recovery-source-stopped" && request.Action != "recovery-reconciled" {
		return nil, ErrInstall
	}
	if request.Action == "recovery-reconciled" && (boundary == nil || boundary.recheckLocal() != nil) {
		return nil, ErrInstall
	}
	j := s.journal
	j.mu.Lock()
	observed, err := j.inspect(ctx, j.operation, j.inventory)
	if err != nil || observed.TailSHA256 != j.tail || uint64(len(observed.Records)) != j.sequence {
		j.mu.Unlock()
		return nil, ErrInstall
	}
	mutations := []originalRecoveryMutationFact{}
	var last uint64
	for _, record := range observed.Records {
		if originalSourceMutationIntent(record.Action) {
			last = record.Sequence
			mutations = append(mutations, originalRecoveryMutationFact{record.Sequence, record.Writer, record.Action, hash(record.Data)})
		}
	}
	j.mu.Unlock()
	record := originalRecoveryFactsRecord{
		Version: "original-recovery-native-facts.v1", Operation: s.owner.operation, InventorySHA256: s.inventorySHA,
		JournalPrefixSHA256: observed.TailSHA256, JournalPrefixSequence: uint64(len(observed.Records)), LastSourceMutationSequence: last,
		Binding: request.Binding, AnchorSHA256: hash([]byte(request.Anchor)), Original: request.Pods, Affected: request.RecoveryAffectedPods,
		Current: peers.Pods, Peers: peers.Pins, Mutations: mutations,
	}
	if boundary != nil {
		if boundary.recheckLocal() != nil || last != boundary.lastMutation {
			return nil, ErrInstall
		}
		record.ClosedMutationEpoch = boundary.epoch
	}
	sequence, digest, err := j.appendReceipt(ctx, node.claim.WriterID, "original_recovery_native_facts", nil, record)
	if err != nil || !digestPattern.MatchString(digest) {
		return nil, ErrInstall
	}
	request.RecoverySnapshotSHA256 = digest
	return &originalRecoveryNodeFacts{s, node, boundary, peers, request, sequence, digest}, nil
}

// SQL final release invokes this only under set.mu. There is no filesystem,
// API or native I/O here, and no new current source assertion is manufactured.
func (f *originalRecoveryNodeFacts) recheckLocal(boundary *originalRecoveryMutationBoundary, request q.NodeObservationRequest) error {
	if f == nil || f.set == nil || f.node == nil || f.node.set != f.set || f.boundary != boundary || boundary == nil || boundary.journal != f.set.journal || boundary.recheckLocal() != nil || f.sequence <= boundary.sequence || f.sha256 != request.RecoverySnapshotSHA256 || !reflect.DeepEqual(f.request, request) {
		return ErrInstall
	}
	return nil
}
