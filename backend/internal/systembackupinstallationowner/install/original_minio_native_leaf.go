package install

import (
	"context"
	"encoding/json"
	"time"

	sb "clawreef/internal/systembackup"
	c "clawreef/internal/systembackupcontroller"
)

// These leaf callers are invoked UNDER the existing original set mutex by
// D's shared factory/hold/recovery dispatcher. They do not acquire that mutex
// again, construct a replacement set, or release either global admission.
// Material pins and selected output accounts are original private inputs;
// only the real C gate supplies native observations and recovery proof.
func (s *PreparedOriginalWriterSet) originalMinIOMember(ctx context.Context, w *originalDeploymentMaintenance, material BootstrapSourceFilePin) error {
	if s == nil || s.origin != s || w == nil || w.owner != s.owner || w.journal != s.journal || s.journal == nil || w.replicas != 1 || len(w.pods) != 1 {
		return ErrInstall
	}
	found := false
	for _, member := range s.deployments {
		if member == w {
			found = true
		}
	}
	if !found {
		return ErrInstall
	}
	raw, e := readBootstrapSourcePin(material, 262144)
	var coordinates struct{ Native sb.MinIOReadGateInput }
	// Full closed material/credential parsing is independently performed by C's
	// actual loader. This projection only binds its genuine native Pod to this
	// genuine original Deployment member; it grants no held status.
	if e != nil || json.Unmarshal(raw, &coordinates) != nil || coordinates.Native.Namespace != w.namespace || coordinates.Native.NamespaceUID != s.initial.NamespaceUID || coordinates.Native.Pod != w.pods[0].Name || coordinates.Native.PodUID != w.pods[0].UID {
		return ErrInstall
	}
	d, e := w.current(ctx)
	if e != nil || d.Spec.Replicas == nil || *d.Spec.Replicas != w.replicas || d.Status.ReadyReplicas != w.replicas || d.Status.ObservedGeneration < d.Generation {
		return ErrInstall
	}
	pods, e := w.currentPods(ctx, d, true)
	if e != nil || len(pods) != 1 || originalObjectSHA(pods) != originalObjectSHA(w.pods) {
		return ErrInstall
	}
	return nil
}

func (s *PreparedOriginalWriterSet) prepareOriginalMinIOReadService(ctx context.Context, w *originalDeploymentMaintenance, material BootstrapSourceFilePin, outputs []string) (*sb.MinIOReadServiceGate, error) {
	if s.originalMinIOMember(ctx, w, material) != nil || s.used || s.owner.check(ctx) != nil {
		return nil, ErrInstall
	}
	check := func(actual context.Context) error {
		if !consumerSameContext(actual, s.owner.ctx) || s.owner.check(actual) != nil {
			return ErrInstall
		}
		if s.used && s.originalMinIOPhysicalPeersClosed(actual) != nil {
			return ErrInstall
		}
		return s.originalMinIOMember(actual, w, material)
	}
	gate, e := sb.PrepareMinIOReadServiceGateFromMaterials(ctx, s.owner.operator.installer.kube, material.File, material.SHA256, s.owner.operation, s.inventorySHA, outputs, check)
	if e != nil {
		return nil, e
	}
	if s.journal.append(ctx, w.ID(), "minio_original_native_checkpoint", &w.original, struct {
		Material             BootstrapSourceFilePin
		OriginalNativeSHA256 string
	}{material, gate.OriginalDigest()}) != nil {
		gate.Close()
		return nil, ErrInstall
	}
	return gate, nil
}

func (s *PreparedOriginalWriterSet) acquireOriginalMinIOReadService(ctx context.Context, w *originalDeploymentMaintenance, material BootstrapSourceFilePin, gate *sb.MinIOReadServiceGate) (*sb.VerifiedMinIOReadServiceObservation, error) {
	if gate == nil || !s.used || w.stopDispatched || s.owner.checkCurrentGate(ctx, c.GateAcquiring) != nil || s.checkApplicationGate(ctx, "acquiring") != nil || s.originalMinIOMember(ctx, w, material) != nil {
		return nil, ErrInstall
	}
	// The shared dispatcher must first stop OTHER genuine source actors and
	// obtain their real B node observations, omitting this kept service's files
	// from the physical-cold universe. An empty node list or lease/SQL ACK is
	// never an equivalent closure. Do not include MinIO as a cold/stopped Pod.
	if s.originalMinIOPhysicalPeersClosed(ctx) != nil {
		return nil, ErrInstall
	}
	if s.journal.append(ctx, w.ID(), "minio_read_gate_acquire_send_unknown", &w.original, material) != nil {
		return nil, ErrInstall
	}
	w.stopDispatched = true
	if gate.Acquire(ctx) != nil {
		return nil, ErrInstall
	}
	proof, e := gate.ObserveHeld(ctx)
	if e != nil || proof.Recheck(ctx, s.owner.operation, s.inventorySHA, "held", time.Now()) != nil || proof.Data().PodUID != w.pods[0].UID {
		return nil, ErrInstall
	}
	return proof, nil
}

func (s *PreparedOriginalWriterSet) originalMinIOPhysicalPeersClosed(ctx context.Context) error {
	if len(s.nodes) == 0 {
		return ErrInstall
	}
	for _, node := range s.nodes {
		if node.current == nil || node.current.Recheck(ctx, node.request.Binding, "stopped", node.boot, time.Now()) != nil {
			return ErrInstall
		}
	}
	return nil
}

func (s *PreparedOriginalWriterSet) restoreOriginalMinIOReadService(ctx context.Context, w *originalDeploymentMaintenance, fence *originalWriterRecoveryFence, gate *sb.MinIOReadServiceGate, material BootstrapSourceFilePin, outputs []string) (*sb.MinIOReadServiceGate, *sb.VerifiedMinIOReadServiceObservation, error) {
	if s == nil || s.origin != s || w == nil || fence == nil || fence.owner != s.owner || fence.checkReleasing(ctx) != nil || s.journal == nil || s.journal.originalSourceMutationsClosed() {
		return gate, nil, ErrInstall
	}
	w.recovery = fence
	fresh := func(actual context.Context) error {
		if fence.checkReleasing(actual) != nil {
			return ErrInstall
		}
		return s.originalMinIOMember(actual, w, material)
	}
	if fresh(ctx) != nil {
		return gate, nil, ErrInstall
	}
	var e error
	if gate == nil {
		// Recovery-only reopen of the SAME original encrypted custody. C refuses
		// missing/foreign journal, expired material or changed secret/version;
		// it cannot mint a new capture operation or produce a held observation.
		gate, e = sb.OpenMinIOReadServiceRecoveryFromMaterials(ctx, fence.operator.installer.kube, material.File, material.SHA256, s.owner.operation, s.inventorySHA, outputs, fresh)
		if e != nil {
			return gate, nil, e
		}
	}
	if s.journal.append(ctx, w.ID(), "minio_read_gate_restore_send_unknown", &w.original, material) != nil {
		return gate, nil, ErrInstall
	}
	if e = sb.RestoreMinIOReadServiceGateFromMaterials(ctx, gate, material.File, material.SHA256, s.owner.operation, s.inventorySHA, outputs, fresh); e != nil {
		return gate, nil, e
	}
	proof, e := gate.ObserveRecovered(ctx)
	if e != nil || proof.Recheck(ctx, s.owner.operation, s.inventorySHA, "recovered", time.Now()) != nil || proof.Data().PodUID != w.pods[0].UID {
		return gate, nil, ErrInstall
	}
	return gate, proof, nil
}
