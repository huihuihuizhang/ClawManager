package install

import (
	q "clawreef/internal/systembackup/quiesce"
	"context"
	"encoding/json"
	"reflect"
	"time"

	sb "clawreef/internal/systembackup"
	c "clawreef/internal/systembackupcontroller"
	archive "clawreef/internal/systembackuphostpatharchive"
	ma "clawreef/internal/systembackupminioauthority"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type originalMinIORecoveryObservation struct {
	origin    *originalMinIORecoveryObservation
	ctx       context.Context
	lifecycle *originalMinIOHistoryLifecycle
	fence     *originalWriterRecoveryFence
	request   q.NodeObservationRequest
	native    *q.VerifiedNodeObservation
	digest    string
}

type originalMinIOHistoryLifecycle struct {
	set                      *PreparedOriginalWriterSet
	ctx                      context.Context
	writer                   *originalDeploymentMaintenance
	material                 BootstrapSourceFilePin
	businessSelection        BootstrapSourceFilePin
	images                   *originalPreColdSQLImageHistory
	native                   archive.NativeStream
	directory                string
	gate                     *sb.MinIOReadServiceGate
	warm                     *OriginalProtectedMinIOWarmHistory
	fence                    *originalWriterRecoveryFence
	recovered                *sb.VerifiedMinIOReadServiceObservation
	captureStarted           bool
	nativeRestored           bool
	recoveryBaseline         *originalMinIORecoveryBaseline
	signing                  *originalMinIORecoverySigning
	signingTransition        *ma.MinIORecoveryTransition
	recoveryObservation      *originalMinIORecoveryObservation
	recoveryPod              ma.ObjectIdentity
	recoveryCID              string
	archiveSource            *originalProtectedMinIOArchive
	adoption                 OriginalAdoptionCommitInspection
	adoptionCommitted        bool
	projectionFailure        error
	physicalRecoveryVerified bool
}

func (r *originalMinIOHistoryLifecycle) check(ctx context.Context) error {
	if r == nil || r.set == nil || r.writer == nil || r.set.minioHistory != r || r.writer.owner != r.set.owner || r.writer.minio != nil || r.writer.redis != nil || originalMaintenanceReadCheck(ctx, r.set.owner, r.fence) != nil {
		return ErrInstall
	}
	raw, e := readBootstrapSourcePin(r.material, 262144)
	clear(raw)
	if e != nil {
		return ErrInstall
	}
	if r.fence != nil {
		if r.fence.owner != r.set.owner || r.fence.checkReleasing(ctx) != nil || r.writer.recovery != r.fence {
			return ErrInstall
		}
	} else {
		if !consumerSameContext(ctx, r.ctx) || r.writer.stopDispatched {
			return ErrInstall
		}
		if r.set.used && (r.set.owner.checkCurrentGate(ctx, c.GateAcquiring, c.GateHeld) != nil || r.set.checkApplicationGate(ctx, "acquiring", "held") != nil) {
			return ErrInstall
		}
	}
	current, e := r.writer.current(ctx)
	if e != nil || current.Spec.Replicas == nil || *current.Spec.Replicas != r.writer.replicas || current.Status.ReadyReplicas != r.writer.replicas || current.Status.ObservedGeneration < current.Generation {
		return ErrInstall
	}
	pods, e := r.writer.currentPods(ctx, current, true)
	if e != nil || len(pods) != 1 {
		return ErrInstall
	}
	if r.fence == nil && (len(r.writer.pods) != 1 || pods[0].UID != r.writer.pods[0].UID) {
		return ErrInstall
	}
	return originalMaintenanceReadCheck(ctx, r.set.owner, r.fence)
}

// Preflight only. This does not acquire native access or stop a source. The
// actual Acquire hook runs after BOTH original SQL admission gates close and
// after all original B native PREPAREs, before the ordinary cold stop loop.
func (s *PreparedOriginalWriterSet) PrepareOriginalMinIOHistoryCapture(ctx context.Context, material BootstrapSourceFilePin, native archive.NativeStream, directory string) error {
	if s == nil {
		return ErrInstall
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.origin != s || s.used || s.minioHistory != nil || s.owner == nil || !consumerSameContext(ctx, s.owner.ctx) || s.recheckPreflight(ctx) != nil || privateDirectory(directory) != nil {
		return ErrInstall
	}
	raw, e := readBootstrapSourcePin(material, 262144)
	var projection struct {
		Version string
		Native  sb.MinIOReadGateInput
	}
	if e != nil || json.Unmarshal(raw, &projection) != nil || projection.Version != "original-minio-source-read-materials.v1" || projection.Native.Operation != "" || projection.Native.InventorySHA256 != "" || len(projection.Native.OutputAccounts) != 0 || projection.Native.NamespaceUID != s.initial.NamespaceUID {
		return ErrInstall
	}
	var selected *originalDeploymentMaintenance
	for _, writer := range s.deployments {
		for _, pod := range writer.pods {
			if pod.UID == projection.Native.PodUID && pod.Name == projection.Native.Pod {
				if selected != nil || writer.minio != nil || writer.redis != nil || writer.replicas != 1 || len(writer.pods) != 1 {
					return ErrInstall
				}
				selected = writer
			}
		}
	}
	if selected == nil {
		return ErrInstall
	}
	r := &originalMinIOHistoryLifecycle{set: s, ctx: ctx, writer: selected, material: material, native: native, directory: directory}
	s.minioHistory = r
	gate, e := sb.PrepareMinIOReadServiceGateFromMaterials(ctx, s.owner.operator.installer.kube, material.File, material.SHA256, s.owner.operation, s.inventorySHA, nil, r.check)
	if e != nil {
		s.minioHistory = nil
		return e
	}
	r.gate = gate
	if gate.CheckOriginalWholeHistoryScope(ctx) != nil {
		gate.Close()
		s.minioHistory = nil
		return ErrInstall
	}
	return s.journal.append(ctx, selected.ID(), "minio_whole_history_prepared", nil, struct {
		Version        string
		Material       BootstrapSourceFilePin
		OriginalNative string
		Native         archive.NativeStream
	}{"original-minio-whole-history-lifecycle.v1", material, gate.OriginalDigest(), native})
}

func (r *originalMinIOHistoryLifecycle) acquireOriginalHistory(ctx context.Context) error {
	if r == nil || r.gate == nil || r.recoveryBaseline == nil || !bootstrapSourcePinValid(r.businessSelection) || r.captureStarted || !r.set.used || r.set.actualHold != nil || len(r.set.nodes) == 0 || r.check(ctx) != nil {
		return ErrInstall
	}
	// Native scopes exist only now, after actual both-gate admission/PREPARE.
	if !originalMinIOProjectionOutsideSources(r.set, r.recoveryBaseline.declaration.ProjectionFile) {
		return ErrInstall
	}
	if r.set.journal.append(ctx, r.writer.ID(), "minio_whole_history_gate_send_unknown", nil, r.gate.OriginalDigest()) != nil {
		return ErrInstall
	}
	r.captureStarted = true
	if r.gate.Acquire(ctx) != nil {
		return ErrInstall
	}
	warm, e := r.set.prepareOriginalProtectedMinIOWarmHistoryLocked(ctx, r.gate, r.native, r.directory)
	if e != nil {
		return e
	}
	r.warm = warm
	r.images, e = r.prepareOriginalGatewayImageHistory(ctx, warm)
	if e != nil {
		return e
	}
	if r.recheckOriginalResourcesBeforeCold(ctx) != nil {
		return ErrInstall
	}
	return r.set.journal.append(ctx, r.writer.ID(), "minio_whole_history_warm_verified", nil, struct {
		Version, S3, Tree, Plan string
		Until                   time.Time
	}{"original-protected-minio-warm.v1", warm.facts.SnapshotSHA256, warm.warm.TreeSHA256, warm.native.PlanSHA256, warm.until})
}

func (h *OriginalWriterHold) PrepareOriginalMixedAdoptionFromCapturedHistory(ctx context.Context, password []byte, enrollment EnrollmentPin, installed *OriginalRuntimeC1Installed, in OriginalMixedFirstAdoptionInputs) (*PreparedOriginalMixedFirstAdoption, error) {
	if h == nil || h.set == nil || h.set.minioHistory == nil || h.set.minioHistory.warm == nil {
		return nil, ErrInstall
	}
	return h.PrepareOriginalMixedFirstAdoption(ctx, password, enrollment, installed, h.set.minioHistory.warm, in)
}

func (r *originalMinIOHistoryLifecycle) restoreNative(ctx context.Context, fence *originalWriterRecoveryFence, observation *originalMinIORecoveryObservation) error {
	if r == nil || r.gate == nil || !r.captureStarted || fence == nil || observation == nil || observation.origin != observation || observation.lifecycle != r || observation.fence != fence || !consumerSameContext(ctx, observation.ctx) || observation.native == nil || observation.digest == "" || fence.owner != r.set.owner {
		return ErrInstall
	}
	r.fence = fence
	r.writer.recovery = fence
	if r.check(ctx) != nil || r.set.recheckVolumePins(ctx) != nil {
		return ErrInstall
	}
	deployment, e := r.writer.current(ctx)
	if e != nil {
		return e
	}
	pods, e := r.writer.currentPods(ctx, deployment, true)
	if e != nil || len(pods) != 1 {
		return ErrInstall
	}
	var node *originalWholeNodeScope
	for _, source := range r.set.nodes {
		if source.request.Binding.Node == pods[0].Node {
			if node != nil {
				return ErrInstall
			}
			node = source
		}
	}
	if node == nil || node.prepare == nil || observation.request.Binding != node.request.Binding {
		return ErrOriginalRecoveryNativeProof
	}
	request := observation.request
	// Request comes from the actual native call retained by B, never hand-built
	// replacement identity JSON. Lower native consumer also verifies its exact
	// signed request hash, full original/current Pod lists and actual target.
	var containerID string
	var material struct{ Native sb.MinIOReadGateInput }
	raw, e := readBootstrapSourcePin(r.material, 262144)
	if e != nil || json.Unmarshal(raw, &material) != nil {
		return ErrInstall
	}
	actual, e := r.set.owner.operator.installer.kube.CoreV1().Pods(r.writer.namespace).Get(ctx, pods[0].Name, metav1.GetOptions{})
	if e != nil || string(actual.UID) != pods[0].UID {
		return ErrInstall
	}
	for _, status := range actual.Status.ContainerStatuses {
		if status.Name == material.Native.Container && status.ImageID == material.Native.ImageID && status.Ready && status.State.Running != nil {
			if containerID != "" {
				return ErrInstall
			}
			containerID = status.ContainerID
		}
	}
	if containerID == "" || r.gate.RestoreAfterOriginalCold(ctx, request, observation.native, pods[0].Name, pods[0].UID, containerID, fence.operator.until, r.check) != nil {
		return ErrOriginalRecoveryNativeProof
	}
	r.recovered, e = r.gate.ObserveRecovered(ctx)
	if e != nil {
		return e
	}
	if r.recovered.Recheck(ctx, r.set.owner.operation, r.set.inventorySHA, "recovered", time.Now()) != nil {
		return ErrOriginalRecoveryNativeProof
	}
	r.recoveryObservation = observation
	r.recoveryPod = ma.ObjectIdentity{Name: pods[0].Name, UID: pods[0].UID}
	r.recoveryCID = containerID
	return nil
}

// This preliminary actual live native observation is only a SAME MinIO target
// source for permission restoration, before source mutations close. It is NOT
// a final B recovery proof or a declaration of closed source membership.
func (r *originalMinIOHistoryLifecycle) observeBeforeNativeRestore(ctx context.Context, fence *originalWriterRecoveryFence) (*originalMinIORecoveryObservation, error) {
	if r == nil || r.writer == nil || fence == nil || fence.owner != r.set.owner || r.set.journal.originalSourceMutationsClosed() {
		return nil, ErrOriginalRecoveryNativeProof
	}
	r.fence = fence
	r.writer.recovery = fence
	if r.check(ctx) != nil || r.set.recheckVolumePins(ctx) != nil {
		return nil, ErrInstall
	}
	deployment, e := r.writer.current(ctx)
	if e != nil {
		return nil, e
	}
	pods, e := r.writer.currentPods(ctx, deployment, true)
	if e != nil || len(pods) != 1 {
		return nil, ErrInstall
	}
	var node *originalWholeNodeScope
	for _, source := range r.set.nodes {
		if source.request.Binding.Node == pods[0].Node {
			if node != nil {
				return nil, ErrInstall
			}
			node = source
		}
	}
	if node == nil || node.prepare == nil {
		return nil, ErrOriginalRecoveryNativeProof
	}
	peers, e := r.set.readOriginalRecoveryPeers(ctx, fence, node, nil)
	if e != nil {
		return nil, e
	}
	request := node.request
	request.Action = "recovery-reconciled"
	request.SourcePaths = nil
	request.Anchor = node.prepare.Response().Anchor
	request.RecoveredPods = peers.Pods
	request.RecoveredGeneration = r.set.owner.token.Generation
	request.RecoveryAffectedPods = nil
	request.RecoverySnapshotSHA256 = originalObjectSHA(struct {
		Version, Operation, Inventory string
		Peers                         originalRecoveryPeerSnapshot
	}{"original-minio-pre-permission-restore-live-scope.v1", r.set.owner.operation, r.set.inventorySHA, peers})
	native, e := r.set.wholePodClient.ObserveVerified(ctx, request)
	if e != nil || native == nil || native.RecheckOriginalRecoveryScope(ctx, request, nil, node.boot, time.Now()) != nil {
		return nil, ErrOriginalRecoveryNativeProof
	}
	again, e := r.set.readOriginalRecoveryPeers(ctx, fence, node, nil)
	if e != nil || !reflect.DeepEqual(peers, again) || r.check(ctx) != nil {
		return nil, ErrOriginalRecoveryNativeProof
	}
	observation := &originalMinIORecoveryObservation{ctx: ctx, lifecycle: r, fence: fence, request: request, native: native, digest: originalObjectSHA(struct{ Version, Snapshot, Request string }{"minio-native-permission-restoration-data-only.v1", request.RecoverySnapshotSHA256, native.Response().RequestSHA256})}
	observation.origin = observation
	return observation, nil
}

func (s *PreparedOriginalWriterSet) prepareOriginalMinIOHistoryRecovery(ctx context.Context, fence *originalWriterRecoveryFence) error {
	if s == nil {
		return ErrInstall
	}
	r := s.minioHistory
	if r == nil || !r.captureStarted {
		return nil
	}
	if s.journal.originalSourceMutationsClosed() {
		// The original native restore already completed before closure. A retry
		// must not re-enter preliminary recovery or send a source mutation. The
		// caller still collects full fresh B proof and the final same-target
		// read-only MinIO observation before any original gate settlement.
		if !r.nativeRestored || r.recovered == nil || fence == nil || r.fence != fence || r.check(ctx) != nil {
			return ErrOriginalRecoveryNativeProof
		}
		if r.adoptionCommitted {
			if r.signing == nil {
				r.projectionFailure = ErrInstall
			} else {
				r.projectionFailure = r.queryOriginalRecoveryProjection(ctx)
			}
		}
		// Pending metadata is checked only AFTER all physical recovery proofs,
		// keeping both admission gates closed without skipping actual recovery.
		return nil
	}
	// Native permission restoration is once; a repeated phase only reads the
	// same actual recovered target while completing/querying original signing.
	proof, e := r.observeBeforeNativeRestore(ctx, fence)
	if e != nil {
		return e
	}
	if !r.nativeRestored {
		if s.journal.append(ctx, r.writer.ID(), "minio_whole_history_restore_send_unknown", nil, proof.digest) != nil {
			return ErrInstall
		}
	}
	if r.restoreNative(ctx, fence, proof) != nil {
		return ErrOriginalRecoveryNativeProof
	}
	if !r.nativeRestored {
		r.nativeRestored = true
		if s.journal.append(ctx, r.writer.ID(), "minio_whole_history_restored_readback", nil, r.recovered.Data()) != nil {
			return ErrInstall
		}
	}
	// All physical restore callbacks must finish even if material signing is
	// unavailable. Preserve that failure; the final proof path retains both
	// admission gates before its SQL release, rather than skipping restoration.
	if r.projectionFailure == nil || r.signing != nil {
		if r.projectionFailure != nil {
			// Any prior send failure permits only an exact original-file query.
			r.signing.attempted = true
		}
		r.projectionFailure = r.issueOriginalRecoveryProjection(ctx)
		if r.projectionFailure != nil {
			_ = s.journal.append(ctx, r.writer.ID(), "minio_recovery_projection_pending_admission_retained", nil, r.recoveryBaseline.descriptor)
		}
	}
	return nil
}

func (s *PreparedOriginalWriterSet) refreshOriginalMinIOHistoryAfterFinalProof(ctx context.Context, fence *originalWriterRecoveryFence, proof *originalRecoveredReadiness) (*originalRecoveredReadiness, error) {
	if s == nil {
		return nil, ErrInstall
	}
	r := s.minioHistory
	if r == nil || !r.captureStarted {
		return proof, nil
	}
	if !r.nativeRestored || proof == nil || proof.set != s || proof.digest == "" || proof.admissionAbort != nil || fence == nil {
		return nil, ErrOriginalRecoveryNativeProof
	}
	current, e := r.writer.current(ctx)
	if e != nil {
		return nil, e
	}
	pods, e := r.writer.currentPods(ctx, current, true)
	if e != nil || len(pods) != 1 {
		return nil, ErrInstall
	}
	var observation *originalMinIORecoveryObservation
	for _, node := range s.nodes {
		if node.request.Binding.Node != pods[0].Node {
			continue
		}
		request, found := proof.requests[node]
		if !found || proof.nodes[node] == nil || observation != nil {
			return nil, ErrOriginalRecoveryNativeProof
		}
		observation = &originalMinIORecoveryObservation{ctx: ctx, lifecycle: r, fence: fence, request: request, native: proof.nodes[node], digest: proof.nodes[node].Response().RequestSHA256}
		observation.origin = observation
	}
	// Native READS ONLY for already restored original target. No source mutation
	// is sent after the complete final B proof/closed mutation barrier.
	if observation == nil || r.restoreNative(ctx, fence, observation) != nil {
		return nil, ErrOriginalRecoveryNativeProof
	}
	r.physicalRecoveryVerified = true
	// Every original business writer and native permission has now recovered.
	// A missing/unknown signed succession still forbids admission release and
	// any new task. Do not renew the old proof or call another signing operation.
	if r.adoptionCommitted && (r.projectionFailure != nil || r.signing == nil || r.signing.receipt == nil) {
		return nil, ErrOriginalRecoveryProjectionPending
	}
	return proof, nil
}

func (s *PreparedOriginalWriterSet) checkOriginalMinIOHistoryRecoveryLocked(ctx context.Context, now time.Time) error {
	if s == nil {
		return ErrInstall
	}
	r := s.minioHistory
	if r == nil || !r.captureStarted {
		return nil
	}
	if r.recovered == nil || r.fence == nil || r.recovered.Recheck(ctx, s.owner.operation, s.inventorySHA, "recovered", now) != nil {
		return ErrOriginalRecoveryNativeProof
	}
	return nil
}

// Operational source locator only. Actual SQL/native bodies are collected by
// the private original lifecycle AFTER the real fence/drain, before cold stop.
func (s *PreparedOriginalWriterSet) PrepareOriginalMinIOBusinessSourceSelection(ctx context.Context, pin BootstrapSourceFilePin) error {
	if s == nil {
		return ErrInstall
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.origin != s || s.used || s.minioHistory == nil || s.owner == nil || !consumerSameContext(ctx, s.owner.ctx) || s.minioHistory.businessSelection != (BootstrapSourceFilePin{}) || s.recheckPreflight(ctx) != nil {
		return ErrInstall
	}
	raw, e := readBootstrapSourcePin(pin, 262144)
	var selected BootstrapSourceAuthoringSelection
	if e != nil || decodeExact(raw, &selected) != nil || validateBootstrapSourceAuthoring(selected, s.owner.operator.installer.plan.Target) != nil || selected.ApplicationScope != s.selection.ApplicationScope {
		return ErrInstall
	}
	sourceRaw, e := json.Marshal(selected)
	if e != nil {
		return ErrInstall
	}
	materialRaw, e := readBootstrapSourcePin(s.minioHistory.material, 262144)
	var material struct{ SourceSelectionSHA256 string }
	if e != nil || json.Unmarshal(materialRaw, &material) != nil || material.SourceSelectionSHA256 != hash(sourceRaw) || observeBootstrapSourceController(ctx, s.owner.operator.installer.kube, s.owner.operator.installer.plan.Target, selected.Controller) != nil {
		return ErrInstall
	}
	s.minioHistory.businessSelection = pin
	return nil
}
