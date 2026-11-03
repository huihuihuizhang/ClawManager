package install

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"sort"
	"sync"
	"time"

	"clawreef/internal/systembackup/domain"
	q "clawreef/internal/systembackup/quiesce"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var ErrOriginalRecoveryNativeProof = errors.New("original sources retain maintenance admission: complete actual native recovery has not been proved")

// RestoreOriginalSources consumes only A's genuine fresh recovery authorization
// for this exact in-memory prepared set and its durable journal. It also covers
// Acquire errors that did not return a hold. No task, grant, replacement state,
// acknowledgement, deadline extension or caller-selected actor list is accepted.
func (s *PreparedOriginalWriterSet) RestoreOriginalSources(ctx context.Context, authorization *OriginalWriterRecoveryAuthorization) error {
	if s == nil || authorization == nil {
		return ErrInstall
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	fence, err := authorization.recoveryFence(ctx, s)
	if err != nil || fence == nil || fence.owner != s.owner || fence.check(ctx) != nil {
		return ErrInstall
	}
	// Preparing A's authorization has actually cancelled and waited every
	// concrete registered provider. Recheck that same narrow authorization;
	// the original capture authority is deliberately never reactivated.
	if err = s.beginOriginalRecovery(ctx, fence); err != nil {
		return err
	}
	if s.journal.originalSourceMutationsClosed() {
		proof, err := s.observeOriginalRecovered(ctx, fence)
		if err != nil {
			return err
		}
		return s.finishOriginalRecovery(ctx, fence, proof)
	}
	// A complete actual hold takes the normal fresh global proof path. Partial
	// acquisition is classified from private actor objects and durable journal;
	// it never requires unaffected originals to stop merely to satisfy a global
	// precondition. The separate per-actor path cannot release either gate until
	// the complete final current-source proof succeeds.
	if s.actualHold == nil {
		return s.restoreOriginalPartial(ctx, fence)
	}
	if s.observeOriginalRecoveryStopped(ctx, fence) != nil {
		return ErrOriginalRecoveryNativeProof
	}
	// Deployment controllers are restored before their workload consumers.
	// Each restore changes the exact RV, fencing a delayed original stop patch.
	for _, writer := range s.deployments {
		if !writer.stopDispatched {
			continue
		}
		if fence.check(ctx) != nil || writer.restore(ctx, fence) != nil {
			return ErrOriginalRecoveryNativeProof
		}
	}
	for _, writer := range s.proPods {
		if !writer.stopDispatched {
			continue
		}
		if fence.check(ctx) != nil || writer.restore(ctx, fence) != nil {
			return ErrOriginalRecoveryNativeProof
		}
	}
	for _, writer := range s.gateways {
		if !writer.stopDispatched {
			continue
		}
		writer.recovery = fence
		if fence.check(ctx) != nil {
			return ErrInstall
		}
		if err = writer.Resume(ctx, writer.state); err != nil {
			return err
		}
	}
	for _, source := range s.stopped {
		if source.anchor == "" {
			return ErrOriginalRecoveryNativeProof
		} // Actual actors restored; missing original native anchor still retains admission.
		if source.observe(ctx, "recovered-stopped") != nil {
			return ErrOriginalRecoveryNativeProof
		}
	}
	proof, err := s.observeOriginalRecovered(ctx, fence)
	if err != nil {
		return err
	}
	return s.finishOriginalRecovery(ctx, fence, proof)
}

// The final proof is made by the concrete native client and actual SQL/API
// reads below. It is private, in-process and cannot be deserialized or supplied
// by the caller. It never stands in for a skipped native observation.
type originalRecoveredReadiness struct {
	admissionAbort *originalAdmissionAbortReadiness
	nodeAction     string
	requests       map[*originalWholeNodeScope]q.NodeObservationRequest
	facts          map[*originalWholeNodeScope]*originalRecoveryNodeFacts
	boundary       *originalRecoveryMutationBoundary
	set            *PreparedOriginalWriterSet
	nodes          map[*originalWholeNodeScope]*q.VerifiedNodeObservation
	expected       []domain.SourceInstance
	digest         string
}

func (s *PreparedOriginalWriterSet) observeOriginalRecovered(ctx context.Context, fence *originalWriterRecoveryFence) (*originalRecoveredReadiness, error) {
	if fence.check(ctx) != nil || s.recheckVolumePins(ctx) != nil {
		return nil, ErrInstall
	}
	recovered := map[string][]q.PodIdentity{}
	for _, writer := range s.deployments {
		writer.recovery = fence
		current, err := writer.current(ctx)
		if err != nil || *current.Spec.Replicas != writer.replicas || current.Status.ObservedGeneration < current.Generation || current.Status.ReadyReplicas != writer.replicas {
			return nil, ErrOriginalRecoveryNativeProof
		}
		pods, err := writer.currentPods(ctx, current, true)
		if err != nil || len(pods) != int(writer.replicas) {
			return nil, ErrOriginalRecoveryNativeProof
		}
		for _, pod := range pods {
			recovered[pod.Node] = append(recovered[pod.Node], pod)
		}
	}
	for _, writer := range s.proPods {
		pod, err := fence.operator.installer.kube.CoreV1().Pods(writer.source.Namespace).Get(ctx, writer.source.Pod, metav1.GetOptions{})
		if err != nil || originalObjectSHA(pod.Spec) != writer.specSHA || len(pod.OwnerReferences) != 0 {
			return nil, ErrOriginalRecoveryNativeProof
		}
		identity, err := originalMaintenancePodIdentity(pod)
		if err != nil {
			return nil, ErrOriginalRecoveryNativeProof
		}
		recovered[identity.Node] = append(recovered[identity.Node], identity)
	}
	expected := append([]domain.SourceInstance(nil), s.owner.instances...)
	for _, gateway := range s.gateways {
		if !gateway.stopDispatched {
			continue
		}
		if gateway.currentBinding(ctx, gateway.state.Running) != nil {
			return nil, ErrOriginalRecoveryNativeProof
		}
		if gateway.state.Running {
			if gateway.request.Running == nil || gateway.resumedPID <= 0 {
				return nil, ErrInstall
			}
			for i := range expected {
				if expected[i].ID == gateway.source.ID {
					expected[i].Generation = gateway.request.Running.ResumeGeneration
				}
			}
		}
	}
	for _, node := range s.nodes {
		if recovered[node.request.Binding.Node] == nil {
			recovered[node.request.Binding.Node] = []q.PodIdentity{}
		}
		sort.Slice(recovered[node.request.Binding.Node], func(i, j int) bool {
			return recovered[node.request.Binding.Node][i].UID < recovered[node.request.Binding.Node][j].UID
		})
	}
	if s.recheckOriginalRecoveredAPI(ctx, fence, recovered) != nil {
		return nil, ErrOriginalRecoveryNativeProof
	}
	action := "recovered"
	if s.actualHold == nil {
		action = "recovery-reconciled"
	}
	proof := &originalRecoveredReadiness{nodeAction: action, set: s, nodes: map[*originalWholeNodeScope]*q.VerifiedNodeObservation{}, expected: expected,
		requests: map[*originalWholeNodeScope]q.NodeObservationRequest{}, facts: map[*originalWholeNodeScope]*originalRecoveryNodeFacts{}}
	if action == "recovery-reconciled" {
		boundary, e := s.journal.closeOriginalSourceMutations(ctx)
		if e != nil {
			return nil, e
		}
		proof.boundary = boundary
		// All source restore callbacks returned before closure. These durable
		// complete owner-graph facts are written BEFORE any final native RPC.
		for _, node := range s.nodes {
			if node.prepare == nil {
				return nil, ErrOriginalRecoveryNativeProof
			}
			peers, e := s.readOriginalRecoveryPeers(ctx, fence, node, nil)
			if e != nil || !reflect.DeepEqual(peers.Pods, recovered[node.request.Binding.Node]) {
				return nil, ErrOriginalRecoveryNativeProof
			}
			request := node.request
			request.Action, request.SourcePaths, request.Anchor = action, nil, node.prepare.Response().Anchor
			request.RecoveredPods, request.RecoveredGeneration = peers.Pods, s.owner.token.Generation
			facts, e := s.persistOriginalRecoveryFacts(ctx, node, request, peers, boundary)
			if e != nil {
				return nil, e
			}
			request.RecoverySnapshotSHA256 = facts.sha256
			proof.requests[node], proof.facts[node] = request, facts
		}
	}
	for node := range recovered {
		sort.Slice(recovered[node], func(i, j int) bool { return recovered[node][i].UID < recovered[node][j].UID })
	}
	// All short native windows must overlap. API and SQL projection reads are
	// outside this concurrent observation section and the final SQL lock prefix.
	var wg sync.WaitGroup
	var proofMu sync.Mutex
	failures := make(chan error, len(s.nodes)+len(s.gateways)+len(s.stopped))
	run := func(fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(); err != nil {
				failures <- err
			}
		}()
	}
	for _, node := range s.nodes {
		node := node
		run(func() error {
			request := node.request
			request.Action = action
			request.SourcePaths = nil
			request.Anchor = node.prepare.Response().Anchor
			request.RecoveredPods = recovered[request.Binding.Node]
			// Recovery has no next acquisition: pin the REAL original generation.
			request.RecoveredGeneration = s.owner.token.Generation
			if action == "recovery-reconciled" {
				request = proof.requests[node]
			}
			native, err := s.wholePodClient.ObserveVerified(ctx, request)
			if err != nil || native == nil {
				return ErrOriginalRecoveryNativeProof
			}
			if action == "recovery-reconciled" {
				peers, e := s.readOriginalRecoveryPeers(ctx, fence, node, nil)
				if e != nil || !sameOriginalRecoveryPeers(peers, proof.facts[node].peers) || proof.facts[node].recheckLocal(proof.boundary, request) != nil || native.RecheckOriginalRecoveryScope(ctx, request, nil, node.boot, time.Now()) != nil {
					return ErrOriginalRecoveryNativeProof
				}
			} else if native.Recheck(ctx, request.Binding, action, node.boot, time.Now()) != nil {
				return ErrOriginalRecoveryNativeProof
			}
			if s.journal.append(ctx, node.claim.WriterID, "native_node_recovered", nil, struct {
				Request     q.NodeObservationRequest
				Observation q.NodeObservationResponse
			}{request, native.Response()}) != nil {
				return ErrInstall
			}
			proofMu.Lock()
			proof.nodes[node] = native
			proofMu.Unlock()
			return nil
		})
	}
	for _, gateway := range s.gateways {
		gateway := gateway
		if !gateway.stopDispatched {
			continue
		}
		run(func() error {
			phase := "recovered"
			if !gateway.state.Running {
				phase = "recovered-stopped"
			}
			return gateway.nativeCheck(ctx, phase)
		})
	}
	for _, source := range s.stopped {
		source := source
		run(func() error { return source.observe(ctx, "recovered-stopped") })
	}
	wg.Wait()
	close(failures)
	for range failures {
		return nil, ErrOriginalRecoveryNativeProof
	}
	tx, err := fence.operator.installer.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, ErrInstall
	}
	defer tx.Rollback()
	actual, err := domain.ReadSourceInstances(ctx, tx)
	if err != nil || !reflect.DeepEqual(actual, expected) || tx.Rollback() != nil {
		return nil, ErrOriginalRecoveryNativeProof
	}
	responses := []any{}
	for _, node := range s.nodes {
		responses = append(responses, proof.nodes[node].Response())
	}
	for _, gateway := range s.gateways {
		if gateway.stopDispatched {
			responses = append(responses, gateway.proof.Response())
		}
	}
	for _, source := range s.stopped {
		responses = append(responses, source.proof.Response())
	}
	proof.digest = originalObjectSHA(struct {
		Inventory string
		Sources   []domain.SourceInstance
		Native    []any
	}{s.inventorySHA, expected, responses})
	if fence.check(ctx) != nil || s.journal.append(ctx, "", "complete_original_recovered_observation", nil, struct {
		Digest  string
		Sources []domain.SourceInstance
		Native  []any
	}{proof.digest, expected, responses}) != nil {
		return nil, ErrInstall
	}
	return proof, nil
}

// Enumerate the complete namespace after restoration. Replacement actors may
// change only the original writer deployments/Pods. Kept Agent and database
// controllers retain the original exact pins; no newly introduced controller,
// workload or persistent claim is omitted by a label filter.
func (s *PreparedOriginalWriterSet) recheckOriginalRecoveredAPI(ctx context.Context, fence *originalWriterRecoveryFence, recovered map[string][]q.PodIdentity) error {
	if fence.check(ctx) != nil {
		return ErrInstall
	}
	k := fence.operator.installer.kube
	ns := fence.operator.installer.plan.Target.Namespace
	namespace, err := k.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
	if err != nil || string(namespace.UID) != s.initial.NamespaceUID || namespace.DeletionTimestamp != nil {
		return ErrInstall
	}
	deps, err := k.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
	if err != nil || len(deps.Items) != len(s.initial.Deployments) {
		return ErrInstall
	}
	writers := map[string]*originalDeploymentMaintenance{}
	for _, writer := range s.deployments {
		writers[writer.selection.Name] = writer
	}
	for _, dep := range deps.Items {
		if writer := writers[dep.Name]; writer != nil {
			if string(dep.UID) != writer.selection.UID || dep.DeletionTimestamp != nil || dep.Spec.Replicas == nil || *dep.Spec.Replicas != writer.replicas || originalDeploymentSpecSHA(&dep) != writer.specSHA {
				return ErrInstall
			}
			continue
		}
		found := false
		for _, old := range s.initial.Deployments {
			if old.Name == dep.Name && old.UID == string(dep.UID) && old.Generation == dep.Generation && old.SpecSHA256 == originalObjectSHA(dep.Spec) {
				found = true
			}
		}
		if !found || dep.DeletionTimestamp != nil {
			return ErrInstall
		}
	}
	claims, err := k.CoreV1().PersistentVolumeClaims(ns).List(ctx, metav1.ListOptions{})
	if err != nil || len(claims.Items) != len(s.initial.PVCs) {
		return ErrInstall
	}
	for _, claim := range claims.Items {
		found := false
		for _, old := range s.initial.PVCs {
			if old.Name == claim.Name && old.UID == string(claim.UID) && old.SpecSHA256 == originalObjectSHA(claim.Spec) {
				found = true
			}
		}
		if !found || claim.DeletionTimestamp != nil {
			return ErrInstall
		}
	}
	sets, err := k.AppsV1().StatefulSets(ns).List(ctx, metav1.ListOptions{})
	if err != nil || len(sets.Items) != 0 {
		return ErrInstall
	}
	daemons, err := k.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
	if err != nil || len(daemons.Items) != 0 {
		return ErrInstall
	}
	jobs, err := k.BatchV1().Jobs(ns).List(ctx, metav1.ListOptions{})
	if err != nil || len(jobs.Items) != 0 {
		return ErrInstall
	}
	crons, err := k.BatchV1().CronJobs(ns).List(ctx, metav1.ListOptions{})
	if err != nil || len(crons.Items) != 0 {
		return ErrInstall
	}
	autoscalers, err := k.AutoscalingV2().HorizontalPodAutoscalers(ns).List(ctx, metav1.ListOptions{})
	if err != nil || len(autoscalers.Items) != 0 {
		return ErrInstall
	}
	originalWriterPods := map[string]bool{}
	for _, writer := range s.deployments {
		for _, pod := range writer.pods {
			originalWriterPods[pod.UID] = true
		}
	}
	for _, writer := range s.proPods {
		originalWriterPods[writer.original.UID] = true
	}
	allowed := map[string]bool{}
	kept := map[string]originalMaintenanceObjectPin{}
	for _, old := range s.initial.Pods {
		if !originalWriterPods[old.UID] {
			allowed[old.UID] = true
			kept[old.UID] = old
		}
	}
	for _, pods := range recovered {
		for _, pod := range pods {
			if allowed[pod.UID] {
				return ErrInstall
			}
			allowed[pod.UID] = true
		}
	}
	pods, err := k.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil || len(pods.Items) != len(allowed) {
		return ErrInstall
	}
	for _, pod := range pods.Items {
		uid := string(pod.UID)
		if !allowed[uid] || pod.DeletionTimestamp != nil {
			return ErrInstall
		}
		if old, ok := kept[uid]; ok {
			pin := originalMaintenanceObjectPin{pod.Name, uid, originalObjectSHA(struct {
				Spec     corev1.PodSpec
				Owners   []metav1.OwnerReference
				Phase    corev1.PodPhase
				Statuses []corev1.ContainerStatus
			}{pod.Spec, pod.OwnerReferences, pod.Status.Phase, pod.Status.ContainerStatuses}), pod.Generation}
			if pin != old {
				return ErrInstall
			}
		}
	}
	return nil
}

// Fresh actual native absence is required BEFORE any original source starts.
// API deletion/replica-zero and an expired capture observation are insufficient.
// The unchanged original bindings/anchors are used with a recovery-only action;
// an older observer which lacks that action refuses and retains both gates.
func (s *PreparedOriginalWriterSet) observeOriginalRecoveryStopped(ctx context.Context, fence *originalWriterRecoveryFence) error {
	if fence.checkReleasing(ctx) != nil || s.recheckVolumePins(ctx) != nil {
		return ErrInstall
	}
	var wg sync.WaitGroup
	failures := make(chan error, len(s.nodes)+len(s.stopped))
	run := func(fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(); err != nil {
				failures <- err
			}
		}()
	}
	for _, node := range s.nodes {
		node := node
		run(func() error {
			if node.prepare == nil {
				return ErrOriginalRecoveryNativeProof
			}
			request := node.request
			request.Action = "recovery-stopped"
			request.SourcePaths = nil
			request.Anchor = node.prepare.Response().Anchor
			proof, err := s.wholePodClient.ObserveVerified(ctx, request)
			if err != nil || proof.Recheck(ctx, request.Binding, "recovery-stopped", node.boot, time.Now()) != nil {
				return ErrOriginalRecoveryNativeProof
			}
			return s.journal.append(ctx, node.claim.WriterID, "native_node_recovery_stopped", nil, struct {
				Request     q.NodeObservationRequest
				Observation q.NodeObservationResponse
			}{request, proof.Response()})
		})
	}
	for _, source := range s.stopped {
		source := source
		source.recovery = fence
		run(func() error {
			if source.anchor == "" {
				return ErrOriginalRecoveryNativeProof
			}
			return source.observe(ctx, "recovery-stopped")
		})
	}
	wg.Wait()
	close(failures)
	for range failures {
		return ErrOriginalRecoveryNativeProof
	}
	return fence.checkReleasing(ctx)
}
