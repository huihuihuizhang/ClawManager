package install

import (
	"context"
	"database/sql"
	"errors"
	"reflect"

	"clawreef/internal/services"
	"clawreef/internal/systembackup/domain"
	q "clawreef/internal/systembackup/quiesce"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var ErrOriginalSourceDispatchPresent = errors.New("original source dispatch intent exists; native recovery is required")

type OriginalAdmissionAbortInspection struct {
	Version, Operation, State, InventorySHA256 string
	AdmissionAbortVerified                     bool
	NativeSourceRecoveryVerified               bool
}

type originalAdmissionAbortReadiness struct {
	origin   *originalAdmissionAbortReadiness
	set      *PreparedOriginalWriterSet
	boundary *originalRecoveryMutationBoundary
	digest   string
}

func (a *originalAdmissionAbortReadiness) recheckLocal(s *PreparedOriginalWriterSet, p *originalRecoveredReadiness) error {
	if a == nil || a.origin != a || a.set != s || s.actualHold != nil || a.boundary == nil || a.boundary.journal != s.journal || a.boundary.lastMutation != 0 || a.boundary.recheckLocal() != nil || p.admissionAbort != a || p.digest != a.digest || len(p.nodes) != 0 || !reflect.DeepEqual(p.expected, s.owner.instances) {
		return ErrInstall
	}
	return s.noOriginalSourceDispatch()
}

// This classification uses the private dispatch flags AND the actual durable
// intent chain. A flag without an intent (or an intent without a flag) never
// becomes an untouched-source claim. No public actor list is accepted.
func (s *PreparedOriginalWriterSet) noOriginalSourceDispatch() error {
	if s == nil || s.origin != s || s.actualHold != nil {
		return ErrOriginalSourceDispatchPresent
	}
	for _, w := range s.deployments {
		if w.stopDispatched {
			return ErrOriginalSourceDispatchPresent
		}
	}
	for _, w := range s.proPods {
		if w.stopDispatched || w.createDispatched {
			return ErrOriginalSourceDispatchPresent
		}
	}
	for _, g := range s.gateways {
		if g.stopDispatched || g.resumeDispatched {
			return ErrOriginalSourceDispatchPresent
		}
	}
	j := s.journal
	if j == nil {
		return ErrInstall
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed {
		return ErrInstall
	}
	if j.lastSourceMutation != 0 {
		return ErrOriginalSourceDispatchPresent
	}
	return nil
}

// AbortUnstartedOriginalAcquisition is a distinct operation from physical
// source recovery. It sends NO stop/reserve/start/complete request. A permits
// this original gate-only case, but a real fresh administrator and exact
// double-gate/SQL readback are still mandatory. Success is never backup or
// native SourceRecovery success.
func (s *PreparedOriginalWriterSet) AbortUnstartedOriginalAcquisition(ctx context.Context, authorization *OriginalWriterRecoveryAuthorization) (OriginalAdmissionAbortInspection, error) {
	var zero OriginalAdmissionAbortInspection
	if s == nil || authorization == nil {
		return zero, ErrInstall
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	fence, err := authorization.recoveryFence(ctx, s)
	if err != nil || fence == nil || fence.owner != s.owner || fence.check(ctx) != nil {
		return zero, ErrInstall
	}
	if err = s.noOriginalSourceDispatch(); err != nil {
		return zero, err
	}
	// Authenticate the real immutable files before any gate transition. A's
	// recovery preparation has already cancelled/waited all concrete providers.
	j := s.journal
	j.mu.Lock()
	observed, err := j.inspect(ctx, j.operation, j.inventory)
	valid := err == nil && !j.failed && observed.TailSHA256 == j.tail && uint64(len(observed.Records)) == j.sequence
	j.mu.Unlock()
	if !valid {
		return zero, ErrInstall
	}
	for _, record := range observed.Records {
		if originalSourceMutationIntent(record.Action) {
			return zero, ErrOriginalSourceDispatchPresent
		}
	}
	if s.beginOriginalRecovery(ctx, fence) != nil {
		return zero, ErrCommitUnknown
	}
	boundary, err := j.closeOriginalSourceMutations(ctx)
	if err != nil || boundary.lastMutation != 0 {
		return zero, ErrInstall
	}
	current, err := s.observeOriginalUnchangedSources(ctx, fence)
	if err != nil {
		return zero, err
	}
	facts := struct {
		Version, Operation, InventorySHA256, JournalPrefixSHA256 string
		PrefixSequence                                           uint64
		Sources                                                  []domain.SourceInstance
		API                                                      originalMaintenanceKubernetesCensus
		Runtime                                                  []any
	}{"original-unstarted-admission-abort.v1", s.owner.operation, s.inventorySHA, observed.TailSHA256, uint64(len(observed.Records)), s.owner.instances, s.initial, current}
	if j.append(ctx, "", "original_unstarted_admission_abort_actual_observation", nil, facts) != nil {
		return zero, ErrInstall
	}
	digest := originalObjectSHA(facts)
	abort := &originalAdmissionAbortReadiness{set: s, boundary: boundary, digest: digest}
	abort.origin = abort
	proof := &originalRecoveredReadiness{set: s, expected: append([]domain.SourceInstance(nil), s.owner.instances...), digest: digest, admissionAbort: abort}
	if s.finishOriginalRecovery(ctx, fence, proof) != nil {
		return zero, ErrCommitUnknown
	}
	return OriginalAdmissionAbortInspection{Version: "original-admission-abort-inspection.v1", Operation: s.owner.operation, State: "actual_unstarted_acquisition_aborted_no_native_recovery_claim", InventorySHA256: s.inventorySHA, AdmissionAbortVerified: true}, nil
}

func (s *PreparedOriginalWriterSet) observeOriginalUnchangedSources(ctx context.Context, fence *originalWriterRecoveryFence) ([]any, error) {
	if fence.checkReleasing(ctx) != nil || s.noOriginalSourceDispatch() != nil || s.recheckVolumePins(ctx) != nil {
		return nil, ErrInstall
	}
	recovered := map[string][]q.PodIdentity{}
	observations := []any{}
	for _, w := range s.deployments {
		w.recovery = fence
		if w.redis != nil {
			if w.redis.observeRecovered(ctx) != nil {
				return nil, ErrInstall
			}
			observations = append(observations, w.redis.recovered.Data())
			continue
		}
		if w.minio != nil {
			if w.minio.observeRecovered(ctx) != nil {
				return nil, ErrInstall
			}
			observations = append(observations, w.minio.recovered.Data())
			continue
		}
		actual, err := w.current(ctx)
		if err != nil || *actual.Spec.Replicas != w.replicas || actual.Status.ObservedGeneration < actual.Generation || actual.Status.ReadyReplicas != w.replicas {
			return nil, ErrInstall
		}
		pods, err := w.currentPods(ctx, actual, true)
		if err != nil || !reflect.DeepEqual(pods, w.pods) {
			return nil, ErrInstall
		}
		for _, pod := range pods {
			recovered[pod.Node] = append(recovered[pod.Node], pod)
		}
	}
	for _, w := range s.proPods {
		actual, err := fence.operator.installer.kube.CoreV1().Pods(w.source.Namespace).Get(ctx, w.source.Pod, metav1.GetOptions{})
		if err != nil || string(actual.UID) != w.original.UID || len(actual.OwnerReferences) != 0 || originalObjectSHA(actual.Spec) != w.specSHA {
			return nil, ErrInstall
		}
		process, err := originalMaintenancePodIdentity(actual)
		if err != nil || !reflect.DeepEqual(process, w.process) {
			return nil, ErrInstall
		}
		recovered[process.Node] = append(recovered[process.Node], process)
	}
	for _, g := range s.gateways {
		g.recovery = fence
		if g.checkIncarnation(ctx) != nil || g.currentBinding(ctx, false) != nil {
			return nil, ErrInstall
		}
		if g.state.Running {
			agent, ok := g.agent.(services.BackupGatewayAgent)
			if !ok {
				return nil, ErrInstall
			}
			state, err := agent.GatewayState(ctx, g.row.Endpoint, g.row.Gateway)
			if err != nil || state == nil || state.State != "running" || state.UserID != g.source.UserID || state.InstanceID != g.source.ID || state.Generation != g.source.Generation || state.GatewayID != g.row.Gateway || state.PID != g.row.PID || state.Port != g.row.Port {
				return nil, ErrInstall
			}
			observations = append(observations, *state)
		} else {
			agent, ok := g.agent.(services.RuntimeAgentStoppedBackupClient)
			if !ok || g.request.Stopped == nil {
				return nil, ErrInstall
			}
			inspection, raw, err := agent.InspectStoppedBackup(ctx, g.row.Endpoint, g.request.Stopped.RuntimeStoppedBackupIdentity)
			if err != nil || inspection.Identity != g.request.Stopped.RuntimeStoppedBackupIdentity || inspection.State != "stopped_unreserved" || inspection.Scope != services.RuntimeStoppedBackupScope || inspection.Slot != g.request.Slot || inspection.CheckpointSHA256 != g.request.Stopped.CheckpointSHA256 {
				return nil, ErrInstall
			}
			observations = append(observations, struct {
				Inspection services.RuntimeStoppedBackupInspection
				RawSHA256  string
			}{inspection, hash(raw)})
		}
		if g.checkIncarnation(ctx) != nil {
			return nil, ErrInstall
		}
	}
	for _, original := range s.stoppedObservations {
		// Borrow ONLY the existing read-only baseline checker; no P7 anchor,
		// opaque handle or native stopped/recovered ACK is constructed here.
		reader := &originalStoppedProMaintenance{owner: s.owner, original: original, recovery: fence}
		if original == nil || reader.recheckSources(ctx) != nil {
			return nil, ErrInstall
		}
	}
	if s.recheckOriginalRecoveredAPI(ctx, fence, recovered) != nil {
		return nil, ErrInstall
	}
	tx, err := fence.operator.installer.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	sources, err := domain.ReadSourceInstances(ctx, tx)
	if err != nil || !reflect.DeepEqual(sources, s.owner.instances) || tx.Rollback() != nil || fence.checkReleasing(ctx) != nil {
		return nil, ErrInstall
	}
	return observations, nil
}
