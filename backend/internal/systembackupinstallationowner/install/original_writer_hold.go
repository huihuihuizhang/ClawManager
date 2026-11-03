package install

import (
	"context"
	"database/sql"
	"reflect"
	"sync"
	"time"

	"clawreef/internal/systembackup/domain"
	q "clawreef/internal/systembackup/quiesce"
	c "clawreef/internal/systembackupcontroller"
)

// OriginalWriterHold is created only by the complete original factory after
// all physical I/O and both actual gate transitions. It is neither JSON nor a
// PreparedCoverage. It cannot be recreated from its public inspection data.
type OriginalWriterHold struct {
	origin          *OriginalWriterHold
	set             *PreparedOriginalWriterSet
	ctx             context.Context
	providers       []*OriginalAdoptionArchiveProvider
	adoptionUnknown bool
	closed          bool
}

func (*OriginalWriterHold) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (*OriginalWriterHold) String() string               { return "OriginalWriterHold" }
func (*OriginalWriterHold) GoString() string             { return "OriginalWriterHold" }

type originalHeldReadiness struct {
	set    *PreparedOriginalWriterSet
	digest string
}

// Acquire performs real source operations. Individual API disappearance or an
// Agent 202 is not a held ACK. Stop dispatches precede the complete independent
// node FD/mmap/namespace proofs; all originals remain journaled on any failure.
func (s *PreparedOriginalWriterSet) Acquire(ctx context.Context) (*OriginalWriterHold, error) {
	if s == nil {
		return nil, ErrInstall
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s == nil || s.origin != s || s.recheckPreflight(ctx) != nil {
		return nil, ErrInstall
	}
	s.used = true
	if s.journal.append(ctx, "", "capture_gate_acquire_send_unknown", nil, s.owner.policy) != nil {
		return nil, ErrInstall
	}
	if _, err := s.owner.BeginAcquisition(ctx); err != nil {
		return nil, err
	}
	if s.beginApplicationGate(ctx) != nil {
		return nil, ErrCommitUnknown
	}
	nodes, err := s.prepareNativeScopes(ctx)
	if err != nil {
		return nil, err
	}
	s.nodes = nodes
	for _, g := range s.gateways {
		if g.prepareNative(ctx) != nil {
			return nil, ErrInstall
		}
	}
	for _, observed := range s.stoppedObservations {
		source, err := s.owner.newStoppedProMaintenance(ctx, observed, s.stoppedProClient, s.journal)
		if err != nil {
			return nil, err
		}
		s.stopped = append(s.stopped, source)
	}
	// Journal and permission/recovery preflight for every actor finished above.
	// Application admission is already closed before the first source mutation.
	for _, w := range s.deployments {
		if w.stop(ctx) != nil {
			return nil, ErrInstall
		}
	}
	for _, w := range s.proPods {
		if w.stop(ctx) != nil {
			return nil, ErrInstall
		}
	}
	for _, g := range s.gateways {
		if g.dispatchStop(ctx) != nil {
			return nil, ErrInstall
		}
	}
	// A stopped-Pro prepare may run after genuine management writers have
	// stopped; its original CURRENT SQL/API/volume baseline was read beforehand.
	for _, source := range s.stopped {
		if source.observe(ctx, "prepare") != nil {
			return nil, ErrInstall
		}
	}
	proof, err := s.refreshNativeHold(ctx)
	if err != nil {
		return nil, err
	}
	if s.holdApplicationGate(ctx, proof) != nil {
		return nil, ErrCommitUnknown
	}
	coordinator, err := c.NewSQLGateCoordinator(s.owner.operator.installer.db)
	if err != nil {
		return nil, err
	}
	coordinator.HoldReadiness = proof
	expected := s.owner.token
	expected.State = c.GateHeld
	expected.FencingToken++
	expected.RowVersion++
	if s.journal.append(ctx, "", "capture_gate_hold_commit_unknown", nil, expected) != nil {
		return nil, ErrInstall
	}
	held, err := coordinator.AdvanceHeld(ctx, s.owner.token, s.owner.policy)
	if err != nil {
		return nil, ErrCommitUnknown
	}
	s.owner.token = held
	if s.owner.checkCurrentGate(ctx, c.GateHeld) != nil || s.journal.append(ctx, "", "capture_gate_held_readback", nil, held) != nil {
		return nil, ErrCommitUnknown
	}
	h := &OriginalWriterHold{set: s, ctx: ctx}
	h.origin = h
	s.actualHold = h
	return h, nil
}

// Real native I/O outside the final original SQL prefix. Independent sources
// are sampled concurrently so their fixed short observation windows overlap.
// Every authority check still uses the SAME original context, never an invented
// context/grant or an extended deadline.
func (s *PreparedOriginalWriterSet) refreshNativeHold(ctx context.Context) (*originalHeldReadiness, error) {
	if s.recheckHeldAPI(ctx) != nil {
		return nil, ErrInstall
	}
	var wg sync.WaitGroup
	failures := make(chan error, len(s.nodes)+len(s.gateways)+len(s.stopped)+len(s.deployments))
	run := func(fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(); err != nil {
				failures <- err
			}
		}()
	}
	for _, w := range s.deployments {
		if w.redis != nil {
			r := w.redis
			run(func() error { return r.observeHeld(ctx) })
		}
	}
	for _, node := range s.nodes {
		node := node
		run(func() error { return node.observeStopped(ctx) })
	}
	for _, g := range s.gateways {
		g := g
		run(func() error { return g.CheckPaused(ctx, g.state) })
	}
	for _, source := range s.stopped {
		source := source
		run(func() error { return source.observe(ctx, "stopped") })
	}
	wg.Wait()
	close(failures)
	for range failures {
		return nil, ErrInstall
	}
	if s.recheckHeldAPI(ctx) != nil {
		return nil, ErrInstall
	}
	responses := []any{}
	for _, w := range s.deployments {
		if w.redis != nil {
			responses = append(responses, w.redis.held.Data())
		}
	}
	for _, node := range s.nodes {
		responses = append(responses, node.current.Response())
	}
	for _, g := range s.gateways {
		responses = append(responses, g.proof.Response())
	}
	for _, source := range s.stopped {
		responses = append(responses, source.proof.Response())
	}
	proof := &originalHeldReadiness{set: s, digest: originalObjectSHA(responses)}
	if s.journal.append(ctx, "", "complete_native_paused_observation", nil, struct {
		InventorySHA256, ObservationSHA256 string
		Responses                          []any
	}{s.inventorySHA, proof.digest, responses}) != nil {
		return nil, ErrInstall
	}
	return proof, nil
}

func (s *PreparedOriginalWriterSet) recheckHeldAPI(ctx context.Context) error {
	if s == nil || s.owner.checkCurrentGate(ctx, c.GateAcquiring, c.GateHeld) != nil || s.checkApplicationGate(ctx, "acquiring", "held") != nil || s.owner.checkInstances(ctx) != nil || s.recheckVolumePins(ctx) != nil {
		return ErrInstall
	}
	current, pods, deps, _, err := s.owner.readKubernetesCensus(ctx)
	if err != nil || len(deps) != len(s.initial.Deployments) || !reflect.DeepEqual(current.PVCs, s.initial.PVCs) || len(current.StatefulSets)+len(current.DaemonSets)+len(current.Jobs)+len(current.CronJobs)+len(current.Autoscalers) != 0 {
		return ErrInstall
	}
	writers := map[string]*originalDeploymentMaintenance{}
	for _, w := range s.deployments {
		if w.redis != nil {
			if w.redis.check(ctx) != nil {
				return ErrInstall
			}
			continue
		}
		writers[w.selection.Name] = w
		d, e := w.current(ctx)
		if e != nil || *d.Spec.Replicas != 0 || d.Status.Replicas != 0 || d.Status.ObservedGeneration < d.Generation {
			return ErrInstall
		}
	}
	for _, dep := range current.Deployments {
		if writers[dep.Name] != nil {
			continue
		}
		found := false
		for _, old := range s.initial.Deployments {
			if dep == old {
				found = true
			}
		}
		if !found {
			return ErrInstall
		}
	}
	allowedPodUIDs := map[string]bool{}
	for _, pod := range pods {
		oldFound := false
		for _, old := range s.initial.Pods {
			if string(pod.UID) == old.UID {
				oldFound = true
			}
		}
		if !oldFound {
			return ErrInstall
		}
		for _, w := range s.deployments {
			if w.redis != nil {
				continue
			}
			for _, old := range w.pods {
				if old.UID == string(pod.UID) {
					return ErrInstall
				}
			}
		}
		for _, w := range s.proPods {
			if w.original.UID == string(pod.UID) {
				return ErrInstall
			}
		}
		allowedPodUIDs[string(pod.UID)] = true
	}
	for _, g := range s.gateways {
		if !allowedPodUIDs[g.row.UID] || g.currentBinding(ctx, false) != nil {
			return ErrInstall
		}
	}
	return nil
}

// This is the actual production GateHoldReadinessVerifier. It accepts only a
// concrete original SQL transaction and concrete B-minted opaque observations.
// No native/network/provider call occurs with the SQL source locks held.
func (p *originalHeldReadiness) VerifyParticipantsPaused(ctx context.Context, coord c.CoordinationTransaction, key c.GateKey, generation uint64) error {
	if p == nil || p.set == nil || p.digest == "" {
		return ErrInstall
	}
	s := p.set
	owner := s.owner
	if !consumerSameContext(ctx, owner.ctx) || !owner.operator.live(ctx) || owner.token.Key != key || owner.token.Generation != generation || owner.token.State != c.GateAcquiring && owner.token.State != c.GateHeld {
		return ErrInstall
	}
	var tx *sql.Tx
	switch t := coord.(type) {
	case c.SQLCoordinationTransaction:
		tx = t.Tx
	case *originalMaintenanceCommit:
		tx = t.Tx
	default:
		return ErrInstall
	}
	if tx == nil {
		return ErrInstall
	}
	var now time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || !now.Before(owner.until) {
		return ErrInstall
	}
	if _, err := owner.operator.lockAdmin(ctx, tx); err != nil {
		return ErrInstall
	}
	head, err := owner.operator.current(ctx, tx, false)
	if err != nil || head.cas != owner.initial {
		return ErrInstall
	}
	instances, err := domain.ReadSourceInstances(ctx, tx)
	if err != nil || !reflect.DeepEqual(instances, owner.instances) {
		return ErrInstall
	}
	var appPhase, appOwner, appInventory string
	var appGeneration, appToken uint64
	var appLive bool
	if tx.QueryRowContext(ctx, `SELECT phase,owner,generation,fencing_token,registry_hash,hold_deadline>UTC_TIMESTAMP(6) FROM system_backup_gate WHERE scope=? FOR SHARE`, s.application.scope).Scan(&appPhase, &appOwner, &appGeneration, &appToken, &appInventory, &appLive) != nil || !appLive || appPhase != s.application.phase || appOwner != s.application.owner || appGeneration != s.application.generation || appToken != s.application.token || appInventory != s.inventorySHA {
		return ErrInstall
	}
	var leases uint64
	if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_mutation_leases WHERE scope=? AND released_at IS NULL`, s.application.scope).Scan(&leases) != nil || leases != 0 {
		return ErrInstall
	}
	rows, err := tx.QueryContext(ctx, `SELECT participant_id,generation,state FROM system_backup_participants WHERE scope=? ORDER BY participant_id FOR SHARE`, s.application.scope)
	if err != nil {
		return ErrInstall
	}
	actual := map[string]bool{}
	for rows.Next() {
		var id, state string
		var generation uint64
		if rows.Scan(&id, &generation, &state) != nil || generation != s.application.generation || appPhase == "held" && state != "paused" || appPhase == "acquiring" && state != "pausing" {
			rows.Close()
			return ErrInstall
		}
		actual[id] = true
	}
	if rows.Err() != nil || rows.Close() != nil || len(actual) != len(s.application.participants) {
		return ErrInstall
	}
	for _, p := range s.application.participants {
		if !actual[p.ID] {
			return ErrInstall
		}
	}
	if len(s.deployments)+len(s.proPods) == 0 || len(s.nodes) == 0 && len(s.stopped) == 0 {
		return ErrInstall
	}
	for _, w := range s.deployments {
		if w.redis != nil && (w.redis.held == nil || w.redis.held.Recheck(ctx, owner.operation, s.inventorySHA, "held", now) != nil) {
			return ErrInstall
		}
	}
	for _, node := range s.nodes {
		if node.current == nil || node.current.Recheck(ctx, node.request.Binding, "stopped", node.boot, now) != nil {
			return ErrInstall
		}
	}
	for _, g := range s.gateways {
		if g.proof == nil || g.proof.Recheck(ctx, g.request.Binding, "stopped", g.boot, originalObjectSHA(g.state), hash(g.raw), hash(g.completion), now) != nil {
			return ErrInstall
		}
	}
	for _, source := range s.stopped {
		if source.proof == nil || q.StoppedProNativeScopeSHA256(source.request) != source.claim.NativeRequestSHA256 || source.proof.Response().NativeScopeSHA256 != source.claim.NativeRequestSHA256 || source.proof.Recheck(ctx, source.request.Binding, "stopped", source.boot, q.StoppedProBaselineSHA256(source.request.Baseline), source.request.OriginalReservationIdentitySHA256, originalObjectSHA(source.state), source.claim.NativeRequestSHA256, now) != nil {
			return ErrInstall
		}
	}
	return nil
}

func (h *OriginalWriterHold) RecheckBeforeOriginalSQL(ctx context.Context) error {
	if h == nil || h.set == nil {
		return ErrInstall
	}
	h.set.mu.Lock()
	defer h.set.mu.Unlock()
	return h.recheckBeforeSQL(ctx)
}

func (h *OriginalWriterHold) recheckBeforeSQL(ctx context.Context) error {
	if h == nil || h.origin != h || h.closed || h.adoptionUnknown || !consumerSameContext(ctx, h.ctx) || h.set.owner.checkCurrentGate(ctx, c.GateHeld) != nil {
		return ErrInstall
	}
	if h.set.historyMounted == nil || h.set.historyMounted.installer != h.set.owner.operator.installer || h.set.historyMounted.recheckReferences(ctx) != nil {
		return ErrInstall
	}
	_, err := h.set.refreshNativeHold(ctx)
	return err
}

// The actual C provider is registered BEFORE it can start a native copy. Its
// concrete Stop will later cancel/wait; callers cannot replace it with a bool.
func (h *OriginalWriterHold) PrepareArchiveProvider(ctx context.Context, password []byte, enrollment EnrollmentPin, nodeName, sourceFile, sourceSHA string) (*OriginalAdoptionArchiveProvider, error) {
	if h == nil || h.set == nil {
		return nil, ErrInstall
	}
	h.set.mu.Lock()
	defer h.set.mu.Unlock()
	if h.recheckBeforeSQL(ctx) != nil {
		return nil, ErrInstall
	}
	var scope *originalWholeNodeScope
	for _, node := range h.set.nodes {
		if node.request.Binding.Node == nodeName {
			scope = node
		}
	}
	if scope == nil {
		return nil, ErrInstall
	}
	claim := scope.claim
	claim.Phase = c.GateHeld
	if h.set.journal.append(ctx, scope.claim.WriterID, "archive_provider_prepare", nil, struct {
		Claim                    c.OriginalAdoptionReservation
		SourceFile, SourceSHA256 string
	}{claim, sourceFile, sourceSHA}) != nil {
		return nil, ErrInstall
	}
	provider, err := h.set.owner.operator.installer.PrepareOriginalAdoptionArchiveProvider(ctx, password, enrollment, claim, sourceFile, sourceSHA)
	if err != nil {
		return nil, err
	}
	if !consumerSameContext(provider.outer, ctx) || provider.reservation.OperationID != h.set.owner.operation || provider.until.After(h.set.owner.until) {
		provider.Close()
		return nil, ErrInstall
	}
	h.providers = append(h.providers, provider)
	return provider, nil
}

func (h *OriginalWriterHold) ArchiveNativeCut(ctx context.Context, nodeName string) (q.NodeObservationRequest, *q.VerifiedNodeObservation, *q.NodeObservationClient, error) {
	if h == nil || h.set == nil {
		return q.NodeObservationRequest{}, nil, nil, ErrInstall
	}
	h.set.mu.Lock()
	defer h.set.mu.Unlock()
	if h.recheckBeforeSQL(ctx) != nil {
		return q.NodeObservationRequest{}, nil, nil, ErrInstall
	}
	for _, node := range h.set.nodes {
		if node.request.Binding.Node == nodeName {
			return node.request, node.prepare, h.set.wholePodClient, nil
		}
	}
	return q.NodeObservationRequest{}, nil, nil, ErrInstall
}
