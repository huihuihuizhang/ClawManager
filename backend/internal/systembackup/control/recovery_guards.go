package control

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"clawreef/internal/systembackup/recovery"
)

// Every operation takes the singleton recovery mutex AFTER its task fence.
// It serializes registration, leases, holds and retention selection, including
// group membership changes. Remote calls never execute inside SQL transactions.
type RecoveryGuards struct {
	Store SQLStore
	Task  Task
}
type RecoveryLease struct {
	Artifact, Task, Consumer string
	Generation, Until        int64
}
type LeaseStopProof struct {
	Lease    RecoveryLease
	Evidence recovery.Reference
	Stopped  bool
}
type LeaseStopVerifier interface {
	VerifyStopped(context.Context, RecoveryLease) (LeaseStopProof, error)
}
type FrozenPrune struct {
	ID                              string
	CreatedAt, ExpiresAt, Retention int64
	Minimum                         int
	Groups                          []recovery.RecoveryGroup
	Plan                            recovery.PrunePlan
}
type PruneDispatch struct {
	Run, CandidateSHA256, FirstActor string
	Artifact                         recovery.PruneArtifact
	Deadline                         int64
}
type PruneObservation struct {
	Dispatch          PruneDispatch
	AllVersionsAbsent bool
	WriterStopped     bool
	Evidence          recovery.Reference
	DeletedAt         int64
}
type PruneProvider interface {
	// The owner must enforce deadline/identity at the storage boundary.
	Delete(context.Context, PruneDispatch) (PruneObservation, error)
	Observe(context.Context, PruneDispatch) (PruneObservation, error)
}
type PruneResult struct {
	Deleted int
	Pending bool
}

func (g RecoveryGuards) begin(ctx context.Context) (*sql.Tx, int64, error) {
	tx, e := g.Store.begin(ctx)
	if e != nil {
		return nil, 0, e
	}
	if g.Store.Fence(ctx, tx, g.Task) != nil {
		tx.Rollback()
		return nil, 0, ErrFence
	}
	var lock int
	if tx.QueryRowContext(ctx, "SELECT guard_id FROM system_backup_recovery_mutex WHERE guard_id=1 FOR UPDATE").Scan(&lock) != nil || lock != 1 {
		tx.Rollback()
		return nil, 0, ErrNotReady
	}
	n, e := now(ctx, tx)
	if e != nil {
		tx.Rollback()
		return nil, 0, e
	}
	return tx, n, nil
}
func (g RecoveryGuards) commit(ctx context.Context, tx *sql.Tx) error {
	if g.Store.Fence(ctx, tx, g.Task) != nil {
		return ErrFence
	}
	if tx.Commit() != nil {
		return ErrNotReady
	}
	return nil
}
func readGuard(ctx context.Context, tx *sql.Tx, id string) (recovery.PruneArtifact, error) {
	var a recovery.PruneArtifact
	var raw []byte
	e := tx.QueryRowContext(ctx, "SELECT artifact_json FROM system_backup_recovery_guards WHERE artifact_id=? FOR UPDATE", id).Scan(&raw)
	if errors.Is(e, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	if e != nil || json.Unmarshal(raw, &a) != nil || a.ID != id {
		return a, ErrNotReady
	}
	return a, nil
}
func saveGuard(ctx context.Context, tx *sql.Tx, a recovery.PruneArtifact) error {
	b, e := recovery.Marshal(a)
	if e != nil {
		return ErrInvalid
	}
	return changed(tx.ExecContext(ctx, "UPDATE system_backup_recovery_guards SET artifact_json=? WHERE artifact_id=?", b, a.ID))
}

// Register must be called by a verified publication/import owner. It accepts
// no external API request and cannot promote a functional artifact to acceptance.
func (g RecoveryGuards) Register(ctx context.Context, a recovery.PruneArtifact) error {
	if !a.Terminal || a.State != "committed" && a.State != "corrupt" || a.CommittedAt <= 0 || a.FinishedAt <= 0 || a.ManualHold || a.PromotionHold || a.ActiveFinalizer || a.LeaseUntil != 0 || a.GuardVersion != 1 {
		return ErrInvalid
	}
	if _, e := recovery.PlanRetention(a.CommittedAt, 0, 1, []recovery.RecoveryGroup{a.Group}, []recovery.PruneArtifact{a}, recovery.Reference{ID: "registration", Version: "v1", SHA256: recovery.Hash([]byte(a.ID))}); e != nil {
		return ErrInvalid
	}
	tx, n, e := g.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if a.CommittedAt > n || a.FinishedAt > n {
		return ErrInvalid
	}
	previous, e := readGuard(ctx, tx, a.ID)
	if e == nil {
		copy := previous
		copy.GuardVersion = 1
		copy.ManualHold = false
		copy.PromotionHold = false
		copy.LeaseUntil = 0
		if !sameDocument(copy, a) {
			return ErrConflict
		}
		return nil
	}
	if !errors.Is(e, ErrNotFound) {
		return e
	}
	b, _ := recovery.Marshal(a)
	if _, e = tx.ExecContext(ctx, "INSERT INTO system_backup_recovery_guards(artifact_id,artifact_json) VALUES(?,?)", a.ID, b); e != nil {
		return ErrNotReady
	}
	return g.commit(ctx, tx)
}
func (g RecoveryGuards) Hold(ctx context.Context, id string, expected int64, manual, promotion bool) error {
	tx, _, e := g.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	a, e := readGuard(ctx, tx, id)
	if e != nil {
		return e
	}
	if a.GuardVersion != expected || a.State != "committed" && a.State != "corrupt" {
		return ErrConflict
	}
	a.ManualHold = manual
	a.PromotionHold = promotion
	a.GuardVersion++
	if e = saveGuard(ctx, tx, a); e != nil {
		return e
	}
	return g.commit(ctx, tx)
}
func (g RecoveryGuards) Acquire(ctx context.Context, id string, ttl time.Duration) (RecoveryLease, error) {
	return g.AcquireFor(ctx, id, "task", ttl)
}
func (g RecoveryGuards) AcquireFor(ctx context.Context, id, consumer string, ttl time.Duration) (RecoveryLease, error) {
	var out RecoveryLease
	if !identifier.MatchString(id) || !identifier.MatchString(consumer) || ttl < time.Second || ttl > 15*time.Minute {
		return out, ErrInvalid
	}
	tx, n, e := g.begin(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	if g.Task.Request.Kind != "drill" && g.Task.Request.Kind != "preflight" && g.Task.Request.Kind != "catalog_import" || n >= g.Task.Deadline {
		return out, ErrFence
	}
	a, e := readGuard(ctx, tx, id)
	if e != nil {
		return out, e
	}
	if a.State != "committed" && a.State != "corrupt" {
		return out, ErrConflict
	}
	until := n + ttl.Milliseconds()
	if until > g.Task.Deadline {
		until = g.Task.Deadline
	}
	var priorGeneration int64
	var released bool
	e = tx.QueryRowContext(ctx, "SELECT generation,released FROM system_backup_recovery_leases WHERE artifact_id=? AND task_id=? AND consumer_id=? FOR UPDATE", id, g.Task.ID, consumer).Scan(&priorGeneration, &released)
	if e == nil && (released || priorGeneration > g.Task.Generation) {
		return out, ErrConflict
	}
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return out, ErrNotReady
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO system_backup_recovery_leases(artifact_id,task_id,consumer_id,generation,until_ms,released) VALUES(?,?,?,?,?,FALSE) ON DUPLICATE KEY UPDATE generation=VALUES(generation),until_ms=VALUES(until_ms)", id, g.Task.ID, consumer, g.Task.Generation, until); e != nil {
		return out, ErrNotReady
	}
	a.GuardVersion++
	if e = saveGuard(ctx, tx, a); e != nil {
		return out, e
	}
	if e = g.commit(ctx, tx); e != nil {
		return out, e
	}
	return RecoveryLease{id, g.Task.ID, consumer, g.Task.Generation, until}, nil
}
func (g RecoveryGuards) Check(ctx context.Context, l RecoveryLease) error {
	tx, n, e := g.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if l.Task != g.Task.ID || l.Generation != g.Task.Generation || !identifier.MatchString(l.Consumer) {
		return ErrFence
	}
	a, e := readGuard(ctx, tx, l.Artifact)
	if e != nil {
		return e
	}
	if a.State != "committed" && a.State != "corrupt" {
		return ErrConflict
	}
	var generation, until int64
	var released bool
	if tx.QueryRowContext(ctx, "SELECT generation,until_ms,released FROM system_backup_recovery_leases WHERE artifact_id=? AND task_id=? AND consumer_id=? FOR UPDATE", l.Artifact, l.Task, l.Consumer).Scan(&generation, &until, &released) != nil || released || generation != l.Generation || until <= n {
		return ErrFence
	}
	return nil
}

// Release follows positive consumer/worker-stop proof. Expiry alone leaves an
// unreleased row and blocks deletion, even after a controller crash.
func (g RecoveryGuards) Release(ctx context.Context, l RecoveryLease, verifier LeaseStopVerifier) error {
	if verifier == nil || l.Task != g.Task.ID || l.Generation != g.Task.Generation || !identifier.MatchString(l.Consumer) {
		return ErrInvalid
	}
	proof, e := verifier.VerifyStopped(ctx, l)
	if e != nil || proof.Lease != l || !proof.Stopped || proof.Evidence.Validate() != nil {
		return ErrNotReady
	}
	tx, _, e := g.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	a, e := readGuard(ctx, tx, l.Artifact)
	if e != nil {
		return e
	}
	var generation int64
	var released bool
	if tx.QueryRowContext(ctx, "SELECT generation,released FROM system_backup_recovery_leases WHERE artifact_id=? AND task_id=? AND consumer_id=? FOR UPDATE", l.Artifact, l.Task, l.Consumer).Scan(&generation, &released) != nil || generation != l.Generation {
		return ErrFence
	}
	if released {
		return nil
	}
	b, _ := recovery.Marshal(proof.Evidence)
	if e = changed(tx.ExecContext(ctx, "UPDATE system_backup_recovery_leases SET released=TRUE,proof_json=? WHERE artifact_id=? AND task_id=? AND consumer_id=? AND generation=? AND released=FALSE", b, l.Artifact, l.Task, l.Consumer, l.Generation)); e != nil {
		return e
	}
	a.GuardVersion++
	if e = saveGuard(ctx, tx, a); e != nil {
		return e
	}
	return g.commit(ctx, tx)
}
func guardInventory(ctx context.Context, tx *sql.Tx, at int64) ([]recovery.PruneArtifact, error) {
	rows, e := tx.QueryContext(ctx, "SELECT artifact_json,(SELECT COUNT(*) FROM system_backup_recovery_leases l WHERE l.artifact_id=g.artifact_id AND l.released=FALSE) FROM system_backup_recovery_guards g ORDER BY artifact_id FOR UPDATE")
	if e != nil {
		return nil, ErrNotReady
	}
	defer rows.Close()
	out := []recovery.PruneArtifact{}
	for rows.Next() {
		var b []byte
		var leases int
		var a recovery.PruneArtifact
		if rows.Scan(&b, &leases) != nil || json.Unmarshal(b, &a) != nil || len(out) >= 100000 {
			return nil, ErrNotReady
		}
		if leases > 0 {
			a.LeaseUntil = at + 1
		}
		out = append(out, a)
	}
	if rows.Err() != nil {
		return nil, ErrNotReady
	}
	return out, nil
}
func (g RecoveryGuards) FreezePrune(ctx context.Context, id string, retention int64, minimum int, groups []recovery.RecoveryGroup, config recovery.Reference) (FrozenPrune, error) {
	var p FrozenPrune
	if !identifier.MatchString(id) {
		return p, ErrInvalid
	}
	tx, n, e := g.begin(ctx)
	if e != nil {
		return p, e
	}
	defer tx.Rollback()
	var stored []byte
	e = tx.QueryRowContext(ctx, "SELECT plan_json FROM system_backup_v2_prune_runs WHERE run_id=? AND task_id=? FOR UPDATE", id, g.Task.ID).Scan(&stored)
	if e == nil {
		if json.Unmarshal(stored, &p) != nil || p.Retention != retention || p.Minimum != minimum || !sameDocument(p.Groups, groups) || p.Plan.Config != config {
			return p, ErrConflict
		}
		return p, nil
	}
	if !errors.Is(e, sql.ErrNoRows) || n >= g.Task.Deadline {
		return p, ErrNotReady
	}
	rows, e := guardInventory(ctx, tx, n)
	if e != nil {
		return p, e
	}
	plan, e := recovery.PlanRetention(n, retention, minimum, groups, rows, config)
	if e != nil {
		return p, e
	}
	until := n + int64((15*time.Minute)/time.Millisecond)
	if until > g.Task.Deadline {
		until = g.Task.Deadline
	}
	p = FrozenPrune{id, n, until, retention, minimum, groups, plan}
	b, _ := recovery.Marshal(p)
	if _, e = tx.ExecContext(ctx, "INSERT INTO system_backup_v2_prune_runs(run_id,task_id,plan_json,run_state) VALUES(?,?,?,'prepared')", id, g.Task.ID, b); e != nil {
		return p, ErrNotReady
	}
	return p, g.commit(ctx, tx)
}

// Claim atomically re-evaluates ALL retention groups and claims every candidate.
// Once claimed, no lease/hold/registration can change those artifact identities.
func (g RecoveryGuards) ClaimPrune(ctx context.Context, p FrozenPrune) error {
	tx, n, e := g.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var b []byte
	var state string
	if tx.QueryRowContext(ctx, "SELECT plan_json,run_state FROM system_backup_v2_prune_runs WHERE run_id=? AND task_id=? FOR UPDATE", p.ID, g.Task.ID).Scan(&b, &state) != nil || !sameDocument(json.RawMessage(b), p) {
		return ErrConflict
	}
	if state == "claimed" || state == "completed" {
		return nil
	}
	if state != "prepared" || n >= p.ExpiresAt {
		return ErrConflict
	}
	rows, e := guardInventory(ctx, tx, p.CreatedAt)
	if e != nil {
		return e
	}
	current, e := recovery.PlanRetention(p.CreatedAt, p.Retention, p.Minimum, p.Groups, rows, p.Plan.Config)
	if e != nil || current.SHA256 != p.Plan.SHA256 {
		return ErrConflict
	}
	for _, a := range p.Plan.Candidates {
		a.State = "deleting"
		a.GuardVersion++
		if e = saveGuard(ctx, tx, a); e != nil {
			return e
		}
		d := PruneDispatch{p.ID, p.Plan.SHA256, strconv.Itoa(g.Task.Actor), a, p.ExpiresAt}
		raw, _ := recovery.Marshal(d)
		if _, e = tx.ExecContext(ctx, "INSERT INTO system_backup_v2_prune_items(run_id,artifact_id,dispatch_json,item_state) VALUES(?,?,?,'prepared')", p.ID, a.ID, raw); e != nil {
			return ErrNotReady
		}
	}
	if e = changed(tx.ExecContext(ctx, "UPDATE system_backup_v2_prune_runs SET run_state='claimed' WHERE run_id=? AND run_state='prepared'", p.ID)); e != nil {
		return e
	}
	return g.commit(ctx, tx)
}
func (g RecoveryGuards) dispatch(ctx context.Context, p FrozenPrune, id string) (PruneDispatch, string, error) {
	tx, n, e := g.begin(ctx)
	if e != nil {
		return PruneDispatch{}, "", e
	}
	defer tx.Rollback()
	var b []byte
	var state string
	var d PruneDispatch
	if tx.QueryRowContext(ctx, "SELECT dispatch_json,item_state FROM system_backup_v2_prune_items WHERE run_id=? AND artifact_id=? FOR UPDATE", p.ID, id).Scan(&b, &state) != nil || json.Unmarshal(b, &d) != nil || d.Run != p.ID || d.CandidateSHA256 != p.Plan.SHA256 {
		return d, state, ErrConflict
	}
	if state != "prepared" {
		return d, state, nil
	}
	if n >= d.Deadline {
		return d, state, ErrFence
	}
	if e = changed(tx.ExecContext(ctx, "UPDATE system_backup_v2_prune_items SET item_state='request_sent' WHERE run_id=? AND artifact_id=? AND item_state='prepared'", p.ID, id)); e != nil {
		return d, state, e
	}
	if e = g.commit(ctx, tx); e != nil {
		return d, "", e
	}
	return d, "send", nil
}
func (g RecoveryGuards) confirm(ctx context.Context, d PruneDispatch, o PruneObservation) error {
	if !sameDocument(d, o.Dispatch) || !o.AllVersionsAbsent || !o.WriterStopped || o.Evidence.Validate() != nil || o.DeletedAt <= 0 {
		return ErrNotReady
	}
	tx, n, e := g.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if o.DeletedAt > n || o.DeletedAt < d.Artifact.CommittedAt {
		return ErrInvalid
	}
	var raw []byte
	var state string
	if tx.QueryRowContext(ctx, "SELECT dispatch_json,item_state FROM system_backup_v2_prune_items WHERE run_id=? AND artifact_id=? FOR UPDATE", d.Run, d.Artifact.ID).Scan(&raw, &state) != nil || !sameDocument(json.RawMessage(raw), d) {
		return ErrConflict
	}
	if state == "completed" {
		return nil
	}
	if state != "request_sent" {
		return ErrConflict
	}
	a, e := readGuard(ctx, tx, d.Artifact.ID)
	if e != nil {
		return e
	}
	if !sameDocument(a, d.Artifact) {
		return ErrConflict
	}
	a.State = "deleted"
	a.GuardVersion++
	if e = saveGuard(ctx, tx, a); e != nil {
		return e
	}
	b, _ := recovery.Marshal(o)
	if e = changed(tx.ExecContext(ctx, "UPDATE system_backup_v2_prune_items SET item_state='completed',observation_json=? WHERE run_id=? AND artifact_id=? AND item_state='request_sent'", b, d.Run, a.ID)); e != nil {
		return e
	}
	return g.commit(ctx, tx)
}

// Abort is allowed only before any external dispatch. A request_sent record
// must first receive positive absence and writer-stop evidence; it cannot be
// reset to prepared by cancellation or lease expiry.
func (g RecoveryGuards) AbortPrune(ctx context.Context, p FrozenPrune) error {
	tx, _, e := g.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var raw []byte
	var state string
	if tx.QueryRowContext(ctx, "SELECT plan_json,run_state FROM system_backup_v2_prune_runs WHERE run_id=? AND task_id=? FOR UPDATE", p.ID, g.Task.ID).Scan(&raw, &state) != nil || !sameDocument(json.RawMessage(raw), p) {
		return ErrConflict
	}
	if state == "canceled" {
		return nil
	}
	if state != "prepared" && state != "claimed" {
		return ErrConflict
	}
	var sent int
	if tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_prune_items WHERE run_id=? AND item_state<>'prepared'", p.ID).Scan(&sent) != nil || sent != 0 {
		return ErrConflict
	}
	if state == "claimed" {
		for _, old := range p.Plan.Candidates {
			a, e := readGuard(ctx, tx, old.ID)
			if e != nil {
				return e
			}
			expected := old
			expected.State = "deleting"
			expected.GuardVersion++
			if !sameDocument(a, expected) {
				return ErrConflict
			}
			old.GuardVersion = a.GuardVersion + 1
			if e = saveGuard(ctx, tx, old); e != nil {
				return e
			}
		}
	}
	if _, e = tx.ExecContext(ctx, "UPDATE system_backup_v2_prune_runs SET run_state='canceled' WHERE run_id=? AND task_id=?", p.ID, g.Task.ID); e != nil {
		return ErrNotReady
	}
	return g.commit(ctx, tx)
}

type PruneJournalProof struct {
	Guards        RecoveryGuards
	Run, Artifact string
}

func (p PruneJournalProof) evidence(ctx context.Context) (PruneDispatch, PruneObservation, error) {
	tx, _, e := p.Guards.begin(ctx)
	if e != nil {
		return PruneDispatch{}, PruneObservation{}, e
	}
	defer tx.Rollback()
	var d PruneDispatch
	var o PruneObservation
	var raw, observation []byte
	var state string
	if tx.QueryRowContext(ctx, "SELECT i.dispatch_json,i.item_state,i.observation_json FROM system_backup_v2_prune_items i JOIN system_backup_v2_prune_runs r ON r.run_id=i.run_id WHERE i.run_id=? AND i.artifact_id=? AND r.task_id=? FOR UPDATE", p.Run, p.Artifact, p.Guards.Task.ID).Scan(&raw, &state, &observation) != nil || state != "completed" || json.Unmarshal(raw, &d) != nil || json.Unmarshal(observation, &o) != nil || !sameDocument(d, o.Dispatch) || !o.AllVersionsAbsent || !o.WriterStopped || o.Evidence.Validate() != nil {
		return d, o, ErrNotReady
	}
	a, e := readGuard(ctx, tx, p.Artifact)
	if e != nil || a.State != "deleted" || a.Locator != d.Artifact.Locator || a.Core != d.Artifact.Core {
		return d, o, ErrConflict
	}
	return d, o, nil
}
func (p PruneJournalProof) Evidence(ctx context.Context) (recovery.DeletionProof, error) {
	d, o, e := p.evidence(ctx)
	if e != nil {
		return recovery.DeletionProof{}, e
	}
	if d.Artifact.RegistrationID == "" {
		return recovery.DeletionProof{}, ErrInvalid
	}
	return recovery.DeletionProof{RegistrationID: d.Artifact.RegistrationID, RegistrationSHA256: d.Artifact.RegistrationSHA256, PruneRun: d.Run, CandidateSHA256: d.CandidateSHA256, FirstActor: d.FirstActor, DeletedAt: o.DeletedAt, Evidence: o.Evidence}, nil
}
func (p PruneJournalProof) VerifyDeleted(ctx context.Context, r recovery.Registration, proof recovery.DeletionProof) error {
	d, o, e := p.evidence(ctx)
	if e != nil {
		return e
	}
	expected := recovery.DeletionProof{RegistrationID: d.Artifact.RegistrationID, RegistrationSHA256: d.Artifact.RegistrationSHA256, PruneRun: d.Run, CandidateSHA256: d.CandidateSHA256, FirstActor: d.FirstActor, DeletedAt: o.DeletedAt, Evidence: o.Evidence}
	if !sameDocument(expected, proof) || r.Locator != d.Artifact.Locator || r.Core != d.Artifact.Core || recovery.RegistrationID(r.Identity) != proof.RegistrationID {
		return ErrConflict
	}
	return nil
}

// ExecutePrune has no built-in provider. The host must supply a native owner
// implementation. An uncertain send is observed on retry, never resent.
func (g RecoveryGuards) ExecutePrune(ctx context.Context, p FrozenPrune, provider PruneProvider) (PruneResult, error) {
	var out PruneResult
	if provider == nil {
		return out, ErrNotReady
	}
	if e := g.ClaimPrune(ctx, p); e != nil {
		return out, e
	}
	for _, a := range p.Plan.Candidates {
		d, state, e := g.dispatch(ctx, p, a.ID)
		if e != nil {
			return out, e
		}
		if state == "completed" {
			out.Deleted++
			continue
		}
		var o PruneObservation
		if state == "send" {
			o, e = provider.Delete(ctx, d)
		} else if state == "request_sent" {
			o, e = provider.Observe(ctx, d)
		} else {
			return out, ErrConflict
		}
		if e != nil {
			out.Pending = true
			return out, ErrNotReady
		}
		if e = g.confirm(ctx, d, o); e != nil {
			out.Pending = true
			return out, e
		}
		out.Deleted++
	}
	tx, _, e := g.begin(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	var pending int
	if tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_prune_items WHERE run_id=? AND item_state<>'completed'", p.ID).Scan(&pending) != nil || pending != 0 {
		return out, ErrConflict
	}
	if _, e = tx.ExecContext(ctx, "UPDATE system_backup_v2_prune_runs SET run_state='completed' WHERE run_id=? AND task_id=?", p.ID, g.Task.ID); e != nil {
		return out, ErrNotReady
	}
	return out, g.commit(ctx, tx)
}
