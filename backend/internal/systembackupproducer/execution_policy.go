package systembackupproducer

import (
	"context"
	"reflect"
	"time"
)

type executionPolicy struct {
	binding            ExecutionBinding
	requestHash        Hash
	environment        ExecutionSession
	capacityObservedAt *time.Time
	facts              ExecutionFacts
	runLock            *LockedRecord
	plan               GuardPlan
	prior, probe       *CallSnapshot
	replayed           bool
	mutate             bool
}

func (p *executionPolicy) LockAndAuthorize(ctx context.Context, tx SQL, scope Scope) (GuardPlan, error) {
	b := p.binding
	env := p.environment
	if scope != b.Scope {
		return GuardPlan{}, ErrInvalid
	}
	if e := env.LockInstallation(ctx, tx, detached(b)); e != nil {
		return GuardPlan{}, e
	}
	l, e := tx.LockRecord(ctx, RecordKey{}, &p.facts.Domain)
	if e != nil {
		return GuardPlan{}, e
	}
	if !l.Found() || p.facts.Domain.State != "open" {
		return GuardPlan{}, ErrGuardRequired
	}
	a, e := env.Authenticate(ctx, tx, detached(b), detached(p.facts.Domain))
	if e != nil {
		return GuardPlan{}, e
	}
	a = detached(a)
	if validateTyped(reflect.ValueOf(a)) != nil || a.RequestHash != p.requestHash || a.IdentityHash != b.Subject {
		return GuardPlan{}, ErrGuardRequired
	}
	if b.Observation == nil {
		if a.AuthenticatedAttestationHash != nil || a.ObservedNotBefore != nil || a.ObservationExpiresNotAfter != nil || a.AdditionalCost != "0" {
			return GuardPlan{}, ErrInvalid
		}
	} else {
		if a.AuthenticatedAttestationHash == nil || *a.AuthenticatedAttestationHash != b.Observation.AttestationHash || a.ObservedNotBefore == nil || a.ObservationExpiresNotAfter == nil || a.AdditionalCost == "0" {
			return GuardPlan{}, ErrGuardRequired
		}
	}
	p.facts.Admission = a
	l, e = tx.LockRecord(ctx, RecordKey{ID: b.GrantID}, &p.facts.Grant)
	if e != nil {
		return GuardPlan{}, e
	}
	if !l.Found() {
		return GuardPlan{}, ErrGuardRequired
	}
	p.runLock, e = tx.LockRecord(ctx, RecordKey{ID: b.RunID}, &p.facts.Run)
	if e != nil {
		return GuardPlan{}, e
	}
	if !p.runLock.Found() {
		return GuardPlan{}, ErrGuardRequired
	}
	if e = env.LockHost(ctx, tx, detached(b), detached(p.facts.Grant)); e != nil {
		return GuardPlan{}, e
	}
	targetHash, e := targetDigest(p.facts.Grant.Target)
	if e != nil {
		return GuardPlan{}, e
	}
	l, e = tx.LockRecord(ctx, RecordKey{Hash: targetHash}, &p.facts.Target)
	if e != nil {
		return GuardPlan{}, e
	}
	if !l.Found() {
		return GuardPlan{}, ErrGuardRequired
	}
	d, g, run, target := p.facts.Domain, p.facts.Grant, p.facts.Run, p.facts.Target
	if g.State != "active" || g.Generation != b.GrantGeneration || g.RowVersion != b.GrantVersion || g.SubjectIdentityHash != b.Subject || g.IssuerIdentityHash != d.IssuerIdentityHash || g.DomainEpoch != d.Epoch || !reflect.DeepEqual(g.Admission, d.Admission) || run.GrantID != g.GrantID || run.GrantGeneration != g.Generation || run.TargetHash != targetHash || run.EvidenceID != b.Call.EvidenceID || run.TargetGeneration != target.Generation || target.CurrentRunID != run.RunID || !reflect.DeepEqual(g.Target, target.Target) || in(run.State, "superseded", "committed") {
		return GuardPlan{}, ErrConflict
	}
	refs, e := env.LockReferences(ctx, tx, detached(b), detached(p.facts))
	if e != nil {
		return GuardPlan{}, e
	}
	refs = detached(refs)
	if validateTyped(reflect.ValueOf(refs)) != nil || refs.RequestHash != p.requestHash || refs.PolicyHash != b.Call.PolicyHash {
		return GuardPlan{}, ErrGuardRequired
	}
	p.facts.References = refs
	p.plan = GuardPlan{BindingHash: p.requestHash}
	for _, stamp := range []Timestamp{d.AdmissionExpiresAt, g.LeaseExpiresAt, g.AuthorizationExpiresAt, a.IdentityExpiresAt, refs.DependencyExpiresAt, b.Call.BudgetUntil} {
		v, e := stamp.Time()
		if e != nil {
			return GuardPlan{}, e
		}
		p.plan.Deadlines = append(p.plan.Deadlines, v)
	}
	var now time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || !validDBTime(now) {
		return GuardPlan{}, ErrUnavailable
	}
	if b.Observation != nil {
		if e = p.prepareObservation(now); e != nil {
			return GuardPlan{}, e
		}
		if p.mutate {
			if p.capacityObservedAt == nil {
				return GuardPlan{}, ErrGuardRequired
			}
			sample := *p.capacityObservedAt
			p.plan.CapacityObservedAt = &sample
			extra, _ := a.AdditionalCost.Uint64()
			cost, e := commandCost(extra, nil)
			if e != nil {
				return GuardPlan{}, e
			}
			if e = env.Reserve(ctx, tx, detached(b), cost); e != nil {
				return GuardPlan{}, e
			}
		}
	} else {
		if e = p.prepareCall(ctx, tx); e != nil {
			return GuardPlan{}, e
		}
		if p.prior != nil {
			if !reflect.DeepEqual(p.prior.binding, b) || !reflect.DeepEqual(p.prior.facts, p.facts) {
				return GuardPlan{}, ErrConflict
			}
			p.plan.Deadlines = append(p.plan.Deadlines, p.prior.until)
		}
	}
	return p.plan, nil // runner resamples AFTER all lock waits and evidence reads
}

func (p *executionPolicy) prepareCall(ctx context.Context, tx SQL) error {
	b, run := p.binding, p.facts.Run
	if b.Call.Purpose == "probe" {
		if run.State != "acquired" || run.ObservedAt != nil || run.ObservationExpiresAt != nil || b.Call.RefIdentityHash != p.facts.Grant.Target.IdentityHash || b.Call.RefVersion != p.facts.Grant.Target.RefVersion {
			return ErrGuardRequired
		}
		return nil
	}
	if run.ObservedAt == nil || run.ObservationExpiresAt == nil {
		return ErrGuardRequired
	}
	expiry, _ := run.ObservationExpiresAt.Time()
	p.plan.Deadlines = append(p.plan.Deadlines, expiry)
	if in(b.Call.Purpose, "content_read", "wrap") && run.State != "acquired" {
		return ErrGuardRequired
	}
	if in(b.Call.Purpose, "sts", "publish") && run.State != "pending" {
		return ErrGuardRequired
	}
	evidence, e := p.environment.LockEvidence(ctx, tx, detached(b), detached(p.facts))
	if e != nil {
		return e
	}
	evidence = detached(evidence)
	if validateTyped(reflect.ValueOf(evidence)) != nil {
		return ErrInvalid
	}
	if evidence.EvidenceID != run.EvidenceID || evidence.OwnerType != "system" || evidence.OwnerID != b.Scope.Installation || evidence.EvidenceType != "capability_snapshot" {
		return ErrGuardRequired
	}
	if in(b.Call.Purpose, "content_read", "wrap") {
		if evidence.State != "reserved" || evidence.RowVersion != "0" || evidence.ManifestHash != nil || evidence.ClaimOwner != nil || evidence.ClaimExpiresAt != nil {
			return ErrGuardRequired
		}
	} else {
		c := b.Claim
		if c == nil || !in(evidence.State, "pending", "write_unknown") || evidence.RowVersion != ZeroCounter(c.EvidenceVersion) || evidence.ManifestHash == nil || *evidence.ManifestHash != c.ManifestHash || evidence.ClaimOwner == nil || *evidence.ClaimOwner != c.Owner || evidence.ClaimExpiresAt == nil || *evidence.ClaimExpiresAt != c.ExpiresAt || c.RefsVersionHash != p.facts.References.VersionHash {
			return ErrGuardRequired
		}
		until, _ := c.ExpiresAt.Time()
		write, _ := run.OwnerWriteExpiresAt.Time()
		p.plan.Deadlines = append(p.plan.Deadlines, until, write)
	}
	p.facts.Evidence = &evidence
	return nil
}

func (p *executionPolicy) prepareObservation(now time.Time) error {
	probe, r := p.probe, p.binding.Observation
	if probe == nil || p.binding.ProbeSnapshotHash == nil || *p.binding.ProbeSnapshotHash != probe.hash || !reflect.DeepEqual(probe.binding.Call, p.binding.Call) {
		return ErrGuardRequired
	}
	// A fresh attestation may add its own bounds, but cannot replace the probe's
	// captured identity, admission, profile, references, grant or target version.
	old, current := probe.facts, p.facts
	if !reflect.DeepEqual(old.Domain, current.Domain) || !reflect.DeepEqual(old.Grant, current.Grant) || !reflect.DeepEqual(old.Target, current.Target) || old.Admission.IdentityHash != current.Admission.IdentityHash || old.Admission.IdentityVersionHash != current.Admission.IdentityVersionHash || old.Admission.IdentityExpiresAt != current.Admission.IdentityExpiresAt || old.References.PolicyHash != current.References.PolicyHash || old.References.VersionHash != current.References.VersionHash || old.References.DependencyExpiresAt != current.References.DependencyExpiresAt {
		return ErrConflict
	}
	observed, _ := r.ObservedAt.Time()
	expires, _ := r.ExpiresAt.Time()
	earliest, _ := current.Admission.ObservedNotBefore.Time()
	latest, _ := current.Admission.ObservationExpiresNotAfter.Time()
	if observed.Before(probe.captured) || observed.Before(earliest) || observed.After(now) || !observed.Before(expires) || !now.Before(expires) || expires.After(latest) {
		return ErrExpired
	}
	p.plan.Deadlines = append(p.plan.Deadlines, probe.until, expires)
	run := p.facts.Run
	if run.ObservedAt != nil || run.ObservationExpiresAt != nil {
		if run.ObservedAt == nil || run.ObservationExpiresAt == nil || *run.ObservedAt != r.ObservedAt || *run.ObservationExpiresAt != r.ExpiresAt {
			return ErrConflict
		}
		oldVersion, _ := r.ExpectedRunVersion.Uint64()
		version, _ := run.RowVersion.Uint64()
		if version <= oldVersion {
			return ErrConflict
		}
		// State/version may advance after binding; all original immutable fields
		// still have to be the probe's run. No new authorization is issued here.
		copy := run
		copy.State = old.Run.State
		copy.RowVersion = old.Run.RowVersion
		copy.ObservedAt = nil
		copy.ObservationExpiresAt = nil
		if !reflect.DeepEqual(copy, old.Run) {
			return ErrConflict
		}
		p.replayed = true
		return nil
	}
	if run.State != "acquired" || run.RowVersion != r.ExpectedRunVersion || !reflect.DeepEqual(run, old.Run) {
		return ErrConflict
	}
	version, e := nextCounter(run.RowVersion)
	if e != nil {
		return e
	}
	run.RowVersion = version
	observedStamp, expiresStamp := r.ObservedAt, r.ExpiresAt
	run.ObservedAt = &observedStamp
	run.ObservationExpiresAt = &expiresStamp
	p.facts.Run = run
	p.mutate = true
	return nil
}

func (p *executionPolicy) write(ctx context.Context, tx *Transaction) error {
	if !p.mutate {
		return nil
	}
	if e := p.environment.Audit(ctx, tx, detached(p.binding), "intent"); e != nil {
		return e
	}
	if e := tx.ReplaceRecord(ctx, p.runLock, &p.facts.Run); e != nil {
		return e
	}
	return p.environment.Audit(ctx, tx, detached(p.binding), "result")
}
func (p *executionPolicy) Recheck(ctx context.Context, tx ReadSQL, scope Scope, plan GuardPlan, now time.Time) error {
	if scope != p.binding.Scope || plan.BindingHash != p.requestHash {
		return ErrGuardRequired
	}
	return p.environment.Recheck(ctx, tx, detached(p.binding), detached(p.facts), now)
}
