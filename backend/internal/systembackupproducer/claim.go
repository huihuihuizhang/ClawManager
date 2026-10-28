package systembackupproducer

import (
	"context"
	"reflect"
	"time"
)

// ClaimRequest is generated once before the first attempt and reused unchanged
// for ReadPublicationClaim after an ambiguous commit. It is ordinary data.
type ClaimRequest struct {
	EvidenceID              EvidenceID `json:"evidence_id"`
	ExpectedEvidenceVersion Counter    `json:"expected_evidence_version"`
	Nonce                   ID         `json:"nonce"`
	ExpiresAt               Timestamp  `json:"expires_at"`
	PolicyHash              Hash       `json:"policy_hash"`
	RefsVersionHash         Hash       `json:"refs_version_hash"`
	BudgetUntil             Timestamp  `json:"budget_until"`
}
type ClaimRequestBinding struct {
	Scope           Scope        `json:"scope"`
	Subject         Hash         `json:"subject"`
	GrantID         ID           `json:"grant_id"`
	GrantGeneration Counter      `json:"grant_generation"`
	GrantVersion    Counter      `json:"grant_version"`
	RunID           ID           `json:"run_id"`
	Request         ClaimRequest `json:"request"`
}
type ClaimEnvironment interface {
	// Freeze an independent session and original capacity sample BEFORE BEGIN.
	// readback is independently authorized; it must never reserve or mutate.
	PrepareClaim(context.Context, ClaimRequestBinding, bool) (PreparedClaim, error)
}
type PreparedClaim struct {
	Session            ClaimSession
	CapacityObservedAt *time.Time
}
type ClaimSession interface {
	LockInstallation(context.Context, SQL, ClaimRequestBinding) error
	Authenticate(context.Context, SQL, ClaimRequestBinding, DomainRecord, bool) (ClaimAdmission, error)
	LockHost(context.Context, SQL, ClaimRequestBinding, GrantRecord) error
	LockReferences(context.Context, SQL, ClaimRequestBinding, ClaimFacts) (ReferenceApproval, error)
	Reserve(context.Context, SQL, ClaimRequestBinding, uint64) error
	Audit(context.Context, SQL, ClaimRequestBinding, string) error
	// L8: current lock of the exact A registry and ordered chunks. Independently
	// compare the complete original A manifest/chunks/ref/owner/type/retention to
	// History using A's codec, and reject GC/deletion/conflicting external work.
	// Returning copied request fields is not an implementation of this contract.
	LockEvidence(context.Context, SQL, ClaimRequestBinding, ClaimFacts) (ClaimEvidence, error)
	Recheck(context.Context, ReadSQL, ClaimRequestBinding, ClaimFacts, time.Time) error
}
type ClaimAdmission struct {
	RequestHash, IdentityHash          Hash
	IdentityExpiresAt, ExpiresNotAfter Timestamp
	AdditionalCost                     Counter
	ReadbackAllowed                    bool
}
type ClaimEvidence struct {
	Evidence                           CallEvidence
	HistoryHash                        Hash
	RetentionExpiresAt, ProtectedUntil Timestamp
}
type ClaimFacts struct {
	Domain     DomainRecord
	Grant      GrantRecord
	Run        RunRecord
	History    HistoricalBindingRecord
	Target     TargetRecord
	Reference  ReferenceRecord
	Admission  ClaimAdmission
	References ReferenceApproval
	Evidence   ClaimEvidence
	Readback   bool
}
type Publication struct {
	execution   *Execution
	environment ClaimEnvironment
}

func NewPublication(execution *Execution, environment ClaimEnvironment) (*Publication, error) {
	if execution == nil || execution.lifecycle == nil || execution.lifecycle.db == nil || nilEnvironment(execution.environment) || nilEnvironment(environment) {
		return nil, ErrGuardRequired
	}
	return &Publication{execution, environment}, nil
}
func ClaimRequestHash(b ClaimRequestBinding) (Hash, error) {
	if validateTyped(reflect.ValueOf(b)) != nil {
		return "", ErrInvalid
	}
	if _, e := b.Request.ExpectedEvidenceVersion.SQLInt64(); e != nil {
		return "", e
	}
	next, e := nextCounter(b.Request.ExpectedEvidenceVersion)
	if e != nil {
		return "", e
	}
	if _, e = next.SQLInt64(); e != nil {
		return "", e
	}
	m, e := recordTree(b)
	if e != nil {
		return "", e
	}
	return hashTree("system-backup-producer-publication-claim.c1", m)
}

// ClaimPublication performs one CAS. A repeated or uncertain attempt must use
// ReadPublicationClaim: no implicit retry, lease refresh, or reconstruction from
// an uncommitted pending result. Neither error path returns a claim.
func (s *Publication) ClaimPublication(ctx context.Context, h *ExecutionHandle, r ClaimRequest) (*PublicationClaim, error) {
	return s.run(ctx, h, r, false)
}
func (s *Publication) ReadPublicationClaim(ctx context.Context, h *ExecutionHandle, r ClaimRequest) (*PublicationClaim, error) {
	return s.run(ctx, h, r, true)
}
func (s *Publication) run(ctx context.Context, h *ExecutionHandle, r ClaimRequest, readback bool) (*PublicationClaim, error) {
	if s == nil || !s.execution.validHandle(h) || nilEnvironment(s.environment) || ctx == nil || ctx.Err() != nil {
		return nil, ErrGuardRequired
	}
	b := ClaimRequestBinding{h.scope, h.subject, h.grant, h.generation, h.version, h.run, r}
	hash, e := ClaimRequestHash(b)
	if e != nil {
		return nil, e
	}
	prepared, e := s.environment.PrepareClaim(ctx, detached(b), readback)
	if e != nil {
		return nil, e
	}
	if nilEnvironment(prepared.Session) {
		return nil, ErrGuardRequired
	}
	p := &claimPolicy{binding: b, hash: hash, environment: prepared.Session, facts: ClaimFacts{Readback: readback}}
	if !readback {
		if prepared.CapacityObservedAt == nil {
			return nil, ErrGuardRequired
		}
		sample := *prepared.CapacityObservedAt
		if !validDBTime(sample) {
			return nil, ErrInvalid
		}
		p.sample = &sample
	}
	tx, e := NewTransactions(s.execution.lifecycle.db, h.scope, p)
	if e != nil {
		return nil, e
	}
	tx.clock = s.execution.lifecycle.clock
	commit, e := tx.Run(ctx, p.write)
	if e != nil || !commit.Committed() {
		return nil, e
	}
	v, _ := nextCounter(r.ExpectedEvidenceVersion)
	return &PublicationClaim{issuer: s.execution, handle: *h, binding: ClaimBinding{EvidenceID: r.EvidenceID, EvidenceVersion: v, ManifestHash: p.facts.History.Evidence.ManifestHash, Owner: ID(p.hash), ExpiresAt: r.ExpiresAt, PolicyHash: r.PolicyHash, RefsVersionHash: r.RefsVersionHash}}, nil
}

type claimPolicy struct {
	binding     ClaimRequestBinding
	hash        Hash
	environment ClaimSession
	sample      *time.Time
	facts       ClaimFacts
	plan        GuardPlan
}

func (p *claimPolicy) LockAndAuthorize(ctx context.Context, tx SQL, scope Scope) (GuardPlan, error) {
	b, env := p.binding, p.environment
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
	a, e := env.Authenticate(ctx, tx, detached(b), detached(p.facts.Domain), p.facts.Readback)
	if e != nil {
		return GuardPlan{}, e
	}
	if validateTyped(reflect.ValueOf(a)) != nil || a.RequestHash != p.hash || a.IdentityHash != b.Subject || p.facts.Readback && !a.ReadbackAllowed {
		return GuardPlan{}, ErrGuardRequired
	}
	p.facts.Admission = detached(a)
	l, e = tx.LockRecord(ctx, RecordKey{ID: b.GrantID}, &p.facts.Grant)
	if e != nil {
		return GuardPlan{}, e
	}
	if !l.Found() {
		return GuardPlan{}, ErrGuardRequired
	}
	l, e = tx.LockRecord(ctx, RecordKey{ID: b.RunID}, &p.facts.Run)
	if e != nil {
		return GuardPlan{}, e
	}
	if !l.Found() {
		return GuardPlan{}, ErrGuardRequired
	}
	l, e = tx.LockRecord(ctx, RecordKey{EvidenceID: b.Request.EvidenceID}, &p.facts.History)
	if e != nil {
		return GuardPlan{}, e
	}
	if !l.Found() {
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
	d, g, run, target, h := p.facts.Domain, p.facts.Grant, p.facts.Run, p.facts.Target, p.facts.History
	if g.State != "active" || g.Generation != b.GrantGeneration || g.RowVersion != b.GrantVersion || g.SubjectIdentityHash != b.Subject || g.IssuerIdentityHash != d.IssuerIdentityHash || g.DomainEpoch != d.Epoch || !reflect.DeepEqual(g.Admission, d.Admission) || run.State != "pending" || run.GrantID != g.GrantID || run.GrantGeneration != g.Generation || run.TargetHash != targetHash || run.TargetGeneration != target.Generation || target.CurrentRunID != run.RunID || !reflect.DeepEqual(target.Target, g.Target) {
		return GuardPlan{}, ErrConflict
	}
	if run.ObservedAt == nil || run.ObservationExpiresAt == nil || run.EvidenceID != b.Request.EvidenceID || h.RunID != run.RunID || h.GrantID != g.GrantID || h.GrantGeneration != g.Generation || h.DomainEpoch != d.Epoch || !reflect.DeepEqual(h.Admission, g.Admission) || h.TargetHash != targetHash || h.InputHash != run.InputHash || h.OwnerWriteExpiresAt != run.OwnerWriteExpiresAt || h.ObservedAt != *run.ObservedAt || h.ObservationExpiresAt != *run.ObservationExpiresAt {
		return GuardPlan{}, ErrConflict
	}
	refHash, e := pendingReferenceHash(h)
	if e != nil {
		return GuardPlan{}, e
	}
	l, e = tx.LockRecord(ctx, RecordKey{EvidenceID: run.EvidenceID, ReferenceKind: "hold", Hash: refHash}, &p.facts.Reference)
	if e != nil {
		return GuardPlan{}, e
	}
	want := ReferenceRecord{Scope: scope, EvidenceID: run.EvidenceID, ReferenceKind: "hold", ReferenceKeyHash: refHash, ProtectedUntil: h.RetentionExpiresAt, CreatedAt: h.CreatedAt}
	if !l.Found() || !reflect.DeepEqual(p.facts.Reference, want) {
		return GuardPlan{}, ErrGuardRequired
	}
	refs, e := env.LockReferences(ctx, tx, detached(b), detached(p.facts))
	if e != nil {
		return GuardPlan{}, e
	}
	if validateTyped(reflect.ValueOf(refs)) != nil || refs.RequestHash != p.hash || refs.PolicyHash != b.Request.PolicyHash || refs.VersionHash != b.Request.RefsVersionHash {
		return GuardPlan{}, ErrGuardRequired
	}
	p.facts.References = detached(refs)
	p.plan = GuardPlan{BindingHash: p.hash}
	for _, stamp := range []Timestamp{d.AdmissionExpiresAt, g.LeaseExpiresAt, g.AuthorizationExpiresAt, a.IdentityExpiresAt, a.ExpiresNotAfter, refs.DependencyExpiresAt, b.Request.BudgetUntil, run.OwnerWriteExpiresAt, *run.ObservationExpiresAt, h.RetentionExpiresAt} {
		v, e := stamp.Time()
		if e != nil {
			return GuardPlan{}, e
		}
		p.plan.Deadlines = append(p.plan.Deadlines, v)
	}
	// Persist a deadline no later than ANY originally admitted boundary. A later
	// BeginCall cannot extend it through a newer call budget or credential policy.
	expiry, _ := b.Request.ExpiresAt.Time()
	if expiry.After(minimum(p.plan.Deadlines)) {
		return GuardPlan{}, ErrExpired
	}
	p.plan.Deadlines = append(p.plan.Deadlines, expiry)
	if !p.facts.Readback {
		sample := *p.sample
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
	return p.plan, nil
}

// The full original evidence bytes were validated by the locked A adapter.
// This additional CAS binds all changing columns and system ownership; it never
// edits manifest/chunks, health, provider result, retention or observation.
const publicationClaimCAS = `UPDATE system_backup_v2_evidence SET claim_owner=?,claim_expires_at=?,row_version=row_version+1,updated_at=UTC_TIMESTAMP(6) WHERE public_id=? AND row_version=? AND owner_target_type='system' AND owner_target_public_id=? AND evidence_type='capability_snapshot' AND storage_state=? AND claim_owner <=> ? AND claim_expires_at <=> ?`

func (p *claimPolicy) write(ctx context.Context, tx *Transaction) error {
	b, env := p.binding, p.environment
	if !p.facts.Readback {
		if e := env.Audit(ctx, tx, detached(b), "intent"); e != nil {
			return e
		}
	}
	v, e := env.LockEvidence(ctx, tx, detached(b), detached(p.facts))
	if e != nil {
		return e
	}
	v = detached(v)
	historyHash, e := PendingHistoryHash(p.facts.History)
	if e != nil {
		return e
	}
	if validateTyped(reflect.ValueOf(v)) != nil || v.HistoryHash != historyHash || v.RetentionExpiresAt < p.facts.History.RetentionExpiresAt || v.ProtectedUntil < p.facts.History.RetentionExpiresAt {
		return ErrGuardRequired
	}
	row := v.Evidence
	if row.EvidenceID != b.Request.EvidenceID || row.OwnerType != "system" || row.OwnerID != b.Scope.Installation || row.EvidenceType != "capability_snapshot" || !in(row.State, "pending", "write_unknown") || row.ManifestHash == nil || *row.ManifestHash != p.facts.History.Evidence.ManifestHash || (row.ClaimOwner == nil) != (row.ClaimExpiresAt == nil) {
		return ErrGuardRequired
	}
	next, e := nextCounter(b.Request.ExpectedEvidenceVersion)
	if e != nil {
		return e
	}
	if p.facts.Readback {
		if row.RowVersion != ZeroCounter(next) || row.ClaimOwner == nil || *row.ClaimOwner != ID(p.hash) || *row.ClaimExpiresAt != b.Request.ExpiresAt {
			return ErrConflict
		}
	} else {
		if row.RowVersion != ZeroCounter(b.Request.ExpectedEvidenceVersion) {
			return ErrConflict
		}
		var ownerArg, untilArg any
		if row.ClaimOwner != nil {
			// Same owner is never renewed in place, even if its previous claim expired.
			if *row.ClaimOwner == ID(p.hash) {
				return ErrConflict
			}
			var now time.Time
			if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || !validDBTime(now) {
				return ErrUnavailable
			}
			until, _ := row.ClaimExpiresAt.Time()
			if now.Before(until) {
				return ErrConflict
			}
			ownerArg = string(*row.ClaimOwner)
			untilArg = until
		}
		version, _ := b.Request.ExpectedEvidenceVersion.SQLInt64()
		expiry, _ := b.Request.ExpiresAt.Time()
		if e = tx.CAS(ctx, publicationClaimCAS, string(p.hash), expiry, string(b.Request.EvidenceID), version, string(b.Scope.Installation), row.State, ownerArg, untilArg); e != nil {
			return e
		}
		owner, stamp := ID(p.hash), b.Request.ExpiresAt
		row.ClaimOwner = &owner
		row.ClaimExpiresAt = &stamp
		row.RowVersion = ZeroCounter(next)
		v.Evidence = row
	}
	p.facts.Evidence = v
	if !p.facts.Readback {
		return env.Audit(ctx, tx, detached(b), "result")
	}
	return nil
}
func (p *claimPolicy) Recheck(ctx context.Context, tx ReadSQL, scope Scope, plan GuardPlan, now time.Time) error {
	if scope != p.binding.Scope || plan.BindingHash != p.hash {
		return ErrGuardRequired
	}
	return p.environment.Recheck(ctx, tx, detached(p.binding), detached(p.facts), now)
}
