package systembackupproducer

import (
	"context"
	"database/sql"
	"encoding/hex"
	"reflect"
	"sync/atomic"
	"time"
)

// RecoveryRequest is a lookup/CAS input, never an authorization. The workload
// and its current revocation epoch are supplied only by the trusted session.
type RecoveryRequest struct {
	Scope                   Scope      `json:"scope"`
	EvidenceID              EvidenceID `json:"evidence_id"`
	ExpectedEvidenceVersion Counter    `json:"expected_evidence_version"`
	Nonce                   ID         `json:"nonce"`
	ClaimExpiresAt          Timestamp  `json:"claim_expires_at"`
	BudgetUntil             Timestamp  `json:"budget_until"`
}

type RecoveryFinishRequest struct {
	State            string    `json:"state"` // ready or write_unknown
	ProofHash        Hash      `json:"proof_hash"`
	ObjectHash       Hash      `json:"object_hash"`
	ObjectBytes      Counter   `json:"object_bytes"`
	ImmutableVersion *Text     `json:"immutable_version"`
	ObservedAt       Timestamp `json:"observed_at"`
	BudgetUntil      Timestamp `json:"budget_until"`
}

// HistoricalRecoveryEnvironment is implemented by A/D/C integration. Each
// call obtains a fresh session; ordinary request fields cannot construct it.
// L2 must lock the dedicated current workload revocation row, compare its
// epoch with A's identity, and reject absence, revocation or changed epoch.
type HistoricalRecoveryEnvironment interface {
	PrepareRecovery(context.Context, RecoveryRequest, string, *RecoveryFinishRequest) (PreparedRecovery, error)
}

type PreparedRecovery struct {
	Session            HistoricalRecoverySession
	CapacityObservedAt *time.Time // required for claim/finish, absent for load
}

type HistoricalRecoverySession interface {
	LockInstallation(context.Context, SQL, RecoveryRequest) error                             // L0-L1; original config need not be active
	Authorize(context.Context, SQL, RecoveryRequest, Hash, string) (RecoveryAdmission, error) // L2 current deployment/workload/revocation
	LockReferences(context.Context, SQL, RecoveryRequest, HistoricalBindingRecord) error      // L5 holds/GC
	Reserve(context.Context, SQL, RecoveryRequest, uint64) error                              // L6
	Audit(context.Context, SQL, RecoveryRequest, string) error                                // L7/L9
	// L8 locks A's exact original registry and ordered chunks, reconstructs the
	// original record using A's codec and compares it with immutable history.
	LockEvidence(context.Context, SQL, RecoveryRequest, HistoricalBindingRecord) (FinishEvidence, error)
	// C must independently verify an already frozen exact-object Stat proof.
	// No network/provider I/O is allowed under these SQL locks. A 404/timeout
	// can only authorize write_unknown; it cannot authorize ready.
	VerifyStat(context.Context, SQL, RecoveryRequest, HistoricalBindingRecord, RecoveryFinishRequest) (RecoveryStatAdmission, error)
	Recheck(context.Context, ReadSQL, RecoveryRequest, HistoricalBindingRecord, time.Time) error // L10 current deployment/revocation/hold
}

type RecoveryAdmission struct {
	VerifiedRequestHash Hash
	IdentityHash        Hash
	RevocationEpoch     Counter
	IdentityExpiresAt   Timestamp
	DeploymentExpiresAt Timestamp
	StatAllowed         bool
	AdditionalCost      ZeroCounter // independently verified existing audit cost
}

const recoveryRevocationLockSQL = `SELECT revocation_epoch,revoked_at,row_version FROM system_backup_v2_producer_recovery_revocations WHERE scope_key=? AND workload_identity_hash=? FOR UPDATE`

// lockRecoveryRevocation checks the D-owned current identity fence in L2.
// An absent row is a denial, including on an installation that has not yet
// installed the reviewed recovery migration.
func lockRecoveryRevocation(ctx context.Context, tx SQL, scope Scope, identity Hash, expected Counter) error {
	scopeBytes, err := recoveryScopeKey(scope)
	if err != nil {
		return err
	}
	identityBytes, err := hex.DecodeString(string(identity))
	if err != nil || len(identityBytes) != 32 {
		return ErrInvalid
	}
	want, err := expected.SQLInt64()
	if err != nil {
		return err
	}
	var epoch, version int64
	var revoked sql.NullTime
	if err = tx.QueryRowContext(ctx, recoveryRevocationLockSQL, scopeBytes, identityBytes).Scan(&epoch, &revoked, &version); err != nil {
		return ErrGuardRequired
	}
	if epoch != want || version < 1 || revoked.Valid {
		return ErrGuardRequired
	}
	return nil
}

func recoveryScopeKey(scope Scope) ([]byte, error) {
	m, err := recordTree(scope)
	if err != nil {
		return nil, err
	}
	key, err := hashTree(ScopeDomain, m)
	if err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(string(key))
	if err != nil || len(b) != 32 {
		return nil, ErrInvalid
	}
	return b, nil
}

// RecoveryScopeKey returns the exact C1 scope key used by historical recovery
// and its current deployment rows. The returned bytes are a lookup key, not an
// authorization; callers must still lock and verify current installation and
// deployment state in D's transaction order.
func RecoveryScopeKey(scope Scope) ([]byte, error) {
	if validateTyped(reflect.ValueOf(scope)) != nil {
		return nil, ErrInvalid
	}
	return recoveryScopeKey(scope)
}

type RecoveryStatAdmission struct {
	VerifiedProofHash Hash
	ProofExpiresAt    Timestamp
	Matched           bool
}

// RecoveryStatContext identifies the exact object for an independently
// admitted Stat. It contains no credential or PUT/Range/Delete/Unwrap right.
type RecoveryStatContext struct {
	EvidenceID        EvidenceID
	StoreIdentityHash Hash
	StoreRefVersion   RefVersion
	RelativeKeyHash   Hash
	ObjectHash        Hash
	ObjectBytes       Counter
	ImmutableVersion  *Text
}

type HistoricalRecovery struct {
	db          *sql.DB
	scope       Scope
	environment HistoricalRecoveryEnvironment
	clock       func() time.Time
}

func NewHistoricalRecovery(db *sql.DB, scope Scope, environment HistoricalRecoveryEnvironment) (*HistoricalRecovery, error) {
	if db == nil || nilEnvironment(environment) || validateTyped(reflect.ValueOf(scope)) != nil {
		return nil, ErrGuardRequired
	}
	return &HistoricalRecovery{db: db, scope: scope, environment: environment, clock: time.Now}, nil
}

func recoveryHash(r RecoveryRequest, op string, finish *RecoveryFinishRequest) (Hash, error) {
	if validateTyped(reflect.ValueOf(r)) != nil || !in(op, "load", "claim", "finish") {
		return "", ErrInvalid
	}
	if op != "load" {
		if _, err := r.ExpectedEvidenceVersion.SQLInt64(); err != nil {
			return "", err
		}
		if _, err := nextCounter(r.ExpectedEvidenceVersion); err != nil {
			return "", err
		}
	}
	if op == "finish" {
		if finish == nil || !in(finish.State, "ready", "write_unknown") || validateTyped(reflect.ValueOf(*finish)) != nil {
			return "", ErrInvalid
		}
		if finish.State == "ready" && !validObjectVersion(finish.ImmutableVersion) || finish.State == "write_unknown" && finish.ImmutableVersion != nil {
			return "", ErrInvalid
		}
	} else if finish != nil {
		return "", ErrInvalid
	}
	m, err := recordTree(struct {
		Request   RecoveryRequest        `json:"request"`
		Operation string                 `json:"operation"`
		Finish    *RecoveryFinishRequest `json:"finish"`
	}{r, op, finish})
	if err != nil {
		return "", err
	}
	return hashTree("system-backup-producer-historical-recovery.c1", m)
}

// LoadHistoricalBinding reads immutable history under a fresh current
// workload authority. It does not consult the old grant or require an open
// producer domain. No provider credential or execution handle is returned.
func (s *HistoricalRecovery) LoadHistoricalBinding(ctx context.Context, r RecoveryRequest) (HistoricalBindingRecord, RecoveryStatContext, error) {
	p, err := s.prepare(ctx, r, "load", nil)
	if err != nil {
		return HistoricalBindingRecord{}, RecoveryStatContext{}, err
	}
	commit, err := p.run(ctx, func(ctx context.Context, tx *Transaction) error {
		_, err := p.lockEvidence(ctx, tx)
		return err
	})
	if !commit.Committed() {
		return HistoricalBindingRecord{}, RecoveryStatContext{}, err
	}
	h := detached(p.history)
	e := h.Evidence
	return h, RecoveryStatContext{e.EvidenceID, e.StoreIdentityHash, e.StoreRefVersion, e.RelativeKeyHash, e.ObjectHash, e.ObjectBytes, e.ImmutableVersion}, err
}

// RecoveryClaim is private to this service. JSON and caller data cannot mint
// it. The claim authorizes at most a separate exact-object Stat admission.
type RecoveryClaim struct {
	issuer      *HistoricalRecovery
	request     RecoveryRequest
	owner       ID
	version     Counter
	historyHash Hash
}

func (RecoveryClaim) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*RecoveryClaim) UnmarshalJSON([]byte) error  { return ErrInvalid }

func (s *HistoricalRecovery) ClaimRecovery(ctx context.Context, r RecoveryRequest) (*RecoveryClaim, error) {
	p, err := s.prepare(ctx, r, "claim", nil)
	if err != nil {
		return nil, err
	}
	commit, err := p.run(ctx, p.claim)
	if !commit.Committed() {
		return nil, err
	}
	v, _ := nextCounter(r.ExpectedEvidenceVersion)
	return &RecoveryClaim{issuer: s, request: detached(r), owner: ID(p.hash), version: v, historyHash: p.historyHash}, err
}

// FinishRecovery changes only the original evidence publication fields. C's
// independently checked Stat result must be supplied before this call. A 404
// or timeout remains write_unknown; no capability/health projection is touched.
func (s *HistoricalRecovery) FinishRecovery(ctx context.Context, claim *RecoveryClaim, result RecoveryFinishRequest) (FinishResult, error) {
	if s == nil || claim == nil || claim.issuer != s {
		return FinishResult{}, ErrGuardRequired
	}
	r := claim.request
	r.ExpectedEvidenceVersion = claim.version
	p, err := s.prepare(ctx, r, "finish", &result)
	if err != nil {
		return FinishResult{}, err
	}
	p.claimOwner, p.expectedHistoryHash = claim.owner, claim.historyHash
	commit, err := p.run(ctx, p.finish)
	if !commit.Committed() {
		return FinishResult{}, err
	}
	v, _ := nextCounter(claim.version)
	return FinishResult{EvidenceID: r.EvidenceID, EvidenceVersion: v, State: result.State, ImmutableVersion: result.ImmutableVersion}, err
}

// PreparedRecoveryFinish freezes the capacity and C proof inputs before the
// caller starts its SQL transaction. It is service-local and single-use.
type PreparedRecoveryFinish struct {
	issuer *HistoricalRecovery
	policy *recoveryPolicy
	used   uint32
}

func (PreparedRecoveryFinish) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*PreparedRecoveryFinish) UnmarshalJSON([]byte) error  { return ErrInvalid }

func (s *HistoricalRecovery) PrepareFinishRecovery(ctx context.Context, claim *RecoveryClaim, result RecoveryFinishRequest) (*PreparedRecoveryFinish, error) {
	if s == nil || claim == nil || claim.issuer != s {
		return nil, ErrGuardRequired
	}
	r := claim.request
	r.ExpectedEvidenceVersion = claim.version
	p, err := s.prepare(ctx, r, "finish", &result)
	if err != nil {
		return nil, err
	}
	p.claimOwner, p.expectedHistoryHash = claim.owner, claim.historyHash
	return &PreparedRecoveryFinish{issuer: s, policy: p}, nil
}

// FinishRecoveryInTx runs D's CAS, audit and FinalGuard inside the caller's
// transaction. It returns only an uncommitted decision. The caller must roll
// back on error and must not send another provider request to resolve an
// uncertain COMMIT; read the original evidence after reauthorization instead.
func (s *HistoricalRecovery) FinishRecoveryInTx(ctx context.Context, tx *sql.Tx, prepared *PreparedRecoveryFinish) error {
	if s == nil || tx == nil || prepared == nil || prepared.issuer != s || prepared.policy == nil || !atomic.CompareAndSwapUint32(&prepared.used, 0, 1) {
		return ErrGuardRequired
	}
	p := prepared.policy
	guard, err := NewTransactions(s.db, s.scope, p)
	if err != nil {
		return err
	}
	return guard.GuardInTx(ctx, tx, p.finish)
}

type recoveryPolicy struct {
	service             *HistoricalRecovery
	request             RecoveryRequest
	op                  string
	result              *RecoveryFinishRequest
	hash                Hash
	session             HistoricalRecoverySession
	sample              *time.Time
	history             HistoricalBindingRecord
	historyHash         Hash
	expectedHistoryHash Hash
	claimOwner          ID
	admission           RecoveryAdmission
	evidence            FinishEvidence
	proofUntil          time.Time
}

func (s *HistoricalRecovery) prepare(ctx context.Context, r RecoveryRequest, op string, result *RecoveryFinishRequest) (*recoveryPolicy, error) {
	if s == nil || s.db == nil || nilEnvironment(s.environment) || ctx == nil || ctx.Err() != nil {
		return nil, ErrGuardRequired
	}
	if r.Scope != s.scope {
		return nil, ErrInvalid
	}
	hash, err := recoveryHash(r, op, result)
	if err != nil {
		return nil, err
	}
	r = detached(r)
	var copyResult *RecoveryFinishRequest
	if result != nil {
		v := detached(*result)
		copyResult = &v
	}
	prepared, err := s.environment.PrepareRecovery(ctx, detached(r), op, copyResult)
	if err != nil {
		return nil, err
	}
	if nilEnvironment(prepared.Session) {
		return nil, ErrGuardRequired
	}
	if op != "load" && (prepared.CapacityObservedAt == nil || !validDBTime(*prepared.CapacityObservedAt)) {
		return nil, ErrGuardRequired
	}
	p := &recoveryPolicy{service: s, request: r, op: op, result: copyResult, hash: hash, session: prepared.Session}
	if prepared.CapacityObservedAt != nil {
		v := *prepared.CapacityObservedAt
		p.sample = &v
	}
	return p, nil
}

func (p *recoveryPolicy) run(ctx context.Context, work func(context.Context, *Transaction) error) (CommitReceipt, error) {
	tx, err := NewTransactions(p.service.db, p.request.Scope, p)
	if err != nil {
		return CommitReceipt{}, err
	}
	tx.clock = p.service.clock
	return tx.Run(ctx, work)
}

func (p *recoveryPolicy) LockAndAuthorize(ctx context.Context, tx SQL, scope Scope) (GuardPlan, error) {
	if scope != p.request.Scope {
		return GuardPlan{}, ErrInvalid
	}
	if err := p.session.LockInstallation(ctx, tx, detached(p.request)); err != nil {
		return GuardPlan{}, err
	}
	// L2 current workload revocation precedes L4 history. The old producer
	// domain and configuration are not authorization sources here.
	a, err := p.session.Authorize(ctx, tx, detached(p.request), p.hash, p.op)
	if err != nil {
		return GuardPlan{}, err
	}
	if !a.StatAllowed || a.VerifiedRequestHash != p.hash || validateTyped(reflect.ValueOf(a)) != nil {
		return GuardPlan{}, ErrGuardRequired
	}
	if err = lockRecoveryRevocation(ctx, tx, scope, a.IdentityHash, a.RevocationEpoch); err != nil {
		return GuardPlan{}, err
	}
	p.admission = a
	locked, err := tx.LockRecord(ctx, RecordKey{EvidenceID: p.request.EvidenceID}, &p.history)
	if err != nil {
		return GuardPlan{}, err
	}
	if !locked.Found() || p.history.Scope != scope || p.history.Evidence.EvidenceID != p.request.EvidenceID {
		return GuardPlan{}, ErrConflict
	}
	p.historyHash, err = PendingHistoryHash(p.history)
	if err != nil {
		return GuardPlan{}, err
	}
	if p.op == "finish" && p.historyHash != p.expectedHistoryHash {
		return GuardPlan{}, ErrConflict
	}
	if err = p.session.LockReferences(ctx, tx, detached(p.request), detached(p.history)); err != nil {
		return GuardPlan{}, err
	}
	plan := GuardPlan{BindingHash: p.hash, CapacityObservedAt: p.sample}
	for _, stamp := range []Timestamp{a.IdentityExpiresAt, a.DeploymentExpiresAt, p.history.RetentionExpiresAt, p.request.BudgetUntil} {
		v, err := stamp.Time()
		if err != nil {
			return GuardPlan{}, err
		}
		plan.Deadlines = append(plan.Deadlines, v)
	}
	if p.op != "load" {
		v, _ := p.request.ClaimExpiresAt.Time()
		plan.Deadlines = append(plan.Deadlines, v)
		extra, err := a.AdditionalCost.Uint64()
		if err != nil {
			return GuardPlan{}, err
		}
		cost, err := commandCost(extra, nil)
		if err != nil {
			return GuardPlan{}, err
		}
		if err = p.session.Reserve(ctx, tx, detached(p.request), cost); err != nil {
			return GuardPlan{}, err
		}
	}
	if p.op == "finish" {
		v, _ := p.result.BudgetUntil.Time()
		plan.Deadlines = append(plan.Deadlines, v)
	}
	return plan, nil
}

func (p *recoveryPolicy) Recheck(ctx context.Context, tx ReadSQL, scope Scope, plan GuardPlan, now time.Time) error {
	if scope != p.request.Scope || plan.BindingHash != p.hash {
		return ErrGuardRequired
	}
	if p.op == "finish" && (p.proofUntil.IsZero() || !now.Before(p.proofUntil)) {
		return ErrExpired
	}
	return p.session.Recheck(ctx, tx, detached(p.request), detached(p.history), now)
}

const recoveryClaimCAS = `UPDATE system_backup_v2_evidence SET claim_owner=?,claim_expires_at=?,row_version=row_version+1,updated_at=UTC_TIMESTAMP(6) WHERE public_id=? AND row_version=? AND owner_target_type='system' AND owner_target_public_id=? AND evidence_type='capability_snapshot' AND storage_state=? AND claim_owner <=> ? AND claim_expires_at <=> ?`
const recoveryFinishCAS = `UPDATE system_backup_v2_evidence SET storage_state=?,evidence_failure_code=?,storage_immutable_version=?,claim_owner=NULL,claim_expires_at=NULL,row_version=row_version+1,updated_at=UTC_TIMESTAMP(6) WHERE public_id=? AND row_version=? AND owner_target_type='system' AND owner_target_public_id=? AND evidence_type='capability_snapshot' AND storage_state=? AND claim_owner=? AND claim_expires_at=? AND storage_immutable_version IS NULL`

func (p *recoveryPolicy) lockEvidence(ctx context.Context, tx *Transaction) (FinishEvidence, error) {
	v, err := p.session.LockEvidence(ctx, tx, detached(p.request), detached(p.history))
	if err != nil {
		return FinishEvidence{}, err
	}
	if v.ClaimEvidence.HistoryHash != p.historyHash || v.ClaimEvidence.RetentionExpiresAt < p.history.RetentionExpiresAt || v.ClaimEvidence.ProtectedUntil < p.history.RetentionExpiresAt {
		return FinishEvidence{}, ErrGuardRequired
	}
	row := v.ClaimEvidence.Evidence
	if row.EvidenceID != p.request.EvidenceID || row.OwnerType != "system" || row.OwnerID != p.request.Scope.Installation || row.EvidenceType != "capability_snapshot" || row.ManifestHash == nil || *row.ManifestHash != p.history.Evidence.ManifestHash {
		return FinishEvidence{}, ErrGuardRequired
	}
	return v, nil
}

func (p *recoveryPolicy) claim(ctx context.Context, tx *Transaction) error {
	if err := p.session.Audit(ctx, tx, detached(p.request), "intent"); err != nil {
		return err
	}
	v, err := p.lockEvidence(ctx, tx)
	if err != nil {
		return err
	}
	row := v.ClaimEvidence.Evidence
	if !in(row.State, "pending", "write_unknown") || row.RowVersion != ZeroCounter(p.request.ExpectedEvidenceVersion) || v.ImmutableVersion != nil {
		return ErrConflict
	}
	var owner, expiry any
	if row.ClaimOwner != nil {
		if row.ClaimExpiresAt == nil {
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
		owner, expiry = string(*row.ClaimOwner), until
	} else if row.ClaimExpiresAt != nil {
		return ErrConflict
	}
	var now time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || !validDBTime(now) {
		return ErrUnavailable
	}
	cutoff, _ := p.history.OwnerWriteExpiresAt.Time()
	if now.Before(cutoff) {
		return ErrConflict
	}
	version, _ := p.request.ExpectedEvidenceVersion.SQLInt64()
	until, _ := p.request.ClaimExpiresAt.Time()
	if err = tx.CAS(ctx, recoveryClaimCAS, string(p.hash), until, string(p.request.EvidenceID), version, string(p.request.Scope.Installation), row.State, owner, expiry); err != nil {
		return err
	}
	return p.session.Audit(ctx, tx, detached(p.request), "result")
}

func (p *recoveryPolicy) finish(ctx context.Context, tx *Transaction) error {
	if err := p.session.Audit(ctx, tx, detached(p.request), "intent"); err != nil {
		return err
	}
	v, err := p.lockEvidence(ctx, tx)
	if err != nil {
		return err
	}
	row := v.ClaimEvidence.Evidence
	if !in(row.State, "pending", "write_unknown") || row.RowVersion != ZeroCounter(p.request.ExpectedEvidenceVersion) || row.ClaimOwner == nil || *row.ClaimOwner != p.claimOwner || row.ClaimExpiresAt == nil || *row.ClaimExpiresAt != p.request.ClaimExpiresAt || v.ImmutableVersion != nil {
		return ErrConflict
	}
	proof, err := p.session.VerifyStat(ctx, tx, detached(p.request), detached(p.history), detached(*p.result))
	if err != nil {
		return err
	}
	if proof.VerifiedProofHash != p.result.ProofHash || p.result.State == "ready" && !proof.Matched {
		return ErrGuardRequired
	}
	proofUntil, err := proof.ProofExpiresAt.Time()
	if err != nil {
		return err
	}
	budgetUntil, _ := p.result.BudgetUntil.Time()
	if proofUntil.Before(budgetUntil) {
		return ErrExpired
	}
	var now time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || !validDBTime(now) || !now.Before(proofUntil) {
		return ErrExpired
	}
	observed, err := p.result.ObservedAt.Time()
	if err != nil || observed.After(now) || !observed.Before(proofUntil) || p.result.ObservedAt < p.history.CreatedAt {
		return ErrExpired
	}
	p.proofUntil = proofUntil
	if p.result.ObjectHash != p.history.Evidence.ObjectHash || p.result.ObjectBytes != p.history.Evidence.ObjectBytes {
		return ErrConflict
	}
	failure := "none"
	var versionArg any
	if p.result.State == "ready" {
		versionArg = string(*p.result.ImmutableVersion)
	} else {
		failure = "provider_unavailable"
	}
	version, _ := p.request.ExpectedEvidenceVersion.SQLInt64()
	until, _ := p.request.ClaimExpiresAt.Time()
	if err = tx.CAS(ctx, recoveryFinishCAS, p.result.State, failure, versionArg, string(p.request.EvidenceID), version, string(p.request.Scope.Installation), row.State, string(p.claimOwner), until); err != nil {
		return err
	}
	return p.session.Audit(ctx, tx, detached(p.request), "result")
}
