package systembackupproducer

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"time"
)

// CommandEnvironment is a trusted deployment integration, never request data.
// Every method is mandatory. Implementations must bind the exact request and
// independently authenticate current principals, profiles, issuers and hosts.
// There is no production implementation or permissive fallback in this package.
type CommandEnvironment interface {
	// Prepare runs before BEGIN and pins immutable identity/deployment inputs
	// and the capacity report. Each call must return its own isolated session.
	Prepare(context.Context, CommandRequest) (PreparedCommand, error)
}

type PreparedCommand struct {
	Session CommandSession
	// Nil permits an independently authorized receipt replay only. A new
	// mutation requires a preloaded report; Reserve cannot select a newer one.
	CapacityObservedAt *time.Time
}

type CommandSession interface {
	// L0-L1 installation/current config (including absence ranges), before domain.
	LockInstallation(context.Context, SQL, CommandRequest) error
	// L2 identity/session/revocation, after the domain has been locked. Verify
	// all requested admission, host, issuer, target/profile/slots and time bounds.
	Authenticate(context.Context, SQL, CommandRequest, DomainRecord) (CommandAdmission, error)
	// L4 host keys, after sorted grant/run keys; no earlier-layer locks.
	LockHosts(context.Context, SQL, CommandRequest) error
	// L5 exact projection/reference/hold keys, after the target key.
	LockReferences(context.Context, SQL, CommandRequest) error
	// L6 reserve the exact checked cost, including AdditionalCost, with the
	// original trusted report pinned BEFORE this transaction. Never reload it.
	Reserve(context.Context, SQL, CommandRequest, uint64) error
	// Intent at L7, result at L9, all actor/FK keys already locked. Must fail
	// atomically with the transaction; no remote I/O in either stage.
	Audit(context.Context, SQL, CommandRequest, string) error
	// Current reads of already locked authority only; compare original fixed
	// deadlines/identity/config/refs and resulting state. No new business locks.
	Recheck(context.Context, ReadSQL, CommandRequest, CommandFacts, time.Time) error
}

// CommandAdmission is supplied only by CommandSession.Authenticate, after
// its live identity checks. Its fields are data, not independently valid proof.
type CommandAdmission struct {
	RequestHash  Hash
	IdentityHash Hash
	Deadlines    []time.Time
	Management   bool
	// Independently authenticated historical read of this exact command key.
	// An old execution handle or merely matching actor hash cannot establish it.
	HistoricalReceiptRead   bool
	TerminationDecisionHash *Hash
	ReceiptRetentionUntil   Timestamp
	AdditionalCost          Counter // existing audit/projection costs, counted exactly once
}

// CommandFacts is a detached final-state copy for the mandatory final recheck.
type CommandFacts struct {
	Domain   DomainRecord
	Grants   []GrantRecord
	Runs     []RunRecord
	Target   *TargetRecord
	Receipt  CommandReceiptRecord
	Replayed bool
}

type Lifecycle struct {
	db          *sql.DB
	scope       Scope
	environment CommandEnvironment
	clock       func() time.Time
}

func NewLifecycle(db *sql.DB, scope Scope, environment CommandEnvironment) (*Lifecycle, error) {
	if db == nil || nilEnvironment(environment) || validateTyped(reflect.ValueOf(scope)) != nil {
		return nil, ErrGuardRequired
	}
	return &Lifecycle{db: db, scope: scope, environment: environment, clock: time.Now}, nil
}
func nilEnvironment(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Func, reflect.Interface, reflect.Slice, reflect.Chan:
		return r.IsNil()
	}
	return false
}

// ExecutionHandle is service-local committed identity, never a bearer token.
// It contains no provider credentials and must be reauthenticated on every use.
type ExecutionHandle struct {
	issuer     *Lifecycle
	scope      Scope
	subject    Hash
	grant      ID
	generation Counter
	version    Counter
	run        ID
}

func (ExecutionHandle) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*ExecutionHandle) UnmarshalJSON([]byte) error  { return ErrInvalid }

type CommandResult struct {
	Receipt  CommandReceiptRecord
	Handle   *ExecutionHandle
	Replayed bool
}

// Execute implements the four C1 commands. Renew needs this service's original
// committed handle; other commands require nil. Commit uncertainty returns no
// receipt/handle and never retries. A known but expired commit returns historical
// receipt metadata and ErrCommittedExpired, with no execution handle.
func (s *Lifecycle) Execute(ctx context.Context, request CommandRequest, handle *ExecutionHandle) (CommandResult, error) {
	if s == nil || s.db == nil || nilEnvironment(s.environment) || ctx.Err() != nil {
		return CommandResult{}, ErrGuardRequired
	}
	if validateTyped(reflect.ValueOf(request)) != nil || request.Scope != s.scope {
		return CommandResult{}, ErrInvalid
	}
	raw, e := json.Marshal(request)
	if e != nil {
		return CommandResult{}, ErrInvalid
	}
	request, e = DecodeCommand(raw)
	if e != nil {
		return CommandResult{}, e
	}
	if request.Command == "renew" {
		if handle == nil || handle.issuer != s || handle.scope != s.scope || handle.subject != request.ActorIdentityHash || handle.grant != request.Expected.GrantID || handle.generation != request.Expected.GrantGeneration || handle.version != request.Expected.GrantRowVersion || handle.run != request.Expected.RunID {
			return CommandResult{}, ErrGuardRequired
		}
	} else if handle != nil {
		return CommandResult{}, ErrGuardRequired
	}
	hashes, e := CommandHashes(request)
	if e != nil {
		return CommandResult{}, e
	}
	prepared, e := s.environment.Prepare(ctx, detached(request))
	if e != nil {
		return CommandResult{}, e
	}
	if nilEnvironment(prepared.Session) {
		return CommandResult{}, ErrGuardRequired
	}
	var pinned *time.Time
	if prepared.CapacityObservedAt != nil {
		sample := *prepared.CapacityObservedAt
		if !validDBTime(sample) {
			return CommandResult{}, ErrInvalid
		}
		pinned = &sample
	}
	p := &commandPolicy{environment: prepared.Session, capacityObservedAt: pinned, request: request, hashes: hashes, grants: map[ID]*commandGrant{}, runs: map[ID]*commandRun{}}
	runner, e := NewTransactions(s.db, s.scope, p)
	if e != nil {
		return CommandResult{}, e
	}
	runner.clock = s.clock
	commit, e := runner.Run(ctx, p.write)
	if !commit.Committed() {
		return CommandResult{}, e
	}
	result := CommandResult{Receipt: p.receipt, Replayed: p.replayed}
	if e != nil {
		return result, e
	}
	if !p.replayed && request.Command != "revoke" {
		result.Handle = &ExecutionHandle{issuer: s, scope: s.scope, subject: request.ActorIdentityHash, grant: p.receipt.Outcome.GrantID, generation: p.receipt.Outcome.GrantGeneration, version: p.receipt.Outcome.GrantRowVersion, run: p.receipt.Outcome.RunID}
	}
	return result, nil
}

type commandGrant struct {
	row    GrantRecord
	locked *LockedRecord
}
type commandRun struct {
	row    RunRecord
	locked *LockedRecord
}
type commandPolicy struct {
	environment        CommandSession
	capacityObservedAt *time.Time
	request            CommandRequest
	hashes             CommandDigests
	domain             DomainRecord
	admission          CommandAdmission
	receipt            CommandReceiptRecord
	receiptLock        *LockedRecord
	grants             map[ID]*commandGrant
	runs               map[ID]*commandRun
	target             TargetRecord
	targetLock         *LockedRecord
	replayed           bool
	cost               uint64
	plan               GuardPlan
}

// detached prevents callbacks from retaining or changing the policy's request,
// domain or final-state slices/pointers. Supported values are already validated.
func detached[T any](v T) T {
	raw, _ := json.Marshal(v)
	var copy T
	_ = json.Unmarshal(raw, &copy)
	return copy
}

func (p *commandPolicy) LockAndAuthorize(ctx context.Context, tx SQL, scope Scope) (GuardPlan, error) {
	r := p.request
	env := p.environment
	if scope != r.Scope {
		return GuardPlan{}, ErrInvalid
	}
	if e := env.LockInstallation(ctx, tx, detached(r)); e != nil {
		return GuardPlan{}, e
	}
	domainLock, e := tx.LockRecord(ctx, RecordKey{}, &p.domain)
	if e != nil {
		return GuardPlan{}, e
	}
	if !domainLock.Found() {
		return GuardPlan{}, ErrGuardRequired
	}
	a, e := env.Authenticate(ctx, tx, detached(r), detached(p.domain))
	if e != nil {
		return GuardPlan{}, e
	}
	a = detached(a)
	if a.RequestHash != p.hashes.Request || a.IdentityHash != r.ActorIdentityHash || len(a.Deadlines) == 0 || len(a.Deadlines) > 8 || (r.Command == "revoke" && !a.Management) {
		return GuardPlan{}, ErrGuardRequired
	}
	for _, d := range a.Deadlines {
		if !validDBTime(d) {
			return GuardPlan{}, ErrInvalid
		}
	}
	if a.TerminationDecisionHash != nil && (r.TerminationDecisionHash == nil || *a.TerminationDecisionHash != *r.TerminationDecisionHash) {
		return GuardPlan{}, ErrGuardRequired
	}
	if _, e = a.ReceiptRetentionUntil.Time(); e != nil {
		return GuardPlan{}, e
	}
	if _, e = a.AdditionalCost.Uint64(); e != nil {
		return GuardPlan{}, e
	}
	p.admission = a
	if p.domain.Epoch != r.ExpectedDomainEpoch || (r.Command != "revoke" && p.domain.State != "open") {
		return GuardPlan{}, ErrConflict
	}
	p.plan = GuardPlan{BindingHash: p.hashes.Request, Deadlines: append([]time.Time(nil), a.Deadlines...)}
	if r.Command != "revoke" {
		d, _ := p.domain.AdmissionExpiresAt.Time()
		p.plan.Deadlines = append(p.plan.Deadlines, d)
	}
	p.receiptLock, e = tx.LockRecord(ctx, RecordKey{Hash: p.hashes.Key}, &p.receipt)
	if e != nil {
		return GuardPlan{}, e
	}
	if p.receiptLock.Found() {
		if !a.HistoricalReceiptRead {
			return GuardPlan{}, ErrGuardRequired
		}
		if p.receipt.RequestHash != p.hashes.Request || !reflect.DeepEqual(p.receipt.Request, r) {
			return GuardPlan{}, ErrConflict
		}
		p.replayed = true
		return p.plan, nil // original receipt only; no L4-L9 mutation or new handle
	}
	retention, _ := a.ReceiptRetentionUntil.Time()
	p.plan.Deadlines = append(p.plan.Deadlines, retention)
	grantIDs, runIDs := []ID{}, []ID{}
	if r.Expected != nil {
		grantIDs = append(grantIDs, r.Expected.GrantID)
		runIDs = append(runIDs, r.Expected.RunID)
	}
	if r.Next != nil {
		grantIDs = append(grantIDs, r.Next.GrantID)
		runIDs = append(runIDs, r.Next.RunID)
	}
	sort.Slice(grantIDs, func(i, j int) bool { return grantIDs[i] < grantIDs[j] })
	sort.Slice(runIDs, func(i, j int) bool { return runIDs[i] < runIDs[j] })
	for _, id := range grantIDs {
		g := &commandGrant{}
		g.locked, e = tx.LockRecord(ctx, RecordKey{ID: id}, &g.row)
		if e != nil {
			return GuardPlan{}, e
		}
		p.grants[id] = g
	}
	for _, id := range runIDs {
		run := &commandRun{}
		run.locked, e = tx.LockRecord(ctx, RecordKey{ID: id}, &run.row)
		if e != nil {
			return GuardPlan{}, e
		}
		p.runs[id] = run
	}
	if e = env.LockHosts(ctx, tx, detached(r)); e != nil {
		return GuardPlan{}, e
	}
	targetHash, e := targetDigest(r.Target)
	if e != nil {
		return GuardPlan{}, e
	}
	p.targetLock, e = tx.LockRecord(ctx, RecordKey{Hash: targetHash}, &p.target)
	if e != nil {
		return GuardPlan{}, e
	}
	var now time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || !validDBTime(now) {
		return GuardPlan{}, ErrUnavailable
	}
	if e = p.prepare(now, targetHash); e != nil {
		return GuardPlan{}, e
	}
	if e = env.LockReferences(ctx, tx, detached(r)); e != nil {
		return GuardPlan{}, e
	}
	newRows := []any{&CommandReceiptRecord{}}
	if r.Next != nil {
		newRows = append(newRows, &GrantRecord{}, &RunRecord{})
		if !p.targetLock.Found() {
			newRows = append(newRows, &TargetRecord{})
		}
	}
	extra, _ := a.AdditionalCost.Uint64()
	p.cost, e = commandCost(extra, newRows)
	if e != nil {
		return GuardPlan{}, e
	}
	if p.capacityObservedAt == nil {
		return GuardPlan{}, ErrGuardRequired
	}
	if e = env.Reserve(ctx, tx, detached(r), p.cost); e != nil {
		return GuardPlan{}, e
	}
	observed := *p.capacityObservedAt
	p.plan.CapacityObservedAt = &observed
	return p.plan, nil
}

func nextCounter(c Counter) (Counter, error) {
	n, e := c.Uint64()
	if e != nil || n == ^uint64(0) {
		return "", ErrConflict
	}
	return Counter(strconv.FormatUint(n+1, 10)), nil
}
func commandCost(extra uint64, records []any) (uint64, error) {
	total := uint64(65536)
	for _, record := range records {
		s, e := storageFor(record)
		if e != nil {
			return 0, e
		}
		cost := uint64(65536 + (s.limit+4095)/4096*4096)
		if total > ^uint64(0)-cost {
			return 0, ErrInvalid
		}
		total += cost
	}
	if extra > uint64(1<<63-1) || total > uint64(1<<63-1)-extra {
		return 0, ErrInvalid
	}
	return total + extra, nil
}

func (p *commandPolicy) prepare(now time.Time, targetHash Hash) error {
	r := p.request
	stamp := Timestamp(now.Format(timeLayout))
	retention, _ := p.admission.ReceiptRetentionUntil.Time()
	if !now.Before(retention) {
		return ErrExpired
	}
	if r.Command == "acquire" {
		// Existing fences need the explicit old grant/run in a takeover command.
		if r.ExpectedTargetGeneration != "0" || p.targetLock.Found() {
			return ErrConflict
		}
	} else {
		expected := r.Expected
		g, run := p.grants[expected.GrantID], p.runs[expected.RunID]
		if !g.locked.Found() || !run.locked.Found() || !p.targetLock.Found() {
			return ErrConflict
		}
		if g.row.Generation != expected.GrantGeneration || g.row.RowVersion != expected.GrantRowVersion || run.row.GrantID != g.row.GrantID || run.row.GrantGeneration != g.row.Generation || run.row.TargetHash != targetHash || run.row.TargetGeneration != expected.TargetGeneration || p.target.Generation != expected.TargetGeneration || p.target.CurrentRunID != run.row.RunID || !reflect.DeepEqual(g.row.Target, p.target.Target) {
			return ErrConflict
		}
		oldEpoch, _ := g.row.DomainEpoch.Uint64()
		currentEpoch, _ := p.domain.Epoch.Uint64()
		if oldEpoch > currentEpoch {
			return ErrConflict
		}
		if r.Command != "takeover" && !reflect.DeepEqual(g.row.Target, r.Target) {
			return ErrConflict
		}
		if p.admission.ReceiptRetentionUntil < g.row.AuthorizationExpiresAt || p.admission.ReceiptRetentionUntil < run.row.OwnerWriteExpiresAt || (run.row.ObservationExpiresAt != nil && p.admission.ReceiptRetentionUntil < *run.row.ObservationExpiresAt) {
			return ErrInvalid
		}
		if r.Command == "renew" {
			if g.row.State != "active" || run.row.State == "superseded" || g.row.SubjectIdentityHash != r.ActorIdentityHash || g.row.DomainEpoch != p.domain.Epoch || !reflect.DeepEqual(g.row.Admission, p.domain.Admission) || !reflect.DeepEqual(g.row.Target, r.Target) {
				return ErrConflict
			}
			oldLease, _ := g.row.LeaseExpiresAt.Time()
			authorization, _ := g.row.AuthorizationExpiresAt.Time()
			lease, _ := r.LeaseExpiresAt.Time()
			if !now.Before(oldLease) || !now.Before(lease) || lease.After(authorization) {
				return ErrExpired
			}
			p.plan.Deadlines = append(p.plan.Deadlines, oldLease, lease, authorization)
			g.row.LeaseExpiresAt = *r.LeaseExpiresAt
			version, e := nextCounter(g.row.RowVersion)
			if e != nil {
				return e
			}
			g.row.RowVersion = version
		} else if r.Command == "revoke" {
			if g.row.State != "active" {
				return ErrConflict
			}
			g.row.State = "revoked"
			version, e := nextCounter(g.row.RowVersion)
			if e != nil {
				return e
			}
			g.row.RowVersion = version
		} else {
			oldLease, _ := g.row.LeaseExpiresAt.Time()
			if now.Before(oldLease) && (r.TerminationDecisionHash == nil || p.admission.TerminationDecisionHash == nil || *r.TerminationDecisionHash != *p.admission.TerminationDecisionHash) {
				return ErrGuardRequired
			}
			if g.row.State == "active" {
				g.row.State = "superseded"
				version, e := nextCounter(g.row.RowVersion)
				if e != nil {
					return e
				}
				g.row.RowVersion = version
			}
			if in(run.row.State, "acquired", "pending", "published") {
				run.row.State = "superseded"
				version, e := nextCounter(run.row.RowVersion)
				if e != nil {
					return e
				}
				run.row.RowVersion = version
			}
		}
	}
	if r.Next != nil {
		n := r.Next
		g, run := p.grants[n.GrantID], p.runs[n.RunID]
		if p.admission.ReceiptRetentionUntil < n.AuthorizationExpiresAt || p.admission.ReceiptRetentionUntil < n.OwnerWriteExpiresAt {
			return ErrInvalid
		}
		if g.locked.Found() || run.locked.Found() || !reflect.DeepEqual(n.Admission, p.domain.Admission) || n.IssuerIdentityHash != p.domain.IssuerIdentityHash {
			return ErrConflict
		}
		if r.Expected != nil && p.runs[r.Expected.RunID].row.EvidenceID == n.EvidenceID {
			return ErrConflict
		}
		lease, _ := r.LeaseExpiresAt.Time()
		authorization, _ := n.AuthorizationExpiresAt.Time()
		write, _ := n.OwnerWriteExpiresAt.Time()
		if !now.Before(lease) || !now.Before(authorization) || !now.Before(write) {
			return ErrExpired
		}
		p.plan.Deadlines = append(p.plan.Deadlines, lease, authorization, write)
		generation := Counter("1")
		version := Counter("1")
		resultVersion := ZeroCounter("0")
		if p.targetLock.Found() {
			var e error
			generation, e = nextCounter(p.target.Generation)
			if e != nil {
				return e
			}
			version, e = nextCounter(p.target.RowVersion)
			if e != nil {
				return e
			}
			resultVersion = p.target.ResultVersion
		}
		g.row = GrantRecord{Scope: r.Scope, GrantID: n.GrantID, Generation: n.GrantGeneration, DomainEpoch: p.domain.Epoch, RowVersion: "1", State: "active", SubjectIdentityHash: n.SubjectIdentityHash, IssuerIdentityHash: n.IssuerIdentityHash, Host: detached(n.Host), Admission: detached(n.Admission), Purpose: n.Purpose, Target: detached(r.Target), LeaseExpiresAt: *r.LeaseExpiresAt, AuthorizationExpiresAt: n.AuthorizationExpiresAt, CreatedAt: stamp}
		run.row = RunRecord{Scope: r.Scope, RunID: n.RunID, GrantID: n.GrantID, GrantGeneration: n.GrantGeneration, TargetHash: targetHash, TargetGeneration: generation, InputHash: n.InputHash, EvidenceID: n.EvidenceID, OwnerWriteExpiresAt: n.OwnerWriteExpiresAt, State: "acquired", RowVersion: "1"}
		p.target = TargetRecord{Scope: r.Scope, TargetHash: targetHash, Target: detached(r.Target), Generation: generation, CurrentRunID: n.RunID, ResultVersion: resultVersion, RowVersion: version}
	}
	return checkTime(context.Background(), p.plan, now)
}

func (p *commandPolicy) write(ctx context.Context, tx *Transaction) error {
	if p.replayed {
		return nil
	}
	r := p.request
	env := p.environment
	if e := env.Audit(ctx, tx, detached(r), "intent"); e != nil {
		return e
	}
	if r.Expected != nil {
		g, run := p.grants[r.Expected.GrantID], p.runs[r.Expected.RunID]
		if string(g.row.RowVersion) != strconv.FormatUint(g.locked.row.Columns["row_version"].(uint64), 10) {
			if e := tx.ReplaceRecord(ctx, g.locked, &g.row); e != nil {
				return e
			}
		}
		if string(run.row.RowVersion) != strconv.FormatUint(run.locked.row.Columns["row_version"].(uint64), 10) {
			if e := tx.ReplaceRecord(ctx, run.locked, &run.row); e != nil {
				return e
			}
		}
	}
	if r.Next != nil {
		g, run := p.grants[r.Next.GrantID], p.runs[r.Next.RunID]
		if e := tx.InsertRecord(ctx, g.locked, &g.row); e != nil {
			return e
		}
		if e := tx.InsertRecord(ctx, run.locked, &run.row); e != nil {
			return e
		}
		if p.targetLock.Found() {
			if e := tx.ReplaceRecord(ctx, p.targetLock, &p.target); e != nil {
				return e
			}
		} else {
			if e := tx.InsertRecord(ctx, p.targetLock, &p.target); e != nil {
				return e
			}
		}
	}
	var now time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || !validDBTime(now) {
		return ErrUnavailable
	}
	grantID, runID := ID(""), ID("")
	if r.Next != nil {
		grantID, runID = r.Next.GrantID, r.Next.RunID
	} else {
		grantID, runID = r.Expected.GrantID, r.Expected.RunID
	}
	g := p.grants[grantID].row
	p.receipt = CommandReceiptRecord{Scope: r.Scope, ReceiptKeyHash: p.hashes.Key, RequestHash: p.hashes.Request, Request: detached(r), Outcome: CommandExpected{GrantID: grantID, GrantGeneration: g.Generation, GrantRowVersion: g.RowVersion, RunID: runID, TargetGeneration: p.target.Generation}, CommittedAt: Timestamp(now.Format(timeLayout)), RetentionExpiresAt: p.admission.ReceiptRetentionUntil, ChargedBytes: Counter(strconv.FormatUint(p.cost, 10))}
	if e := tx.InsertRecord(ctx, p.receiptLock, &p.receipt); e != nil {
		return e
	}
	return env.Audit(ctx, tx, detached(r), "result")
}

func (p *commandPolicy) Recheck(ctx context.Context, tx ReadSQL, scope Scope, plan GuardPlan, now time.Time) error {
	if scope != p.request.Scope || plan.BindingHash != p.hashes.Request {
		return ErrGuardRequired
	}
	facts := CommandFacts{Domain: p.domain, Receipt: p.receipt, Replayed: p.replayed}
	if !p.replayed {
		facts.Target = &p.target
		ids := make([]string, 0, len(p.grants))
		for id := range p.grants {
			ids = append(ids, string(id))
		}
		sort.Strings(ids)
		for _, id := range ids {
			facts.Grants = append(facts.Grants, p.grants[ID(id)].row)
		}
		ids = nil
		for id := range p.runs {
			ids = append(ids, string(id))
		}
		sort.Strings(ids)
		for _, id := range ids {
			facts.Runs = append(facts.Runs, p.runs[ID(id)].row)
		}
	}
	return p.environment.Recheck(ctx, tx, detached(p.request), detached(facts), now)
}
