package systembackupproducer

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"
	"sync"
	"time"
)

// SQL exposes no Commit/Rollback. It belongs to the one transaction that owns
// the installation/authorization/reference locks. It must not escape Work.
type SQL interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
	LockRecord(context.Context, RecordKey, any) (*LockedRecord, error)
}
type ReadSQL interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// GuardPlan contains already authenticated/locked facts. Its fields do NOT
// establish authentication. Only the mandatory trusted Policy supplies it.
// Every operation must include its identity, deployment, lease, observation and
// claim deadlines as applicable; the executor never discovers or substitutes
// them. Current-state proof is separately required through Policy.Recheck.
type GuardPlan struct {
	BindingHash        Hash
	Deadlines          []time.Time
	CapacityObservedAt *time.Time // the original report, never reread at commit
}
type Policy interface {
	// LockAndAuthorize must acquire the full reviewed L0-L6 prefix, authenticate
	// the caller, validate exact scope/config/grant/run/refs and return fixed facts.
	// No defaults. No network/provider I/O or nested transaction is permitted.
	LockAndAuthorize(context.Context, SQL, Scope) (GuardPlan, error)
	// Recheck runs after Work (including chunks, CAS and result audit). It must
	// check only the rows/ranges already locked by LockAndAuthorize. No new
	// business locks, files, remote work, audit or mutation is permitted here.
	Recheck(context.Context, ReadSQL, Scope, GuardPlan, time.Time) error
}
type Transactions struct {
	db     *sql.DB
	scope  Scope
	policy Policy
	clock  func() time.Time
}

func NewTransactions(db *sql.DB, scope Scope, policy Policy) (*Transactions, error) {
	if db == nil || nilPolicy(policy) || validateTyped(reflect.ValueOf(scope)) != nil {
		return nil, ErrGuardRequired
	}
	return &Transactions{db: db, scope: scope, policy: policy, clock: time.Now}, nil
}
func nilPolicy(p Policy) bool {
	if p == nil {
		return true
	}
	v := reflect.ValueOf(p)
	switch v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Func, reflect.Interface, reflect.Slice:
		return v.IsNil()
	}
	return false
}

// Transaction serializes query dispatch and latches mutation/CAS failures even
// if a caller accidentally ignores the error. Work is synchronous; callers
// must consume and close query rows before returning. The executor closes this
// capability before FinalGuard, rejecting retained use and goroutine late writes.
type Transaction struct {
	mu           sync.Mutex
	tx           *sql.Tx
	open         bool
	fault        error
	scope        Scope
	clockContext context.Context
	clockFloor   time.Time
	identity     *Transaction
}

// A copied public Transaction value must not copy an open SQL capability or a
// separate failure latch. Factory-issued sessions keep their original address;
// reject a value copy before locking its copied mutex and poison the ORIGINAL
// guard even when its caller ignores the error.
func (t *Transaction) rejectCopy() bool {
	if t == nil {
		return true
	}
	if original := t.identity; original != nil && original != t {
		original.mu.Lock()
		if original.fault == nil {
			original.fault = ErrGuardRequired
		}
		original.mu.Unlock()
		return true
	}
	return false
}

// SampleTime is the shared A/D clock for caller-owned guarded work. Callers
// must not scan independent authority timestamps from raw SQL in that path.
// Each successful sample advances one floor; a failed or backward sample is
// latched even if a callback ignores its error. Closing Work closes this API.
func (t *Transaction) SampleTime(ctx context.Context) (time.Time, error) {
	return t.sampleGuardTime(ctx, false)
}

func (t *Transaction) sampleGuardTime(ctx context.Context, internal bool) (time.Time, error) {
	if t.rejectCopy() {
		return time.Time{}, ErrGuardRequired
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.fault != nil {
		return time.Time{}, t.fault
	}
	fail := func(err error) (time.Time, error) { t.fault = err; return time.Time{}, err }
	if t.tx == nil || t.clockContext == nil || !sameBootstrapContext(ctx, t.clockContext) || (!internal && !t.open) {
		return fail(ErrGuardRequired)
	}
	if ctx.Err() != nil {
		return fail(ErrExpired)
	}
	now, err := sampleTime(ctx, t.tx)
	if err != nil {
		return fail(err)
	}
	if now.Before(t.clockFloor) {
		return fail(ErrExpired)
	}
	t.clockFloor = now
	return now, nil
}

func (t *Transaction) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	if t.rejectCopy() {
		return nil, ErrGuardRequired
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.open {
		return nil, ErrGuardRequired
	}
	if !statement(q, false) {
		t.fault = ErrGuardRequired
		return nil, t.fault
	}
	r, e := t.tx.ExecContext(ctx, q, args...)
	if e != nil {
		t.fault = ErrUnavailable
	}
	return r, e
}
func (t *Transaction) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	if t.rejectCopy() {
		return nil, ErrGuardRequired
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.open {
		return nil, ErrGuardRequired
	}
	if !statement(q, true) {
		t.fault = ErrGuardRequired
		return nil, t.fault
	}
	r, e := t.tx.QueryContext(ctx, q, args...)
	if e != nil {
		t.fault = ErrUnavailable
	}
	return r, e
}
func (t *Transaction) QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row {
	if t.rejectCopy() {
		if t == nil || t.identity == nil || t.identity.tx == nil {
			return nil
		}
		canceled, cancel := context.WithCancel(context.Background())
		cancel()
		return t.identity.tx.QueryRowContext(canceled, q, args...)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.open || !statement(q, true) {
		t.fault = ErrGuardRequired
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		return t.tx.QueryRowContext(canceled, q, args...)
	}
	return t.tx.QueryRowContext(ctx, q, args...)
}

// CAS must affect exactly one row; 0 or >1, RowsAffected errors and SQL errors
// make the whole transaction uncommittable even if Work ignores the result.
func (t *Transaction) CAS(ctx context.Context, q string, args ...any) error {
	if t.rejectCopy() {
		return ErrGuardRequired
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.open {
		return ErrGuardRequired
	}
	if !statement(q, false) {
		t.fault = ErrGuardRequired
		return t.fault
	}
	r, e := t.tx.ExecContext(ctx, q, args...)
	if e != nil {
		t.fault = ErrUnavailable
		return t.fault
	}
	n, e := r.RowsAffected()
	if e != nil || n != 1 {
		t.fault = ErrConflict
		return t.fault
	}
	return nil
}
func (t *Transaction) close() error {
	if t.rejectCopy() {
		return ErrGuardRequired
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.open = false
	return t.fault
}
func (t *Transaction) failure() error {
	if t.rejectCopy() {
		return ErrGuardRequired
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.fault
}

// Only reviewed single-statement SELECT/DML with parameterized data belongs in
// this API. Reject transaction control/DDL (which could commit before Guard),
// comments and statement separators. This is an integration safeguard, not a
// SQL sandbox against malicious Policy code or privileged stored functions.
func statement(q string, read bool) bool {
	if strings.ContainsAny(q, ";\x00") || strings.Contains(q, "/*") || strings.Contains(q, "--") || strings.Contains(q, "#") {
		return false
	}
	f := strings.Fields(q)
	if len(f) < 2 {
		return false
	}
	verb := strings.ToUpper(f[0])
	if read {
		return verb == "SELECT"
	}
	return verb == "INSERT" || verb == "UPDATE" || verb == "DELETE"
}

type readSQL struct {
	tx    *sql.Tx
	fault *error
}

func (r readSQL) QueryContext(c context.Context, q string, a ...any) (*sql.Rows, error) {
	if !statement(q, true) {
		*r.fault = ErrGuardRequired
		return nil, ErrGuardRequired
	}
	return r.tx.QueryContext(c, q, a...)
}
func (r readSQL) QueryRowContext(c context.Context, q string, a ...any) *sql.Row {
	if !statement(q, true) {
		*r.fault = ErrGuardRequired
		canceled, cancel := context.WithCancel(c)
		cancel()
		return r.tx.QueryRowContext(canceled, q, a...)
	}
	return r.tx.QueryRowContext(c, q, a...)
}

// CommitReceipt is local transaction metadata, NOT a persisted C1 result
// receipt or producer handle. Zero values have no committed proof and JSON
// cannot mint one. Query persisted idempotency receipts after commit uncertainty.
type CommitReceipt struct {
	committed bool
	at        time.Time
	binding   Hash
}

func (r CommitReceipt) Committed() bool            { return r.committed }
func (r CommitReceipt) LinearizedAt() time.Time    { return r.at }
func (r CommitReceipt) BindingHash() Hash          { return r.binding }
func (CommitReceipt) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*CommitReceipt) UnmarshalJSON([]byte) error  { return ErrInvalid }

var ErrCommittedExpired = errors.New("producer_committed_but_execution_expired")

// Run owns begin/guard/commit. It never retries and never returns a receipt on
// ambiguous commit. Policy and Work are trusted integration code, not HTTP
// callbacks. No production Policy exists until the C1 authority SQL is reviewed.
func (r *Transactions) Run(ctx context.Context, work func(context.Context, *Transaction) error) (CommitReceipt, error) {
	empty := CommitReceipt{}
	if r == nil || r.db == nil || nilPolicy(r.policy) || work == nil || ctx.Err() != nil {
		return empty, ErrGuardRequired
	}
	tx, e := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return empty, ErrUnavailable
	}
	defer tx.Rollback()
	var server, database string
	var now time.Time
	var offset int64
	if e = tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))").Scan(&server, &database, &now, &offset); e != nil || server != string(r.scope.ServerUUID) || database != string(r.scope.Database) || offset != 0 || !validDBTime(now) {
		return empty, ErrUnavailable
	}
	session := &Transaction{tx: tx, open: true, scope: r.scope}
	session.identity = session
	defer session.close()
	plan, e := r.policy.LockAndAuthorize(ctx, session, r.scope)
	if e != nil {
		return empty, e
	}
	if e = session.failure(); e != nil {
		return empty, e
	}
	plan = copyPlan(plan)
	if !validPlan(plan) {
		return empty, ErrGuardRequired
	}
	if now, e = sampleTime(ctx, tx); e != nil {
		return empty, e
	}
	if e = checkTime(ctx, plan, now); e != nil {
		return empty, e
	}
	if e = work(ctx, session); e != nil {
		return empty, e
	}
	if e = session.close(); e != nil {
		return empty, e
	}
	// This sample is AFTER every mutation and audit (including blocked writes).
	if now, e = sampleTime(ctx, tx); e != nil {
		return empty, e
	}
	if e = checkTime(ctx, plan, now); e != nil {
		return empty, e
	}
	var readFailure error
	if e = r.policy.Recheck(ctx, readSQL{tx: tx, fault: &readFailure}, r.scope, copyPlan(plan), now); e != nil {
		return empty, e
	}
	if readFailure != nil {
		return empty, readFailure
	}
	if e = session.failure(); e != nil {
		return empty, e
	}
	// Recheck queries can also wait; they cannot reuse their earlier timestamp.
	if now, e = sampleTime(ctx, tx); e != nil {
		return empty, e
	}
	if e = checkTime(ctx, plan, now); e != nil {
		return empty, e
	}
	if e = tx.Commit(); e != nil {
		return empty, ErrCommitUnknown
	}
	receipt := CommitReceipt{committed: true, at: now, binding: plan.BindingHash}
	// A known commit after expiry is a historical fact, not permission to send
	// the next provider call. Preserve that distinction for the caller.
	if e = checkTime(ctx, plan, r.clock().UTC()); e != nil {
		return receipt, ErrCommittedExpired
	}
	return receipt, nil
}

// GuardInTx performs the same L0-L10 checks and work in a caller-owned
// transaction. It never commits or rolls back. The caller must begin a
// repeatable-read MySQL transaction, hold the reviewed lock prefix, roll back
// on every error, and commit only after this method succeeds. A nil return is
// an uncommitted authorization decision, never a persisted receipt.
func (r *Transactions) GuardInTx(ctx context.Context, tx *sql.Tx, work func(context.Context, *Transaction) error) error {
	if r == nil || tx == nil || nilPolicy(r.policy) || work == nil || !sameBootstrapContext(ctx, ctx) || ctx.Err() != nil {
		return ErrGuardRequired
	}
	var server, database string
	var now time.Time
	var offset int64
	if err := tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))").Scan(&server, &database, &now, &offset); err != nil || server != string(r.scope.ServerUUID) || database != string(r.scope.Database) || offset != 0 || !validDBTime(now) {
		return ErrUnavailable
	}
	session := &Transaction{tx: tx, open: true, scope: r.scope, clockContext: ctx, clockFloor: now}
	session.identity = session
	defer session.close()
	plan, err := r.policy.LockAndAuthorize(ctx, session, r.scope)
	if err != nil {
		return err
	}
	if err = session.failure(); err != nil {
		return err
	}
	plan = copyPlan(plan)
	if !validPlan(plan) {
		return ErrGuardRequired
	}
	if now, err = session.sampleGuardTime(ctx, true); err != nil {
		return err
	}
	if err = checkTime(ctx, plan, now); err != nil {
		return err
	}
	if err = work(ctx, session); err != nil {
		return err
	}
	if err = session.close(); err != nil {
		return err
	}
	if now, err = session.sampleGuardTime(ctx, true); err != nil {
		return err
	}
	if err = checkTime(ctx, plan, now); err != nil {
		return err
	}
	var readFailure error
	if err = r.policy.Recheck(ctx, readSQL{tx: tx, fault: &readFailure}, r.scope, copyPlan(plan), now); err != nil {
		return err
	}
	if readFailure != nil {
		return readFailure
	}
	if err = session.failure(); err != nil {
		return err
	}
	if now, err = session.sampleGuardTime(ctx, true); err != nil {
		return err
	}
	return checkTime(ctx, plan, now)
}
func copyPlan(p GuardPlan) GuardPlan {
	p.Deadlines = append([]time.Time(nil), p.Deadlines...)
	if p.CapacityObservedAt != nil {
		t := *p.CapacityObservedAt
		p.CapacityObservedAt = &t
	}
	return p
}
func validPlan(p GuardPlan) bool {
	if !hashPattern.MatchString(string(p.BindingHash)) || len(p.Deadlines) == 0 || len(p.Deadlines) > 16 {
		return false
	}
	for _, t := range p.Deadlines {
		if !validDBTime(t) {
			return false
		}
	}
	return p.CapacityObservedAt == nil || validDBTime(*p.CapacityObservedAt)
}
func validDBTime(t time.Time) bool {
	_, offset := t.Zone()
	return !t.IsZero() && offset == 0 && t.Year() >= 1000 && t.Year() <= 9999 && t.Nanosecond()%1000 == 0
}
func sampleTime(ctx context.Context, tx *sql.Tx) (time.Time, error) {
	var t time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&t) != nil || !validDBTime(t) {
		return time.Time{}, ErrUnavailable
	}
	return t, nil
}
func checkTime(ctx context.Context, p GuardPlan, now time.Time) error {
	if ctx.Err() != nil {
		return ErrExpired
	}
	for _, until := range p.Deadlines {
		if !now.Before(until) {
			return ErrExpired
		}
	}
	if p.CapacityObservedAt != nil && (now.Before(*p.CapacityObservedAt) || now.Sub(*p.CapacityObservedAt) > 5*time.Second) {
		return ErrExpired
	}
	return nil
}
