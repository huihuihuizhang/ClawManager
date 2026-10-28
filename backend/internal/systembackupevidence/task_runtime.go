package systembackupevidence

import (
	"context"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

// TaskRuntimeConfig is admitted host configuration, never request JSON. Policy,
// Failure and Absence must be real control-plane/provider implementations.
type TaskRuntimeConfig struct {
	Authority TaskAuthorityConfig
	Registry  SQLRegistry
	S3        S3STSConfig
	Transit   TransitJWTConfig
	Absence   S3AbsenceVerifier
	Failure   func(context.Context, string, string)
}

// TaskRegistrationTimes comes from the locked owner/config lifecycle. The
// mandatory SQLPolicy.Admit independently checks these values at insertion.
type TaskRegistrationTimes struct{ Created, Expires, Protected, Deadline time.Time }

// TaskRuntime connects preparation, immutable registration and claim-scoped
// publication. The host owns durable ciphertext staging and retries Publish on
// the same registered bytes, never by calling Prepare again for an existing ID.
type TaskRuntime struct {
	authority *SQLTaskAuthority
	preparer  *TaskPreparer
	sts       *S3STSCredentials
	store     *S3Store
	service   Service
	closed    atomic.Bool
}

func NewTaskRuntime(c TaskRuntimeConfig) (*TaskRuntime, error) {
	a, s, reg := c.Authority, c.S3.Store, c.Registry
	if reg.DB == nil || reg.Policy == nil || reg.DB != a.DB || reg.Installation != a.Installation || reg.ServerUUID != a.ServerUUID || reg.Database != a.Database ||
		c.Absence == nil || c.Failure == nil || s.Installation != a.Installation || s.Identity != a.Store.Identity || s.Version != a.Store.Version || s.Root != a.Root ||
		c.S3.Issuer != a.Issuer || c.S3.Audience != a.Audience {
		return nil, ErrInvalid
	}
	authority, err := NewSQLTaskAuthority(a)
	if err != nil {
		return nil, err
	}
	r := &TaskRuntime{authority: authority}
	fail := func(err error) (*TaskRuntime, error) { r.Close(); return nil, err }
	r.preparer, err = NewTaskPreparer(authority, c.Transit)
	if err != nil {
		return fail(err)
	}
	r.sts, err = NewS3STSCredentials(c.S3, authority)
	if err != nil {
		return fail(err)
	}
	r.store, err = NewS3Store(s, r.sts, TaskAbsenceVerifier{Authority: authority, Verifier: c.Absence})
	if err != nil {
		return fail(err)
	}
	r.service = Service{Registry: reg, Store: taskWriteStore{r.store}, Failure: c.Failure}
	return r, nil
}

func (r *TaskRuntime) AuthenticateRequest(req *http.Request) (context.Context, error) {
	if r == nil || r.closed.Load() {
		return nil, ErrAuth
	}
	return r.authority.AuthenticateRequest(req)
}

func (r *TaskRuntime) Prepare(ctx context.Context, identity Identity, src Source, dst io.Writer) (Prepared, error) {
	if r == nil || r.closed.Load() {
		return Prepared{}, ErrDenied
	}
	return r.preparer.Prepare(ctx, identity, src, dst)
}

func (r *TaskRuntime) Register(ctx context.Context, p Prepared, times TaskRegistrationTimes) error {
	if r == nil || r.closed.Load() || !r.authority.accepts(p.manifest.Identity) || p.manifest.Key != r.preparer.c.Transit.Key {
		return ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if _, err := r.authority.authorizeKey(ctx, nil, &p.manifest.Key); err != nil {
		return ErrDenied
	}
	a := r.authority.c
	return r.service.Register(ctx, p, a.Root, Ref{Identity: a.Store.Identity, Version: a.Store.Version}, times.Created, times.Expires, times.Protected, times.Deadline)
}

func (r *TaskRuntime) Publish(ctx context.Context, id string, originalCiphertext Source) error {
	if r == nil || r.closed.Load() || !idPattern.MatchString(id) {
		return ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if _, err := r.authority.authorizeKey(ctx, nil, &r.preparer.c.Transit.Key); err != nil {
		return ErrDenied
	}
	// Reject another task's record before Service.Publish can acquire a claim
	// or update its failure state. The registry keeps identity/key immutable.
	if err := r.service.Registry.WithLocked(ctx, id, func(tx Locked) error {
		record := tx.Record()
		if record.Manifest.Identity.ID != id || !r.authority.accepts(record.Manifest.Identity) || record.Manifest.Key != r.preparer.c.Transit.Key {
			return ErrDenied
		}
		return nil
	}); err != nil {
		return boundary(err)
	}
	service := r.service
	service.Registry = taskPublishRegistry{Registry: service.Registry, actor: "task:" + r.authority.principal}
	err := service.Publish(ctx, id, originalCiphertext)
	if err != nil && err != ErrConflict && err != ErrState {
		failureCtx, failureCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer failureCancel()
		service.Failure(failureCtx, id, boundary(err).Error())
	}
	return err
}

// Close only after host request/worker draining; no caller-owned DB is closed.
func (r *TaskRuntime) Close() {
	if r != nil && !r.closed.Swap(true) {
		r.preparer.Close()
		r.store.Close()
		r.sts.Close()
	}
}

type taskWriteStore struct{ *S3Store }

func (taskWriteStore) Range(context.Context, Ref, int64, int64) (io.ReadCloser, error) {
	return nil, ErrDenied
}
func (taskWriteStore) Delete(context.Context, Ref, ObjectInfo) error { return ErrDenied }

// Add publish intent/result audit to the same transaction as each claim/state
// CAS. A failed audit aborts that transaction; never append it after a PUT.
type taskPublishRegistry struct {
	Registry
	actor string
}

func (r taskPublishRegistry) WithLocked(ctx context.Context, id string, fn func(Locked) error) error {
	return r.Registry.WithLocked(ctx, id, func(tx Locked) error { return fn(taskPublishLocked{Locked: tx, actor: r.actor}) })
}

type taskPublishLocked struct {
	Locked
	actor string
}

func (t taskPublishLocked) Save(ctx context.Context, next Record) error {
	old := t.Record()
	audit := Audit{EvidenceID: old.Manifest.Identity.ID, ActorID: t.actor}
	if next.Claim != "" && next.Claim != old.Claim && oneOf(old.State, "pending", "write_unknown") && next.State == old.State {
		audit.ID, audit.Action = next.Claim, "evidence.publish.intent"
	} else if old.Claim != "" && next.Claim == "" && oneOf(next.State, "ready", "write_unknown", "write_failed") {
		audit.ID, audit.Action, audit.Outcome = old.Claim, "evidence.publish.result", next.State
	} else {
		return ErrState
	}
	if err := t.Audit(ctx, audit); err != nil {
		return ErrAudit
	}
	return t.Locked.Save(ctx, next)
}

// TaskAbsenceVerifier gates the independently trusted provider proof on a live
// task and committed evidence claim, before and after external verification.
// This is authorization, not an implementation of provider absence semantics.
type TaskAbsenceVerifier struct {
	Authority *SQLTaskAuthority
	Verifier  S3AbsenceVerifier
}

func (v TaskAbsenceVerifier) VerifyAbsent(ctx context.Context, request S3AbsenceRequest) (S3AbsenceProof, error) {
	if v.Authority == nil || v.Verifier == nil {
		return S3AbsenceProof{}, ErrDenied
	}
	scope := S3Scope{Ref: request.Ref, Operation: S3Stat}
	before, err := v.Authority.authorize(ctx, &scope)
	if err != nil {
		return S3AbsenceProof{}, ErrDenied
	}
	ctx, cancel := context.WithDeadline(ctx, before.until.Add(-transitClockMargin))
	defer cancel()
	if ctx.Err() != nil {
		return S3AbsenceProof{}, ErrDenied
	}
	proof, err := v.Verifier.VerifyAbsent(ctx, request)
	if err != nil {
		return S3AbsenceProof{}, ErrUnavailable
	}
	after, err := v.Authority.authorize(ctx, &scope)
	if err != nil || after.leaseHash != before.leaseHash || proof.Request != request || ctx.Err() != nil || !time.Now().Before(after.until.Add(-transitClockMargin)) {
		return S3AbsenceProof{}, ErrDenied
	}
	return proof, nil
}
