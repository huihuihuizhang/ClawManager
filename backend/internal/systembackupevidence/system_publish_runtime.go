package systembackupevidence

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"strconv"
	"sync/atomic"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// SystemPublicationProofRequest binds a fresh independent C verification to
// this exact claim and object. Local observations are inputs, never proof.
type SystemPublicationProofRequest struct {
	Scope                                         pd.Scope
	RunID                                         pd.ID
	Claim                                         pd.ClaimBinding
	PolicyHash, ProviderProfileHash, ManifestHash string
	Ref                                           Ref
	Expected, Observed                            ObjectInfo
	Observation                                   string // match, mismatch, unavailable
	PutAttempted                                  bool
	Challenge                                     string
	Deadline                                      time.Time
}

type SystemPublicationProof struct {
	Request               SystemPublicationProofRequest
	State                 string // ready or write_unknown
	Object                ObjectInfo
	ProofHash             string
	ObservedAt, ExpiresAt time.Time
}

// The verifier authenticates C provenance and the complete request, including
// original claim/store/key/manifest/version/time. FinishAuthority independently
// authenticates this proof again by ProofHash; the hash itself grants nothing.
// An unavailable provider may establish only an inconclusive write_unknown
// result. There is no default verifier and no caller-supplied ready switch.
type SystemPublicationVerifier interface {
	VerifySystemPublication(context.Context, SystemPublicationProofRequest) (SystemPublicationProof, error)
}

type systemPublicationStore interface {
	Stat(context.Context, Ref) (ObjectInfo, error)
	Absent(context.Context, Ref) (Absence, error)
	Put(context.Context, Ref, io.Reader, ObjectInfo, time.Time) error
	Close()
}
type systemPublicationFinalizer interface {
	FinishPublication(context.Context, *pd.PublicationClaim, pd.FinishRequest) (pd.FinishResult, error)
}

// SystemPublisher owns one committed claim's original STS snapshots and one
// publication attempt. It never claims, renews, wraps, regenerates IDs, or uses
// the legacy task registry. The host retains staging for subsequent recovery.
// Close must follow draining Publish; returned FinishResult is not an evaluator
// receipt. The host must separately invoke D CommitResult.
type SystemPublisher struct {
	sts          *SystemSTSCredentials
	store        systemPublicationStore
	finalizer    systemPublicationFinalizer
	claim        *pd.PublicationClaim
	verifier     SystemPublicationVerifier
	absence      *systemPublicationAbsence
	used, closed atomic.Bool
}

// Preserve C's absence expiry through staging and the signed upload. S3Store
// validates challenge/freshness too, but its legacy Absence value omits expiry.
type systemPublicationAbsence struct {
	sts      *SystemSTSCredentials
	verifier S3AbsenceVerifier
	until    time.Time
}

func (a *systemPublicationAbsence) VerifyAbsent(ctx context.Context, q S3AbsenceRequest) (S3AbsenceProof, error) {
	a.until = time.Time{}
	if q.Ref != a.sts.original.record.Ref || a.sts.recheck(ctx) != nil {
		return S3AbsenceProof{}, ErrDenied
	}
	started := time.Now().UTC().Truncate(time.Second)
	p, err := a.verifier.VerifyAbsent(ctx, q)
	now := time.Now()
	if a.sts.recheck(ctx) != nil || err != nil || p.Request != q || p.ObservedAt.Before(started) || p.ObservedAt.After(now) || !now.Before(p.ExpiresAt) || p.ExpiresAt.After(p.ObservedAt.Add(30*time.Second)) {
		return S3AbsenceProof{}, ErrDenied
	}
	a.until = earlier(a.sts.until, p.ExpiresAt)
	return p, nil
}

func NewSystemPublisher(ctx context.Context, e *pd.Execution, h *pd.ExecutionHandle, claim *pd.PublicationClaim, p Prepared, policy SystemSTSPolicy, profile SystemSTSProfileVerifier, absence S3AbsenceVerifier, verifier SystemPublicationVerifier, authority SystemFinishAuthority) (*SystemPublisher, error) {
	if nilSystemAdapter(absence) || nilSystemAdapter(verifier) || nilSystemAdapter(authority) {
		return nil, ErrDenied
	}
	env, err := NewSystemFinishEnvironment(authority, p, policy.Channel, policy.History)
	if err != nil {
		return nil, err
	}
	finish, err := pd.NewFinalizer(e, env)
	if err != nil {
		return nil, ErrDenied
	}
	sts, err := NewSystemExecutionSTSCredentials(ctx, e, h, claim, p, policy, profile)
	if err != nil {
		return nil, err
	}
	absenceGate := &systemPublicationAbsence{sts: sts, verifier: absence}
	store, err := NewS3Store(policy.STS.Store, sts, absenceGate)
	if err != nil {
		sts.Close()
		return nil, err
	}
	return &SystemPublisher{sts: sts, store: store, finalizer: finish, claim: claim, verifier: verifier, absence: absenceGate}, nil
}

func (p *SystemPublisher) check(ctx context.Context) error {
	if p == nil || ctx == nil || ctx.Err() != nil || p.closed.Load() || p.sts == nil || p.sts.closed.Load() || !time.Now().Before(p.sts.until) {
		return ErrDenied
	}
	return p.sts.recheck(ctx)
}

func (p *SystemPublisher) Publish(ctx context.Context, originalCiphertext Source) (pd.FinishResult, error) {
	if p.check(ctx) != nil || nilSystemAdapter(p.store) || nilSystemAdapter(p.finalizer) || nilSystemAdapter(p.verifier) || p.absence == nil || p.used.Swap(true) {
		return pd.FinishResult{}, ErrDenied
	}
	ctx, cancel := context.WithDeadline(ctx, p.sts.until)
	defer cancel()
	r := p.sts.original.record
	info, statErr := p.store.Stat(ctx, r.Ref)
	if p.check(ctx) != nil {
		return pd.FinishResult{}, ErrDenied
	}
	attempted := false
	// Integrity/authorization failures never authorize a write. A generic 404
	// is unavailable and still requires an independent fresh exact-key proof.
	if statErr == ErrUnavailable {
		absent, err := p.store.Absent(ctx, r.Ref)
		if p.check(ctx) != nil {
			return pd.FinishResult{}, ErrDenied
		}
		if err == nil && absent.Authoritative && absent.Version == "" && originalCiphertext != nil {
			putCtx, cancelPut := context.WithDeadline(ctx, p.absence.until)
			defer cancelPut()
			body, err := p.readOriginal(putCtx, originalCiphertext)
			if err != nil {
				return pd.FinishResult{}, err
			}
			defer wipe(body)
			if p.check(putCtx) != nil {
				return pd.FinishResult{}, ErrDenied
			}
			attempted = true
			// A lost response or conditional conflict is resolved only by a new
			// exact Stat and C proof, never a second PUT in this attempt.
			_ = p.store.Put(putCtx, r.Ref, bytes.NewReader(body), ObjectInfo{SHA256: r.Manifest.ObjectHash, Size: r.Manifest.ObjectSize}, r.OwnerDeadline)
			cancelPut()
			if p.check(ctx) != nil {
				return pd.FinishResult{}, ErrDenied
			}
			info, statErr = p.store.Stat(ctx, r.Ref)
			if p.check(ctx) != nil {
				return pd.FinishResult{}, ErrDenied
			}
		}
	}
	return p.finish(ctx, info, statErr, attempted)
}

func (p *SystemPublisher) readOriginal(ctx context.Context, source Source) ([]byte, error) {
	if p.check(ctx) != nil {
		return nil, ErrDenied
	}
	r, err := source()
	if err != nil || nilSystemAdapter(r) {
		if !nilSystemAdapter(r) {
			_ = r.Close()
		}
		return nil, ErrUnavailable
	}
	if p.check(ctx) != nil {
		_ = r.Close()
		return nil, ErrDenied
	}
	m := p.sts.original.record.Manifest
	body, err := io.ReadAll(io.LimitReader(r, m.ObjectSize+1))
	closeErr := r.Close()
	if p.check(ctx) != nil {
		wipe(body)
		return nil, ErrDenied
	}
	if err != nil || closeErr != nil {
		wipe(body)
		return nil, ErrUnavailable
	}
	if int64(len(body)) != m.ObjectSize || hash(body) != m.ObjectHash {
		wipe(body)
		return nil, ErrIntegrity
	}
	return body, nil
}

func (p *SystemPublisher) finish(ctx context.Context, info ObjectInfo, statErr error, attempted bool) (pd.FinishResult, error) {
	if p.check(ctx) != nil {
		return pd.FinishResult{}, ErrDenied
	}
	r := p.sts.original.record
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return pd.FinishResult{}, ErrUnavailable
	}
	q := SystemPublicationProofRequest{Scope: p.sts.c.History.Scope, RunID: p.sts.c.History.RunID, Claim: *p.sts.views[0].Binding.Claim, PolicyHash: p.sts.policy, ProviderProfileHash: p.sts.c.ProviderProfileHash, ManifestHash: string(p.sts.c.History.Evidence.ManifestHash), Ref: r.Ref, Expected: ObjectInfo{SHA256: r.Manifest.ObjectHash, Size: r.Manifest.ObjectSize}, PutAttempted: attempted, Challenge: hex.EncodeToString(challenge), Deadline: p.sts.until, Observation: "unavailable"}
	if statErr == nil {
		q.Observed = info
		q.Observation = "mismatch"
		if matchObject(r, info) && s3Version(info.Version) {
			q.Observation = "match"
		}
	}
	started := time.Now().UTC().Truncate(time.Microsecond)
	proof, err := p.verifier.VerifySystemPublication(ctx, q)
	now := time.Now()
	if p.check(ctx) != nil || err != nil || proof.Request != q || !digestPattern.MatchString(proof.ProofHash) || proof.ObservedAt.Before(started) || proof.ObservedAt.After(now) || !now.Before(proof.ExpiresAt) || proof.ExpiresAt.After(q.Deadline) || proof.ExpiresAt.After(proof.ObservedAt.Add(30*time.Second)) {
		return pd.FinishResult{}, ErrDenied
	}
	request := pd.FinishRequest{State: proof.State, ProofHash: pd.Hash(proof.ProofHash), ObjectHash: pd.Hash(r.Manifest.ObjectHash), ObjectBytes: pd.Counter(strconv.FormatInt(r.Manifest.ObjectSize, 10)), ObservedAt: systemPublicationTimestamp(proof.ObservedAt), BudgetUntil: systemPublicationTimestamp(earlier(p.sts.until, proof.ExpiresAt))}
	switch proof.State {
	case "ready":
		if q.Observation != "match" || proof.Object != info {
			return pd.FinishResult{}, ErrIntegrity
		}
		v := pd.Text(info.Version)
		request.ImmutableVersion = &v
	case "write_unknown":
		if proof.Object != (ObjectInfo{}) {
			return pd.FinishResult{}, ErrIntegrity
		}
	default:
		return pd.FinishResult{}, ErrDenied
	}
	if p.check(ctx) != nil {
		return pd.FinishResult{}, ErrDenied
	}
	// The concrete production finalizer repeats current authorization and C
	// provenance inside D's transaction and performs its final Guard before CAS.
	return p.finalizer.FinishPublication(ctx, p.claim, request)
}

func (p *SystemPublisher) Close() {
	if p != nil && !p.closed.Swap(true) {
		if p.sts != nil {
			p.sts.Close()
		}
		if !nilSystemAdapter(p.store) {
			p.store.Close()
		}
	}
}
