package systembackupevidence

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// NativeSystemPublicationVerifier has no public DTO constructor. It is created
// only together with the original opaque execution/claim-backed STS channel.
// Its separate TLS/SigV4 client independently HEADs the exact original key and
// requires the native immutable version and FULL_OBJECT SHA256/size to match.
// It grants no GET, PUT, claim, renewal, evaluator result or standalone proof.
type NativeSystemPublicationVerifier struct {
	mu                          sync.Mutex
	origin                      *NativeSystemPublicationVerifier
	sts                         *SystemSTSCredentials
	store                       *S3Store
	ctx                         context.Context
	proof                       SystemPublicationProof
	used, bound, closed, failed bool
}

// NewVerifiedSystemPublisher is the production constructor for the concrete
// independent verifier AND its mandatory original FinishAuthority binding.
// The remaining authorities/profile/absence are still independently mandatory.
// No caller verifier, ready boolean, FinishResult or proof hash is accepted.
func NewVerifiedSystemPublisher(ctx context.Context, e *pd.Execution, h *pd.ExecutionHandle, claim *pd.PublicationClaim, p Prepared, policy SystemSTSPolicy, profile SystemSTSProfileVerifier, absence S3AbsenceVerifier, authority SystemFinishAuthority) (*SystemPublisher, error) {
	if nilSystemAdapter(authority) || nilSystemAdapter(profile) || nilSystemAdapter(absence) {
		return nil, ErrDenied
	}
	sts, err := NewSystemExecutionSTSCredentials(ctx, e, h, claim, p, policy, profile)
	if err != nil {
		return nil, err
	}
	// Independent transport/client, original exact-key operation-specific native
	// STS resolver. Each read repeats live opaque D authorization + C profile.
	readStore, err := NewS3Store(policy.STS.Store, sts, downloadNoAbsence{})
	if err != nil {
		sts.Close()
		return nil, err
	}
	v := &NativeSystemPublicationVerifier{sts: sts, store: readStore}
	v.origin = v
	fail := func(err error) (*SystemPublisher, error) { v.Close(); sts.Close(); return nil, err }
	env, err := NewSystemFinishEnvironment(&nativePublicationFinishAuthority{verifier: v, original: authority}, p, policy.Channel, policy.History)
	if err != nil {
		return fail(err)
	}
	finish, err := pd.NewFinalizer(e, env)
	if err != nil {
		return fail(ErrDenied)
	}
	absenceGate := &systemPublicationAbsence{sts: sts, verifier: absence}
	writeStore, err := NewS3Store(policy.STS.Store, sts, absenceGate)
	if err != nil {
		return fail(err)
	}
	return &SystemPublisher{sts: sts, store: writeStore, finalizer: finish, claim: claim, verifier: v, absence: absenceGate, nativeVerifier: v}, nil
}

func (v *NativeSystemPublicationVerifier) VerifySystemPublication(ctx context.Context, q SystemPublicationProofRequest) (SystemPublicationProof, error) {
	var zero SystemPublicationProof
	if v == nil {
		return zero, ErrDenied
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.origin != v || v.closed || v.used || v.failed {
		v.failed = true
		return zero, ErrDenied
	}
	v.used = true // Every attempt, including a malformed one, consumes the reader.
	if nilSystemAdapter(ctx) || ctx.Err() != nil || v.sts == nil || v.store == nil || v.sts.recheck(ctx) != nil {
		return zero, ErrDenied
	}
	s := v.sts
	if s.views[0].Binding.Claim == nil {
		return zero, ErrDenied
	}
	r := s.original.record
	expected := ObjectInfo{SHA256: r.Manifest.ObjectHash, Size: r.Manifest.ObjectSize}
	if q.Scope != s.original.scope || q.RunID != s.original.runID || q.Claim != *s.views[0].Binding.Claim || q.PolicyHash != s.policy || q.ProviderProfileHash != s.c.ProviderProfileHash || q.ManifestHash != string(s.c.History.Evidence.ManifestHash) || q.Ref != r.Ref || q.Expected != expected || !q.Deadline.Equal(s.until) || !digestPattern.MatchString(q.Challenge) || q.Observation != "match" || q.Observed.SHA256 != expected.SHA256 || q.Observed.Size != expected.Size || !s3Version(q.Observed.Version) {
		return zero, ErrDenied
	}
	started := time.Now().UTC().Truncate(time.Microsecond)
	if !started.Before(q.Deadline) {
		return zero, ErrDenied
	}
	// A fresh actual native read, NEVER q.Observed or PUT acknowledgement as proof.
	actual, err := v.store.Stat(ctx, r.Ref)
	if err != nil {
		return zero, err
	} // 403/404/unavailable never become ready/unknown proof.
	if actual != q.Observed || actual.SHA256 != expected.SHA256 || actual.Size != expected.Size || !s3Version(actual.Version) {
		return zero, ErrIntegrity
	}
	if s.recheck(ctx) != nil {
		return zero, ErrDenied
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	until := earlier(q.Deadline, now.Add(30*time.Second))
	if now.Before(started) || !now.Before(until) || ctx.Err() != nil {
		return zero, ErrDenied
	}
	proof := SystemPublicationProof{Request: q, State: "ready", Object: actual, ObservedAt: now, ExpiresAt: until}
	// Unpredictable correlation bound to retained original private provenance.
	// The returned hash cannot reconstruct the sealed verifier state.
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return zero, ErrUnavailable
	}
	proof.ProofHash = hash(canonical(struct {
		Domain, Binding, Nonce string
		Proof                  SystemPublicationProof
	}{"system-backup-native-publication-readback.v1", s.binding, hex.EncodeToString(nonce), proof}))
	v.ctx, v.proof = ctx, proof
	return proof, nil
}

func (v *NativeSystemPublicationVerifier) Close() {
	if v == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.origin != v || v.closed {
		return
	}
	v.closed = true
	if v.store != nil {
		v.store.Close()
	}
}

var _ SystemPublicationVerifier = (*NativeSystemPublicationVerifier)(nil)
