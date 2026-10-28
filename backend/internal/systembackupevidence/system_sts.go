package systembackupevidence

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// SystemSTSPolicy is independently admitted deployment/channel data. Its hash
// must be approved by D before claiming publication; it is not authorization.
type SystemSTSPolicy struct {
	History                                         pd.HistoricalBindingRecord
	Channel                                         ProducerEvidenceChannel
	STS                                             S3STSConfig
	SubjectIdentityHash, IssuerIdentityHash         string
	Subject, TokenFile                              string
	AuthenticationAudience, AuthenticationTokenFile string
	ProviderProfileHash                             string
}

func SystemSTSPolicyHash(c SystemSTSPolicy) string {
	c.STS.CAPEM, c.STS.Store.CAPEM = nil, nil
	raw, err := json.Marshal(struct {
		Domain string
		Policy SystemSTSPolicy
	}{"system-backup-system-sts-policy.v1", c})
	if err != nil {
		return ""
	}
	return hash(raw)
}

// The independent C verifier must verify real endpoint/role/CA/ACL and deadline
// enforcement for this exact policy and operation. In particular IAM GetObject
// alone does NOT isolate HEAD from GET/Range. Stat requires a reviewed restricted
// channel/provider proof; local method filtering cannot establish remote ACLs.
// Hashes are lookup/correlation data, never proof. No success default exists.
type SystemSTSProfileVerifier interface {
	VerifySystemSTSProfile(context.Context, SystemSTSProfileRequest) error
}
type SystemSTSProfileRequest struct {
	PolicyHash, ProviderProfileHash string
	Scope                           pd.Scope
	RunID                           pd.ID
	ManifestHash                    pd.Hash
	Claim                           pd.ClaimBinding
	STS                             S3STSConfig // CA hashes retained; owned PEM bytes omitted
	Operation                       S3Scope
	Deadline                        time.Time
}

// One instance retains one pair of committed D snapshots. It never renews them,
// claims evidence, performs PUT, or grants historical recovery privileges.
type SystemSTSCredentials struct {
	c               SystemSTSPolicy
	original        systemPublicationOriginal
	transport       *S3STSCredentials
	calls           systemExecutionCalls
	snapshots       [2]systemCallSnapshot
	views           [2]pd.SnapshotView
	verifier        SystemSTSProfileVerifier
	policy, binding string
	until           time.Time
	closed          atomic.Bool
}

type systemDPublicationCalls struct {
	execution *pd.Execution
	handle    *pd.ExecutionHandle
	claim     *pd.PublicationClaim
}

func (d systemDPublicationCalls) begin(ctx context.Context, r pd.CallRequest) (systemCallSnapshot, error) {
	return d.execution.BeginCall(ctx, d.handle, r, d.claim)
}
func (d systemDPublicationCalls) recheck(ctx context.Context, s systemCallSnapshot) error {
	v, ok := s.(*pd.CallSnapshot)
	if !ok || v == nil {
		return ErrDenied
	}
	return d.execution.RecheckCall(ctx, v)
}

// No public callback can replace D's opaque handle/claim/snapshot validation.
// Provider verification is an additional independent gate, never its substitute.
func NewSystemExecutionSTSCredentials(ctx context.Context, e *pd.Execution, h *pd.ExecutionHandle, claim *pd.PublicationClaim, prepared Prepared, c SystemSTSPolicy, verifier SystemSTSProfileVerifier) (*SystemSTSCredentials, error) {
	if e == nil || h == nil || claim == nil {
		return nil, ErrDenied
	}
	return newSystemSTSCredentials(ctx, systemDPublicationCalls{e, h, claim}, prepared, c, verifier)
}

func newSystemSTSCredentials(ctx context.Context, calls systemExecutionCalls, prepared Prepared, c SystemSTSPolicy, verifier SystemSTSProfileVerifier) (*SystemSTSCredentials, error) {
	if ctx == nil || ctx.Err() != nil || nilSystemAdapter(calls) || nilSystemAdapter(verifier) ||
		!digestPattern.MatchString(c.SubjectIdentityHash) || !digestPattern.MatchString(c.IssuerIdentityHash) || !digestPattern.MatchString(c.ProviderProfileHash) ||
		!s3Token([]byte(c.Subject), 6, 255) || !filepath.IsAbs(c.TokenFile) || !filepath.IsAbs(c.AuthenticationTokenFile) ||
		!s3Token([]byte(c.AuthenticationAudience), 1, 255) || c.AuthenticationAudience == c.STS.Audience || strings.EqualFold(filepath.Clean(c.TokenFile), filepath.Clean(c.AuthenticationTokenFile)) {
		return nil, ErrDenied
	}
	// Retain detached historical admission pointers, never caller-mutable data.
	var history pd.HistoricalBindingRecord
	if pd.DecodeRecord(canonical(c.History), &history) != nil {
		return nil, ErrInvalid
	}
	c.History = history
	o, err := newSystemPublicationOriginal(prepared, c.Channel, history)
	if err != nil {
		return nil, err
	}
	store := c.STS.Store
	if store.Identity != c.Channel.Store.Identity || store.Version != c.Channel.Store.Version || store.Root != c.Channel.Root || store.Installation != o.record.Manifest.Identity.Installation {
		return nil, ErrDenied
	}
	transport, err := newS3STSTransport(c.STS)
	if err != nil {
		return nil, err
	}
	policy := SystemSTSPolicyHash(c)
	c.STS.CAPEM, c.STS.Store.CAPEM = nil, nil
	s := &SystemSTSCredentials{c: c, original: o, transport: transport, calls: calls, verifier: verifier, policy: policy}
	fail := func() (*SystemSTSCredentials, error) { s.Close(); return nil, ErrDenied }
	budget := time.Now().UTC().Add(20 * time.Second).Truncate(time.Microsecond)
	if d, ok := ctx.Deadline(); ok {
		budget = earlier(budget, d.UTC().Truncate(time.Microsecond))
	}
	budget = earlier(budget, o.record.OwnerDeadline)
	ctx, cancel := context.WithDeadline(ctx, budget)
	defer cancel()
	for n, purpose := range []string{"sts", "publish"} {
		ref := c.Channel.Write
		if purpose == "publish" {
			ref = c.Channel.Store
		}
		r := pd.CallRequest{Purpose: purpose, EvidenceID: history.Evidence.EvidenceID, RefIdentityHash: pd.Hash(ref.Identity), RefVersion: pd.ProviderVersion(ref.Version), PolicyHash: pd.Hash(policy), BudgetUntil: systemPublicationTimestamp(budget)}
		v, err := calls.begin(ctx, r)
		if err != nil || nilSystemAdapter(v) || !s.matchesSnapshot(r, v, v.View()) {
			return fail()
		}
		s.snapshots[n], s.views[n] = v, v.View()
	}
	left, right := s.views[0], s.views[1]
	left.Binding.Call, right.Binding.Call = pd.CallRequest{}, pd.CallRequest{}
	left.Facts.Admission.RequestHash, right.Facts.Admission.RequestHash = "", ""
	left.Facts.References.RequestHash, right.Facts.References.RequestHash = "", ""
	if !reflect.DeepEqual(left.Binding, right.Binding) || !reflect.DeepEqual(left.Facts, right.Facts) {
		return fail()
	}
	s.until = earlier(budget, earlier(s.snapshots[0].Deadline(), s.snapshots[1].Deadline())).Add(-transitClockMargin)
	s.binding = hash(canonical(struct {
		Policy       string
		STS, Publish pd.Hash
		Until        time.Time
	}{policy, s.snapshots[0].BindingHash(), s.snapshots[1].BindingHash(), s.until}))
	if ctx.Err() != nil || !time.Now().Before(s.until) {
		return fail()
	}
	return s, nil
}

func (s *SystemSTSCredentials) matchesSnapshot(r pd.CallRequest, snapshot systemCallSnapshot, v pd.SnapshotView) bool {
	b, f, h := v.Binding, v.Facts, s.c.History
	expiry, err := v.ValidUntil.Time()
	budget, _ := r.BudgetUntil.Time()
	if err != nil || !expiry.Equal(snapshot.Deadline()) || expiry.After(budget) || !time.Now().Before(expiry) || v.BindingHash != snapshot.BindingHash() || !digestPattern.MatchString(string(v.BindingHash)) || snapshot.Purpose() != r.Purpose || b.Kind != "call" || b.Call != r || b.Scope != h.Scope || b.RunID != h.RunID || b.GrantID != h.GrantID || b.GrantGeneration != h.GrantGeneration || string(b.Subject) != s.c.SubjectIdentityHash || b.Claim == nil || b.Observation != nil || b.ProbeSnapshotHash != nil {
		return false
	}
	if f.Domain.Scope != h.Scope || f.Domain.Epoch != h.DomainEpoch || string(f.Domain.IssuerIdentityHash) != s.c.IssuerIdentityHash || !reflect.DeepEqual(f.Domain.Admission, h.Admission) || f.Grant.Scope != h.Scope || f.Grant.GrantID != h.GrantID || f.Grant.Generation != h.GrantGeneration || f.Grant.RowVersion != b.GrantVersion || f.Run.Scope != h.Scope || f.Target.Scope != h.Scope || f.Run.RunID != h.RunID || f.Run.InputHash != h.InputHash || f.Run.EvidenceID != h.Evidence.EvidenceID || f.Run.State != "pending" || f.Run.OwnerWriteExpiresAt != h.OwnerWriteExpiresAt || f.Run.ObservedAt == nil || *f.Run.ObservedAt != h.ObservedAt || f.Run.ObservationExpiresAt == nil || *f.Run.ObservationExpiresAt != h.ObservationExpiresAt {
		return false
	}
	if f.Run.TargetHash != h.TargetHash || f.Target.TargetHash != h.TargetHash {
		return false
	}
	claim, evidence := b.Claim, f.Evidence
	claimUntil, err := claim.ExpiresAt.Time()
	return err == nil && !expiry.After(claimUntil) && claim.EvidenceID == h.Evidence.EvidenceID && claim.ManifestHash == h.Evidence.ManifestHash && claim.PolicyHash == r.PolicyHash && f.References.PolicyHash == r.PolicyHash && claim.RefsVersionHash == f.References.VersionHash && evidence != nil && evidence.EvidenceID == claim.EvidenceID && evidence.OwnerType == "system" && evidence.OwnerID == h.Scope.Installation && evidence.EvidenceType == "capability_snapshot" && oneOf(evidence.State, "pending", "write_unknown") && evidence.RowVersion == pd.ZeroCounter(claim.EvidenceVersion) && evidence.ManifestHash != nil && *evidence.ManifestHash == claim.ManifestHash && evidence.ClaimOwner != nil && *evidence.ClaimOwner == claim.Owner && evidence.ClaimExpiresAt != nil && *evidence.ClaimExpiresAt == claim.ExpiresAt
}

func (s *SystemSTSCredentials) accepts(scope S3Scope) bool {
	if s == nil || scope.Ref != s.original.record.Ref {
		return false
	}
	want := S3Scope{Ref: s.original.record.Ref, Operation: scope.Operation}
	switch scope.Operation {
	case S3Stat:
	case S3Put:
		want.Object = ObjectInfo{SHA256: s.original.record.Manifest.ObjectHash, Size: s.original.record.Manifest.ObjectSize}
		want.Deadline = s.original.record.OwnerDeadline
	default:
		return false
	}
	return scope == want
}

func (s *SystemSTSCredentials) authorize(ctx context.Context, scope S3Scope) (stsExchangeGrant, error) {
	if s == nil || s.closed.Load() || ctx == nil || ctx.Err() != nil || !s.accepts(scope) || !time.Now().Before(s.until) {
		return stsExchangeGrant{}, ErrDenied
	}
	if s.recheck(ctx) != nil {
		return stsExchangeGrant{}, ErrDenied
	}
	request := SystemSTSProfileRequest{s.policy, s.c.ProviderProfileHash, s.c.History.Scope, s.c.History.RunID, s.c.History.Evidence.ManifestHash, *s.views[0].Binding.Claim, s.c.STS, scope, s.until}
	if s.verifier.VerifySystemSTSProfile(ctx, request) != nil || ctx.Err() != nil || !time.Now().Before(s.until) {
		return stsExchangeGrant{}, ErrDenied
	}
	jwt, expiry, err := readProjectedToken(s.c.TokenFile, s.c.STS.Issuer, s.c.STS.Audience, s.c.Subject)
	if err != nil {
		return stsExchangeGrant{}, ErrDenied
	}
	if s.recheck(ctx) != nil {
		wipe(jwt)
		return stsExchangeGrant{}, ErrDenied
	}
	return stsExchangeGrant{Authorization: stsExchangeAuthorization{BindingHash: s.binding, Subject: s.c.Subject, ExpiresAt: s.until}, Token: jwt, TokenExpiresAt: expiry}, nil
}

func (s *SystemSTSCredentials) recheck(ctx context.Context) error {
	for n, snapshot := range s.snapshots {
		if !reflect.DeepEqual(snapshot.View(), s.views[n]) || s.calls.recheck(ctx, snapshot) != nil {
			return ErrDenied
		}
	}
	if ctx.Err() != nil || s.closed.Load() || !time.Now().Before(s.until) {
		return ErrDenied
	}
	return nil
}

func (s *SystemSTSCredentials) Resolve(ctx context.Context, scope S3Scope) (S3Credential, error) {
	if s == nil || s.closed.Load() || ctx == nil || ctx.Err() != nil || !s.accepts(scope) {
		return S3Credential{}, ErrDenied
	}
	ctx, cancel := context.WithDeadline(ctx, s.until)
	defer cancel()
	return s.transport.exchange(ctx, scope, s.authorize)
}
func (s *SystemSTSCredentials) Close() {
	if s != nil && !s.closed.Swap(true) && s.transport != nil {
		s.transport.Close()
	}
}

var _ S3Credentials = (*SystemSTSCredentials)(nil)
