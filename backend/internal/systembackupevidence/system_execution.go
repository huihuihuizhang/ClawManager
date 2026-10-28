package systembackupevidence

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	"clawreef/internal/systembackupproducer"
)

// SystemExecutionPreparationPolicy is independent deployment/evaluator input,
// never an HTTP body or authority inferred from the document being prepared.
// D's production environment must independently admit its full PolicyHash,
// including the workload JWT projection and exact body digest. Hash equality
// alone does not establish this trust or independence from the tested provider.
type SystemExecutionPreparationPolicy struct {
	Scope                                                                    systembackupproducer.Scope
	RunID                                                                    systembackupproducer.ID
	InputHash, EvaluatorProfileHash, SubjectIdentityHash, IssuerIdentityHash string
	Identity                                                                 Identity
	Content                                                                  CapabilityContentPolicy
	Wrap                                                                     TransitJWTConfig
	AuthenticationAudience, AuthenticationTokenFile                          string
}

// SystemExecutionPreparationPolicyHash is a local closed-structure digest for
// D's ReferenceApproval.PolicyHash. It is not the C1 channel profile hash and
// cannot mint a handle. It includes the exact Wrap profile without PEM bytes.
func SystemExecutionPreparationPolicyHash(c SystemExecutionPreparationPolicy) string {
	c.Wrap.Transit.CAPEM = nil
	raw, err := json.Marshal(struct {
		Domain string
		Policy SystemExecutionPreparationPolicy
	}{"system-backup-system-preparation-policy.v1", c})
	if err != nil {
		return ""
	}
	return hash(raw)
}

// NewSystemExecutionPreparer begins two committed D calls on the original
// handle before any body/token/provider I/O. The returned preparer retains both
// opaque snapshots and never replaces them with a renewed lease. Construct a
// new preparer for a new call; Close it after use. No SQL transaction is retained
// while reading the body, exchanging a JWT or contacting Transit.
func NewSystemExecutionPreparer(ctx context.Context, execution *systembackupproducer.Execution, handle *systembackupproducer.ExecutionHandle, c SystemExecutionPreparationPolicy) (*SystemTransitPreparer, error) {
	if execution == nil || handle == nil {
		return nil, ErrDenied
	}
	a, err := newSystemExecutionAuthority(ctx, systemDCalls{execution, handle}, c)
	if err != nil {
		return nil, err
	}
	return NewSystemTransitPreparer(a, c.Wrap)
}

// This seam is package-private; the public constructor accepts only concrete D
// services and handles, not caller-supplied views or permissive callback gates.
type systemCallSnapshot interface {
	View() systembackupproducer.SnapshotView
	Deadline() time.Time
	BindingHash() systembackupproducer.Hash
	Purpose() string
}
type systemExecutionCalls interface {
	begin(context.Context, systembackupproducer.CallRequest) (systemCallSnapshot, error)
	recheck(context.Context, systemCallSnapshot) error
}
type systemDCalls struct {
	execution *systembackupproducer.Execution
	handle    *systembackupproducer.ExecutionHandle
}

func (d systemDCalls) begin(ctx context.Context, r systembackupproducer.CallRequest) (systemCallSnapshot, error) {
	return d.execution.BeginCall(ctx, d.handle, r, nil)
}
func (d systemDCalls) recheck(ctx context.Context, s systemCallSnapshot) error {
	p, ok := s.(*systembackupproducer.CallSnapshot)
	if !ok || p == nil {
		return ErrDenied
	}
	return d.execution.RecheckCall(ctx, p)
}

type systemExecutionAuthority struct {
	calls     systemExecutionCalls
	snapshots [2]systemCallSnapshot
	views     [2]systembackupproducer.SnapshotView
	grant     SystemPreparationAuthorization
}

var systemProducerRunID = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

func newSystemExecutionAuthority(ctx context.Context, calls systemExecutionCalls, c SystemExecutionPreparationPolicy) (*systemExecutionAuthority, error) {
	if ctx == nil || ctx.Err() != nil || nilSystemAdapter(calls) || !c.Identity.validExternal() || c.Identity.OwnerType != "system" || c.Identity.Type != "capability_snapshot" || c.Identity.Media != "application/json" || c.Identity.ContentSize > MaxCapabilityContent ||
		string(c.Scope.Installation) != c.Identity.Installation || c.Identity.OwnerID != c.Identity.Installation || !taskJobUID.MatchString(string(c.Scope.ServerUUID)) || !systemProducerRunID.MatchString(string(c.RunID)) || string(c.Scope.Database) == "" ||
		!digestPattern.MatchString(c.InputHash) || !digestPattern.MatchString(c.EvaluatorProfileHash) || !digestPattern.MatchString(c.SubjectIdentityHash) || !digestPattern.MatchString(c.IssuerIdentityHash) ||
		c.Content.Installation != c.Identity.Installation || c.Content.EvidenceID != c.Identity.ID || c.Content.Classification != c.Identity.Classification ||
		c.Wrap.Transit.Installation != c.Identity.Installation || !c.Wrap.Transit.Key.valid() || hash(c.Wrap.Transit.CAPEM) != c.Wrap.Transit.CASHA256 ||
		!s3Token([]byte(c.AuthenticationAudience), 1, 255) || c.AuthenticationAudience == c.Wrap.Audience || !filepath.IsAbs(c.AuthenticationTokenFile) || strings.EqualFold(filepath.Clean(c.AuthenticationTokenFile), filepath.Clean(c.Wrap.TokenFile)) {
		return nil, ErrDenied
	}
	validator, err := NewCapabilityRedactor(c.Content)
	if err != nil {
		return nil, ErrDenied
	}
	c.Content = validator.policy // own the nullable observed-version value
	budget := earlier(time.Now().Add(20*time.Second), c.Content.ValidUntil).UTC().Truncate(time.Microsecond)
	if d, ok := ctx.Deadline(); ok {
		budget = earlier(budget, d.UTC().Truncate(time.Microsecond))
	}
	ctx, cancel := context.WithDeadline(ctx, budget)
	defer cancel()
	policy := SystemExecutionPreparationPolicyHash(c)
	a := &systemExecutionAuthority{calls: calls}
	for n, purpose := range []string{"content_read", "wrap"} {
		ref, version := c.Content.ProviderIdentity, c.Content.ProviderVersion
		if n == 1 {
			ref, version = c.Wrap.Transit.Key.Identity, c.Wrap.Transit.Key.Version
		}
		r := systembackupproducer.CallRequest{Purpose: purpose, EvidenceID: systembackupproducer.EvidenceID(c.Identity.ID), RefIdentityHash: systembackupproducer.Hash(ref), RefVersion: systembackupproducer.ProviderVersion(version), PolicyHash: systembackupproducer.Hash(policy), BudgetUntil: systembackupproducer.Timestamp(budget.Format("2006-01-02T15:04:05.000000Z"))}
		s, err := calls.begin(ctx, r)
		if err != nil || nilSystemAdapter(s) {
			return nil, ErrDenied
		}
		v := s.View()
		if !systemPreparationSnapshotMatches(c, r, s, v) {
			return nil, ErrDenied
		}
		a.snapshots[n], a.views[n] = s, v
	}
	// References and their request hashes legitimately differ by purpose. All
	// shared authority, host, run/observation and locked evidence facts must match.
	left, right := a.views[0], a.views[1]
	left.Binding.Call, right.Binding.Call = systembackupproducer.CallRequest{}, systembackupproducer.CallRequest{}
	left.Facts.Admission.RequestHash, right.Facts.Admission.RequestHash = "", ""
	left.Facts.References, right.Facts.References = systembackupproducer.ReferenceApproval{}, systembackupproducer.ReferenceApproval{}
	if !reflect.DeepEqual(left.Binding, right.Binding) || !reflect.DeepEqual(left.Facts, right.Facts) {
		return nil, ErrDenied
	}
	until := earlier(budget, earlier(a.snapshots[0].Deadline(), a.snapshots[1].Deadline()))
	producer := hash([]byte("system-backup-system-preparation-calls.v1\x00" + string(a.snapshots[0].BindingHash()) + "\x00" + string(a.snapshots[1].BindingHash())))
	a.grant = SystemPreparationAuthorization{Content: ContentAuthorization{Identity: c.Identity, ProducerIdentityHash: producer, ValidUntil: until, Capability: &c.Content}, Key: c.Wrap.Transit.Key, ProfileHash: SystemWrapProfileHash(c.Wrap), AuthenticationAudience: c.AuthenticationAudience, AuthenticationTokenFile: c.AuthenticationTokenFile}
	// A change between the two admissions must fail before token/body I/O.
	if _, err := a.AuthorizeSystemPreparation(ctx, c.Identity, a.grant.ProfileHash); err != nil {
		return nil, ErrDenied
	}
	return a, nil
}

func systemPreparationSnapshotMatches(c SystemExecutionPreparationPolicy, r systembackupproducer.CallRequest, s systemCallSnapshot, v systembackupproducer.SnapshotView) bool {
	b, f := v.Binding, v.Facts
	expiry, err := v.ValidUntil.Time()
	if err != nil || !expiry.Equal(s.Deadline()) || !time.Now().Before(expiry) || v.BindingHash != s.BindingHash() || !digestPattern.MatchString(string(v.BindingHash)) || s.Purpose() != r.Purpose || b.Kind != "call" || b.Call != r || b.Scope != c.Scope || b.RunID != c.RunID || string(b.Subject) != c.SubjectIdentityHash || b.Claim != nil || b.Observation != nil || b.ProbeSnapshotHash != nil {
		return false
	}
	if f.Domain.Scope != c.Scope || string(f.Domain.IssuerIdentityHash) != c.IssuerIdentityHash || f.Grant.Scope != c.Scope || f.Run.Scope != c.Scope || f.Target.Scope != c.Scope || f.Run.RunID != c.RunID || string(f.Run.InputHash) != c.InputHash || string(f.Run.EvidenceID) != c.Identity.ID || f.Run.State != "acquired" || f.Run.ObservedAt == nil || f.Run.ObservationExpiresAt == nil {
		return false
	}
	observationExpiry, err := f.Run.ObservationExpiresAt.Time()
	if err != nil || !c.Content.ValidUntil.Equal(observationExpiry) {
		return false
	}
	t := f.Grant.Target
	if string(t.EvaluatorProfileHash) != c.EvaluatorProfileHash || string(t.Role) != c.Content.Role || string(t.IdentityHash) != c.Content.ProviderIdentity || string(t.RefVersion) != c.Content.ProviderVersion || string(t.ProbeScopeHash) != c.Content.ScopeHash || f.References.PolicyHash != r.PolicyHash {
		return false
	}
	return f.Evidence != nil && f.Evidence.EvidenceID == r.EvidenceID && f.Evidence.OwnerType == "system" && string(f.Evidence.OwnerID) == c.Identity.Installation && f.Evidence.EvidenceType == "capability_snapshot" && f.Evidence.State == "reserved" && f.Evidence.RowVersion == "0" && f.Evidence.ManifestHash == nil && f.Evidence.ClaimOwner == nil && f.Evidence.ClaimExpiresAt == nil
}

func (a *systemExecutionAuthority) AuthorizeSystemPreparation(ctx context.Context, i Identity, profile string) (SystemPreparationAuthorization, error) {
	if a == nil || ctx == nil || ctx.Err() != nil || i != a.grant.Content.Identity || profile != a.grant.ProfileHash || !time.Now().Before(a.grant.Content.ValidUntil) {
		return SystemPreparationAuthorization{}, ErrDenied
	}
	for n, s := range a.snapshots {
		if nilSystemAdapter(s) || !reflect.DeepEqual(s.View(), a.views[n]) || a.calls.recheck(ctx, s) != nil {
			return SystemPreparationAuthorization{}, ErrDenied
		}
	}
	if ctx.Err() != nil || !time.Now().Before(a.grant.Content.ValidUntil) {
		return SystemPreparationAuthorization{}, ErrDenied
	}
	g := a.grant
	p := *g.Content.Capability
	if p.ObservedVersion != nil {
		v := *p.ObservedVersion
		p.ObservedVersion = &v
	}
	g.Content.Capability = &p
	return g, nil
}
