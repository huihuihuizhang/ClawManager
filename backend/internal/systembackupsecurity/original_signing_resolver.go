package systembackupsecurity

import (
	"context"
	"crypto/ed25519"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

var signingDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// OriginalSigningUse is issued only after the original capture, acceptance or
// catalog owner authenticates the workload and the exact frozen input digest.
// Recheck must revisit that same owner and current revocation state.
type OriginalSigningUse struct {
	Request              TransitSigningRequest
	Workload             SigningWorkloadIdentity
	NotBefore, ExpiresAt time.Time
	Recheck              func(context.Context, TransitSigningRequest) error
}

// Workload comes from the original authenticated Pod/SA and artifact owner.
type SigningWorkloadIdentity struct{ Namespace, PodUID, ServiceAccountUID string }

type OriginalSigningAuthority interface {
	AuthorizeSigning(context.Context, TransitSigningRequest) (OriginalSigningUse, error)
}

// SigningToken is an owned, short-lived provider credential for one exact use.
// The provider role/policy implementation must keep the three purposes apart.
type SigningToken struct {
	Request              TransitSigningRequest
	Secret               []byte
	NotBefore, ExpiresAt time.Time
	Recheck              func(context.Context, TransitSigningRequest) error
}

type SigningTokenSource interface {
	ResolveSigningToken(context.Context, OriginalSigningUse) (SigningToken, error)
}

// OriginalSigningResolver composes original business authorization with the
// separate provider credential source. It is used by CredentialTransitSigner;
// no artifact bytes or signing format are changed here.
type OriginalSigningResolver struct {
	installation string
	bindings     map[string]TransitSigningBinding
	keyWindows   map[string]struct{ start, end time.Time }
	authority    OriginalSigningAuthority
	tokens       SigningTokenSource
	now          func() time.Time
}

func NewOriginalSigningResolver(history *ArtifactSigningKeyHistory, bindings []TransitSigningBinding, authority OriginalSigningAuthority, tokens SigningTokenSource) (*OriginalSigningResolver, error) {
	if history == nil || candidateAuthorityNil(authority) || candidateAuthorityNil(tokens) || len(bindings) != 3 {
		return nil, ErrRegistrationUnavailable
	}
	r := &OriginalSigningResolver{installation: history.installationID, bindings: make(map[string]TransitSigningBinding, 3), keyWindows: make(map[string]struct{ start, end time.Time }, 3), authority: authority, tokens: tokens, now: time.Now}
	providerKeys := map[string]bool{}
	for _, binding := range bindings {
		if binding.InstallationID != r.installation || !artifactSigningPurpose(binding.Purpose) || r.bindings[binding.Purpose].Purpose != "" ||
			!providerBoundedString(binding.KeyID) || !providerBoundedString(binding.KeyVersion) ||
			!safeTransitName(binding.KeyName) || !canonicalProviderVersion(binding.ProviderVersion) ||
			!exactSigningEndpoint(binding.Endpoint) || providerKeys[binding.Endpoint+"\x00"+binding.KeyName] {
			return nil, ErrRegistrationUnavailable
		}
		key, ok := history.keys[artifactSigningIdentity(binding.Purpose, binding.KeyID, binding.KeyVersion)]
		if !ok || key.Revoked || len(key.PublicKey) != ed25519.PublicKeySize {
			return nil, ErrRegistrationUnavailable
		}
		r.bindings[binding.Purpose] = binding
		r.keyWindows[binding.Purpose] = struct{ start, end time.Time }{key.NotBefore, key.NotAfter}
		providerKeys[binding.Endpoint+"\x00"+binding.KeyName] = true
	}
	if len(r.bindings) != 3 {
		return nil, ErrRegistrationUnavailable
	}
	return r, nil
}

func canonicalProviderVersion(v string) bool {
	n, err := strconv.ParseUint(v, 10, 32)
	return err == nil && n > 0 && strconv.FormatUint(n, 10) == v
}

func exactSigningEndpoint(endpoint string) bool {
	u, err := url.Parse(endpoint)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Opaque == "" &&
		u.Path == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == ""
}

func (r *OriginalSigningResolver) ResolveSigning(ctx context.Context, request TransitSigningRequest) (TransitSigningCredential, error) {
	fail := func() (TransitSigningCredential, error) {
		return TransitSigningCredential{}, ErrRegistrationUnavailable
	}
	if r == nil || ctx == nil || ctx.Err() != nil || r.now == nil || !signingDigest.MatchString(request.InputSHA256) ||
		request.Binding.InstallationID != r.installation || r.bindings[request.Binding.Purpose] != request.Binding {
		return fail()
	}
	now := r.now()
	key := r.bindings[request.Binding.Purpose]
	window := r.keyWindows[request.Binding.Purpose]
	// The key history is immutable for this resolver; current revocation is
	// checked by the original authority on every use and recheck.
	if key.Purpose == "" || now.Before(window.start) || !now.Before(window.end) {
		return fail()
	}
	use, err := r.authority.AuthorizeSigning(ctx, request)
	if err != nil || use.Request != request || use.Recheck == nil ||
		!providerBoundedString(use.Workload.Namespace) || !providerBoundedString(use.Workload.PodUID) ||
		!providerBoundedString(use.Workload.ServiceAccountUID) || use.NotBefore.IsZero() ||
		use.ExpiresAt.IsZero() || now.Before(use.NotBefore) || !now.Before(use.ExpiresAt) {
		return fail()
	}
	if use.Recheck(ctx, request) != nil {
		return fail()
	}
	token, err := r.tokens.ResolveSigningToken(ctx, use)
	if err != nil || token.Request != request || token.Recheck == nil || token.NotBefore.IsZero() ||
		now.Before(token.NotBefore) || !now.Before(token.ExpiresAt) || token.ExpiresAt.After(now.Add(20*time.Second)) ||
		len(token.Secret) < 16 || len(token.Secret) > 4096 {
		clearSigningToken(token.Secret)
		return fail()
	}
	until := use.ExpiresAt
	if window.end.Before(until) {
		until = window.end
	}
	if token.ExpiresAt.Before(until) {
		until = token.ExpiresAt
	}
	if use.Recheck(ctx, request) != nil || token.Recheck(ctx, request) != nil || !r.now().Before(until) {
		clearSigningToken(token.Secret)
		return fail()
	}
	credential := TransitSigningCredential{Request: request, Secret: token.Secret, NotBefore: token.NotBefore, ExpiresAt: until}
	credential.Recheck = func(c context.Context, got TransitSigningRequest) error {
		at := r.now()
		if c == nil || c.Err() != nil || got != request || at.Before(window.start) || !at.Before(until) || use.Recheck(c, request) != nil || token.Recheck(c, request) != nil {
			return ErrRegistrationUnavailable
		}
		return nil
	}
	return credential, nil
}

func clearSigningToken(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
