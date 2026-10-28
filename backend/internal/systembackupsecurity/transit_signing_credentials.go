package systembackupsecurity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// TransitSigningBinding comes from authenticated deployment composition.
// KeyVersion is the opaque registry version; ProviderVersion is the separate
// exact Transit numeric version. Neither is inferred from the other.
type TransitSigningBinding struct {
	InstallationID, Purpose, KeyID, KeyVersion string
	Endpoint, KeyName, ProviderVersion         string
}

type TransitSigningRequest struct {
	Binding     TransitSigningBinding
	InputSHA256 string
}

// ResolveSigning must authenticate the original workload, purpose, resource,
// input and current permission; a matching request alone proves none of these.
// It returns an exclusively owned token buffer, erased by the caller even on
// failure, and an original grant recheck (no renewal or replacement grant).
type TransitSigningCredentials interface {
	ResolveSigning(context.Context, TransitSigningRequest) (TransitSigningCredential, error)
}

type TransitSigningCredential struct {
	Request              TransitSigningRequest
	Secret               []byte
	NotBefore, ExpiresAt time.Time
	Recheck              func(context.Context, TransitSigningRequest) error
}

func (TransitSigningCredential) String() string               { return "TransitSigningCredential" }
func (TransitSigningCredential) GoString() string             { return "TransitSigningCredential" }
func (TransitSigningCredential) MarshalJSON() ([]byte, error) { return nil, ErrRegistrationUnavailable }

// CredentialTransitSigner implements ProofSigner. It preserves the existing
// provider wire and pinned public-key verification. It does not define artifact
// payload/framing, implement the original authority, or register production links.
type CredentialTransitSigner struct {
	transport           *TransitSigner
	binding             TransitSigningBinding
	notBefore, notAfter time.Time
	credentials         TransitSigningCredentials
	now                 func() time.Time
}

func NewCredentialTransitSigner(binding TransitSigningBinding, key ArtifactSigningPublicKey, caPEM []byte, credentials TransitSigningCredentials) (*CredentialTransitSigner, error) {
	if candidateAuthorityNil(credentials) || !artifactSigningPurpose(binding.Purpose) ||
		!providerBoundedString(binding.InstallationID) || !providerBoundedString(binding.KeyID) ||
		!providerBoundedString(binding.KeyVersion) || len(binding.KeyID) > 256 || len(binding.KeyVersion) > 128 ||
		key.InstallationID != binding.InstallationID || key.Purpose != binding.Purpose ||
		key.KeyID != binding.KeyID || key.KeyVersion != binding.KeyVersion || key.Revoked ||
		key.NotBefore.IsZero() || !key.NotAfter.After(key.NotBefore) {
		return nil, ErrRegistrationUnavailable
	}
	s, err := newTransitSignerTransport(binding.Endpoint, binding.KeyName, binding.ProviderVersion, caPEM, key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &CredentialTransitSigner{transport: s, binding: binding, notBefore: key.NotBefore, notAfter: key.NotAfter, credentials: credentials, now: time.Now}, nil
}

func (s *CredentialTransitSigner) Close() {
	if s != nil && s.transport != nil {
		s.transport.client.CloseIdleConnections()
	}
}

func (s *CredentialTransitSigner) Sign(ctx context.Context, input []byte) ([]byte, error) {
	fail := func() ([]byte, error) { return nil, ErrRegistrationUnavailable }
	if s == nil || s.transport == nil || s.now == nil || candidateAuthorityNil(ctx) || ctx.Err() != nil || len(input) == 0 || len(input) > 16384 {
		return fail()
	}
	// Freeze the bytes before the trusted resolver is invoked.
	input = append([]byte(nil), input...)
	sum := sha256.Sum256(input)
	r := TransitSigningRequest{Binding: s.binding, InputSHA256: hex.EncodeToString(sum[:])}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	first := s.now()
	if first.Before(s.notBefore) || !first.Before(s.notAfter) {
		return fail()
	}
	c, err := s.credentials.ResolveSigning(ctx, r)
	defer func() {
		for i := range c.Secret {
			c.Secret[i] = 0
		}
	}()
	if err != nil || c.Request != r || c.Recheck == nil || len(c.Secret) < 16 || len(c.Secret) > 4096 ||
		strings.ContainsAny(string(c.Secret), "\r\n") || c.NotBefore.IsZero() || !c.ExpiresAt.After(c.NotBefore) {
		return fail()
	}
	until := c.ExpiresAt
	if s.notAfter.Before(until) {
		until = s.notAfter
	}
	floor := first
	check := func() bool {
		now := s.now()
		if ctx.Err() != nil || now.Before(floor) || now.Before(c.NotBefore) || !now.Before(until) {
			return false
		}
		floor = now
		return true
	}
	if !check() || c.Recheck(ctx, r) != nil || !check() {
		return fail()
	}
	callCtx, callCancel := context.WithDeadline(ctx, until)
	defer callCancel()
	// Only this call-local copy retains the immutable HTTP header string.
	call := *s.transport
	call.token = string(c.Secret)
	sig, err := call.Sign(callCtx, input)
	call.token = ""
	if err != nil || !check() || c.Recheck(ctx, r) != nil || !check() {
		return fail()
	}
	return sig, nil
}
