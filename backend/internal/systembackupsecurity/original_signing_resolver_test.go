package systembackupsecurity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

type signingAuthorityFixture func(context.Context, TransitSigningRequest) (OriginalSigningUse, error)

func (f signingAuthorityFixture) AuthorizeSigning(ctx context.Context, r TransitSigningRequest) (OriginalSigningUse, error) {
	return f(ctx, r)
}

type signingTokensFixture func(context.Context, OriginalSigningUse) (SigningToken, error)

func (f signingTokensFixture) ResolveSigningToken(ctx context.Context, u OriginalSigningUse) (SigningToken, error) {
	return f(ctx, u)
}

func signingResolverFixture(t *testing.T, now time.Time, revoked bool, auth signingAuthorityFixture, tokens signingTokensFixture) (*OriginalSigningResolver, TransitSigningRequest, error) {
	t.Helper()
	keys := make([]ArtifactSigningPublicKey, 0, 3)
	bindings := make([]TransitSigningBinding, 0, 3)
	for i, purpose := range []string{"capture_certificate", "acceptance_record", "catalog_record"} {
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		binding := TransitSigningBinding{InstallationID: "installation_test", Purpose: purpose, KeyID: purpose, KeyVersion: "registry-v1", Endpoint: "https://provider.invalid", KeyName: purpose, ProviderVersion: "1"}
		bindings = append(bindings, binding)
		keys = append(keys, ArtifactSigningPublicKey{InstallationID: binding.InstallationID, Purpose: purpose, KeyID: binding.KeyID, KeyVersion: binding.KeyVersion, PublicKey: public, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), Revoked: revoked && i == 0})
	}
	history, err := NewArtifactSigningKeyHistory("installation_test", keys)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewOriginalSigningResolver(history, bindings, auth, tokens)
	return r, TransitSigningRequest{Binding: bindings[0], InputSHA256: strings.Repeat("a", 64)}, err
}

func TestOriginalSigningResolverExactBusinessAndTokenBoundary(t *testing.T) {
	now := time.Now().UTC()
	checks, calls := 0, 0
	revoked := false
	auth := signingAuthorityFixture(func(_ context.Context, r TransitSigningRequest) (OriginalSigningUse, error) {
		calls++
		return OriginalSigningUse{Request: r, NotBefore: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute), Recheck: func(context.Context, TransitSigningRequest) error {
			checks++
			if revoked {
				return errors.New("revoked")
			}
			return nil
		}}, nil
	})
	secret := []byte(strings.Repeat("t", 32))
	tokens := signingTokensFixture(func(_ context.Context, u OriginalSigningUse) (SigningToken, error) {
		return SigningToken{Request: u.Request, Secret: secret, NotBefore: now.Add(-time.Second), ExpiresAt: now.Add(10 * time.Second), Recheck: func(context.Context, TransitSigningRequest) error { return nil }}, nil
	})
	r, request, err := signingResolverFixture(t, now, false, auth, tokens)
	if err != nil {
		t.Fatal(err)
	}
	r.now = func() time.Time { return now }
	if _, err := r.ResolveSigning(context.Background(), TransitSigningRequest{Binding: request.Binding, InputSHA256: "latest"}); err == nil || calls != 0 {
		t.Fatal("invalid digest reached original authority")
	}
	wrong := request
	wrong.Binding.KeyVersion = "other"
	if _, err := r.ResolveSigning(context.Background(), wrong); err == nil || calls != 0 {
		t.Fatal("wrong version reached original authority")
	}
	credential, err := r.ResolveSigning(context.Background(), request)
	if err != nil || credential.Request != request || checks != 2 {
		t.Fatalf("valid signing use rejected: %v", err)
	}
	if credential.Recheck(context.Background(), request) != nil {
		t.Fatal("current original use rejected")
	}
	revoked = true
	if credential.Recheck(context.Background(), request) == nil {
		t.Fatal("revocation not observed")
	}
	for i := range credential.Secret {
		credential.Secret[i] = 0
	}
	if _, _, err := signingResolverFixture(t, now, true, auth, tokens); err == nil {
		t.Fatal("revoked current key accepted")
	}
}

func TestOriginalSigningResolverErasesRejectedToken(t *testing.T) {
	now := time.Now().UTC()
	auth := signingAuthorityFixture(func(_ context.Context, r TransitSigningRequest) (OriginalSigningUse, error) {
		return OriginalSigningUse{Request: r, NotBefore: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute), Recheck: func(context.Context, TransitSigningRequest) error { return nil }}, nil
	})
	secret := []byte(strings.Repeat("s", 32))
	tokens := signingTokensFixture(func(_ context.Context, u OriginalSigningUse) (SigningToken, error) {
		return SigningToken{Request: u.Request, Secret: secret, NotBefore: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute), Recheck: func(context.Context, TransitSigningRequest) error { return nil }}, nil
	})
	r, request, err := signingResolverFixture(t, now, false, auth, tokens)
	if err != nil {
		t.Fatal(err)
	}
	r.now = func() time.Time { return now }
	if _, err = r.ResolveSigning(context.Background(), request); err == nil {
		t.Fatal("long provider token accepted")
	}
	for _, b := range secret {
		if b != 0 {
			t.Fatal("rejected token not erased")
		}
	}
}

func TestOriginalSigningResolverEnforcesCurrentKeyWindow(t *testing.T) {
	base := time.Now().UTC()
	current := base
	calls := 0
	auth := signingAuthorityFixture(func(_ context.Context, r TransitSigningRequest) (OriginalSigningUse, error) {
		calls++
		return OriginalSigningUse{Request: r, NotBefore: current.Add(-time.Second), ExpiresAt: current.Add(time.Minute),
			Recheck: func(context.Context, TransitSigningRequest) error { return nil }}, nil
	})
	tokens := signingTokensFixture(func(_ context.Context, use OriginalSigningUse) (SigningToken, error) {
		return SigningToken{Request: use.Request, Secret: []byte(strings.Repeat("t", 32)),
			NotBefore: current.Add(-time.Second), ExpiresAt: current.Add(10 * time.Second),
			Recheck: func(context.Context, TransitSigningRequest) error { return nil }}, nil
	})
	resolver, request, err := signingResolverFixture(t, base, false, auth, tokens)
	if err != nil {
		t.Fatal(err)
	}
	resolver.now = func() time.Time { return current }
	for _, at := range []time.Time{base.Add(-2 * time.Minute), base.Add(2 * time.Hour)} {
		current = at
		if _, err := resolver.ResolveSigning(context.Background(), request); err == nil || calls != 0 {
			t.Fatal("signing credential issued outside the current key window", at, err)
		}
	}
	current = base.Add(time.Hour - 5*time.Second)
	credential, err := resolver.ResolveSigning(context.Background(), request)
	if err != nil || calls != 1 || !credential.ExpiresAt.Equal(base.Add(time.Hour)) {
		t.Fatal("current key expiration did not cap the credential", err)
	}
	current = base.Add(time.Hour + time.Second)
	if credential.Recheck(context.Background(), request) == nil {
		t.Fatal("expired key remained usable after credential issuance")
	}
}
