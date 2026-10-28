package systembackupsecurity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// TransitSigner uses a dedicated least-privilege token. It never accepts a
// key path, version, purpose, endpoint or token from an HTTP caller. TLS and
// public-key verification protect against a misconfigured signing endpoint.
type TransitSigner struct {
	client                            *http.Client
	endpoint, keyName, version, token string
	public                            ed25519.PublicKey
}

func NewTransitSigner(endpoint, keyName, version, token string, caPEM []byte, public ed25519.PublicKey) (*TransitSigner, error) {
	u, err := url.Parse(endpoint)
	n, e := strconv.ParseUint(version, 10, 32)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || e != nil || n == 0 || strconv.FormatUint(n, 10) != version || len(public) != 32 || len(token) < 16 || strings.ContainsAny(token, "\r\n") || !safeTransitName(keyName) {
		return nil, ErrRegistrationUnavailable
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, ErrRegistrationUnavailable
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, ResponseHeaderTimeout: 10 * time.Second, MaxIdleConnsPerHost: 4}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &TransitSigner{client: client, endpoint: endpoint, keyName: keyName, version: version, token: token, public: append(ed25519.PublicKey(nil), public...)}, nil
}
func safeTransitName(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func (s *TransitSigner) Sign(ctx context.Context, input []byte) ([]byte, error) {
	if s == nil || s.client == nil || len(input) == 0 || len(input) > 16384 {
		return nil, ErrRegistrationUnavailable
	}
	// The pinned provider ACL compares parameter types before Transit decoding.
	// Keep the explicit version in the lab's verified string wire format.
	body, _ := json.Marshal(map[string]string{"input": base64.StdEncoding.EncodeToString(input), "key_version": s.version})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint+"/v1/transit/sign/"+s.keyName, bytes.NewReader(body))
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	req.Header.Set("X-Vault-Token", s.token)
	req.Header.Set("Content-Type", "application/json")
	res, err := s.client.Do(req)
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 65537))
	if err != nil || len(raw) > 65536 || res.StatusCode != 200 {
		return nil, ErrRegistrationUnavailable
	}
	var wire struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &wire) != nil {
		return nil, ErrRegistrationUnavailable
	}
	prefix := "vault:v" + s.version + ":"
	if !strings.HasPrefix(wire.Data.Signature, prefix) {
		return nil, ErrRegistrationUnavailable
	}
	encoded := strings.TrimPrefix(wire.Data.Signature, prefix)
	sig, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(sig) != encoded || !ed25519.Verify(s.public, input, sig) {
		return nil, ErrRegistrationUnavailable
	}
	return sig, nil
}

// Raw signing is an internal interface, never an exposed HTTP endpoint.
type ProofSigner interface {
	Sign(context.Context, []byte) ([]byte, error)
}

type ProviderObservation struct {
	Binding    ProviderProofBinding
	ObservedAt time.Time
}
type ProviderObserver interface {
	Observe(context.Context, ProviderProofTarget, int64) (ProviderObservation, error)
}

type ProviderAttestationService struct {
	Scope    ProviderProofScope
	Key      ProviderProofKey
	Observer ProviderObserver
	Signer   ProofSigner
	Lifetime time.Duration
}

// Attest only accepts a typed target and row version. All signed facts come
// from the configured observer, never a client-supplied payload or digest.
func (s ProviderAttestationService) Attest(ctx context.Context, target ProviderProofTarget, version int64) (ProviderProof, error) {
	empty := ProviderProof{}
	if s.Observer == nil || s.Signer == nil || version < 1 || s.Lifetime < time.Minute || s.Lifetime > time.Hour {
		return empty, ErrRegistrationUnavailable
	}
	o, err := s.Observer.Observe(ctx, target, version)
	if err != nil {
		return empty, registrationBoundaryError(err)
	}
	now := time.Now().UTC()
	b := o.Binding
	if b.Target != target || b.RowVersion != version || o.ObservedAt.Before(now.Add(-30*time.Second)) || o.ObservedAt.After(now.Add(5*time.Second)) || b.Issuer != s.Key.Issuer || s.Key.Revoked || now.Before(s.Key.NotBefore) || !now.Add(s.Lifetime).Before(s.Key.NotAfter) {
		return empty, ErrRegistrationUnavailable
	}
	p := ProviderProof{ProofType: b.ProofType, Issuer: b.Issuer, ProviderIdentityHash: b.ProviderIdentityHash, LocationHash: b.LocationHash, ActionKeyHash: b.ActionKeyHash, ResourceUID: b.ResourceUID, ResourceVersion: b.ResourceVersion, ObservedVersion: b.ObservedVersion, ObservedChecksum: b.ObservedChecksum, ContentLength: b.ContentLength, ObservedState: b.ObservedState, IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(s.Lifetime).Format(time.RFC3339Nano)}
	input, err := ProviderProofSigningInput(s.Scope, target, p, s.Key.KeyID, s.Key.KeyVersion)
	if err != nil {
		return empty, err
	}
	sig, err := s.Signer.Sign(ctx, input)
	if err != nil {
		return empty, ErrRegistrationUnavailable
	}
	p.SignedProofBase64, err = EncodeProviderProof(s.Scope, target, p, s.Key.KeyID, s.Key.KeyVersion, sig)
	if err != nil {
		return empty, err
	}
	verifier, err := NewProviderEd25519Verifier(s.Scope, now, []ProviderProofKey{s.Key})
	if err != nil {
		return empty, err
	}
	doc, _ := base64.StdEncoding.DecodeString(p.SignedProofBase64)
	if verifier.Verify(target, p, doc) != nil {
		return empty, ErrRegistrationUnavailable
	}
	return p, nil
}
