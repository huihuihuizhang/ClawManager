package systembackupsecurity

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// RFC 6238 SHA-1, six digits, 30-second step, one adjacent step of skew.
// The caller MUST persist the returned step before releasing a proof.
func matchTOTP(secret []byte, code string, now time.Time, lastStep int64) (int64, bool) {
	if len(secret) != 20 || len(code) != 6 || now.Unix() < 30 {
		return 0, false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	matched := int64(-1)
	for _, step := range []int64{now.Unix()/30 - 1, now.Unix() / 30, now.Unix()/30 + 1} {
		if subtle.ConstantTimeCompare([]byte(totpCode(secret, step, 6)), []byte(code)) == 1 && step > lastStep {
			matched = step
		}
	}
	return matched, matched >= 0
}
func totpCode(secret []byte, step int64, digits int) string {
	var count [8]byte
	binary.BigEndian.PutUint64(count[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	mac.Write(count[:])
	sum := mac.Sum(nil)
	offset := int(sum[len(sum)-1] & 15)
	n := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	modulus := uint32(1000000)
	if digits == 8 {
		modulus = 100000000
	}
	return fmt.Sprintf("%0*d", digits, n%modulus)
}

type TOTPSecretBox struct{ aead cipher.AEAD }

func NewTOTPSecretBox(key []byte) (TOTPSecretBox, error) {
	if len(key) != 32 {
		return TOTPSecretBox{}, ErrRegistrationUnavailable
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return TOTPSecretBox{}, ErrRegistrationUnavailable
	}
	aead, err := cipher.NewGCM(block)
	return TOTPSecretBox{aead}, err
}
func (b TOTPSecretBox) seal(secret []byte, identity string) ([]byte, error) {
	if b.aead == nil || len(secret) != 20 || identity == "" {
		return nil, ErrRegistrationUnavailable
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, ErrRegistrationUnavailable
	}
	return b.aead.Seal(nonce, nonce, secret, []byte(identity)), nil
}
func (b TOTPSecretBox) open(sealed []byte, identity string) ([]byte, error) {
	if b.aead == nil || len(sealed) < b.aead.NonceSize()+b.aead.Overhead() {
		return nil, ErrRegistrationUnavailable
	}
	n := b.aead.NonceSize()
	raw, err := b.aead.Open(nil, sealed[:n], sealed[n:], []byte(identity))
	if err != nil || len(raw) != 20 {
		return nil, ErrRegistrationUnavailable
	}
	return raw, nil
}
func enrollmentURI(secret []byte, account string) string {
	values := url.Values{"secret": {base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)}, "issuer": {"ClawManager"}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + url.PathEscape("ClawManager:"+account) + "?" + values.Encode()
}

type StrongAuthProofIssuer struct {
	Key      StrongAuthRegistryKey
	Audience string
	Signer   ProofSigner
	Lifetime time.Duration
}

// issue is only called after a persisted successful TOTP verification. There
// is no public method that accepts an arbitrary auth_time or method assertion.
func (s StrongAuthProofIssuer) issue(ctx context.Context, actor RegistrationActor, binding RequestBinding, now time.Time) (Proof, error) {
	empty := Proof{}
	if s.Signer == nil || s.Key.Purpose != "strong_auth_issuer" || s.Key.Revoked || s.Audience == "" || s.Lifetime < time.Minute || s.Lifetime > 5*time.Minute || now.Before(s.Key.NotBefore) || now.Add(s.Lifetime).After(s.Key.NotAfter) || !totpProofEndpoint(binding.Endpoint) || !providerHashPattern.MatchString(binding.RequestHash) || !validIdempotencyKey(binding.IdempotencyKey) {
		return empty, ErrRegistrationUnavailable
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return empty, ErrRegistrationUnavailable
	}
	p := ProofPayload{Issuer: s.Key.Issuer, Audience: s.Audience, Subject: actor.Subject, Session: actor.Session, AuthTime: now.UTC().Format(time.RFC3339Nano), ExpiresAt: now.Add(s.Lifetime).UTC().Format(time.RFC3339Nano), Method: "totp", Nonce: base64.RawURLEncoding.EncodeToString(nonce), Endpoint: binding.Endpoint, RequestHash: binding.RequestHash, IdempotencyKey: binding.IdempotencyKey, AMR: []string{"otp"}}
	payload, err := CanonicalPayload(p)
	if err != nil {
		return empty, err
	}
	header := []byte(`{"alg":"EdDSA","key_version":` + jcsString(s.Key.KeyVersion) + `,"kid":` + jcsString(s.Key.KeyID) + `,"purpose":"strong_auth_issuer","typ":` + jcsString(DomainSeparator) + `}`)
	protected := base64.RawURLEncoding.EncodeToString(header)
	input := []byte(protected + "." + base64.RawURLEncoding.EncodeToString(payload))
	sig, err := s.Signer.Sign(ctx, input)
	if err != nil {
		return empty, ErrRegistrationUnavailable
	}
	signature := ProofSignature{Format: "jws", Algorithm: "EdDSA", KeyID: s.Key.KeyID, KeyVersion: s.Key.KeyVersion, DomainSeparator: DomainSeparator, ProtectedHeader: protected, Value: base64.RawURLEncoding.EncodeToString(sig)}
	v := Ed25519JWSVerifier{PublicKey: s.Key.PublicKey, KeyID: s.Key.KeyID, KeyVersion: s.Key.KeyVersion, Purpose: s.Key.Purpose}
	if v.Verify(payload, signature) != nil {
		return empty, ErrRegistrationUnavailable
	}
	return Proof{SchemaVersion: ProofSchemaVersion, Payload: p, Signature: signature}, nil
}

func totpProofEndpoint(endpoint string) bool {
	return endpoint == ProviderRegistrationEndpoint || endpoint == ConfigUpdateEndpoint || endpoint == ConfigRollbackEndpoint || endpoint == SensitiveDownloadEndpoint
}

func wipeSecret(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
func constantString(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
func normalizedCode(code string) bool {
	return len(code) == 6 && strings.Trim(code, "0123456789") == ""
}
