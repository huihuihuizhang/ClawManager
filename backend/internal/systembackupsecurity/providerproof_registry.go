package systembackupsecurity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// These are D integration profiles, pending cross-owner contract review. Raw
// UTF-8 file bytes (not re-marshaled JSON) are hashed by the locked config.
type ProviderIssuerRegistry struct {
	SchemaVersion string                      `json:"schema_version"`
	Version       string                      `json:"version"`
	Scope         ProviderProofScope          `json:"scope"`
	Keys          []ProviderIssuerRegistryKey `json:"keys"`
}

type ProviderIssuerRegistryKey struct {
	Issuer      string    `json:"issuer"`
	KeyID       string    `json:"key_id"`
	KeyVersion  string    `json:"key_version"`
	Purpose     string    `json:"purpose"`
	PublicKey   []byte    `json:"public_key_base64"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Revoked     bool      `json:"revoked"`
	TargetTypes []string  `json:"target_types"`
	ProofTypes  []string  `json:"proof_types"`
}

func (r ProviderIssuerRegistry) resolvedKeys() []ProviderProofKey {
	keys := make([]ProviderProofKey, 0, len(r.Keys))
	for _, k := range r.Keys {
		keys = append(keys, ProviderProofKey{Issuer: k.Issuer, KeyID: k.KeyID, KeyVersion: k.KeyVersion, Purpose: k.Purpose, PublicKey: k.PublicKey, NotBefore: k.NotBefore, NotAfter: k.NotAfter, Revoked: k.Revoked, TargetTypes: k.TargetTypes, ProofTypes: k.ProofTypes})
	}
	return keys
}

type StrongAuthRegistryKey struct {
	Issuer     string       `json:"issuer"`
	KeyID      string       `json:"key_id"`
	KeyVersion string       `json:"key_version"`
	Purpose    string       `json:"purpose"`
	PublicKey  []byte       `json:"public_key_base64"`
	NotBefore  time.Time    `json:"not_before"`
	NotAfter   time.Time    `json:"not_after"`
	Revoked    bool         `json:"revoked"`
	Policy     IssuerPolicy `json:"policy"`
}
type StrongAuthIssuerRegistry struct {
	SchemaVersion string                  `json:"schema_version"`
	Version       string                  `json:"version"`
	Audience      string                  `json:"audience"`
	Keys          []StrongAuthRegistryKey `json:"keys"`
}
type RegistrationRBACRegistry struct {
	SchemaVersion  string `json:"schema_version"`
	Version        string `json:"version"`
	InstallationID string `json:"installation_id"`
	Bindings       []struct {
		ActorID string `json:"actor_id"`
		Subject string `json:"subject"`
		Role    string `json:"role"`
	} `json:"bindings"`
}

// PinnedRegistrationAuthority resolves immutable registries. The remaining
// functions are explicit application integrations: live session/visibility,
// trusted target metadata, secret-backed nonce material and shared metadata
// accounting. None has an allow-all fallback. They receive the SAME sql.Tx.
type PinnedRegistrationAuthority struct {
	InstallationID            string
	RegistryBytes             func(kind, version, sha256 string) ([]byte, error)
	CheckSessionAndVisibility func(context.Context, *sql.Tx, RegistrationActor, ProviderProofTarget) error
	TargetBinding             func(context.Context, *sql.Tx, ProviderProofTarget) (ProviderProofBinding, error)
	// Must resolve exact identity/version refs from locked config history,
	// including c.NonceIdentityHash; a version string is not a secret identity.
	NonceKeys       func(context.Context, *sql.Tx, RegistrationConfig, []string) (map[string][]byte, error)
	ReserveMetadata func(context.Context, *sql.Tx, int64, int) error
}

func (a PinnedRegistrationAuthority) registry(kind, version, digest string, out any) error {
	if a.RegistryBytes == nil || version == "" || !providerHashPattern.MatchString(digest) {
		return ErrRegistrationUnavailable
	}
	raw, err := a.RegistryBytes(kind, version, digest)
	if err != nil {
		return ErrRegistrationUnavailable
	}
	return decodePinnedRegistry(raw, digest, out)
}

func decodePinnedRegistry(raw []byte, digest string, out any) error {
	if len(raw) == 0 || len(raw) > 262144 || registrationHash(string(raw)) != digest || !json.Valid(raw) || !providerJSONUnicode(raw) {
		return ErrRegistrationUnavailable
	}
	unique := json.NewDecoder(bytes.NewReader(raw))
	if !providerUniqueJSON(unique) {
		return ErrRegistrationUnavailable
	}
	// encoding/json alone accepts missing/null fields and case-insensitive
	// aliases (including two differently cased names for one field). A pinned
	// hash authenticates bytes; it does not make a malformed registry valid.
	if !registryShape(raw, reflect.TypeOf(out)) {
		return ErrRegistrationUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrRegistrationUnavailable
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrRegistrationUnavailable
	}
	return nil
}

// Every registry field is required, exactly cased and non-null. Empty arrays
// are distinct from null; their semantic limits are checked by the consumer.
func registryShape(raw []byte, typ reflect.Type) bool {
	if typ == nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return false
	}
	if typ.Kind() == reflect.Pointer {
		return registryShape(raw, typ.Elem())
	}
	if typ == reflect.TypeOf(time.Time{}) {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return false
		}
		_, err := time.Parse(time.RFC3339Nano, s)
		return err == nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || len(fields) != typ.NumField() {
			return false
		}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "" {
				name = f.Name
			}
			v, ok := fields[name]
			if !ok || !registryShape(v, f.Type) {
				return false
			}
		}
	case reflect.Slice:
		if typ.Elem().Kind() == reflect.Uint8 {
			var s string
			if json.Unmarshal(raw, &s) != nil {
				return false
			}
			b, err := base64.StdEncoding.Strict().DecodeString(s)
			return err == nil && base64.StdEncoding.EncodeToString(b) == s
		}
		var elements []json.RawMessage
		if json.Unmarshal(raw, &elements) != nil {
			return false
		}
		for _, v := range elements {
			if !registryShape(v, typ.Elem()) {
				return false
			}
		}
	default:
		v := reflect.New(typ).Interface()
		return json.Unmarshal(raw, v) == nil
	}
	return true
}

// DecodeProviderIssuerRegistry never trusts a hash supplied by an Admin body.
// expectedVersion/hash must be from the locked persistent config row.
func DecodeProviderIssuerRegistry(raw []byte, expectedVersion, expectedHash string, now time.Time) (ProviderIssuerRegistry, error) {
	var r ProviderIssuerRegistry
	if err := decodePinnedRegistry(raw, expectedHash, &r); err != nil {
		return r, err
	}
	if r.SchemaVersion != "system-backup-provider-issuers.draft.v1" || r.Version != expectedVersion || len(r.Keys) == 0 || len(r.Keys) > 128 || now.IsZero() {
		return ProviderIssuerRegistry{}, ErrRegistrationUnavailable
	}
	if _, err := NewProviderEd25519Verifier(r.Scope, now, r.resolvedKeys()); err != nil {
		return ProviderIssuerRegistry{}, ErrRegistrationUnavailable
	}
	return r, nil
}

func (a PinnedRegistrationAuthority) Authorize(ctx context.Context, tx *sql.Tx, actor RegistrationActor, target ProviderProofTarget, c RegistrationConfig) error {
	if a.CheckSessionAndVisibility == nil || a.TargetBinding == nil || a.NonceKeys == nil || a.ReserveMetadata == nil {
		return ErrRegistrationUnavailable
	}
	if err := a.CheckSessionAndVisibility(ctx, tx, actor, target); err != nil {
		return registrationBoundaryError(err)
	}
	return a.AuthorizeRole(actor, c)
}

func (a PinnedRegistrationAuthority) AuthorizeRole(actor RegistrationActor, c RegistrationConfig) error {
	var registry RegistrationRBACRegistry
	if err := a.registry("rbac_bindings", c.RBACRegistryVersion, c.RBACRegistrySHA256, &registry); err != nil {
		return err
	}
	if registry.SchemaVersion != "system-backup-registration-rbac.draft.v1" || registry.Version != c.RBACRegistryVersion || registry.InstallationID != a.InstallationID || len(registry.Bindings) > 10000 {
		return ErrRegistrationUnavailable
	}
	seen := map[string]bool{}
	allowed := false
	for _, binding := range registry.Bindings {
		id, err := strconv.ParseInt(binding.ActorID, 10, 64)
		if err != nil || id <= 0 || strconv.FormatInt(id, 10) != binding.ActorID || binding.Subject == "" || seen[binding.ActorID] || !contains([]string{"viewer", "operator", "config_admin", "security_admin"}, binding.Role) {
			return ErrRegistrationUnavailable
		}
		seen[binding.ActorID] = true
		if id == actor.UserID && binding.Subject == actor.Subject && binding.Role == "security_admin" {
			allowed = true
		}
	}
	if !allowed {
		return ErrRegistrationPermission
	}
	return nil
}

func (a PinnedRegistrationAuthority) Load(ctx context.Context, tx *sql.Tx, actor RegistrationActor, target ProviderProofTarget, c RegistrationConfig, versions []string, now time.Time) (ProviderProofRegistrationContext, VerifyConfig, error) {
	pc, sc := ProviderProofRegistrationContext{}, VerifyConfig{}
	fail := func() (ProviderProofRegistrationContext, VerifyConfig, error) {
		return ProviderProofRegistrationContext{}, VerifyConfig{}, ErrRegistrationUnavailable
	}
	if a.RegistryBytes == nil || a.TargetBinding == nil || a.NonceKeys == nil {
		return fail()
	}
	raw, err := a.RegistryBytes("provider_proof_issuers", c.ProviderRegistryVersion, c.ProviderRegistrySHA256)
	if err != nil {
		return fail()
	}
	pr, err := DecodeProviderIssuerRegistry(raw, c.ProviderRegistryVersion, c.ProviderRegistrySHA256, now)
	if err != nil || pr.Scope.InstallationID != a.InstallationID {
		return fail()
	}
	strongRaw, err := a.RegistryBytes("strong_auth_issuers", c.StrongAuthRegistryVersion, c.StrongAuthRegistrySHA256)
	if err != nil {
		return fail()
	}
	sr, err := DecodeStrongAuthIssuerRegistry(strongRaw, c.StrongAuthRegistryVersion, c.StrongAuthRegistrySHA256, now)
	if err != nil {
		return fail()
	}
	sc.ExpectedAudience = sr.Audience
	sc.ExpectedSubject = actor.Subject
	sc.ExpectedSession = actor.Session
	sc.TrustedSigners = map[string]map[string]SignatureVerifier{}
	sc.TrustedIssuerPolicies = map[string]IssuerPolicy{}
	seen := map[string]bool{}
	for _, k := range sr.Keys {
		if k.Issuer == "" || k.KeyID == "" || k.KeyVersion == "" || k.Purpose != "strong_auth_issuer" || len(k.PublicKey) != ed25519.PublicKeySize || k.NotBefore.IsZero() || !k.NotAfter.After(k.NotBefore) || len(k.Policy.Methods) == 0 {
			return fail()
		}
		// Provider attestation and user strong authentication cannot share a key.
		for _, pk := range pr.Keys {
			if bytes.Equal(pk.PublicKey, k.PublicKey) {
				return fail()
			}
		}
		identity := k.Issuer + "\x00" + k.KeyVersion
		if seen[identity] {
			return fail()
		}
		seen[identity] = true
		if k.Revoked || now.Before(k.NotBefore) || !now.Before(k.NotAfter) {
			continue
		}
		if old, ok := sc.TrustedIssuerPolicies[k.Issuer]; ok {
			x, _ := json.Marshal(old)
			y, _ := json.Marshal(k.Policy)
			if !bytes.Equal(x, y) {
				return fail()
			}
		}
		if sc.TrustedSigners[k.Issuer] == nil {
			sc.TrustedSigners[k.Issuer] = map[string]SignatureVerifier{}
		}
		sc.TrustedIssuerPolicies[k.Issuer] = k.Policy
		sc.TrustedSigners[k.Issuer][k.KeyVersion] = timedStrongAuthVerifier{Ed25519JWSVerifier{PublicKey: append(ed25519.PublicKey(nil), k.PublicKey...), KeyID: k.KeyID, KeyVersion: k.KeyVersion, Purpose: k.Purpose}, k.NotBefore, k.NotAfter}
	}
	sc.NonceHMACKeys, err = a.NonceKeys(ctx, tx, c, append([]string(nil), versions...))
	if err != nil {
		return fail()
	}
	for _, key := range sc.NonceHMACKeys {
		if len(key) < 32 {
			return fail()
		}
	}
	sc.ActiveNonceHMACKeyVersion = c.NonceKeyVersion
	pc.Scope, pc.Keys, pc.RegistryVersion, pc.RegistrySHA256 = pr.Scope, pr.resolvedKeys(), pr.Version, c.ProviderRegistrySHA256
	pc.Binding, err = a.TargetBinding(ctx, tx, target)
	if err != nil {
		return fail()
	}
	return pc, sc, nil
}

func (a PinnedRegistrationAuthority) ReserveCapacity(ctx context.Context, tx *sql.Tx, c RegistrationConfig, inlineBytes int) error {
	if a.ReserveMetadata == nil {
		return ErrRegistrationUnavailable
	}
	return a.ReserveMetadata(ctx, tx, c.CapacityBytes, inlineBytes)
}

type timedStrongAuthVerifier struct {
	key                 Ed25519JWSVerifier
	notBefore, notAfter time.Time
}

func (v timedStrongAuthVerifier) Verify(payload []byte, signature ProofSignature) error {
	var p ProofPayload
	if json.Unmarshal(payload, &p) != nil {
		return ErrRegistrationUnavailable
	}
	start, end, err := parseTimes(p)
	if err != nil || start.Before(v.notBefore) || end.After(v.notAfter) {
		return ErrRegistrationUnavailable
	}
	return v.key.Verify(payload, signature)
}
