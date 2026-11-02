package systembackupkekadapter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
	kms "clawreef/internal/systembackupkms"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// Installer-owned, independently pinned metadata READ identity. Never pass a
// root/unseal credential, runtime worker token, candidate JSON or browser input.
// The observer needs only named policy/role/JWT-config/key metadata reads plus
// lookup-self. It cannot write ACLs, mint runtime tokens, Generate or Unwrap.
type VaultPermissionObserverConfig struct {
	Binding                                reg.Binding
	CAPEM                                  []byte
	TokenFile, TokenSHA256, ObserverPolicy string
	Worker, Publisher                      VaultPermissionRole
	Trust                                  VaultJWTTrust
}
type VaultPermissionRole struct {
	AuthMount, Role, Policy, Audience                string
	Namespace, ServiceAccountName, ServiceAccountUID string
	// Capture workers have dynamic Pod UIDs: a mandatory signed Pod-UID user
	// claim and response mapping is checked against the original Job by the
	// real client. The independent fixed publisher additionally binds its UID.
	PodUID   string
	Workload *ControllerVerifierWorkload
}
type VaultJWTTrust struct {
	Issuer               string
	JWKSURL, JWKSCAPEM   string
	ValidationPublicKeys []string
	Algorithms           []string
}

type VaultPermissionObserver struct {
	cfg    VaultPermissionObserverConfig
	client *http.Client
}
type ObservedVaultPermissions struct {
	owner            *VaultPermissionObserver
	observed         time.Time
	generate, unwrap ProviderCapabilityFacts
}

func vaultCanonical(raw []byte) ([]byte, error) { return jsoncanonicalizer.Transform(raw) }
func vaultProviderVersion(v string) bool {
	n, err := strconv.ParseUint(v, 10, 32)
	return err == nil && n > 0 && strconv.FormatUint(n, 10) == v
}

func vaultPermissionACL(operation kms.Operation, key, version string) (string, error) {
	if !keyNameValid(key) || !vaultProviderVersion(version) {
		return "", kms.ErrPermission
	}
	switch operation {
	case kms.Generate:
		return "path \"transit/datakey/plaintext/" + key + "\" {\n  capabilities = [\"update\"]\n  required_parameters = [\"context\", \"bits\", \"key_version\"]\n  allowed_parameters = {\n    \"context\" = []\n    \"bits\" = [\"256\"]\n    \"key_version\" = [\"" + version + "\"]\n  }\n}\n", nil
	case kms.Unwrap:
		return "path \"transit/decrypt/" + key + "\" {\n  capabilities = [\"update\"]\n  required_parameters = [\"context\", \"ciphertext\"]\n  allowed_parameters = {\n    \"context\" = []\n    \"ciphertext\" = []\n  }\n}\n", nil
	}
	return "", kms.ErrPermission
}

// VaultRuntimeACL returns the exact narrow ACL that the installation owner
// writes, then the independent observer reads back byte-for-byte. No wildcard
// path, default/root policy, key administration or capture decryption is added.
func VaultRuntimeACL(operation kms.Operation, key, version string) (string, error) {
	return vaultPermissionACL(operation, key, version)
}

func NewVaultPermissionObserver(cfg VaultPermissionObserverConfig) (*VaultPermissionObserver, error) {
	endpoint, err := url.Parse(cfg.Binding.Provider.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Opaque != "" || endpoint.ForceQuery || !keyNameValid(cfg.Binding.Provider.KeyName) || !vaultProviderVersion(cfg.Binding.Key.ProviderVersion) || cfg.Binding.Key.Provider != "external-kms" || !vaultPolicyName(cfg.ObserverPolicy) || !authorityHash.MatchString(cfg.TokenSHA256) || len(cfg.CAPEM) == 0 || len(cfg.CAPEM) > 65536 {
		return nil, kms.ErrPermission
	}
	caHash := sha256.Sum256(cfg.CAPEM)
	roots := x509.NewCertPool()
	if hex.EncodeToString(caHash[:]) != cfg.Binding.Provider.CAPEMSHA256 || !roots.AppendCertsFromPEM(cfg.CAPEM) || cfg.Binding.InstallationID == "" || cfg.Worker.Policy == cfg.Publisher.Policy || cfg.ObserverPolicy == cfg.Worker.Policy || cfg.ObserverPolicy == cfg.Publisher.Policy || cfg.Worker.Role == cfg.Publisher.Role || cfg.Worker.Workload != nil || cfg.Publisher.Workload == nil || cfg.Publisher.PodUID == "" || cfg.Worker.PodUID != "" {
		return nil, kms.ErrPermission
	}
	for _, role := range []VaultPermissionRole{cfg.Worker, cfg.Publisher} {
		for _, name := range []string{role.AuthMount, role.Role, role.Policy} {
			if !vaultPolicyName(name) {
				return nil, kms.ErrPermission
			}
		}
		if role.Audience == "" || role.Namespace == "" || role.ServiceAccountName == "" || role.ServiceAccountUID == "" {
			return nil, kms.ErrPermission
		}
	}
	wk := cfg.Publisher.Workload
	if wk.Namespace != cfg.Publisher.Namespace || wk.ServiceAccountName != cfg.Publisher.ServiceAccountName || wk.ServiceAccountUID != cfg.Publisher.ServiceAccountUID || wk.PodUID != cfg.Publisher.PodUID {
		return nil, kms.ErrPermission
	}
	if _, err := VaultJWTAuthConfig(cfg.Trust); err != nil {
		return nil, kms.ErrPermission
	}
	if cfg.Trust.JWKSURL != "" {
		u, err := url.Parse(cfg.Trust.JWKSURL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || cfg.Trust.JWKSCAPEM == "" {
			return nil, kms.ErrPermission
		}
	} else if cfg.Trust.JWKSCAPEM != "" {
		return nil, kms.ErrPermission
	}
	for _, algorithm := range cfg.Trust.Algorithms {
		if algorithm != "RS256" && algorithm != "ES256" && algorithm != "EdDSA" {
			return nil, kms.ErrPermission
		}
	}
	cfg.CAPEM = bytes.Clone(cfg.CAPEM)
	cfg.Trust.ValidationPublicKeys = append([]string(nil), cfg.Trust.ValidationPublicKeys...)
	cfg.Trust.Algorithms = append([]string(nil), cfg.Trust.Algorithms...)
	copyWorkload := *cfg.Publisher.Workload
	cfg.Publisher.Workload = &copyWorkload
	cfg.Binding.GenerateRef.RawJSON = bytes.Clone(cfg.Binding.GenerateRef.RawJSON)
	cfg.Binding.UnwrapRef.RawJSON = bytes.Clone(cfg.Binding.UnwrapRef.RawJSON)
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16384, DisableCompression: true}
	return &VaultPermissionObserver{cfg: cfg, client: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (o *VaultPermissionObserver) Close() {
	if o != nil && o.client != nil {
		o.client.CloseIdleConnections()
	}
}
func (o *VaultPermissionObserver) token() ([]byte, error) {
	if o == nil {
		return nil, kms.ErrPermission
	}
	token, err := readVerifierJWT(o.cfg.TokenFile)
	if err != nil {
		return nil, kms.ErrPermission
	}
	h := sha256.Sum256(token)
	if hex.EncodeToString(h[:]) != o.cfg.TokenSHA256 {
		clear(token)
		return nil, kms.ErrPermission
	}
	return token, nil
}
func (o *VaultPermissionObserver) read(ctx context.Context, endpoint string) (json.RawMessage, error) {
	if o == nil || nilSource(ctx) || ctx.Err() != nil || !strings.HasPrefix(endpoint, "/v1/") || strings.ContainsAny(endpoint, "?#\r\n") {
		return nil, kms.ErrPermission
	}
	token, err := o.token()
	if err != nil {
		return nil, err
	}
	defer clear(token)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.cfg.Binding.Provider.Endpoint+endpoint, nil)
	if err != nil {
		return nil, kms.ErrPermission
	}
	req.Header.Set("X-Vault-Token", string(token))
	defer req.Header.Del("X-Vault-Token")
	response, err := o.client.Do(req)
	if err != nil {
		return nil, kms.ErrPermission
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Encoding") != "" {
		return nil, kms.ErrPermission
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	defer clear(raw)
	if err != nil || len(raw) > 1<<20 || !time.Now().Before(observerDeadline(ctx)) {
		return nil, kms.ErrPermission
	}
	var envelope struct {
		Data     json.RawMessage   `json:"data"`
		Errors   []json.RawMessage `json:"errors"`
		WrapInfo json.RawMessage   `json:"wrap_info"`
	}
	if !vaultExactFields(raw, []string{"data"}, []string{"data", "errors", "wrap_info"}) {
		return nil, kms.ErrPermission
	}
	if strictPermitIssuerJSON(raw, &envelope) != nil {
		// Vault adds standard transport fields. They do not authorize anything;
		// duplicate rejection still covers the full envelope and data below.
		if _, err := vaultCanonical(raw); err != nil || json.Unmarshal(raw, &envelope) != nil {
			return nil, kms.ErrPermission
		}
	}
	if len(envelope.Errors) != 0 || len(envelope.WrapInfo) != 0 && !bytes.Equal(bytes.TrimSpace(envelope.WrapInfo), []byte("null")) || len(envelope.Data) == 0 || bytes.Equal(bytes.TrimSpace(envelope.Data), []byte("null")) {
		return nil, kms.ErrPermission
	}
	return bytes.Clone(envelope.Data), nil
}

func observerDeadline(ctx context.Context) time.Time {
	if end, ok := ctx.Deadline(); ok {
		return end
	}
	return time.Time{}
}
func sameStrings(a, b []string) bool {
	a, b = append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	return reflect.DeepEqual(a, b)
}

func vaultExactFields(raw []byte, required, protected []string) bool {
	var fields map[string]json.RawMessage
	if _, err := vaultCanonical(raw); err != nil || json.Unmarshal(raw, &fields) != nil || fields == nil {
		return false
	}
	for _, name := range required {
		if len(fields[name]) == 0 || bytes.Equal(bytes.TrimSpace(fields[name]), []byte("null")) {
			return false
		}
	}
	for name := range fields {
		for _, exact := range protected {
			if name != exact && strings.EqualFold(name, exact) {
				return false
			}
		}
	}
	return true
}

func (o *VaultPermissionObserver) checkObserver(ctx context.Context) error {
	raw, err := o.read(ctx, "/v1/auth/token/lookup-self")
	if err != nil {
		return err
	}
	defer clear(raw)
	var token struct {
		Policies         []string `json:"policies"`
		IdentityPolicies []string `json:"identity_policies"`
		TTL              int64    `json:"ttl"`
	}
	if !vaultExactFields(raw, []string{"policies", "ttl"}, []string{"policies", "identity_policies", "ttl"}) || json.Unmarshal(raw, &token) != nil || token.TTL < 1 || !sameStrings(token.Policies, []string{o.cfg.ObserverPolicy}) || len(token.IdentityPolicies) != 0 {
		return kms.ErrPermission
	}
	policyRaw, err := o.read(ctx, "/v1/sys/policies/acl/"+o.cfg.ObserverPolicy)
	if err != nil {
		return err
	}
	var policy struct {
		Name   string `json:"name"`
		Policy string `json:"policy"`
	}
	expected, err := VaultObserverACL(o.cfg.Binding.Provider.KeyName, o.cfg.Worker, o.cfg.Publisher, o.cfg.ObserverPolicy)
	if err != nil || !vaultExactFields(policyRaw, []string{"name", "policy"}, []string{"name", "policy"}) || json.Unmarshal(policyRaw, &policy) != nil || policy.Name != o.cfg.ObserverPolicy || policy.Policy != expected {
		return kms.ErrPermission
	}
	return nil
}

func validateVaultRole(raw []byte, expected VaultPermissionRole) error {
	fields := strings.Fields("role_type bound_audiences bound_subject user_claim user_claim_json_pointer groups_claim bound_claims_type bound_claims claim_mappings token_policies token_type token_no_default_policy token_ttl token_max_ttl token_explicit_max_ttl token_period token_num_uses clock_skew_leeway expiration_leeway not_before_leeway")
	if !vaultExactFields(raw, fields, append(fields, "alias_metadata", "policies")) {
		return kms.ErrPermission
	}
	var role struct {
		Type                string            `json:"role_type"`
		Audience            []string          `json:"bound_audiences"`
		Subject             string            `json:"bound_subject"`
		UserClaim           string            `json:"user_claim"`
		UserPointer         bool              `json:"user_claim_json_pointer"`
		Groups              string            `json:"groups_claim"`
		ClaimsType          string            `json:"bound_claims_type"`
		Claims              map[string]string `json:"bound_claims"`
		Mappings            map[string]string `json:"claim_mappings"`
		Policies            []string          `json:"token_policies"`
		LegacyPolicies      []string          `json:"policies"`
		TokenType           string            `json:"token_type"`
		NoDefault           bool              `json:"token_no_default_policy"`
		TokenTTL            int64             `json:"token_ttl"`
		TokenMaxTTL         int64             `json:"token_max_ttl"`
		TokenExplicitMaxTTL int64             `json:"token_explicit_max_ttl"`
		TokenPeriod         int64             `json:"token_period"`
		TokenUses           int64             `json:"token_num_uses"`
		ClockLeeway         int64             `json:"clock_skew_leeway"`
		ExpirationLeeway    int64             `json:"expiration_leeway"`
		NotBeforeLeeway     int64             `json:"not_before_leeway"`
		AliasMetadata       map[string]string `json:"alias_metadata"`
	}
	if _, err := vaultCanonical(raw); err != nil || json.Unmarshal(raw, &role) != nil {
		return kms.ErrPermission
	}
	if len(role.LegacyPolicies) != 0 && !sameStrings(role.LegacyPolicies, []string{expected.Policy}) {
		return kms.ErrPermission
	}
	claims := map[string]string{"/kubernetes.io/namespace": expected.Namespace, "/kubernetes.io/serviceaccount/name": expected.ServiceAccountName, "/kubernetes.io/serviceaccount/uid": expected.ServiceAccountUID}
	if expected.PodUID != "" {
		claims["/kubernetes.io/pod/uid"] = expected.PodUID
	}
	mappings := map[string]string{"/kubernetes.io/namespace": "namespace", "/kubernetes.io/serviceaccount/uid": "service_account_uid", "/kubernetes.io/pod/uid": "pod_uid"}
	if role.Type != "jwt" || !sameStrings(role.Audience, []string{expected.Audience}) || role.Subject != "system:serviceaccount:"+expected.Namespace+":"+expected.ServiceAccountName || role.UserClaim != "/kubernetes.io/pod/uid" || !role.UserPointer || role.Groups != "" || role.ClaimsType != "string" || !reflect.DeepEqual(role.Claims, claims) || !reflect.DeepEqual(role.Mappings, mappings) || !sameStrings(role.Policies, []string{expected.Policy}) || role.TokenType != "batch" || !role.NoDefault || role.TokenTTL < 1 || role.TokenTTL > 20 || role.TokenMaxTTL < 1 || role.TokenMaxTTL > 20 || role.TokenExplicitMaxTTL < 1 || role.TokenExplicitMaxTTL > 20 || role.TokenPeriod != 0 || role.TokenUses != 0 || role.ClockLeeway != -1 || role.ExpirationLeeway != -1 || role.NotBeforeLeeway != -1 || len(role.AliasMetadata) != 0 {
		return kms.ErrPermission
	}
	return nil
}

func validateVaultJWTTrust(raw []byte, expected VaultJWTTrust) error {
	if !vaultExactFields(raw, []string{"bound_issuer", "jwt_supported_algs"}, strings.Fields("bound_issuer jwks_url jwks_ca_pem jwt_validation_pubkeys jwt_supported_algs oidc_discovery_url jwks_pairs default_role")) {
		return kms.ErrPermission
	}
	var trust struct {
		Issuer      string            `json:"bound_issuer"`
		JWKSURL     string            `json:"jwks_url"`
		JWKSCAPEM   string            `json:"jwks_ca_pem"`
		PublicKeys  []string          `json:"jwt_validation_pubkeys"`
		Algorithms  []string          `json:"jwt_supported_algs"`
		OIDC        string            `json:"oidc_discovery_url"`
		Pairs       []json.RawMessage `json:"jwks_pairs"`
		DefaultRole string            `json:"default_role"`
	}
	if _, err := vaultCanonical(raw); err != nil || json.Unmarshal(raw, &trust) != nil || trust.Issuer != expected.Issuer || trust.JWKSURL != expected.JWKSURL || trust.JWKSCAPEM != expected.JWKSCAPEM || !sameStrings(trust.PublicKeys, expected.ValidationPublicKeys) || !sameStrings(trust.Algorithms, expected.Algorithms) || trust.OIDC != "" || len(trust.Pairs) != 0 || trust.DefaultRole != "" {
		return kms.ErrPermission
	}
	return nil
}

func (o *VaultPermissionObserver) observePass(ctx context.Context) (ProviderCapabilityFacts, ProviderCapabilityFacts, error) {
	bad := func() (ProviderCapabilityFacts, ProviderCapabilityFacts, error) {
		return ProviderCapabilityFacts{}, ProviderCapabilityFacts{}, kms.ErrPermission
	}
	if o.checkObserver(ctx) != nil {
		return bad()
	}
	keyRaw, err := o.read(ctx, "/v1/transit/keys/"+o.cfg.Binding.Provider.KeyName)
	if err != nil {
		return bad()
	}
	var key struct {
		Type            string                     `json:"type"`
		Derived         bool                       `json:"derived"`
		Convergent      bool                       `json:"convergent_encryption"`
		Exportable      bool                       `json:"exportable"`
		PlaintextBackup bool                       `json:"allow_plaintext_backup"`
		Deletion        bool                       `json:"deletion_allowed"`
		Latest          int64                      `json:"latest_version"`
		MinEncryption   int64                      `json:"min_encryption_version"`
		MinDecryption   int64                      `json:"min_decryption_version"`
		Keys            map[string]json.RawMessage `json:"keys"`
	}
	keyFields := strings.Fields("type derived convergent_encryption exportable allow_plaintext_backup deletion_allowed latest_version min_encryption_version min_decryption_version keys")
	if !vaultExactFields(keyRaw, keyFields, keyFields) {
		return bad()
	}
	version, err := strconv.ParseInt(o.cfg.Binding.Key.ProviderVersion, 10, 64)
	if err != nil || json.Unmarshal(keyRaw, &key) != nil || key.Type != "aes256-gcm96" || !key.Derived || key.Convergent || key.Exportable || key.PlaintextBackup || key.Deletion || key.Latest < version || key.MinEncryption > version || key.MinDecryption > version || len(key.Keys[o.cfg.Binding.Key.ProviderVersion]) == 0 {
		return bad()
	}
	var results []ProviderCapabilityFacts
	for _, purpose := range []struct {
		operation kms.Operation
		role      VaultPermissionRole
		reference reg.TypedReference
	}{{kms.Generate, o.cfg.Worker, o.cfg.Binding.GenerateRef}, {kms.Unwrap, o.cfg.Publisher, o.cfg.Binding.UnwrapRef}} {
		role := purpose.role
		policyRaw, err := o.read(ctx, "/v1/sys/policies/acl/"+role.Policy)
		if err != nil {
			return bad()
		}
		var policy struct {
			Name   string `json:"name"`
			Policy string `json:"policy"`
		}
		expectedACL, err := vaultPermissionACL(purpose.operation, o.cfg.Binding.Provider.KeyName, o.cfg.Binding.Key.ProviderVersion)
		if err != nil || !vaultExactFields(policyRaw, []string{"name", "policy"}, []string{"name", "policy"}) || json.Unmarshal(policyRaw, &policy) != nil || policy.Name != role.Policy || policy.Policy != expectedACL {
			return bad()
		}
		roleRaw, err := o.read(ctx, "/v1/auth/"+role.AuthMount+"/role/"+role.Role)
		if err != nil || validateVaultRole(roleRaw, role) != nil {
			return bad()
		}
		trustRaw, err := o.read(ctx, "/v1/auth/"+role.AuthMount+"/config")
		if err != nil || validateVaultJWTTrust(trustRaw, o.cfg.Trust) != nil {
			return bad()
		}
		canonicalRole, err := vaultCanonical(roleRaw)
		if err != nil {
			return bad()
		}
		canonicalTrust, err := vaultCanonical(trustRaw)
		if err != nil {
			return bad()
		}
		path := "transit/decrypt/" + o.cfg.Binding.Provider.KeyName
		if purpose.operation == kms.Generate {
			path = "transit/datakey/plaintext/" + o.cfg.Binding.Provider.KeyName
		}
		hash := func(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
		permission := ProviderCapabilityPermission{Path: path, ProviderVersion: o.cfg.Binding.Key.ProviderVersion, AuthMount: role.AuthMount, Role: role.Role, Policy: role.Policy, PolicySHA256: hash([]byte(policy.Policy)), RoleSHA256: hash(canonicalRole), JWTTrustSHA256: hash(canonicalTrust), Reference: purpose.reference, ControllerVerifier: role.Workload}
		results = append(results, ProviderCapabilityFacts{Binding: o.cfg.Binding, Operation: purpose.operation, Permission: permission})
	}
	if o.checkObserver(ctx) != nil {
		return bad()
	}
	return results[0], results[1], nil
}

// Observe performs two complete real metadata observations with a separate
// least-privileged observer token. Any error, unknown source or drift rejects;
// no successful policy write or boolean can manufacture the private result.
// This is permission observation, NOT proof that a task has used a provider.
func (o *VaultPermissionObserver) Observe(ctx context.Context) (*ObservedVaultPermissions, error) {
	if o == nil || nilSource(ctx) || ctx.Err() != nil {
		return nil, kms.ErrPermission
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	g, u, err := o.observePass(ctx)
	if err != nil {
		return nil, err
	}
	againG, againU, err := o.observePass(ctx)
	if err != nil || !reflect.DeepEqual(g, againG) || !reflect.DeepEqual(u, againU) {
		return nil, kms.ErrPermission
	}
	return &ObservedVaultPermissions{owner: o, observed: time.Now().UTC(), generate: g, unwrap: u}, nil
}

// Sign emits only the existing owner-signed capability format consumed by
// SQLProviderCapabilityPreparation. The original installer independently pins
// this observer issuer and stores the exact bytes in immutable evidence.
func (p *ObservedVaultPermissions) Sign(operation kms.Operation, source reg.SourceRecord, revision string, until time.Time, issuer ed25519.PrivateKey) (SignedProviderCapabilityRecord, error) {
	if p == nil || p.owner == nil || p.observed.IsZero() || time.Since(p.observed) < 0 || time.Since(p.observed) > time.Minute || !until.After(time.Now()) || until.After(p.observed.Add(24*time.Hour)) || len(issuer) != ed25519.PrivateKeySize || source.SourceID == "" || !strings.HasPrefix(source.RecordID, "sev_") || source.RecordVersion == "" || revision == "" {
		return SignedProviderCapabilityRecord{}, kms.ErrPermission
	}
	facts := p.generate
	if operation == kms.Unwrap {
		facts = p.unwrap
	} else if operation != kms.Generate {
		return SignedProviderCapabilityRecord{}, kms.ErrPermission
	}
	raw, err := json.Marshal(facts)
	if err != nil {
		return SignedProviderCapabilityRecord{}, kms.ErrPermission
	}
	h := sha256.Sum256(raw)
	source.ContentSHA256 = hex.EncodeToString(h[:])
	record, err := json.Marshal(ProviderCapabilityRecord{Facts: facts, Source: source, Revision: revision, NotBefore: p.observed, Until: until})
	if err != nil {
		return SignedProviderCapabilityRecord{}, kms.ErrPermission
	}
	return SignedProviderCapabilityRecord{Record: record, Signature: ed25519.Sign(issuer, append([]byte(ProviderCapabilityDomain), record...))}, nil
}
