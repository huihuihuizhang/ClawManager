package systembackupkekadapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	ev "clawreef/internal/systembackupevidence"
	kms "clawreef/internal/systembackupkms"
)

// This is evidence's existing TransitConfig, not a capture binding, execution
// record key or task grant. Only dedicated wrap/unwrap roles are supported.
type EvidenceVaultObserverConfig struct {
	Transit                                ev.TransitConfig
	TokenFile, TokenSHA256, ObserverPolicy string
	Wrap, Unwrap                           VaultPermissionRole
	Trust                                  VaultJWTTrust
}
type EvidenceVaultObservation struct {
	origin         *EvidenceVaultObservation
	identity       string
	started, until time.Time
}

func (o *EvidenceVaultObservation) IdentitySHA256() string {
	if o == nil || o.origin != o {
		return ""
	}
	return o.identity
}
func (o *EvidenceVaultObservation) StartedAt() time.Time {
	if o == nil || o.origin != o {
		return time.Time{}
	}
	return o.started
}
func (o *EvidenceVaultObservation) ValidUntil() time.Time {
	if o == nil || o.origin != o {
		return time.Time{}
	}
	return o.until
}
func (*EvidenceVaultObservation) MarshalJSON() ([]byte, error) { return nil, kms.ErrPermission }

// Installer payload only. Reading back these exact policies is mandatory.
// Evidence wraps an existing random DEK: datakey/plaintext is never allowed.
func EvidenceVaultRuntimeACL(c ev.TransitConfig, op ev.TransitOperation) (string, error) {
	context, e := ev.EvidenceTransitContext(c.Installation, c.Key)
	if e != nil || !keyNameValid(c.KeyName) || c.KeyVersion == 0 {
		return "", kms.ErrPermission
	}
	if op == ev.TransitWrap {
		return "path \"transit/encrypt/" + c.KeyName + "\" {\n  capabilities = [\"update\"]\n  required_parameters = [\"context\", \"plaintext\", \"key_version\"]\n  allowed_parameters = {\n    \"context\" = [\"" + context + "\"]\n    \"plaintext\" = []\n    \"key_version\" = [\"" + strconv.FormatUint(uint64(c.KeyVersion), 10) + "\"]\n  }\n}\n", nil
	}
	if op == ev.TransitUnwrap {
		return "path \"transit/decrypt/" + c.KeyName + "\" {\n  capabilities = [\"update\"]\n  required_parameters = [\"context\", \"ciphertext\"]\n  allowed_parameters = {\n    \"context\" = [\"" + context + "\"]\n    \"ciphertext\" = []\n  }\n}\n", nil
	}
	return "", kms.ErrPermission
}

func ValidateEvidenceVaultObserver(c EvidenceVaultObserverConfig) error {
	u, e := url.Parse(c.Transit.Endpoint)
	h := sha256.Sum256(c.Transit.CAPEM)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.ForceQuery || !authorityHash.MatchString(c.Transit.CASHA256) || hex.EncodeToString(h[:]) != c.Transit.CASHA256 || len(c.Transit.CAPEM) == 0 || len(c.Transit.CAPEM) > 65536 || !filepath.IsAbs(c.TokenFile) || filepath.Clean(c.TokenFile) != c.TokenFile || !authorityHash.MatchString(c.TokenSHA256) || !vaultPolicyName(c.ObserverPolicy) || c.Wrap.Policy == c.Unwrap.Policy || c.Wrap.Role == c.Unwrap.Role || c.ObserverPolicy == c.Wrap.Policy || c.ObserverPolicy == c.Unwrap.Policy {
		return kms.ErrPermission
	}
	if _, e := EvidenceVaultRuntimeACL(c.Transit, ev.TransitWrap); e != nil {
		return e
	}
	if _, e := VaultJWTAuthConfig(c.Trust); e != nil {
		return e
	}
	for _, r := range []VaultPermissionRole{c.Wrap, c.Unwrap} {
		if _, e := VaultJWTAuthRole(r); e != nil || r.Workload != nil {
			return kms.ErrPermission
		}
	}
	if _, e := VaultObserverACL(c.Transit.KeyName, c.Wrap, c.Unwrap, c.ObserverPolicy); e != nil {
		return e
	}
	return nil
}

type evidenceVaultReader struct {
	c      EvidenceVaultObserverConfig
	client *http.Client
	until  time.Time
}

func evidenceHash(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func (r *evidenceVaultReader) read(ctx context.Context, path string) (json.RawMessage, error) {
	if ctx == nil || ctx.Err() != nil || !strings.HasPrefix(path, "/v1/") || strings.ContainsAny(path, "?#\r\n") {
		return nil, kms.ErrPermission
	}
	token, e := readVerifierJWT(r.c.TokenFile)
	if e != nil {
		return nil, kms.ErrPermission
	}
	defer clear(token)
	if evidenceHash(token) != r.c.TokenSHA256 {
		return nil, kms.ErrPermission
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, r.c.Transit.Endpoint+path, nil)
	if e != nil {
		return nil, kms.ErrPermission
	}
	req.Header.Set("X-Vault-Token", string(token))
	defer req.Header.Del("X-Vault-Token")
	resp, e := r.client.Do(req)
	if e != nil {
		return nil, kms.ErrPermission
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Encoding") != "" {
		return nil, kms.ErrPermission
	}
	raw, e := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	defer clear(raw)
	if e != nil || len(raw) > 1<<20 || ctx.Err() != nil || !time.Now().Before(r.until) {
		return nil, kms.ErrPermission
	}
	var envelope struct {
		Data     json.RawMessage   `json:"data"`
		Errors   []json.RawMessage `json:"errors"`
		WrapInfo json.RawMessage   `json:"wrap_info"`
	}
	if _, e := vaultCanonical(raw); e != nil || json.Unmarshal(raw, &envelope) != nil || len(envelope.Data) == 0 || len(envelope.Errors) > 0 || len(envelope.WrapInfo) > 0 && !bytes.Equal(envelope.WrapInfo, []byte("null")) {
		return nil, kms.ErrPermission
	}
	return bytes.Clone(envelope.Data), nil
}
func (r *evidenceVaultReader) policy(ctx context.Context, name, expected string) (json.RawMessage, error) {
	raw, e := r.read(ctx, "/v1/sys/policies/acl/"+name)
	var p struct {
		Name   string `json:"name"`
		Policy string `json:"policy"`
	}
	if e != nil || !vaultExactFields(raw, []string{"name", "policy"}, []string{"name", "policy"}) || json.Unmarshal(raw, &p) != nil || p.Name != name || p.Policy != expected {
		return nil, kms.ErrPermission
	}
	return raw, nil
}
func (r *evidenceVaultReader) observer(ctx context.Context) error {
	started := time.Now().UTC()
	raw, e := r.read(ctx, "/v1/auth/token/lookup-self")
	var token struct {
		Policies         []string `json:"policies"`
		IdentityPolicies []string `json:"identity_policies"`
		TTL              int64    `json:"ttl"`
	}
	if e != nil || !vaultExactFields(raw, []string{"policies", "ttl"}, []string{"policies", "identity_policies", "ttl"}) || json.Unmarshal(raw, &token) != nil || !sameStrings(token.Policies, []string{r.c.ObserverPolicy}) || len(token.IdentityPolicies) > 0 || token.TTL < 1 {
		return kms.ErrPermission
	}
	// TTL bounds the original interval from before lookup, never receipt time.
	if token.TTL <= 15 {
		end := started.Add(time.Duration(token.TTL) * time.Second)
		if end.Before(r.until) {
			r.until = end
		}
	}
	expected, e := VaultObserverACL(r.c.Transit.KeyName, r.c.Wrap, r.c.Unwrap, r.c.ObserverPolicy)
	if e != nil {
		return e
	}
	_, e = r.policy(ctx, r.c.ObserverPolicy, expected)
	return e
}
func (r *evidenceVaultReader) pass(ctx context.Context) (string, error) {
	if r.observer(ctx) != nil {
		return "", kms.ErrPermission
	}
	raw, e := r.read(ctx, "/v1/transit/keys/"+r.c.Transit.KeyName)
	var key struct {
		Type       string                     `json:"type"`
		Derived    bool                       `json:"derived"`
		Convergent bool                       `json:"convergent_encryption"`
		Exportable bool                       `json:"exportable"`
		Backup     bool                       `json:"allow_plaintext_backup"`
		Deletion   bool                       `json:"deletion_allowed"`
		Latest     uint64                     `json:"latest_version"`
		MinEncrypt uint64                     `json:"min_encryption_version"`
		MinDecrypt uint64                     `json:"min_decryption_version"`
		Keys       map[string]json.RawMessage `json:"keys"`
	}
	fields := strings.Fields("type derived convergent_encryption exportable allow_plaintext_backup deletion_allowed latest_version min_encryption_version min_decryption_version keys")
	v := uint64(r.c.Transit.KeyVersion)
	version := strconv.FormatUint(v, 10)
	if e != nil || !vaultExactFields(raw, fields, fields) || json.Unmarshal(raw, &key) != nil || key.Type != "aes256-gcm96" || !key.Derived || key.Convergent || key.Exportable || key.Backup || key.Deletion || key.Latest < v || key.MinEncrypt > v || key.MinDecrypt > v || len(key.Keys[version]) == 0 {
		return "", kms.ErrPermission
	}
	// Only stable key metadata enters identity; native per-version metadata is
	// retained, so changing the selected historical key cannot pass unnoticed.
	parts := []json.RawMessage{raw}
	for n, role := range []VaultPermissionRole{r.c.Wrap, r.c.Unwrap} {
		op := ev.TransitWrap
		if n == 1 {
			op = ev.TransitUnwrap
		}
		expected, e := EvidenceVaultRuntimeACL(r.c.Transit, op)
		if e != nil {
			return "", e
		}
		policy, e := r.policy(ctx, role.Policy, expected)
		if e != nil {
			return "", e
		}
		roleRaw, e := r.read(ctx, "/v1/auth/"+role.AuthMount+"/role/"+role.Role)
		if e != nil || validateVaultRole(roleRaw, role) != nil {
			return "", kms.ErrPermission
		}
		trust, e := r.read(ctx, "/v1/auth/"+role.AuthMount+"/config")
		if e != nil || validateVaultJWTTrust(trust, r.c.Trust) != nil {
			return "", kms.ErrPermission
		}
		parts = append(parts, policy, roleRaw, trust)
	}
	encoded, e := json.Marshal(parts)
	if e != nil {
		return "", kms.ErrPermission
	}
	encoded, e = vaultCanonical(encoded)
	if e != nil || r.observer(ctx) != nil {
		return "", kms.ErrPermission
	}
	return evidenceHash(encoded), nil
}

// ObserveEvidenceVault performs no login, key generation, wrap or decrypt.
// Actual protected runtime operations still require their live task authority.
func ObserveEvidenceVault(ctx context.Context, c EvidenceVaultObserverConfig) (*EvidenceVaultObservation, error) {
	if ctx == nil || ctx.Err() != nil || ValidateEvidenceVaultObserver(c) != nil {
		return nil, kms.ErrPermission
	}
	encoded, e := json.Marshal(c)
	if e != nil {
		return nil, kms.ErrPermission
	}
	var frozen EvidenceVaultObserverConfig
	if json.Unmarshal(encoded, &frozen) != nil {
		return nil, kms.ErrPermission
	}
	c = frozen
	started := time.Now().UTC().Truncate(time.Microsecond)
	until := started.Add(15 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(until) {
		until = d
	}
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(c.Transit.CAPEM) {
		return nil, kms.ErrPermission
	}
	t := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 2 * time.Second, MaxResponseHeaderBytes: 16384, DisableCompression: true}
	client := &http.Client{Transport: t, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	r := &evidenceVaultReader{c: c, client: client, until: until}
	a, e := r.pass(ctx)
	if e != nil {
		return nil, kms.ErrPermission
	}
	b, e := r.pass(ctx)
	if e != nil || a != b || ctx.Err() != nil || !time.Now().Before(r.until) || RecheckEvidenceVaultFiles(c) != nil {
		return nil, kms.ErrPermission
	}
	o := &EvidenceVaultObservation{identity: a, started: started, until: r.until}
	o.origin = o
	return o, nil
}
func RecheckEvidenceVaultFiles(c EvidenceVaultObserverConfig) error {
	if ValidateEvidenceVaultObserver(c) != nil {
		return kms.ErrPermission
	}
	raw, e := readVerifierJWT(c.TokenFile)
	defer clear(raw)
	if e != nil || evidenceHash(raw) != c.TokenSHA256 {
		return kms.ErrPermission
	}
	return nil
}
