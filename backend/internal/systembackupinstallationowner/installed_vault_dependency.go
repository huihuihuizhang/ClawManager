package systembackupinstallationowner

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	a "clawreef/internal/systembackupkekadapter"
	kms "clawreef/internal/systembackupkms"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Existing installation metadata only: no ConfigRef, configuration candidate,
// future workload, active capture grant, task, Mapping/Generate/Unwrap record
// or observed Passed field. Original-owner-readonly mode is INSTALLER ONLY;
// formal workloads must use their separate metadata-only observer identity.
type InstalledVaultDependencyConfig struct {
	Version, Endpoint, CASHA256, ClusterID, TransitMount string
	PinnedKeyName, PinnedKeyVersion                      string
	TokenFile, TokenSHA256, IdentityMode, ObserverPolicy string
	CAPEM                                                []byte
	JWTMount                                             string
	Trust                                                a.VaultJWTTrust
	EvidenceWrap                                         *InstalledVaultEvidenceWrapProfile `json:",omitempty"`
}

type InstalledVaultKeyVersion struct{ Version, PublicKeySHA256 string }
type InstalledVaultKey struct {
	Name, Type                                   string
	Versions                                     []InstalledVaultKeyVersion
	Latest, MinimumEncryption, MinimumDecryption int64
}
type InstalledVaultRole struct{ Name, Policy, Namespace, ServiceAccount, ServiceAccountUID, PodUID, Audience, PolicySHA256, RoleSHA256 string }
type InstalledVaultDependencyData struct {
	Version, ClusterID, ServerVersion, NamespaceUID, MetadataSHA256, TransportIdentity string
	Keys                                                                               []InstalledVaultKey
	Roles                                                                              []InstalledVaultRole
}
type InstalledVaultDependencyObserver struct {
	cfg                     InstalledVaultDependencyConfig
	transport               *CaptureSigningObserver
	kube                    kubernetes.Interface
	namespace, namespaceUID string
}
type ObservedInstalledVaultDependency struct {
	origin          *ObservedInstalledVaultDependency
	owner           *InstalledVaultDependencyObserver
	ctx             context.Context
	data            InstalledVaultDependencyData
	observed, until time.Time
}

func (*ObservedInstalledVaultDependency) MarshalJSON() ([]byte, error) { return nil, ErrOwner }
func (*InstalledVaultDependencyObserver) MarshalJSON() ([]byte, error) { return nil, ErrOwner }

func NewInstalledVaultDependencyObserver(cfg InstalledVaultDependencyConfig, kube kubernetes.Interface, namespace, namespaceUID string) (*InstalledVaultDependencyObserver, error) {
	u, e := url.Parse(cfg.Endpoint)
	if e != nil || cfg.Version != "installed-vault-dependency-input.v1" || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.ForceQuery || nilInterface(kube) || namespace == "" || namespaceUID == "" || cfg.ClusterID == "" || !safeName.MatchString(cfg.TransitMount) || !safeName.MatchString(cfg.JWTMount) || !safeName.MatchString(cfg.PinnedKeyName) || !numericVersion(cfg.PinnedKeyVersion) || len(cfg.CAPEM) == 0 || len(cfg.CAPEM) > 65536 || digest(cfg.CAPEM) != cfg.CASHA256 || !hashPattern.MatchString(cfg.TokenSHA256) || !filepath.IsAbs(cfg.TokenFile) || filepath.Clean(cfg.TokenFile) != cfg.TokenFile || cfg.Trust.JWKSURL != "" || cfg.Trust.JWKSCAPEM != "" || len(cfg.Trust.ValidationPublicKeys) == 0 || !reflect.DeepEqual(cfg.Trust.Algorithms, []string{"RS256"}) {
		return nil, ErrOwner
	}
	if cfg.EvidenceWrap != nil && validateInstalledEvidenceWrap(cfg) != nil {
		return nil, ErrOwner
	}
	if cfg.IdentityMode != "original-owner-readonly" && cfg.IdentityMode != "metadata-only" || cfg.IdentityMode == "metadata-only" && (!safeName.MatchString(cfg.ObserverPolicy) || cfg.ObserverPolicy == "root" || cfg.ObserverPolicy == "default") || cfg.IdentityMode == "original-owner-readonly" && cfg.ObserverPolicy != "" {
		return nil, ErrOwner
	}
	if _, e := a.VaultJWTAuthConfig(cfg.Trust); e != nil {
		return nil, ErrOwner
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cfg.CAPEM) {
		return nil, ErrOwner
	}
	cfg.CAPEM = bytes.Clone(cfg.CAPEM)
	cfg.Trust.ValidationPublicKeys = append([]string(nil), cfg.Trust.ValidationPublicKeys...)
	cfg.Trust.Algorithms = append([]string(nil), cfg.Trust.Algorithms...)
	// Reuse only the existing bounded TLS HTTP/envelope readers. This object
	// is a transport, not a fabricated original record or capture authority.
	transport := &CaptureSigningObserver{cfg: SigningObserverConfig{Endpoint: cfg.Endpoint}, client: &http.Client{Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16384, DisableCompression: true}, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	return &InstalledVaultDependencyObserver{cfg: cfg, transport: transport, kube: kube, namespace: namespace, namespaceUID: namespaceUID}, nil
}

func (o *InstalledVaultDependencyObserver) Close() {
	if o != nil && o.transport != nil {
		o.transport.Close()
	}
}

func (o *InstalledVaultDependencyObserver) inputToken() ([]byte, error) {
	st, e := os.Lstat(o.cfg.TokenFile)
	if e != nil || !st.Mode().IsRegular() || runtime.GOOS == "linux" && st.Mode().Perm()&0077 != 0 {
		return nil, ErrOwner
	}
	raw, e := localFile(o.cfg.TokenFile, 16384)
	if e != nil || digest(raw) != o.cfg.TokenSHA256 {
		clear(raw)
		return nil, ErrOwner
	}
	// The original owner's existing CLI token file may have one line ending.
	// Pin its exact original bytes first; normalization grants no new token.
	if o.cfg.IdentityMode == "original-owner-readonly" {
		raw = bytes.TrimSuffix(raw, []byte("\n"))
		raw = bytes.TrimSuffix(raw, []byte("\r"))
	}
	if len(raw) < 16 {
		clear(raw)
		return nil, ErrOwner
	}
	for _, b := range raw {
		if b < 33 || b > 126 {
			clear(raw)
			return nil, ErrOwner
		}
	}
	return raw, nil
}

// Exact desired observer policy. The wildcard is limited to this original
// provider's key/role/policy metadata READ census, never crypto/key export,
// token creation, policy/role writes, or a task permission.
func InstalledVaultDependencyObserverACL(transit, jwt string) (string, error) {
	if !safeName.MatchString(transit) || !safeName.MatchString(jwt) {
		return "", ErrOwner
	}
	paths := []struct{ p, c string }{{"auth/token/lookup-self", "read"}, {transit + "/keys", "list"}, {transit + "/keys/*", "read"}, {"auth/" + jwt + "/config", "read"}, {"auth/" + jwt + "/role", "list"}, {"auth/" + jwt + "/role/*", "read"}, {"sys/policies/acl/*", "read"}}
	var out strings.Builder
	for _, p := range paths {
		out.WriteString("path \"" + p.p + "\" {\n  capabilities = [\"" + p.c + "\"]\n}\n")
	}
	return out.String(), nil
}

func (o *InstalledVaultDependencyObserver) kubernetesTrust(ctx context.Context) error {
	ns, e := o.kube.CoreV1().Namespaces().Get(ctx, o.namespace, metav1.GetOptions{})
	if e != nil || string(ns.UID) != o.namespaceUID || ns.DeletionTimestamp != nil {
		return ErrOwner
	}
	client := o.kube.Discovery().RESTClient()
	if client == nil {
		return ErrOwner
	}
	raw, e := client.Get().AbsPath("/.well-known/openid-configuration").Do(ctx).Raw()
	var discovery struct {
		Issuer string `json:"issuer"`
		JWKS   string `json:"jwks_uri"`
	}
	if e != nil || len(raw) > 65536 || json.Unmarshal(raw, &discovery) != nil || discovery.Issuer != o.cfg.Trust.Issuer {
		return ErrOwner
	}
	keysRequest := client.Get().AbsPath("/openid/v1/jwks")
	if !installedVaultDiscoveryURL(discovery.Issuer, discovery.JWKS, keysRequest.URL()) {
		return ErrOwner
	}
	raw, e = keysRequest.Do(ctx).Raw()
	var jwks struct {
		Keys []struct{ Kty, N, E, Use, Alg string }
	}
	if e != nil || len(raw) > 262144 || json.Unmarshal(raw, &jwks) != nil || len(jwks.Keys) == 0 || len(jwks.Keys) > 32 {
		return ErrOwner
	}
	actual := map[string]bool{}
	for _, key := range jwks.Keys {
		if key.Kty != "RSA" || key.Use != "sig" || key.Alg != "RS256" {
			return ErrOwner
		}
		n, e := base64.RawURLEncoding.Strict().DecodeString(key.N)
		if e != nil {
			return ErrOwner
		}
		exponent, e := base64.RawURLEncoding.Strict().DecodeString(key.E)
		if e != nil || len(exponent) == 0 || len(exponent) > 4 {
			return ErrOwner
		}
		v := 0
		for _, b := range exponent {
			v = v<<8 | int(b)
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: v}
		if pub.N.BitLen() < 2048 || v < 3 {
			return ErrOwner
		}
		der, e := x509.MarshalPKIXPublicKey(pub)
		if e != nil {
			return ErrOwner
		}
		actual[digest(der)] = true
	}
	want := map[string]bool{}
	for _, text := range o.cfg.Trust.ValidationPublicKeys {
		block, rest := pem.Decode([]byte(text))
		if block == nil || len(bytes.TrimSpace(rest)) != 0 {
			return ErrOwner
		}
		pub, e := x509.ParsePKIXPublicKey(block.Bytes)
		if e != nil {
			return ErrOwner
		}
		if _, ok := pub.(*rsa.PublicKey); !ok {
			return ErrOwner
		}
		der, e := x509.MarshalPKIXPublicKey(pub)
		if e != nil {
			return ErrOwner
		}
		want[digest(der)] = true
	}
	if !reflect.DeepEqual(actual, want) {
		return ErrOwner
	}
	return nil
}

func (o *InstalledVaultDependencyObserver) health(ctx context.Context) (string, error) {
	raw, e := o.transport.request(ctx, "GET", "/v1/sys/health", nil, nil)
	var state struct {
		ClusterID           string `json:"cluster_id"`
		Version             string
		Initialized, Sealed bool
	}
	if e != nil || !requiredFields(raw, "cluster_id", "version", "initialized", "sealed") || json.Unmarshal(raw, &state) != nil || state.ClusterID != o.cfg.ClusterID || !state.Initialized || state.Sealed || state.Version == "" || len(state.Version) > 64 {
		return "", ErrOwner
	}
	return state.Version, nil
}

func installedVaultNames(raw []byte) ([]string, error) {
	var data struct {
		Keys []string `json:"keys"`
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(raw, &members) != nil || len(members) != 1 || members["keys"] == nil || json.Unmarshal(raw, &data) != nil || data.Keys == nil || len(data.Keys) > 64 {
		return nil, ErrOwner
	}
	seen := map[string]bool{}
	for _, name := range data.Keys {
		if !safeName.MatchString(name) || seen[name] {
			return nil, ErrOwner
		}
		seen[name] = true
	}
	sort.Strings(data.Keys)
	return data.Keys, nil
}

// Vault returns an authenticated empty role-list as 404/errors:[] when the
// already-read JWT mount has no roles. A 403, another body, unknown mount or
// missing key list never becomes an empty successful census.
func (o *InstalledVaultDependencyObserver) listMetadata(ctx context.Context, path string, token []byte, emptyAllowed bool) ([]string, error) {
	request, e := http.NewRequestWithContext(ctx, "LIST", o.cfg.Endpoint+path, nil)
	if e != nil {
		return nil, ErrOwner
	}
	request.Header.Set("X-Vault-Token", string(token))
	response, e := o.transport.client.Do(request)
	if e != nil {
		return nil, ErrOwner
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, 65537))
	if e != nil || len(raw) > 65536 {
		return nil, ErrOwner
	}
	if response.StatusCode == 404 && emptyAllowed {
		var empty struct {
			Errors []string `json:"errors"`
		}
		var members map[string]json.RawMessage
		if json.Unmarshal(raw, &members) == nil && len(members) == 1 && members["errors"] != nil && json.Unmarshal(raw, &empty) == nil && empty.Errors != nil && len(empty.Errors) == 0 {
			return []string{}, nil
		}
		return nil, ErrOwner
	}
	if response.StatusCode != 200 {
		return nil, ErrOwner
	}
	data, e := dataEnvelope(raw)
	if e != nil {
		return nil, ErrOwner
	}
	return installedVaultNames(data)
}

// Normalize only an independently verified public-key set. All other JWT
// configuration fields retain the original exact JSON checks.
func installedVaultJWTConfigMatches(actual, expected []byte) bool {
	if !utf8JSON(actual) || !utf8JSON(expected) {
		return false
	}
	var got, want map[string]json.RawMessage
	if json.Unmarshal(actual, &got) != nil || json.Unmarshal(expected, &want) != nil {
		return false
	}
	var actualKeys, expectedKeys []string
	if json.Unmarshal(got["jwt_validation_pubkeys"], &actualKeys) != nil ||
		json.Unmarshal(want["jwt_validation_pubkeys"], &expectedKeys) != nil ||
		!installedVaultPublicKeysEqual(actualKeys, expectedKeys) {
		return false
	}
	got["jwt_validation_pubkeys"] = want["jwt_validation_pubkeys"]
	normalized, err := json.Marshal(got)
	return err == nil && jsonSubset(normalized, expected)
}

type installedVaultNativeFailure struct {
	stage string
	cause error
}

func (e *installedVaultNativeFailure) Error() string {
	return "installed Vault native metadata unconfirmed"
}
func (e *installedVaultNativeFailure) Unwrap() error { return e.cause }
func (e *installedVaultNativeFailure) Phase() string { return e.stage }

func (o *InstalledVaultDependencyObserver) pass(ctx context.Context, token []byte) (_ InstalledVaultDependencyData, resultErr error) {
	stage := "kubernetes_trust"
	defer func() {
		if resultErr != nil {
			resultErr = &installedVaultNativeFailure{stage: stage, cause: resultErr}
		}
	}()
	var zero InstalledVaultDependencyData
	if o.kubernetesTrust(ctx) != nil {
		return zero, ErrOwner
	}
	stage = "health"
	version, e := o.health(ctx)
	if e != nil {
		return zero, e
	}
	stage = "token_identity"
	self, e := o.transport.read(ctx, "/v1/auth/token/lookup-self", token)
	var identity struct {
		Policies         []string `json:"policies"`
		IdentityPolicies []string `json:"identity_policies"`
		TTL              int64    `json:"ttl"`
	}
	if e != nil || json.Unmarshal(self, &identity) != nil || len(identity.Policies) != 1 || len(identity.IdentityPolicies) != 0 {
		return zero, ErrOwner
	}
	if o.cfg.IdentityMode == "original-owner-readonly" {
		if identity.Policies[0] != "root" {
			return zero, ErrOwner
		}
	} else {
		if identity.Policies[0] != o.cfg.ObserverPolicy || identity.TTL < 1 {
			return zero, ErrOwner
		}
		raw, e := o.transport.read(ctx, "/v1/sys/policies/acl/"+o.cfg.ObserverPolicy, token)
		var policy struct{ Name, Policy string }
		expected, _ := InstalledVaultDependencyObserverACL(o.cfg.TransitMount, o.cfg.JWTMount)
		if e != nil || json.Unmarshal(raw, &policy) != nil || policy.Name != o.cfg.ObserverPolicy || policy.Policy != expected {
			return zero, ErrOwner
		}
	}
	stage = "jwt_config"
	jwt, e := o.transport.read(ctx, "/v1/auth/"+o.cfg.JWTMount+"/config", token)
	expected, e2 := a.VaultJWTAuthConfig(o.cfg.Trust)
	if e != nil || e2 != nil || !installedVaultJWTConfigMatches(jwt, expected) {
		return zero, ErrOwner
	}
	var extra struct {
		OIDC        string            `json:"oidc_discovery_url"`
		JWKSURL     string            `json:"jwks_url"`
		JWKSCA      string            `json:"jwks_ca_pem"`
		DefaultRole string            `json:"default_role"`
		JWKSPairs   []json.RawMessage `json:"jwks_pairs"`
	}
	if json.Unmarshal(jwt, &extra) != nil || extra.OIDC != "" || extra.JWKSURL != "" || extra.JWKSCA != "" || extra.DefaultRole != "" || len(extra.JWKSPairs) != 0 {
		return zero, ErrOwner
	}
	stage = "transit_key_list"
	names, e := o.listMetadata(ctx, "/v1/"+o.cfg.TransitMount+"/keys", token, false)
	if e != nil || len(names) == 0 {
		return zero, ErrOwner
	}
	out := InstalledVaultDependencyData{Version: "installed-vault-dependency-observation.v1", ClusterID: o.cfg.ClusterID, ServerVersion: version, NamespaceUID: o.namespaceUID, TransportIdentity: o.cfg.IdentityMode, Keys: []InstalledVaultKey{}, Roles: []InstalledVaultRole{}}
	stamps := []string{digest(jwt)}
	pinned := false
	keyVersions := map[string][]string{}
	stage = "transit_key_metadata"
	for _, name := range names {
		raw, e := o.transport.read(ctx, "/v1/"+o.cfg.TransitMount+"/keys/"+name, token)
		var key struct {
			Type                string
			Derived, Exportable bool
			PlaintextBackup     bool                       `json:"allow_plaintext_backup"`
			Deletion            bool                       `json:"deletion_allowed"`
			Convergent          bool                       `json:"convergent_encryption"`
			Latest              int64                      `json:"latest_version"`
			MinEncryption       int64                      `json:"min_encryption_version"`
			MinDecryption       int64                      `json:"min_decryption_version"`
			Keys                map[string]json.RawMessage `json:"keys"`
		}
		if e != nil || !requiredFields(raw, "type", "derived", "exportable", "allow_plaintext_backup", "deletion_allowed", "latest_version", "min_encryption_version", "min_decryption_version", "keys") || json.Unmarshal(raw, &key) != nil || key.Exportable || key.PlaintextBackup || key.Deletion || key.Convergent || key.Latest < 1 || len(key.Keys) == 0 || len(key.Keys) > 256 {
			return zero, ErrOwner
		}
		if key.Type != "aes256-gcm96" && key.Type != "ed25519" || key.Type == "aes256-gcm96" && !key.Derived || key.Type == "ed25519" && key.Derived {
			return zero, ErrOwner
		}
		item := InstalledVaultKey{Name: name, Type: key.Type, Latest: key.Latest, MinimumEncryption: key.MinEncryption, MinimumDecryption: key.MinDecryption, Versions: []InstalledVaultKeyVersion{}}
		for v, body := range key.Keys {
			if !numericVersion(v) {
				return zero, ErrOwner
			}
			n, _ := strconv.ParseInt(v, 10, 64)
			if n > key.Latest {
				return zero, ErrOwner
			}
			pubSHA := ""
			if key.Type == "ed25519" {
				var public struct {
					PublicKey string `json:"public_key"`
				}
				if json.Unmarshal(body, &public) != nil {
					return zero, ErrOwner
				}
				b, e := base64.StdEncoding.Strict().DecodeString(public.PublicKey)
				if e != nil || len(b) != 32 {
					return zero, ErrOwner
				}
				pubSHA = digest(b)
			}
			item.Versions = append(item.Versions, InstalledVaultKeyVersion{v, pubSHA})
			keyVersions[name] = append(keyVersions[name], v)
			if name == o.cfg.PinnedKeyName && v == o.cfg.PinnedKeyVersion {
				pinned = key.Type == "aes256-gcm96" && n >= key.MinEncryption && n >= key.MinDecryption
			}
		}
		sort.Slice(item.Versions, func(i, j int) bool { return item.Versions[i].Version < item.Versions[j].Version })
		out.Keys = append(out.Keys, item)
		canonical, e := canonicalRaw(raw)
		if e != nil {
			return zero, ErrOwner
		}
		stamps = append(stamps, digest(canonical))
	}
	stage = "pinned_key"
	if !pinned {
		return zero, ErrOwner
	}
	stage = "role_list"
	roles, e := o.listMetadata(ctx, "/v1/auth/"+o.cfg.JWTMount+"/role", token, true)
	if e != nil {
		return zero, ErrOwner
	}
	stage = "role_metadata"
	for _, name := range roles {
		role, e := o.installedRole(ctx, name, token, out.Keys, keyVersions)
		if e != nil {
			return zero, e
		}
		out.Roles = append(out.Roles, role)
		stamps = append(stamps, role.RoleSHA256, role.PolicySHA256)
	}
	stage = "health_recheck"
	if _, e = o.health(ctx); e != nil {
		return zero, ErrOwner
	}
	encoded, _ := json.Marshal(stamps)
	out.MetadataSHA256 = digest(encoded)
	return out, nil
}

func (o *InstalledVaultDependencyObserver) installedRole(ctx context.Context, name string, token []byte, keys []InstalledVaultKey, versions map[string][]string) (InstalledVaultRole, error) {
	var zero InstalledVaultRole
	raw, e := o.transport.read(ctx, "/v1/auth/"+o.cfg.JWTMount+"/role/"+name, token)
	var role struct {
		Policies []string          `json:"token_policies"`
		Audience []string          `json:"bound_audiences"`
		Claims   map[string]string `json:"bound_claims"`
	}
	if e != nil || json.Unmarshal(raw, &role) != nil || len(role.Policies) != 1 || len(role.Audience) != 1 {
		return zero, ErrOwner
	}
	policyName := role.Policies[0]
	if !safeName.MatchString(policyName) || policyName == "root" || policyName == "default" {
		return zero, ErrOwner
	}
	ns, sa, uid, pod := role.Claims["/kubernetes.io/namespace"], role.Claims["/kubernetes.io/serviceaccount/name"], role.Claims["/kubernetes.io/serviceaccount/uid"], role.Claims["/kubernetes.io/pod/uid"]
	if ns != o.namespace || sa == "" || uid == "" {
		return zero, ErrOwner
	}
	actual, e := o.kube.CoreV1().ServiceAccounts(ns).Get(ctx, sa, metav1.GetOptions{})
	if e != nil || string(actual.UID) != uid || actual.DeletionTimestamp != nil {
		return zero, ErrOwner
	}
	if pod != "" {
		pods, e := o.kube.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if e != nil {
			return zero, ErrOwner
		}
		found := false
		for _, p := range pods.Items {
			found = found || string(p.UID) == pod && p.Spec.ServiceAccountName == sa && p.DeletionTimestamp == nil
		}
		if !found {
			return zero, ErrOwner
		}
	}
	expected, e := a.VaultJWTAuthRole(a.VaultPermissionRole{AuthMount: o.cfg.JWTMount, Role: name, Policy: policyName, Audience: role.Audience[0], Namespace: ns, ServiceAccountName: sa, ServiceAccountUID: uid, PodUID: pod})
	if e != nil || !jsonSubset(raw, expected) {
		return zero, ErrOwner
	}
	policyRaw, e := o.transport.read(ctx, "/v1/sys/policies/acl/"+policyName, token)
	var policy struct{ Name, Policy string }
	if e != nil || json.Unmarshal(policyRaw, &policy) != nil || policy.Name != policyName {
		return zero, ErrOwner
	}
	matched := false
	for _, key := range keys {
		for _, v := range versions[key.Name] {
			if key.Type == "ed25519" {
				want := "path \"" + o.cfg.TransitMount + "/sign/" + key.Name + "\" {\n  capabilities = [\"update\"]\n  required_parameters = [\"input\", \"key_version\"]\n  allowed_parameters = {\n    \"input\" = []\n    \"key_version\" = [\"" + v + "\"]\n  }\n}\n"
				matched = matched || policy.Policy == want
			} else if o.cfg.TransitMount == "transit" && (o.cfg.EvidenceWrap == nil || key.Name != o.cfg.EvidenceWrap.Transit.KeyName) {
				for _, op := range []kms.Operation{kms.Generate, kms.Unwrap} {
					want, e := a.VaultRuntimeACL(op, key.Name, v)
					matched = matched || e == nil && policy.Policy == want
				}
			}
		}
	}
	if o.cfg.EvidenceWrap != nil && installedEvidenceWrapMatches(o.cfg, name, raw, policy.Policy, keys) {
		matched = true
	}
	if !matched {
		return zero, ErrOwner
	}
	canonical, e := canonicalRaw(raw)
	if e != nil {
		return zero, ErrOwner
	}
	return InstalledVaultRole{name, policyName, ns, sa, uid, pod, role.Audience[0], digest([]byte(policy.Policy)), digest(canonical)}, nil
}

func (o *InstalledVaultDependencyObserver) Observe(ctx context.Context) (*ObservedInstalledVaultDependency, error) {
	if o == nil || o.transport == nil || !sameContext(ctx, ctx) || ctx.Err() != nil {
		return nil, ErrOwner
	}
	deadline, bounded := ctx.Deadline()
	if !bounded {
		return nil, ErrOwner
	}
	token, e := o.inputToken()
	if e != nil {
		return nil, ErrOwner
	}
	defer clear(token)
	first, e := o.pass(ctx, token)
	if e != nil {
		return nil, e
	}
	second, e := o.pass(ctx, token)
	if e != nil || !reflect.DeepEqual(first, second) {
		return nil, ErrOwner
	}
	current, e := o.inputToken()
	defer clear(current)
	if e != nil || !bytes.Equal(current, token) || ctx.Err() != nil {
		return nil, ErrOwner
	}
	// Bound the private observation by the native token's remaining lifetime.
	// Do not put a changing TTL in immutable source metadata or extend it to 10s.
	tokenUntil := deadline
	if o.cfg.IdentityMode == "metadata-only" {
		started := time.Now().UTC()
		raw, err := o.transport.read(ctx, "/v1/auth/token/lookup-self", token)
		var identity struct {
			Policies         []string `json:"policies"`
			IdentityPolicies []string `json:"identity_policies"`
			TTL              int64    `json:"ttl"`
		}
		if err != nil || json.Unmarshal(raw, &identity) != nil || !reflect.DeepEqual(identity.Policies, []string{o.cfg.ObserverPolicy}) || len(identity.IdentityPolicies) != 0 || identity.TTL < 1 || identity.TTL > 86400 {
			return nil, ErrOwner
		}
		tokenUntil = started.Add(time.Duration(identity.TTL) * time.Second)
	}
	now := time.Now().UTC()
	p := &ObservedInstalledVaultDependency{owner: o, ctx: ctx, data: first, observed: now, until: minimum(minimum(deadline, tokenUntil), now.Add(10*time.Second))}
	p.origin = p
	if p.Recheck(ctx, now) != nil {
		return nil, ErrOwner
	}
	return p, nil
}
func (p *ObservedInstalledVaultDependency) Recheck(ctx context.Context, now time.Time) error {
	if p == nil || p.origin != p || p.owner == nil || !sameContext(ctx, p.ctx) || ctx.Err() != nil || now.Before(p.observed) || !now.Before(p.until) || !hashPattern.MatchString(p.data.MetadataSHA256) || p.data.ClusterID != p.owner.cfg.ClusterID {
		return ErrOwner
	}
	return nil
}
func (p *ObservedInstalledVaultDependency) Data(ctx context.Context) (InstalledVaultDependencyData, time.Time, error) {
	if p == nil || p.Recheck(ctx, time.Now().UTC()) != nil {
		return InstalledVaultDependencyData{}, time.Time{}, ErrOwner
	}
	raw, _ := json.Marshal(p.data)
	var out InstalledVaultDependencyData
	if json.Unmarshal(raw, &out) != nil {
		return out, time.Time{}, ErrOwner
	}
	return out, p.until, nil
}
