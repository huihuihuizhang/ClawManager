package systembackupinstallationowner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	a "clawreef/internal/systembackupkekadapter"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Constructor-fixed deployment input. Tokens/paths are not supplied by Record.
type SigningObserverConfig struct {
	Endpoint, CASHA256, ObserverPolicy, ObserverTokenFile, ObserverTokenSHA256, RuntimeJWTFile string
	CAPEM                                                                                      []byte
	Trust                                                                                      a.VaultJWTTrust
	Kubernetes                                                                                 kubernetes.Interface
}
type CaptureSigningObserver struct {
	cfg    SigningObserverConfig
	client *http.Client
}
type signingObservation struct {
	owner           *CaptureSigningObserver
	recordHash      string
	observed, until time.Time
	probeSignature  []byte
}

func (*CaptureSigningObserver) MarshalJSON() ([]byte, error) { return nil, ErrOwner }
func (*signingObservation) MarshalJSON() ([]byte, error)     { return nil, ErrOwner }
func NewCaptureSigningObserver(cfg SigningObserverConfig) (*CaptureSigningObserver, error) {
	u, e := url.Parse(cfg.Endpoint)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || !safeName.MatchString(cfg.ObserverPolicy) || strings.EqualFold(cfg.ObserverPolicy, "root") || strings.EqualFold(cfg.ObserverPolicy, "default") || !hashPattern.MatchString(cfg.ObserverTokenSHA256) || nilInterface(cfg.Kubernetes) || len(cfg.CAPEM) == 0 || len(cfg.CAPEM) > 65536 || digest(cfg.CAPEM) != cfg.CASHA256 {
		return nil, ErrOwner
	}
	for _, p := range []string{cfg.ObserverTokenFile, cfg.RuntimeJWTFile} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return nil, ErrOwner
		}
	}
	if cfg.ObserverTokenFile == cfg.RuntimeJWTFile {
		return nil, ErrOwner
	}
	if _, e := a.VaultJWTAuthConfig(cfg.Trust); e != nil {
		return nil, ErrOwner
	}
	cfg.CAPEM = bytes.Clone(cfg.CAPEM)
	cfg.Trust.ValidationPublicKeys = append([]string(nil), cfg.Trust.ValidationPublicKeys...)
	cfg.Trust.Algorithms = append([]string(nil), cfg.Trust.Algorithms...)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cfg.CAPEM) {
		return nil, ErrOwner
	}
	tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16384, DisableCompression: true}
	return &CaptureSigningObserver{cfg: cfg, client: &http.Client{Transport: tr, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (o *CaptureSigningObserver) Close() {
	if o != nil && o.client != nil {
		o.client.CloseIdleConnections()
	}
}
func privateToken(path string) ([]byte, error) {
	st, e := os.Stat(path)
	if e != nil || !st.Mode().IsRegular() || (runtime.GOOS == "linux" && st.Mode().Perm()&0077 != 0) {
		return nil, ErrOwner
	}
	b, e := localFile(path, 16384)
	if e != nil || len(b) < 16 {
		clear(b)
		return nil, ErrOwner
	}
	for _, c := range b {
		if c < 33 || c > 126 {
			clear(b)
			return nil, ErrOwner
		}
	}
	return b, nil
}
func (o *CaptureSigningObserver) request(ctx context.Context, method, path string, token, body []byte) ([]byte, error) {
	if ctx.Err() != nil || !strings.HasPrefix(path, "/v1/") || strings.ContainsAny(path, "?#\r\n") {
		return nil, ErrOwner
	}
	req, e := http.NewRequestWithContext(ctx, method, o.cfg.Endpoint+path, bytes.NewReader(body))
	if e != nil {
		return nil, ErrOwner
	}
	if len(token) > 0 {
		req.Header.Set("X-Vault-Token", string(token))
		defer req.Header.Del("X-Vault-Token")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, e := o.client.Do(req)
	if e != nil {
		return nil, ErrOwner
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Encoding") != "" {
		return nil, ErrOwner
	}
	raw, e := io.ReadAll(io.LimitReader(resp.Body, 1048577))
	if e != nil || len(raw) > 1048576 || ctx.Err() != nil {
		clear(raw)
		return nil, ErrOwner
	}
	if !utf8JSON(raw) {
		clear(raw)
		return nil, ErrOwner
	}
	return raw, nil
}
func utf8JSON(raw []byte) bool { _, e := canonicalRaw(raw); return e == nil }
func canonicalRaw(raw []byte) ([]byte, error) {
	var v any
	if len(raw) == 0 || len(raw) > 1048576 {
		return nil, ErrOwner
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&v) != nil || d.Decode(new(any)) != io.EOF {
		return nil, ErrOwner
	}
	c, e := jsoncanonical(raw)
	if e != nil {
		return nil, ErrOwner
	}
	return c, nil
}
func dataEnvelope(raw []byte) (json.RawMessage, error) {
	var v struct {
		Data   json.RawMessage   `json:"data"`
		Errors []json.RawMessage `json:"errors"`
		Wrap   json.RawMessage   `json:"wrap_info"`
	}
	if json.Unmarshal(raw, &v) != nil || len(v.Data) == 0 || bytes.Equal(v.Data, []byte("null")) || len(v.Errors) != 0 || len(v.Wrap) > 0 && !bytes.Equal(v.Wrap, []byte("null")) {
		return nil, ErrOwner
	}
	return v.Data, nil
}

func requiredFields(raw []byte, names ...string) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	for _, name := range names {
		v, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return false
		}
	}
	return true
}
func (o *CaptureSigningObserver) read(ctx context.Context, path string, token []byte) (json.RawMessage, error) {
	raw, e := o.request(ctx, "GET", path, token, nil)
	if e != nil {
		return nil, e
	}
	defer clear(raw)
	data, e := dataEnvelope(raw)
	return bytes.Clone(data), e
}
func equalJSON(a, b []byte) bool {
	// The JCS library's top-level entry accepts only objects/arrays. A role
	// field can be a scalar, so compare each complete JSON value inside an
	// identical single-element array, retaining duplicate/UTF-8 rejection.
	canonicalElement := func(raw []byte) ([]byte, error) {
		if len(raw) == 0 || len(raw) > 1048574 || !json.Valid(raw) {
			return nil, ErrOwner
		}
		wrapped := make([]byte, 0, len(raw)+2)
		wrapped = append(wrapped, '[')
		wrapped = append(wrapped, raw...)
		wrapped = append(wrapped, ']')
		return canonicalRaw(wrapped)
	}
	x, e := canonicalElement(a)
	y, f := canonicalElement(b)
	return e == nil && f == nil && bytes.Equal(x, y)
}
func jsonSubset(actual, expected []byte) bool {
	var got, want map[string]json.RawMessage
	if !utf8JSON(actual) || json.Unmarshal(actual, &got) != nil || json.Unmarshal(expected, &want) != nil {
		return false
	}
	for k, v := range want {
		for name := range got {
			if name != k && strings.EqualFold(name, k) {
				return false
			}
		}
		if !equalJSON(got[k], v) {
			return false
		}
	}
	return true
}
func CaptureSigningACL(b Binding) (string, error) {
	if !safeName.MatchString(b.TransitMount) || !safeName.MatchString(b.KeyName) || !numericVersion(b.ProviderVersion) {
		return "", ErrOwner
	}
	return "path \"" + b.TransitMount + "/sign/" + b.KeyName + "\" {\n  capabilities = [\"update\"]\n  required_parameters = [\"input\", \"key_version\"]\n  allowed_parameters = {\n    \"input\" = []\n    \"key_version\" = [\"" + b.ProviderVersion + "\"]\n  }\n}\n", nil
}
func CaptureSigningObserverACL(r Record, observerPolicy string) (string, error) {
	if !safeName.MatchString(observerPolicy) || observerPolicy == r.Binding.Policy || strings.EqualFold(observerPolicy, "root") || strings.EqualFold(observerPolicy, "default") {
		return "", ErrOwner
	}
	b := r.Binding
	for _, name := range []string{b.TransitMount, b.AuthMount, b.Role, b.Policy} {
		if !safeName.MatchString(name) || strings.EqualFold(name, "root") || strings.EqualFold(name, "default") {
			return "", ErrOwner
		}
	}
	if len(r.Histories) != 3 {
		return "", ErrOwner
	}
	seen := map[string]bool{}
	for _, h := range r.Histories {
		if !safeName.MatchString(h.KeyName) || seen[h.KeyName] {
			return "", ErrOwner
		}
		seen[h.KeyName] = true
	}
	paths := []string{"auth/token/lookup-self", "sys/policies/acl/" + observerPolicy, "sys/policies/acl/" + b.Policy, "auth/" + b.AuthMount + "/role/" + b.Role, "auth/" + b.AuthMount + "/config"}
	for _, h := range r.Histories {
		paths = append(paths, b.TransitMount+"/keys/"+h.KeyName)
	}
	sort.Strings(paths)
	var out strings.Builder
	for _, p := range paths {
		out.WriteString("path \"" + p + "\" { capabilities = [\"read\"] }\n")
	}
	return out.String(), nil
}
func (o *CaptureSigningObserver) identity(ctx context.Context, b Binding, clusterID string, jwt []byte) error {
	// v1 Kubernetes cluster identity is the independently pinned kube-system
	// namespace UID, separate from Vault's /sys/health cluster_id.
	cluster, e := o.cfg.Kubernetes.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
	if e != nil || string(cluster.UID) != clusterID || cluster.DeletionTimestamp != nil {
		return ErrOwner
	}
	ns, e := o.cfg.Kubernetes.CoreV1().Namespaces().Get(ctx, b.Namespace, metav1.GetOptions{})
	if e != nil || string(ns.UID) != b.NamespaceUID || ns.DeletionTimestamp != nil {
		return ErrOwner
	}
	pod, e := o.cfg.Kubernetes.CoreV1().Pods(b.Namespace).Get(ctx, b.PodName, metav1.GetOptions{})
	if e != nil || string(pod.UID) != b.PodUID || pod.DeletionTimestamp != nil || pod.Status.Phase != "Running" || pod.Spec.ServiceAccountName != b.ServiceAccountName {
		return ErrOwner
	}
	sa, e := o.cfg.Kubernetes.CoreV1().ServiceAccounts(b.Namespace).Get(ctx, b.ServiceAccountName, metav1.GetOptions{})
	if e != nil || string(sa.UID) != b.ServiceAccountUID || sa.DeletionTimestamp != nil {
		return ErrOwner
	}
	review, e := o.cfg.Kubernetes.AuthenticationV1().TokenReviews().Create(ctx, &authenticationv1.TokenReview{Spec: authenticationv1.TokenReviewSpec{Token: string(jwt), Audiences: []string{b.Audience}}}, metav1.CreateOptions{})
	if e != nil || !review.Status.Authenticated || review.Status.Error != "" || review.Status.User.Username != "system:serviceaccount:"+b.Namespace+":"+b.ServiceAccountName || review.Status.User.UID != b.ServiceAccountUID || len(review.Status.Audiences) != 1 || review.Status.Audiences[0] != b.Audience {
		return ErrOwner
	}
	ids := review.Status.User.Extra["authentication.kubernetes.io/pod-uid"]
	if len(ids) != 1 || ids[0] != b.PodUID {
		return ErrOwner
	}
	return nil
}
func (o *CaptureSigningObserver) metadata(ctx context.Context, aRecord *AuthenticatedRecord, token []byte) ([]byte, error) {
	r, b := aRecord.record, aRecord.record.Binding
	raw, e := o.read(ctx, "/v1/auth/token/lookup-self", token)
	if e != nil {
		return nil, e
	}
	var self struct {
		Policies, IdentityPolicies []string
		TTL                        int64
	}
	var selfWire struct {
		Policies         []string `json:"policies"`
		IdentityPolicies []string `json:"identity_policies"`
		TTL              int64    `json:"ttl"`
	}
	if json.Unmarshal(raw, &selfWire) != nil {
		return nil, ErrOwner
	}
	self.Policies, self.IdentityPolicies, self.TTL = selfWire.Policies, selfWire.IdentityPolicies, selfWire.TTL
	if len(self.Policies) != 1 || self.Policies[0] != o.cfg.ObserverPolicy || len(self.IdentityPolicies) != 0 || self.TTL < 1 {
		return nil, ErrOwner
	}
	expectedObserver, e := CaptureSigningObserverACL(r, o.cfg.ObserverPolicy)
	if e != nil {
		return nil, e
	}
	var stamp []json.RawMessage
	for _, entry := range []struct{ name, expected string }{{o.cfg.ObserverPolicy, expectedObserver}, {b.Policy, ""}} {
		v, e := o.read(ctx, "/v1/sys/policies/acl/"+entry.name, token)
		if e != nil {
			return nil, e
		}
		var p struct{ Name, Policy string }
		if json.Unmarshal(v, &p) != nil || p.Name != entry.name {
			return nil, ErrOwner
		}
		expected := entry.expected
		if expected == "" {
			expected, _ = CaptureSigningACL(b)
			if digest([]byte(p.Policy)) != b.PolicySHA256 {
				return nil, ErrOwner
			}
		}
		if p.Policy != expected {
			return nil, ErrOwner
		}
		stamp = append(stamp, v)
	}
	role, e := o.read(ctx, "/v1/auth/"+b.AuthMount+"/role/"+b.Role, token)
	if e != nil {
		return nil, e
	}
	roleCanonical, e := canonicalRaw(role)
	if e != nil || digest(roleCanonical) != b.RoleSHA256 {
		return nil, ErrOwner
	}
	expectedRole, e := a.VaultJWTAuthRole(a.VaultPermissionRole{AuthMount: b.AuthMount, Role: b.Role, Policy: b.Policy, Audience: b.Audience, Namespace: b.Namespace, ServiceAccountName: b.ServiceAccountName, ServiceAccountUID: b.ServiceAccountUID, PodUID: b.PodUID})
	if e != nil || !jsonSubset(role, expectedRole) {
		return nil, ErrOwner
	}
	stamp = append(stamp, role)
	trust, e := o.read(ctx, "/v1/auth/"+b.AuthMount+"/config", token)
	if e != nil {
		return nil, e
	}
	tc, e := canonicalRaw(trust)
	wanted, e2 := a.VaultJWTAuthConfig(o.cfg.Trust)
	if e != nil || e2 != nil || digest(tc) != b.JWTConfigSHA256 || !jsonSubset(trust, wanted) {
		return nil, ErrOwner
	}
	stamp = append(stamp, trust)
	for _, history := range r.Histories {
		meta, e := o.read(ctx, "/v1/"+b.TransitMount+"/keys/"+history.KeyName, token)
		if e != nil {
			return nil, e
		}
		var key struct {
			Type                 string `json:"type"`
			SupportsSigning      bool   `json:"supports_signing"`
			Derived, Exportable  bool
			AllowPlaintextBackup bool `json:"allow_plaintext_backup"`
			DeletionAllowed      bool `json:"deletion_allowed"`
			Keys                 map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		}
		if !requiredFields(meta, "type", "supports_signing", "derived", "exportable", "allow_plaintext_backup", "deletion_allowed", "keys") || json.Unmarshal(meta, &key) != nil || key.Type != "ed25519" || !key.SupportsSigning || key.Derived || key.Exportable || key.AllowPlaintextBackup || key.DeletionAllowed || len(key.Keys) != len(history.Keys) {
			return nil, ErrOwner
		}
		for _, k := range history.Keys {
			if key.Keys[k.Version].PublicKey != k.PublicKey {
				return nil, ErrOwner
			}
		}
		stamp = append(stamp, meta)
	}
	return canonical(stamp)
}
func (o *CaptureSigningObserver) observe(ctx context.Context, aRecord *AuthenticatedRecord) (*signingObservation, error) {
	if o == nil || o.client == nil || nilInterface(o.cfg.Kubernetes) || aRecord == nil || !sameContext(ctx, ctx) || ctx.Err() != nil {
		return nil, ErrOwner
	}
	r, b := aRecord.record, aRecord.record.Binding
	now := time.Now().UTC()
	limit := minimum(r.Until, r.Probe.Until)
	if now.Before(r.NotBefore) || !now.Before(limit) || b.Endpoint != o.cfg.Endpoint || b.CASHA256 != o.cfg.CASHA256 || b.Policy == o.cfg.ObserverPolicy {
		return nil, ErrOwner
	}
	active, cancel := context.WithDeadline(ctx, limit)
	defer cancel()
	// Health is unauthenticated but covered by the exact TLS endpoint/CA pin.
	health, e := o.request(active, "GET", "/v1/sys/health", nil, nil)
	if e != nil {
		return nil, e
	}
	var state struct {
		ClusterID           string `json:"cluster_id"`
		Initialized, Sealed bool
	}
	if !requiredFields(health, "cluster_id", "initialized", "sealed") || json.Unmarshal(health, &state) != nil || !state.Initialized || state.Sealed || state.ClusterID != b.ProviderClusterID {
		return nil, ErrOwner
	}
	token, e := privateToken(o.cfg.ObserverTokenFile)
	if e != nil {
		return nil, e
	}
	defer clear(token)
	if digest(token) != o.cfg.ObserverTokenSHA256 {
		return nil, ErrOwner
	}
	first, e := o.metadata(active, aRecord, token)
	if e != nil {
		return nil, e
	}
	jwt, e := privateToken(o.cfg.RuntimeJWTFile)
	if e != nil {
		return nil, e
	}
	defer clear(jwt)
	jwtHash := sha256.Sum256(jwt)
	if o.identity(active, b, r.Target.ClusterID, jwt) != nil {
		return nil, ErrOwner
	}
	body, _ := json.Marshal(map[string]string{"role": b.Role, "jwt": string(jwt)})
	defer clear(body)
	started := time.Now()
	login, e := o.request(active, "POST", "/v1/auth/"+b.AuthMount+"/login", nil, body)
	if e != nil {
		return nil, e
	}
	defer clear(login)
	var loginFields map[string]json.RawMessage
	if json.Unmarshal(login, &loginFields) != nil || !requiredFields(login, "auth") {
		return nil, ErrOwner
	}
	if v := bytes.TrimSpace(loginFields["errors"]); len(v) > 0 && !bytes.Equal(v, []byte("[]")) && !bytes.Equal(v, []byte("null")) {
		return nil, ErrOwner
	}
	if v := bytes.TrimSpace(loginFields["wrap_info"]); len(v) > 0 && !bytes.Equal(v, []byte("null")) {
		return nil, ErrOwner
	}
	if !requiredFields(loginFields["auth"], "client_token", "token_type", "renewable", "lease_duration", "policies", "token_policies", "metadata") {
		return nil, ErrOwner
	}
	var response struct {
		Auth struct {
			ClientToken      string `json:"client_token"`
			TokenType        string `json:"token_type"`
			Renewable        bool
			LeaseDuration    int64 `json:"lease_duration"`
			Policies         []string
			TokenPolicies    []string `json:"token_policies"`
			IdentityPolicies []string `json:"identity_policies"`
			Metadata         map[string]string
		}
	}
	if json.Unmarshal(login, &response) != nil {
		return nil, ErrOwner
	}
	credential := []byte(response.Auth.ClientToken)
	defer clear(credential)
	auth := response.Auth
	if len(credential) < 16 || auth.TokenType != "batch" || auth.Renewable || auth.LeaseDuration < 1 || auth.LeaseDuration > 10 || len(auth.Policies) != 1 || auth.Policies[0] != b.Policy || len(auth.TokenPolicies) != 1 || auth.TokenPolicies[0] != b.Policy || len(auth.IdentityPolicies) != 0 || auth.Metadata["role"] != b.Role || auth.Metadata["namespace"] != b.Namespace || auth.Metadata["pod_uid"] != b.PodUID || auth.Metadata["service_account_uid"] != b.ServiceAccountUID {
		return nil, ErrOwner
	}
	probe, e := canonical(struct {
		SchemaVersion, RecordSHA256, InstallationID, GrantID, Purpose, Challenge string
		Until                                                                    time.Time
	}{ProbeVersion, aRecord.pin.RecordSHA256, r.Target.InstallationID, r.GrantID, b.Purpose, r.Probe.Challenge, r.Probe.Until})
	if e != nil {
		return nil, e
	}
	input := append([]byte(ProbeDomain), probe...)
	request, _ := json.Marshal(map[string]string{"input": base64.StdEncoding.EncodeToString(input), "key_version": b.ProviderVersion})
	defer clear(request)
	signing, cancelSign := context.WithDeadline(active, started.Add(time.Duration(auth.LeaseDuration)*time.Second))
	defer cancelSign()
	signed, e := o.request(signing, "POST", "/v1/"+b.TransitMount+"/sign/"+b.KeyName, credential, request)
	if e != nil {
		return nil, e
	}
	data, e := dataEnvelope(signed)
	if e != nil {
		return nil, e
	}
	var signature struct{ Signature string }
	if json.Unmarshal(data, &signature) != nil {
		return nil, ErrOwner
	}
	prefix := "vault:v" + b.ProviderVersion + ":"
	if !strings.HasPrefix(signature.Signature, prefix) {
		return nil, ErrOwner
	}
	sig, e := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(signature.Signature, prefix))
	if e != nil || len(sig) != 64 {
		return nil, ErrOwner
	}
	var pub []byte
	for _, h := range r.Histories {
		if h.Purpose == b.Purpose {
			for _, k := range h.Keys {
				if k.Version == b.ProviderVersion {
					pub, _ = publicBytes(k.PublicKey)
				}
			}
		}
	}
	if len(pub) != 32 || !ed25519.Verify(pub, input, sig) || signing.Err() != nil {
		return nil, ErrOwner
	}
	current, e := privateToken(o.cfg.RuntimeJWTFile)
	defer clear(current)
	if e != nil || sha256.Sum256(current) != jwtHash || o.identity(active, b, r.Target.ClusterID, current) != nil {
		return nil, ErrOwner
	}
	second, e := o.metadata(active, aRecord, token)
	if e != nil || !bytes.Equal(first, second) || active.Err() != nil {
		return nil, ErrOwner
	}
	currentToken, e := privateToken(o.cfg.ObserverTokenFile)
	defer clear(currentToken)
	if e != nil || digest(currentToken) != o.cfg.ObserverTokenSHA256 {
		return nil, ErrOwner
	}
	observed := time.Now().UTC().Truncate(time.Microsecond)
	end := minimum(limit, observed.Add(time.Minute))
	if !observed.Before(end) {
		return nil, ErrOwner
	}
	return &signingObservation{o, aRecord.pin.RecordSHA256, observed, end, bytes.Clone(sig)}, nil
}
