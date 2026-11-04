package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	ev "clawreef/internal/systembackupevidence"
	owner "clawreef/internal/systembackupinstallationowner"
	a "clawreef/internal/systembackupkekadapter"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	authn "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Private transport only, not an authentication handle. Its caller retains
// original Installer/enrollment authority before every provider mutation.
type originalPublicationVault struct {
	client   *http.Client
	endpoint string
}

func newOriginalPublicationVault(endpoint string, ca []byte, sha string) (*originalPublicationVault, error) {
	c, e := originalArchiveTLSClient(ev.TransitConfig{Endpoint: endpoint, CAPEM: ca, CASHA256: sha})
	if e != nil {
		return nil, ErrInstall
	}
	return &originalPublicationVault{c, endpoint}, nil
}
func (v *originalPublicationVault) close() {
	if v != nil {
		v.client.CloseIdleConnections()
	}
}
func (v *originalPublicationVault) call(ctx context.Context, method, path string, token, body []byte) ([]byte, int, error) {
	if v == nil || ctx == nil || ctx.Err() != nil || !strings.HasPrefix(path, "/v1/") || strings.ContainsAny(path, "?#\\\r\n") {
		return nil, 0, ErrInstall
	}
	req, e := http.NewRequestWithContext(ctx, method, v.endpoint+path, bytes.NewReader(body))
	if e != nil {
		return nil, 0, ErrInstall
	}
	req.Header.Set("Content-Type", "application/json")
	if len(token) > 0 {
		req.Header.Set("X-Vault-Token", string(token))
	}
	res, e := v.client.Do(req)
	if e != nil {
		return nil, 0, ErrInstall
	}
	defer res.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(res.Body, 262145))
	if e != nil || len(raw) > 262144 {
		return nil, res.StatusCode, ErrInstall
	}
	if res.StatusCode == 404 {
		clear(raw)
		return nil, 404, nil
	}
	if res.StatusCode != 200 && res.StatusCode != 204 {
		clear(raw)
		return nil, res.StatusCode, ErrInstall
	}
	if res.StatusCode == 200 {
		root, objectErr := originalArchiveObject(raw)
		if objectErr != nil {
			clear(raw)
			return nil, res.StatusCode, ErrInstall
		}
		for _, field := range []string{"errors", "wrap_info"} {
			if value, ok := root[field]; ok && !bytes.Equal(bytes.TrimSpace(value), []byte("null")) && !(field == "errors" && bytes.Equal(bytes.TrimSpace(value), []byte("[]"))) {
				clear(raw)
				return nil, res.StatusCode, ErrInstall
			}
		}
		checked, e := jsoncanonicalizer.Transform(raw)
		clear(checked)
		if e != nil {
			clear(raw)
			return nil, res.StatusCode, ErrInstall
		}
	}
	return raw, res.StatusCode, nil
}
func (v *originalPublicationVault) data(ctx context.Context, path string, token []byte) ([]byte, error) {
	raw, status, e := v.call(ctx, "GET", path, token, nil)
	defer clear(raw)
	var envelope struct{ Data json.RawMessage }
	if e != nil || status != 200 || json.Unmarshal(raw, &envelope) != nil || len(envelope.Data) == 0 || !originalPublicationFields(raw, "data") {
		return nil, ErrInstall
	}
	return bytes.Clone(envelope.Data), nil
}
func originalPublicationSubset(actual, wanted []byte) bool {
	var got, want any
	if json.Unmarshal(actual, &got) != nil || json.Unmarshal(wanted, &want) != nil {
		return false
	}
	var contains func(any, any) bool
	contains = func(g, w any) bool {
		if wm, ok := w.(map[string]any); ok {
			gm, ok := g.(map[string]any)
			if !ok {
				return false
			}
			for k, x := range wm {
				y, ok := gm[k]
				if !ok || !contains(y, x) {
					return false
				}
			}
			return true
		}
		return reflect.DeepEqual(g, w)
	}
	return contains(got, want)
}
func originalPublicationObjectCanonical(raw []byte) ([]byte, error) {
	var x any
	if json.Unmarshal(raw, &x) != nil {
		return nil, ErrInstall
	}
	return canonical(x)
}
func (v *originalPublicationVault) health(ctx context.Context, cluster string) error {
	raw, status, e := v.call(ctx, "GET", "/v1/sys/health", nil, nil)
	var x struct {
		ClusterID           string `json:"cluster_id"`
		Initialized, Sealed bool
	}
	if e != nil || status != 200 || !originalPublicationFields(raw, "cluster_id", "initialized", "sealed") || json.Unmarshal(raw, &x) != nil || !x.Initialized || x.Sealed || x.ClusterID != cluster {
		return ErrInstall
	}
	return nil
}
func originalPublicationToken(raw []byte) ([]byte, error) {
	t := bytes.TrimSpace(raw)
	if len(t) < 16 || len(t) > 16384 {
		return nil, ErrInstall
	}
	for _, b := range t {
		if b < 33 || b > 126 {
			return nil, ErrInstall
		}
	}
	return bytes.Clone(t), nil
}

// Only the already-retained native Vault initialization file or exact token
// file is accepted, both independently pinned. Nothing is printed/exported.
func originalPublicationOwnerToken(pin BootstrapSourceFilePin, initJSON bool) ([]byte, error) {
	raw, e := readBootstrapSourcePin(pin, 262144)
	if e != nil {
		return nil, ErrInstall
	}
	defer clear(raw)
	if !initJSON {
		return originalPublicationToken(raw)
	}
	if _, e := jsoncanonicalizer.Transform(raw); e != nil {
		return nil, ErrInstall
	}
	var x struct {
		RootToken string `json:"root_token"`
	}
	if json.Unmarshal(raw, &x) != nil {
		return nil, ErrInstall
	}
	return originalPublicationToken([]byte(x.RootToken))
}
func (v *originalPublicationVault) root(ctx context.Context, token []byte) error {
	raw, e := v.data(ctx, "/v1/auth/token/lookup-self", token)
	defer clear(raw)
	var x struct {
		Policies         []string
		IdentityPolicies []string `json:"identity_policies"`
		Type             string
	}
	if e != nil || json.Unmarshal(raw, &x) != nil || !reflect.DeepEqual(x.Policies, []string{"root"}) || len(x.IdentityPolicies) != 0 || x.Type != "service" {
		return ErrInstall
	}
	return nil
}

// Existing exact role/policy may be reused only byte-for-byte. A foreign or
// expanded role/policy is never overwritten. Unknown writes remain inspectable.
func (v *originalPublicationVault) policy(ctx context.Context, name, policy string, token []byte, auth func() error) error {
	raw, status, e := v.call(ctx, "GET", "/v1/sys/policies/acl/"+name, token, nil)
	if e != nil {
		return ErrInstall
	}
	if status == 404 {
		body, _ := json.Marshal(map[string]string{"policy": policy})
		if auth() != nil {
			return ErrInstall
		}
		if _, _, e = v.call(ctx, "PUT", "/v1/sys/policies/acl/"+name, token, body); e != nil {
			return ErrInstall
		}
	}
	actual, e := v.data(ctx, "/v1/sys/policies/acl/"+name, token)
	var p struct{ Name, Policy string }
	if e != nil || json.Unmarshal(actual, &p) != nil || p.Name != name || p.Policy != policy {
		return ErrInstall
	}
	_ = raw
	return nil
}
func (v *originalPublicationVault) role(ctx context.Context, mount, name string, wanted, token []byte, auth func() error) ([]byte, error) {
	raw, status, e := v.call(ctx, "GET", "/v1/auth/"+mount+"/role/"+name, token, nil)
	if e != nil {
		return nil, ErrInstall
	}
	if status == 404 {
		if auth() != nil {
			return nil, ErrInstall
		}
		if _, _, e = v.call(ctx, "POST", "/v1/auth/"+mount+"/role/"+name, token, wanted); e != nil {
			return nil, ErrInstall
		}
	}
	actual, e := v.data(ctx, "/v1/auth/"+mount+"/role/"+name, token)
	if e != nil || !originalPublicationSubset(actual, wanted) {
		return nil, ErrInstall
	}
	_ = raw
	return originalPublicationObjectCanonical(actual)
}
func (v *originalPublicationVault) observerToken(ctx context.Context, policy string, root []byte, auth func() error) ([]byte, error) {
	body, _ := json.Marshal(map[string]any{"policies": []string{policy}, "no_default_policy": true, "renewable": false, "ttl": "600s", "explicit_max_ttl": "600s", "type": "service"})
	if auth() != nil {
		return nil, ErrInstall
	}
	raw, _, e := v.call(ctx, "POST", "/v1/auth/token/create", root, body)
	defer clear(raw)
	var x struct {
		Auth struct {
			ClientToken      string `json:"client_token"`
			Policies         []string
			IdentityPolicies []string `json:"identity_policies"`
			Renewable        bool
			LeaseDuration    int64 `json:"lease_duration"`
		}
	}
	if e != nil || json.Unmarshal(raw, &x) != nil || x.Auth.Renewable || x.Auth.LeaseDuration < 1 || x.Auth.LeaseDuration > 600 || !reflect.DeepEqual(x.Auth.Policies, []string{policy}) || len(x.Auth.IdentityPolicies) != 0 {
		return nil, ErrInstall
	}
	return originalPublicationToken([]byte(x.Auth.ClientToken))
}
func (v *originalPublicationVault) key(ctx context.Context, mount, name string, token []byte) (ed25519.PublicKey, error) {
	raw, e := v.data(ctx, "/v1/"+mount+"/keys/"+name, token)
	var k struct {
		Type                 string
		SupportsSigning      bool `json:"supports_signing"`
		Derived, Exportable  bool
		AllowPlaintextBackup bool `json:"allow_plaintext_backup"`
		DeletionAllowed      bool `json:"deletion_allowed"`
		LatestVersion        int  `json:"latest_version"`
		Keys                 map[string]struct {
			PublicKey string `json:"public_key"`
		}
	}
	if e != nil || !originalPublicationFields(raw, "type", "supports_signing", "derived", "exportable", "allow_plaintext_backup", "deletion_allowed", "latest_version", "keys") || json.Unmarshal(raw, &k) != nil || k.Type != "ed25519" || !k.SupportsSigning || k.Derived || k.Exportable || k.AllowPlaintextBackup || k.DeletionAllowed || k.LatestVersion != 1 || len(k.Keys) != 1 {
		return nil, ErrInstall
	}
	pub, e := base64.StdEncoding.Strict().DecodeString(k.Keys["1"].PublicKey)
	if e != nil || len(pub) != 32 {
		return nil, ErrInstall
	}
	return pub, nil
}

// Real purpose-specific TokenReview -> JWT login -> exact-version challenge
// signature. This is an installation probe domain, never an artifact/task.
func (i *Installer) originalPublicationProbe(ctx context.Context, v *originalPublicationVault, b owner.Binding, pub ed25519.PublicKey, jwt []byte) (time.Time, error) {
	tr, e := i.kube.AuthenticationV1().TokenReviews().Create(ctx, &authn.TokenReview{Spec: authn.TokenReviewSpec{Token: string(jwt), Audiences: []string{b.Audience}}}, metav1.CreateOptions{})
	if e != nil || !tr.Status.Authenticated || tr.Status.Error != "" || tr.Status.User.Username != "system:serviceaccount:"+b.Namespace+":"+b.ServiceAccountName || tr.Status.User.UID != b.ServiceAccountUID || !reflect.DeepEqual(tr.Status.Audiences, []string{b.Audience}) || !reflect.DeepEqual([]string(tr.Status.User.Extra["authentication.kubernetes.io/pod-uid"]), []string{b.PodUID}) {
		return time.Time{}, ErrInstall
	}
	body, _ := json.Marshal(map[string]string{"role": b.Role, "jwt": string(jwt)})
	defer clear(body)
	started := time.Now().UTC()
	raw, _, e := v.call(ctx, "POST", "/v1/auth/"+b.AuthMount+"/login", nil, body)
	defer clear(raw)
	// Explicit tags avoid ever accepting a missing token_type as a default.
	var login struct {
		Auth struct {
			Token            string `json:"client_token"`
			Type             string `json:"token_type"`
			Renewable        bool
			TTL              int64 `json:"lease_duration"`
			Policies         []string
			TokenPolicies    []string `json:"token_policies"`
			IdentityPolicies []string `json:"identity_policies"`
			Metadata         map[string]string
		}
	}
	if e != nil || json.Unmarshal(raw, &login) != nil {
		return time.Time{}, ErrInstall
	}
	authBody, authErr := originalArchiveObject(raw)
	if authErr != nil || !originalPublicationFields(authBody["auth"], "client_token", "token_type", "renewable", "lease_duration", "policies", "token_policies", "identity_policies", "metadata") {
		return time.Time{}, ErrInstall
	}
	a := login.Auth
	if a.Type != "batch" || a.Renewable || a.TTL < 1 || a.TTL > 10 || !reflect.DeepEqual(a.Policies, []string{b.Policy}) || !reflect.DeepEqual(a.TokenPolicies, []string{b.Policy}) || len(a.IdentityPolicies) != 0 || a.Metadata["role"] != b.Role || a.Metadata["namespace"] != b.Namespace || a.Metadata["pod_uid"] != b.PodUID || a.Metadata["service_account_uid"] != b.ServiceAccountUID {
		return time.Time{}, ErrInstall
	}
	token, e := originalPublicationToken([]byte(a.Token))
	if e != nil {
		return time.Time{}, ErrInstall
	}
	defer clear(token)
	until := started.Add(time.Duration(a.TTL) * time.Second)
	probeCtx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	var nonce [32]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return time.Time{}, ErrInstall
	}
	payload, e := canonical(struct {
		Version, PlanSHA256, Purpose, PodUID string
		Challenge                            []byte
	}{"original-publication-installation-probe.v1", i.planHash, b.Purpose, b.PodUID, nonce[:]})
	if e != nil {
		return time.Time{}, ErrInstall
	}
	message := append([]byte("system-backup-original-publication-installation-probe.v1\x00"), payload...)
	input, _ := json.Marshal(map[string]string{"input": base64.StdEncoding.EncodeToString(message), "key_version": b.ProviderVersion})
	signed, _, e := v.call(probeCtx, "POST", "/v1/"+b.TransitMount+"/sign/"+b.KeyName, token, input)
	var result struct{ Data struct{ Signature string } }
	if e != nil || json.Unmarshal(signed, &result) != nil || !strings.HasPrefix(result.Data.Signature, "vault:v"+b.ProviderVersion+":") {
		return time.Time{}, ErrInstall
	}
	sig, e := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(result.Data.Signature, "vault:v"+b.ProviderVersion+":"))
	if e != nil || !ed25519.Verify(pub, message, sig) || probeCtx.Err() != nil {
		return time.Time{}, ErrInstall
	}
	return until, nil
}
func originalPublicationRole(b owner.Binding) ([]byte, error) {
	return a.VaultJWTAuthRole(a.VaultPermissionRole{AuthMount: b.AuthMount, Role: b.Role, Policy: b.Policy, Audience: b.Audience, Namespace: b.Namespace, ServiceAccountName: b.ServiceAccountName, ServiceAccountUID: b.ServiceAccountUID, PodUID: b.PodUID})
}

func originalPublicationCheckMetadata(ctx context.Context, v *originalPublicationVault, b owner.Binding, h owner.PurposeKeys, token []byte) error {
	p, e := v.data(ctx, "/v1/sys/policies/acl/"+b.Policy, token)
	var policy struct{ Name, Policy string }
	acl, ae := owner.CaptureSigningACL(b)
	if e != nil || ae != nil || json.Unmarshal(p, &policy) != nil || policy.Name != b.Policy || policy.Policy != acl || hash([]byte(policy.Policy)) != b.PolicySHA256 {
		return ErrInstall
	}
	r, e := v.data(ctx, "/v1/auth/"+b.AuthMount+"/role/"+b.Role, token)
	wanted, we := originalPublicationRole(b)
	rc, re := originalPublicationObjectCanonical(r)
	if e != nil || we != nil || re != nil || !originalPublicationSubset(r, wanted) || hash(rc) != b.RoleSHA256 {
		return ErrInstall
	}
	t, e := v.data(ctx, "/v1/auth/"+b.AuthMount+"/config", token)
	tc, te := originalPublicationObjectCanonical(t)
	if e != nil || te != nil || hash(tc) != b.JWTConfigSHA256 {
		return ErrInstall
	}
	pub, e := v.key(ctx, b.TransitMount, b.KeyName, token)
	if e != nil || h.Purpose != b.Purpose || h.KeyName != b.KeyName || len(h.Keys) != 1 || h.Keys[0].Version != b.ProviderVersion || h.Keys[0].PublicKey != base64.StdEncoding.EncodeToString(pub) {
		return ErrInstall
	}
	return nil
}

func originalPublicationFields(raw []byte, names ...string) bool {
	object, e := originalArchiveObject(raw)
	if e != nil {
		return false
	}
	for _, n := range names {
		value, ok := object[n]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	return true
}

func originalPublicationName(name string) bool {
	if len(name) < 1 || len(name) > 128 {
		return false
	}
	switch strings.ToLower(name) {
	case "root", "default", "latest", "current":
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
