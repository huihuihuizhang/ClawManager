package systembackupinstallationowner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// Reuses only the existing TLS/request/Kubernetes identity mechanisms. It
// neither constructs an AuthenticatedRecord nor borrows capture authorization.
type SigningResourceObserver struct{ transport *CaptureSigningObserver }
type ObservedSigningResource struct {
	owner            *SigningResourceObserver
	ctx              context.Context
	grantSHA256      string
	runtimeJWTSHA256 string
	observed, until  time.Time
	signature        []byte
}

func (*SigningResourceObserver) MarshalJSON() ([]byte, error) { return nil, ErrOwner }
func (*ObservedSigningResource) MarshalJSON() ([]byte, error) { return nil, ErrOwner }

// Detached timing DATA for the authenticated installer's final SQL-window
// check. This cannot construct a consumer guard or extend the observation.
func (o *ObservedSigningResource) Window() (time.Time, time.Time, error) {
	if o == nil || o.owner == nil || !sameContext(o.ctx, o.ctx) || !hashPattern.MatchString(o.grantSHA256) || len(o.signature) != 64 || !validTime(o.observed) || !validTime(o.until) || !o.until.After(o.observed) || o.until.Sub(o.observed) > 30*time.Second {
		return time.Time{}, time.Time{}, ErrOwner
	}
	return o.observed, o.until, nil
}
func NewSigningResourceObserver(cfg SigningObserverConfig) (*SigningResourceObserver, error) {
	cfg.CAPEM = bytes.Clone(cfg.CAPEM)
	cfg.Trust.ValidationPublicKeys = append([]string(nil), cfg.Trust.ValidationPublicKeys...)
	cfg.Trust.Algorithms = append([]string(nil), cfg.Trust.Algorithms...)
	t, e := NewCaptureSigningObserver(cfg)
	if e != nil {
		return nil, ErrOwner
	}
	return &SigningResourceObserver{transport: t}, nil
}
func (o *SigningResourceObserver) Close() {
	if o != nil && o.transport != nil {
		o.transport.Close()
	}
}

func (o *SigningResourceObserver) health(ctx context.Context, b Binding) error {
	raw, e := o.transport.request(ctx, "GET", "/v1/sys/health", nil, nil)
	var state struct {
		ClusterID           string `json:"cluster_id"`
		Initialized, Sealed bool
	}
	if e != nil || !requiredFields(raw, "cluster_id", "initialized", "sealed") || json.Unmarshal(raw, &state) != nil || !state.Initialized || state.Sealed || state.ClusterID != b.ProviderClusterID {
		return ErrOwner
	}
	return nil
}

// Runs outside SQL. Success is a private, short observation of an actual
// purpose-specific JWT login + Transit signature, never a business receipt.
// The observation begins BEFORE any provider/API work and cannot be renewed
// by the later final read. It confers no SQL admission on its own.
func (o *SigningResourceObserver) ObserveSigningResource(ctx context.Context, raw, sig []byte, pin SigningResourceTrustPin) (*ObservedSigningResource, error) {
	if o == nil || o.transport == nil || !sameContext(ctx, ctx) || ctx.Err() != nil {
		return nil, ErrOwner
	}
	r, e := InspectSigningResourceGrant(raw, sig, pin)
	if e != nil {
		return nil, ErrOwner
	}
	b, t := r.Binding, o.transport
	started := time.Now().UTC().Truncate(time.Microsecond)
	limit := minimum(r.Until, started.Add(30*time.Second))
	if end, ok := ctx.Deadline(); ok {
		limit = minimum(limit, end.UTC().Truncate(time.Microsecond))
	}
	if started.Before(r.NotBefore) || !started.Before(limit) || b.Endpoint != t.cfg.Endpoint || b.CASHA256 != t.cfg.CASHA256 {
		return nil, ErrOwner
	}
	active, cancel := context.WithDeadline(ctx, limit)
	defer cancel()
	if o.health(active, b) != nil {
		return nil, ErrOwner
	}
	token, e := privateToken(t.cfg.ObserverTokenFile)
	if e != nil {
		return nil, ErrOwner
	}
	defer clear(token)
	if digest(token) != t.cfg.ObserverTokenSHA256 {
		return nil, ErrOwner
	}
	first, observerEnd, e := o.metadata(active, r, token)
	if e != nil {
		return nil, ErrOwner
	}
	limit = minimum(limit, observerEnd.UTC().Truncate(time.Microsecond))
	jwt, e := privateToken(t.cfg.RuntimeJWTFile)
	if e != nil {
		return nil, ErrOwner
	}
	defer clear(jwt)
	jwtSHA := digest(jwt)
	if t.identity(active, b, r.Target.ClusterID, jwt) != nil {
		return nil, ErrOwner
	}
	body, _ := json.Marshal(map[string]string{"role": b.Role, "jwt": string(jwt)})
	defer clear(body)
	loginStarted := time.Now().UTC()
	login, e := t.request(active, "POST", "/v1/auth/"+b.AuthMount+"/login", nil, body)
	if e != nil {
		return nil, ErrOwner
	}
	defer clear(login)
	var fields map[string]json.RawMessage
	if json.Unmarshal(login, &fields) != nil || !requiredFields(login, "auth") {
		return nil, ErrOwner
	}
	if v := bytes.TrimSpace(fields["errors"]); len(v) > 0 && !bytes.Equal(v, []byte("[]")) && !bytes.Equal(v, []byte("null")) {
		return nil, ErrOwner
	}
	if v := bytes.TrimSpace(fields["wrap_info"]); len(v) > 0 && !bytes.Equal(v, []byte("null")) {
		return nil, ErrOwner
	}
	if !requiredFields(fields["auth"], "client_token", "token_type", "renewable", "lease_duration", "policies", "token_policies", "identity_policies", "metadata") {
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
	a := response.Auth
	credential := []byte(a.ClientToken)
	defer clear(credential)
	if len(credential) < 16 || len(credential) > 16384 || a.TokenType != "batch" || a.Renewable || a.LeaseDuration < 1 || a.LeaseDuration > 10 || len(a.Policies) != 1 || a.Policies[0] != b.Policy || len(a.TokenPolicies) != 1 || a.TokenPolicies[0] != b.Policy || len(a.IdentityPolicies) != 0 || a.Metadata["role"] != b.Role || a.Metadata["namespace"] != b.Namespace || a.Metadata["pod_uid"] != b.PodUID || a.Metadata["service_account_uid"] != b.ServiceAccountUID {
		return nil, ErrOwner
	}
	for _, c := range credential {
		if c < 33 || c > 126 {
			return nil, ErrOwner
		}
	}
	limit = minimum(limit, loginStarted.Add(time.Duration(a.LeaseDuration)*time.Second).UTC().Truncate(time.Microsecond))
	var challenge [32]byte
	if _, e := rand.Read(challenge[:]); e != nil {
		return nil, ErrOwner
	}
	probe, e := canonical(struct {
		SchemaVersion, GrantSHA256, AuthorityID, GrantID, Purpose, Challenge string
		Target                                                               Target
		ReferenceIdentitySHA256, ReferenceVersion                            string
		Until                                                                time.Time
	}{SigningResourceProbeVersion, pin.GrantSHA256, r.AuthorityID, r.GrantID, b.Purpose, hex.EncodeToString(challenge[:]), r.Target, r.Reference.IdentityHash, r.Reference.Version, limit})
	if e != nil || !time.Now().UTC().Before(limit) {
		return nil, ErrOwner
	}
	message := append([]byte(SigningResourceProbeDomain), probe...)
	version, _ := strconv.ParseUint(b.ProviderVersion, 10, 32)
	request, _ := json.Marshal(map[string]any{"input": base64.StdEncoding.EncodeToString(message), "key_version": version})
	defer clear(request)
	signing, cancelSign := context.WithDeadline(active, limit)
	defer cancelSign()
	signed, e := t.request(signing, "POST", "/v1/"+b.TransitMount+"/sign/"+b.KeyName, credential, request)
	if e != nil {
		return nil, ErrOwner
	}
	data, e := dataEnvelope(signed)
	var signature struct{ Signature string }
	if e != nil || !requiredFields(data, "signature") || json.Unmarshal(data, &signature) != nil {
		return nil, ErrOwner
	}
	prefix := "vault:v" + b.ProviderVersion + ":"
	if !strings.HasPrefix(signature.Signature, prefix) {
		return nil, ErrOwner
	}
	proof, e := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(signature.Signature, prefix))
	if e != nil || len(proof) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(proof) != strings.TrimPrefix(signature.Signature, prefix) {
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
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, message, proof) || signing.Err() != nil {
		return nil, ErrOwner
	}
	current, e := privateToken(t.cfg.RuntimeJWTFile)
	defer clear(current)
	if e != nil || digest(current) != jwtSHA || t.identity(signing, b, r.Target.ClusterID, current) != nil {
		return nil, ErrOwner
	}
	second, secondEnd, e := o.metadata(signing, r, token)
	if e != nil || !bytes.Equal(first, second) || o.health(signing, b) != nil {
		return nil, ErrOwner
	}
	limit = minimum(limit, secondEnd.UTC().Truncate(time.Microsecond))
	currentToken, e := privateToken(t.cfg.ObserverTokenFile)
	defer clear(currentToken)
	if e != nil || digest(currentToken) != t.cfg.ObserverTokenSHA256 || signing.Err() != nil || !time.Now().UTC().Before(limit) {
		return nil, ErrOwner
	}
	return &ObservedSigningResource{owner: o, ctx: ctx, grantSHA256: pin.GrantSHA256, runtimeJWTSHA256: jwtSHA, observed: started, until: limit, signature: bytes.Clone(proof)}, nil
}

func (o *ObservedSigningResource) pinsCurrent() bool {
	if o == nil || o.owner == nil || o.owner.transport == nil || !hashPattern.MatchString(o.runtimeJWTSHA256) {
		return false
	}
	cfg := o.owner.transport.cfg
	jwt, e := privateToken(cfg.RuntimeJWTFile)
	defer clear(jwt)
	if e != nil || digest(jwt) != o.runtimeJWTSHA256 {
		return false
	}
	token, e := privateToken(cfg.ObserverTokenFile)
	defer clear(token)
	return e == nil && digest(token) == cfg.ObserverTokenSHA256
}
