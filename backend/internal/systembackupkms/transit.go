// Package systembackupkms implements the public C backup KEK boundary. It does
// not mint execution authority: every operation requires the original task and
// Job authority supplied by deployment composition.
package systembackupkms

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	w "clawreef/internal/systembackupwire"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

type Operation string

const (
	Generate Operation = "backup_dek_generate"
	Unwrap   Operation = "backup_dek_unwrap"
)

var (
	ErrPermission   = errors.New("permission_denied")
	ErrBinding      = errors.New("binding_mismatch")
	ErrIntegrity    = errors.New("integrity_failed")
	ErrUnavailable  = errors.New("key_unavailable")
	ErrDeadline     = errors.New("deadline_exceeded")
	ErrUnknown      = errors.New("outcome_unknown")
	digest          = regexp.MustCompile(`^[0-9a-f]{64}$`)
	registryVersion = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	decimal         = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	keyName         = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	backupID        = regexp.MustCompile(`^sbk_[A-Za-z0-9_-]+$`)
)

// Access binds a provider operation to one frozen request. Endpoint/key name
// are included so credentials cannot silently be reused against another mount.
type Access struct {
	Request           w.KeyRequest
	Operation         Operation
	Endpoint, KeyName string
}

// Grant is a call-local capability returned by a trusted resolver. Secret is
// exclusively owned. Recheck and WithUse must check the SAME original authority;
// they must not renew it. WithUse serializes final DEK use against original task
// and Job revocation, checks before AND after use, and never retries use.
// A post-use error invalidates the result but cannot undo already observed bytes.
type Grant struct {
	Access               Access
	Secret               []byte
	NotBefore, ExpiresAt time.Time
	// CredentialExpiresAt bounds only the provider RPC. ExpiresAt is the
	// original permission to use the resulting DEK. Zero means the same bound
	// (legacy pinned-token permits); it never means an unbounded token.
	CredentialExpiresAt time.Time
	Recheck             func(context.Context, Access) error
	WithUse             func(context.Context, Access, func() error) error
}

func (Grant) String() string               { return "BackupKEKGrant" }
func (Grant) GoString() string             { return "BackupKEKGrant" }
func (Grant) MarshalJSON() ([]byte, error) { return nil, ErrPermission }

type Resolver interface {
	Resolve(context.Context, Access) (Grant, error)
}

// Config is an admitted exact mapping. Neither it nor Resolver may be created
// from an Admin request. Retained historic keys need independent recovery
// authority and a separate Unwrapper construction; no latest-version fallback.
type Config struct {
	Endpoint, InstallationID, KeyName string
	Key                               w.KeyBinding
	CAPEM                             []byte
	CASHA256                          string
	NotBefore, NotAfter               time.Time
}

type transit struct {
	c        Config
	resolver Resolver
	client   *http.Client
	op       Operation
}

// These types deliberately have disjoint method sets. A capture Job cannot
// type-assert its generator to an unwrapper.
type CaptureGenerator struct{ t *transit }
type RecoveryUnwrapper struct{ t *transit }

func NewCaptureGenerator(c Config, r Resolver) (*CaptureGenerator, error) {
	t, err := newTransit(c, r, Generate)
	if err != nil {
		return nil, err
	}
	return &CaptureGenerator{t}, nil
}
func NewRecoveryUnwrapper(c Config, r Resolver) (*RecoveryUnwrapper, error) {
	t, err := newTransit(c, r, Unwrap)
	if err != nil {
		return nil, err
	}
	return &RecoveryUnwrapper{t}, nil
}
func (g *CaptureGenerator) Close() {
	if g != nil && g.t != nil {
		g.t.client.CloseIdleConnections()
	}
}
func (u *RecoveryUnwrapper) Close() {
	if u != nil && u.t != nil {
		u.t.client.CloseIdleConnections()
	}
}

func newTransit(c Config, r Resolver, op Operation) (*transit, error) {
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.Opaque != "" || strings.ContainsAny(c.Endpoint, "?#\r\n") ||
		!text(c.InstallationID) || !keyName.MatchString(c.KeyName) || !validKey(c.Key) || absent(r) || c.NotBefore.IsZero() || !c.NotAfter.After(c.NotBefore) ||
		len(c.CAPEM) > 65536 || !digest.MatchString(c.CASHA256) || hash(c.CAPEM) != c.CASHA256 {
		return nil, ErrBinding
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(c.CAPEM) {
		return nil, ErrBinding
	}
	c.CAPEM = nil
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 16384, DisableCompression: true}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &transit{c: c, resolver: r, client: client, op: op}, nil
}

func text(s string) bool { return len(s) > 0 && len(s) <= 256 && utf8.ValidString(s) }
func absent(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	}
	return false
}
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func validKey(k w.KeyBinding) bool {
	v, e := strconv.ParseUint(k.ProviderVersion, 10, 32)
	// Registry versions stay opaque, but must name an immutable version under
	// the original typed-reference contract. Matching mutable aliases on both
	// sides of a request is not an exact-version binding.
	exact := registryVersion.MatchString(k.RegistryVersion) && k.RegistryVersion != "latest" && k.RegistryVersion != "current" && k.RegistryVersion != "default"
	return k.Provider == "external-kms" && digest.MatchString(k.IdentityHash) && exact && text(k.ProviderKeyID) && e == nil && v > 0 && strconv.FormatUint(v, 10) == k.ProviderVersion
}
func canonical(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	return canonicalRaw(b)
}

func canonicalRaw(b []byte) ([]byte, error) { return jsoncanonicalizer.Transform(b) }

// TransitContext is the exact C encryption-context JCS/base64, also used by the
// operator policy compiler. It is not an authorization check.
func TransitContext(r w.KeyRequest) (string, error) {
	k, c := r.Key, r.Context
	if !validKey(k) || !backupID.MatchString(c.BackupPublicID) || !decimal.MatchString(c.AttemptNo) || c.AttemptNo == "0" || !decimal.MatchString(c.PartIndex) || !digest.MatchString(c.CaptureContextHash) {
		return "", ErrBinding
	}
	for _, s := range []string{c.InstallationID, c.BackupPublicID, c.AttemptNo, c.Phase, c.Part, c.PartIndex, c.EnvelopeID, c.CaptureContextHash} {
		if !text(s) {
			return "", ErrBinding
		}
	}
	b, e := canonical(map[string]string{"provider": k.Provider, "identity_hash": k.IdentityHash, "registry_version": k.RegistryVersion, "provider_key_id": k.ProviderKeyID, "provider_version": k.ProviderVersion})
	if e != nil {
		return "", ErrBinding
	}
	b, e = canonical(map[string]string{"origin_installation_id": c.InstallationID, "backup_public_id": c.BackupPublicID, "attempt_no": c.AttemptNo, "phase": c.Phase, "part": c.Part, "part_index": c.PartIndex, "envelope_id": c.EnvelopeID, "capture_context_hash": c.CaptureContextHash, "kek_binding_sha256": hash(b)})
	if e != nil {
		return "", ErrBinding
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func validCiphertext(ciphertext []byte, version string) bool {
	prefix := "vault:v" + version + ":"
	if len(ciphertext) != len(prefix)+80 || !bytes.HasPrefix(ciphertext, []byte(prefix)) {
		return false
	}
	b, e := base64.StdEncoding.Strict().DecodeString(string(ciphertext[len(prefix):]))
	defer clear(b)
	return e == nil && len(b) == 60 && base64.StdEncoding.EncodeToString(b) == string(ciphertext[len(prefix):])
}

func (g *CaptureGenerator) Generate(ctx context.Context, r w.KeyRequest, use w.WithDEK) (w.WrappedKey, error) {
	if g == nil || g.t == nil {
		return w.WrappedKey{}, ErrPermission
	}
	return g.t.run(ctx, r, nil, use)
}
func (u *RecoveryUnwrapper) Unwrap(ctx context.Context, r w.KeyRequest, wrapped w.WrappedKey, use w.WithDEK) error {
	if u == nil || u.t == nil {
		return ErrPermission
	}
	if wrapped.Request != r || wrapped.Algorithm != "provider-native" || !validCiphertext(wrapped.Ciphertext, r.Key.ProviderVersion) {
		return ErrBinding
	}
	_, e := u.t.run(ctx, r, bytes.Clone(wrapped.Ciphertext), use)
	return e
}

func (t *transit) run(ctx context.Context, r w.KeyRequest, wrapped []byte, use w.WithDEK) (w.WrappedKey, error) {
	zero := w.WrappedKey{}
	if absent(ctx) || use == nil || ctx.Err() != nil {
		return zero, ErrPermission
	}
	context64, err := TransitContext(r)
	if err != nil || r.Key != t.c.Key || r.Context.InstallationID != t.c.InstallationID {
		return zero, ErrBinding
	}
	access := Access{r, t.op, t.c.Endpoint, t.c.KeyName}
	first := time.Now()
	if first.Before(t.c.NotBefore) || !first.Before(t.c.NotAfter) {
		return zero, ErrPermission
	}
	resolveCtx, resolveCancel := context.WithTimeout(ctx, 15*time.Second)
	grant, err := t.resolver.Resolve(resolveCtx, access)
	resolveCancel()
	defer clear(grant.Secret)
	if err != nil || grant.Access != access || grant.Recheck == nil || grant.WithUse == nil || grant.NotBefore.IsZero() || !grant.ExpiresAt.After(grant.NotBefore) || len(grant.Secret) < 16 || len(grant.Secret) > 4096 {
		return zero, ErrPermission
	}
	for _, b := range grant.Secret {
		if b < 33 || b > 126 {
			return zero, ErrPermission
		}
	}
	until := grant.ExpiresAt
	if t.c.NotAfter.Before(until) {
		until = t.c.NotAfter
	}
	credentialUntil := grant.CredentialExpiresAt
	if credentialUntil.IsZero() || until.Before(credentialUntil) {
		credentialUntil = until
	}
	if !time.Now().Before(credentialUntil) {
		return zero, ErrDeadline
	}
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	floor := first
	check := func() error {
		now := time.Now()
		if ctx.Err() != nil || now.Before(floor) || !now.Before(until) {
			return ErrDeadline
		}
		floor = now
		if now.Before(grant.NotBefore) {
			return ErrPermission
		}
		return nil
	}
	if e := check(); e != nil {
		return zero, e
	}
	if grant.Recheck(ctx, access) != nil {
		return zero, ErrPermission
	}
	if e := check(); e != nil {
		return zero, e
	}
	body := map[string]string{"context": context64}
	path := "datakey/plaintext/"
	if t.op == Generate {
		body["bits"] = "256"
		body["key_version"] = r.Key.ProviderVersion
	} else {
		path = "decrypt/"
		body["ciphertext"] = string(wrapped)
	}
	raw, _ := json.Marshal(body)
	callCtx, callCancel := context.WithTimeout(ctx, 15*time.Second)
	defer callCancel()
	callCtx, credentialCancel := context.WithDeadline(callCtx, credentialUntil)
	defer credentialCancel()
	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, t.c.Endpoint+"/v1/transit/"+path+t.c.KeyName, bytes.NewReader(raw))
	if err != nil {
		return zero, ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", string(grant.Secret))
	defer req.Header.Del("X-Vault-Token")
	response, err := t.client.Do(req)
	if err != nil {
		return zero, ErrUnknown
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusUnauthorized {
		return zero, ErrPermission
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Encoding") != "" {
		return zero, ErrUnknown
	}
	responseRaw, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	defer clear(responseRaw)
	if err != nil || len(responseRaw) > 65536 {
		return zero, ErrUnknown
	}
	if callCtx.Err() != nil || !time.Now().Before(credentialUntil) {
		return zero, ErrUnknown
	}
	// Reject duplicate JSON members before decoding; never let last-member-wins
	// parsing change the authenticated provider version or plaintext.
	root, err := object(responseRaw)
	if err != nil {
		return zero, ErrIntegrity
	}
	defer clearFields(root)
	data, err := object(root["data"])
	if err != nil {
		return zero, ErrIntegrity
	}
	defer clearFields(data)
	var dek []byte
	defer func() { clear(dek) }()
	if json.Unmarshal(data["plaintext"], &dek) != nil || len(dek) != 32 {
		return zero, ErrIntegrity
	}
	encoded, _ := json.Marshal(dek)
	defer clear(encoded)
	if !bytes.Equal(encoded, bytes.TrimSpace(data["plaintext"])) {
		return zero, ErrIntegrity
	}
	result := zero
	if t.op == Generate {
		var ciphertext string
		var version uint32
		if len(data) != 3 || json.Unmarshal(data["ciphertext"], &ciphertext) != nil || json.Unmarshal(data["key_version"], &version) != nil || strconv.FormatUint(uint64(version), 10) != r.Key.ProviderVersion || !validCiphertext([]byte(ciphertext), r.Key.ProviderVersion) {
			return zero, ErrIntegrity
		}
		result = w.WrappedKey{Request: r, Algorithm: "provider-native", Ciphertext: []byte(ciphertext)}
	} else if len(data) != 1 {
		return zero, ErrIntegrity
	}
	if e := check(); e != nil {
		return zero, e
	}
	if grant.Recheck(ctx, access) != nil {
		return zero, ErrPermission
	}
	called := false
	var useErr error
	var repeated bool
	err = grant.WithUse(ctx, access, func() error {
		if called {
			repeated = true
			return ErrPermission
		}
		called = true
		if e := check(); e != nil {
			useErr = e
			return e
		}
		if e := use(dek); e != nil {
			useErr = ErrUnavailable
			return useErr
		}
		useErr = check()
		return useErr
	})
	if err != nil || !called || repeated || useErr != nil {
		if errors.Is(err, ErrUnknown) {
			return zero, ErrUnknown
		}
		return zero, ErrPermission
	}
	if e := check(); e != nil {
		return zero, e
	}
	if grant.Recheck(ctx, access) != nil {
		return zero, ErrPermission
	}
	return result, nil
}

func clearFields(m map[string]json.RawMessage) {
	for _, v := range m {
		clear(v)
	}
}
func object(raw []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	token, e := d.Token()
	if e != nil || token != json.Delim('{') {
		return nil, ErrIntegrity
	}
	m := map[string]json.RawMessage{}
	fail := func() (map[string]json.RawMessage, error) { clearFields(m); return nil, ErrIntegrity }
	for d.More() {
		token, e = d.Token()
		if e != nil {
			return fail()
		}
		k, ok := token.(string)
		if !ok {
			return fail()
		}
		if _, ok = m[k]; ok {
			return fail()
		}
		var v json.RawMessage
		if d.Decode(&v) != nil {
			return fail()
		}
		m[k] = v
	}
	if token, e = d.Token(); e != nil || token != json.Delim('}') {
		return fail()
	}
	if d.Decode(new(any)) != io.EOF {
		return fail()
	}
	return m, nil
}
