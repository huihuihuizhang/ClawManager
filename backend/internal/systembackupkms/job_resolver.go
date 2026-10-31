package systembackupkms

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// JobIdentity is obtained from the existing mTLS + TokenReview + original Job
// journal checks, never from DownwardAPI fields or a request DTO alone.
type JobIdentity struct {
	Namespace            string `json:"namespace"`
	PodUID               string `json:"pod_uid"`
	ServiceAccountUID    string `json:"service_account_uid"`
	JobUID               string `json:"job_uid"`
	InvocationSHA256     string `json:"invocation_sha256"`
	ExecutionGrantSHA256 string `json:"execution_grant_sha256"`
}

// OriginalJobAuthority is a reference to the EXISTING execution authorization.
// Recheck verifies the original task/attempt/config/fence/Job/workload and the
// complete frozen provider request. WithUse invokes use synchronously IN THE
// ORIGINAL JOB, within either its shared local revocation lock or a persisted
// original-Job use window. A remote window requires reserve/begin/end, fixed
// original expiry, no replay, and real StopJob/Stopped before revocation is
// complete. A detached check followed by an unrecorded callback is insufficient.
type OriginalJobAuthority interface {
	Identity() JobIdentity
	ValidUntil() time.Time
	Recheck(context.Context, Access) error
	WithUse(context.Context, Access, func() error) error
}

// ProviderPermit supplements original execution authority; it cannot authorize
// a task by itself. One signed permit admits one operation, exact frozen context
// and immutable credential reference. It is independently pinned on deployment.
type ProviderPermit struct {
	Version          string           `json:"schema_version"`
	Identity         JobIdentity      `json:"identity"`
	Operation        Operation        `json:"operation"`
	Endpoint         string           `json:"endpoint"`
	KeyName          string           `json:"key_name"`
	ContextBase64    string           `json:"context_base64"`
	NotBefore        time.Time        `json:"not_before"`
	ExpiresAt        time.Time        `json:"expires_at"`
	CredentialRef    string           `json:"credential_ref"`
	CredentialSHA256 string           `json:"credential_sha256"`
	JWT              JWTIdentityGrant `json:"jwt"`
}

// JWTIdentityGrant pins the reviewed login role/policy and projected identity
// path. Role admission must bind issuer, audience, namespace, SA UID and Pod UID
// to Identity above. Token parsing locally is NOT authentication: the pinned
// provider authenticates it, and OriginalJobAuthority still checks live work.
type JWTIdentityGrant struct {
	Mount        string `json:"mount"`
	Role         string `json:"role"`
	Policy       string `json:"policy"`
	IdentityFile string `json:"identity_file"`
}

type PermitMount struct {
	PermitPath, PermitSHA256, CredentialDirectory string
	PublicKey                                     ed25519.PublicKey
}

type PinnedJobResolver struct {
	mount     PermitMount
	original  OriginalJobAuthority
	identity  JobIdentity
	until     time.Time
	config    *Config
	delivered *deliveredPermitState
}

// NewJobResolver additionally admits projected-JWT exchange on the exact
// pinned TLS provider. Static-file permits remain available with their original
// short window; they are never used as a fallback when JWT exchange fails.
func NewJobResolver(c Config, m PermitMount, original OriginalJobAuthority) (*PinnedJobResolver, error) {
	r, e := NewPinnedJobResolver(m, original)
	if e != nil {
		return nil, e
	}
	t, e := newTransit(c, r, Generate)
	if e != nil {
		return nil, e
	}
	t.client.CloseIdleConnections()
	c.CAPEM = bytes.Clone(c.CAPEM)
	r.config = &c
	return r, nil
}

func NewPinnedJobResolver(m PermitMount, original OriginalJobAuthority) (*PinnedJobResolver, error) {
	if !filepath.IsAbs(m.PermitPath) || !filepath.IsAbs(m.CredentialDirectory) || !digest.MatchString(m.PermitSHA256) || len(m.PublicKey) != ed25519.PublicKeySize || absent(original) {
		return nil, ErrPermission
	}
	i := original.Identity()
	until := original.ValidUntil()
	if !text(i.Namespace) || !text(i.PodUID) || !text(i.ServiceAccountUID) || !text(i.JobUID) || !digest.MatchString(i.InvocationSHA256) || !digest.MatchString(i.ExecutionGrantSHA256) || until.IsZero() {
		return nil, ErrPermission
	}
	m.PublicKey = bytes.Clone(m.PublicKey)
	return &PinnedJobResolver{mount: m, original: original, identity: i, until: until}, nil
}

// readControlled follows Kubernetes projected-volume atomic symlinks. The mount
// is trusted composition, while exact pins detect replaced bytes at every use.
func readControlled(path string, max int64, private bool) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, ErrPermission
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || s.Size() > max || (private && runtime.GOOS == "linux" && s.Mode().Perm()&0077 != 0) {
		return nil, ErrPermission
	}
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(b)) > max {
		clear(b)
		return nil, ErrPermission
	}
	return b, nil
}

func closedJSON(raw []byte, out any) error {
	// Canonicalization rejects duplicate members throughout nested objects.
	if _, e := canonicalRaw(raw); e != nil {
		return ErrPermission
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrPermission
	}
	return nil
}

func (r *PinnedJobResolver) permit(ctx context.Context, a Access) (ProviderPermit, error) {
	var p ProviderPermit
	if r == nil || absent(ctx) || ctx.Err() != nil || r.original.Identity() != r.identity || !r.original.ValidUntil().Equal(r.until) || !time.Now().Before(r.until) {
		return p, ErrPermission
	}
	if r.delivered != nil {
		p, e := r.deliveredPermit(ctx, a)
		if e != nil {
			return ProviderPermit{}, ErrPermission
		}
		return r.validatePermit(a, p)
	}
	b, e := readControlled(r.mount.PermitPath, 65536, false)
	if e != nil {
		return p, ErrPermission
	}
	defer clear(b)
	var envelope struct {
		Payload   string `json:"payload_base64"`
		Signature string `json:"signature_base64"`
	}
	if hash(b) != r.mount.PermitSHA256 || closedJSON(b, &envelope) != nil {
		return p, ErrPermission
	}
	payload, e := base64.StdEncoding.Strict().DecodeString(envelope.Payload)
	defer clear(payload)
	if e != nil {
		return p, ErrPermission
	}
	sig, e := base64.StdEncoding.Strict().DecodeString(envelope.Signature)
	if e != nil || !ed25519.Verify(r.mount.PublicKey, payload, sig) || closedJSON(payload, &p) != nil {
		return ProviderPermit{}, ErrPermission
	}
	return r.validatePermit(a, p)
}

func (r *PinnedJobResolver) validatePermit(a Access, p ProviderPermit) (ProviderPermit, error) {
	c, e := TransitContext(a.Request)
	now := time.Now()
	if e != nil || p.Version != "system-backup-provider-permit.v1" || p.Identity != r.identity || p.Operation != a.Operation || (a.Operation != Generate && a.Operation != Unwrap) || p.Endpoint != a.Endpoint || p.KeyName != a.KeyName || p.ContextBase64 != c || p.NotBefore.IsZero() || !p.ExpiresAt.After(p.NotBefore) || now.Before(p.NotBefore) || !now.Before(p.ExpiresAt) || p.ExpiresAt.After(r.until) {
		return ProviderPermit{}, ErrPermission
	}
	if p.JWT != (JWTIdentityGrant{}) {
		if r.config == nil || now.Before(r.config.NotBefore) || !now.Before(r.config.NotAfter) || p.ExpiresAt.After(r.config.NotAfter) || a.Endpoint != r.config.Endpoint || a.KeyName != r.config.KeyName || a.Request.Key != r.config.Key || a.Request.Context.InstallationID != r.config.InstallationID ||
			p.CredentialRef != "" || p.CredentialSHA256 != "" || !keyName.MatchString(p.JWT.Mount) || !keyName.MatchString(p.JWT.Role) || !keyName.MatchString(p.JWT.Policy) || !filepath.IsAbs(p.JWT.IdentityFile) || p.ExpiresAt.Sub(p.NotBefore) > 24*time.Hour {
			return ProviderPermit{}, ErrPermission
		}
	} else if !keyName.MatchString(p.CredentialRef) || !digest.MatchString(p.CredentialSHA256) || p.ExpiresAt.Sub(p.NotBefore) > 20*time.Second {
		return ProviderPermit{}, ErrPermission
	}
	return p, nil
}

func (r *PinnedJobResolver) credentialCurrent(p ProviderPermit) error {
	if p.JWT != (JWTIdentityGrant{}) {
		return nil
	} // JWT is authenticated at login, never reparsed as a local grant.
	secret, e := readControlled(filepath.Join(r.mount.CredentialDirectory, p.CredentialRef), 4096, true)
	defer clear(secret)
	if e != nil || hash(secret) != p.CredentialSHA256 {
		return ErrPermission
	}
	return nil
}

func (r *PinnedJobResolver) Resolve(ctx context.Context, a Access) (Grant, error) {
	p, e := r.permit(ctx, a)
	if e != nil {
		return Grant{}, ErrPermission
	}
	if r.original.Recheck(ctx, a) != nil {
		return Grant{}, ErrPermission
	}
	var token []byte
	credentialUntil := p.ExpiresAt
	if p.JWT != (JWTIdentityGrant{}) {
		token, credentialUntil, e = r.exchangeJWT(ctx, p, a)
	} else {
		token, e = readControlled(filepath.Join(r.mount.CredentialDirectory, p.CredentialRef), 4096, true)
		if e == nil && hash(token) != p.CredentialSHA256 {
			e = ErrPermission
		}
	}
	if e != nil {
		clear(token)
		return Grant{}, ErrPermission
	}
	check := func(c context.Context, b Access) error {
		if b != a {
			return ErrPermission
		}
		current, e := r.permit(c, a)
		if e != nil || current != p {
			return ErrPermission
		}
		if r.credentialCurrent(p) != nil {
			return ErrPermission
		}
		return r.original.Recheck(c, a)
	}
	if check(ctx, a) != nil {
		clear(token)
		return Grant{}, ErrPermission
	}
	return Grant{Access: a, Secret: token, NotBefore: p.NotBefore, ExpiresAt: p.ExpiresAt, CredentialExpiresAt: credentialUntil, Recheck: check, WithUse: func(c context.Context, b Access, use func() error) error {
		if b != a || use == nil {
			return ErrPermission
		}
		// Original authority owns locking. Avoid recursively acquiring its SQL
		// guard from inside this callback; only the provider permit is rechecked.
		return r.original.WithUse(c, a, func() error {
			current, e := r.permit(c, a)
			if e != nil || current != p {
				return ErrPermission
			}
			if r.credentialCurrent(p) != nil {
				return ErrPermission
			}
			if e = use(); e != nil {
				return e
			}
			current, e = r.permit(c, a)
			if e != nil || current != p {
				return ErrPermission
			}
			return nil
		})
	}}, nil
}
