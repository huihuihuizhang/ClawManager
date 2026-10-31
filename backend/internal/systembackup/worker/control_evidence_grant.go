package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	k "clawreef/internal/systembackupkms"
)

const ControlEvidenceSourceGrantVersion = "system-backup-control-evidence-source-grant.v1"
const ControlEvidenceSourceGrantDomain = "system-backup-original-control-evidence-source.v1\x00"

// Independent source owner, distinct from KEK Generate issuer. No future
// task/attempt/Job/Pod/hash or worker SQL credential is required in this grant.
type ControlEvidenceSourceGrant struct {
	Version                 string    `json:"schema_version"`
	InstallationID          string    `json:"installation_id"`
	ConfigSHA256            string    `json:"config_sha256"`
	WorkerNamespace         string    `json:"worker_namespace"`
	WorkerServiceAccountUID string    `json:"worker_service_account_uid"`
	Operation               string    `json:"operation"`
	ScopeSHA256             string    `json:"scope_sha256"`
	NotBefore               time.Time `json:"not_before"`
	Until                   time.Time `json:"until"`
	Revoked                 bool      `json:"revoked"`
}
type SignedControlEvidenceSourceGrant struct {
	Record    []byte `json:"record"`
	Signature []byte `json:"signature"`
}
type ControlEvidenceSourceMount struct {
	Endpoint            string            `json:"endpoint"`
	GrantFile           string            `json:"grant_file"`
	ControllerGrantFile string            `json:"controller_grant_file,omitempty"`
	GrantSHA256         string            `json:"grant_sha256"`
	Issuer              ed25519.PublicKey `json:"issuer"`
}

func (m ControlEvidenceSourceMount) Validate() error {
	u, err := url.Parse(m.Endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.RawPath != "" || u.Fragment != "" || strings.ContainsAny(m.Endpoint, "?#\r\n") || u.Opaque != "" || u.Path != "" && u.Path != "/" || !filepath.IsAbs(m.GrantFile) || filepath.Clean(m.GrantFile) != m.GrantFile || m.ControllerGrantFile != "" && (!filepath.IsAbs(m.ControllerGrantFile) || filepath.Clean(m.ControllerGrantFile) != m.ControllerGrantFile) || !keyUseHash.MatchString(m.GrantSHA256) || len(m.Issuer) != ed25519.PublicKeySize {
		return ErrNotReady
	}
	return nil
}

// Scope excludes future task/attempt/cutoff/ref hashes. The original live
// task/Job/current nonce and exact registry/config mapping remain mandatory at
// the mTLS source pull; this static grant can never select arbitrary evidence.
func ControlEvidenceSourceScopeSHA256(expected ce.Expected, endpoint string) (string, error) {
	raw, err := ce.Canonical(struct {
		Version, Installation, ConfigSHA256, SourceIdentitySHA256, Endpoint string
		SchemaRegistry, RedactionRegistry                                   ce.RegistryPin
	}{"system-backup-control-evidence-source-scope.v1", expected.Installation, expected.ConfigSHA256, expected.SourceIdentitySHA256, endpoint, expected.SchemaRegistry, expected.RedactionRegistry})
	if err != nil {
		return "", ErrNotReady
	}
	return ce.SHA256(raw), nil
}

type ControlEvidenceCaptureSources struct {
	invocation    Invocation
	invocationSHA string
	job           *CaptureKeyJob
	mount         ControlEvidenceSourceMount
	grant         ControlEvidenceSourceGrant
	scopeSHA      string
	until         time.Time
	closed        atomic.Bool
}

func OpenControlEvidenceCaptureSources(ctx context.Context, i Invocation, job *CaptureKeyJob, mount *ControlEvidenceSourceMount) (*ControlEvidenceCaptureSources, error) {
	if ctx == nil || ctx.Err() != nil || mount == nil || mount.Validate() != nil || !validControlEvidenceRequest(i.Request) || i.ProviderKey == nil || i.FormalCapture == nil || i.FormalCapture.PermitDelivery == nil || job == nil || job.original == nil || job.original.client == nil || job.original.client.endpoint != mount.Endpoint || bytes.Equal(mount.Issuer, i.FormalCapture.PermitDelivery.Issuer) || i.FormalCapture.SourceConfigSHA256 != i.Request.ControlEvidence.Expected.ConfigSHA256 {
		return nil, ErrNotReady
	}
	raw, err := json.Marshal(i)
	var frozen Invocation
	if err != nil || json.Unmarshal(raw, &frozen) != nil {
		return nil, ErrNotReady
	}
	invHash, err := frozen.Hash()
	if err != nil || invHash != job.original.lease.Identity.InvocationSHA256 {
		return nil, ErrNotReady
	}
	scopeSHA, err := ControlEvidenceSourceScopeSHA256(frozen.Request.ControlEvidence.Expected, mount.Endpoint)
	if err != nil {
		return nil, err
	}
	copyMount := *mount
	copyMount.Issuer = bytes.Clone(mount.Issuer)
	out := &ControlEvidenceCaptureSources{invocation: frozen, invocationSHA: invHash, job: job, mount: copyMount, scopeSHA: scopeSHA, until: job.until}
	grant, err := out.readGrant(ctx, false)
	if err != nil {
		return nil, err
	}
	out.grant = grant
	for _, bound := range []time.Time{grant.Until, frozen.Request.Deadline} {
		if bound.Before(out.until) {
			out.until = bound
		}
	}
	if out.Authorize(ctx, frozen) != nil {
		return nil, ErrNotReady
	}
	return out, nil
}
func (s *ControlEvidenceCaptureSources) ValidUntil() time.Time {
	if s == nil || s.closed.Load() {
		return time.Time{}
	}
	return s.until
}
func (s *ControlEvidenceCaptureSources) Close() {
	if s != nil {
		s.closed.Store(true)
	}
}

func (s *ControlEvidenceCaptureSources) readGrant(ctx context.Context, bound bool) (ControlEvidenceSourceGrant, error) {
	var zero ControlEvidenceSourceGrant
	if s == nil || s.closed.Load() || ctx == nil || ctx.Err() != nil || s.job == nil || s.job.original == nil || !time.Now().Before(s.until) {
		return zero, ErrNotReady
	}
	grant, err := ReadControlEvidenceSourceGrant(ctx, s.mount, s.invocation.Request.ControlEvidence.Expected, s.job.original.Identity(), false)
	if err != nil || bound && grant != s.grant {
		return zero, ErrNotReady
	}
	return grant, nil
}

// The server repeats the SAME independent source-owner signature/scope/actor
// checks from its separately projected controller path. Voluntary worker-side
// validation or KEK Generate permission alone cannot release source bodies.
func ReadControlEvidenceSourceGrant(ctx context.Context, mount ControlEvidenceSourceMount, expected ce.Expected, identity k.JobIdentity, controller bool) (ControlEvidenceSourceGrant, error) {
	var zero ControlEvidenceSourceGrant
	if ctx == nil || ctx.Err() != nil || mount.Validate() != nil {
		return zero, ErrNotReady
	}
	path := mount.GrantFile
	if controller {
		path = mount.ControllerGrantFile
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return zero, ErrNotReady
		}
	}
	scopeSHA, err := ControlEvidenceSourceScopeSHA256(expected, mount.Endpoint)
	if err != nil {
		return zero, err
	}
	raw, err := readPinnedSourceFile(path, mount.GrantSHA256, 65536, false)
	if err != nil {
		return zero, err
	}
	defer clear(raw)
	var signed SignedControlEvidenceSourceGrant
	if !uniqueFormalJSON(raw) || decodeBounded(bytes.NewReader(raw), &signed, 65536) != nil || len(signed.Record) > 32768 || !ed25519.Verify(mount.Issuer, append([]byte(ControlEvidenceSourceGrantDomain), signed.Record...), signed.Signature) {
		return zero, ErrNotReady
	}
	var grant ControlEvidenceSourceGrant
	now := time.Now()
	if !uniqueFormalJSON(signed.Record) || decodeBounded(bytes.NewReader(signed.Record), &grant, 32768) != nil || grant.Version != ControlEvidenceSourceGrantVersion || grant.InstallationID != expected.Installation || grant.ConfigSHA256 != expected.ConfigSHA256 || grant.WorkerNamespace != identity.Namespace || grant.WorkerServiceAccountUID != identity.ServiceAccountUID || grant.Operation != ce.Operation || grant.ScopeSHA256 != scopeSHA || grant.Revoked || grant.NotBefore.IsZero() || !grant.Until.After(grant.NotBefore) || grant.Until.Sub(grant.NotBefore) > 24*time.Hour || now.Before(grant.NotBefore) || !now.Before(grant.Until) {
		return zero, ErrNotReady
	}
	return grant, nil
}

// Bounded local-only source checks are safe from inside the original DEK
// callback; the real job/key-use RPC is performed separately by the C sink and
// ControlEvidenceSource pull, without recursively locking its authority.
func (s *ControlEvidenceCaptureSources) Authorize(ctx context.Context, i Invocation) error {
	if s == nil || s.closed.Load() || ctx == nil || ctx.Err() != nil || !time.Now().Before(s.until) {
		return ErrNotReady
	}
	hash, err := i.Hash()
	if err != nil || hash != s.invocationSHA || s.job.original.failed {
		return ErrNotReady
	}
	_, err = s.readGrant(ctx, true)
	return err
}
func (s *ControlEvidenceCaptureSources) Read(ctx context.Context, i Invocation) (ce.PreparedSource, error) {
	if s.Authorize(ctx, i) != nil {
		return ce.PreparedSource{}, ErrNotReady
	}
	ctx, cancel := context.WithDeadline(ctx, s.until)
	defer cancel()
	out, err := s.job.ControlEvidenceSource(ctx)
	if err != nil {
		return ce.PreparedSource{}, err
	}
	if s.Authorize(ctx, i) != nil || ctx.Err() != nil {
		clear(out.SidecarJSON)
		clear(out.ProofsJSON)
		return ce.PreparedSource{}, ErrNotReady
	}
	return out, nil
}
