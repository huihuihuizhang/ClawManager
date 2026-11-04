package systembackupevidence

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"

	pd "clawreef/internal/systembackupproducer"
	"github.com/minio/minio-go/v7/pkg/signer"
)

type originalC1ChannelScope struct {
	scope S3Scope
	until time.Time
}

type originalC1ChannelProfile struct {
	mu        sync.Mutex
	gateway   *OriginalC1OwnerChannel
	ctx       context.Context
	execution *pd.Execution
	handle    *pd.ExecutionHandle
	claim     *pd.PublicationClaim
	policy    SystemSTSPolicy
	original  systemPublicationOriginal
	transport *S3STSCredentials
	snapshots [2]*pd.CallSnapshot
	until     time.Time
	scopes    []originalC1ChannelScope
	probed    map[string]bool
	version   string
	failed    bool
}

// NewProfileVerifier cannot register a caller's scope DTO. It requires the
// actual service-local original ExecutionHandle, PublicationClaim and Prepared,
// and independently starts both original guarded SDK authorization snapshots.
// Retain it (and the owner channel) through the original Result final guard.
func (g *OriginalC1OwnerChannel) NewProfileVerifier(ctx context.Context, e *pd.Execution, h *pd.ExecutionHandle, claim *pd.PublicationClaim, prepared Prepared, policy SystemSTSPolicy) (SystemSTSProfileVerifier, S3AbsenceVerifier, error) {
	if g == nil || e == nil || h == nil || claim == nil || ctx == nil || ctx.Err() != nil || g.ctx.Err() != nil {
		return nil, nil, ErrDenied
	}
	original, err := newSystemPublicationOriginal(prepared, policy.Channel, policy.History)
	if err != nil {
		return nil, nil, err
	}
	cfg, _ := g.Config()
	if !reflect.DeepEqual(policy.STS, cfg) || policy.ProviderProfileHash != g.providerHash || policy.Subject != "system:serviceaccount:"+g.owner.Namespace+":"+g.owner.ServiceAccount || policy.History.Scope.Installation != pd.Installation(g.owner.Upstream.Installation) {
		return nil, nil, ErrDenied
	}
	transport, err := newS3STSTransport(cfg)
	if err != nil {
		return nil, nil, err
	}
	until := original.record.OwnerDeadline
	if d, ok := ctx.Deadline(); !ok {
		return nil, nil, ErrDenied
	} else if d.Before(until) {
		until = d
	}
	p := &originalC1ChannelProfile{gateway: g, ctx: ctx, execution: e, handle: h, claim: claim, policy: policy, original: original, transport: transport, until: until, probed: map[string]bool{}}
	policyHash := SystemSTSPolicyHash(policy)
	for n, purpose := range []string{"sts", "publish"} {
		ref := policy.Channel.Write
		if purpose == "publish" {
			ref = policy.Channel.Store
		}
		r := pd.CallRequest{Purpose: purpose, EvidenceID: policy.History.Evidence.EvidenceID, RefIdentityHash: pd.Hash(ref.Identity), RefVersion: pd.ProviderVersion(ref.Version), PolicyHash: pd.Hash(policyHash), BudgetUntil: systemPublicationTimestamp(until)}
		snapshot, err := e.BeginCall(ctx, h, r, claim)
		if err != nil {
			return nil, nil, err
		}
		p.snapshots[n] = snapshot
		view := snapshot.View()
		if view.Binding.Scope != policy.History.Scope || view.Binding.RunID != policy.History.RunID || view.Binding.Subject != pd.Hash(policy.SubjectIdentityHash) || view.Binding.Claim == nil || view.Binding.Claim.EvidenceID != policy.History.Evidence.EvidenceID || view.Binding.Claim.ManifestHash != policy.History.Evidence.ManifestHash || view.Facts.Grant.GrantID != policy.History.GrantID || view.Facts.Grant.Generation != policy.History.GrantGeneration || view.Facts.Run.RunID != policy.History.RunID || view.Facts.Run.InputHash != policy.History.InputHash {
			return nil, nil, ErrDenied
		}
		if snapshot.Deadline().Before(p.until) {
			p.until = snapshot.Deadline()
		}
	}
	if p.check() != nil {
		return nil, nil, ErrDenied
	}
	key := string(p.snapshots[0].BindingHash()) + ":" + string(p.snapshots[1].BindingHash())
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || len(g.profiles) >= 1024 {
		return nil, nil, ErrDenied
	}
	g.profiles[key] = p
	return p, p, nil
}

func (p *originalC1ChannelProfile) check() error {
	if p == nil {
		return ErrDenied
	}
	p.mu.Lock()
	failed := p.failed
	p.mu.Unlock()
	if failed {
		return ErrDenied
	}

	if p == nil || p.gateway == nil || p.ctx.Err() != nil || p.gateway.ctx.Err() != nil || !time.Now().Before(p.until) {
		return ErrDenied
	}
	p.gateway.mu.Lock()
	closed := p.gateway.closed
	p.gateway.mu.Unlock()
	if closed {
		return ErrDenied
	}
	for _, s := range p.snapshots {
		if s == nil || p.execution.RecheckCall(p.ctx, s) != nil {
			return ErrDenied
		}
	}
	return nil
}

func (p *originalC1ChannelProfile) VerifySystemSTSProfile(ctx context.Context, q SystemSTSProfileRequest) error {
	if p == nil {
		return ErrDenied
	}
	accepted := false
	defer func() {
		if !accepted {
			p.mu.Lock()
			p.failed = true
			p.mu.Unlock()
		}
	}()

	if ctx == nil || ctx.Err() != nil || p.check() != nil {
		return ErrDenied
	}
	wantSTS := p.policy.STS
	wantSTS.CAPEM = nil
	wantSTS.Store.CAPEM = nil
	claim := p.snapshots[0].View().Binding.Claim
	ref := q.Operation.Ref
	ref.ImmutableVersion = ""
	if q.PolicyHash != SystemSTSPolicyHash(p.policy) || q.ProviderProfileHash != p.gateway.providerHash || q.Scope != p.policy.History.Scope || q.RunID != p.policy.History.RunID || claim == nil || q.Claim != *claim || q.ManifestHash != p.policy.History.Evidence.ManifestHash || !reflect.DeepEqual(q.STS, wantSTS) || q.Deadline.After(p.until) || !time.Now().Before(q.Deadline) || ref != p.original.record.Ref || q.Operation.Offset != 0 || q.Operation.Length != 0 || q.Operation.Operation != S3Stat && q.Operation.Operation != S3Put {
		return ErrDenied
	}
	// Operation.Deadline is the immutable original owner-write cutoff required
	// by SystemSTSCredentials.accepts. The shorter call/credential window is
	// q.Deadline (already bounded by p.until above) and the native IAM until.
	// Requiring the owner cutoff itself <= call cutoff makes every legitimate
	// shorter-call PUT fail. Require exact original owner equality instead;
	// g.issue/object still enforce the original shorter credential until.
	if q.Operation.Operation == S3Put && (q.Operation.Object.SHA256 != p.original.record.Manifest.ObjectHash || q.Operation.Object.Size != p.original.record.Manifest.ObjectSize || q.Operation.Object.Version != "" || q.Operation.Ref.ImmutableVersion != "" || q.Operation.Deadline.IsZero() || !q.Operation.Deadline.Equal(p.original.record.OwnerDeadline)) {
		return ErrDenied
	}
	p.mu.Lock()
	if q.Operation.Ref.ImmutableVersion != "" && p.version != q.Operation.Ref.ImmutableVersion {
		p.mu.Unlock()
		return ErrDenied
	}
	key := hash(canonical(q))
	known := p.probed[key]
	if !known {
		p.scopes = append(p.scopes, originalC1ChannelScope{scope: q.Operation, until: q.Deadline})
	}
	p.mu.Unlock()
	if known {
		err := p.check()
		accepted = err == nil
		return err
	}
	until := q.Deadline.Truncate(time.Second)
	if !time.Now().Add(time.Second).Before(until) {
		return ErrDenied
	}
	// Actual native STS exchange through the real TLS listener, with the REAL
	// projected JWT and same Kubernetes TokenReview as subsequent issuance.
	jwt, expiry, err := readProjectedToken(p.policy.TokenFile, p.gateway.config.Issuer, p.gateway.config.Audience, p.policy.Subject)
	if err != nil {
		return ErrDenied
	}
	defer wipe(jwt)
	if expiry.Before(until) {
		return ErrDenied
	}
	policy, err := p.transport.policy(q.Operation, until)
	if err != nil {
		return ErrDenied
	}
	nonce, err := c1Random(16)
	if err != nil {
		return ErrDenied
	}
	form := url.Values{"Action": {"AssumeRoleWithWebIdentity"}, "Version": {"2011-06-15"}, "RoleArn": {p.policy.STS.RoleARN}, "RoleSessionName": {"evidence-" + nonce}, "DurationSeconds": {"900"}, "Policy": {string(policy)}, "WebIdentityToken": {string(jwt)}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.gateway.config.Endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return ErrDenied
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := p.transport.client.Do(request)
	if err != nil {
		return ErrDenied
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, 65537))
	response.Body.Close()
	defer wipe(raw)
	if readErr != nil || len(raw) > 65536 || response.StatusCode != http.StatusOK {
		return ErrDenied
	}
	fields, err := decodeSTS(raw)
	if err != nil {
		return ErrDenied
	}
	p.gateway.mu.Lock()
	credential := p.gateway.sessions[fields["Credentials/AccessKeyId"]]
	if credential != nil {
		copy := *credential
		copy.secret = append([]byte(nil), credential.secret...)
		credential = &copy
	}
	p.gateway.mu.Unlock()
	if credential != nil {
		defer wipe(credential.secret)
	}
	if credential == nil || credential.profile != p || credential.scope != q.Operation || !credential.until.Equal(until) {
		return ErrDenied
	}
	// Every probe is correctly SigV4 signed with that SAME virtual credential.
	// Server denials therefore demonstrate the remote method/key constraint,
	// not just the inability to fabricate a signature or a client method filter.
	checks := []struct {
		method, key, rangeHeader string
		allow                    bool
	}{{http.MethodGet, q.Operation.Ref.RelativeKey, "", false}, {http.MethodGet, q.Operation.Ref.RelativeKey, "bytes=0-0", false}, {http.MethodHead, q.Operation.Ref.RelativeKey + ".foreign", "", false}, {http.MethodHead, q.Operation.Ref.RelativeKey, "bytes=0-0", false}}
	if q.Operation.Operation == S3Stat {
		checks = append(checks, struct {
			method, key, rangeHeader string
			allow                    bool
		}{http.MethodHead, q.Operation.Ref.RelativeKey, "", true})
	}
	for _, test := range checks {
		status, headers, err := p.probe(ctx, credential, test.method, test.key, test.rangeHeader)
		if err != nil {
			return ErrDenied
		}
		if test.allow {
			if status != http.StatusOK && status != http.StatusNotFound || headers.Get("X-Claw-C1-Scope") != hash(canonical(q.Operation)) {
				return ErrDenied
			}
		} else if status != http.StatusForbidden {
			return ErrDenied
		}
	}
	if p.check() != nil {
		return ErrDenied
	}
	p.mu.Lock()
	p.probed[key] = true
	p.mu.Unlock()
	accepted = true
	return nil
}

func (p *originalC1ChannelProfile) probe(ctx context.Context, c *originalC1ChannelCredential, method, key, rangeHeader string) (int, http.Header, error) {
	u, _ := url.Parse(p.gateway.config.Store.Endpoint)
	u.Path = "/" + p.gateway.config.Store.Bucket + "/" + key
	if c.scope.Ref.ImmutableVersion != "" {
		u.RawQuery = url.Values{"versionId": {c.scope.Ref.ImmutableVersion}}.Encode()
	}
	r, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return 0, nil, err
	}
	r.Header.Set("X-Amz-Content-Sha256", hash(nil))
	r.Header.Set("X-Amz-Checksum-Mode", "ENABLED")
	if rangeHeader != "" {
		r.Header.Set("Range", rangeHeader)
	}
	seconds := int64(time.Until(c.until) / time.Second)
	if seconds < 1 {
		return 0, nil, ErrDenied
	}
	r = signer.PreSignV4(*r, c.access, string(c.secret), c.token, p.gateway.config.Store.Region, seconds)
	response, err := p.transport.client.Do(r)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 65536))
	return response.StatusCode, response.Header.Clone(), nil
}

// A 404 was not used as absence. The owner performs native authenticated
// all-version AND delete-marker listing, requires exact-key EOF, and repeats
// the original opaque SDK authorization before and after network work.
func (p *originalC1ChannelProfile) VerifyAbsent(ctx context.Context, q S3AbsenceRequest) (S3AbsenceProof, error) {
	var zero S3AbsenceProof
	if p.check() != nil || q.Ref != p.original.record.Ref || q.Ref.ImmutableVersion != "" || !digestPattern.MatchString(q.Challenge) {
		return zero, ErrDenied
	}
	started := time.Now().UTC().Truncate(time.Second)
	if err := p.gateway.exactVersionAbsence(ctx, q.Ref); err != nil {
		return zero, err
	}
	if p.check() != nil {
		return zero, ErrDenied
	}
	until := started.Add(30 * time.Second)
	if p.until.Before(until) {
		until = p.until
	}
	if !time.Now().Before(until) {
		return zero, ErrDenied
	}
	return S3AbsenceProof{Request: q, ObservedAt: started, ExpiresAt: until}, nil
}

var _ SystemSTSProfileVerifier = (*originalC1ChannelProfile)(nil)
var _ S3AbsenceVerifier = (*originalC1ChannelProfile)(nil)
