package systembackupinstallationowner

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

// Constructor-fixed pins/files and native observers, NEVER caller-provided
// readiness facts. This one pointer owns both aliases so its four original
// rows are acquired acceptance head/grant then catalog head/grant, once.
type SigningResourceInput struct {
	Pin      SigningResourceTrustPin
	Files    RecordFiles
	Material SigningResourceMaterial
	Observer *SigningResourceObserver
}
type SigningResources struct {
	inputs  [2]SigningResourceInput
	binding string
}

func NewSigningResources(inputs []SigningResourceInput) (*SigningResources, error) {
	if len(inputs) != 2 {
		return nil, ErrOwner
	}
	a := &SigningResources{}
	paths := map[string]bool{}
	for n, in := range inputs {
		if !signingPinValid(in.Pin) || in.Pin.Purpose != SigningResourcePurposes()[n] || in.Observer == nil || in.Observer.transport == nil || in.Material.Pin.InstallationID != in.Pin.Target.InstallationID || in.Material.Pin.Revision < 1 || in.Material.Pin.Revision > 9007199254740991 || !hashPattern.MatchString(in.Material.Pin.RecordSHA256) || len(in.Material.Pin.Issuer) != 32 || in.Material.Files.RecordFile == in.Material.Files.SignatureFile {
			return nil, ErrOwner
		}
		for _, path := range []string{in.Files.RecordFile, in.Files.SignatureFile, in.Observer.transport.cfg.RuntimeJWTFile} {
			if !filepath.IsAbs(path) || filepath.Clean(path) != path || paths[path] {
				return nil, ErrOwner
			}
			paths[path] = true
		}
		in.Pin.Issuer = bytes.Clone(in.Pin.Issuer)
		in.Material.Pin.Issuer = bytes.Clone(in.Material.Pin.Issuer)
		for _, path := range []string{in.Material.Files.RecordFile, in.Material.Files.SignatureFile} {
			if !filepath.IsAbs(path) || filepath.Clean(path) != path {
				return nil, ErrOwner
			}
		}
		a.inputs[n] = in
	}
	x, y := a.inputs[0].Pin, a.inputs[1].Pin
	if x.Target != y.Target || x.Actor != y.Actor || x.EnrollmentID != y.EnrollmentID || x.EnrollmentRevision != y.EnrollmentRevision || x.EnrollmentDocumentSHA256 != y.EnrollmentDocumentSHA256 || x.IssuerID != y.IssuerID || !bytes.Equal(x.Issuer, y.Issuer) {
		return nil, ErrOwner
	}
	for _, in := range a.inputs {
		for _, other := range a.inputs {
			if in.Observer.transport.cfg.RuntimeJWTFile == other.Observer.transport.cfg.ObserverTokenFile || in.Observer.transport.cfg.RuntimeJWTFile == other.Material.Files.RecordFile || in.Observer.transport.cfg.RuntimeJWTFile == other.Material.Files.SignatureFile {
				return nil, ErrOwner
			}
		}
	}
	type inputBinding struct {
		Pin                                                                                        SigningResourceTrustPin
		Files                                                                                      RecordFiles
		Material                                                                                   SigningResourceMaterial
		Endpoint, CASHA256, ObserverPolicy, ObserverTokenFile, ObserverTokenSHA256, RuntimeJWTFile string
		TrustSHA256                                                                                string
	}
	var data []inputBinding
	for _, in := range a.inputs {
		cfg := in.Observer.transport.cfg
		trust, e := canonical(cfg.Trust)
		if e != nil {
			return nil, ErrOwner
		}
		data = append(data, inputBinding{in.Pin, in.Files, in.Material, cfg.Endpoint, cfg.CASHA256, cfg.ObserverPolicy, cfg.ObserverTokenFile, cfg.ObserverTokenSHA256, cfg.RuntimeJWTFile, digest(trust)})
	}
	raw, e := canonical(struct {
		Version string
		Inputs  []inputBinding
	}{SigningResourceGrantVersion, data})
	if e != nil {
		return nil, ErrOwner
	}
	a.binding = digest(raw)
	return a, nil
}

func (*SigningResources) TerminalKeys() []string {
	return []string{"reference:acceptance_signing", "reference:catalog_signing"}
}
func (*SigningResources) MarshalJSON() ([]byte, error) { return nil, ErrOwner }
func (a *SigningResources) BindingSHA256() (string, error) {
	if a == nil || !hashPattern.MatchString(a.binding) {
		return "", ErrOwner
	}
	return a.binding, nil
}
func (*SigningResources) Prepare(context.Context, sec.OfflineBootstrapGrant, sec.BootstrapConfig) (sec.BootstrapResourceCheck, error) {
	return nil, ErrOwner
}

type signingResourcePrepared struct {
	mu              sync.Mutex
	failed          atomic.Bool
	origin          *signingResourcePrepared
	owner           *SigningResources
	ctx             context.Context
	grants          [2]SigningResourceGrant
	raw, signatures [2][]byte
	observations    [2]*ObservedSigningResource
	current         [2]*SigningResourceSnapshot
	tx              pd.BootstrapSQL
	identityUntil   time.Time
	last            time.Time
	locked          bool
}

func signingResourceMatch(g SigningResourceGrant, offline sec.OfflineBootstrapGrant, c sec.BootstrapConfig) bool {
	raw, e := json.Marshal(offline)
	if e != nil || digest(raw) != g.BootstrapGrantSHA256 || g.ConfigSHA256 != c.SHA256() || offline.ConfigSHA256 != g.ConfigSHA256 || offline.InstallationID != g.Target.InstallationID || offline.ServerUUID != g.Target.ServerUUID || offline.Database != g.Target.Database || offline.UserID != g.Actor.UserID || offline.Username != g.Actor.Username {
		return false
	}
	count := 0
	for _, r := range c.References() {
		if r.Purpose == g.Reference.Purpose {
			if r != g.Reference {
				return false
			}
			count++
		}
	}
	return count == 1
}

func (a *SigningResources) PrepareTerminalResource(ctx context.Context, g sec.OfflineBootstrapGrant, c sec.BootstrapConfig) (sec.BootstrapTerminalResourceCheck, error) {
	if a == nil || !sameContext(ctx, ctx) || ctx.Err() != nil {
		return nil, ErrOwner
	}
	p := &signingResourcePrepared{owner: a, ctx: ctx}
	p.origin = p
	for n, in := range a.inputs {
		raw, e := localFile(in.Files.RecordFile, 262144)
		sig, f := localFile(in.Files.SignatureFile, 64)
		grant, v := InspectSigningResourceGrant(raw, sig, in.Pin)
		if e != nil || f != nil || v != nil || !signingResourceMatch(grant, g, c) || CheckSigningResourceMaterial(ctx, in.Material, grant) != nil {
			return nil, ErrOwner
		}
		p.grants[n], p.raw[n], p.signatures[n] = grant, raw, sig
	}
	x, y := p.grants[0], p.grants[1]
	if x.Target != y.Target || x.Actor != y.Actor || x.PlanSHA256 != y.PlanSHA256 || x.BootstrapGrantSHA256 != y.BootstrapGrantSHA256 || x.ConfigSHA256 != y.ConfigSHA256 || x.SigningMaterialSHA256 != y.SigningMaterialSHA256 || x.SigningMaterialRevision != y.SigningMaterialRevision || !x.NotBefore.Equal(y.NotBefore) || !x.Until.Equal(y.Until) || !reflect.DeepEqual(x.Bindings, y.Bindings) || !reflect.DeepEqual(x.Histories, y.Histories) {
		return nil, ErrOwner
	}
	// Physical failure closes fresh use only. Both independent current signed
	// heads/grants and original admin remain mandatory even for exact history.
	for n, in := range a.inputs {
		p.observations[n], _ = in.Observer.ObserveSigningResource(ctx, p.raw[n], p.signatures[n], in.Pin)
	}
	if p.local(ctx) != nil {
		return nil, ErrOwner
	}
	return p, nil
}

func (p *signingResourcePrepared) fail() error {
	if p != nil {
		p.failed.Store(true)
		if p.origin != nil {
			p.origin.failed.Store(true)
		}
	}
	return ErrOwner
}
func (p *signingResourcePrepared) local(ctx context.Context) error {
	if p == nil || p.origin != p || p.failed.Load() || p.owner == nil || !sameContext(ctx, p.ctx) || ctx.Err() != nil {
		return p.fail()
	}
	for n, in := range p.owner.inputs {
		raw, e := localFile(in.Files.RecordFile, 262144)
		sig, f := localFile(in.Files.SignatureFile, 64)
		if e != nil || f != nil || !bytes.Equal(raw, p.raw[n]) || !bytes.Equal(sig, p.signatures[n]) || CheckSigningResourceMaterial(ctx, in.Material, p.grants[n]) != nil {
			return p.fail()
		}
	}
	return nil
}
func (p *signingResourcePrepared) identity(ctx context.Context, view pd.BootstrapReadSQL, first bool) error {
	if !pd.SameBootstrapTransaction(p.tx, view) || p.local(ctx) != nil {
		return p.fail()
	}
	before, e := view.SampleTime(ctx)
	if e != nil || !validTime(before) || before.Before(p.last) {
		return p.fail()
	}
	var until time.Time
	for n, in := range p.owner.inputs {
		s, e := ReadSigningResourceCandidate(ctx, view, in.Pin)
		if e != nil || s.RequireCurrent(before) != nil || !bytes.Equal(s.raw, p.raw[n]) || !bytes.Equal(s.signature, p.signatures[n]) {
			return p.fail()
		}
		if first {
			p.current[n] = s
		} else if p.current[n] == nil || p.current[n].cas != s.cas || !bytes.Equal(p.current[n].headRaw, s.headRaw) || !bytes.Equal(p.current[n].headSignature, s.headSignature) {
			return p.fail()
		}
		if n == 0 {
			until = s.grant.Until
		} else {
			until = minimum(until, s.grant.Until)
		}
	}
	if p.local(ctx) != nil {
		return p.fail()
	}
	after, e := view.SampleTime(ctx)
	if e != nil || !validTime(after) || after.Before(before) || !after.Before(until) || ctx.Err() != nil {
		return p.fail()
	}
	for _, s := range p.current {
		if s == nil || s.RequireCurrent(after) != nil {
			return p.fail()
		}
	}
	if first {
		p.identityUntil = until
	} else if !p.identityUntil.Equal(until) {
		return p.fail()
	}
	p.last = after
	return nil
}
func (p *signingResourcePrepared) AuthorizeIdentity(ctx context.Context, tx pd.BootstrapSQL) (*pd.Timestamp, error) {
	if p == nil {
		return nil, ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.origin != p || p.tx != nil || !pd.SameBootstrapTransaction(tx, tx) {
		return nil, p.fail()
	}
	p.tx = tx
	if p.identity(ctx, tx, true) != nil {
		return nil, p.fail()
	}
	stamp := pd.Timestamp(p.identityUntil.UTC().Format("2006-01-02T15:04:05.000000Z"))
	return &stamp, nil
}
func (p *signingResourcePrepared) RecheckIdentity(ctx context.Context, view pd.BootstrapReadSQL) error {
	if p == nil {
		return ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.identity(ctx, view, false)
}
func (p *signingResourcePrepared) dependency() *pd.Timestamp {
	if p == nil || p.origin != p || p.failed.Load() || p.tx == nil || p.identityUntil.IsZero() {
		return nil
	}
	end := p.identityUntil
	for n, o := range p.observations {
		if o == nil || o.owner != p.owner.inputs[n].Observer || !sameContext(o.ctx, p.ctx) || o.grantSHA256 != p.owner.inputs[n].Pin.GrantSHA256 || len(o.signature) != 64 || !o.pinsCurrent() {
			return nil
		}
		end = minimum(end, o.until)
	}
	stamp := pd.Timestamp(end.UTC().Format("2006-01-02T15:04:05.000000Z"))
	return &stamp
}
func (p *signingResourcePrepared) DependencyDeadline() *pd.Timestamp {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.dependency()
}
func (p *signingResourcePrepared) resource(ctx context.Context, view pd.BootstrapReadSQL) error {
	if p.identity(ctx, view, false) != nil {
		return p.fail()
	}
	end := p.dependency()
	if end == nil {
		return p.fail()
	}
	limit, e := end.Time()
	now, f := view.SampleTime(ctx)
	if e != nil || f != nil || !validTime(now) || now.Before(p.last) || !now.Before(limit) || ctx.Err() != nil {
		return p.fail()
	}
	for _, o := range p.observations {
		if now.Before(o.observed) {
			return p.fail()
		}
	}
	p.last = now
	return nil
}
func (p *signingResourcePrepared) LockReferences(ctx context.Context, tx pd.BootstrapSQL) error {
	if p == nil {
		return ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.locked || p.resource(ctx, tx) != nil {
		return p.fail()
	}
	p.locked = true
	return nil
}
func (p *signingResourcePrepared) Recheck(ctx context.Context, view pd.BootstrapReadSQL) error {
	if p == nil {
		return ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.locked {
		return p.fail()
	}
	return p.resource(ctx, view)
}

var _ sec.BootstrapTerminalResource = (*SigningResources)(nil)
var _ sec.BootstrapTerminalResourceCheck = (*signingResourcePrepared)(nil)
