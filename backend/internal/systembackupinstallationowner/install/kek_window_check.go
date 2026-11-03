package install

import (
	"bytes"
	"context"
	"sync"
	"sync/atomic"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	kek "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

type originalWindowKEKCheck struct {
	mu                         sync.Mutex
	failed                     atomic.Bool
	origin                     *originalWindowKEKCheck
	owner                      *OriginalWindowKEK
	ctx                        context.Context
	source                     *consumerCaptureState
	record                     BootstrapKEKWindowRecord
	raw, signature             []byte
	identity                   *owner.PreparedCaptureSigning
	guard                      *owner.OwnerGuard
	tx                         pd.BootstrapSQL
	actual                     reg.PreparedAdmission
	started, completed, locked bool
	last                       time.Time
}

func (*originalWindowKEKCheck) MarshalJSON() ([]byte, error) { return nil, ErrInstall }

func (p *originalWindowKEKCheck) fail() error {
	if p != nil {
		p.failed.Store(true)
		if p.origin != nil {
			p.origin.failed.Store(true)
		}
	}
	return ErrInstall
}
func (p *originalWindowKEKCheck) local(ctx context.Context) error {
	if p == nil || p.origin != p || p.failed.Load() || p.owner == nil || p.owner.origin != p.owner || p.source == nil || !consumerSameContext(ctx, p.ctx) || ctx.Err() != nil || p.source.current(ctx) != nil {
		return p.fail()
	}
	raw, err := ReadPrivateFile(p.owner.files.RecordFile, 262144)
	sig, se := ReadPrivateFile(p.owner.files.SignatureFile, 64)
	if err != nil || se != nil || hash(raw) != p.owner.files.RecordSHA256 || !bytes.Equal(raw, p.raw) || !bytes.Equal(sig, p.signature) {
		return p.fail()
	}
	return nil
}

func (p *originalWindowKEKCheck) matches(actual reg.PreparedAdmission) bool {
	if p == nil || consumerNil(actual) {
		return false
	}
	original, ok := actual.(kek.BootstrapOriginalEvidenceAdmission)
	if !ok || consumerNil(original.OriginalCoverage()) || len(original.OriginalEvidenceIDs()) != 17 {
		return false
	}
	// These are getters on the actual private admission produced by the fixed
	// concrete source, not source facts supplied by a caller or an approval DTO.
	binding, err := kekWindowBindingSHA(actual.Binding())
	snapshot, se := kekWindowSnapshotSHA(actual.ExpectedSnapshot())
	o := actual.Observation()
	cfg := p.owner.cfg
	return err == nil && se == nil && binding == p.record.BindingSHA256 && snapshot == p.record.SnapshotFactsSHA256 && o.InstallationID == p.record.Target.InstallationID && o.ConfigSHA256 == string(p.record.Selection.ConfigHash) && o.MappingSource == p.record.MappingSource && o.SourceRevision == p.record.SourceRevision && o.GenerateCapabilitySource == cfg.Generate.Source && o.UnwrapCapabilitySource == cfg.Unwrap.Source && !actual.ValidUntil().IsZero()
}

func (p *originalWindowKEKCheck) current(ctx context.Context, view pd.BootstrapReadSQL) error {
	if p == nil || p.guard == nil || !pd.SameBootstrapTransaction(p.tx, view) || p.local(ctx) != nil || p.guard.RecheckCandidateIdentity(ctx, view) != nil || p.local(ctx) != nil {
		return p.fail()
	}
	// All local bytes are delivered BEFORE this last controlled SQL sample.
	now, err := view.SampleTime(ctx)
	end, valid := terminalMinimum(p.record.Until, p.guard.IdentityDeadline())
	if err != nil || !valid || now.Before(p.last) || now.Before(p.record.NotBefore) || !now.Before(end) || ctx.Err() != nil {
		return p.fail()
	}
	p.last = now
	return nil
}

func (p *originalWindowKEKCheck) AuthorizeIdentity(ctx context.Context, tx pd.BootstrapSQL) (*pd.Timestamp, error) {
	if p == nil || p.origin != p {
		return nil, p.fail()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.started || !p.completed || p.guard != nil || p.identity == nil || !pd.SameBootstrapTransaction(tx, tx) || p.local(ctx) != nil {
		return nil, p.fail()
	}
	p.tx = tx
	var err error
	p.guard, err = p.identity.AuthorizeCandidate(ctx, tx)
	if err != nil || p.current(ctx, tx) != nil {
		return nil, p.fail()
	}
	end, valid := terminalMinimum(p.record.Until, p.guard.IdentityDeadline())
	if !valid {
		return nil, p.fail()
	}
	stamp := terminalTimestamp(end)
	return &stamp, nil
}
func (p *originalWindowKEKCheck) RecheckIdentity(ctx context.Context, view pd.BootstrapReadSQL) error {
	if p == nil || p.origin != p {
		return p.fail()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.current(ctx, view)
}
func (p *originalWindowKEKCheck) dependency() *pd.Timestamp {
	if p == nil || p.origin != p || p.failed.Load() || !p.started || !p.completed || p.guard == nil || !p.matches(p.actual) {
		return nil
	}
	end, valid := terminalMinimum(p.record.Until, p.guard.IdentityDeadline())
	if !valid {
		return nil
	}
	if p.actual.ValidUntil().Before(end) {
		end = p.actual.ValidUntil()
	}
	stamp := terminalTimestamp(end)
	return &stamp
}
func (p *originalWindowKEKCheck) DependencyDeadline() *pd.Timestamp {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.dependency()
}
func (p *originalWindowKEKCheck) resource(ctx context.Context, view pd.BootstrapReadSQL) error {
	if p.current(ctx, view) != nil {
		return p.fail()
	}
	end := p.dependency()
	if end == nil {
		return p.fail()
	}
	limit, err := end.Time()
	now, se := view.SampleTime(ctx)
	if err != nil || se != nil || now.Before(p.last) || !now.Before(limit) || ctx.Err() != nil {
		return p.fail()
	}
	p.last = now
	// NO mapping/capability/evidence/KEK lock here. The exact returned opaque
	// admission is rechecked later by the independent original D KEK path.
	return nil
}
func (p *originalWindowKEKCheck) LockReferences(ctx context.Context, tx pd.BootstrapSQL) error {
	if p == nil || p.origin != p {
		return p.fail()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.locked || p.resource(ctx, tx) != nil {
		return p.fail()
	}
	p.locked = true
	return nil
}
func (p *originalWindowKEKCheck) Recheck(ctx context.Context, view pd.BootstrapReadSQL) error {
	if p == nil || p.origin != p {
		return p.fail()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.locked {
		return p.fail()
	}
	return p.resource(ctx, view)
}

var _ sec.BootstrapTerminalResourceCheck = (*originalWindowKEKCheck)(nil)
