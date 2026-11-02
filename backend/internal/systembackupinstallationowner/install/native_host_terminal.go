package install

import (
	"context"
	"sync/atomic"
	"time"

	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

type BootstrapNativeHostFiles struct{ RecordFile, RecordSHA256, SignatureFile string }

// NativeHostBootstrapTerminalOriginal constructs its own concrete terminal;
// no missing generic Original authority or success callback is an input.
// The additional signed source is mandatory on this new route. It does not
// make any of the twenty-three missing compiled resource owners present.
type NativeHostBootstrapTerminalOriginal struct {
	terminal *BootstrapTerminalOriginal
	files    BootstrapNativeHostFiles
}

func NewNativeHostBootstrapTerminalOriginal(capture *CaptureSigningConsumer, files BootstrapTerminalFiles, resources map[string]sec.BootstrapTerminalResource, native BootstrapNativeHostFiles) (*NativeHostBootstrapTerminalOriginal, error) {
	if !digestPattern.MatchString(native.RecordSHA256) {
		return nil, ErrInstall
	}
	terminal, err := NewBootstrapTerminalOriginal(capture, files, resources)
	if err != nil {
		return nil, err
	}
	return &NativeHostBootstrapTerminalOriginal{terminal: terminal, files: native}, nil
}

func (*NativeHostBootstrapTerminalOriginal) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (*NativeHostBootstrapTerminalOriginal) String() string {
	return "NativeHostBootstrapTerminalOriginal"
}
func (a *NativeHostBootstrapTerminalOriginal) MissingTerminalResources() []string {
	if a == nil {
		return (*BootstrapTerminalOriginal)(nil).MissingTerminalResources()
	}
	return a.terminal.MissingTerminalResources()
}
func (a *NativeHostBootstrapTerminalOriginal) Owners() (sec.BootstrapOwnerAdapters, error) {
	if a == nil || a.terminal == nil {
		return sec.BootstrapOwnerAdapters{}, ErrInstall
	}
	return a.terminal.Owners()
}

func (a *NativeHostBootstrapTerminalOriginal) PrepareBootstrapCandidates(ctx context.Context, grant sec.OfflineBootstrapGrant, config sec.BootstrapConfig, request pd.BootstrapConsumptionRequest) (sec.PreparedBootstrapCandidateAuthority, error) {
	var zero sec.PreparedBootstrapCandidateAuthority
	if a == nil || a.terminal == nil || consumerNil(ctx) || ctx.Err() != nil || len(a.MissingTerminalResources()) != 0 {
		return zero, ErrInstall
	}
	// Authenticate the same original public source/mapping first, without
	// preparing any signing probe, other owner or capacity report twice.
	loaded, err := a.terminal.load(ctx, grant, config, request)
	if err != nil {
		return zero, err
	}
	defer loaded.source.request.observer.Close()
	raw, err := ReadPrivateFile(a.files.RecordFile, 262144)
	if err != nil || hash(raw) != a.files.RecordSHA256 {
		return zero, ErrInstall
	}
	signature, err := ReadPrivateFile(a.files.SignatureFile, 64)
	if err != nil {
		return zero, ErrInstall
	}
	locator, plan, public, err := readBootstrapOriginalPublicSource(ctx, a.terminal.capture, loaded.source)
	if err != nil {
		return zero, ErrInstall
	}
	native, err := verifyNativeHostMapping(raw, signature, public, loaded.mapping, a.terminal.files.MappingSHA256)
	if err != nil {
		return zero, ErrInstall
	}
	kube, err := openCaptureConsumerKubernetes(plan, locator.KubeconfigFile, locator.KubeconfigSHA256)
	if err != nil {
		return zero, ErrInstall
	}
	check := &nativeBootstrapHostCheck{ctx: ctx, notBefore: native.NotBefore, identityUntil: native.Until, files: []consumerPinnedFile{{a.files.RecordFile, a.files.RecordSHA256, 262144}, {a.files.SignatureFile, hash(signature), 64}}, available: true}
	check.origin = check
	for n, binding := range native.Bindings {
		observed, err := observeNativeMappedBootstrapHost(ctx, kube, loaded.mapping.Hosts[n], binding)
		if err != nil {
			check.available = false
			continue
		}
		if check.observedAt.IsZero() || observed.ObservedAt.After(check.observedAt) {
			check.observedAt = observed.ObservedAt
		}
		if check.until.IsZero() || observed.Until.Before(check.until) {
			check.until = observed.Until
		}
	}
	if loaded.source.current(ctx) != nil || loaded.currentFiles(ctx) != nil || check.checkFiles(ctx) != nil {
		return zero, ErrInstall
	}
	// Native observations precede the single provider preparation. The frozen
	// terminal still reads original capacity LAST, never rereads/restamps it.
	prepared, err := a.terminal.PrepareBootstrapCandidates(ctx, grant, config, loaded.request)
	if err != nil {
		return zero, err
	}
	session, ok := prepared.Session.(*bootstrapTerminalSession)
	if !ok || session == nil || !session.complete || session.loaded.mapping.SelectionSHA256 != native.SelectionSHA256 || session.loaded.mapping.PlanSHA256 != native.PlanSHA256 {
		return zero, ErrInstall
	}
	// Keep the old terminal's independent physical failure closed. A later
	// native observer cannot resurrect a failed old source/observation.
	if session.loaded.hostUntil == nil {
		check.available = false
	}
	if check.available {
		limit, valid := terminalMinimum(check.until, session.loaded.hostUntil)
		if !valid {
			return zero, ErrInstall
		}
		check.until = limit
		stamp := terminalTimestamp(limit)
		session.loaded.hostUntil = &stamp
	}
	session.loaded.files = append(session.loaded.files, check.files...)
	session.ordered = append(session.ordered, check)
	if check.checkFiles(ctx) != nil || session.loaded.source.current(ctx) != nil || session.loaded.currentFiles(ctx) != nil {
		return zero, ErrInstall
	}
	return prepared, nil
}

// This check is a real additional host condition on the existing six terminal
// stages. It fills no registry/reference slot and accepts no observed DTO from
// an operator. Only this module's native Prepare can issue an available check.
type nativeBootstrapHostCheck struct {
	origin                                      *nativeBootstrapHostCheck
	ctx                                         context.Context
	tx                                          pd.BootstrapSQL
	files                                       []consumerPinnedFile
	notBefore, identityUntil, observedAt, until time.Time
	available, locked                           bool
	failed                                      atomic.Bool
}

func (c *nativeBootstrapHostCheck) fail() error {
	if c != nil {
		c.failed.Store(true)
		if c.origin != nil {
			c.origin.failed.Store(true)
		}
	}
	return ErrInstall
}
func (c *nativeBootstrapHostCheck) checkFiles(ctx context.Context) error {
	if c == nil || c.origin != c || c.failed.Load() || !consumerSameContext(ctx, c.ctx) || ctx.Err() != nil {
		return c.fail()
	}
	for _, pin := range c.files {
		raw, err := ReadPrivateFile(pin.path, pin.limit)
		if err != nil || hash(raw) != pin.sha {
			return c.fail()
		}
	}
	return nil
}
func (c *nativeBootstrapHostCheck) current(ctx context.Context, view pd.BootstrapReadSQL) error {
	if c.checkFiles(ctx) != nil || !pd.SameBootstrapTransaction(c.tx, view) {
		return c.fail()
	}
	now, err := view.SampleTime(ctx)
	if err != nil || now.Before(c.notBefore) || !now.Before(c.identityUntil) {
		return c.fail()
	}
	return nil
}
func (c *nativeBootstrapHostCheck) AuthorizeIdentity(ctx context.Context, tx pd.BootstrapSQL) (*pd.Timestamp, error) {
	if c == nil || c.tx != nil && !pd.SameBootstrapTransaction(c.tx, tx) {
		return nil, c.fail()
	}
	c.tx = tx
	if err := c.current(ctx, tx); err != nil {
		return nil, err
	}
	stamp := terminalTimestamp(c.identityUntil)
	return &stamp, nil
}
func (c *nativeBootstrapHostCheck) RecheckIdentity(ctx context.Context, view pd.BootstrapReadSQL) error {
	return c.current(ctx, view)
}
func (c *nativeBootstrapHostCheck) DependencyDeadline() *pd.Timestamp {
	if c == nil || c.origin != c || c.failed.Load() || !c.available || c.until.IsZero() {
		return nil
	}
	stamp := terminalTimestamp(c.until)
	return &stamp
}
func (c *nativeBootstrapHostCheck) fresh(ctx context.Context, view pd.BootstrapReadSQL) error {
	if c.current(ctx, view) != nil || !c.available {
		return c.fail()
	}
	now, err := view.SampleTime(ctx)
	if err != nil || now.Before(c.observedAt) || !now.Before(c.until) {
		return c.fail()
	}
	return nil
}
func (c *nativeBootstrapHostCheck) LockReferences(ctx context.Context, tx pd.BootstrapSQL) error {
	if c == nil || c.locked || c.fresh(ctx, tx) != nil {
		return c.fail()
	}
	c.locked = true
	return nil
}
func (c *nativeBootstrapHostCheck) Recheck(ctx context.Context, view pd.BootstrapReadSQL) error {
	if c == nil || !c.locked {
		return c.fail()
	}
	return c.fresh(ctx, view)
}

var _ sec.BootstrapCandidateAuthority = (*NativeHostBootstrapTerminalOriginal)(nil)
var _ sec.BootstrapTerminalResourceCheck = (*nativeBootstrapHostCheck)(nil)
