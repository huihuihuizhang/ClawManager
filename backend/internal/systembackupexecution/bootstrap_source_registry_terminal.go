package systembackupexecution

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	"clawreef/internal/systembackupinstallationowner/install"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

// BootstrapSourceRegistryTerminalResource is composed with the SAME enrolled
// capture consumer as A20. Its only inputs locate original signed material.
// It accepts no enabled Forward, task, Job, observer callback or passed result.
type BootstrapSourceRegistryTerminalResource struct {
	capture     *install.CaptureSigningConsumer
	files       install.BootstrapSourceRegistryFiles
	binding     string
	nativeFiles *BootstrapSourceNativeRegistryFiles
}

// The additional files are authenticated by ORIGINAL config registry hashes
// (inside the enrolled capture selection) and this original signed mapping
// binding. Native READ authority remains the actual unchanged V2 delegation.
func NewBootstrapSourceRegistryTerminalResourceWithNativeRegistries(capture *install.CaptureSigningConsumer, files install.BootstrapSourceRegistryFiles, native BootstrapSourceNativeRegistryFiles) (*BootstrapSourceRegistryTerminalResource, error) {
	r, err := NewBootstrapSourceRegistryTerminalResource(capture, files)
	if err != nil || !validBootstrapNativeFiles(native) {
		return nil, sec.ErrRegistrationUnavailable
	}
	r.nativeFiles = &native
	binding, err := r.compositionBinding()
	if err != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	r.binding = binding
	return r, nil
}

func (r *BootstrapSourceRegistryTerminalResource) compositionBinding() (string, error) {
	if r == nil || r.capture == nil {
		return "", sec.ErrRegistrationUnavailable
	}
	base, err := r.capture.BootstrapSourceRegistryBindingSHA256(r.files)
	if err != nil {
		return "", sec.ErrRegistrationUnavailable
	}
	if r.nativeFiles == nil {
		return base, nil
	}
	if !validBootstrapNativeFiles(*r.nativeFiles) {
		return "", sec.ErrRegistrationUnavailable
	}
	raw, err := ce.Canonical(struct {
		Version, OriginalSourceBinding string
		Files                          BootstrapSourceNativeRegistryFiles
	}{"original-source-native-registry-composition.v1", base, *r.nativeFiles})
	if err != nil {
		return "", sec.ErrRegistrationUnavailable
	}
	return hash(raw), nil
}

func NewBootstrapSourceRegistryTerminalResource(capture *install.CaptureSigningConsumer, files install.BootstrapSourceRegistryFiles) (*BootstrapSourceRegistryTerminalResource, error) {
	binding, err := capture.BootstrapSourceRegistryBindingSHA256(files)
	if err != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	return &BootstrapSourceRegistryTerminalResource{capture: capture, files: files, binding: binding}, nil
}

func (*BootstrapSourceRegistryTerminalResource) String() string {
	return "OriginalSourceRegistryTerminal"
}
func (*BootstrapSourceRegistryTerminalResource) GoString() string {
	return "OriginalSourceRegistryTerminal"
}
func (*BootstrapSourceRegistryTerminalResource) MarshalJSON() ([]byte, error) {
	return nil, sec.ErrRegistrationUnavailable
}
func (r *BootstrapSourceRegistryTerminalResource) TerminalKeys() []string {
	if r != nil && r.nativeFiles != nil {
		return []string{"registry:parts", "registry:redis_sources", "registry:secret_allowlist", "registry:source_writers"}
	}
	return []string{"registry:parts", "registry:source_writers"}
}

// Both entries share this concrete pointer, so A20 prepares/authorizes it once.
func (r *BootstrapSourceRegistryTerminalResource) TerminalResources() map[string]sec.BootstrapTerminalResource {
	if r == nil {
		return nil
	}
	resources := map[string]sec.BootstrapTerminalResource{}
	for _, key := range r.TerminalKeys() {
		resources[key] = r
	}
	return resources
}

func (r *BootstrapSourceRegistryTerminalResource) BindingSHA256() (string, error) {
	if r == nil || r.capture == nil || r.binding == "" {
		return "", sec.ErrRegistrationUnavailable
	}
	binding, err := r.compositionBinding()
	if err != nil || binding != r.binding {
		return "", sec.ErrRegistrationUnavailable
	}
	return binding, nil
}

func (*BootstrapSourceRegistryTerminalResource) Prepare(context.Context, sec.OfflineBootstrapGrant, sec.BootstrapConfig) (sec.BootstrapResourceCheck, error) {
	return nil, sec.ErrRegistrationUnavailable
}

func (r *BootstrapSourceRegistryTerminalResource) PrepareTerminalResource(ctx context.Context, grant sec.OfflineBootstrapGrant, config sec.BootstrapConfig) (sec.BootstrapTerminalResourceCheck, error) {
	if r == nil || !minioTerminalContext(ctx, ctx) || !sec.ValidOfflineBootstrapGrant(grant) || grant.ConfigSHA256 != config.SHA256() {
		return nil, sec.ErrRegistrationUnavailable
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, sec.ErrRegistrationUnavailable
	}
	if _, err := r.BindingSHA256(); err != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	// This first decode supplies comparison DATA only. The actual consumer below
	// independently verifies the signature, enrollment and complete selection
	// against the enrolled original capture record; the bytes are not authority.
	raw, err := pinnedDeploymentFile(r.files.RecordFile, r.files.RecordSHA256, 262144)
	var data install.BootstrapSourceRegistryV2Record
	if err != nil || strictBootstrapSourceJSON(raw, &data) != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	identity, err := r.capture.PrepareBootstrapSourceRegistriesV2(ctx, grant, config, data.Selection, r.files)
	if err != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	s := &bootstrapSourceRegistryTerminalCheck{ctx: ctx, identity: identity}
	if r.nativeFiles != nil {
		if _, _, err := bootstrapNativeRegistryRefs(config, *r.nativeFiles); err != nil {
			return nil, sec.ErrRegistrationUnavailable
		}
		copyFiles := *r.nativeFiles
		s.nativeFiles = &copyFiles
	}
	s.origin = s
	// Only the actual closed reader can set these private freshness bounds. All
	// real native work completes here, BEFORE the controlled SQL prefix. Missing
	// or failed physical reads preserve current identity for exact history only.
	reader, physicalErr := newBootstrapSourceRegistryReader(ctx, identity)
	if physicalErr == nil {
		var start, until time.Time
		var observeErr error
		if r.nativeFiles == nil {
			start, until, observeErr = reader.observeRegistries()
		} else {
			start, until, observeErr = reader.observeRegistriesWithNative(config, *r.nativeFiles)
		}
		reader.Close()
		if observeErr == nil && !start.IsZero() && start.Before(until) && time.Now().Before(until) {
			s.dependencyStart, s.dependencyUntil = start, until
		}
	}
	if ctx.Err() != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	return s, nil
}

type bootstrapSourceRegistryTerminalCheck struct {
	mu                               sync.Mutex
	origin                           *bootstrapSourceRegistryTerminalCheck
	failed                           atomic.Bool
	ctx                              context.Context
	identity                         *install.PreparedBootstrapSourceRegistriesV2
	tx                               pd.BootstrapSQL
	authorized, locked               bool
	dependencyStart, dependencyUntil time.Time
	identityUntil                    time.Time
	nativeFiles                      *BootstrapSourceNativeRegistryFiles
}

func (*bootstrapSourceRegistryTerminalCheck) MarshalJSON() ([]byte, error) {
	return nil, sec.ErrRegistrationUnavailable
}
func (*bootstrapSourceRegistryTerminalCheck) String() string {
	return "OriginalSourceRegistryTerminalCheck"
}
func (*bootstrapSourceRegistryTerminalCheck) GoString() string {
	return "OriginalSourceRegistryTerminalCheck"
}

func (s *bootstrapSourceRegistryTerminalCheck) fail() error {
	if s != nil {
		s.failed.Store(true)
		if s.origin != nil {
			s.origin.failed.Store(true)
		}
	}
	return sec.ErrRegistrationUnavailable
}

func (s *bootstrapSourceRegistryTerminalCheck) current(ctx context.Context) error {
	if s == nil || s.origin != s || s.failed.Load() || s.identity == nil || !minioTerminalContext(ctx, s.ctx) {
		return s.fail()
	}
	return nil
}

func (s *bootstrapSourceRegistryTerminalCheck) AuthorizeIdentity(ctx context.Context, tx pd.BootstrapSQL) (*pd.Timestamp, error) {
	if s == nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current(ctx) != nil || s.authorized || s.tx != nil || !pd.SameBootstrapTransaction(tx, tx) {
		return nil, s.fail()
	}
	s.tx = tx
	until, err := s.identity.AuthorizeIdentity(ctx, tx)
	if err != nil || until == nil {
		return nil, s.fail()
	}
	s.identityUntil, err = until.Time()
	if err != nil {
		return nil, s.fail()
	}
	s.authorized = true
	copyUntil := *until
	return &copyUntil, nil
}

func (s *bootstrapSourceRegistryTerminalCheck) identityCurrent(ctx context.Context, view pd.BootstrapReadSQL) error {
	if s.current(ctx) != nil || !s.authorized || !pd.SameBootstrapTransaction(s.tx, view) || s.identity.RecheckIdentity(ctx, view) != nil {
		return s.fail()
	}
	return nil
}

func (s *bootstrapSourceRegistryTerminalCheck) RecheckIdentity(ctx context.Context, view pd.BootstrapReadSQL) error {
	if s == nil {
		return sec.ErrRegistrationUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.identityCurrent(ctx, view)
}

func (s *bootstrapSourceRegistryTerminalCheck) DependencyDeadline() *pd.Timestamp {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.origin != s {
		_ = s.fail()
		return nil
	}
	if s.failed.Load() || s.dependencyUntil.IsZero() {
		return nil
	}
	return minioTerminalTimestamp(s.dependencyUntil)
}

func (s *bootstrapSourceRegistryTerminalCheck) fresh(ctx context.Context, view pd.BootstrapReadSQL) error {
	if s.identityCurrent(ctx, view) != nil || s.dependencyStart.IsZero() || s.dependencyUntil.IsZero() || s.identity.RecheckPhysicalFiles(ctx, view) != nil {
		return s.fail()
	}
	before, err := view.SampleTime(ctx)
	if err != nil || before.Before(s.dependencyStart) || !before.Before(s.dependencyUntil) || !before.Before(s.identityUntil) {
		return s.fail()
	}
	if s.nativeFiles != nil {
		for _, pin := range []install.BootstrapSourceFilePin{s.nativeFiles.RedisSources, s.nativeFiles.SecretAllowlist} {
			raw, err := readBootstrapNativeRegistryPin(pin)
			clear(raw)
			if err != nil {
				return s.fail()
			}
		}
	}
	// LAST sample follows every original identity and selected-file tail. The
	// caller's original transaction/final read view owns the clock floor latch.
	now, err := view.SampleTime(ctx)
	if err != nil || now.Before(before) || now.Before(s.dependencyStart) || !now.Before(s.dependencyUntil) || !now.Before(s.identityUntil) || ctx.Err() != nil {
		return s.fail()
	}
	return nil
}

func (s *bootstrapSourceRegistryTerminalCheck) LockReferences(ctx context.Context, tx pd.BootstrapSQL) error {
	if s == nil {
		return sec.ErrRegistrationUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locked {
		return s.fail()
	}
	if s.fresh(ctx, tx) != nil {
		return s.fail()
	}
	s.locked = true
	return nil
}

func (s *bootstrapSourceRegistryTerminalCheck) Recheck(ctx context.Context, view pd.BootstrapReadSQL) error {
	if s == nil {
		return sec.ErrRegistrationUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.locked {
		return s.fail()
	}
	return s.fresh(ctx, view)
}

var _ sec.BootstrapTerminalResource = (*BootstrapSourceRegistryTerminalResource)(nil)
var _ sec.BootstrapTerminalResourceCheck = (*bootstrapSourceRegistryTerminalCheck)(nil)
