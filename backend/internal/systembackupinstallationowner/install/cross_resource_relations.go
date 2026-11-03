package install

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	backup "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/worker"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

const OriginalCrossResourceRelationsVersion = "original-bootstrap-cross-resource-relations.v1"

// This owner JOINS the actual checks from ONE authenticated terminal attempt.
// No caller may supply a check map, Passed value, authority or future task.
// The existing signed original mapping binds this constructor and every real
// member; no new signature/authorization protocol is introduced.
type OriginalCrossResourceRelations struct{ capture *CaptureSigningConsumer }

func NewOriginalCrossResourceRelations(capture *CaptureSigningConsumer) (*OriginalCrossResourceRelations, error) {
	if capture == nil {
		return nil, ErrInstall
	}
	for _, path := range []string{capture.sourceFile, capture.sourcePinFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, ErrInstall
		}
	}
	return &OriginalCrossResourceRelations{capture: capture}, nil
}
func (*OriginalCrossResourceRelations) TerminalKeys() []string       { return []string{"cross_resources"} }
func (*OriginalCrossResourceRelations) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (*OriginalCrossResourceRelations) Prepare(context.Context, sec.OfflineBootstrapGrant, sec.BootstrapConfig) (sec.BootstrapResourceCheck, error) {
	return nil, ErrInstall
}
func (r *OriginalCrossResourceRelations) BindingSHA256() (string, error) {
	if r == nil || r.capture == nil {
		return "", ErrInstall
	}
	// Deliberately no final mapping hash: that signed mapping contains this
	// binding. Its signature/current source are verified by the real terminal.
	raw, e := canonical(struct{ Version, Consumer, IndependentPin string }{OriginalCrossResourceRelationsVersion, r.capture.sourceFile, r.capture.sourcePinFile})
	if e != nil {
		return "", ErrInstall
	}
	return hash(raw), nil
}
func (r *OriginalCrossResourceRelations) PrepareTerminalResource(ctx context.Context, grant sec.OfflineBootstrapGrant, config sec.BootstrapConfig) (sec.BootstrapTerminalResourceCheck, error) {
	if r == nil || r.capture == nil || consumerNil(ctx) || ctx.Err() != nil || config.SHA256() != grant.ConfigSHA256 {
		return nil, ErrInstall
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return nil, ErrInstall
	}
	check := &originalCrossResourceCheck{ctx: ctx, resource: r, grant: grant, config: config}
	check.origin = check
	// It remains unusable until the private real terminal binds its actual
	// complete prepared graph below. A detached direct caller gets no authority.
	return check, nil
}

type originalCrossResourceMember struct {
	key, binding string
	resource     sec.BootstrapTerminalResource
	check        sec.BootstrapTerminalResourceCheck
}
type originalCrossResourceCheck struct {
	mu                 sync.Mutex
	origin             *originalCrossResourceCheck
	failed             atomic.Bool
	ctx                context.Context
	resource           *OriginalCrossResourceRelations
	grant              sec.OfflineBootstrapGrant
	config             sec.BootstrapConfig
	parent             *bootstrapTerminalSession
	members            []originalCrossResourceMember
	tx                 pd.BootstrapSQL
	authorized, locked bool
}

func (*originalCrossResourceCheck) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (c *originalCrossResourceCheck) fail() error {
	if c != nil {
		c.failed.Store(true)
		if c.origin != nil {
			c.origin.failed.Store(true)
		}
	}
	return ErrInstall
}

// This is intentionally package-private and accepts the concrete terminal,
// whose source, signed original mapping, selection and every owner binding
// were already authenticated by BootstrapTerminalOriginal.load. External
// Go adapters and JSON cannot bind a synthetic graph to this capability.
func bindOriginalCrossResourceRelations(s *bootstrapTerminalSession) error {
	if s == nil || s.original == nil || s.loaded == nil || !s.complete {
		return ErrInstall
	}
	c, actual := s.checks["cross_resources"].(*originalCrossResourceCheck)
	if !actual {
		return nil
	} // preserve other pre-existing concrete owner routes
	if c == nil || c.origin != c || c.parent != nil || c.resource == nil || c.resource.capture != s.original.capture || c.grant != s.grant || c.config.SHA256() != s.config.SHA256() || !consumerSameContext(c.ctx, s.ctx) {
		return c.fail()
	}
	keys := sec.MissingBootstrapOwnerAdapters(sec.BootstrapOwnerAdapters{})
	if len(s.loaded.bindings) != len(keys) || len(s.checks)+1 != len(keys) {
		return c.fail()
	}
	for _, key := range keys {
		if key == "reference:capture_signing" {
			continue
		}
		resource, check := s.original.resources[key], s.checks[key]
		if consumerNil(resource) || consumerNil(check) {
			return c.fail()
		}
		binding, e := resource.BindingSHA256()
		if e != nil || s.loaded.bindings[key] != binding {
			return c.fail()
		}
		if key == "cross_resources" {
			if resource != c.resource || check != c {
				return c.fail()
			}
			continue
		}
		c.members = append(c.members, originalCrossResourceMember{key: key, binding: binding, resource: resource, check: check})
	}
	c.parent = s
	return c.relations(s.ctx)
}

func (c *originalCrossResourceCheck) local(ctx context.Context) error {
	if c == nil || c.origin != c || c.failed.Load() || c.parent == nil || c.resource == nil || !consumerSameContext(ctx, c.ctx) || ctx.Err() != nil {
		return c.fail()
	}
	s := c.parent
	if s.origin != s || s.failed.Load() || s.original == nil || s.loaded == nil || s.original.capture != c.resource.capture || s.grant != c.grant || s.config.SHA256() != c.config.SHA256() || s.loaded.source.current(ctx) != nil || s.loaded.currentFiles(ctx) != nil {
		return c.fail()
	}
	for _, m := range c.members {
		if s.original.resources[m.key] != m.resource || s.checks[m.key] != m.check || s.loaded.bindings[m.key] != m.binding {
			return c.fail()
		}
	}
	return nil
}

// Actual exact registry bytes supply the relation values. Their individual
// original owner checks still supply physical scope/permissions/retained-key
// authority. This join neither reconstructs those observations nor replaces
// their current SQL checks with a registry hash or metadata success flag.
func originalCrossResourceRegistryRelations(config sec.BootstrapConfig, installation, namespace, namespaceUID string, registries map[string][]byte) error {
	validated, e := sec.DecodeBootstrapConfig(config.CanonicalJSON())
	if e != nil || validated.SHA256() != config.SHA256() {
		return ErrInstall
	}
	if len(registries) != len(config.Registries()) {
		return ErrInstall
	}
	byKind := map[string]sec.BootstrapRegistryRef{}
	for _, pin := range config.Registries() {
		if len(registries[pin.Kind]) == 0 || hash(registries[pin.Kind]) != pin.SHA256 {
			return ErrInstall
		}
		byKind[pin.Kind] = pin
	}
	var mapping FunctionalDisasterIdentityRegistry
	if decodeExact(registries["disaster_identity_mapping"], &mapping) != nil || mapping.SchemaVersion != FunctionalDisasterMappingVersion || mapping.Profile != FunctionalNonDRProfile || mapping.Installation != installation || mapping.Version != byKind["disaster_identity_mapping"].Version || mapping.State != "unavailable" {
		return ErrInstall
	}
	refs := config.References()
	sort.Slice(refs, func(a, b int) bool { return refs[a].Purpose < refs[b].Purpose })
	if len(mapping.Entries) != len(refs) {
		return ErrInstall
	}
	for n, entry := range mapping.Entries {
		ref := refs[n]
		if entry.Purpose != ref.Purpose || entry.IdentityHash != ref.IdentityHash || entry.ReferenceVersion != ref.Version || entry.State != "unavailable" || (entry.Reason != "not_provided" && entry.Reason != "not_provisioned" && entry.Reason != "source_dependent" && entry.Reason != "not_independently_observed") {
			return ErrInstall
		}
	}
	allow := byKind["secret_allowlist"]
	policy, e := backup.DecodeSecretCapturePolicy(registries["secret_allowlist"], allow.Version, allow.SHA256)
	if e != nil {
		return ErrInstall
	}
	// This projection is a JOIN only. B's actual owner decodes every original
	// parts field and compares it against two complete native source reads.
	var parts struct {
		SchemaVersion, Installation, Version string
		Secrets                              worker.ResourceCaptureSpec
	}
	if json.Unmarshal(registries["parts"], &parts) != nil || parts.SchemaVersion != "system-backup-original-source-parts.v2" || parts.Installation != installation || parts.Version != byKind["parts"].Version || parts.Secrets.Namespace != namespace || parts.Secrets.NamespaceUID != namespaceUID || parts.Secrets.Part != "secret_bundle" || policy.ValidateSelections(namespace, parts.Secrets.Selections) != nil {
		return ErrInstall
	}
	// Actual B metadata facts intentionally omit policy authority. The original
	// independent config-selected policy above authorizes the observed names;
	// B28 separately binds it to template.Discovery.SecretPolicy. If a selected
	// older producer includes policy bytes, they must still match exactly.
	if parts.Secrets.SecretPolicy != nil && !reflect.DeepEqual(*parts.Secrets.SecretPolicy, policy) {
		return ErrInstall
	}
	return nil
}
func (c *originalCrossResourceCheck) relations(ctx context.Context) error {
	if c.local(ctx) != nil {
		return c.fail()
	}
	registries := map[string][]byte{}
	files := sec.RegistrationFiles{RegistryDirectory: c.parent.loaded.registryDirectory}
	for _, pin := range c.config.Registries() {
		raw, e := files.RegistryBytes(pin.Kind, pin.Version, pin.SHA256)
		if e != nil {
			return c.fail()
		}
		registries[pin.Kind] = raw
	}
	if originalCrossResourceRegistryRelations(c.config, c.parent.loaded.mapping.Target.InstallationID, c.parent.loaded.mapping.Target.Namespace, c.parent.loaded.mapping.Target.NamespaceUID, registries) != nil {
		return c.fail()
	}
	return c.local(ctx)
}
func (c *originalCrossResourceCheck) identity(ctx context.Context, view pd.BootstrapReadSQL) error {
	if c.local(ctx) != nil || c.parent.guard == nil || !pd.SameBootstrapTransaction(c.tx, view) || !pd.SameBootstrapTransaction(c.parent.tx, view) || c.parent.guard.RecheckCandidateIdentity(ctx, view) != nil {
		return c.fail()
	}
	now, e := view.SampleTime(ctx)
	if e != nil || now.Before(c.parent.loaded.mapping.NotBefore) || !now.Before(c.parent.loaded.mapping.Until) {
		return c.fail()
	}
	return c.local(ctx)
}
func (c *originalCrossResourceCheck) AuthorizeIdentity(ctx context.Context, tx pd.BootstrapSQL) (*pd.Timestamp, error) {
	if c == nil {
		return nil, ErrInstall
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.authorized || !pd.SameBootstrapTransaction(tx, tx) {
		return nil, c.fail()
	}
	c.tx = tx
	if c.identity(ctx, tx) != nil {
		return nil, c.fail()
	}
	end, ok := terminalMinimum(c.parent.loaded.mapping.Until, c.parent.guard.IdentityDeadline())
	if !ok {
		return nil, c.fail()
	}
	c.authorized = true
	stamp := terminalTimestamp(end)
	return &stamp, nil
}
func (c *originalCrossResourceCheck) RecheckIdentity(ctx context.Context, view pd.BootstrapReadSQL) error {
	if c == nil {
		return ErrInstall
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.authorized {
		return c.fail()
	}
	return c.identity(ctx, view)
}
func (c *originalCrossResourceCheck) deadline() *pd.Timestamp {
	if c.local(c.ctx) != nil || !c.authorized || c.parent.guard == nil {
		return nil
	}
	end, ok := terminalMinimum(c.parent.loaded.mapping.Until, c.parent.guard.IdentityDeadline())
	if !ok {
		return nil
	}
	seen := map[sec.BootstrapTerminalResourceCheck]bool{}
	for _, m := range c.members {
		if !seen[m.check] {
			end, ok = terminalMinimum(end, m.check.DependencyDeadline())
			if !ok {
				return nil
			}
			seen[m.check] = true
		}
	}
	stamp := terminalTimestamp(end)
	return &stamp
}
func (c *originalCrossResourceCheck) DependencyDeadline() *pd.Timestamp {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.origin != c {
		_ = c.fail()
		return nil
	}
	return c.deadline()
}
func (c *originalCrossResourceCheck) fresh(ctx context.Context, view pd.BootstrapReadSQL) error {
	if !c.authorized || c.identity(ctx, view) != nil || c.relations(ctx) != nil {
		return c.fail()
	}
	deadline := c.deadline()
	if deadline == nil {
		return c.fail()
	}
	end, e := deadline.Time()
	if e != nil {
		return c.fail()
	}
	now, e := view.SampleTime(ctx)
	if e != nil || !now.Before(end) || !time.Now().Before(end) || ctx.Err() != nil {
		return c.fail()
	}
	return c.local(ctx)
}
func (c *originalCrossResourceCheck) LockReferences(ctx context.Context, tx pd.BootstrapSQL) error {
	if c == nil {
		return ErrInstall
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.locked || c.fresh(ctx, tx) != nil {
		return c.fail()
	}
	c.locked = true
	return nil
}
func (c *originalCrossResourceCheck) Recheck(ctx context.Context, view pd.BootstrapReadSQL) error {
	if c == nil {
		return ErrInstall
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.locked {
		return c.fail()
	}
	return c.fresh(ctx, view)
}

var _ sec.BootstrapTerminalResource = (*OriginalCrossResourceRelations)(nil)
var _ sec.BootstrapTerminalResourceCheck = (*originalCrossResourceCheck)(nil)
