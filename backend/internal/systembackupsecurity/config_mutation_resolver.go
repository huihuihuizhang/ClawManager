package systembackupsecurity

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"time"
	"unicode/utf8"
)

// Owner validators resolve real resources before SQL locks, including schema,
// capability, exact identity/version, TLS/SSRF, retained references and current
// environment policy. They cannot be replaced by bootstrap/read grants or JSON
// approval flags. A check uses only local immutable/SQL state and never commits.
type ConfigMutationResourceValidator interface {
	Prepare(context.Context, ConfigMutationResourceInput) (ConfigMutationResourceObservation, error)
}
type ConfigMutationResourceObservation interface {
	Risk() ConfigMutationRisk
	ValidUntil() time.Time
	Recheck(context.Context, *sql.Tx, time.Time) error
}
type ConfigMutationDeploymentObservation interface {
	Enabled() bool
	ValidUntil() time.Time
	Recheck(context.Context, *sql.Tx, time.Time) error
}
type ConfigMutationResolverSources struct {
	// RegistryBytes must read only deployment-owned local immutable files. It
	// is also called inside the transaction to recheck every exact byte pin.
	RegistryBytes  func(kind, version, digest string) ([]byte, error)
	Registries     map[string]ConfigMutationResourceValidator
	References     map[string]ConfigMutationResourceValidator
	CrossResources ConfigMutationResourceValidator
	// The deployment switch is independently observed, never inferred from
	// the request's enabled value or the old last_effective_enabled column.
	Deployment func(context.Context, string) (ConfigMutationDeploymentObservation, error)
}

type ConfigMutationRegistryPair struct {
	Current, Proposed         BootstrapRegistryRef
	CurrentJSON, ProposedJSON []byte
}
type configMutationReferencePair struct{ current, proposed BootstrapSecretRef }

// This immutable view carries business snapshots, not write authorization.
// Byte/slice getters return copies, including for cross-resource validators.
type ConfigMutationResourceInput struct {
	installation      string
	actor             RegistrationActor
	current, proposed ConfigValues
	slot              string
	registries        map[string]ConfigMutationRegistryPair
	references        map[string]configMutationReferencePair
}

func (i ConfigMutationResourceInput) InstallationID() string   { return i.installation }
func (i ConfigMutationResourceInput) Actor() RegistrationActor { return i.actor }
func (i ConfigMutationResourceInput) Slot() string             { return i.slot }
func (i ConfigMutationResourceInput) Configs() (ConfigValues, ConfigValues) {
	return i.current, i.proposed
}
func (ConfigMutationResourceInput) MarshalJSON() ([]byte, error) { return nil, ErrConfigMutation }
func (i ConfigMutationResourceInput) RegistryPair(kind string) (ConfigMutationRegistryPair, bool) {
	p, ok := i.registries[kind]
	p.CurrentJSON = append([]byte(nil), p.CurrentJSON...)
	p.ProposedJSON = append([]byte(nil), p.ProposedJSON...)
	return p, ok
}
func (i ConfigMutationResourceInput) ReferencePair(purpose string) (BootstrapSecretRef, BootstrapSecretRef, bool) {
	p, ok := i.references[purpose]
	return p.current, p.proposed, ok
}

type PinnedConfigMutationResolver struct {
	installation string
	database     DatabaseIdentity
	sources      ConfigMutationResolverSources
}

func MissingConfigMutationResolverAdapters(s ConfigMutationResolverSources) []string {
	missing := []string{}
	for _, kind := range bootstrapRegistryKinds {
		if nilConfigMutationBoundary(s.Registries[kind]) {
			missing = append(missing, "registry:"+kind)
		}
	}
	for _, purpose := range bootstrapReferencePurposes {
		if nilConfigMutationBoundary(s.References[purpose]) {
			missing = append(missing, "reference:"+purpose)
		}
	}
	if s.RegistryBytes == nil {
		missing = append(missing, "registry_bytes")
	}
	if nilConfigMutationBoundary(s.CrossResources) {
		missing = append(missing, "cross_resources")
	}
	if s.Deployment == nil {
		missing = append(missing, "deployment_switch")
	}
	return missing
}
func NewPinnedConfigMutationResolver(installation string, database DatabaseIdentity, s ConfigMutationResolverSources) (*PinnedConfigMutationResolver, error) {
	if !configMutationInstallation.MatchString(installation) || !database.valid() || len(MissingConfigMutationResolverAdapters(s)) != 0 || len(s.Registries) != len(bootstrapRegistryKinds) || len(s.References) != len(bootstrapReferencePurposes) {
		return nil, ErrRegistrationUnavailable
	}
	owned := s
	owned.Registries, owned.References = map[string]ConfigMutationResourceValidator{}, map[string]ConfigMutationResourceValidator{}
	for kind, v := range s.Registries {
		owned.Registries[kind] = v
	}
	for purpose, v := range s.References {
		owned.References[purpose] = v
	}
	return &PinnedConfigMutationResolver{installation, database, owned}, nil
}

type configMutationObservedResource struct {
	check ConfigMutationResourceObservation
	risk  ConfigMutationRisk
	until time.Time
}
type preparedConfigMutationReadiness struct {
	resolver        *PinnedConfigMutationResolver
	input           ConfigMutationResourceInput
	checks          []configMutationObservedResource
	deployment      ConfigMutationDeploymentObservation
	deploymentUntil time.Time
	enabled         bool
	until           time.Time
	risk            ConfigMutationRisk
}

func (r *preparedConfigMutationReadiness) DeploymentEnabled() bool { return r != nil && r.enabled }
func (r *preparedConfigMutationReadiness) ValidUntil() time.Time {
	if r == nil {
		return time.Time{}
	}
	return r.until
}

func (r *PinnedConfigMutationResolver) registryBytes(pin BootstrapRegistryRef) ([]byte, error) {
	raw, err := r.sources.RegistryBytes(pin.Kind, pin.Version, pin.SHA256)
	if err != nil || len(raw) < 2 || len(raw) > 262144 {
		return nil, ErrRegistrationUnavailable
	}
	raw = append([]byte(nil), raw...)
	if registrationHash(string(raw)) != pin.SHA256 || !json.Valid(raw) || !providerJSONUnicode(raw) || !providerUniqueJSON(json.NewDecoder(bytes.NewReader(raw))) {
		return nil, ErrRegistrationUnavailable
	}
	return raw, nil
}

func (r *PinnedConfigMutationResolver) Prepare(ctx context.Context, installation string, actor RegistrationActor, current, proposed ConfigValues) (ConfigMutationReadiness, error) {
	fail := func() (ConfigMutationReadiness, error) { return nil, ErrRegistrationUnavailable }
	if r == nil || !configMutationInstallation.MatchString(r.installation) || !r.database.valid() || len(MissingConfigMutationResolverAdapters(r.sources)) != 0 || ctx == nil || ctx.Err() != nil || installation != r.installation || actor.UserID < 1 || actor.Subject == "" || len(actor.Subject) > 256 || !utf8.ValidString(actor.Subject) || actor.Session == "" || len(actor.Session) > 256 || !utf8.ValidString(actor.Session) || len(current.CanonicalJSON()) < 2 || len(proposed.CanonicalJSON()) < 2 {
		return fail()
	}
	in := ConfigMutationResourceInput{installation: installation, actor: actor, current: current, proposed: proposed, registries: map[string]ConfigMutationRegistryPair{}, references: map[string]configMutationReferencePair{}}
	oldPins := map[string]BootstrapRegistryRef{}
	for _, pin := range current.Registries() {
		oldPins[pin.Kind] = pin
	}
	for _, pin := range proposed.Registries() {
		if ctx.Err() != nil {
			return fail()
		}
		old := oldPins[pin.Kind]
		a, err := r.registryBytes(old)
		if err != nil {
			return fail()
		}
		b, err := r.registryBytes(pin)
		if err != nil {
			return fail()
		}
		in.registries[pin.Kind] = ConfigMutationRegistryPair{old, pin, a, b}
	}
	oldRefs := map[string]BootstrapSecretRef{}
	for _, ref := range current.References() {
		oldRefs[ref.Purpose] = ref
	}
	for _, ref := range proposed.References() {
		in.references[ref.Purpose] = configMutationReferencePair{oldRefs[ref.Purpose], ref}
	}
	// Classify actual RBAC contents even if an owner adapter misses the change.
	// Permission/self-grant/last-admin enforcement remains in Authority under
	// SQL locks, so this readiness phase cannot turn a 403 into not_ready.
	rbac := in.registries["rbac_bindings"]
	oldBindings, oldAdmins, err := configMutationRoleBindings(rbac.CurrentJSON, rbac.Current, installation)
	if err != nil || oldAdmins == 0 {
		return fail()
	}
	newBindings, _, err := configMutationRoleBindings(rbac.ProposedJSON, rbac.Proposed, installation)
	if err != nil {
		return fail()
	}
	baseRisk := configMutationBaseRisk(current, proposed)
	baseRisk.SecurityBoundary = baseRisk.SecurityBoundary || !reflect.DeepEqual(oldBindings, newBindings)
	d, err := r.sources.Deployment(ctx, installation)
	if err != nil || nilConfigMutationBoundary(d) {
		return fail()
	}
	deploymentUntil := d.ValidUntil()
	if deploymentUntil.IsZero() {
		return fail()
	}
	p := &preparedConfigMutationReadiness{resolver: r, input: in, deployment: d, deploymentUntil: deploymentUntil, enabled: d.Enabled(), until: deploymentUntil, risk: baseRisk}
	prepare := func(slot string, v ConfigMutationResourceValidator) error {
		if ctx.Err() != nil {
			return ErrRegistrationUnavailable
		}
		input := in
		input.slot = slot
		check, err := v.Prepare(ctx, input)
		if err != nil || nilConfigMutationBoundary(check) {
			return ErrRegistrationUnavailable
		}
		until := check.ValidUntil()
		if until.IsZero() {
			return ErrRegistrationUnavailable
		}
		o := configMutationObservedResource{check, check.Risk(), until}
		p.checks = append(p.checks, o)
		if o.until.Before(p.until) {
			p.until = o.until
		}
		p.risk.SecurityBoundary = p.risk.SecurityBoundary || o.risk.SecurityBoundary
		p.risk.ProtectionReduction = p.risk.ProtectionReduction || o.risk.ProtectionReduction
		return nil
	}
	for _, kind := range bootstrapRegistryKinds {
		if prepare("registry:"+kind, r.sources.Registries[kind]) != nil {
			return fail()
		}
	}
	for _, purpose := range bootstrapReferencePurposes {
		if prepare("reference:"+purpose, r.sources.References[purpose]) != nil {
			return fail()
		}
	}
	if prepare("cross_resources", r.sources.CrossResources) != nil {
		return fail()
	}
	if ctx.Err() != nil {
		return fail()
	}
	return p, nil
}

func (p *preparedConfigMutationReadiness) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) (ConfigMutationRisk, error) {
	fail := func() (ConfigMutationRisk, error) { return ConfigMutationRisk{}, ErrRegistrationUnavailable }
	if p == nil || ctx == nil || ctx.Err() != nil || tx == nil || now.IsZero() || !now.Before(p.until) || p.resolver.database.check(ctx, tx) != nil {
		return fail()
	}
	for _, kind := range bootstrapRegistryKinds {
		pair := p.input.registries[kind]
		a, err := p.resolver.registryBytes(pair.Current)
		if err != nil || !bytes.Equal(a, pair.CurrentJSON) {
			return fail()
		}
		b, err := p.resolver.registryBytes(pair.Proposed)
		if err != nil || !bytes.Equal(b, pair.ProposedJSON) {
			return fail()
		}
	}
	if p.deployment.Recheck(ctx, tx, now) != nil {
		return fail()
	}
	for _, o := range p.checks {
		if ctx.Err() != nil || o.check.Recheck(ctx, tx, now) != nil {
			return fail()
		}
	}
	// Recheck frozen facts after every callback, including any callback that
	// accidentally mutated a different previously checked observation.
	if p.deployment.Enabled() != p.enabled || !p.deployment.ValidUntil().Equal(p.deploymentUntil) {
		return fail()
	}
	for _, o := range p.checks {
		if o.check.Risk() != o.risk || !o.check.ValidUntil().Equal(o.until) {
			return fail()
		}
	}
	if ctx.Err() != nil {
		return fail()
	}
	return p.risk, nil
}
