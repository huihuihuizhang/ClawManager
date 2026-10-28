package systembackupsecurity

import (
	"bytes"
	"context"
	"database/sql"
	"time"
)

// Internal verified facts, NOT a grant/issuer wire format. Only independently
// reviewed deployment authenticators may produce these. They must verify the
// real grant bytes/signature, issuer, principal, purpose, current revocation,
// immutable version and every binding; echoing request claims is not a verifier.
type configMaintenancePurpose uint8

const (
	configMaintenanceWrite configMaintenancePurpose = iota + 1
	configMaintenanceObserve
)

type configMaintenanceGrantFacts struct {
	actorIssuer, principal, issuer, grantID, version string
	grantBytesSHA256, revocationVersion              string
	purpose                                          configMaintenancePurpose
	bindings                                         configMaintenanceIdentity
	key, requestSHA256                               string
	notBefore, expiresAt                             time.Time
}

type configMaintenanceSourceFacts struct {
	provenance           ConfigBackfillProvenanceFacts
	verificationVersion  string
	notBefore, expiresAt time.Time
}

type configMaintenanceAuthorityPins struct {
	database                                     DatabaseIdentity
	installation, actor                          string
	schemaSHA256, catalogSHA256, migrationSHA256 string
}

type configMaintenanceAuthoritySources struct {
	// Independently verify the CURRENT installed target/schema/catalog/ledger,
	// rather than only the pins present in an authenticated grant.
	CurrentTarget    func(context.Context, *sql.Tx, time.Time) (configMaintenanceAuthorityPins, error)
	WriteGrant       func(context.Context, *sql.Tx, configMaintenanceScope, time.Time) (configMaintenanceGrantFacts, error)
	ObservationGrant func(context.Context, *sql.Tx, configMaintenanceScope, time.Time) (configMaintenanceGrantFacts, error)
	OriginalArchive  func(context.Context, *sql.Tx, configMaintenanceScope, []byte, time.Time) (configMaintenanceSourceFacts, error)
	ReserveMetadata  func(context.Context, *sql.Tx, configMaintenanceScope, configMaintenanceBudget, time.Time) (ConfigMutationCapacityReservation, error)
}

// Mandatory source functions are trusted deployment configuration, not request
// fields. All callbacks use only local/SQL work, never commit the supplied tx,
// and must enforce their own real grant/archive/provider/physical-capacity ACLs.
// No concrete authenticator, runtime grant, source or default allow-all exists.
type pinnedConfigMaintenanceAuthority struct {
	pins    configMaintenanceAuthorityPins
	sources configMaintenanceAuthoritySources
}

var _ configMaintenanceAuthority = (*pinnedConfigMaintenanceAuthority)(nil)

func newPinnedConfigMaintenanceAuthority(pins configMaintenanceAuthorityPins, sources configMaintenanceAuthoritySources) (*pinnedConfigMaintenanceAuthority, error) {
	if !pins.database.valid() || !configMutationInstallation.MatchString(pins.installation) || !providerHashPattern.MatchString(pins.actor) || !providerHashPattern.MatchString(pins.schemaSHA256) || !providerHashPattern.MatchString(pins.catalogSHA256) || !providerHashPattern.MatchString(pins.migrationSHA256) || sources.CurrentTarget == nil || sources.WriteGrant == nil || sources.ObservationGrant == nil || sources.OriginalArchive == nil || sources.ReserveMetadata == nil {
		return nil, ErrRegistrationUnavailable
	}
	return &pinnedConfigMaintenanceAuthority{pins: pins, sources: sources}, nil
}

func (a *pinnedConfigMaintenanceAuthority) bound(scope configMaintenanceScope) bool {
	return a != nil && scope.valid() && scope.database == a.pins.database && scope.identity.Installation == a.pins.installation && scope.identity.Actor == a.pins.actor && scope.identity.SchemaSHA == a.pins.schemaSHA256 && scope.identity.CatalogSHA == a.pins.catalogSHA256 && scope.identity.MigrationSHA == a.pins.migrationSHA256 && a.sources.CurrentTarget != nil && a.sources.WriteGrant != nil && a.sources.ObservationGrant != nil && a.sources.OriginalArchive != nil && a.sources.ReserveMetadata != nil
}

func (a *pinnedConfigMaintenanceAuthority) currentTarget(ctx context.Context, tx *sql.Tx, now time.Time) error {
	current, err := a.sources.CurrentTarget(ctx, tx, now)
	if err != nil {
		return registrationBoundaryError(err)
	}
	if current != a.pins || ctx.Err() != nil {
		return ErrRegistrationUnavailable
	}
	return nil
}

func maintenanceAuthorityTime(notBefore, until, now time.Time) bool {
	return configMaintenanceSQLTime(notBefore) && configMaintenanceSQLTime(until) && until.After(notBefore) && !now.Before(notBefore) && now.Before(until)
}

func (g configMaintenanceGrantFacts) matches(scope configMaintenanceScope, purpose configMaintenancePurpose, now time.Time) bool {
	actor, actorErr := ConfigMaintenanceActorSHA256(g.actorIssuer, g.principal)
	grant, grantErr := ConfigMaintenanceGrantIdentitySHA256(g.issuer, g.grantID)
	if actorErr != nil || grantErr != nil || actor != scope.identity.Actor || g.purpose != purpose || g.bindings != scope.identity || g.key != scope.key || g.requestSHA256 != scope.hash || !bootstrapVersion.MatchString(g.version) || !bootstrapVersion.MatchString(g.revocationVersion) || !providerHashPattern.MatchString(g.grantBytesSHA256) || !maintenanceAuthorityTime(g.notBefore, g.expiresAt, now) {
		return false
	}
	// Current observation has its OWN authenticated grant. Its bindings still
	// refer to the ORIGINAL write request, including its old grant/version.
	return purpose == configMaintenanceObserve || purpose == configMaintenanceWrite && grant == scope.identity.Grant && g.version == scope.identity.GrantVersion
}

func (f configMaintenanceSourceFacts) matches(scope configMaintenanceScope, original []byte, now time.Time) bool {
	p := f.provenance
	_, digest, err := CanonicalConfigBackfillProvenance(p)
	return err == nil && digest == scope.identity.ProvenanceSHA && p.TargetServerUUID == scope.identity.Server && p.TargetDatabase == scope.identity.Database && p.InstallationID == scope.identity.Installation && p.Version == scope.identity.Version && p.ConfigSHA256 == scope.identity.ConfigSHA && p.ConfigSizeBytes == scope.identity.ConfigSize && int64(len(original)) == p.ConfigSizeBytes && registrationHash(string(original)) == p.ConfigSHA256 && bootstrapVersion.MatchString(f.verificationVersion) && maintenanceAuthorityTime(f.notBefore, f.expiresAt, now)
}

func maintenanceSameGrant(a, b configMaintenanceGrantFacts) bool {
	return a.actorIssuer == b.actorIssuer && a.principal == b.principal && a.issuer == b.issuer && a.grantID == b.grantID && a.version == b.version && a.grantBytesSHA256 == b.grantBytesSHA256 && a.revocationVersion == b.revocationVersion && a.purpose == b.purpose && a.bindings == b.bindings && a.key == b.key && a.requestSHA256 == b.requestSHA256 && a.notBefore.Equal(b.notBefore) && a.expiresAt.Equal(b.expiresAt)
}

func maintenanceSameSource(a, b configMaintenanceSourceFacts) bool {
	return a.provenance == b.provenance && a.verificationVersion == b.verificationVersion && a.notBefore.Equal(b.notBefore) && a.expiresAt.Equal(b.expiresAt)
}

type pinnedConfigMaintenanceAdmission struct {
	authority  *pinnedConfigMaintenanceAuthority
	tx         *sql.Tx
	scope      configMaintenanceScope
	original   []byte
	grant      configMaintenanceGrantFacts
	source     configMaintenanceSourceFacts
	until      time.Time
	observedAt time.Time
}

func (p *pinnedConfigMaintenanceAdmission) ValidUntil() time.Time {
	if p == nil {
		return time.Time{}
	}
	return p.until
}

func (*pinnedConfigMaintenanceAdmission) MarshalJSON() ([]byte, error) { return nil, ErrConfigMutation }

func (a *pinnedConfigMaintenanceAuthority) authorize(ctx context.Context, tx *sql.Tx, scope configMaintenanceScope, original []byte, now time.Time, purpose configMaintenancePurpose) (*pinnedConfigMaintenanceAdmission, error) {
	if ctx == nil || ctx.Err() != nil || tx == nil || !a.bound(scope) || len(original) < 2 || len(original) > 262144 || (purpose != configMaintenanceWrite && purpose != configMaintenanceObserve) {
		return nil, ErrRegistrationPermission
	}
	// Freeze again at this independent boundary. A verifier gets only copies.
	scope, original = cloneConfigMaintenanceScope(scope), append([]byte(nil), original...)
	values, err := DecodeConfigValues(original)
	if err != nil || !bytes.Equal(values.CanonicalJSON(), original) || int64(len(original)) != scope.identity.ConfigSize || registrationHash(string(original)) != scope.identity.ConfigSHA {
		return nil, ErrRegistrationPermission
	}
	start, err := configMaintenanceClock(ctx, tx, a.pins.database, now)
	if err != nil {
		return nil, err
	}
	verify := a.sources.WriteGrant
	if err := a.currentTarget(ctx, tx, start); err != nil {
		return nil, err
	}
	if purpose == configMaintenanceObserve {
		verify = a.sources.ObservationGrant
	}
	grant, err := verify(ctx, tx, cloneConfigMaintenanceScope(scope), start)
	if err != nil {
		return nil, registrationBoundaryError(err)
	}
	if !grant.matches(scope, purpose, start) {
		return nil, ErrRegistrationPermission
	}
	source, err := a.sources.OriginalArchive(ctx, tx, cloneConfigMaintenanceScope(scope), append([]byte(nil), original...), start)
	if err != nil {
		return nil, registrationBoundaryError(err)
	}
	if err := a.currentTarget(ctx, tx, start); err != nil {
		return nil, err
	}
	last, err := configMaintenanceClock(ctx, tx, a.pins.database, start)
	if err != nil {
		return nil, err
	}
	if !grant.matches(scope, purpose, last) || !source.matches(scope, original, last) {
		return nil, ErrRegistrationPermission
	}
	until := grant.expiresAt
	if source.expiresAt.Before(until) {
		until = source.expiresAt
	}
	return &pinnedConfigMaintenanceAdmission{authority: a, tx: tx, scope: scope, original: original, grant: grant, source: source, until: until, observedAt: last}, nil
}

func (a *pinnedConfigMaintenanceAuthority) AuthorizeWrite(ctx context.Context, tx *sql.Tx, scope configMaintenanceScope, original []byte, now time.Time) (configMaintenanceAdmission, error) {
	p, err := a.authorize(ctx, tx, scope, original, now, configMaintenanceWrite)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (a *pinnedConfigMaintenanceAuthority) AuthorizeObservation(ctx context.Context, tx *sql.Tx, scope configMaintenanceScope, original []byte, now time.Time) (configMaintenanceAdmission, error) {
	p, err := a.authorize(ctx, tx, scope, original, now, configMaintenanceObserve)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (p *pinnedConfigMaintenanceAdmission) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if p == nil || p.authority == nil || tx == nil || tx != p.tx || now.Before(p.observedAt) || !now.Before(p.until) {
		return ErrRegistrationPermission
	}
	fresh, err := p.authority.authorize(ctx, tx, p.scope, p.original, now, p.grant.purpose)
	if err != nil {
		return err
	}
	if !maintenanceSameGrant(p.grant, fresh.grant) || !maintenanceSameSource(p.source, fresh.source) || !p.until.Equal(fresh.until) {
		// The verifier returned valid CURRENT facts, but they no longer match
		// this admission. In particular, different bytes under the same grant
		// identity/version are unavailable per the accepted digest contract.
		return ErrRegistrationUnavailable
	}
	p.observedAt = fresh.observedAt
	return nil
}

func (a *pinnedConfigMaintenanceAuthority) Reserve(ctx context.Context, tx *sql.Tx, scope configMaintenanceScope, budget configMaintenanceBudget, now time.Time) (ConfigMutationCapacityReservation, error) {
	if ctx == nil || ctx.Err() != nil || tx == nil || !a.bound(scope) || (budget.canonicalWriteBytes != 0 && int64(budget.canonicalWriteBytes) != scope.identity.ConfigSize) || budget.receiptMaxBytes < 2 || budget.receiptMaxBytes > maxConfigMaintenanceReceiptBytes || budget.intentBytes < 2 || budget.intentBytes > 65536 || budget.resultBytes < 2 || budget.resultBytes > 65536 {
		return nil, ErrRegistrationUnavailable
	}
	start, err := configMaintenanceClock(ctx, tx, a.pins.database, now)
	if err != nil {
		return nil, err
	}
	if err := a.currentTarget(ctx, tx, start); err != nil {
		return nil, err
	}
	r, err := a.sources.ReserveMetadata(ctx, tx, cloneConfigMaintenanceScope(scope), budget, start)
	if err != nil {
		return nil, registrationBoundaryError(err)
	}
	if nilConfigMutationBoundary(r) {
		return nil, ErrRegistrationUnavailable
	}
	until := r.ValidUntil()
	if err := a.currentTarget(ctx, tx, start); err != nil {
		return nil, err
	}
	last, err := configMaintenanceClock(ctx, tx, a.pins.database, start)
	if err != nil || until.IsZero() || !last.Before(until) {
		return nil, ErrRegistrationUnavailable
	}
	return &pinnedConfigMaintenanceReservation{authority: a, tx: tx, inner: r, until: until, observedAt: last}, nil
}

type pinnedConfigMaintenanceReservation struct {
	authority         *pinnedConfigMaintenanceAuthority
	tx                *sql.Tx
	inner             ConfigMutationCapacityReservation
	until, observedAt time.Time
}

func (*pinnedConfigMaintenanceReservation) MarshalJSON() ([]byte, error) {
	return nil, ErrConfigMutation
}

func (p *pinnedConfigMaintenanceReservation) ValidUntil() time.Time {
	if p == nil {
		return time.Time{}
	}
	return p.until
}

func (p *pinnedConfigMaintenanceReservation) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if p == nil || p.authority == nil || ctx == nil || ctx.Err() != nil || tx == nil || tx != p.tx || nilConfigMutationBoundary(p.inner) || now.Before(p.observedAt) || !now.Before(p.until) {
		return ErrRegistrationUnavailable
	}
	if err := p.inner.Recheck(ctx, tx, now); err != nil {
		return registrationBoundaryError(err)
	}
	if err := p.authority.currentTarget(ctx, tx, now); err != nil {
		return err
	}
	last, err := configMaintenanceClock(ctx, tx, p.authority.pins.database, now)
	if err != nil || !last.Before(p.until) {
		return ErrRegistrationUnavailable
	}
	p.observedAt = last
	return nil
}
