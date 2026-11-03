package systembackupexecution

import (
	"bytes"
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	bs "clawreef/internal/systembackupbootstrapsecurity"
	ce "clawreef/internal/systembackupcontrolevidence"
	"clawreef/internal/systembackupinstallationowner/install"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
	"k8s.io/client-go/kubernetes"
)

type CatalogInitialInventoryTerminalInput struct {
	MinIO                        MinIOBootstrapTerminalInput
	LocationFile, LocationSHA256 string
}
type OriginalCatalogInitialInventory struct {
	input    CatalogInitialInventoryTerminalInput
	base     *MinIOBootstrapTerminalResource
	location CatalogInitialInventoryLocation
	record   install.CatalogInitialInventory
	binding  string
}

// One shared owner pointer for the original five roles AND catalog_snapshot.
// This avoids duplicate head/grant/reference lock acquisition and binds the
// exact same producer/SQL source, independently signed checkpoint and native
// immutable version. This adapter explicitly supports INITIAL inventory only.
func NewOriginalCatalogInitialInventory(kube kubernetes.Interface, in CatalogInitialInventoryTerminalInput) (*OriginalCatalogInitialInventory, error) {
	base, e := NewMinIOBootstrapTerminalResource(kube, in.MinIO)
	if e != nil {
		return nil, e
	}
	raw, e := pinnedDeploymentFile(in.LocationFile, in.LocationSHA256, 16384)
	var location CatalogInitialInventoryLocation
	if e != nil || decodePublicationCanonical(raw, &location) != nil || location.Version != "original-catalog-initial-inventory-location.v1" || location.DefinitionSHA256 != in.MinIO.DefinitionSHA256 || !minioTerminalVersion(location.VersionID) {
		return nil, sec.ErrRegistrationUnavailable
	}
	raw, e = pinnedDeploymentFile(location.EnvelopeFile, location.EnvelopeSHA256, 4096)
	var signed install.SignedCatalogInitialInventory
	if e != nil || decodePublicationCanonical(raw, &signed) != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	record, e := install.InspectCatalogInitialInventory(signed, in.MinIO.Pin.IssuerPublic)
	if e != nil || record.DefinitionSHA256 != in.MinIO.DefinitionSHA256 || location.Key != record.Key || location.Bucket != record.Bucket {
		return nil, sec.ErrRegistrationUnavailable
	}
	p, e := readMinIOPermissionProductionInputs(in.MinIO.DefinitionFile, in.MinIO.DefinitionSHA256)
	if e != nil {
		return nil, e
	}
	defer p.clear()
	ref, e := catalogInitialReference(p)
	if e != nil || record.Reference != ref || !catalogInitialMatches(record, p, in.MinIO.DefinitionSHA256) {
		return nil, sec.ErrRegistrationUnavailable
	}
	// The selected mode is inventory_read, never a failed LIST fallback. The
	// existing exact-read credential is joined through the same signed five-role
	// MinIO source; no seventh broad ListBucket credential is installed.
	scope, _ := ce.Canonical([]string{record.Bucket, record.CoveragePrefix, record.Key, "initial-checkpoint-at-captured-time"})
	descriptor, _ := ce.Canonical(map[string]string{"ref_kind": "catalog_credential", "purpose": "catalog_discovery", "identity_hash": ref.IdentityHash, "identity_version": ref.Version, "provider_identity_hash": record.ProviderSHA256, "scope_hash": hash(scope), "description_redacted": "Original signed initial inventory checkpoint; no later publication coverage", "provider_role": "catalog", "credential_capability": "inventory_read"})
	decoded, e := bs.DecodeSecurityReference(descriptor, hash(descriptor))
	if e != nil || !decoded.MatchesBootstrapPin(ref) {
		return nil, sec.ErrRegistrationUnavailable
	}
	baseSHA, e := base.BindingSHA256()
	if e != nil {
		return nil, e
	}
	wire, e := ce.Canonical(struct {
		Version, MinIOBinding string
		Input                 CatalogInitialInventoryTerminalInput
	}{"original-catalog-initial-inventory-terminal-binding.v1", baseSHA, in})
	if e != nil {
		return nil, e
	}
	return &OriginalCatalogInitialInventory{in, base, location, record, hash(wire)}, nil
}
func (*OriginalCatalogInitialInventory) TerminalKeys() []string {
	return []string{"reference:artifact_delete", "reference:artifact_read", "reference:artifact_write", "reference:catalog_append", "reference:catalog_read", "reference:catalog_snapshot"}
}
func (r *OriginalCatalogInitialInventory) TerminalResources() map[string]sec.BootstrapTerminalResource {
	out := map[string]sec.BootstrapTerminalResource{}
	if r != nil {
		for _, key := range r.TerminalKeys() {
			out[key] = r
		}
	}
	return out
}
func (r *OriginalCatalogInitialInventory) BindingSHA256() (string, error) {
	if r == nil || r.binding == "" {
		return "", sec.ErrRegistrationUnavailable
	}
	return r.binding, nil
}
func (*OriginalCatalogInitialInventory) MarshalJSON() ([]byte, error) {
	return nil, sec.ErrRegistrationUnavailable
}
func (*OriginalCatalogInitialInventory) Prepare(context.Context, sec.OfflineBootstrapGrant, sec.BootstrapConfig) (sec.BootstrapResourceCheck, error) {
	return nil, sec.ErrRegistrationUnavailable
}
func (r *OriginalCatalogInitialInventory) local() error {
	if r == nil || r.base == nil {
		return sec.ErrRegistrationUnavailable
	}
	raw, e := pinnedDeploymentFile(r.input.LocationFile, r.input.LocationSHA256, 16384)
	var location CatalogInitialInventoryLocation
	if e != nil || decodePublicationCanonical(raw, &location) != nil || location != r.location {
		return sec.ErrRegistrationUnavailable
	}
	raw, e = pinnedDeploymentFile(location.EnvelopeFile, location.EnvelopeSHA256, 4096)
	var signed install.SignedCatalogInitialInventory
	if e != nil || decodePublicationCanonical(raw, &signed) != nil {
		return sec.ErrRegistrationUnavailable
	}
	record, e := install.InspectCatalogInitialInventory(signed, r.base.input.Pin.IssuerPublic)
	if e != nil || record != r.record {
		return sec.ErrRegistrationUnavailable
	}
	return nil
}
func (r *OriginalCatalogInitialInventory) observe(ctx context.Context) error {
	if r.local() != nil {
		return sec.ErrRegistrationUnavailable
	}
	p, e := readMinIOPermissionProductionInputs(r.base.input.DefinitionFile, r.base.input.DefinitionSHA256)
	if e != nil {
		return e
	}
	defer p.clear()
	if !catalogInitialMatches(r.record, p, r.base.input.DefinitionSHA256) {
		return sec.ErrRegistrationUnavailable
	}
	var credential nativePublicationCredential
	for _, u := range p.uses {
		if u.principal.Purpose == "catalog_read" {
			credential = u.credential
		}
	}
	reader, e := newMinioPermissionHTTP(p.grant.Provider, credential)
	if e != nil {
		return e
	}
	defer reader.close()
	expected, e := pinnedDeploymentFile(r.location.EnvelopeFile, r.location.EnvelopeSHA256, 4096)
	if e != nil {
		return e
	}
	for _, version := range []string{"", r.location.VersionID, ""} {
		reply, e := minioTerminalProbeRequest(ctx, reader, r.location.Bucket, r.location.Key, version, http.MethodGet, nil, false, "")
		if e != nil || reply.status != 200 || reply.header.Get("X-Amz-Version-Id") != r.location.VersionID || !bytes.Equal(reply.body, expected) {
			return sec.ErrRegistrationUnavailable
		}
	}
	return r.local()
}
func (r *OriginalCatalogInitialInventory) PrepareTerminalResource(ctx context.Context, g sec.OfflineBootstrapGrant, config sec.BootstrapConfig) (sec.BootstrapTerminalResourceCheck, error) {
	if r == nil || !minioTerminalContext(ctx, ctx) || r.local() != nil || g.ConfigSHA256 != r.record.ConfigSHA256 || g.InstallationID != r.record.Installation {
		return nil, sec.ErrRegistrationUnavailable
	}
	found := false
	for _, ref := range config.References() {
		if ref == r.record.Reference {
			found = true
		}
	}
	if !found {
		return nil, sec.ErrRegistrationUnavailable
	}
	base, e := r.base.PrepareTerminalResource(ctx, g, config)
	if e != nil {
		return nil, e
	}
	check := &catalogInitialInventoryCheck{owner: r, base: base, ctx: ctx, started: time.Now().UTC().Truncate(time.Microsecond)}
	check.origin = check
	deadline := check.started.Add(25 * time.Second)
	if r.record.Until.Before(deadline) {
		deadline = r.record.Until
	}
	if end, ok := ctx.Deadline(); !ok {
		return nil, sec.ErrRegistrationUnavailable
	} else if end.Before(deadline) {
		deadline = end
	}
	active, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if r.observe(active) == nil && time.Now().Before(deadline) {
		check.until = deadline
	}
	if ctx.Err() != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	return check, nil
}

type catalogInitialInventoryCheck struct {
	mu                 sync.Mutex
	origin             *catalogInitialInventoryCheck
	owner              *OriginalCatalogInitialInventory
	base               sec.BootstrapTerminalResourceCheck
	ctx                context.Context
	tx                 pd.BootstrapSQL
	started, until     time.Time
	authorized, locked bool
	failed             atomic.Bool
}

func (*catalogInitialInventoryCheck) MarshalJSON() ([]byte, error) {
	return nil, sec.ErrRegistrationUnavailable
}
func (s *catalogInitialInventoryCheck) fail() error {
	if s != nil {
		s.failed.Store(true)
		if s.origin != nil {
			s.origin.failed.Store(true)
		}
	}
	return sec.ErrRegistrationUnavailable
}
func (s *catalogInitialInventoryCheck) current(ctx context.Context, q pd.BootstrapReadSQL, fresh bool) error {
	if s == nil || s.origin != s || s.failed.Load() || !minioTerminalContext(ctx, s.ctx) || !pd.SameBootstrapTransaction(s.tx, q) || s.owner.local() != nil {
		return s.fail()
	}
	now, e := q.SampleTime(ctx)
	if e != nil || now.Before(s.owner.record.NotBefore) || !now.Before(s.owner.record.Until) {
		return s.fail()
	}
	if fresh && (s.until.IsZero() || now.Before(s.started) || !now.Before(s.until) || !time.Now().Before(s.until)) {
		return s.fail()
	}
	return nil
}
func (s *catalogInitialInventoryCheck) AuthorizeIdentity(ctx context.Context, tx pd.BootstrapSQL) (*pd.Timestamp, error) {
	if s == nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.authorized || s.failed.Load() {
		return nil, s.fail()
	}
	s.tx = tx
	if s.current(ctx, tx, false) != nil {
		return nil, s.fail()
	}
	end, e := s.base.AuthorizeIdentity(ctx, tx)
	if e != nil || end == nil {
		return nil, s.fail()
	}
	t, e := end.Time()
	if e != nil {
		return nil, s.fail()
	}
	if s.owner.record.Until.Before(t) {
		t = s.owner.record.Until
	}
	s.authorized = true
	return minioTerminalTimestamp(t), nil
}
func (s *catalogInitialInventoryCheck) RecheckIdentity(ctx context.Context, q pd.BootstrapReadSQL) error {
	if s == nil {
		return sec.ErrRegistrationUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.authorized || s.current(ctx, q, false) != nil || s.base.RecheckIdentity(ctx, q) != nil {
		return s.fail()
	}
	return nil
}
func (s *catalogInitialInventoryCheck) DependencyDeadline() *pd.Timestamp {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.origin != s || s.failed.Load() || s.until.IsZero() {
		return nil
	}
	end := s.base.DependencyDeadline()
	if end == nil {
		return nil
	}
	t, e := end.Time()
	if e != nil {
		return nil
	}
	if s.until.Before(t) {
		t = s.until
	}
	return minioTerminalTimestamp(t)
}
func (s *catalogInitialInventoryCheck) LockReferences(ctx context.Context, tx pd.BootstrapSQL) error {
	if s == nil {
		return sec.ErrRegistrationUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.authorized || s.locked || s.current(ctx, tx, true) != nil || s.base.LockReferences(ctx, tx) != nil {
		return s.fail()
	}
	s.locked = true
	return nil
}
func (s *catalogInitialInventoryCheck) Recheck(ctx context.Context, q pd.BootstrapReadSQL) error {
	if s == nil {
		return sec.ErrRegistrationUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.locked || s.current(ctx, q, true) != nil || s.base.Recheck(ctx, q) != nil {
		return s.fail()
	}
	return nil
}

var _ sec.BootstrapTerminalResource = (*OriginalCatalogInitialInventory)(nil)
var _ sec.BootstrapTerminalResourceCheck = (*catalogInitialInventoryCheck)(nil)
