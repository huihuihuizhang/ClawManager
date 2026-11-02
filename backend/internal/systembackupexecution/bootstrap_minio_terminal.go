package systembackupexecution

import (
	"context"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	ma "clawreef/internal/systembackupminioauthority"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
	"k8s.io/client-go/kubernetes"
)

// MinIOBootstrapTerminalInput is installed by the original deployment owner,
// never decoded from a request. Bundle is the original install transport; its
// signatures are verified against the independently selected enrollment pin.
// No observation, readiness bit, callback, private issuer key or DB is accepted.
type MinIOBootstrapTerminalInput struct {
	Pin                                          ma.SQLTrustPin
	BundleFile, BundleSHA256                     string
	GrantFile, GrantSHA256                       string
	DefinitionFile, DefinitionSHA256             string
	PermissionSource                             MinIOPublicationPermissionInput
	CapabilityIntentFile, CapabilityIntentSHA256 string
	ReferenceFiles                               []MinIOBootstrapReferenceFile
	ProvenanceFile                               string
}

type MinIOBootstrapReferenceFile struct {
	Purpose ma.Purpose
	File    string
}

type MinIOBootstrapTerminalResource struct {
	input   MinIOBootstrapTerminalInput
	kube    kubernetes.Interface
	grant   ma.SQLGrant
	head    ma.SQLHead
	refs    []ma.SQLReferenceRecord
	binding string
}

func NewMinIOBootstrapTerminalResource(kube kubernetes.Interface, input MinIOBootstrapTerminalInput) (*MinIOBootstrapTerminalResource, error) {
	if kube == nil || reflect.ValueOf(kube).Kind() == reflect.Pointer && reflect.ValueOf(kube).IsNil() {
		return nil, sec.ErrRegistrationUnavailable
	}
	for _, f := range [][2]string{{input.BundleFile, input.BundleSHA256}, {input.GrantFile, input.GrantSHA256}, {input.DefinitionFile, input.DefinitionSHA256}, {input.PermissionSource.File, input.PermissionSource.SHA256}, {input.CapabilityIntentFile, input.CapabilityIntentSHA256}} {
		if !filepath.IsAbs(f[0]) || filepath.Clean(f[0]) != f[0] || !formalCandidateDigest(f[1]) {
			return nil, sec.ErrRegistrationUnavailable
		}
	}
	input.Pin.IssuerPublic = append([]byte(nil), input.Pin.IssuerPublic...)
	input.ReferenceFiles = append([]MinIOBootstrapReferenceFile(nil), input.ReferenceFiles...)
	raw, e := pinnedDeploymentFile(input.BundleFile, input.BundleSHA256, 1<<20)
	if e != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	b, e := ma.DecodeSQLBundle(raw, ma.Digest(input.BundleSHA256))
	if e != nil || b.Action != ma.SQLActionInstall || b.PlanSHA256 != input.Pin.Enrollment.PlanSHA256 || b.EnrollmentDocumentSHA256 != input.Pin.Enrollment.DocumentSHA256 {
		return nil, sec.ErrRegistrationUnavailable
	}
	set, e := ma.VerifySQLRecordSet(input.Pin, b.Grant, b.GrantSignature, b.Head, b.HeadSignature, b.References)
	if e != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	g, h, refs, e := set.Detached()
	if e != nil || h.State != ma.StateActive || g.BootstrapGrantSHA256 != ma.Digest(input.GrantSHA256) || g.Observation.DefinitionSHA256 != ma.Digest(input.DefinitionSHA256) || g.Observation.CapabilityIntentSHA256 != ma.Digest(input.CapabilityIntentSHA256) {
		return nil, sec.ErrRegistrationUnavailable
	}
	if len(input.ReferenceFiles) != 5 || !filepath.IsAbs(input.ProvenanceFile) || filepath.Clean(input.ProvenanceFile) != input.ProvenanceFile {
		return nil, sec.ErrRegistrationUnavailable
	}
	for i, f := range input.ReferenceFiles {
		if f.Purpose != refs[i].Reference.Purpose || !filepath.IsAbs(f.File) || filepath.Clean(f.File) != f.File {
			return nil, sec.ErrRegistrationUnavailable
		}
	}
	wire, e := ce.Canonical(struct {
		Version string
		Input   MinIOBootstrapTerminalInput
	}{"original-minio-bootstrap-terminal-binding.v1", input})
	if e != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	return &MinIOBootstrapTerminalResource{input: input, kube: kube, grant: g, head: h, refs: refs, binding: hash(wire)}, nil
}

func (*MinIOBootstrapTerminalResource) String() string   { return "OriginalMinIOBootstrapTerminal" }
func (*MinIOBootstrapTerminalResource) GoString() string { return "OriginalMinIOBootstrapTerminal" }
func (*MinIOBootstrapTerminalResource) MarshalJSON() ([]byte, error) {
	return nil, sec.ErrRegistrationUnavailable
}
func (*MinIOBootstrapTerminalResource) TerminalKeys() []string {
	return []string{"reference:artifact_delete", "reference:artifact_read", "reference:artifact_write", "reference:catalog_append", "reference:catalog_read"}
}

// Install this map in A20: all five entries deliberately share this pointer.
func (r *MinIOBootstrapTerminalResource) TerminalResources() map[string]sec.BootstrapTerminalResource {
	if r == nil {
		return nil
	}
	out := map[string]sec.BootstrapTerminalResource{}
	for _, key := range r.TerminalKeys() {
		out[key] = r
	}
	return out
}
func (r *MinIOBootstrapTerminalResource) BindingSHA256() (string, error) {
	if r == nil || r.binding == "" {
		return "", sec.ErrRegistrationUnavailable
	}
	return r.binding, nil
}

// Legacy config-order admission cannot establish admin -> capture -> MinIO.
func (*MinIOBootstrapTerminalResource) Prepare(context.Context, sec.OfflineBootstrapGrant, sec.BootstrapConfig) (sec.BootstrapResourceCheck, error) {
	return nil, sec.ErrRegistrationUnavailable
}

func (r *MinIOBootstrapTerminalResource) PrepareTerminalResource(ctx context.Context, grant sec.OfflineBootstrapGrant, config sec.BootstrapConfig) (sec.BootstrapTerminalResourceCheck, error) {
	if r == nil || !minioTerminalContext(ctx, ctx) || !sec.ValidOfflineBootstrapGrant(grant) || grant.ConfigSHA256 != config.SHA256() {
		return nil, sec.ErrRegistrationUnavailable
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, sec.ErrRegistrationUnavailable
	}
	original, nb, end, e := sec.ReadBootstrapGrantFile(r.input.GrantFile, r.input.GrantSHA256)
	g := r.grant
	if e != nil || original != grant || grant.InstallationID != g.Target.InstallationID || grant.ServerUUID != g.Target.ServerUUID || grant.Database != g.Target.Database || grant.UserID != g.Actor.LocalAdminUserID || grant.Username != g.Actor.LocalAdminUsername || ma.Digest(config.SHA256()) != g.ConfigSHA256 {
		return nil, sec.ErrRegistrationUnavailable
	}
	byPurpose := map[string]sec.BootstrapSecretRef{}
	for _, ref := range config.References() {
		byPurpose[ref.Purpose] = ref
	}
	for _, ref := range r.refs {
		wanted := byPurpose[string(ref.Reference.Purpose)]
		if wanted.IdentityHash != string(ref.Reference.IdentityHash) || wanted.Version != ref.Reference.IdentityVersion {
			return nil, sec.ErrRegistrationUnavailable
		}
	}
	s := &minioBootstrapTerminalCheck{owner: r, ctx: ctx, start: g.NotBefore, identityUntil: g.Until}
	s.origin = s
	s.dependencyStart = time.Now().UTC().Truncate(time.Microsecond)
	if nb.After(s.start) {
		s.start = nb
	}
	if end.Before(s.identityUntil) {
		s.identityUntil = end
	}
	// Failure of real physical observation preserves ONLY current identity for
	// exact history. Nothing can set the private fresh deadline except observe.
	started := s.dependencyStart
	deadline := started.Add(time.Duration(g.Observation.MaximumAgeMicroseconds) * time.Microsecond)
	if s.identityUntil.Before(deadline) {
		deadline = s.identityUntil
	}
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d.UTC().Truncate(time.Microsecond)
	}
	physicalCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if until, err := r.observeTerminal(physicalCtx, started, deadline, &s.inventory); err == nil && time.Now().Before(until) {
		s.dependencyUntil = until
	}
	if ctx.Err() != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	return s, nil
}

func minioTerminalContext(ctx, original context.Context) bool {
	return ctx != nil && original != nil && reflect.ValueOf(ctx).Comparable() && reflect.ValueOf(original).Comparable() && ctx == original && ctx.Err() == nil
}

type minioBootstrapTerminalCheck struct {
	mu                                    sync.Mutex
	origin                                *minioBootstrapTerminalCheck
	failed                                atomic.Bool
	owner                                 *MinIOBootstrapTerminalResource
	ctx                                   context.Context
	tx                                    pd.BootstrapSQL
	start, identityUntil, dependencyUntil time.Time
	dependencyStart                       time.Time
	authorized, locked                    bool
	expected                              ma.SQLExpected
	inventory                             []MinIOBootstrapProbeObject
}

// Inventory is comparison/audit data only; it never admits a resource. Failed
// probes retain their fixed owned key with unknown outcome for owner review.
type MinIOBootstrapProbeObject struct{ Bucket, Key, Version, State string }

func (s *minioBootstrapTerminalCheck) ProbeInventory() []MinIOBootstrapProbeObject {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]MinIOBootstrapProbeObject(nil), s.inventory...)
}

func (*minioBootstrapTerminalCheck) MarshalJSON() ([]byte, error) {
	return nil, sec.ErrRegistrationUnavailable
}
func (*minioBootstrapTerminalCheck) String() string   { return "OriginalMinIOTerminalCheck" }
func (*minioBootstrapTerminalCheck) GoString() string { return "OriginalMinIOTerminalCheck" }
func (s *minioBootstrapTerminalCheck) fail() error {
	if s != nil {
		s.failed.Store(true)
		if s.origin != nil {
			s.origin.failed.Store(true)
		}
	}
	return sec.ErrRegistrationUnavailable
}
func (s *minioBootstrapTerminalCheck) identity(ctx context.Context, q pd.BootstrapReadSQL, initial bool) (time.Time, error) {
	if s.origin != s || s.failed.Load() || !minioTerminalContext(ctx, s.ctx) || !pd.SameBootstrapTransaction(s.tx, q) {
		return time.Time{}, s.fail()
	}
	snapshot, e := ma.ReadSQLCurrentCandidate(ctx, q, s.owner.input.Pin)
	if e != nil {
		return time.Time{}, s.fail()
	}
	g, h, refs, e := snapshot.Declarations()
	expected, now, ce := snapshot.Comparison()
	// Signed reference lifetimes belong to fresh resource use. Exact history
	// checks current SQL identity/revocation and original grant/head windows.
	if e != nil || ce != nil || !reflect.DeepEqual(g, s.owner.grant) || !reflect.DeepEqual(h, s.owner.head) || !reflect.DeepEqual(refs, s.owner.refs) || expected.State != ma.StateActive || now.Before(s.start) || !now.Before(s.identityUntil) || !initial && !reflect.DeepEqual(expected, s.expected) {
		return time.Time{}, s.fail()
	}
	if initial {
		s.expected = expected
	}
	return now, nil
}
func minioTerminalTimestamp(t time.Time) *pd.Timestamp {
	v := pd.Timestamp(t.UTC().Format("2006-01-02T15:04:05.000000Z"))
	return &v
}
func (s *minioBootstrapTerminalCheck) AuthorizeIdentity(ctx context.Context, tx pd.BootstrapSQL) (*pd.Timestamp, error) {
	if s == nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.authorized || !pd.SameBootstrapTransaction(tx, tx) {
		return nil, s.fail()
	}
	s.tx = tx
	if _, e := s.identity(ctx, tx, true); e != nil {
		return nil, e
	}
	s.authorized = true
	return minioTerminalTimestamp(s.identityUntil), nil
}
func (s *minioBootstrapTerminalCheck) RecheckIdentity(ctx context.Context, q pd.BootstrapReadSQL) error {
	if s == nil {
		return sec.ErrRegistrationUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.authorized {
		return s.fail()
	}
	_, e := s.identity(ctx, q, false)
	return e
}
func (s *minioBootstrapTerminalCheck) DependencyDeadline() *pd.Timestamp {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.origin != s || s.failed.Load() || s.dependencyUntil.IsZero() {
		return nil
	}
	return minioTerminalTimestamp(s.dependencyUntil)
}
func (s *minioBootstrapTerminalCheck) fresh(ctx context.Context, q pd.BootstrapReadSQL) error {
	if !s.authorized || s.dependencyUntil.IsZero() {
		return s.fail()
	}
	now, e := s.identity(ctx, q, false)
	if e != nil || now.Before(s.dependencyStart) || !now.Before(s.dependencyUntil) {
		return s.fail()
	}
	for _, ref := range s.owner.refs {
		r := ref.Reference
		if now.Before(r.NotBefore) || !now.Before(r.Until) || !now.Before(r.ProtectedUntil) {
			return s.fail()
		}
	}
	return nil
}
func (s *minioBootstrapTerminalCheck) LockReferences(ctx context.Context, tx pd.BootstrapSQL) error {
	if s == nil {
		return sec.ErrRegistrationUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locked {
		return s.fail()
	}
	if e := s.fresh(ctx, tx); e != nil {
		return e
	}
	s.locked = true
	return nil
}
func (s *minioBootstrapTerminalCheck) Recheck(ctx context.Context, q pd.BootstrapReadSQL) error {
	if s == nil {
		return sec.ErrRegistrationUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.locked {
		return s.fail()
	}
	return s.fresh(ctx, q)
}

// Keep the legacy interface explicit; no raw transaction adapter is provided.
var _ sec.BootstrapTerminalResource = (*MinIOBootstrapTerminalResource)(nil)
var _ sec.BootstrapTerminalResourceCheck = (*minioBootstrapTerminalCheck)(nil)
