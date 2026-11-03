package install

import (
	"context"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	evidence "clawreef/internal/systembackupevidence"
	owner "clawreef/internal/systembackupinstallationowner"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

// BootstrapTerminalOriginal has NO other BootstrapCandidateAuthority input.
// It consumes the enrolled current source, independently signed original
// association, concrete resource owners, original capacity and actual evidence
// registry. Absent concrete owners close fresh use; there are no success stubs.
type BootstrapTerminalOriginal struct {
	capture   *CaptureSigningConsumer
	files     BootstrapTerminalFiles
	resources map[string]sec.BootstrapTerminalResource
}
type BootstrapTerminalFiles struct {
	MappingFile, MappingSHA256, SignatureFile, EvidenceFile, RegistryDirectory string
}

func NewBootstrapTerminalOriginal(capture *CaptureSigningConsumer, files BootstrapTerminalFiles, resources map[string]sec.BootstrapTerminalResource) (*BootstrapTerminalOriginal, error) {
	if capture == nil || !digestPattern.MatchString(files.MappingSHA256) {
		return nil, ErrInstall
	}
	known := map[string]bool{}
	for _, key := range sec.MissingBootstrapOwnerAdapters(sec.BootstrapOwnerAdapters{}) {
		known[key] = true
	}
	owned := make(map[string]sec.BootstrapTerminalResource, len(resources))
	for key, resource := range resources {
		if !known[key] || key == "reference:capture_signing" || consumerNil(resource) || reflect.TypeOf(resource).Kind() != reflect.Pointer {
			return nil, ErrInstall
		}
		declared := false
		keys := map[string]bool{}
		for _, ownedKey := range resource.TerminalKeys() {
			if !known[ownedKey] || keys[ownedKey] || ownedKey == "reference:capture_signing" {
				return nil, ErrInstall
			}
			keys[ownedKey] = true
			if ownedKey == key {
				declared = true
			}
		}
		if !declared {
			return nil, ErrInstall
		}
		owned[key] = resource
	}
	return &BootstrapTerminalOriginal{capture: capture, files: files, resources: owned}, nil
}
func (*BootstrapTerminalOriginal) String() string               { return "EnrolledBootstrapTerminalOriginal" }
func (*BootstrapTerminalOriginal) GoString() string             { return "EnrolledBootstrapTerminalOriginal" }
func (*BootstrapTerminalOriginal) MarshalJSON() ([]byte, error) { return nil, ErrInstall }

func (a *BootstrapTerminalOriginal) PrepareBootstrapCandidates(ctx context.Context, grant sec.OfflineBootstrapGrant, config sec.BootstrapConfig, request pd.BootstrapConsumptionRequest) (sec.PreparedBootstrapCandidateAuthority, error) {
	var zero sec.PreparedBootstrapCandidateAuthority
	if a == nil || a.capture == nil || consumerNil(ctx) || ctx.Err() != nil {
		return zero, ErrInstall
	}
	if len(a.MissingTerminalResources()) != 0 {
		return zero, ErrInstall
	}
	loaded, e := a.load(ctx, grant, config, request)
	if e != nil {
		return zero, e
	}
	defer loaded.source.request.observer.Close()
	capture, e := loaded.source.validator.PrepareCandidateAttempt(ctx, grant, config, loaded.request)
	if e != nil {
		return zero, e
	}
	state := &bootstrapTerminalSession{ctx: ctx, original: a, loaded: loaded, grant: grant, config: loaded.config, request: loaded.request, hash: pd.Hash(loaded.mapping.SelectionSHA256), capture: capture, checks: map[string]sec.BootstrapTerminalResourceCheck{}}
	state.origin = state
	preparedBySource := map[sec.BootstrapTerminalResource]sec.BootstrapTerminalResourceCheck{}
	for _, key := range sec.MissingBootstrapOwnerAdapters(sec.BootstrapOwnerAdapters{}) {
		if key == "reference:capture_signing" {
			continue
		}
		resource := a.resources[key]
		if consumerNil(resource) {
			return zero, ErrInstall
		}
		binding, e := resource.BindingSHA256()
		if e != nil || loaded.bindings[key] != binding {
			return zero, ErrInstall
		}
		check := preparedBySource[resource]
		if consumerNil(check) {
			check, e = resource.PrepareTerminalResource(ctx, grant, config)
			if e != nil || consumerNil(check) || reflect.TypeOf(check).Kind() != reflect.Pointer {
				return zero, ErrInstall
			}
			preparedBySource[resource] = check
			state.ordered = append(state.ordered, check)
		}
		state.checks[key] = check
	}
	state.complete = len(state.checks)+1 == len(sec.MissingBootstrapOwnerAdapters(sec.BootstrapOwnerAdapters{}))
	// Bind the actual same-attempt checks only after EVERY real owner has
	// prepared under the authenticated original mapping. No caller graph/DTO.
	if bindOriginalCrossResourceRelations(state) != nil {
		return zero, ErrInstall
	}
	// Read the original capacity report last, after all potentially slow owner
	// observations. Its original observation time is never refreshed here.
	capacity, e := sec.NewBootstrapCandidateCapacity(sec.DatabaseIdentity{ServerUUID: grant.ServerUUID, Database: grant.Database}, loaded.mapping.CapacityReportFile)
	if e != nil {
		return zero, e
	}
	preparedCapacity, e := capacity.PrepareAttempt(ctx, grant, config)
	if e != nil {
		return zero, e
	}
	state.capacity = preparedCapacity
	if loaded.source.current(ctx) != nil || loaded.currentFiles(ctx) != nil {
		return zero, ErrInstall
	}
	return sec.PreparedBootstrapCandidateAuthority{Session: state, CapacityObservedAt: preparedCapacity.CapacityObservedAt()}, nil
}

type bootstrapTerminalSession struct {
	mu                                                     sync.Mutex
	origin                                                 *bootstrapTerminalSession
	ctx                                                    context.Context
	original                                               *BootstrapTerminalOriginal
	loaded                                                 *bootstrapTerminalLoaded
	grant                                                  sec.OfflineBootstrapGrant
	config                                                 sec.BootstrapConfig
	request                                                pd.BootstrapConsumptionRequest
	hash                                                   pd.Hash
	capture                                                *owner.PreparedCaptureSigning
	guard                                                  *owner.OwnerGuard
	capacity                                               *sec.PreparedBootstrapCandidateCapacity
	reservation                                            *sec.BootstrapCandidateCapacityReservation
	checks                                                 map[string]sec.BootstrapTerminalResourceCheck
	ordered                                                []sec.BootstrapTerminalResourceCheck
	evidenceLock                                           *evidence.BootstrapOriginalEvidenceLock
	tx                                                     pd.BootstrapSQL
	grants                                                 []*pd.GrantRecord
	receipts                                               []*pd.ReceiptRecord
	runs                                                   []*pd.RunRecord
	histories                                              []*pd.HistoricalBindingRecord
	targets                                                []*pd.TargetRecord
	references                                             []pd.ReferenceRecord
	authorized, hosts, refs, reserved, evidenced, complete bool
	failed                                                 atomic.Bool
}

func (*bootstrapTerminalSession) String() string               { return "BootstrapTerminalOriginalSession" }
func (*bootstrapTerminalSession) GoString() string             { return "BootstrapTerminalOriginalSession" }
func (*bootstrapTerminalSession) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (s *bootstrapTerminalSession) finish(e error) error {
	if e != nil && s != nil {
		s.failed.Store(true)
		if s.origin != nil {
			s.origin.failed.Store(true)
		}
	}
	return e
}
func (s *bootstrapTerminalSession) current(ctx context.Context, view pd.BootstrapReadSQL, request pd.BootstrapConsumptionRequest) error {
	if s == nil {
		return ErrInstall
	}
	if s.origin != s || s.failed.Load() || s.loaded == nil || s.loaded.source == nil || !consumerSameContext(ctx, s.ctx) || ctx.Err() != nil || !pd.SameBootstrapTransaction(s.tx, view) {
		return s.finish(ErrInstall)
	}
	hash, e := pd.BootstrapConsumptionHash(request)
	if e != nil || hash != s.hash || s.loaded.source.current(ctx) != nil || s.loaded.currentFiles(ctx) != nil {
		return s.finish(ErrInstall)
	}
	return nil
}
func terminalTimestamp(t time.Time) pd.Timestamp {
	return pd.Timestamp(t.UTC().Format("2006-01-02T15:04:05.000000Z"))
}
func terminalMinimum(current time.Time, deadline *pd.Timestamp) (time.Time, bool) {
	if deadline == nil {
		return time.Time{}, false
	}
	limit, e := deadline.Time()
	if e != nil {
		return time.Time{}, false
	}
	if limit.Before(current) {
		return limit, true
	}
	return current, true
}
func (s *bootstrapTerminalSession) Authorize(ctx context.Context, tx pd.BootstrapSQL, request pd.BootstrapConsumptionRequest, domain pd.DomainRecord, now time.Time) (pd.BootstrapConsumptionAdmission, error) {
	var zero pd.BootstrapConsumptionAdmission
	if s == nil {
		return zero, ErrInstall
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.authorized || !s.complete || s.capture == nil || !pd.SameBootstrapTransaction(tx, tx) {
		return zero, s.finish(ErrInstall)
	}
	s.tx = tx
	if e := s.current(ctx, tx, request); e != nil {
		return zero, e
	}
	if now.Before(s.loaded.mapping.NotBefore) || !now.Before(s.loaded.mapping.Until) || domain.Scope != request.Scope || string(domain.IssuerIdentityHash) != s.loaded.mapping.ProducerIssuerIdentitySHA256 || domain.Admission.Unconfigured == nil || domain.Admission.Configured != nil || !reflect.DeepEqual(*domain.Admission.Unconfigured, *request.Candidates[0].Request.Admission.Unconfigured) || s.loaded.authorizeRBAC() != nil {
		return zero, s.finish(ErrInstall)
	}
	var e error
	s.guard, e = s.capture.AuthorizeCandidate(ctx, tx)
	if e != nil {
		return zero, s.finish(e)
	}
	identity, ok := terminalMinimum(s.loaded.mapping.Until, s.guard.IdentityDeadline())
	if !ok {
		return zero, s.finish(ErrInstall)
	}
	// Current owner domains are checked at L2, before original operation/config.
	// A grouped MinIO check owns head -> grant -> sorted five ref locks here;
	// it is prepared/called once even when it supplies five purpose entries.
	for _, check := range s.ordered {
		limit, e := check.AuthorizeIdentity(ctx, tx)
		if e != nil {
			return zero, s.finish(e)
		}
		identity, ok = terminalMinimum(identity, limit)
		if !ok {
			return zero, s.finish(ErrInstall)
		}
	}
	dependency, usable := terminalMinimum(identity, s.capture.DependencyDeadline())
	if usable && s.complete && s.loaded.hostUntil != nil {
		dependency, usable = terminalMinimum(dependency, s.loaded.hostUntil)
		if usable {
			dependency, usable = terminalMinimum(dependency, s.loaded.evidence.Deadline())
		}
		for _, check := range s.ordered {
			if usable {
				dependency, usable = terminalMinimum(dependency, check.DependencyDeadline())
			}
		}
	} else {
		usable = false
	}
	if !usable {
		dependency = time.Date(1000, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	after, e := tx.SampleTime(ctx)
	if e != nil || after.Before(now) || !after.Before(identity) {
		return zero, s.finish(ErrInstall)
	}
	s.authorized = true
	return pd.BootstrapConsumptionAdmission{BindingHash: s.hash, IdentityExpiresAt: terminalTimestamp(identity), DependencyExpiresAt: terminalTimestamp(dependency)}, nil
}
func (s *bootstrapTerminalSession) LockHosts(ctx context.Context, tx pd.BootstrapSQL, request pd.BootstrapConsumptionRequest, facts pd.BootstrapConsumptionFacts) error {
	if s == nil {
		return ErrInstall
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.current(ctx, tx, request); e != nil {
		return e
	}
	if !s.authorized || !s.complete || s.hosts || facts.Replayed || s.loaded.hostUntil == nil {
		return s.finish(ErrInstall)
	}
	if e := s.lockHosts(ctx, tx, facts); e != nil {
		return s.finish(e)
	}
	s.hosts = true
	return nil
}
func (s *bootstrapTerminalSession) LockReferences(ctx context.Context, tx pd.BootstrapSQL, request pd.BootstrapConsumptionRequest, facts pd.BootstrapConsumptionFacts) error {
	if s == nil {
		return ErrInstall
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.current(ctx, tx, request); e != nil {
		return e
	}
	if !s.hosts || s.refs || facts.Replayed || s.loaded.source.physical(ctx) != nil {
		return s.finish(ErrInstall)
	}
	if e := s.lockTargets(ctx, tx, facts); e != nil {
		return s.finish(e)
	}
	for _, check := range s.ordered {
		if check.LockReferences(ctx, tx) != nil {
			return s.finish(ErrInstall)
		}
	}
	if e := s.capture.RecheckCandidateResource(ctx, tx); e != nil {
		return s.finish(e)
	}
	s.refs = true
	return nil
}
func (s *bootstrapTerminalSession) Reserve(ctx context.Context, tx pd.BootstrapSQL, request pd.BootstrapConsumptionRequest, facts pd.BootstrapConsumptionFacts) error {
	if s == nil {
		return ErrInstall
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.current(ctx, tx, request); e != nil {
		return e
	}
	if !s.refs || s.reserved || facts.Replayed || s.capacity == nil {
		return s.finish(ErrInstall)
	}
	var e error
	s.reservation, e = s.capacity.Reserve(ctx, tx)
	if e != nil {
		return s.finish(e)
	}
	s.reserved = true
	return nil
}
func (s *bootstrapTerminalSession) LockEvidence(ctx context.Context, tx pd.BootstrapSQL, request pd.BootstrapConsumptionRequest, facts pd.BootstrapConsumptionFacts) ([]pd.ResultEvidence, error) {
	if s == nil {
		return nil, ErrInstall
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.current(ctx, tx, request); e != nil {
		return nil, e
	}
	if !s.reserved || s.evidenced || facts.Replayed || !s.matchesEvidenceFacts(facts) {
		return nil, s.finish(ErrInstall)
	}
	if e := s.captureReferences(facts); e != nil {
		return nil, s.finish(e)
	}
	var outputs []pd.ResultEvidence
	var e error
	s.evidenceLock, outputs, e = s.loaded.evidence.Lock(ctx, tx)
	if e != nil {
		return nil, s.finish(e)
	}
	byID := map[pd.EvidenceID]pd.ResultEvidence{}
	for _, output := range outputs {
		byID[output.Evidence.EvidenceID] = output
	}
	expanded := make([]pd.ResultEvidence, 0, len(facts.Candidates))
	for _, candidate := range facts.Candidates {
		output, ok := byID[candidate.Receipt.Request.Evidence.EvidenceID]
		if !ok || !reflect.DeepEqual(output.Evidence, candidate.Receipt.Request.Evidence) {
			return nil, s.finish(ErrInstall)
		}
		expanded = append(expanded, output)
	}
	s.evidenced = true
	return expanded, nil
}
func (s *bootstrapTerminalSession) Recheck(ctx context.Context, view pd.BootstrapReadSQL, request pd.BootstrapConsumptionRequest, facts pd.BootstrapConsumptionFacts, now time.Time) error {
	if s == nil {
		return ErrInstall
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.current(ctx, view, request); e != nil {
		return e
	}
	if !s.authorized || s.guard == nil || now.Before(s.loaded.mapping.NotBefore) || !now.Before(s.loaded.mapping.Until) || s.loaded.authorizeRBAC() != nil {
		return s.finish(ErrInstall)
	}
	for _, check := range s.ordered {
		if check.RecheckIdentity(ctx, view) != nil {
			return s.finish(ErrInstall)
		}
	}
	if facts.Replayed {
		if s.hosts || s.refs || s.reserved || s.evidenced {
			return s.finish(ErrInstall)
		}
		return s.finish(s.guard.RecheckCandidateIdentity(ctx, view))
	}
	if !s.complete || !s.hosts || !s.refs || !s.reserved || !s.evidenced || s.reservation == nil || s.evidenceLock == nil || s.loaded.source.physical(ctx) != nil {
		return s.finish(ErrInstall)
	}
	if e := s.recheckSQLSources(ctx, view); e != nil {
		return s.finish(e)
	}
	for _, check := range s.ordered {
		if check.Recheck(ctx, view) != nil {
			return s.finish(ErrInstall)
		}
	}
	if s.reservation.Recheck(ctx, view) != nil || s.evidenceLock.Recheck(ctx, view) != nil {
		return s.finish(ErrInstall)
	}
	return s.finish(s.capture.RecheckCandidateResource(ctx, view))
}

var _ sec.BootstrapCandidateAuthority = (*BootstrapTerminalOriginal)(nil)
var _ sec.BootstrapCandidateAuthoritySession = (*bootstrapTerminalSession)(nil)
