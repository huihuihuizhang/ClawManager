package systembackupexecution

import (
	"context"
	"encoding/json"
	"reflect"
	"strconv"
	"time"

	"clawreef/internal/systembackup/worker"
	d "clawreef/internal/systembackupdispatch"
	k "clawreef/internal/systembackupkms"
	w "clawreef/internal/systembackupwire"
)

// The original encrypted journal/plan supplies this scope. The factory must
// authenticate a DIFFERENT, live controller/verifier Pod/SA and current unwrap
// permit from actual SQL/workload authority. A DTO/hash is never the grant.
type FormalCandidateReadScope struct {
	Authority          d.Authority
	Job                d.JobBinding
	Invocation         worker.Invocation
	Candidate          worker.FormalCaptureResult
	CapturePod         BoundPod
	CaptureGrantSHA256 string
}

// Each use is new, task/attempt/part scoped, and closed on every outcome.
// Identity must originate in mTLS/TokenReview/actual controller owner checks;
// DownwardAPI or an assertion from the capture process is insufficient.
type FormalCandidateKeyUse interface {
	w.Unwrapper
	Identity() FormalVerifierIdentity
	// Bound by the actual independent grant/capability/task authority. Zero
	// means unavailable; callers cannot turn it into an unbounded callback.
	ValidUntil() time.Time
	Recheck(context.Context, FormalCandidateReadScope) error
	Close()
}
type FormalCandidateKeyFactory func(context.Context, FormalCandidateReadScope) (FormalCandidateKeyUse, error)

// A controller may be Deployment/StatefulSet-owned; it must never borrow a
// verifier Job UID/JWT. OwnerKind/UID are independently resolved from the real
// controller Pod (following ReplicaSet to Deployment where necessary).
type FormalVerifierIdentity struct {
	Namespace, PodName, PodUID            string
	ServiceAccountName, ServiceAccountUID string
	OwnerKind, OwnerUID                   string
	GrantSHA256                           string
}

func (s FormalCandidateReadScope) ExpectedUnwrapAccess() (k.Access, error) {
	if s.Invocation.ProviderKey == nil || !worker.ValidateFormalCaptureResult(s.Invocation, &s.Candidate) {
		return k.Access{}, d.ErrNotReady
	}
	access := *s.Invocation.ProviderKey
	access.Operation = k.Unwrap
	return access, nil
}

type scopedFormalCandidateKeys struct {
	use               FormalCandidateKeyUse
	scope             FormalCandidateReadScope
	identity          FormalVerifierIdentity
	grantUntil, until time.Time
}

func cloneFormalReadScope(s FormalCandidateReadScope) (FormalCandidateReadScope, error) {
	raw, err := json.Marshal(s)
	var out FormalCandidateReadScope
	if err != nil || len(raw) > 1<<20 || json.Unmarshal(raw, &out) != nil {
		return out, d.ErrNotReady
	}
	return out, nil
}

func openFormalCandidateKeys(ctx context.Context, factory FormalCandidateKeyFactory, scope FormalCandidateReadScope) (*scopedFormalCandidateKeys, error) {
	if ctx == nil || ctx.Err() != nil || factory == nil || scope.Invocation.ProviderKey == nil || !worker.ValidateFormalCaptureResult(scope.Invocation, &scope.Candidate) || scope.CapturePod.UID == "" || scope.CapturePod.ServiceAccountUID == "" || !formalCandidateDigest(scope.CaptureGrantSHA256) {
		return nil, d.ErrNotReady
	}
	keyContext := scope.Invocation.ProviderKey.Request.Context
	if scope.Authority.TaskType != "backup" || scope.Authority.Phase != "capture" || scope.Authority.InstallationID != keyContext.InstallationID || scope.Authority.TaskPublicID != keyContext.BackupPublicID || strconv.FormatUint(scope.Authority.AttemptNo, 10) != keyContext.AttemptNo || scope.Authority.ConfigVersion == 0 || !formalCandidateDigest(scope.Authority.ConfigSHA256) || scope.CapturePod.Namespace != scope.Job.Namespace {
		return nil, d.ErrNotReady
	}
	frozen, err := cloneFormalReadScope(scope)
	if err != nil {
		return nil, err
	}
	forFactory, err := cloneFormalReadScope(frozen)
	if err != nil {
		return nil, err
	}
	use, err := factory(ctx, forFactory)
	if err != nil {
		if use != nil && !(reflect.ValueOf(use).Kind() == reflect.Pointer && reflect.ValueOf(use).IsNil()) {
			use.Close()
		}
		return nil, err
	}
	if use == nil || (reflect.ValueOf(use).Kind() == reflect.Pointer && reflect.ValueOf(use).IsNil()) {
		return nil, d.ErrNotReady
	}
	identity := use.Identity()
	grantUntil := use.ValidUntil()
	ownerOK := identity.OwnerKind == "Deployment" || identity.OwnerKind == "StatefulSet" || identity.OwnerKind == "Job"
	if identity.Namespace == "" || identity.PodName == "" || identity.PodUID == "" || identity.ServiceAccountName == "" || identity.ServiceAccountUID == "" || !ownerOK || identity.OwnerUID == "" || !formalCandidateDigest(identity.GrantSHA256) || identity.PodUID == scope.CapturePod.UID || identity.ServiceAccountUID == scope.CapturePod.ServiceAccountUID || identity.OwnerUID == scope.Job.UID || identity.GrantSHA256 == scope.CaptureGrantSHA256 {
		use.Close()
		return nil, d.ErrNotReady
	}
	until := grantUntil
	for _, bound := range []time.Time{scope.Authority.DeadlineAt, scope.Invocation.Request.Deadline, scope.Job.RelayExpiresAt} {
		if !bound.IsZero() && bound.Before(until) {
			until = bound
		}
	}
	if grantUntil.IsZero() || !time.Now().Before(until) {
		use.Close()
		return nil, d.ErrNotReady
	}
	keys := &scopedFormalCandidateKeys{use: use, scope: frozen, identity: identity, grantUntil: grantUntil, until: until}
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	if err = keys.recheck(ctx); err != nil {
		use.Close()
		return nil, err
	}
	return keys, nil
}

func (s *scopedFormalCandidateKeys) recheck(ctx context.Context) error {
	if s == nil || s.use == nil || ctx == nil || ctx.Err() != nil || !time.Now().Before(s.until) || !s.use.ValidUntil().Equal(s.grantUntil) || s.use.Identity() != s.identity {
		return w.ErrStreamAuthority
	}
	ctx, cancel := context.WithDeadline(ctx, s.until)
	defer cancel()
	copy, err := cloneFormalReadScope(s.scope)
	if err != nil {
		return err
	}
	if err = s.use.Recheck(ctx, copy); err != nil {
		return err
	}
	if !time.Now().Before(s.until) || !s.use.ValidUntil().Equal(s.grantUntil) || s.use.Identity() != s.identity {
		return w.ErrStreamAuthority
	}
	return nil
}
func (s *scopedFormalCandidateKeys) ValidUntil() time.Time {
	if s == nil {
		return time.Time{}
	}
	return s.until
}
func (s *scopedFormalCandidateKeys) RecheckStream(ctx context.Context) error { return s.recheck(ctx) }
func (s *scopedFormalCandidateKeys) Unwrap(ctx context.Context, expected w.KeyRequest, wrapped w.WrappedKey, use w.WithDEK) error {
	if s == nil || ctx == nil || ctx.Err() != nil || s.scope.Invocation.ProviderKey == nil || expected != s.scope.Invocation.ProviderKey.Request || wrapped.Request != expected || use == nil {
		return w.ErrStreamAuthority
	}
	ctx, cancel := context.WithDeadline(ctx, s.until)
	defer cancel()
	if err := s.recheck(ctx); err != nil {
		return err
	}
	if err := s.use.Unwrap(ctx, expected, wrapped, use); err != nil {
		return err
	}
	return s.recheck(ctx)
}
func (s *scopedFormalCandidateKeys) Close() {
	if s != nil && s.use != nil {
		s.use.Close()
		s.use = nil
	}
}
