package install

import (
	"context"
	"database/sql"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	sec "clawreef/internal/systembackupsecurity"
)

// Independently selected ORIGINAL consumer documents, not installer material,
// caller endpoints, an issuer private key, a bootstrap approval or a native
// observation. Both expected SHA values belong to deployment composition.
type OriginalSignerMutationSourceFiles struct {
	CaptureSourceFile, CaptureSourcePinFile, CaptureSourceSHA256 string
	SigningSourceFile, SigningSourcePinFile, SigningSourceSHA256 string
}
type OriginalSignerConfigMutationReferences struct {
	origin  *OriginalSignerConfigMutationReferences
	db      *sql.DB
	files   OriginalSignerMutationSourceFiles
	mu      sync.Mutex
	pending map[context.Context]*originalSignerMutationCheck
}

func NewOriginalSignerConfigMutationReferences(db *sql.DB, files OriginalSignerMutationSourceFiles) (*OriginalSignerConfigMutationReferences, error) {
	if db == nil || !digestPattern.MatchString(files.CaptureSourceSHA256) || !digestPattern.MatchString(files.SigningSourceSHA256) {
		return nil, ErrInstall
	}
	paths := map[string]bool{}
	for _, path := range []string{files.CaptureSourceFile, files.CaptureSourcePinFile, files.SigningSourceFile, files.SigningSourcePinFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || paths[path] {
			return nil, ErrInstall
		}
		paths[path] = true
	}
	r := &OriginalSignerConfigMutationReferences{db: db, files: files, pending: map[context.Context]*originalSignerMutationCheck{}}
	r.origin = r
	return r, nil
}
func (*OriginalSignerConfigMutationReferences) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (r *OriginalSignerConfigMutationReferences) References() map[string]sec.ConfigMutationResourceValidator {
	out := map[string]sec.ConfigMutationResourceValidator{}
	if r != nil {
		for _, purpose := range []string{"capture_signing", "acceptance_signing", "catalog_signing"} {
			out[purpose] = r
		}
	}
	return out
}
func originalSignerMutationSlot(slot string) bool {
	return slot == "reference:capture_signing" || slot == "reference:acceptance_signing" || slot == "reference:catalog_signing"
}
func (r *OriginalSignerConfigMutationReferences) Prepare(ctx context.Context, input sec.ConfigMutationResourceInput) (sec.ConfigMutationResourceObservation, error) {
	if r == nil || r.origin != r || !consumerSameContext(ctx, ctx) || ctx.Err() != nil || !originalSignerMutationSlot(input.Slot()) {
		return nil, ErrInstall
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, ErrInstall
	}
	current, proposed := input.Configs()
	// Reject an out-of-profile config before opening any provider credential.
	refs := []sec.BootstrapSecretRef{}
	for _, ref := range current.References() {
		if originalSignerMutationSlot("reference:" + ref.Purpose) {
			refs = append(refs, ref)
		}
	}
	if !owner.OriginalSignerFirstEnableScope(current, proposed, current.SHA256(), refs) {
		return nil, ErrInstall
	}
	r.mu.Lock()
	if previous := r.pending[ctx]; previous != nil {
		previous.mu.Lock()
		same := previous.origin == previous && !previous.failed.Load() && previous.inner != nil && time.Now().Before(previous.inner.ValidUntil()) && previous.installation == input.InstallationID() && previous.actor == input.Actor() && previous.currentSHA == current.SHA256() && previous.proposedSHA == proposed.SHA256()
		previous.mu.Unlock()
		r.mu.Unlock()
		if !same {
			return nil, ErrInstall
		}
		return previous, nil
	}
	if len(r.pending) >= 32 {
		r.mu.Unlock()
		return nil, ErrInstall
	}
	check := &originalSignerMutationCheck{owner: r, ctx: ctx, installation: input.InstallationID(), actor: input.Actor(), currentSHA: current.SHA256(), proposedSHA: proposed.SHA256()}
	check.origin = check
	r.pending[ctx] = check
	r.mu.Unlock()
	context.AfterFunc(ctx, func() {
		r.mu.Lock()
		if r.pending[ctx] == check {
			delete(r.pending, ctx)
		}
		r.mu.Unlock()
		check.mu.Lock()
		check.close()
		check.mu.Unlock()
	})
	check.mu.Lock()
	defer check.mu.Unlock()
	ok := false
	defer func() {
		if !ok {
			check.close()
		}
	}()
	pin, e := ReadPrivateFile(r.files.CaptureSourcePinFile, 64)
	if e != nil || string(pin) != r.files.CaptureSourceSHA256 {
		return nil, check.fail()
	}
	capture := NewCaptureSigningConsumer(r.files.CaptureSourceFile, r.files.CaptureSourcePinFile)
	check.capture, e = capture.load(ctx)
	if e != nil || check.capture.request == nil || check.capture.request.observer == nil || check.capture.physical(ctx) != nil {
		return nil, check.fail()
	}
	check.signers, e = OpenPinnedSigningResourceConsumer(ctx, r.files.SigningSourceFile, r.files.SigningSourcePinFile, r.files.SigningSourceSHA256)
	if e != nil {
		return nil, check.fail()
	}
	check.inner, e = owner.PrepareOriginalSignerMutationResources(ctx, r.db, check.capture.validator, check.signers.resource, input)
	if e != nil || check.inner == nil || check.inner.ValidUntil().IsZero() || check.capture.current(ctx) != nil || check.signers.current(ctx) != nil {
		return nil, check.fail()
	}
	ok = true
	return check, nil
}

type originalSignerMutationCheck struct {
	mu                                    sync.Mutex
	origin                                *originalSignerMutationCheck
	owner                                 *OriginalSignerConfigMutationReferences
	ctx                                   context.Context
	installation, currentSHA, proposedSHA string
	actor                                 sec.RegistrationActor
	capture                               *consumerCaptureState
	signers                               *SigningResourceConsumer
	inner                                 sec.ConfigMutationResourceObservation
	tx                                    *sql.Tx
	prefixTx                              *sql.Tx
	lastSQL                               time.Time
	closed                                bool
	failed                                atomic.Bool
}

func (*originalSignerMutationCheck) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (s *originalSignerMutationCheck) fail() error {
	if s != nil {
		s.failed.Store(true)
		if s.origin != nil {
			s.origin.failed.Store(true)
		}
	}
	return ErrInstall
}
func (s *originalSignerMutationCheck) close() {
	if s == nil || s.closed {
		return
	}
	s.closed = true
	if s.capture != nil && s.capture.request != nil {
		s.capture.request.observer.Close()
	}
	if s.signers != nil {
		s.signers.Close()
	}
}
func (s *originalSignerMutationCheck) Risk() sec.ConfigMutationRisk {
	if s == nil || s.origin != s || s.failed.Load() || s.inner == nil {
		return sec.ConfigMutationRisk{SecurityBoundary: true, ProtectionReduction: true}
	}
	return s.inner.Risk()
}
func (s *originalSignerMutationCheck) ValidUntil() time.Time {
	if s == nil || s.origin != s || s.failed.Load() || s.inner == nil {
		return time.Time{}
	}
	return s.inner.ValidUntil()
}
func (s *originalSignerMutationCheck) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	return s.recheck(ctx, tx, now, false)
}

// The actual mutation readiness assembly MUST call this concrete observation
// prefix before its ordinary resource Recheck loop / MinIO source locks.
// Three aliases share this same object, so one call locks capture head/grant
// -> acceptance head/grant -> catalog head/grant. It does not write/enable or
// borrow bootstrap authorization. An unwired prefix fails the later Recheck.
func (s *originalSignerMutationCheck) RecheckOriginalSignerPrefix(ctx context.Context, tx *sql.Tx, now time.Time) error {
	return s.recheck(ctx, tx, now, true)
}
func (s *originalSignerMutationCheck) recheck(ctx context.Context, tx *sql.Tx, now time.Time, prefix bool) error {
	if s == nil {
		return ErrInstall
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.origin != s || s.failed.Load() || s.closed || s.inner == nil || !consumerSameContext(ctx, s.ctx) || ctx.Err() != nil || tx == nil || s.tx != nil && s.tx != tx || now.IsZero() || now.Before(s.lastSQL) || s.capture == nil || s.signers == nil || s.capture.physical(ctx) != nil || s.signers.current(ctx) != nil {
		return s.fail()
	}
	s.tx = tx
	if !prefix && s.prefixTx != tx {
		return s.fail()
	}
	if prefix && s.prefixTx == tx {
		if now.IsZero() || !now.Before(s.inner.ValidUntil()) || !time.Now().Before(s.inner.ValidUntil()) {
			return s.fail()
		}
		s.lastSQL = now
		return nil
	}
	if s.inner.Recheck(ctx, tx, now) != nil || s.capture.current(ctx) != nil || s.signers.current(ctx) != nil {
		return s.fail()
	}
	if prefix {
		s.prefixTx = tx
	}
	s.lastSQL = now
	return nil
}

var _ sec.ConfigMutationResourceValidator = (*OriginalSignerConfigMutationReferences)(nil)
var _ sec.ConfigMutationResourceObservation = (*originalSignerMutationCheck)(nil)
