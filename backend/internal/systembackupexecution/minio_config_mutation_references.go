package systembackupexecution

import (
	"context"
	"database/sql"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	ma "clawreef/internal/systembackupminioauthority"
	sec "clawreef/internal/systembackupsecurity"
	"k8s.io/client-go/kubernetes"
)

// A separate MUTATION-resource observation owner, not a BootstrapResourceCheck
// cast and not enabling/write authority. The actual config service must still
// authenticate the real session/admin/RBAC/strong-auth/nonce and all other
// resource/KEK/deployment owners. Only unchanged original six reference pins
// are supported; reference rotation requires a new original source install.
type OriginalMinIOConfigMutationReferences struct {
	origin  *OriginalMinIOConfigMutationReferences
	db      *sql.DB
	catalog *OriginalCatalogInitialInventory
	mu      sync.Mutex
	pending map[context.Context]*minioConfigMutationObservation
}

func NewOriginalMinIOConfigMutationReferences(db *sql.DB, kube kubernetes.Interface, in CatalogInitialInventoryTerminalInput) (*OriginalMinIOConfigMutationReferences, error) {
	if db == nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	catalog, e := NewOriginalCatalogInitialInventory(kube, in)
	if e != nil {
		return nil, e
	}
	r := &OriginalMinIOConfigMutationReferences{db: db, catalog: catalog, pending: map[context.Context]*minioConfigMutationObservation{}}
	r.origin = r
	return r, nil
}
func (*OriginalMinIOConfigMutationReferences) MarshalJSON() ([]byte, error) {
	return nil, sec.ErrRegistrationUnavailable
}
func (r *OriginalMinIOConfigMutationReferences) References() map[string]sec.ConfigMutationResourceValidator {
	out := map[string]sec.ConfigMutationResourceValidator{}
	if r != nil {
		for _, key := range r.catalog.TerminalKeys() {
			out[strings.TrimPrefix(key, "reference:")] = r
		}
	}
	return out
}
func (r *OriginalMinIOConfigMutationReferences) wanted() []sec.BootstrapSecretRef {
	refs := []sec.BootstrapSecretRef{r.catalog.record.Reference}
	for _, record := range r.catalog.base.refs {
		ref := record.Reference
		refs = append(refs, sec.BootstrapSecretRef{Purpose: string(ref.Purpose), IdentityHash: string(ref.IdentityHash), Version: ref.IdentityVersion})
	}
	return refs
}
func minioMutationReferencesMatch(current, proposed, wanted []sec.BootstrapSecretRef) bool {
	left, right := map[string]sec.BootstrapSecretRef{}, map[string]sec.BootstrapSecretRef{}
	for _, refs := range []struct {
		items  []sec.BootstrapSecretRef
		target map[string]sec.BootstrapSecretRef
	}{{current, left}, {proposed, right}} {
		for _, ref := range refs.items {
			if _, found := refs.target[ref.Purpose]; found {
				return false
			}
			refs.target[ref.Purpose] = ref
		}
	}
	for _, ref := range wanted {
		if left[ref.Purpose] != ref || right[ref.Purpose] != ref {
			return false
		}
	}
	return len(wanted) == 6
}
func (r *OriginalMinIOConfigMutationReferences) matches(in sec.ConfigMutationResourceInput) bool {
	if r == nil || r.origin != r || in.InstallationID() != r.catalog.record.Installation || in.Actor().UserID != r.catalog.base.grant.Actor.LocalAdminUserID {
		return false
	}
	slot := false
	for _, key := range r.catalog.TerminalKeys() {
		if key == in.Slot() {
			slot = true
		}
	}
	current, proposed := in.Configs()
	return slot && minioMutationReferencesMatch(current.References(), proposed.References(), r.wanted())
}
func (r *OriginalMinIOConfigMutationReferences) snapshot(ctx context.Context, q ma.SQLReader) (ma.SQLExpected, error) {
	snapshot, e := ma.ReadSQLCurrent(ctx, q, r.catalog.base.input.Pin)
	if e != nil {
		return ma.SQLExpected{}, e
	}
	grant, head, refs, e := snapshot.Declarations()
	expected, _, ce := snapshot.Comparison()
	if e != nil || ce != nil || expected.State != ma.StateActive || !reflect.DeepEqual(grant, r.catalog.base.grant) || !reflect.DeepEqual(head, r.catalog.base.head) || !reflect.DeepEqual(refs, r.catalog.base.refs) {
		return ma.SQLExpected{}, sec.ErrRegistrationUnavailable
	}
	return expected, nil
}
func (r *OriginalMinIOConfigMutationReferences) readBeforeLocks(ctx context.Context) (ma.SQLExpected, error) {
	tx, e := r.db.BeginTx(ctx, nil)
	if e != nil {
		return ma.SQLExpected{}, e
	}
	defer tx.Rollback()
	return r.snapshot(ctx, tx)
}
func (r *OriginalMinIOConfigMutationReferences) Prepare(ctx context.Context, in sec.ConfigMutationResourceInput) (sec.ConfigMutationResourceObservation, error) {
	if !minioTerminalContext(ctx, ctx) || !r.matches(in) {
		return nil, sec.ErrRegistrationUnavailable
	}
	current, proposed := in.Configs()
	r.mu.Lock()
	if old := r.pending[ctx]; old != nil {
		old.mu.Lock()
		valid := old.origin == old && !old.failed.Load() && old.prepared && old.currentSHA == current.SHA256() && old.proposedSHA == proposed.SHA256() && old.actor == in.Actor()
		old.mu.Unlock()
		r.mu.Unlock()
		if !valid {
			return nil, sec.ErrRegistrationUnavailable
		}
		return old, nil
	}
	if len(r.pending) >= 32 {
		r.mu.Unlock()
		return nil, sec.ErrRegistrationUnavailable
	}
	check := &minioConfigMutationObservation{owner: r, ctx: ctx, currentSHA: current.SHA256(), proposedSHA: proposed.SHA256(), actor: in.Actor(), started: time.Now().UTC().Truncate(time.Microsecond)}
	check.origin = check
	r.pending[ctx] = check
	r.mu.Unlock()
	context.AfterFunc(ctx, func() {
		r.mu.Lock()
		if r.pending[ctx] == check {
			delete(r.pending, ctx)
		}
		r.mu.Unlock()
	})
	check.mu.Lock()
	defer check.mu.Unlock()
	before, e := r.readBeforeLocks(ctx)
	if e != nil {
		return nil, check.fail()
	}
	deadline := check.started.Add(25 * time.Second)
	if r.catalog.record.Until.Before(deadline) {
		deadline = r.catalog.record.Until
	}
	if end, ok := ctx.Deadline(); !ok {
		return nil, check.fail()
	} else if end.Before(deadline) {
		deadline = end
	}
	active, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	recovery, e := prepareMinIORecoverySession(active, r.db, r.catalog.base.input.RecoverySource, r.catalog.base.input.PermissionSource)
	if e != nil {
		return nil, check.fail()
	}
	observed, e := observeOriginalMinIOPermissionsRecovered(active, r.catalog.base.kube, r.catalog.base.input.DefinitionFile, r.catalog.base.input.DefinitionSHA256, recovery)
	if e != nil || r.catalog.observeRecovery(active, recovery) != nil {
		return nil, check.fail()
	}
	after, e := r.readBeforeLocks(active)
	if e != nil || !reflect.DeepEqual(before, after) || r.catalog.local() != nil || !time.Now().Before(deadline) {
		return nil, check.fail()
	}
	if observed.Until.Before(deadline) {
		deadline = observed.Until
	}
	if !time.Now().Before(deadline) {
		return nil, check.fail()
	}
	check.expected, check.until, check.prepared = after, deadline, true
	check.recovery = recovery
	if recovery != nil && recovery.until.Before(check.until) {
		check.until = recovery.until
	}
	if !time.Now().Before(check.until) {
		return nil, check.fail()
	}
	return check, nil
}

type minioConfigMutationObservation struct {
	recovery                *minioRecoverySession
	mu                      sync.Mutex
	origin                  *minioConfigMutationObservation
	owner                   *OriginalMinIOConfigMutationReferences
	ctx                     context.Context
	actor                   sec.RegistrationActor
	currentSHA, proposedSHA string
	expected                ma.SQLExpected
	started, until          time.Time
	tx                      *sql.Tx
	prepared                bool
	failed                  atomic.Bool
}

func (c *minioConfigMutationObservation) fail() error {
	if c != nil {
		c.failed.Store(true)
		if c.origin != nil {
			c.origin.failed.Store(true)
		}
	}
	return sec.ErrRegistrationUnavailable
}
func (*minioConfigMutationObservation) MarshalJSON() ([]byte, error) {
	return nil, sec.ErrRegistrationUnavailable
}
func (c *minioConfigMutationObservation) Risk() sec.ConfigMutationRisk {
	if c == nil || c.origin != c || c.failed.Load() {
		return sec.ConfigMutationRisk{SecurityBoundary: true, ProtectionReduction: true}
	}
	return sec.ConfigMutationRisk{}
}
func (c *minioConfigMutationObservation) ValidUntil() time.Time {
	if c == nil || c.origin != c || c.failed.Load() || !c.prepared {
		return time.Time{}
	}
	return c.until
}

// The resolver supplies its already-authoritative transaction time. Rechecks
// never sample raw UTC_TIMESTAMP or open a nested transaction/provider call.
type minioMutationControlledSQL struct {
	*sql.Tx
	now time.Time
}

func (r minioMutationControlledSQL) SampleTime(ctx context.Context) (time.Time, error) {
	if ctx == nil || ctx.Err() != nil || r.Tx == nil || r.now.IsZero() {
		return time.Time{}, sec.ErrRegistrationUnavailable
	}
	return r.now, nil
}
func (c *minioConfigMutationObservation) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if c == nil {
		return sec.ErrRegistrationUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.origin != c || c.failed.Load() || !c.prepared || !minioTerminalContext(ctx, c.ctx) || tx == nil || c.tx != nil && c.tx != tx || now.Before(c.started) || !now.Before(c.until) || !time.Now().Before(c.until) || c.owner.catalog.local() != nil {
		return c.fail()
	}
	c.tx = tx
	snapshot, e := ma.ReadSQLCurrentCandidate(ctx, minioMutationControlledSQL{tx, now}, c.owner.catalog.base.input.Pin)
	if e != nil {
		return c.fail()
	}
	expected, checkedAt, e := snapshot.Comparison()
	if e != nil || !checkedAt.Equal(now) || !reflect.DeepEqual(expected, c.expected) || c.recovery.recheck(snapshot, now) != nil {
		return c.fail()
	}
	return nil
}

var _ sec.ConfigMutationResourceValidator = (*OriginalMinIOConfigMutationReferences)(nil)
var _ sec.ConfigMutationResourceObservation = (*minioConfigMutationObservation)(nil)
