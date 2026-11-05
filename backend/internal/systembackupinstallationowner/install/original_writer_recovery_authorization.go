package install

import (
	"context"
	"database/sql"
	"time"

	c "clawreef/internal/systembackupcontroller"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OriginalWriterRecoveryAuthorization permits recovery of one genuine in-memory
// original set. It is neither a replacement hold nor renewed capture authority.
// After process death the journal is inspection data: this factory deliberately
// does not reconstruct actors or an Agent incarnation from caller DTOs.
type OriginalWriterRecoveryAuthorization struct {
	origin                          *OriginalWriterRecoveryAuthorization
	set                             *PreparedOriginalWriterSet
	operator                        *authenticatedOperator
	enrollment                      EnrollmentPin
	operation, inventory, prefixSHA string
	prefixLength                    int
	gate                            c.GateToken
	application                     originalApplicationGate
	journal                         *originalWriterJournal
	fence                           *originalWriterRecoveryFence
	providersStopped                bool
}

func (*OriginalWriterRecoveryAuthorization) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (*OriginalWriterRecoveryAuthorization) String() string {
	return "OriginalWriterRecoveryAuthorization"
}
func (*OriginalWriterRecoveryAuthorization) GoString() string {
	return "OriginalWriterRecoveryAuthorization"
}

// PrepareOriginalWriterRecovery reauthenticates the actual local administrator
// and Kubernetes owner with a NEW bounded context (at most two minutes). The
// original set supplies operation, actors, journal and registered providers.
// This also accepts an Acquire failure which returned no hold after real stops.
func (i *Installer) PrepareOriginalWriterRecovery(ctx context.Context, password []byte,
	enrollment EnrollmentPin, set *PreparedOriginalWriterSet) (*OriginalWriterRecoveryAuthorization, error) {
	if i == nil || set == nil {
		return nil, ErrInstall
	}
	set.mu.Lock()
	defer set.mu.Unlock()
	p := set.owner
	if set.origin != set || !set.used || p == nil || p.origin != p || p.operator == nil ||
		p.operator.installer != i || enrollment != p.enrollment || consumerSameContext(ctx, p.ctx) ||
		set.journal == nil || set.inventorySHA == "" ||
		p.token.Generation == 0 || p.token.Owner != "adoption:"+p.operation ||
		set.application.owner != p.token.Owner || set.application.scope == "" {
		return nil, ErrInstall
	}
	if p.commitUnknown || set.application.unknown || set.actualHold != nil && set.actualHold.adoptionUnknown {
		return nil, ErrCommitUnknown
	}
	// No old authentication is consulted: it may have expired or been cancelled.
	operator, err := i.authenticate(ctx, password)
	if err != nil || operator.userID != p.operator.userID || operator.authority(ctx, enrollment) != nil {
		return nil, ErrInstall
	}
	r := &OriginalWriterRecoveryAuthorization{set: set, operator: operator, enrollment: enrollment,
		operation: p.operation, inventory: set.inventorySHA, gate: p.token, application: set.application, journal: set.journal}
	r.origin = r
	r.fence = &originalWriterRecoveryFence{owner: p, operator: operator, authorization: r}
	if r.targetPermissions(ctx) != nil || r.readAuthority(ctx) != nil {
		return nil, ErrInstall
	}
	inspection, err := r.inspectOriginal(ctx)
	if err != nil {
		return nil, ErrInstall
	}
	r.prefixLength, r.prefixSHA = len(inspection.Records), inspection.TailSHA256
	r.fence.journalSHA = r.prefixSHA // provenance only; never an authorization input
	if h := set.actualHold; h != nil {
		if h.origin != h || h.set != set || h.adoptionUnknown {
			return nil, ErrCommitUnknown
		}
		if !r.providersMatchJournal(h.providers, inspection) {
			return nil, ErrInstall
		}
	} else if r.hasProviderIntent(inspection) {
		return nil, ErrInstall
	}
	// Permanently close every original capture entry before stopping providers.
	// Failure/timeout below does not reopen collection. The old ctx/until/operator
	// remain unchanged, and the old maintenance capability is poisoned, not renewed.
	set.recovering = true
	p.mu.Lock()
	p.failed = true
	p.mu.Unlock()
	if set.actualHold != nil {
		set.actualHold.closed = true
	}
	set.recoveryAuthorization = nil
	if h := set.actualHold; h != nil {
		for _, provider := range h.providers {
			if provider.Stop(ctx) != nil {
				return nil, ErrInstall
			}
		}
	}
	r.providersStopped = true
	if r.targetPermissions(ctx) != nil || r.readAuthority(ctx) != nil || r.checkJournal(ctx) != nil {
		return nil, ErrInstall
	}
	if set.journal.append(ctx, "", "fresh_original_recovery_authorized", nil, struct {
		PrefixSHA256    string
		PrefixRecords   int
		AdministratorID int64
		Until           time.Time
	}{r.prefixSHA, r.prefixLength, operator.userID, operator.until}) != nil {
		return nil, ErrInstall
	}
	set.recoveryAuthorization = r
	return r, nil
}

func (r *OriginalWriterRecoveryAuthorization) basic(ctx context.Context) bool {
	if r == nil || r.origin != r || r.fence == nil || r.operator == nil || !r.operator.live(ctx) || !r.providersStopped ||
		r.set == nil || r.set.origin != r.set || r.set.recoveryAuthorization != r || !r.set.recovering ||
		r.set.owner != r.fence.owner || r.set.journal != r.journal || r.set.inventorySHA != r.inventory ||
		r.set.owner.operation != r.operation || r.set.owner.commitUnknown || r.set.application.unknown {
		return false
	}
	s := r.set
	return s.owner.token.Key == r.gate.Key && s.owner.token.Owner == r.gate.Owner &&
		s.owner.token.Generation == r.gate.Generation && s.owner.token.FencingToken == r.gate.FencingToken &&
		s.application.scope == r.application.scope && s.application.owner == r.application.owner &&
		s.application.generation == r.application.generation && s.application.token == r.application.token &&
		(s.actualHold == nil || s.actualHold.closed && !s.actualHold.adoptionUnknown)
}

// Caller holds set.mu. The returned fence cannot be made from journal hashes.
func (r *OriginalWriterRecoveryAuthorization) recoveryFence(ctx context.Context, set *PreparedOriginalWriterSet) (*originalWriterRecoveryFence, error) {
	if !r.basic(ctx) || r.set != set || r.fence.check(ctx) != nil {
		return nil, ErrInstall
	}
	return r.fence, nil
}

func (f *originalWriterRecoveryFence) check(ctx context.Context) error {
	if f == nil || f.authorization == nil || f.authorization.fence != f || f.operator != f.authorization.operator ||
		!f.authorization.basic(ctx) {
		return ErrInstall
	}
	r := f.authorization
	if r.targetPermissions(ctx) != nil || r.checkJournal(ctx) != nil {
		return ErrInstall
	}
	return r.readAuthority(ctx)
}

// lockAuthority performs SQL ONLY. D first locks admission -> application gate
// -> V2 gate in its original transaction, then calls this method. No remote I/O,
// password hashing, new transaction, commit, or old capture expiry override.
func (f *originalWriterRecoveryFence) lockAuthority(ctx context.Context, tx *sql.Tx) error {
	if f == nil || f.authorization == nil || f.authorization.fence != f ||
		!f.authorization.basic(ctx) || f.operator != f.authorization.operator || f.owner != f.authorization.set.owner || tx == nil {
		return ErrInstall
	}
	return f.authorization.lockAuthority(ctx, tx)
}

func (r *OriginalWriterRecoveryAuthorization) lockAuthority(ctx context.Context, tx *sql.Tx) error {
	now, err := r.operator.lockAdmin(ctx, tx)
	if err != nil {
		return ErrInstall
	}
	current, err := r.operator.current(ctx, tx, false)
	// The exact signed original head is provenance, including an expired active
	// capture head. Fresh recovery is an explicit admin operation, not use of its
	// old grant. Revocation, any CAS drift and a not-yet-valid head still refuse.
	if err != nil || current.cas != r.set.owner.initial || current.cas.State == "revoked" ||
		current.cas.HeadRevision != 0 && (current.cas.State != "active" || now.Before(current.head.NotBefore) || now.Before(current.record.NotBefore)) {
		return ErrInstall
	}
	after, err := r.operator.installer.database(ctx, tx, r.operator.until)
	if err != nil || after.Before(now) {
		return ErrInstall
	}
	return nil
}

// All locks are fresh locking reads; old capture gate deadlines may be past,
// but ownership/generation/token/row-version must still match exactly. Neither
// expiration nor this observation is permission to unlock either gate.
func (r *OriginalWriterRecoveryAuthorization) readAuthority(ctx context.Context) error {
	if r == nil || r.operator == nil || !r.operator.live(ctx) {
		return ErrInstall
	}
	s := r.set
	if s.owner.token.State != c.GateAcquiring && s.owner.token.State != c.GateHeld && s.owner.token.State != c.GateReleasing ||
		s.application.phase != "acquiring" && s.application.phase != "held" && s.application.phase != "releasing" {
		return ErrInstall
	}
	tx, err := r.operator.installer.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return ErrInstall
	}
	defer tx.Rollback()
	var admission sql.NullString
	if tx.QueryRowContext(ctx, `SELECT owner FROM system_backup_gate_admissions WHERE scope=? FOR SHARE`, s.application.scope).Scan(&admission) != nil ||
		!admission.Valid || admission.String != s.application.owner {
		return ErrInstall
	}
	var phase, owner, inventory string
	var generation, token uint64
	if tx.QueryRowContext(ctx, `SELECT phase,COALESCE(owner,''),generation,fencing_token,registry_hash FROM system_backup_gate WHERE scope=? FOR SHARE`, s.application.scope).
		Scan(&phase, &owner, &generation, &token, &inventory) != nil || phase != s.application.phase || owner != s.application.owner ||
		generation != s.application.generation || token != s.application.token || inventory != s.inventorySHA {
		return ErrInstall
	}
	got := c.GateSnapshot{Key: s.owner.token.Key}
	if tx.QueryRowContext(ctx, `SELECT gate_state,generation,fencing_token,COALESCE(lock_owner,''),row_version FROM system_backup_v2_maintenance_locks WHERE origin_installation_id=? AND scope=? FOR SHARE`, got.Key.InstallationID, got.Key.Scope).
		Scan(&got.State, &got.Generation, &got.FencingToken, &got.Owner, &got.RowVersion) != nil || got != s.owner.token.GateSnapshot ||
		r.lockAuthority(ctx, tx) != nil || tx.Rollback() != nil {
		return ErrInstall
	}
	return nil
}

// Recheck the actual namespace/subject/enrollment and permissions on the real
// original targets. Target SSARs never come from the old preflight or a DTO.
func (r *OriginalWriterRecoveryAuthorization) targetPermissions(ctx context.Context) error {
	if r.operator.authority(ctx, r.enrollment) != nil {
		return ErrInstall
	}
	i := r.operator.installer
	allow := func(ns, group, resource, name, verb string) error {
		result, err := i.kube.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx,
			&authorizationv1.SelfSubjectAccessReview{Spec: authorizationv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &authorizationv1.ResourceAttributes{Namespace: ns, Group: group, Resource: resource, Name: name, Verb: verb}}}, metav1.CreateOptions{})
		if err != nil || result == nil || !result.Status.Allowed || result.Status.Denied || result.Status.EvaluationError != "" {
			return ErrInstall
		}
		return nil
	}
	for _, w := range r.set.deployments {
		for _, verb := range []string{"get", "patch"} {
			if allow(w.namespace, "apps", "deployments", w.selection.Name, verb) != nil {
				return ErrInstall
			}
		}
	}
	for _, w := range r.set.proPods {
		for _, verb := range []string{"get", "delete", "create"} {
			if allow(w.source.Namespace, "", "pods", w.source.Pod, verb) != nil {
				return ErrInstall
			}
		}
	}
	for _, w := range r.set.gateways {
		if allow(w.row.Namespace, "", "pods", w.row.Pod, "get") != nil {
			return ErrInstall
		}
	}
	return nil
}
