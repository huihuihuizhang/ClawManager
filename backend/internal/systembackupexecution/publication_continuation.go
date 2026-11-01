package systembackupexecution

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
)

var (
	ErrPublicationNextIntentRequired   = errors.New("original publication continuation requires the next immutable intent")
	ErrPublicationFinalizationRequired = errors.New("original publication requires independent final verification and catalog acceptance")
)

var publicationContinuationOrder = [...]string{"manifest_put", "marker_put", "acceptance_put", "catalog_registration_append"}

// This private handle contains independently read ORIGINAL confirmed objects.
// It grants no signing, new payload generation, new epoch adoption or terminal
// success. A's assembler supplies the next exact immutable intent separately.
type publicationContinuation struct {
	service      *DeploymentService
	ctx          context.Context
	claim        c.ClaimToken
	attempt      uint64
	policy       c.LeasePolicy
	access       *security.SQLPublisherCaptureAuthority
	target       PublicationTargetMaterials
	actions      []publicationJournalAction
	objects      []nativePublicationObject
	next         string
	closed, used atomic.Bool
	operations   sync.RWMutex
	closeOnce    sync.Once
	closeErr     error
}

// preparePublicationContinuation acquires the SAME publishing task with the
// actual durable claim receipt. Unknown actions are exclusively query-only and
// cannot enter this path, including a concurrent newly committed unknown.
func (s *DeploymentService) preparePublicationContinuation(ctx context.Context, store *nativePublicationS3) (_ *publicationContinuation, resultErr error) {
	if s == nil || ctx == nil || ctx.Err() != nil || store == nil || s.publisherVerifierDB == nil || s.PublisherOwner == "" {
		return nil, c.ErrExecutionAuthority
	}
	var backup string
	var version, attempt uint64
	var ttl, heartbeat, reconcile int64
	err := s.publisherVerifierDB.QueryRowContext(ctx, `SELECT b.public_id,b.row_version,a.attempt_no,cfg.controller_claim_ttl_seconds,cfg.controller_claim_heartbeat_seconds,cfg.controller_reconcile_interval_seconds
FROM system_backup_v2_backups b JOIN system_backup_v2_configs cfg ON cfg.origin_installation_id=b.origin_installation_id AND cfg.version=b.config_version AND cfg.config_sha256=b.config_snapshot_sha256
JOIN system_backup_v2_attempts a ON a.target_type='backup' AND a.target_public_id=b.public_id AND a.phase='capture' AND a.status='sealed'
WHERE b.origin_installation_id=? AND b.status='publishing' AND b.commit_started_at IS NOT NULL AND b.deadline_at>UTC_TIMESTAMP(6)
AND (b.next_reconcile_at IS NULL OR b.next_reconcile_at<=UTC_TIMESTAMP(6)) AND (b.controller_owner IS NULL OR b.controller_lease_expires_at<=UTC_TIMESTAMP(6))
AND a.attempt_no=(SELECT MAX(a2.attempt_no) FROM system_backup_v2_attempts a2 WHERE a2.target_type='backup' AND a2.target_public_id=b.public_id AND a2.phase='capture')
AND EXISTS(SELECT 1 FROM system_backup_v2_external_actions x WHERE x.origin_installation_id=b.origin_installation_id AND x.target_type='backup' AND x.target_public_id=b.public_id AND x.state='confirmed_present')
AND NOT EXISTS(SELECT 1 FROM system_backup_v2_external_actions x WHERE x.origin_installation_id=b.origin_installation_id AND x.target_type='backup' AND x.target_public_id=b.public_id AND x.state<>'confirmed_present')
ORDER BY b.id LIMIT 1`, s.Config.InstallationID).Scan(&backup, &version, &attempt, &ttl, &heartbeat, &reconcile)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, errPublicationUnavailable
	}
	policy := c.LeasePolicy{TTL: time.Duration(ttl) * time.Second, HeartbeatInterval: time.Duration(heartbeat) * time.Second, ReconcileInterval: time.Duration(reconcile) * time.Second}
	if policy.Validate() != nil {
		return nil, c.ErrExecutionAuthority
	}
	claim, err := (c.SQLTaskClaimStore{DB: s.publisherVerifierDB, InstallationID: s.Config.InstallationID}).AcquireWithReceipt(ctx, c.Target{Kind: c.TargetBackup, PublicID: backup}, s.PublisherOwner, version, policy)
	if err != nil {
		return nil, err
	}
	p := &publicationContinuation{service: s, ctx: ctx, claim: claim, attempt: attempt, policy: policy, target: store.config}
	defer func() {
		if resultErr != nil {
			p.close()
		}
	}()
	access, err := s.publicationAccess(ctx, claim, attempt)
	if err != nil {
		return nil, err
	}
	if err := access.Check(ctx); err != nil {
		return nil, err
	}
	p.access = access
	tx, err := s.publisherVerifierDB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	guard, err := access.Bind(ctx, tx)
	if err != nil {
		return nil, err
	}
	if guard.Facts().Status != "publishing" || s.checkPublicationTargetTx(ctx, tx, guard.Facts(), store.config) != nil {
		return nil, c.ErrExecutionAuthority
	}
	p.actions, err = p.readActions(ctx, tx)
	if err != nil {
		return nil, err
	}
	if len(p.actions) == 0 || len(p.actions) > len(publicationContinuationOrder) {
		return nil, c.ErrExecutionRecord
	}
	for i, action := range p.actions {
		intent := publicationJSONIntent{Kind: action.Kind, Key: action.Key, Payload: action.Payload, Deadline: action.Deadline}
		if action.Kind != publicationContinuationOrder[i] || action.State != "confirmed_present" || !action.ObjectVersion.Valid || action.ObjectVersion.String == "" || !action.ObjectSHA.Valid || action.ObjectSHA.String != action.PayloadSHA || intent.validate(store.config) != nil || action.ActionKey != publicationActionKey(backup, attempt, action.Kind) || action.LogicalSHA != publicationLogicalHash(s.Config.InstallationID, backup, attempt, intent) {
			return nil, c.ErrExecutionRecord
		}
	}
	if guard.RecheckTx(ctx, tx) != nil {
		return nil, c.ErrClaimLost
	}
	if err := tx.Rollback(); err != nil {
		return nil, err
	}
	if len(p.actions) < len(publicationContinuationOrder) {
		p.next = publicationContinuationOrder[len(p.actions)]
	}
	for _, action := range p.actions {
		// Existing confirmed actions ALWAYS use the original version and complete
		// EOF readback. This existing helper cannot issue a second PUT for them.
		object, err := s.publishOriginalJSON(ctx, claim, attempt, store, publicationJSONIntent{Kind: action.Kind, Key: action.Key, Payload: action.Payload, Deadline: action.Deadline})
		if err != nil {
			return nil, err
		}
		p.objects = append(p.objects, object)
	}
	check, err := s.publisherVerifierDB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, err
	}
	defer check.Rollback()
	if err := p.recheckTx(ctx, check); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *publicationContinuation) readActions(ctx context.Context, tx *sql.Tx) ([]publicationJournalAction, error) {
	rows, err := tx.QueryContext(ctx, "SELECT "+publicationActionColumns+" FROM system_backup_v2_external_actions WHERE origin_installation_id=? AND target_type='backup' AND target_public_id=? ORDER BY FIELD(action_type,'manifest_put','marker_put','acceptance_put','catalog_registration_append'),public_id FOR UPDATE", p.service.Config.InstallationID, p.claim.Target.PublicID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var actions []publicationJournalAction
	for rows.Next() {
		action, err := scanPublicationAction(rows)
		if err != nil {
			return nil, err
		}
		actions = append(actions, action)
		if len(actions) > len(publicationContinuationOrder) {
			return nil, c.ErrExecutionRecord
		}
	}
	return actions, rows.Err()
}

func (p *publicationContinuation) recheckTx(ctx context.Context, tx *sql.Tx) error {
	if p == nil || p.closed.Load() || ctx != p.ctx || ctx.Err() != nil || len(p.actions) == 0 || len(p.objects) != len(p.actions) {
		return c.ErrExecutionAuthority
	}
	if p.access == nil {
		return c.ErrExecutionAuthority
	}
	guard, err := p.access.Bind(ctx, tx)
	if err != nil {
		return err
	}
	if guard.Facts().Status != "publishing" || p.service.checkPublicationTargetTx(ctx, tx, guard.Facts(), p.target) != nil {
		return c.ErrExecutionAuthority
	}
	current, err := p.readActions(ctx, tx)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(current, p.actions) {
		return c.ErrExecutionRecord
	}
	for _, object := range p.objects {
		if err := object.recheckPublicationReceiptTx(ctx, tx, p.claim); err != nil {
			return err
		}
	}
	return guard.RecheckTx(ctx, tx)
}

// publishNext is consumed once, even on an uncertain commit. Reentry must
// reacquire and independently observe the durable original journal again.
func (p *publicationContinuation) publishNext(ctx context.Context, store *nativePublicationS3, intent publicationJSONIntent) (nativePublicationObject, error) {
	// Confirmed existence is not independent artifact acceptance. A must
	// provide a typed final-verification/acceptance producer before either of
	// these stages can be enabled through this continuation interface.
	if intent.Kind == "acceptance_put" || intent.Kind == "catalog_registration_append" {
		return nativePublicationObject{}, ErrPublicationFinalizationRequired
	}
	if p == nil {
		return nativePublicationObject{}, c.ErrExecutionAuthority
	}
	p.operations.RLock()
	defer p.operations.RUnlock()
	if p.closed.Load() || ctx != p.ctx || store == nil || !reflect.DeepEqual(store.config, p.target) || p.next == "" || intent.Kind != p.next || !p.used.CompareAndSwap(false, true) {
		return nativePublicationObject{}, c.ErrExecutionAuthority
	}
	return p.service.publishOriginalJSONWithContinuation(ctx, p.claim, p.attempt, store, intent, p)
}

func (p *publicationContinuation) close() error {
	if p == nil {
		return nil
	}
	p.closed.Store(true)
	// Once.Do waits for the SAME in-flight close, including its join and
	// single exact Release. Every caller observes the same completion/error.
	p.closeOnce.Do(func() {
		p.operations.Lock()
		defer p.operations.Unlock()
		ctx, cancel := context.WithTimeout(context.WithoutCancel(p.ctx), 3*time.Second)
		defer cancel()
		_, p.closeErr = (c.ClaimCoordinator{Executor: p.service.publisherVerifierDB, InstallationID: p.service.Config.InstallationID}).Release(ctx, p.claim, p.policy.ReconcileInterval)
	})
	return p.closeErr
}

// A's assembler supplies the next immutable intent through publishNext. Until
// connected, an eligible task is explicitly protected rather than silently
// skipped or promoted to success from confirmed_present alone.
func (s *DeploymentService) runPublicationContinuation(ctx context.Context, store *nativePublicationS3) (resultErr error) {
	p, err := s.preparePublicationContinuation(ctx, store)
	if err != nil || p == nil {
		return err
	}
	defer func() {
		if err := p.close(); resultErr == nil {
			resultErr = err
		}
	}()
	if p.next == "" || p.next == "acceptance_put" || p.next == "catalog_registration_append" {
		return ErrPublicationFinalizationRequired
	}
	return ErrPublicationNextIntentRequired
}
