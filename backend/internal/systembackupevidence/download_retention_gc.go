package systembackupevidence

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

var (
	ErrDownloadRetentionGCCommitUnknown   = errors.New("download_retention_gc_commit_unknown")
	ErrDownloadRetentionGCRollbackUnknown = errors.New("download_retention_gc_rollback_unknown")
)

// These are server-observed identifiers, not an authorization or deletion
// capability. No receipt, nonce HMAC, claim, proof or provider locator escapes.
type DownloadRetentionGCScope struct {
	Database                                       sec.DatabaseIdentity
	Installation, WorkerOperation, PrincipalSHA256 string
	Operation, RequestHash                         string
	ManifestSHA256                                 string
	Evidence                                       Identity
	OperationID, EvidenceID, ActorID               int64
	EvidenceRowVersion                             int64
	IntentAuditID, ResultAuditID                   int64
	AdmittedAt, RetainUntil, MinimumRetainUntil    time.Time
	EvidenceCreatedAt                              time.Time
}

func (DownloadRetentionGCScope) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// This is trusted deployment wiring, never an HTTP field. Early verifies the
// CURRENT metadata-GC grant/revocation, complete schema/grants and DDL freeze,
// and locks incoming L1 audit references. Lock then locks the actual owner/
// artifact and ALL logical/FK reference/hold/lease
// ranges (including empty ranges) at L3/L4/L5. It must cover references to the
// operation, both audits and nonce, not only evidence_id columns. Only this
// exact group's own links may be excluded. A live owner, committed artifact,
// hold/promotion/import/retry reference, unknown schema or incomplete metadata
// visibility must deny. Callbacks perform locking/reads only, not mutations.
// Expired user proof/session is not the worker's grant.
// No provider call, nested transaction, commit or permissive fallback exists.
type DownloadRetentionGCPolicy interface {
	// Early verifies current GC authority/schema/DDL freeze and locks incoming
	// L1 audit-reference ranges using hints. It grants no deletion authority.
	Early(context.Context, *sql.Tx, DownloadGCEarlyScope, time.Time) (DownloadRetentionGCGuard, error)
	Lock(context.Context, *sql.Tx, DownloadRetentionGCScope, time.Time) (DownloadRetentionGCGuard, error)
}

// Recheck rereads the ORIGINAL locked ranges without taking new prefix locks.
// It checks current worker authorization and every original eligibility fact,
// and must remain usable after this group's own rows have been removed.
type DownloadRetentionGCGuard interface {
	Recheck(context.Context, *sql.Tx, DownloadRetentionGCScope, time.Time) error
}

// All inputs are deployment-owned. One authority is pinned to a separate peer
// certificate and exact running control_metadata_gc operation/claim. It grants
// no evidence/provider deletion, proof issuance, download or tombstone expiry.
// Policy has no default implementation; SQLDownloadOwners' read-only policy is
// deliberately NOT a metadata-GC policy. Production must supply reviewed actual
// guards and a measured physical tombstone/index/audit reservation.
type DownloadRetentionGCConfig struct {
	Registry                          SQLRegistry
	Policy                            DownloadRetentionGCPolicy
	References                        *SQLDownloadGCDirectReferences
	Capacity                          *sec.ConfigMutationCapacity
	MeasuredReservationBytes          int
	ConfigVersion                     int64
	ConfigSHA256                      string
	OperationID, OperationClaim       string
	OperationRowVersion               int64
	ClientCAPEM                       []byte
	ClientCASHA256, CertificateSHA256 string
	ExpiresAt                         time.Time
	// Explicit deployment wiring. Nil retains the historical non-freeze path;
	// it does not approve that path for production metadata GC.
	Freeze *DownloadGCFullFreezeConfig
}

func (DownloadRetentionGCConfig) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (DownloadRetentionGCConfig) String() string               { return "DownloadRetentionGCConfig" }
func (DownloadRetentionGCConfig) GoString() string             { return "DownloadRetentionGCConfig" }

type SQLDownloadRetentionGC struct {
	c         DownloadRetentionGCConfig
	roots     *x509.CertPool
	principal string
	freeze    *downloadGCFullFreeze
}

func (SQLDownloadRetentionGC) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (SQLDownloadRetentionGC) String() string               { return "SQLDownloadRetentionGC" }
func (SQLDownloadRetentionGC) GoString() string             { return "SQLDownloadRetentionGC" }

func NewSQLDownloadRetentionGC(c DownloadRetentionGCConfig) (*SQLDownloadRetentionGC, error) {
	r := c.Registry
	if r.DB == nil || nilSystemAdapter(r.Policy) || !installationPattern.MatchString(r.Installation) || r.ServerUUID == "" || r.Database == "" ||
		nilSystemAdapter(c.Policy) || c.References == nil || c.References.c.Database.ServerUUID != r.ServerUUID || c.References.c.Database.Database != r.Database || c.References.c.Installation != r.Installation ||
		c.Capacity == nil || c.MeasuredReservationBytes < 4096 || c.MeasuredReservationBytes > 1048576 ||
		c.ConfigVersion < 1 || !digestPattern.MatchString(c.ConfigSHA256) || !gcOperationID.MatchString(c.OperationID) || !s3Token([]byte(c.OperationClaim), 1, 128) || c.OperationRowVersion < 1 || c.OperationRowVersion > 9007199254740991 ||
		!digestPattern.MatchString(c.CertificateSHA256) || !digestPattern.MatchString(c.ClientCASHA256) || len(c.ClientCAPEM) == 0 || len(c.ClientCAPEM) > 65536 || hash(c.ClientCAPEM) != c.ClientCASHA256 || !time.Now().Before(c.ExpiresAt) {
		return nil, ErrDenied
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(c.ClientCAPEM) {
		return nil, ErrDenied
	}
	var freeze *downloadGCFullFreeze
	if c.Freeze != nil {
		var err error
		freeze, err = newDownloadGCFullFreeze(*c.Freeze, c)
		if err != nil {
			return nil, ErrDenied
		}
		c.Policy = &downloadGCFullFreezePolicy{freeze: freeze, domain: c.Policy}
	} else if _, requiresFreeze := c.Policy.(DownloadGCFullFreezeAuthority); requiresFreeze {
		// A full-profile policy must never silently downgrade if its explicit
		// owner configuration is omitted.
		return nil, ErrDenied
	}
	c.Freeze = nil // retain only the validated, private value copy
	c.ClientCAPEM = nil
	principal := hash(canonical(struct {
		Installation, Server, Database, Certificate, Worker, Claim, Config string
		Version, Row                                                       int64
	}{
		r.Installation, r.ServerUUID, r.Database, c.CertificateSHA256, c.OperationID, c.OperationClaim, c.ConfigSHA256, c.ConfigVersion, c.OperationRowVersion,
	}))
	return &SQLDownloadRetentionGC{c: c, roots: roots, principal: principal, freeze: freeze}, nil
}

func (s *SQLDownloadRetentionGC) AuthenticateRequest(r *http.Request) (context.Context, error) {
	if s == nil {
		return nil, ErrAuth
	}
	return authenticatePinnedPeer(r, s, s.roots, s.c.CertificateSHA256, s.c.ExpiresAt)
}

const downloadGCActorHintSQL = `SELECT o.id,o.actor_type,o.actor_id,a.intent_audit_id,r.result_audit_id FROM system_backup_v2_operations o JOIN system_backup_v2_download_admission_receipts a ON a.operation_id=o.id AND a.origin_installation_id=o.origin_installation_id AND a.operation_public_id=o.public_id JOIN system_backup_v2_download_result_receipts r ON r.operation_id=a.operation_id AND r.origin_installation_id=a.origin_installation_id AND r.operation_public_id=a.operation_public_id WHERE o.origin_installation_id=? AND o.public_id=?`
const downloadGCWorkerSQL = `SELECT operation_type,target_type,target_public_id,actor_type,actor_id,status,claim_owner,claim_expires_at,row_version,deadline_at,schema_version
FROM system_backup_v2_operations WHERE origin_installation_id=? AND public_id=? FOR UPDATE`

type downloadGCWorker struct{ lease, deadline time.Time }

func (s *SQLDownloadRetentionGC) worker(ctx context.Context, tx *sql.Tx) (downloadGCWorker, error) {
	return s.readWorker(ctx, tx, downloadGCWorkerSQL)
}

func (s *SQLDownloadRetentionGC) readWorker(ctx context.Context, tx *sql.Tx, query string) (downloadGCWorker, error) {
	var kind, target, id, actorType, actor, status, claim, schema string
	var version int64
	var w downloadGCWorker
	if tx.QueryRowContext(ctx, query, s.c.Registry.Installation, s.c.OperationID).Scan(&kind, &target, &id, &actorType, &actor, &status, &claim, &w.lease, &version, &w.deadline, &schema) != nil ||
		schema != "system-backup-operation.v1" || kind != "control_metadata_gc" || target != "system" || id != s.c.Registry.Installation || actorType != "system" || actor != "system:controller" || status != "running" || claim != s.c.OperationClaim || version != s.c.OperationRowVersion || !downloadAdmissionContentTime(w.lease) || !downloadAdmissionContentTime(w.deadline) {
		return w, ErrDenied
	}
	return w, nil
}

func (s *SQLDownloadRetentionGC) clock(ctx context.Context, tx *sql.Tx, floor, until time.Time) (time.Time, error) {
	now, err := downloadIntentNow(ctx, tx, floor)
	if err != nil || !now.Before(until) || time.Since(now) > 5*time.Second || time.Until(now) > 5*time.Second {
		return time.Time{}, ErrDenied
	}
	// SQL is the retention clock. The peer chain must independently remain
	// valid at BOTH the host observation and this SQL sample.
	if _, err = pinnedPeerExpiry(ctx, s, s.roots, s.c.CertificateSHA256, s.c.ExpiresAt); err != nil {
		return time.Time{}, ErrDenied
	}
	if _, err = pinnedPeerExpiryAt(ctx, s, s.roots, s.c.CertificateSHA256, s.c.ExpiresAt, now); err != nil {
		return time.Time{}, ErrDenied
	}
	return now, nil
}

// Collect owns ONE fresh RR transaction and its sole commit, for ONE candidate
// ID. It neither scans nor retries. No receipt is returned after unknown commit.
// The target evidence must already be durably deleted by separate evidence GC;
// this transaction keeps that minimum envelope and never deletes provider data.
func (s *SQLDownloadRetentionGC) Collect(ctx context.Context, operation string) (collectErr error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !downloadAdmissionOperationID.MatchString(operation) || operation == s.c.OperationID {
		return ErrDenied
	}
	if s.freeze != nil {
		return s.collectWithFullFreeze(ctx, operation)
	}
	peer, err := pinnedPeerExpiry(ctx, s, s.roots, s.c.CertificateSHA256, s.c.ExpiresAt)
	if err != nil {
		return ErrDenied
	}
	r := s.c.Registry
	owned, now, err := beginDownloadGCConnection(ctx, r)
	if err != nil {
		return ErrAudit
	}
	defer func() {
		if closeErr := owned.close(); closeErr != nil {
			collectErr = closeErr
		}
	}()
	tx := owned.tx
	if err := s.collectInTransaction(ctx, tx, operation, peer, now); err != nil {
		return err
	}
	return owned.commit()
}

// collectInTransaction is the protected work stage, shared by the existing
// connection owner and a future reviewed freeze adapter. The caller owns the
// exact authenticated session, its initial SQL clock sample and peer bound.
// This stage never acquires a connection, begins/ends a transaction, unlocks,
// retries or renews authority. A nil return still requires the caller's final
// freeze/authority checks and sole commit; any later failure must roll back.
// It is not a production freeze adapter or a default metadata-GC policy.
func (s *SQLDownloadRetentionGC) collectInTransaction(ctx context.Context, tx *sql.Tx, operation string, peer, now time.Time) error {
	return s.collectProtectedWork(ctx, tx, operation, peer, now, nil)
}

// capture is private candidate wiring. Ordinary Collect preserves its original
// guards and transaction owner. A completion is issued only after all real
// protected work and post-delete checks succeeded on this exact transaction.
func (s *SQLDownloadRetentionGC) collectProtectedWork(ctx context.Context, tx *sql.Tx, operation string, peer, now time.Time, capture **downloadGCWorkFinalizer) error {
	return s.collectProtectedWorkWithCapacity(ctx, tx, operation, peer, now, capture, nil)
}

func (s *SQLDownloadRetentionGC) collectProtectedWorkWithCapacity(ctx context.Context, tx *sql.Tx, operation string, peer, now time.Time, capture **downloadGCWorkFinalizer, prepared *sec.PreparedConfigMutationCapacity) error {
	var reservation sec.ConfigMutationCapacityReservation
	clock := func(c context.Context, t *sql.Tx, floor, until time.Time) (time.Time, error) {
		if prepared != nil && reservation != nil {
			pinned, ok := reservation.(interface {
				SQLFloor(context.Context, *sql.Tx) (time.Time, error)
			})
			if !ok {
				return time.Time{}, ErrDenied
			}
			observed, err := pinned.SQLFloor(c, t)
			if err != nil {
				return time.Time{}, ErrDenied
			}
			if observed.After(floor) {
				floor = observed
			}
		}
		return s.clock(c, t, floor, until)
	}
	if capture != nil {
		*capture = nil
	}
	if s == nil || ctx == nil || ctx.Err() != nil || tx == nil || !downloadAdmissionOperationID.MatchString(operation) || operation == s.c.OperationID || now.IsZero() || !now.Before(peer) {
		return ErrDenied
	}
	if s.freeze != nil && prepared == nil {
		return ErrDenied
	}
	// Revalidate the original authenticated context, without extending the
	// caller's bound. This also rejects an unrelated context before any SQL.
	currentPeer, err := pinnedPeerExpiry(ctx, s, s.roots, s.c.CertificateSHA256, s.c.ExpiresAt)
	if err != nil || peer.After(currentPeer) {
		return ErrDenied
	}
	r := s.c.Registry
	database := sec.DatabaseIdentity{ServerUUID: r.ServerUUID, Database: r.Database}
	nonceScope, err := sec.LockSensitiveDownloadNonceScope(ctx, tx, database, r.Installation)
	if err != nil {
		return ErrAudit
	}
	config, err := nonceScope.LoadConfig(ctx, tx)
	if err != nil || config.Version() != s.c.ConfigVersion || hash(config.Values().CanonicalJSON()) != s.c.ConfigSHA256 {
		return ErrDenied
	}
	// L2 protects the actual audit FK target, even if this old user is revoked
	// or disabled. The hint is compared with the independently locked group.
	var actorType, actorID string
	var hintOperation, hintIntent, hintResult int64
	if tx.QueryRowContext(ctx, downloadGCActorHintSQL, r.Installation, operation).Scan(&hintOperation, &actorType, &actorID, &hintIntent, &hintResult) != nil || actorType != "admin" || hintOperation < 1 || hintOperation > 9007199254740991 || hintIntent < 1 || hintIntent > 2147483647 || hintResult < 1 || hintResult > 2147483647 || hintIntent == hintResult {
		return ErrAudit
	}
	actor, err := strconv.ParseInt(actorID, 10, 64)
	if err != nil || actor < 1 || actor > 2147483647 || strconv.FormatInt(actor, 10) != actorID {
		return ErrAudit
	}
	// L1 precedes the original user's L2 FK and all L3 group/worker rows.
	// These hints choose only early reference ranges; compare all of them below.
	hint := DownloadGCEarlyScope{Database: database, Installation: r.Installation, WorkerOperation: s.c.OperationID, PrincipalSHA256: s.principal, Operation: operation, OperationID: hintOperation, ActorID: actor, IntentAuditID: hintIntent, ResultAuditID: hintResult}
	direct, err := s.c.References.early(ctx, tx, hint, now)
	if err != nil {
		return ErrDenied
	}
	early, err := s.c.Policy.Early(ctx, tx, hint, now)
	if err != nil || nilSystemAdapter(early) {
		return ErrDenied
	}
	var originalActor int64
	if tx.QueryRowContext(ctx, downloadResultActorSQL, actor).Scan(&originalActor) != nil || originalActor != actor {
		return ErrAudit
	}
	worker, err := s.worker(ctx, tx)
	if err != nil {
		return err
	}
	until := earlier(peer, earlier(worker.lease, worker.deadline))
	now, err = clock(ctx, tx, now, until)
	if err != nil {
		return err
	}
	g, err := LockDownloadRetentionGroup(ctx, tx, database, config, operation)
	if err != nil || g.result == nil || g.operation.ActorID != actor || g.operationID != hintOperation || g.receipt.IntentAuditID != hintIntent || g.result.resultID != hintResult {
		return ErrAudit
	}
	if err = lockDownloadGCTombstone(ctx, tx, g); err != nil {
		return err
	}
	identity, evidenceCreated, err := downloadGCEvidenceHint(ctx, tx, g)
	if err != nil {
		return err
	}
	minimum := g.operation.AdmittedAt.Add(config.ControlRetention())
	if config.ControlRetention() <= 0 || !downloadAdmissionContentTime(minimum) || !minimum.After(g.operation.AdmittedAt) {
		return ErrAudit
	}
	if minimum.Before(g.retain) {
		minimum = g.retain
	}
	scope := DownloadRetentionGCScope{Database: database, Installation: r.Installation, WorkerOperation: s.c.OperationID, PrincipalSHA256: s.principal, Operation: operation, RequestHash: g.operation.RequestHash, ManifestSHA256: g.receipt.ManifestSHA256, Evidence: identity, EvidenceCreatedAt: evidenceCreated, OperationID: g.operationID, ActorID: actor, EvidenceID: g.evidenceID, EvidenceRowVersion: g.receipt.EvidenceRowVersion, IntentAuditID: g.receipt.IntentAuditID, ResultAuditID: g.result.resultID, AdmittedAt: g.operation.AdmittedAt, RetainUntil: g.retain, MinimumRetainUntil: minimum}
	if early.Recheck(ctx, tx, scope, now) != nil {
		return ErrDenied
	}
	if direct.bindL3(ctx, tx, scope, g) != nil {
		return ErrDenied
	}
	guard, err := s.c.Policy.Lock(ctx, tx, scope, now)
	if err != nil || nilSystemAdapter(guard) || g.LockNonce(ctx, tx) != nil {
		return ErrDenied
	}
	if direct.lockL5(ctx, tx, g) != nil {
		return ErrDenied
	}
	now, err = clock(ctx, tx, now, until)
	if err != nil || now.Before(minimum) || now.Before(g.receipt.ClaimExpiresAt) || now.Before(g.operation.DeadlineAt) || now.Before(g.result.at) {
		return ErrDenied
	}
	if prepared != nil {
		reservation, err = prepared.Reserve(ctx, tx, s.c.Capacity, config.Values(), config.Values(), now)
	} else {
		reservation, err = s.c.Capacity.Reserve(ctx, tx, config.Values(), config.Values(), s.c.MeasuredReservationBytes, now)
	}
	if err != nil || nilSystemAdapter(reservation) || !downloadAdmissionContentTime(reservation.ValidUntil()) || !now.Before(reservation.ValidUntil()) {
		return ErrAudit
	}
	until = earlier(until, reservation.ValidUntil())
	if g.VerifyAudits(ctx, tx) != nil {
		return ErrAudit
	}
	if direct.lockL7(ctx, tx) != nil {
		return ErrDenied
	}
	evidence, err := lockDownloadGCDeletedEvidence(ctx, tx, scope, now)
	if err != nil {
		return err
	}
	now, err = clock(ctx, tx, now, until)
	if err != nil || now.Before(minimum) || guard.Recheck(ctx, tx, scope, now) != nil || reservation.Recheck(ctx, tx, now) != nil || g.Recheck(ctx, tx) != nil || early.Recheck(ctx, tx, scope, now) != nil || direct.Recheck(ctx, tx, scope, now) != nil {
		return ErrDenied
	}
	stone, err := newDownloadGCTombstone(g, s.c.OperationID, now, config.ControlRetention())
	if err != nil || stone.insert(ctx, tx) != nil || g.Recheck(ctx, tx) != nil {
		return ErrAudit
	}
	if err = deleteDownloadGCGroup(ctx, tx, g); err != nil {
		return err
	}
	now, err = clock(ctx, tx, now, until)
	if err != nil || guard.Recheck(ctx, tx, scope, now) != nil || reservation.Recheck(ctx, tx, now) != nil || early.Recheck(ctx, tx, scope, now) != nil || direct.Recheck(ctx, tx, scope, now) != nil {
		return ErrDenied
	}
	// Nothing after this point calls the deployment guard. Independently check
	// every retained replacement and original absent key AFTER all callbacks.
	currentWorker, err := s.worker(ctx, tx)
	if err != nil || !currentWorker.lease.Equal(worker.lease) || !currentWorker.deadline.Equal(worker.deadline) || config.Recheck(ctx, tx) != nil || evidence.recheck(ctx, tx, scope, now) != nil || stone.verify(ctx, tx) != nil || verifyDownloadGCAbsent(ctx, tx, g) != nil {
		return ErrAudit
	}
	if now, err = clock(ctx, tx, now, until); err != nil {
		return err
	}
	if capture != nil {
		// All values below belong to THIS completed work. No replacement DTO,
		// newly acquired prefix, renewed reservation or deleted-group Recheck.
		*capture = issueDownloadGCFinalizer(ctx, tx, s, operation, func(finalCtx context.Context, finalTx *sql.Tx) error {
			last, err := clock(finalCtx, finalTx, now, until)
			if err != nil || last.Before(minimum) || guard.Recheck(finalCtx, finalTx, scope, last) != nil || reservation.Recheck(finalCtx, finalTx, last) != nil || early.Recheck(finalCtx, finalTx, scope, last) != nil || direct.Recheck(finalCtx, finalTx, scope, last) != nil {
				return ErrDenied
			}
			// Every deployment callback precedes these independent checks.
			current, err := s.worker(finalCtx, finalTx)
			if err != nil || !current.lease.Equal(worker.lease) || !current.deadline.Equal(worker.deadline) || config.Recheck(finalCtx, finalTx) != nil || evidence.recheck(finalCtx, finalTx, scope, last) != nil || stone.verify(finalCtx, finalTx) != nil || verifyDownloadGCAbsent(finalCtx, finalTx, g) != nil {
				return ErrAudit
			}
			_, err = clock(finalCtx, finalTx, last, until)
			return err
		})
		if *capture == nil {
			return ErrDenied
		}
	}
	return nil
}

const downloadGCEvidenceHintSQL = `SELECT origin_installation_id,owner_target_type,owner_target_public_id,evidence_type,redaction_classification,content_checksum,content_size_bytes,media_type,created_at
FROM system_backup_v2_evidence WHERE id=? AND public_id=?`

func downloadGCEvidenceHint(ctx context.Context, tx *sql.Tx, g *DownloadRetentionGroup) (Identity, time.Time, error) {
	i := Identity{ID: g.receipt.EvidenceID}
	var created time.Time
	if tx.QueryRowContext(ctx, downloadGCEvidenceHintSQL, g.evidenceID, i.ID).Scan(&i.Installation, &i.OwnerType, &i.OwnerID, &i.Type, &i.Classification, &i.ContentHash, &i.ContentSize, &i.Media, &created) != nil || i.Installation != g.operation.Installation || !i.validExternal() || !oneOf(i.Classification, "confidential", "sensitive") || !downloadAdmissionContentTime(created) || created.After(g.operation.AdmittedAt) {
		return i, created, ErrDenied
	}
	return i, created, nil
}

const downloadGCDeletedEvidenceSQL = `SELECT origin_installation_id,owner_target_type,owner_target_public_id,evidence_type,redaction_classification,content_checksum,content_size_bytes,media_type,row_version,expires_at,protected_until,created_at
FROM system_backup_v2_evidence WHERE id=? AND public_id=? AND schema_version='system-backup-evidence.v1' AND storage_state='deleted' AND evidence_failure_code='none'
AND claim_owner IS NULL AND claim_expires_at IS NULL AND storage_provider_role IS NULL AND storage_identity_hash IS NULL AND storage_ref_version IS NULL
AND storage_relative_key IS NULL AND storage_relative_key_hash IS NULL AND storage_immutable_version IS NULL AND inline_payload IS NULL
AND object_checksum IS NULL AND object_size_bytes IS NULL AND plaintext_chunk_size_bytes IS NULL AND chunk_count=0 AND chunk_list_root IS NULL FOR UPDATE`
const downloadGCEmptyChunksSQL = `SELECT chunk_index FROM system_backup_v2_evidence_chunks WHERE evidence_id=? ORDER BY chunk_index LIMIT 1 FOR UPDATE`

type downloadGCDeletedEvidence struct {
	identity  Identity
	version   int64
	expires   time.Time
	created   time.Time
	protected sql.NullTime
}

func lockDownloadGCDeletedEvidence(ctx context.Context, tx *sql.Tx, s DownloadRetentionGCScope, now time.Time) (downloadGCDeletedEvidence, error) {
	f := downloadGCDeletedEvidence{identity: Identity{ID: s.Evidence.ID}}
	i := &f.identity
	if tx.QueryRowContext(ctx, downloadGCDeletedEvidenceSQL, s.EvidenceID, i.ID).Scan(&i.Installation, &i.OwnerType, &i.OwnerID, &i.Type, &i.Classification, &i.ContentHash, &i.ContentSize, &i.Media, &f.version, &f.expires, &f.protected, &f.created) != nil || *i != s.Evidence || f.version <= s.EvidenceRowVersion || f.version > 9007199254740991 || !downloadAdmissionContentTime(f.created) || !f.created.Equal(s.EvidenceCreatedAt) || !downloadAdmissionContentTime(f.expires) || now.Before(f.expires) || f.protected.Valid && (!downloadAdmissionContentTime(f.protected.Time) || now.Before(f.protected.Time)) {
		return f, ErrDenied
	}
	var chunk int64
	if err := tx.QueryRowContext(ctx, downloadGCEmptyChunksSQL, s.EvidenceID).Scan(&chunk); !errors.Is(err, sql.ErrNoRows) {
		return f, ErrDenied
	}
	return f, nil
}
func (f downloadGCDeletedEvidence) recheck(ctx context.Context, tx *sql.Tx, s DownloadRetentionGCScope, now time.Time) error {
	current, err := lockDownloadGCDeletedEvidence(ctx, tx, s, now)
	if err != nil || current.identity != f.identity || current.version != f.version || !current.created.Equal(f.created) || !current.expires.Equal(f.expires) || current.protected.Valid != f.protected.Valid || f.protected.Valid && !current.protected.Time.Equal(f.protected.Time) {
		return ErrDenied
	}
	return nil
}

const downloadGCTombstoneSourceKeySQL = `SELECT id FROM system_backup_v2_compact_tombstones WHERE origin_installation_id=? AND source_type='operation' AND source_public_id=? FOR UPDATE`
const downloadGCTombstoneIdempotencyKeySQL = `SELECT id FROM system_backup_v2_compact_tombstones WHERE origin_installation_id=? AND actor_type='admin' AND actor_id=? AND endpoint='getSystemBackupEvidence' AND idempotency_key=? FOR UPDATE`

func lockDownloadGCTombstone(ctx context.Context, tx *sql.Tx, g *DownloadRetentionGroup) error {
	var id int64
	for _, key := range []struct {
		q    string
		args []any
	}{
		{downloadGCTombstoneSourceKeySQL, []any{g.operation.Installation, g.operation.OperationID}},
		{downloadGCTombstoneIdempotencyKeySQL, []any{g.operation.Installation, strconv.FormatInt(g.operation.ActorID, 10), g.operation.IdempotencyKey}},
	} {
		err := tx.QueryRowContext(ctx, key.q, key.args...).Scan(&id)
		if err == nil {
			return ErrConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return ErrAudit
		}
	}
	return nil
}

const downloadGCTombstoneInsertSQL = `INSERT INTO system_backup_v2_compact_tombstones
(source_type,source_public_id,origin_installation_id,actor_type,actor_id,endpoint,idempotency_key,request_hash,terminal_status,failure_category,eligibility,artifact_final_state,response_summary_hash,source_created_at,source_finished_at,detail_rolling_hash,gc_batch_id,gc_at,retention_class,delete_after,row_version)
VALUES ('operation',?,?,'admin',?,'getSystemBackupEvidence',?,?,'succeeded','none',NULL,NULL,?,?,?,?,?,?,'standard',?,1)`
const downloadGCTombstoneReadSQL = `SELECT id,schema_version,source_type,source_public_id,origin_installation_id,actor_type,actor_id,endpoint,idempotency_key,request_hash,terminal_status,failure_category,eligibility,artifact_final_state,response_summary_hash,source_created_at,source_finished_at,detail_rolling_hash,gc_batch_id,gc_at,retention_class,delete_after,row_version
FROM system_backup_v2_compact_tombstones WHERE origin_installation_id=? AND source_type='operation' AND source_public_id=? FOR UPDATE`

type downloadGCTombstone struct {
	id                                                                   int64
	operation, installation, actor, key, request, summary, detail, batch string
	created, finished, at, deleteAfter                                   time.Time
}

func newDownloadGCTombstone(g *DownloadRetentionGroup, batch string, at time.Time, cycle time.Duration) (downloadGCTombstone, error) {
	detail, complete := g.DetailRollingHash()
	t := downloadGCTombstone{operation: g.operation.OperationID, installation: g.operation.Installation, actor: strconv.FormatInt(g.operation.ActorID, 10), key: g.operation.IdempotencyKey, request: g.operation.RequestHash, summary: hash(g.public), detail: detail, batch: batch, created: g.operation.AdmittedAt, finished: g.operation.AdmittedAt, at: at, deleteAfter: at.Add(cycle)}
	if !complete || !downloadAdmissionOperationID.MatchString(batch) || cycle <= 0 || !downloadAdmissionContentTime(at) || at.Before(g.retain) || !downloadAdmissionContentTime(t.deleteAfter) || !t.deleteAfter.After(at) {
		return t, ErrAudit
	}
	return t, nil
}
func (t *downloadGCTombstone) insert(ctx context.Context, tx *sql.Tx) error {
	r, err := tx.ExecContext(ctx, downloadGCTombstoneInsertSQL, t.operation, t.installation, t.actor, t.key, t.request, t.summary, t.created, t.finished, t.detail, t.batch, t.at, t.deleteAfter)
	if !downloadAdmissionOne(r, err) {
		return ErrAudit
	}
	t.id, err = r.LastInsertId()
	if err != nil || t.id < 1 {
		return ErrAudit
	}
	return t.verify(ctx, tx)
}
func (t downloadGCTombstone) verify(ctx context.Context, tx *sql.Tx) error {
	var stored downloadGCTombstone
	var schema, source, actorType, endpoint, status, failure, retention string
	var eligible sql.NullBool
	var artifact sql.NullString
	var row int64
	if tx.QueryRowContext(ctx, downloadGCTombstoneReadSQL, t.installation, t.operation).Scan(&stored.id, &schema, &source, &stored.operation, &stored.installation, &actorType, &stored.actor, &endpoint, &stored.key, &stored.request, &status, &failure, &eligible, &artifact, &stored.summary, &stored.created, &stored.finished, &stored.detail, &stored.batch, &stored.at, &retention, &stored.deleteAfter, &row) != nil || schema != "system-backup-compact-tombstone.v1" || source != "operation" || actorType != "admin" || endpoint != "getSystemBackupEvidence" || status != "succeeded" || failure != "none" || eligible.Valid || artifact.Valid || retention != "standard" || row != 1 || !t.matches(stored) {
		return ErrAudit
	}
	return nil
}

func (t downloadGCTombstone) matches(s downloadGCTombstone) bool {
	return t.id == s.id && t.operation == s.operation && t.installation == s.installation && t.actor == s.actor && t.key == s.key && t.request == s.request && t.summary == s.summary && t.detail == s.detail && t.batch == s.batch && t.created.Equal(s.created) && t.finished.Equal(s.finished) && t.at.Equal(s.at) && t.deleteAfter.Equal(s.deleteAfter)
}

const downloadGCDeleteResultSQL = `DELETE FROM system_backup_v2_download_result_receipts WHERE operation_id=? AND origin_installation_id=? AND operation_public_id=? AND evidence_id=? AND evidence_public_id=? AND intent_audit_id=? AND result_audit_id=? AND result_sha256=? AND result_size_bytes=? AND result_at=? AND retain_until=? AND schema_version='system-backup-evidence-download-result.v1'`
const downloadGCDeleteNonceSQL = `DELETE FROM system_backup_v2_strong_auth_nonces WHERE id=? AND origin_installation_id=? AND operation_id=? AND audit_log_id=? AND nonce_hmac=? AND nonce_hmac_key_version=? AND retain_until=? AND schema_version='system-backup-strong-auth-nonce.v1'`
const downloadGCDeleteReceiptSQL = `DELETE FROM system_backup_v2_download_admission_receipts WHERE operation_id=? AND origin_installation_id=? AND operation_public_id=? AND evidence_id=? AND evidence_public_id=? AND intent_audit_id=? AND receipt_sha256=? AND operation_sha256=? AND retain_until=? AND schema_version='system-backup-evidence-download-admission.v1'`
const downloadGCDeleteOperationSQL = `DELETE FROM system_backup_v2_operations WHERE id=? AND origin_installation_id=? AND public_id=? AND operation_type='evidence_download_admission' AND target_type='evidence' AND target_public_id=? AND download_evidence_id=? AND request_hash=? AND status='succeeded' AND row_version=1`
const downloadGCDeleteAuditSQL = `DELETE FROM audit_logs WHERE id=? AND user_id=? AND action=? AND resource_type='system_backup' AND resource_id IS NULL AND created_at=?`

func deleteDownloadGCGroup(ctx context.Context, tx *sql.Tx, g *DownloadRetentionGroup) error {
	intent, err := decodeDownloadAudit(g.intentBody, 8192)
	if err != nil {
		return ErrAudit
	}
	intentStamp, ok := intent["intent_at"].(string)
	intentAt, err := time.Parse("2006-01-02T15:04:05.000000Z", intentStamp)
	if !ok || err != nil {
		return ErrAudit
	}
	r := g.result
	if r == nil || r.verify(ctx, tx) != nil || !downloadAdmissionOne(tx.ExecContext(ctx, downloadGCDeleteResultSQL, r.operationID, r.installation, r.operationPublicID, r.evidenceID, r.evidencePublicID, r.intentID, r.resultID, r.digest, r.size, r.at, r.retain)) {
		return ErrAudit
	}
	if g.readNonce(ctx) != nil {
		return ErrAudit
	}
	n := g.nonce
	if !downloadAdmissionOne(tx.ExecContext(ctx, downloadGCDeleteNonceSQL, n.id, n.installation, n.operationID, n.auditID, n.hmac, n.version, n.retain)) {
		return ErrAudit
	}
	if g.readReceipt(ctx) != nil || !downloadAdmissionOne(tx.ExecContext(ctx, downloadGCDeleteReceiptSQL, g.operationID, g.operation.Installation, g.operation.OperationID, g.evidenceID, g.receipt.EvidenceID, g.receipt.IntentAuditID, hash(g.private), hash(g.public), g.retain)) {
		return ErrAudit
	}
	if readDownloadAdmissionOperationRow(ctx, tx, g.operationID, g.evidenceID, g.operation) != nil || !downloadAdmissionOne(tx.ExecContext(ctx, downloadGCDeleteOperationSQL, g.operationID, g.operation.Installation, g.operation.OperationID, g.receipt.EvidenceID, g.evidenceID, g.operation.RequestHash)) {
		return ErrAudit
	}
	// Recheck each audit immediately before deletion. Triggers on preceding
	// DELETEs cannot quietly change a later row after its rolling hash froze.
	for _, a := range []struct {
		id     int64
		action string
		body   []byte
		at     time.Time
	}{
		{r.resultID, "system_backup.evidence_download.result", g.resultBody, r.at},
		{g.receipt.IntentAuditID, "system_backup.evidence_download.intent", g.intentBody, intentAt},
	} {
		body, created, err := g.audit(ctx, a.id, a.action, 8192)
		if err != nil || !bytes.Equal(canonical(body), a.body) || !created.Equal(a.at.Truncate(time.Second)) {
			return ErrAudit
		}
		if !downloadAdmissionOne(tx.ExecContext(ctx, downloadGCDeleteAuditSQL, a.id, g.operation.ActorID, a.action, created)) {
			return ErrAudit
		}
	}
	return nil
}

func verifyDownloadGCAbsent(ctx context.Context, tx *sql.Tx, g *DownloadRetentionGroup) error {
	// All of these exact keys/ranges were locked before deletion; no new L3+
	// lock is acquired at the final boundary. Read our own writes, not hints.
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{"SELECT id FROM system_backup_v2_operations WHERE id=?", []any{g.operationID}},
		// A later audit DELETE trigger could reinsert either unique source key
		// under a NEW numeric ID. Absence of the deleted PK alone is insufficient.
		{downloadGCAbsentOperationPublicSQL, []any{g.operation.Installation, g.operation.OperationID}},
		{downloadGCAbsentOperationKeySQL, []any{g.operation.Installation, strconv.FormatInt(g.operation.ActorID, 10), g.operation.IdempotencyKey}},
		{"SELECT operation_id FROM system_backup_v2_download_admission_receipts WHERE operation_id=?", []any{g.operationID}},
		{"SELECT operation_id FROM system_backup_v2_download_result_receipts WHERE operation_id=?", []any{g.operationID}},
		{"SELECT id FROM system_backup_v2_strong_auth_nonces WHERE operation_id=? LIMIT 1", []any{g.operationID}},
		{"SELECT id FROM audit_logs WHERE id=?", []any{g.receipt.IntentAuditID}},
		{"SELECT id FROM audit_logs WHERE id=?", []any{g.result.resultID}},
	} {
		var id int64
		if err := tx.QueryRowContext(ctx, q.sql, q.args...).Scan(&id); !errors.Is(err, sql.ErrNoRows) {
			return ErrAudit
		}
	}
	return nil
}

const downloadGCAbsentOperationPublicSQL = `SELECT id FROM system_backup_v2_operations WHERE origin_installation_id=? AND public_id=?`
const downloadGCAbsentOperationKeySQL = `SELECT id FROM system_backup_v2_operations WHERE origin_installation_id=? AND actor_type='admin' AND actor_id=? AND endpoint='getSystemBackupEvidence' AND idempotency_key=?`
