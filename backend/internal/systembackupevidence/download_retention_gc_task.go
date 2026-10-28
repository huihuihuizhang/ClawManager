package systembackupevidence

import (
	"context"
	"database/sql"
	"reflect"
	"sync"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

// This is one necessary part of DownloadRetentionGCPolicy.Lock, not a complete
// policy or a production grant. It covers the four 067 task owners, their local
// backup artifact, inventory, leases, retained promotions, incoming retries,
// other source-consuming tasks and retained prune items.
// The caller must also provide Early authority/schema/DDL freeze and ALL other
// operation/audit/nonce/evidence/logical reference checks. In particular this
// component cannot replace the system producer's original write binding.
type DownloadGCTaskEligibilityConfig struct {
	Database     sec.DatabaseIdentity
	Installation string
}

type SQLDownloadGCTaskEligibility struct {
	c DownloadGCTaskEligibilityConfig
}

func NewSQLDownloadGCTaskEligibility(c DownloadGCTaskEligibilityConfig) (*SQLDownloadGCTaskEligibility, error) {
	if c.Database.ServerUUID == "" || !gcSQLName.MatchString(c.Database.Database) || !installationPattern.MatchString(c.Installation) {
		return nil, ErrDenied
	}
	return &SQLDownloadGCTaskEligibility{c: c}, nil
}

const downloadGCTaskDatabaseSQL = `SELECT @@server_uuid,DATABASE()`
const downloadGCTaskTablesSQL = `SELECT TABLE_NAME,TABLE_TYPE,COALESCE(ENGINE,'') FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('system_backup_v2_backups','system_backup_v2_restore_drills','system_backup_v2_preflights','system_backup_v2_artifact_verifications','system_backup_v2_artifact_lease_states','system_backup_v2_artifact_leases','system_backup_v2_staging_resources','system_backup_v2_restore_drill_resources','system_backup_v2_promotions','system_backup_v2_prune_items') ORDER BY BINARY TABLE_NAME`
const downloadGCTaskLeaseStateSQL = `SELECT id,origin_installation_id,lease_mode,generation,row_version FROM system_backup_v2_artifact_lease_states WHERE source_artifact_type='backup' AND source_public_id=? ORDER BY id LIMIT 10001 FOR UPDATE`
const downloadGCTaskSourceLeaseSQL = `SELECT id,origin_installation_id,source_artifact_type,source_public_id,lease_generation,lease_mode,holder_type,holder_public_id,purpose,heartbeat_at,expires_at,lease_ttl_seconds,row_version,lease_owner,config_version FROM system_backup_v2_artifact_leases WHERE source_artifact_type='backup' AND source_public_id=? ORDER BY id LIMIT 10001 FOR UPDATE`
const downloadGCTaskHolderLeaseSQL = `SELECT id,origin_installation_id,source_artifact_type,source_public_id,lease_generation,lease_mode,holder_type,holder_public_id,purpose,heartbeat_at,expires_at,lease_ttl_seconds,row_version,lease_owner,config_version FROM system_backup_v2_artifact_leases WHERE holder_type=? AND holder_public_id=? ORDER BY id LIMIT 10001 FOR UPDATE`
const downloadGCTaskStagingSQL = `SELECT id,origin_installation_id,lifecycle,claim_owner,claim_expires_at,row_version,cleanup_result,last_failure_code FROM system_backup_v2_staging_resources WHERE backup_public_id=? ORDER BY id LIMIT 10001 FOR UPDATE`
const downloadGCTaskRestoreSQL = `SELECT id,origin_installation_id,lifecycle,claim_owner,claim_expires_at,row_version,'',last_failure_code FROM system_backup_v2_restore_drill_resources WHERE drill_public_id=? ORDER BY id LIMIT 10001 FOR UPDATE`
const downloadGCTaskBackupPromotionSQL = `SELECT id FROM system_backup_v2_promotions WHERE backup_public_id=? LIMIT 1 FOR UPDATE`
const downloadGCTaskDrillPromotionSQL = `SELECT id FROM system_backup_v2_promotions WHERE drill_public_id=? LIMIT 1 FOR UPDATE`
const downloadGCTaskPruneDependencySQL = `SELECT id FROM system_backup_v2_prune_items WHERE artifact_public_id=? LIMIT 1 FOR UPDATE`

func downloadGCTaskDependentSQL(kind string) string {
	if !oneOf(kind, "drill", "preflight", "artifact_verify") {
		return ""
	}
	return "SELECT " + downloadGCTaskProjection(kind) + " FROM " + taskTable(kind) + " WHERE source_public_id=? ORDER BY id LIMIT 10001 FOR UPDATE"
}

// Only closed, published table names reach SQL. A nonlocking source hint selects
// the backup key before L4; the locked child must independently match it. Lock
// backup before child, then ranges in a fixed order. No source is derived from a
// deadline, current TTL, evidence type, metadata name or caller-supplied SQL.
func downloadGCTaskSQL(kind string, hint bool) string {
	table := taskTable(kind)
	if table == "" {
		return ""
	}
	if hint {
		return "SELECT source_artifact_type,source_public_id FROM " + table + " WHERE public_id=?"
	}
	return "SELECT " + downloadGCTaskProjection(kind) + " FROM " + table + " WHERE public_id=? FOR UPDATE"
}

func downloadGCTaskProjection(kind string) string {
	q := "id,origin_installation_id,public_id,task_type,schema_version,status,row_version,deadline_at,created_at,finished_at,controller_owner,controller_lease_expires_at,next_reconcile_at,"
	if kind == "backup" {
		q += "'backup',public_id,artifact_state,artifact_committed_at,artifact_usable,artifact_unusable_reason,manual_hold,promotion_hold,commit_started_at,prune_guard_version,'',''"
	} else {
		q += "source_artifact_type,source_public_id,'',NULL,FALSE,'',FALSE,FALSE,NULL,0,"
		if kind == "drill" {
			q += "cleanup_status,cleanup_failure_code"
		} else {
			q += "'',''"
		}
	}
	return q
}

func downloadGCTaskRetrySQL(kind string) string {
	if table := taskTable(kind); table != "" {
		return "SELECT id FROM " + table + " WHERE retry_of_public_id=? LIMIT 1 FOR UPDATE"
	}
	return ""
}

type gcTaskFacts struct {
	id, version, pruneVersion                                              int64
	installation, publicID, kind, schema, status                           string
	deadline, created                                                      time.Time
	finished, controllerLease, nextReconcile, committed, committing        sql.NullTime
	controller                                                             sql.NullString
	sourceKind, sourceID, artifactState, unusable, cleanup, cleanupFailure string
	usable, manualHold, promotionHold                                      bool
}

func readGCTask(ctx context.Context, tx *sql.Tx, kind, id, installation string, admitted, now time.Time) (gcTaskFacts, error) {
	return scanGCTask(tx.QueryRowContext(ctx, downloadGCTaskSQL(kind, false), id), kind, id, installation, admitted, now)
}

func scanGCTask(row taskDownloadScanner, kind, id, installation string, admitted, now time.Time) (gcTaskFacts, error) {
	var f gcTaskFacts
	err := row.Scan(
		&f.id, &f.installation, &f.publicID, &f.kind, &f.schema, &f.status, &f.version, &f.deadline, &f.created, &f.finished,
		&f.controller, &f.controllerLease, &f.nextReconcile, &f.sourceKind, &f.sourceID, &f.artifactState, &f.committed,
		&f.usable, &f.unusable, &f.manualHold, &f.promotionHold, &f.committing, &f.pruneVersion, &f.cleanup, &f.cleanupFailure)
	pattern := ownerPatterns[kind]
	if err != nil || f.id < 1 || f.version < 1 || f.version > 9007199254740991 || pattern == nil || !pattern.MatchString(f.publicID) || id != "" && f.publicID != id || f.installation != installation || f.kind != kind ||
		f.schema != "system-backup-task.v1" || !oneOf(f.status, "succeeded", "failed", "canceled") ||
		!downloadAdmissionContentTime(f.created) || !downloadAdmissionContentTime(f.deadline) || !f.created.Before(f.deadline) || f.deadline.After(now) || f.created.After(admitted) ||
		!f.finished.Valid || !downloadAdmissionContentTime(f.finished.Time) || f.finished.Time.Before(f.created) || f.finished.Time.After(now) || f.nextReconcile.Valid ||
		!gcTaskExpiredClaim(f.controller, f.controllerLease, now) {
		return f, ErrDenied
	}
	return f, nil
}

func gcTaskExpiredClaim(owner sql.NullString, expiry sql.NullTime, now time.Time) bool {
	return !owner.Valid && !expiry.Valid || owner.Valid && expiry.Valid && s3Token([]byte(owner.String), 1, 128) && downloadAdmissionContentTime(expiry.Time) && !expiry.Time.After(now)
}

func readGCTaskDependents(ctx context.Context, tx *sql.Tx, kind, backup, installation string, backupCreated, now time.Time) ([]gcTaskFacts, error) {
	rows, err := tx.QueryContext(ctx, downloadGCTaskDependentSQL(kind), backup)
	if err != nil {
		return nil, ErrDenied
	}
	defer rows.Close()
	out := []gcTaskFacts{}
	seen := map[string]bool{}
	for rows.Next() {
		f, err := scanGCTask(rows, kind, "", installation, now, now)
		if err != nil || len(out) >= maxTaskDownloadReferences || len(out) > 0 && f.id <= out[len(out)-1].id || seen[f.publicID] ||
			f.sourceKind != "backup" || f.sourceID != backup || f.created.Before(backupCreated) ||
			kind == "drill" && (!oneOf(f.cleanup, "not_started", "succeeded") || f.cleanupFailure != "none") {
			return nil, ErrDenied
		}
		seen[f.publicID] = true
		out = append(out, f)
	}
	if rows.Err() != nil || rows.Close() != nil {
		return nil, ErrDenied
	}
	return out, nil
}

type gcTaskResource struct {
	id, version                               int64
	installation, lifecycle, cleanup, failure string
	claim                                     sql.NullString
	expiry                                    sql.NullTime
}

func readGCTaskResources(ctx context.Context, tx *sql.Tx, q, id, installation string, now time.Time) ([]gcTaskResource, error) {
	rows, err := tx.QueryContext(ctx, q, id)
	if err != nil {
		return nil, ErrDenied
	}
	defer rows.Close()
	out := []gcTaskResource{}
	for rows.Next() {
		var f gcTaskResource
		if rows.Scan(&f.id, &f.installation, &f.lifecycle, &f.claim, &f.expiry, &f.version, &f.cleanup, &f.failure) != nil ||
			len(out) >= maxTaskDownloadReferences || f.id < 1 || f.version < 1 || f.version > 9007199254740991 ||
			len(out) > 0 && f.id <= out[len(out)-1].id || f.installation != installation || !oneOf(f.lifecycle, "absent", "deleted") || f.failure != "none" ||
			!gcTaskExpiredClaim(f.claim, f.expiry, now) ||
			q == downloadGCTaskStagingSQL && f.cleanup != "succeeded" {
			return nil, ErrDenied
		}
		out = append(out, f)
	}
	if rows.Err() != nil || rows.Close() != nil {
		return nil, ErrDenied
	}
	return out, nil
}

type gcTaskLeaseState struct {
	id, generation, version int64
	installation, mode      string
}

type gcTaskLease struct {
	id, generation, ttl, version, configVersion                                    int64
	installation, sourceKind, sourceID, mode, holderKind, holderID, purpose, owner string
	heartbeat, expiry                                                              time.Time
}

func readGCTaskLeaseState(ctx context.Context, tx *sql.Tx, id, installation string) ([]gcTaskLeaseState, error) {
	rows, err := tx.QueryContext(ctx, downloadGCTaskLeaseStateSQL, id)
	if err != nil {
		return nil, ErrDenied
	}
	defer rows.Close()
	out := []gcTaskLeaseState{}
	for rows.Next() {
		var f gcTaskLeaseState
		if rows.Scan(&f.id, &f.installation, &f.mode, &f.generation, &f.version) != nil || len(out) != 0 || f.id < 1 || f.generation < 1 || f.version < 1 || f.version > 9007199254740991 || f.installation != installation || !oneOf(f.mode, "shared", "delete") {
			return nil, ErrDenied
		}
		out = append(out, f)
	}
	if rows.Err() != nil || rows.Close() != nil {
		return nil, ErrDenied
	}
	return out, nil
}

func readGCTaskLeases(ctx context.Context, tx *sql.Tx, q string, args []any, backup, installation string, state []gcTaskLeaseState, now time.Time) ([]gcTaskLease, error) {
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, ErrDenied
	}
	defer rows.Close()
	out := []gcTaskLease{}
	for rows.Next() {
		var f gcTaskLease
		if rows.Scan(&f.id, &f.installation, &f.sourceKind, &f.sourceID, &f.generation, &f.mode, &f.holderKind, &f.holderID, &f.purpose, &f.heartbeat, &f.expiry, &f.ttl, &f.version, &f.owner, &f.configVersion) != nil ||
			len(out) >= maxTaskDownloadReferences || f.id < 1 || len(out) > 0 && f.id <= out[len(out)-1].id || f.version < 1 || f.version > 9007199254740991 ||
			f.installation != installation || f.sourceKind != "backup" || f.sourceID != backup || len(state) != 1 || f.generation != state[0].generation || f.mode != state[0].mode ||
			f.ttl < 15 || f.ttl > 300 || f.configVersion < 1 || f.configVersion > 9007199254740991 || !s3Token([]byte(f.owner), 1, 128) || !downloadAdmissionContentTime(f.heartbeat) || !downloadAdmissionContentTime(f.expiry) || !f.heartbeat.Before(f.expiry) || f.expiry.After(now) || f.expiry.Sub(f.heartbeat) > time.Duration(f.ttl)*time.Second {
			return nil, ErrDenied
		}
		p := ownerPatterns[f.holderKind]
		if f.holderKind == "prune" {
			p = ownerPatterns["prune_run"]
		}
		if f.holderKind == "health_reconcile" {
			if !downloadAdmissionOperationID.MatchString(f.holderID) || f.purpose != "verify" || f.mode != "shared" {
				return nil, ErrDenied
			}
		} else if p == nil || !p.MatchString(f.holderID) ||
			!(oneOf(f.holderKind, "drill", "preflight") && f.purpose == "read" && f.mode == "shared" ||
				f.holderKind == "artifact_verify" && f.purpose == "verify" && f.mode == "shared" ||
				f.holderKind == "prune" && f.purpose == "delete" && f.mode == "delete") {
			return nil, ErrDenied
		}
		if q == downloadGCTaskHolderLeaseSQL && (f.holderKind != args[0] || f.holderID != args[1]) {
			return nil, ErrDenied
		}
		out = append(out, f)
	}
	if rows.Err() != nil || rows.Close() != nil {
		return nil, ErrDenied
	}
	return out, nil
}

type gcTaskSnapshot struct {
	owner, backup              gcTaskFacts
	dependents                 []gcTaskFacts
	dependentResources         map[string][]gcTaskResource
	dependentHolderLeases      map[string][]gcTaskLease
	staging, restore           []gcTaskResource
	leaseState                 []gcTaskLeaseState
	sourceLeases, holderLeases []gcTaskLease
}

func gcTaskEmptyRange(ctx context.Context, tx *sql.Tx, q, id string) error {
	var found int64
	if err := tx.QueryRowContext(ctx, q, id).Scan(&found); err != sql.ErrNoRows {
		return ErrDenied
	}
	return nil
}

func gcTaskTables(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, downloadGCTaskTablesSQL)
	if err != nil {
		return ErrDenied
	}
	defer rows.Close()
	expected := map[string]bool{}
	for _, t := range taskDownloadTables() {
		expected[t.table] = true
	}
	for _, table := range []string{"system_backup_v2_artifact_lease_states", "system_backup_v2_artifact_leases", "system_backup_v2_staging_resources", "system_backup_v2_restore_drill_resources", "system_backup_v2_promotions", "system_backup_v2_prune_items"} {
		expected[table] = true
	}
	for rows.Next() {
		var name, kind, engine string
		if rows.Scan(&name, &kind, &engine) != nil || !expected[name] || kind != "BASE TABLE" || engine != "InnoDB" {
			return ErrDenied
		}
		delete(expected, name)
	}
	if len(expected) != 0 || rows.Err() != nil || rows.Close() != nil {
		return ErrDenied
	}
	return nil
}

func (s *SQLDownloadGCTaskEligibility) read(ctx context.Context, tx *sql.Tx, scope DownloadRetentionGCScope, backup string, original *gcTaskSnapshot, now time.Time) (gcTaskSnapshot, error) {
	var out gcTaskSnapshot
	var server, database string
	if tx.QueryRowContext(ctx, downloadGCTaskDatabaseSQL).Scan(&server, &database) != nil || server != s.c.Database.ServerUUID || database != s.c.Database.Database || gcTaskTables(ctx, tx) != nil {
		return out, ErrDenied
	}
	var err error
	out.backup, err = readGCTask(ctx, tx, "backup", backup, s.c.Installation, scope.AdmittedAt, now)
	if err != nil {
		return out, err
	}
	b := out.backup
	if b.manualHold || b.promotionHold || b.usable || b.pruneVersion < 1 || b.pruneVersion > 9007199254740991 ||
		b.committed.Valid && (!downloadAdmissionContentTime(b.committed.Time) || b.committed.Time.Before(b.created) || b.committed.Time.After(now)) ||
		b.committing.Valid && (!downloadAdmissionContentTime(b.committing.Time) || b.committing.Time.Before(b.created) || b.committing.Time.After(now)) ||
		!(b.artifactState == "deleted" && b.unusable == "deleted" || b.artifactState == "staging" && b.unusable == "not_committed" && !b.committed.Valid && !b.committing.Valid) {
		return out, ErrDenied
	}
	out.owner = b
	if scope.Evidence.OwnerType != "backup" {
		out.owner, err = readGCTask(ctx, tx, scope.Evidence.OwnerType, scope.Evidence.OwnerID, s.c.Installation, scope.AdmittedAt, now)
		if err != nil || out.owner.sourceKind != "backup" || out.owner.sourceID != backup || b.created.After(out.owner.created) ||
			scope.Evidence.OwnerType == "drill" && (!oneOf(out.owner.cleanup, "not_started", "succeeded") || out.owner.cleanupFailure != "none") {
			return out, ErrDenied
		}
	}
	if original != nil && out.owner.id != original.owner.id {
		return out, ErrDenied
	}
	out.dependents = []gcTaskFacts{}
	out.dependentResources = map[string][]gcTaskResource{}
	out.dependentHolderLeases = map[string][]gcTaskLease{}
	for _, kind := range []string{"artifact_verify", "preflight", "drill"} {
		facts, err := readGCTaskDependents(ctx, tx, kind, backup, s.c.Installation, b.created, now)
		if err != nil {
			return out, ErrDenied
		}
		ownerSeen := false
		for _, f := range facts {
			if f.kind == out.owner.kind && f.id == out.owner.id {
				if f != out.owner {
					return out, ErrDenied
				}
				ownerSeen = true
			}
		}
		if kind == out.owner.kind && !ownerSeen {
			return out, ErrDenied
		}
		if len(out.dependents)+len(facts) > maxTaskDownloadReferences {
			return out, ErrDenied
		}
		out.dependents = append(out.dependents, facts...)
	}
	// A changed membership/fact must fail before selecting any new resource
	// range during a later-phase recheck. Expired terminal siblings may remain;
	// requiring their absence would create mutually blocked metadata groups.
	if original != nil && !reflect.DeepEqual(out.dependents, original.dependents) {
		return out, ErrDenied
	}
	resourceCount := 0
	for _, f := range out.dependents {
		if f.kind == out.owner.kind && f.id == out.owner.id {
			continue
		}
		if gcTaskEmptyRange(ctx, tx, downloadGCTaskRetrySQL(f.kind), f.publicID) != nil {
			return out, ErrDenied
		}
		if f.kind != "drill" {
			continue
		}
		if gcTaskEmptyRange(ctx, tx, downloadGCTaskDrillPromotionSQL, f.publicID) != nil {
			return out, ErrDenied
		}
		resources, err := readGCTaskResources(ctx, tx, downloadGCTaskRestoreSQL, f.publicID, s.c.Installation, now)
		if err != nil || f.cleanup == "not_started" && len(resources) != 0 {
			return out, ErrDenied
		}
		resourceCount += len(resources)
		if resourceCount > maxTaskDownloadReferences {
			return out, ErrDenied
		}
		out.dependentResources[f.publicID] = resources
	}
	// Even terminal/deleted prune items remain references until their own
	// reviewed lifecycle removes them. Scope/status/source-type predicates may
	// not hide a contradictory incoming link to this backup public ID.
	if gcTaskEmptyRange(ctx, tx, downloadGCTaskPruneDependencySQL, backup) != nil {
		return out, ErrDenied
	}
	// No installation/status filter may hide a contradictory incoming link.
	// Retained promotions/retries still protect their source until their own
	// reviewed lifecycle has removed that reference; a flag alone is insufficient.
	if gcTaskEmptyRange(ctx, tx, downloadGCTaskRetrySQL("backup"), backup) != nil || gcTaskEmptyRange(ctx, tx, downloadGCTaskBackupPromotionSQL, backup) != nil {
		return out, ErrDenied
	}
	if scope.Evidence.OwnerType != "backup" && gcTaskEmptyRange(ctx, tx, downloadGCTaskRetrySQL(scope.Evidence.OwnerType), scope.Evidence.OwnerID) != nil ||
		scope.Evidence.OwnerType == "drill" && gcTaskEmptyRange(ctx, tx, downloadGCTaskDrillPromotionSQL, scope.Evidence.OwnerID) != nil {
		return out, ErrDenied
	}
	if out.staging, err = readGCTaskResources(ctx, tx, downloadGCTaskStagingSQL, backup, s.c.Installation, now); err != nil {
		return out, err
	}
	if scope.Evidence.OwnerType == "drill" {
		out.restore, err = readGCTaskResources(ctx, tx, downloadGCTaskRestoreSQL, scope.Evidence.OwnerID, s.c.Installation, now)
		if err != nil || out.owner.cleanup == "not_started" && len(out.restore) > 0 {
			return out, ErrDenied
		}
	}
	if out.leaseState, err = readGCTaskLeaseState(ctx, tx, backup, s.c.Installation); err != nil {
		return out, err
	}
	out.sourceLeases, err = readGCTaskLeases(ctx, tx, downloadGCTaskSourceLeaseSQL, []any{backup}, backup, s.c.Installation, out.leaseState, now)
	if err != nil {
		return out, err
	}
	if scope.Evidence.OwnerType != "backup" {
		out.holderLeases, err = readGCTaskLeases(ctx, tx, downloadGCTaskHolderLeaseSQL, []any{scope.Evidence.OwnerType, scope.Evidence.OwnerID}, backup, s.c.Installation, out.leaseState, now)
		if err != nil {
			return out, err
		}
	}
	sourceLeases := map[int64]gcTaskLease{}
	for _, lease := range out.sourceLeases {
		sourceLeases[lease.id] = lease
	}
	for _, f := range out.dependents {
		if f.kind == out.owner.kind && f.id == out.owner.id {
			continue
		}
		leases, err := readGCTaskLeases(ctx, tx, downloadGCTaskHolderLeaseSQL, []any{f.kind, f.publicID}, backup, s.c.Installation, out.leaseState, now)
		if err != nil {
			return out, ErrDenied
		}
		for _, lease := range leases {
			if original, found := sourceLeases[lease.id]; !found || !reflect.DeepEqual(original, lease) {
				return out, ErrDenied
			}
		}
		out.dependentHolderLeases[f.publicID] = leases
	}
	return out, err
}

type gcTaskEligibilityState struct {
	sync.Mutex
	failed bool
	lastAt time.Time
}

type DownloadGCTaskEligibilityGuard struct {
	source   *SQLDownloadGCTaskEligibility
	tx       *sql.Tx
	scope    DownloadRetentionGCScope
	backup   string
	original gcTaskSnapshot
	state    *gcTaskEligibilityState
}

func (DownloadGCTaskEligibilityGuard) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (DownloadGCTaskEligibilityGuard) String() string               { return "DownloadGCTaskEligibilityGuard" }
func (DownloadGCTaskEligibilityGuard) GoString() string             { return "DownloadGCTaskEligibilityGuard" }

func (s *SQLDownloadGCTaskEligibility) Lock(ctx context.Context, tx *sql.Tx, scope DownloadRetentionGCScope, now time.Time) (*DownloadGCTaskEligibilityGuard, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || tx == nil || scope.Database != s.c.Database || scope.Installation != s.c.Installation ||
		!taskDownloadIdentity(SQLRegistry{Installation: s.c.Installation}, scope.Evidence) || !digestPattern.MatchString(scope.PrincipalSHA256) ||
		!downloadAdmissionOperationID.MatchString(scope.WorkerOperation) || !downloadAdmissionOperationID.MatchString(scope.Operation) || scope.WorkerOperation == scope.Operation ||
		!digestPattern.MatchString(scope.RequestHash) || scope.OperationID < 1 || scope.EvidenceID < 1 || scope.EvidenceRowVersion < 1 || scope.ActorID < 1 ||
		scope.IntentAuditID < 1 || scope.ResultAuditID < 1 || scope.IntentAuditID == scope.ResultAuditID ||
		!downloadAdmissionContentTime(now) || !downloadAdmissionContentTime(scope.AdmittedAt) || scope.AdmittedAt.After(now) ||
		!downloadAdmissionContentTime(scope.RetainUntil) || !downloadAdmissionContentTime(scope.MinimumRetainUntil) || scope.RetainUntil.Before(scope.AdmittedAt) || scope.MinimumRetainUntil.Before(scope.AdmittedAt) || scope.RetainUntil.After(now) || scope.MinimumRetainUntil.After(now) {
		return nil, ErrDenied
	}
	backup := scope.Evidence.OwnerID
	if scope.Evidence.OwnerType != "backup" {
		var source string
		if tx.QueryRowContext(ctx, downloadGCTaskSQL(scope.Evidence.OwnerType, true), scope.Evidence.OwnerID).Scan(&source, &backup) != nil || source != "backup" || !ownerPatterns["backup"].MatchString(backup) {
			return nil, ErrDenied
		}
	}
	original, err := s.read(ctx, tx, scope, backup, nil, now)
	if err != nil {
		return nil, ErrDenied
	}
	return &DownloadGCTaskEligibilityGuard{source: s, tx: tx, scope: scope, backup: backup, original: original, state: &gcTaskEligibilityState{lastAt: now}}, nil
}

func (g *DownloadGCTaskEligibilityGuard) Recheck(ctx context.Context, tx *sql.Tx, scope DownloadRetentionGCScope, now time.Time) error {
	if g == nil || g.state == nil {
		return ErrDenied
	}
	g.state.Lock()
	defer g.state.Unlock()
	fail := func() error { g.state.failed = true; return ErrDenied }
	if g.state.failed || g.source == nil || ctx == nil || ctx.Err() != nil || tx != g.tx || scope != g.scope || !downloadAdmissionContentTime(now) || now.Before(g.state.lastAt) {
		return fail()
	}
	// SAME keys and predicates, all current locking reads, no hint refresh and
	// no new prefix lock after later phases. Eligible-but-changed also denies.
	current, err := g.source.read(ctx, tx, scope, g.backup, &g.original, now)
	if err != nil || !reflect.DeepEqual(current, g.original) {
		return fail()
	}
	g.state.lastAt = now
	return nil
}

var _ DownloadRetentionGCGuard = (*DownloadGCTaskEligibilityGuard)(nil)
