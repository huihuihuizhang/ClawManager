//go:build systembackup_mysql

package systembackupevidence

import (
	"context"
	"database/sql"
	"database/sql/driver"
	_ "embed"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

// Candidate CHECK change ONLY inside the exact UID-owned cloned database.
// This is not an embedded migration or an approval for a live upgrade.
//
//go:embed testdata/download-gc-full-cold-schema.sql
var dGCColdSchema []byte

var dGCColdCases = []string{"commit", "late_policy_denied", "last_delete_reply_lost", "commit_reply_lost", "rollback_reply_lost", "unlock_reply_lost", "cancel_after_work"}

type dGCColdStatement struct {
	query string
	args  []any
}

func dGCColdValues(values []driver.Value) []any {
	out := make([]any, len(values))
	for n, v := range values {
		out[n] = v
	}
	return out
}
func dGCColdWithID(query string) string {
	return strings.Replace(strings.Replace(query, "(", "(id,", 1), "VALUES (", "VALUES (?,", 1)
}

// Reuse the already validated sealed cold facts. No historical proof is
// renewed, FK disabled, production deadline relaxed, or row UPDATE used to age
// a live admission. All group rows are inserted directly with matching keys.
func dGCColdGroupStatements(t *testing.T, m *retentionGCFixture) []dGCColdStatement {
	t.Helper()
	d := m.d
	r := d.record
	i := r.Manifest.Identity
	if len(d.m.op) != 14 || len(d.m.receipt) != 16 || len(d.nonce) != 16 || len(d.resultRetention) != 11 || r.State != "deleted" {
		t.Fatal("invalid original cold model")
	}
	statements := []dGCColdStatement{
		{`INSERT INTO system_backup_v2_evidence(id,public_id,origin_installation_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,evidence_failure_code,content_checksum,content_size_bytes,media_type,encryption,envelope_framing_version,kek_identity_hash,kek_version,envelope_hash,redaction_classification,observed_health,expires_at,protected_until,row_version,created_at) VALUES(61,?,?,?,?,?,'deleted','none',?,?,?,'envelope_v1',?,?,?,?,?,'unknown',?,?,?,?)`, []any{i.ID, i.Installation, i.OwnerType, i.OwnerID, i.Type, i.ContentHash, i.ContentSize, i.Media, Framing, r.Manifest.Key.Identity, r.Manifest.Key.Version, r.Manifest.EnvelopeHash, i.Classification, r.ExpiresAt, r.ProtectedUntil, r.RowVersion, r.CreatedAt}},
		{dGCColdWithID(downloadIntentInsertSQL), []any{int64(1729), int64(42), append([]byte(nil), d.body...), d.created}},
		{dGCColdWithID(downloadResultInsertSQL), []any{int64(1730), int64(42), append([]byte(nil), d.resultBody...), d.resultCreated}},
		{dGCColdWithID(downloadAdmissionOperationInsertSQL), append([]any{int64(73)}, dGCColdValues(d.m.op)...)},
		{downloadAdmissionReceiptInsertSQL, dGCColdValues(d.m.receipt)},
	}
	n := d.nonce
	statements = append(statements, dGCColdStatement{`INSERT INTO system_backup_v2_strong_auth_nonces(id,origin_installation_id,issuer_sha256,subject_sha256,session_sha256,nonce_hmac,nonce_hmac_key_version,endpoint,request_hash,idempotency_key,authenticated_at,expires_at,consumed_at,operation_id,response_sha256,audit_log_id,retain_until,created_at) VALUES(95,?,?,?,?,?,?,'getSystemBackupEvidence',?,?,?,?,?,?,NULL,?,?,?)`, []any{n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7], n[8], n[9], d.consumed, n[10], n[11], n[12], d.consumed}}, dGCColdStatement{downloadResultRetentionInsertSQL, dGCColdValues(d.resultRetention)})
	for _, statement := range statements {
		if strings.Count(statement.query, "?") != len(statement.args) {
			t.Fatal("cold SQL parameter mismatch")
		}
	}
	return statements
}

// Keep the same committed admission/result and sealed retention-group model,
// but obtain its config from the already validated embedded MFA capsule. Both
// the detached seed and remote SQL fixture must work without a checkout.
func dGCColdModelFixture(t *testing.T, input aDownloadMFAInputs) *retentionGCFixture {
	t.Helper()
	f := newAdmissionTxFixtureWithConfig(t, func(t *testing.T, rbac string) (sec.ConfigValues, map[string]driver.Value) {
		return admissionConfigBytes(t, input.EffectiveConfig, rbac)
	})
	// This is the original uncommittedConfiguredFixture setup, with only its
	// config source supplied above. Do not skip the authority constructor or
	// replace the real admission/result transitions with fabricated rows.
	r := f.initial
	r.Ref.Identity = f.db.configCells["evidence_store_identity_hash"].(string)
	r.Ref.Version = f.db.configCells["evidence_store_ref_version"].(string)
	var err error
	r.Ref.RelativeKey, err = keyFor("evidence", r.Manifest.Identity)
	dGCFreezeOK(t, err)
	f.initial, f.db.record, f.env.hint, f.db.m.f.Record = r, r, r, r
	f.env.reservationUntil = f.db.now.Add(20 * time.Second)
	f.service.registry.Policy = &committedTestPolicy{downloadTestPolicy: &downloadTestPolicy{deadline: r.OwnerDeadline}, db: f.db}
	dir := t.TempDir()
	writeAdmissionPinnedFile(t, filepath.Join(dir, "rbac_bindings", "v1", f.env.rbacHash+".json"), f.env.rbac)
	_, err = NewSQLDownloadAuthority(DownloadAuthorityConfig{Registry: f.service.registry, JWTSecret: f.secret,
		ConfigVersion: 1, ConfigSHA256: f.db.config.SHA256(), RBACVersion: "v1", RBACSHA256: f.env.rbacHash, RegistryDirectory: dir,
		Root: "evidence", Store: KeyRef{r.Ref.Identity, r.Ref.Version},
		Read:   KeyRef{f.db.configCells["evidence_read_identity_hash"].(string), f.db.configCells["evidence_read_ref_version"].(string)},
		Issuer: "https://issuer.local", Audience: "download-provider", Subject: "system:download", TokenFile: filepath.Join(dir, "token"), ExpiresAt: f.db.now.Add(2 * time.Minute)})
	dGCFreezeOK(t, err)
	committed, err := f.service.Admit(f.request)
	dGCFreezeOK(t, err)
	if committed == nil {
		t.Fatal("capsule cold admission missing")
	}
	dGCFreezeOK(t, resultFixture(t, f).Finish(context.Background(), committed, DownloadResultObservation{Outcome: "interrupted", BytesWritten: 3}))
	return newRetentionGCFixtureFromGroup(t, f, committed.operationID, time.Hour)
}

func TestDDownloadGCFullCollectMySQLSeed(t *testing.T) {
	seen := map[string]bool{}
	for _, name := range dGCColdCases {
		if seen[name] {
			t.Fatal("duplicate cold case")
		}
		seen[name] = true
	}
	if len(seen) != 7 {
		t.Fatal("cold case count")
	}
	if !strings.Contains(string(dGCColdSchema), "storage_state='deleted'") || strings.Contains(string(dGCColdSchema), "FOREIGN_KEY_CHECKS") {
		t.Fatal("candidate GC schema scope")
	}
	input, err := decodeADownloadMFAInputs(aDownloadMFASeed)
	dGCFreezeOK(t, err)
	m := dGCColdModelFixture(t, input)
	statements := dGCColdGroupStatements(t, m)
	if len(statements) != 7 {
		t.Fatal("cold group incomplete")
	}
	if err := m.s.Collect(m.ctx, m.operation); err != nil {
		t.Fatal("original sealed cold facts fail protected collector", err)
	}
	t.Log("PASS full_collect_seed cases=7 actual_mysql=not_run schema=candidate_only authority=synthetic_known_task_domain physical_capacity=no production=no")
}

type dGCColdPolicy struct {
	profile   *dGCFullProfileAuthority
	collector *SQLDownloadRetentionGC
	tasks     *SQLDownloadGCTaskEligibility
	schema    map[string]string
	mode      string
}

func (p *dGCColdPolicy) AdmitFreezeSession(ctx context.Context, c *sql.Conn, s DownloadGCFreezeScope) error {
	if p.collector == nil {
		return ErrDenied
	}
	cfg := p.collector.c
	if s.WorkerOperation != cfg.OperationID || s.ConfigVersion != cfg.ConfigVersion || s.ConfigSHA256 != cfg.ConfigSHA256 || s.WorkerRowVersion != cfg.OperationRowVersion || s.PeerCertificateSHA256 != cfg.CertificateSHA256 || !s.AuthorityExpiresAt.Equal(cfg.ExpiresAt) {
		return ErrDenied
	}
	return p.profile.AdmitFreezeSession(ctx, c, s)
}
func (p *dGCColdPolicy) verifySchema(ctx context.Context, tx *sql.Tx) error {
	names := make([]string, 0, len(p.schema))
	for name := range p.schema {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		var table, ddl string
		if tx.QueryRowContext(ctx, "SHOW CREATE TABLE `"+name+"`").Scan(&table, &ddl) != nil || table != name || p.schema[name] == "" || dGCColdSchemaPin(ddl) == "" || dGCColdSchemaPin(ddl) != p.schema[name] {
			return ErrDenied
		}
	}
	return nil
}
func (p *dGCColdPolicy) Early(ctx context.Context, tx *sql.Tx, h DownloadGCEarlyScope, _ time.Time) (DownloadRetentionGCGuard, error) {
	if p.collector == nil || p.verifySchema(ctx, tx) != nil || h.Installation != p.collector.c.Registry.Installation || h.WorkerOperation != p.collector.c.OperationID || h.PrincipalSHA256 != p.collector.principal {
		return nil, ErrDenied
	}
	g := &DownloadGCEarlyReferenceGuard{source: p.collector.freeze.worker, tx: tx, hint: h, state: &downloadGCEarlyReferenceState{}}
	if g.references(ctx, tx) != nil {
		return nil, ErrDenied
	}
	return &dGCColdEarlyGuard{policy: p, original: g}, nil
}

type dGCColdEarlyGuard struct {
	policy   *dGCColdPolicy
	original *DownloadGCEarlyReferenceGuard
}

func (g *dGCColdEarlyGuard) Recheck(ctx context.Context, tx *sql.Tx, s DownloadRetentionGCScope, _ time.Time) error {
	h := g.original.hint
	if tx != g.original.tx || s.Database != h.Database || s.Installation != h.Installation || s.WorkerOperation != h.WorkerOperation || s.PrincipalSHA256 != h.PrincipalSHA256 || s.Operation != h.Operation || s.OperationID != h.OperationID || s.IntentAuditID != h.IntentAuditID || s.ResultAuditID != h.ResultAuditID || s.ActorID != h.ActorID || g.policy.verifySchema(ctx, tx) != nil {
		return ErrDenied
	}
	return g.original.references(ctx, tx)
}
func (p *dGCColdPolicy) Lock(ctx context.Context, tx *sql.Tx, s DownloadRetentionGCScope, now time.Time) (DownloadRetentionGCGuard, error) {
	// Only explicitly constructed published task rows. Catalog/import/system
	// authority is neither inferred nor approved by this isolated fixture.
	if !oneOf(s.Evidence.OwnerType, "backup", "drill", "preflight", "artifact_verify") {
		return nil, ErrDenied
	}
	g, err := p.tasks.Lock(ctx, tx, s, now)
	if err != nil {
		return nil, err
	}
	return &dGCColdTaskGuard{policy: p, guard: g}, nil
}

type dGCColdTaskGuard struct {
	policy *dGCColdPolicy
	guard  *DownloadGCTaskEligibilityGuard
	checks int
}

func (g *dGCColdTaskGuard) Recheck(ctx context.Context, tx *sql.Tx, s DownloadRetentionGCScope, now time.Time) error {
	g.checks++
	if (g.policy.mode == "late_policy_denied" || g.policy.mode == "rollback_reply_lost") && g.checks == 3 {
		return ErrDenied
	}
	return g.guard.Recheck(ctx, tx, s, now)
}

type dGCColdTrace struct {
	sync.Mutex
	inner                                                   driver.Connector
	mode                                                    string
	cancel                                                  context.CancelFunc
	connections, begins, commits, rollbacks, closed, writes int
	last, prior                                             string
	finalTicket                                             bool
}

func (t *dGCColdTrace) Driver() driver.Driver { return t.inner.Driver() }
func (t *dGCColdTrace) Connect(ctx context.Context) (driver.Conn, error) {
	c, err := t.inner.Connect(ctx)
	if err != nil {
		return nil, err
	}
	t.Lock()
	t.connections++
	t.Unlock()
	return &dGCColdConn{Conn: c, t: t}, nil
}

type dGCColdConn struct {
	driver.Conn
	t *dGCColdTrace
}

func (c *dGCColdConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	tx, err := c.Conn.(driver.ConnBeginTx).BeginTx(ctx, o)
	if err != nil {
		return nil, err
	}
	c.t.Lock()
	c.t.begins++
	c.t.Unlock()
	return &dGCColdTx{Tx: tx, t: c.t}, nil
}
func (c *dGCColdConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	c.t.Lock()
	final := q == downloadGCFreezeHeldSQL && c.t.writes == 7 && c.t.last == downloadIntentClockSQL && c.t.prior == "SELECT id FROM audit_logs WHERE id=?" && !c.t.finalTicket
	if final {
		c.t.finalTicket = true
	}
	c.t.prior, c.t.last = c.t.last, q
	c.t.Unlock()
	rows, err := c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
	if final && c.t.mode == "cancel_after_work" {
		c.t.cancel()
	}
	return rows, err
}
func (c *dGCColdConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if q == "UNLOCK INSTANCE" && c.t.mode == "unlock_reply_lost" {
		return nil, errors.New("synthetic full unlock reply loss")
	}
	result, err := c.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
	if err != nil {
		return nil, err
	}
	if oneOf(q, downloadGCTombstoneInsertSQL, downloadGCDeleteResultSQL, downloadGCDeleteNonceSQL, downloadGCDeleteReceiptSQL, downloadGCDeleteOperationSQL, downloadGCDeleteAuditSQL) {
		c.t.Lock()
		c.t.writes++
		lost := c.t.writes == 7 && c.t.mode == "last_delete_reply_lost"
		c.t.Unlock()
		if lost {
			return nil, errors.New("synthetic last delete reply loss")
		}
	}
	return result, nil
}
func (c *dGCColdConn) Close() error { c.t.Lock(); c.t.closed++; c.t.Unlock(); return c.Conn.Close() }

type dGCColdTx struct {
	driver.Tx
	t *dGCColdTrace
}

func (t *dGCColdTx) Commit() error {
	t.t.Lock()
	t.t.commits++
	t.t.Unlock()
	err := t.Tx.Commit()
	if err == nil && t.t.mode == "commit_reply_lost" {
		return errors.New("synthetic full commit reply loss")
	}
	return err
}
func (t *dGCColdTx) Rollback() error {
	t.t.Lock()
	t.t.rollbacks++
	t.t.Unlock()
	err := t.Tx.Rollback()
	if err == nil && t.t.mode == "rollback_reply_lost" {
		return errors.New("synthetic full rollback reply loss")
	}
	return err
}

type dGCColdFixture struct {
	p                      *dGCFullProfileFixture
	model                  *retentionGCFixture
	collector              *SQLDownloadRetentionGC
	trace                  *dGCColdTrace
	ctx                    context.Context
	cancel                 context.CancelFunc
	before, evidenceBefore string
}

func dGCColdExec(t *testing.T, ctx context.Context, db *sql.DB, query string, args ...any) {
	t.Helper()
	_, err := db.ExecContext(ctx, query, args...)
	dGCFreezeOK(t, err)
}
func newDGCColdFixture(t *testing.T, input aDownloadMFAInputs, mode string) *dGCColdFixture {
	t.Helper()
	m := dGCColdModelFixture(t, input)
	statements := dGCColdGroupStatements(t, m)
	p := newDGCFullProfileFixture(t, input)
	ctx, db := p.ddl.ctx, p.role.root
	if !regexp.MustCompile(`^amfa_[a-f0-9]{32}$`).MatchString(p.role.c.Database.Database) {
		t.Fatal("cold candidate schema outside owned clone")
	}
	dGCColdExec(t, ctx, db, string(dGCColdSchema))
	t.Log("CANDIDATE_GC_CHECKS uid_owned_clone=yes embedded_migration=no production_approval=no")
	installation := m.d.record.Manifest.Identity.Installation
	p.role.c.Installation = installation
	cells := aDownloadMFAConfigCells(m.p)
	rows, err := db.QueryContext(ctx, "SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='system_backup_v2_configs' ORDER BY ORDINAL_POSITION")
	dGCFreezeOK(t, err)
	var columns []string
	var args []any
	for rows.Next() {
		var name string
		dGCFreezeOK(t, rows.Scan(&name))
		if value, ok := cells[name]; ok {
			columns = append(columns, name)
			args = append(args, value)
		}
	}
	dGCFreezeOK(t, rows.Err())
	dGCFreezeOK(t, rows.Close())
	dGCColdExec(t, ctx, db, "INSERT INTO system_backup_v2_configs("+strings.Join(columns, ",")+") VALUES("+strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")+")", args...)
	now := aDownloadMFANow(t, ctx, db)
	dGCColdExec(t, ctx, db, "INSERT INTO system_backup_v2_installation_state(origin_installation_id,active_config_version,last_effective_enabled_transition_at,matrix_key) VALUES(?,1,?,'k8s-cluster')", installation, now.Add(-time.Hour))
	for _, row := range aTaskOwnerSQLSeeds(installation, now.Add(-800*24*time.Hour), now.Add(-500*24*time.Hour), m.d.config.CanonicalJSON()) {
		dGCColdExec(t, ctx, db, row.statement, row.args...)
		dGCColdExec(t, ctx, db, "UPDATE "+row.table+" SET status='failed',can_cancel=FALSE,failure_category='validation_failed',started_at=created_at,finished_at=? WHERE public_id=?", now.Add(-600*24*time.Hour), row.id)
	}
	dGCColdExec(t, ctx, db, "UPDATE system_backup_v2_backups SET artifact_state='deleted',artifact_unusable_reason='deleted',prune_guard_version=3 WHERE public_id=?", m.d.record.Manifest.Identity.OwnerID)
	dGCColdExec(t, ctx, db, "UPDATE system_backup_v2_restore_drills SET cleanup_status='succeeded'")
	for _, statement := range statements {
		dGCColdExec(t, ctx, db, statement.query, statement.args...)
	}
	empty := []byte("[]")
	dGCColdExec(t, ctx, db, `INSERT INTO system_backup_v2_operations(id,public_id,origin_installation_id,operation_type,target_type,target_public_id,actor_type,actor_id,endpoint,idempotency_key,request_hash,external_action_public_ids_canonical_json,external_action_public_ids_size_bytes,external_action_public_ids_sha256,status,claim_owner,claim_expires_at,row_version,deadline_at,started_at,next_reconcile_at,created_at,updated_at) VALUES(74,?,?,'control_metadata_gc','system',?,'system','system:controller','CollectSystemBackupControlMetadata','full-gc-cold-worker-fixture',?,?,2,?,'running',?,?,7,?,?,?,?,?)`, m.s.c.OperationID, installation, installation, hash([]byte("full-gc-cold-worker")), empty, hash(empty), m.s.c.OperationClaim, now.Add(time.Minute), now.Add(2*time.Minute), now, now, now, now)
	dGCColdExec(t, ctx, db, "INSERT INTO system_backup_v2_metadata_reservations(id,sample_at,reserved_bytes) VALUES(1,?,0)", now)
	var maintenance int
	dGCFreezeOK(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='system_backup_v2_config_maintenance_receipts'").Scan(&maintenance))
	if maintenance == 1 {
		p.role.c.MaintenanceReceipts = "installed"
	}
	allowed := gcFullReadTables(maintenance == 1)
	var names []string
	for name := range allowed {
		if name != "users" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	schema := map[string]string{}
	for _, name := range names {
		var count int
		dGCFreezeOK(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?", name).Scan(&count))
		if count == 0 {
			continue
		}
		dGCColdExec(t, ctx, db, "GRANT SELECT ON `"+p.role.c.Database.Database+"`.`"+name+"` TO '"+p.role.user+"'@'%'")
		var got, ddl string
		dGCFreezeOK(t, db.QueryRowContext(ctx, "SHOW CREATE TABLE `"+name+"`").Scan(&got, &ddl))
		if got != name {
			t.Fatal("cold schema identity")
		}
		schema[name] = dGCColdSchemaPin(ddl)
		if schema[name] == "" {
			t.Fatal("unknown SHOW CREATE format in synthetic domain schema pin")
		}
	}
	r, profile := p.runtime(t)
	tasks, err := NewSQLDownloadGCTaskEligibility(DownloadGCTaskEligibilityConfig{Database: p.role.c.Database, Installation: installation})
	dGCFreezeOK(t, err)
	policy := &dGCColdPolicy{profile: profile, tasks: tasks, schema: schema, mode: mode}
	trace := &dGCColdTrace{inner: r.connector, mode: mode}
	peer := newTaskFixture(t, false)
	config := m.s.c
	config.Registry = SQLRegistry{DB: p.role.db, ServerUUID: p.role.c.Database.ServerUUID, Database: p.role.c.Database.Database, Installation: installation, Policy: &gcConnectionPolicy{}}
	config.Policy = policy
	config.ClientCAPEM = peer.c.ClientCAPEM
	config.ClientCASHA256 = peer.c.ClientCASHA256
	config.CertificateSHA256 = peer.c.CertificateSHA256
	config.ExpiresAt = peer.c.ExpiresAt
	config.References, err = NewSQLDownloadGCDirectReferences(DownloadGCDirectReferencesConfig{Database: p.role.c.Database, Installation: installation, MaintenanceReceipts: p.role.c.MaintenanceReceipts})
	dGCFreezeOK(t, err)
	config.Capacity, err = sec.NewConfigMutationCapacity(p.role.c.Database, m.p.reportPath, 1)
	dGCFreezeOK(t, err)
	config.Freeze = &DownloadGCFullFreezeConfig{Connector: trace, WaitSeconds: 2, Worker: r.worker.c, Observer: p.observerConfig, ProgramsSHA256: r.programs}
	collector, err := NewSQLDownloadRetentionGC(config)
	dGCFreezeOK(t, err)
	policy.collector = collector
	authenticated, err := collector.AuthenticateRequest(peer.request)
	dGCFreezeOK(t, err)
	authenticated, cancel := context.WithCancel(authenticated)
	t.Cleanup(cancel)
	trace.cancel = cancel
	f := &dGCColdFixture{p: p, model: m, collector: collector, trace: trace, ctx: authenticated, cancel: cancel}
	f.before = f.fingerprint(t, false)
	f.evidenceBefore = f.fingerprint(t, true)
	// New physical-report fixture sample only; original cold facts stay sealed.
	m.p.report.ServerUUID = p.role.c.Database.ServerUUID
	m.p.report.Database = p.role.c.Database.Database
	m.p.report.ObservedAt = aDownloadMFANow(t, ctx, db)
	m.p.writeReport(t)
	return f
}

func (f *dGCColdFixture) fingerprint(t *testing.T, evidenceOnly bool) string {
	t.Helper()
	tables := []string{"audit_logs", "system_backup_v2_operations", "system_backup_v2_download_admission_receipts", "system_backup_v2_download_result_receipts", "system_backup_v2_strong_auth_nonces", "system_backup_v2_compact_tombstones", "system_backup_v2_metadata_reservations", "system_backup_v2_evidence", "system_backup_v2_evidence_chunks"}
	if evidenceOnly {
		tables = []string{"system_backup_v2_evidence", "system_backup_v2_evidence_chunks"}
	}
	var snapshot []any
	for _, table := range tables {
		rows, err := f.p.role.root.QueryContext(f.p.ddl.ctx, "SELECT * FROM `"+table+"` ORDER BY 1")
		dGCFreezeOK(t, err)
		columns, err := rows.Columns()
		dGCFreezeOK(t, err)
		records := []any{table, columns}
		for rows.Next() {
			values := make([]any, len(columns))
			args := make([]any, len(columns))
			for n := range values {
				args[n] = &values[n]
			}
			dGCFreezeOK(t, rows.Scan(args...))
			records = append(records, values)
		}
		dGCFreezeOK(t, rows.Err())
		dGCFreezeOK(t, rows.Close())
		snapshot = append(snapshot, records)
	}
	return hash(canonical(snapshot))
}

func TestDDownloadGCFullCollectMySQL(t *testing.T) {
	raw, err := os.ReadFile(os.Getenv("D_PROVIDER_REGISTRATION_DDL"))
	dGCFreezeOK(t, err)
	if hash(raw) != os.Getenv("D_PROVIDER_REGISTRATION_DDL_SHA256") || hash(raw) != hash(aDownloadMFASeed) {
		t.Fatal("cold full input capsule mismatch")
	}
	input, err := decodeADownloadMFAInputs(raw)
	dGCFreezeOK(t, err)
	for _, mode := range dGCColdCases {
		t.Run(mode, func(t *testing.T) {
			f := newDGCColdFixture(t, input, mode)
			err := f.collector.Collect(f.ctx, f.model.operation)
			trace := f.trace
			trace.Lock()
			connections, begins, commits, rollbacks, closed, writes, final := trace.connections, trace.begins, trace.commits, trace.rollbacks, trace.closed, trace.writes, trace.finalTicket
			trace.Unlock()
			if connections != 1 || begins != 1 || closed != 1 || writes != 7 {
				t.Fatal("cold full did not reach one real owned transaction and complete group writes", connections, begins, closed, writes)
			}
			if mode != "last_delete_reply_lost" && !final {
				t.Fatal("cold full did not reach captured final-ticket boundary")
			}
			committed := oneOf(mode, "commit", "commit_reply_lost", "unlock_reply_lost")
			if committed {
				if commits != 1 || rollbacks != 0 {
					t.Fatal("commit retried or claimed rolled back")
				}
			} else if commits != 0 || rollbacks != 1 {
				t.Fatal("shared rollback not executed exactly once")
			}
			if mode == "commit" && err != nil {
				t.Fatal("real cold full success rejected", boundary(err))
			}
			if mode != "commit" && err == nil {
				t.Fatal("faulted cold full claimed success")
			}
			if mode == "commit_reply_lost" && (!errors.Is(err, ErrDownloadRetentionGCCommitUnknown) || !errors.Is(err, ErrDownloadRetentionGCReleaseUnknown)) {
				t.Fatal("commit uncertainty lost")
			}
			if mode == "rollback_reply_lost" && (!errors.Is(err, ErrDownloadRetentionGCRollbackUnknown) || !errors.Is(err, ErrDownloadRetentionGCReleaseUnknown)) {
				t.Fatal("rollback uncertainty lost")
			}
			if mode == "unlock_reply_lost" && !errors.Is(err, ErrDownloadRetentionGCReleaseUnknown) {
				t.Fatal("release uncertainty lost")
			}
			// Independently observe the original live-pinned thread, never a new
			// session or another holder. Observation does not renew business scope.
			holder := f.collector.freeze.authority.(*dGCColdPolicy).profile.holder
			deadline := time.Now().Add(3 * time.Second)
			for len(f.p.ddl.tickets(t, holder)) != 0 {
				if time.Now().After(deadline) {
					t.Fatal("original full holder release not observed")
				}
				time.Sleep(10 * time.Millisecond)
			}
			if f.fingerprint(t, true) != f.evidenceBefore {
				t.Fatal("retained evidence envelope changed")
			}
			if !committed {
				if f.fingerprint(t, false) != f.before {
					t.Fatal("actual group/audits/nonce/tombstone/reservation were not restored")
				}
				return
			}
			for _, query := range []string{"SELECT COUNT(*) FROM system_backup_v2_operations WHERE id=73", "SELECT COUNT(*) FROM system_backup_v2_download_admission_receipts WHERE operation_id=73", "SELECT COUNT(*) FROM system_backup_v2_download_result_receipts WHERE operation_id=73", "SELECT COUNT(*) FROM system_backup_v2_strong_auth_nonces WHERE operation_id=73", "SELECT COUNT(*) FROM audit_logs WHERE id IN(1729,1730)"} {
				var n int
				dGCFreezeOK(t, f.p.role.root.QueryRowContext(f.p.ddl.ctx, query).Scan(&n))
				if n != 0 {
					t.Fatal("known committed cold group retained details")
				}
			}
			var stones int
			var reserved int64
			dGCFreezeOK(t, f.p.role.root.QueryRowContext(f.p.ddl.ctx, "SELECT COUNT(*) FROM system_backup_v2_compact_tombstones WHERE source_public_id=?", f.model.operation).Scan(&stones))
			dGCFreezeOK(t, f.p.role.root.QueryRowContext(f.p.ddl.ctx, "SELECT reserved_bytes FROM system_backup_v2_metadata_reservations WHERE id=1").Scan(&reserved))
			if stones != 1 || reserved != 65536 {
				t.Fatal("exact marker/capacity commit missing")
			}
		})
	}
	t.Log("PASS full_collect_candidate cases=7 actual_sql=yes public_collect=yes domain=synthetic_uid_scoped_published_tasks physical_report=synthetic candidate_gc_check=yes provider_read=no production_approval=no")
}
