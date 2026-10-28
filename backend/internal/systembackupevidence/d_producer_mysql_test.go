//go:build systembackup_mysql

package systembackupevidence

import (
	"context"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
	"github.com/go-sql-driver/mysql"
)

// Every case receives a separate run-owned database after the existing isolated
// pod marker and UUID have been verified. Never accepts an arbitrary DSN.
func dProducerMySQLDB(t *testing.T, beforeDDL ...func(*sql.DB)) (*sql.DB, *atomic.Bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	t.Cleanup(cancel)
	run, uid := os.Getenv("D_INVARIANT_RUN"), os.Getenv("D_INVARIANT_NAMESPACE_UID")
	if !regexp.MustCompile(`^sbk-mig-[0-9]{12}-[0-9a-f]{4}$`).MatchString(run) || !regexp.MustCompile(`^[a-f0-9-]{36}$`).MatchString(uid) || os.Getenv("MYSQL_ROOT_PASSWORD") == "" {
		t.Fatal("isolated marker required")
	}
	cfg := mysql.NewConfig()
	cfg.User = "root"
	cfg.Passwd = os.Getenv("MYSQL_ROOT_PASSWORD")
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort("127.0.0.1", "3306")
	cfg.DBName = "clawmanager"
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = 5*time.Second, 15*time.Second, 15*time.Second
	cfg.Params = map[string]string{"time_zone": "'+00:00'", "innodb_lock_wait_timeout": "5"}
	cfg.MultiStatements = true
	admin, e := sql.Open("mysql", cfg.FormatDSN())
	mustSQL(t, e)
	t.Cleanup(func() { admin.Close() })
	var gotRun, gotUID, pinned, server string
	mustSQL(t, admin.QueryRowContext(ctx, "SELECT run_namespace,namespace_uid,server_uuid FROM d_invariant_run_marker WHERE id=1").Scan(&gotRun, &gotUID, &pinned))
	mustSQL(t, admin.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&server))
	if gotRun != run || gotUID != uid || server != pinned {
		t.Fatal("isolated identity mismatch")
	}
	var version, mode string
	mustSQL(t, admin.QueryRowContext(ctx, "SELECT VERSION(),@@session.sql_mode").Scan(&version, &mode))
	if !strings.HasPrefix(version, "8.") || (!strings.Contains(mode, "STRICT_TRANS_TABLES") && !strings.Contains(mode, "STRICT_ALL_TABLES")) {
		t.Fatal("requires MySQL 8 with strict SQL mode")
	}
	ddl, e := os.ReadFile(os.Getenv("D_PROVIDER_REGISTRATION_DDL"))
	mustSQL(t, e)
	if hash(ddl) != os.Getenv("D_PROVIDER_REGISTRATION_DDL_SHA256") {
		t.Fatal("DDL digest mismatch")
	}
	var entropy [16]byte
	_, e = rand.Read(entropy[:])
	mustSQL(t, e)
	name := "dprod_" + hex.EncodeToString(entropy[:])
	_, e = admin.ExecContext(ctx, "CREATE DATABASE "+name)
	mustSQL(t, e)
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		var current string
		if admin.QueryRowContext(cleanup, "SELECT @@server_uuid").Scan(&current) != nil || current != server {
			t.Error("CLEANUP_PENDING evidence database identity")
			return
		}
		if _, e := admin.ExecContext(cleanup, "DROP DATABASE "+name); e != nil {
			t.Error("CLEANUP_PENDING evidence database")
			return
		}
		var count int
		if admin.QueryRowContext(cleanup, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=?", name).Scan(&count) != nil || count != 0 {
			t.Error("CLEANUP_PENDING evidence database absence")
			return
		}
		t.Log("CLEANED evidence run-owned database")
	})
	cfg.DBName = name
	connector, e := mysql.NewConnector(cfg)
	mustSQL(t, e)
	lost := &atomic.Bool{}
	db := sql.OpenDB(dLostConnector{Connector: connector, lost: lost})
	mustSQL(t, e)
	t.Cleanup(func() { db.Close() })
	// Test-owned migration ordering: initialize real legacy fixtures before the
	// original C1 schema is installed. Never remove an already-present domain.
	for _, initialize := range beforeDDL {
		initialize(db)
	}
	_, e = db.ExecContext(ctx, string(ddl))
	mustSQL(t, e)
	_, e = db.ExecContext(ctx, "CREATE TABLE synthetic_guard_marker (n INT NOT NULL) ENGINE=InnoDB")
	mustSQL(t, e)
	return db, lost
}

// The actual InnoDB COMMIT completes, then its acknowledgement is hidden from
// database/sql. This tests service recovery, not a network protocol proxy.
type dLostConnector struct {
	driver.Connector
	lost *atomic.Bool
}

func (c dLostConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &dLostConn{Conn: conn, lost: c.lost}, nil
}

type dLostConn struct {
	driver.Conn
	lost *atomic.Bool
}

func (c *dLostConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	tx, err := c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return dLostTx{Tx: tx, lost: c.lost}, nil
}
func (c *dLostConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
}
func (c *dLostConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
}
func (c *dLostConn) CheckNamedValue(v *driver.NamedValue) error {
	return c.Conn.(driver.NamedValueChecker).CheckNamedValue(v)
}

type dLostTx struct {
	driver.Tx
	lost *atomic.Bool
}

func (t dLostTx) Commit() error {
	if err := t.Tx.Commit(); err != nil {
		return err
	}
	if t.lost.Swap(false) {
		return errors.New("injected lost COMMIT acknowledgement")
	}
	return nil
}

// Snapshot all A/D and transactional audit rows, with stable ordering and
// driver-independent byte copies. No counter-only rollback assertions.
func dMySQLSnapshot(t *testing.T, db *sql.DB) map[string][][]any {
	t.Helper()
	names, err := db.Query("SHOW TABLES")
	mustSQL(t, err)
	var tables []string
	for names.Next() {
		var s string
		mustSQL(t, names.Scan(&s))
		tables = append(tables, s)
	}
	mustSQL(t, names.Err())
	mustSQL(t, names.Close())
	out := map[string][][]any{}
	for _, table := range tables {
		rows, err := db.Query("SELECT * FROM " + table)
		mustSQL(t, err)
		cols, err := rows.Columns()
		mustSQL(t, err)
		for rows.Next() {
			v := make([]any, len(cols))
			p := make([]any, len(cols))
			for i := range v {
				p[i] = &v[i]
			}
			mustSQL(t, rows.Scan(p...))
			for i, x := range v {
				if b, ok := x.([]byte); ok {
					v[i] = string(b)
				}
			}
			out[table] = append(out[table], v)
		}
		mustSQL(t, rows.Err())
		mustSQL(t, rows.Close())
		sort.Slice(out[table], func(i, j int) bool { return fmt.Sprint(out[table][i]) < fmt.Sprint(out[table][j]) })
	}
	return out
}
func dMySQLUnchanged(t *testing.T, db *sql.DB, before map[string][][]any) {
	t.Helper()
	if !reflect.DeepEqual(before, dMySQLSnapshot(t, db)) {
		t.Fatal("partial write or replay mutation")
	}
}
func dMySQLReceipt(t *testing.T, f *dIntegrationFixture) pd.ReceiptRecord {
	var r pd.RunRecord
	f.load("system_backup_producer_runs", &r)
	var target pd.TargetRecord
	f.load("system_backup_producer_targets", &target)
	var receipt pd.ReceiptRecord
	f.load("system_backup_producer_result_receipts", &receipt)
	if r.State != "committed" || r.RowVersion != "5" || target.ResultVersion != "1" || receipt.ResultVersion != "1" || !reflect.DeepEqual(receipt.Request, f.resultRequest) {
		t.Fatal("incomplete D commit")
	}
	var state, version, health string
	var claim any
	var rv, refs, chunks int
	mustSQL(t, f.db.QueryRow("SELECT storage_state,storage_immutable_version,observed_health,claim_owner,row_version FROM system_backup_v2_evidence").Scan(&state, &version, &health, &claim, &rv))
	mustSQL(t, f.db.QueryRow("SELECT COUNT(*) FROM system_backup_producer_evidence_refs").Scan(&refs))
	mustSQL(t, f.db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_evidence_chunks").Scan(&chunks))
	if state != "ready" || version != "Exact.Version/1" || health != "unknown" || claim != nil || rv != 3 || refs != 3 || chunks != 1 {
		t.Fatal("incomplete A commit")
	}
	var history pd.HistoricalBindingRecord
	f.load("system_backup_producer_evidence_bindings", &history)
	if !reflect.DeepEqual(history, f.history) {
		t.Fatal("history mutated")
	}
	return receipt
}
func TestDProducerMySQLSeed(t *testing.T) {
	sample := (&dIntegrationFixture{realDB: true}).sample()
	if sample.Nanosecond()%1000 != 0 {
		t.Fatal("MySQL capacity sample must have microsecond precision")
	}
	for _, mode := range []string{"fixed_clock", "advancing_clock"} {
		t.Run(mode, func(t *testing.T) {
			f := newDIntegrationFixtureWithDB(t, nil, mode == "advancing_clock")
			f.advance("pending", "claim", "finish", "result")
		})
	}
}

// Out-of-band revocation/expiry fixtures update both canonical bytes and SQL
// projections. They never manufacture a successful lifecycle transition.
func dMySQLInvalidateGrant(t *testing.T, f *dIntegrationFixture, kind string) {
	var grant pd.GrantRecord
	f.load("system_backup_producer_grants", &grant)
	if kind == "revoked" {
		grant.State = "revoked"
	} else {
		grant.CreatedAt = systemExecutionStamp(time.Now().UTC().Add(-2 * time.Minute))
		grant.LeaseExpiresAt = systemExecutionStamp(time.Now().UTC().Add(-time.Minute))
	}
	row, err := pd.EncodeStoredRecord(&grant)
	mustSQL(t, err)
	var sets []string
	var args []any
	for k, v := range row.Columns {
		sets = append(sets, k+"=?")
		args = append(args, v)
	}
	args = append(args, row.Columns["scope_key"], row.Columns["grant_id"])
	result, err := f.db.Exec("UPDATE "+row.Table+" SET "+strings.Join(sets, ",")+" WHERE scope_key=? AND grant_id=?", args...)
	mustSQL(t, err)
	n, err := result.RowsAffected()
	mustSQL(t, err)
	if n != 1 {
		t.Fatal("grant fixture not updated")
	}
}

// This is a test-only read authority. Production identity and revocation
// admission must be supplied by the deployment integration.
type dMySQLHistoricalReceiptAuthority struct {
	allowed bool
}

func (a *dMySQLHistoricalReceiptAuthority) PrepareReceiptRead(context.Context, pd.ResultRequest) (pd.HistoricalReceiptSession, error) {
	return a, nil
}
func (a *dMySQLHistoricalReceiptAuthority) AuthorizeReceiptRead(ctx context.Context, tx pd.SQL, _ pd.ResultRequest, hashes pd.ResultDigests) (pd.HistoricalReceiptAdmission, error) {
	var now time.Time
	if err := tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil {
		return pd.HistoricalReceiptAdmission{}, err
	}
	return pd.HistoricalReceiptAdmission{VerifiedRequestHash: hashes.Request, IdentityExpiresAt: systemExecutionStamp(now.Add(time.Minute)), ReadAllowed: a.allowed}, nil
}
func (a *dMySQLHistoricalReceiptAuthority) RecheckReceiptRead(context.Context, pd.ReadSQL, pd.ResultRequest, pd.ReceiptRecord, time.Time) error {
	if !a.allowed {
		return pd.ErrGuardRequired
	}
	return nil
}
func (a *dMySQLHistoricalReceiptAuthority) PrepareCommandReceiptRead(context.Context, pd.CommandRequest) (pd.HistoricalCommandReceiptSession, error) {
	return a, nil
}
func (a *dMySQLHistoricalReceiptAuthority) AuthorizeCommandReceiptRead(ctx context.Context, tx pd.SQL, _ pd.CommandRequest, hashes pd.CommandDigests) (pd.HistoricalReceiptAdmission, error) {
	var now time.Time
	if err := tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil {
		return pd.HistoricalReceiptAdmission{}, err
	}
	return pd.HistoricalReceiptAdmission{VerifiedRequestHash: hashes.Request, IdentityExpiresAt: systemExecutionStamp(now.Add(time.Minute)), ReadAllowed: a.allowed}, nil
}
func (a *dMySQLHistoricalReceiptAuthority) RecheckCommandReceiptRead(context.Context, pd.ReadSQL, pd.CommandRequest, pd.CommandReceiptRecord, time.Time) error {
	if !a.allowed {
		return pd.ErrGuardRequired
	}
	return nil
}

// This test authority proves the D SQL transition only. It supplies no
// production deployment identity, management permission, or audit writer.
type dMySQLDomainRevokeAuthority struct {
	allowed   bool
	failAudit string
}

func (a *dMySQLDomainRevokeAuthority) PrepareDomainRevoke(context.Context, pd.DomainRevokeRequest) (pd.DomainRevokeSession, error) {
	return a, nil
}
func (a *dMySQLDomainRevokeAuthority) LockInstallation(context.Context, pd.SQL, pd.DomainRevokeRequest) error {
	return nil
}
func (a *dMySQLDomainRevokeAuthority) Authorize(ctx context.Context, tx pd.SQL, r pd.DomainRevokeRequest, _ pd.DomainRecord) (pd.DomainRevokeAdmission, error) {
	var now time.Time
	if err := tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil {
		return pd.DomainRevokeAdmission{}, err
	}
	h, err := pd.DomainRevokeHash(r)
	if err != nil {
		return pd.DomainRevokeAdmission{}, err
	}
	return pd.DomainRevokeAdmission{VerifiedRequestHash: h, IdentityExpiresAt: systemExecutionStamp(now.Add(time.Minute)), ManagementAllowed: a.allowed}, nil
}
func (a *dMySQLDomainRevokeAuthority) Audit(_ context.Context, _ pd.SQL, _ pd.DomainRevokeRequest, stage string) error {
	if a.failAudit == stage {
		return pd.ErrUnavailable
	}
	return nil
}
func (a *dMySQLDomainRevokeAuthority) Recheck(_ context.Context, _ pd.ReadSQL, _ pd.DomainRevokeRequest, domain pd.DomainRecord, _ time.Time) error {
	if !a.allowed || domain.State != "revoked" {
		return pd.ErrGuardRequired
	}
	return nil
}

// Test-only deployment admission and capacity participant for D domain SQL.
type dMySQLDomainOpenAuthority struct {
	db        *sql.DB
	issuer    pd.Hash
	admission pd.Admission
	failAudit string
}

func (a *dMySQLDomainOpenAuthority) PrepareDomainOpen(ctx context.Context, _ pd.DomainOpenRequest) (pd.PreparedDomainOpen, error) {
	var now time.Time
	if err := a.db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil {
		return pd.PreparedDomainOpen{}, err
	}
	return pd.PreparedDomainOpen{Session: a, CapacityObservedAt: now}, nil
}
func (a *dMySQLDomainOpenAuthority) LockInstallation(context.Context, pd.SQL, pd.DomainOpenRequest) error {
	return nil
}
func (a *dMySQLDomainOpenAuthority) Authorize(ctx context.Context, tx pd.SQL, r pd.DomainOpenRequest, _ *pd.DomainRecord) (pd.DomainOpenAdmission, error) {
	var now time.Time
	if err := tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil {
		return pd.DomainOpenAdmission{}, err
	}
	h, err := pd.DomainOpenHash(r)
	if err != nil {
		return pd.DomainOpenAdmission{}, err
	}
	return pd.DomainOpenAdmission{VerifiedRequestHash: h, IdentityExpiresAt: systemExecutionStamp(now.Add(time.Minute)), IssuerIdentityHash: a.issuer, Admission: a.admission, AdmissionExpiresAt: systemExecutionStamp(now.Add(time.Hour)), AdditionalCost: "0", ManagementAllowed: true}, nil
}
func (a *dMySQLDomainOpenAuthority) Reserve(_ context.Context, _ pd.SQL, r pd.DomainOpenRequest, cost uint64) error {
	if r.Operation == "provision" && cost != 147456 || r.Operation == "rotate" && cost != 65536 {
		return pd.ErrInvalid
	}
	return nil
}
func (a *dMySQLDomainOpenAuthority) Audit(_ context.Context, _ pd.SQL, _ pd.DomainOpenRequest, stage string) error {
	if a.failAudit == stage {
		return pd.ErrUnavailable
	}
	return nil
}
func (a *dMySQLDomainOpenAuthority) Recheck(_ context.Context, _ pd.ReadSQL, _ pd.DomainOpenRequest, domain pd.DomainRecord, _ time.Time) error {
	if domain.State != "open" || domain.IssuerIdentityHash != a.issuer {
		return pd.ErrGuardRequired
	}
	return nil
}

func TestDProducerMySQL(t *testing.T) {
	ctx := context.Background()
	t.Run("domain_provision_and_rotate", func(t *testing.T) {
		db, _ := dProducerMySQLDB(t)
		f := newDIntegrationFixtureWithDB(t, db)
		var existing pd.DomainRecord
		f.load("system_backup_producer_domains", &existing)
		scope := existing.Scope
		scope.Installation = "installation_domain_open_probe"
		authority := &dMySQLDomainOpenAuthority{db: db, issuer: pd.Hash(strings.Repeat("e", 64)), admission: existing.Admission, failAudit: "result"}
		opener, err := pd.NewDomainOpener(db, scope, authority)
		mustSQL(t, err)
		request := pd.DomainOpenRequest{Scope: scope, Operation: "provision", ExpectedEpoch: "0", ExpectedRowVersion: "0", DeploymentHash: pd.Hash(strings.Repeat("a", 64))}
		before := dMySQLSnapshot(t, db)
		if _, err := opener.OpenDomain(ctx, request); err == nil {
			t.Fatal("provision audit failure did not roll back")
		}
		dMySQLUnchanged(t, db, before)
		authority.failAudit = ""
		first, err := opener.OpenDomain(ctx, request)
		mustSQL(t, err)
		if first.Epoch != "1" || first.RowVersion != "1" || first.State != "open" {
			t.Fatal("provision result", first)
		}
		if _, err := opener.OpenDomain(ctx, request); !errors.Is(err, pd.ErrConflict) {
			t.Fatal("duplicate provision", err)
		}
		request.Operation, request.ExpectedEpoch, request.ExpectedRowVersion = "rotate", "1", "1"
		authority.issuer = pd.Hash(strings.Repeat("f", 64))
		second, err := opener.OpenDomain(ctx, request)
		mustSQL(t, err)
		if second.Epoch != "2" || second.RowVersion != "2" || second.State != "open" || second.CreatedAt != first.CreatedAt || second.IssuerIdentityHash != authority.issuer {
			t.Fatal("rotation result", second)
		}
		if _, err := opener.OpenDomain(ctx, request); !errors.Is(err, pd.ErrConflict) {
			t.Fatal("old rotation replay", err)
		}
		var count int
		mustSQL(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_producer_domains").Scan(&count))
		if count != 2 {
			t.Fatal("unexpected domain count", count)
		}
	})
	t.Run("independent_command_receipt_closed_domain", func(t *testing.T) {
		db, _ := dProducerMySQLDB(t)
		f := newDIntegrationFixtureWithDB(t, db)
		var domain pd.DomainRecord
		f.load("system_backup_producer_domains", &domain)
		dMySQLInvalidateGrant(t, f, "revoked")
		domain.State = "closed"
		row, err := pd.EncodeStoredRecord(&domain)
		mustSQL(t, err)
		var sets []string
		var args []any
		for k, v := range row.Columns {
			sets = append(sets, k+"=?")
			args = append(args, v)
		}
		args = append(args, row.Columns["scope_key"])
		_, err = db.Exec("UPDATE "+row.Table+" SET "+strings.Join(sets, ",")+" WHERE scope_key=?", args...)
		mustSQL(t, err)
		var want pd.CommandReceiptRecord
		f.load("system_backup_producer_command_receipts", &want)
		before := dMySQLSnapshot(t, db)
		authority := &dMySQLHistoricalReceiptAuthority{allowed: true}
		reader, err := pd.NewHistoricalCommandReceiptReader(db, domain.Scope, authority)
		mustSQL(t, err)
		got, err := reader.ReadCommandReceipt(ctx, f.command)
		mustSQL(t, err)
		if !reflect.DeepEqual(got, want) {
			t.Fatal("historical command receipt mismatch")
		}
		dMySQLUnchanged(t, db, before)
		authority.allowed = false
		if _, err := reader.ReadCommandReceipt(ctx, f.command); err == nil {
			t.Fatal("unauthorized command receipt read")
		}
		dMySQLUnchanged(t, db, before)
	})
	t.Run("domain_emergency_revoke", func(t *testing.T) {
		db, _ := dProducerMySQLDB(t)
		f := newDIntegrationFixtureWithDB(t, db)
		var domain pd.DomainRecord
		f.load("system_backup_producer_domains", &domain)
		request := pd.DomainRevokeRequest{Scope: domain.Scope, ExpectedEpoch: domain.Epoch, ExpectedRowVersion: domain.RowVersion, ReasonHash: pd.Hash(strings.Repeat("a", 64))}
		authority := &dMySQLDomainRevokeAuthority{allowed: true, failAudit: "result"}
		revoker, err := pd.NewDomainRevoker(db, domain.Scope, authority)
		mustSQL(t, err)
		before := dMySQLSnapshot(t, db)
		if _, err := revoker.RevokeDomain(ctx, request); err == nil {
			t.Fatal("audit failure did not roll back domain fence")
		}
		dMySQLUnchanged(t, db, before)
		authority.failAudit = ""
		got, err := revoker.RevokeDomain(ctx, request)
		mustSQL(t, err)
		if got.State != "revoked" || got.Epoch != "2" || got.RowVersion != "2" {
			t.Fatal("domain fence", got)
		}
		f.load("system_backup_producer_domains", &domain)
		if !reflect.DeepEqual(got, domain) {
			t.Fatal("domain projection mismatch")
		}
		if _, err := revoker.RevokeDomain(ctx, request); !errors.Is(err, pd.ErrConflict) {
			t.Fatal("old epoch replay", err)
		}
		var grant pd.GrantRecord
		f.load("system_backup_producer_grants", &grant)
		if grant.DomainEpoch == domain.Epoch {
			t.Fatal("old grant was not fenced")
		}
	})
	t.Run("preparation_absence_gap_lock", func(t *testing.T) {
		db, _ := dProducerMySQLDB(t)
		f := newDIntegrationFixtureWithDB(t, db)
		var domain pd.DomainRecord
		f.load("system_backup_producer_domains", &domain)
		until, err := f.history.ObservationExpiresAt.Time()
		mustSQL(t, err)
		identity := f.prepared.Manifest().Identity
		c := SystemExecutionPreparationPolicy{
			Scope: f.history.Scope, RunID: f.history.RunID, InputHash: string(f.history.InputHash),
			SubjectIdentityHash: string(f.command.ActorIdentityHash), IssuerIdentityHash: string(domain.IssuerIdentityHash),
			EvaluatorProfileHash: string(f.command.Target.EvaluatorProfileHash), Identity: identity,
			Content: CapabilityContentPolicy{Installation: identity.Installation, EvidenceID: identity.ID, Classification: identity.Classification,
				Role: string(f.command.Target.Role), ProviderIdentity: string(f.command.Target.IdentityHash),
				ProviderVersion: string(f.command.Target.RefVersion), ScopeHash: string(f.command.Target.ProbeScopeHash), ValidUntil: until},
			Wrap: TransitJWTConfig{Transit: TransitConfig{Key: KeyRef{Identity: strings.Repeat("b", 64), Version: "v1"}}},
		}
		f.policy = pd.Hash(SystemExecutionPreparationPolicyHash(c))
		env, err := NewSystemPreparationCallEnvironment(&dIntegrationExecution{f}, c)
		mustSQL(t, err)
		execution, err := pd.NewExecution(f.lifecycle, env)
		mustSQL(t, err)
		request := pd.CallRequest{Purpose: "content_read", EvidenceID: f.history.Evidence.EvidenceID, RefIdentityHash: pd.Hash(c.Content.ProviderIdentity), RefVersion: pd.ProviderVersion(c.Content.ProviderVersion), PolicyHash: f.policy, BudgetUntil: systemExecutionStamp(time.Now().Add(15 * time.Second))}
		locked, release := make(chan struct{}), make(chan struct{})
		var releaseOnce sync.Once
		free := func() { releaseOnce.Do(func() { close(release) }) }
		defer free()
		f.executionRecheckHook = func() { close(locked); <-release }
		type outcome struct {
			snapshot *pd.CallSnapshot
			err      error
		}
		result := make(chan outcome, 1)
		go func() {
			s, e := execution.BeginCall(context.Background(), f.handle, request, nil)
			result <- outcome{s, e}
		}()
		select {
		case <-locked:
		case <-time.After(10 * time.Second):
			free()
			t.Fatal("first call never reached final guard with absence locked")
		}
		record, _, err := systemPreparedRecord(f.prepared, f.channel, f.history)
		mustSQL(t, err)
		values := append(systemPendingValues(record), "pending", "none", nil, nil, int64(1), "unknown", nil, nil)
		query := "INSERT INTO system_backup_v2_evidence (" + strings.Join(systemPendingImmutableColumns, ",") + "," + systemPendingMutableColumns + ") VALUES (" + strings.TrimSuffix(strings.Repeat("?,", len(values)), ",") + ")"
		insertCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		insertResult := make(chan error, 1)
		go func() {
			_, insertErr := db.ExecContext(insertCtx, query, values...)
			insertResult <- insertErr
		}()
		select {
		case insertErr := <-insertResult:
			free()
			t.Fatalf("missing-key lock did not hold competing INSERT: %v", insertErr)
		case <-time.After(800 * time.Millisecond):
		}
		var count int
		mustSQL(t, db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_evidence WHERE public_id=?", identity.ID).Scan(&count))
		if count != 0 {
			free()
			t.Fatal("blocked INSERT became visible")
		}
		free()
		select {
		case out := <-result:
			if out.err != nil || out.snapshot == nil {
				t.Fatal("original D call", out.err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("original D call did not release gap lock")
		}
		f.executionRecheckHook = nil
		select {
		case insertErr := <-insertResult:
			mustSQL(t, insertErr)
		case <-time.After(10 * time.Second):
			t.Fatal("competing INSERT did not complete after gap lock release")
		}
		mustSQL(t, db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_evidence WHERE public_id=?", identity.ID).Scan(&count))
		if count != 1 {
			t.Fatalf("competing INSERT count after release: %d", count)
		}
		if snapshot, err := execution.BeginCall(context.Background(), f.handle, request, nil); err == nil || snapshot != nil {
			t.Fatal("new D call accepted now-present A evidence")
		}
	})
	t.Run("historical_record_locked_reconstruction", func(t *testing.T) {
		db, _ := dProducerMySQLDB(t)
		f := newDIntegrationFixtureWithDB(t, db)
		f.advance("pending")
		load := func(h pd.HistoricalBindingRecord) (Record, error) {
			runner, err := pd.NewTransactions(db, f.history.Scope, systemHistoricalTestPolicy{until: f.until})
			if err != nil {
				return Record{}, err
			}
			var record Record
			receipt, err := runner.Run(ctx, func(ctx context.Context, tx *pd.Transaction) error {
				var loadErr error
				record, loadErr = loadSystemHistoricalRecord(ctx, tx, h, f.channel)
				return loadErr
			})
			if err == nil && !receipt.Committed() {
				return Record{}, pd.ErrGuardRequired
			}
			return record, err
		}
		pending, err := load(f.history)
		mustSQL(t, err)
		if pending.State != "pending" || !reflect.DeepEqual(pending.Manifest, f.prepared.Manifest()) || pending.Ref.ImmutableVersion != "" {
			t.Fatal("pending historical A bytes did not match D", pending.State)
		}
		f.advance("claim", "finish")
		ready, err := load(f.history)
		mustSQL(t, err)
		if ready.State != "ready" || ready.Ref.ImmutableVersion != "Exact.Version/1" || !reflect.DeepEqual(ready.Manifest, f.prepared.Manifest()) {
			t.Fatal("ready historical A bytes did not match D", ready.State)
		}
		locked, release := make(chan struct{}), make(chan struct{})
		var releaseOnce sync.Once
		free := func() { releaseOnce.Do(func() { close(release) }) }
		defer free()
		readResult := make(chan error, 1)
		go func() {
			runner, err := pd.NewTransactions(db, f.history.Scope, systemHistoricalTestPolicy{until: f.until})
			if err != nil {
				readResult <- err
				return
			}
			receipt, err := runner.Run(context.Background(), func(ctx context.Context, tx *pd.Transaction) error {
				if _, err := loadSystemHistoricalRecord(ctx, tx, f.history, f.channel); err != nil {
					return err
				}
				close(locked)
				<-release
				return nil
			})
			if err == nil && !receipt.Committed() {
				err = pd.ErrGuardRequired
			}
			readResult <- err
		}()
		select {
		case <-locked:
		case err := <-readResult:
			t.Fatal("historical reader failed before lock check", err)
		case <-time.After(10 * time.Second):
			t.Fatal("historical reader did not reach locked A rows")
		}
		updateCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		updateResult := make(chan error, 1)
		go func() {
			_, updateErr := db.ExecContext(updateCtx, "UPDATE system_backup_v2_evidence SET observed_health='degraded' WHERE public_id=?", f.history.Evidence.EvidenceID)
			updateResult <- updateErr
		}()
		select {
		case updateErr := <-updateResult:
			free()
			t.Fatalf("historical row lock did not hold competing UPDATE: %v", updateErr)
		case <-time.After(800 * time.Millisecond):
		}
		free()
		select {
		case err := <-readResult:
			mustSQL(t, err)
		case <-time.After(10 * time.Second):
			t.Fatal("historical reader did not release A row lock")
		}
		select {
		case err := <-updateResult:
			mustSQL(t, err)
		case <-time.After(10 * time.Second):
			t.Fatal("competing UPDATE did not complete after historical reader")
		}
		var health string
		mustSQL(t, db.QueryRowContext(ctx, "SELECT observed_health FROM system_backup_v2_evidence WHERE public_id=?", f.history.Evidence.EvidenceID).Scan(&health))
		if health != "degraded" {
			t.Fatal("competing UPDATE did not persist after lock release", health)
		}
		altered := f.history
		altered.Evidence.ManifestHash = pd.Hash(strings.Repeat("f", 64))
		if record, err := load(altered); err == nil || !reflect.DeepEqual(record, Record{}) {
			t.Fatal("changed D history reconstructed A record", err)
		}
		_, err = db.ExecContext(ctx, "UPDATE system_backup_v2_evidence SET envelope_hash=? WHERE public_id=?", strings.Repeat("f", 64), f.history.Evidence.EvidenceID)
		mustSQL(t, err)
		if record, err := load(f.history); err == nil || !reflect.DeepEqual(record, Record{}) {
			t.Fatal("changed A envelope reconstructed historical record", err)
		}
	})
	t.Run("independent_historical_receipt_closed_domain", func(t *testing.T) {
		db, _ := dProducerMySQLDB(t)
		f := newDIntegrationFixtureWithDB(t, db)
		f.advance("pending", "claim", "finish", "result")
		want := dMySQLReceipt(t, f)
		dMySQLInvalidateGrant(t, f, "revoked")
		var domain pd.DomainRecord
		f.load("system_backup_producer_domains", &domain)
		domain.State = "closed"
		row, err := pd.EncodeStoredRecord(&domain)
		mustSQL(t, err)
		var sets []string
		var args []any
		for k, v := range row.Columns {
			sets = append(sets, k+"=?")
			args = append(args, v)
		}
		args = append(args, row.Columns["scope_key"])
		_, err = db.Exec("UPDATE "+row.Table+" SET "+strings.Join(sets, ",")+" WHERE scope_key=?", args...)
		mustSQL(t, err)
		before := dMySQLSnapshot(t, db)
		authority := &dMySQLHistoricalReceiptAuthority{allowed: true}
		reader, err := pd.NewHistoricalReceiptReader(db, f.resultRequest.Scope, authority)
		mustSQL(t, err)
		got, err := reader.ReadResultReceipt(ctx, f.resultRequest)
		mustSQL(t, err)
		if !reflect.DeepEqual(got, want) {
			t.Fatal("historical receipt mismatch")
		}
		dMySQLUnchanged(t, db, before)
		authority.allowed = false
		if _, err := reader.ReadResultReceipt(ctx, f.resultRequest); err == nil {
			t.Fatal("read without current authority")
		}
		dMySQLUnchanged(t, db, before)
	})
	t.Run("lifecycle_and_exact_replay", func(t *testing.T) {
		db, _ := dProducerMySQLDB(t)
		f := newDIntegrationFixtureWithDB(t, db)
		f.advance("pending")
		before := dMySQLSnapshot(t, db)
		out, err := f.pending.AdmitPending(ctx, f.handle, f.pendingRequest)
		mustSQL(t, err)
		if !out.Replayed {
			t.Fatal("pending replay")
		}
		dMySQLUnchanged(t, db, before)
		f.advance("claim")
		before = dMySQLSnapshot(t, db)
		claim, err := f.publication.ReadPublicationClaim(ctx, f.handle, f.claimRequest)
		mustSQL(t, err)
		f.claim = claim
		dMySQLUnchanged(t, db, before)
		f.advance("finish", "result")
		receipt := dMySQLReceipt(t, f)
		before = dMySQLSnapshot(t, db)
		replay, err := f.results.CommitResult(ctx, f.handle, f.resultRequest)
		mustSQL(t, err)
		if !replay.Replayed || !reflect.DeepEqual(receipt, replay.Receipt) {
			t.Fatal("not exact receipt")
		}
		dMySQLUnchanged(t, db, before)
		f.readReceipt = false
		_, err = f.results.CommitResult(ctx, f.handle, f.resultRequest)
		if err == nil {
			t.Fatal("unauthorized receipt")
		}
		dMySQLUnchanged(t, db, before)
	})
	for _, kind := range []string{"expired", "revoked"} {
		for _, stage := range []string{"pending", "claim", "finish", "result"} {
			t.Run(kind+"_"+stage, func(t *testing.T) {
				db, _ := dProducerMySQLDB(t)
				f := newDIntegrationFixtureWithDB(t, db)
				for _, s := range []string{"pending", "claim", "finish", "result"} {
					if s == stage {
						break
					}
					f.advance(s)
				}
				dMySQLInvalidateGrant(t, f, kind)
				before := dMySQLSnapshot(t, db)
				want := pd.ErrExpired
				if kind == "revoked" {
					want = pd.ErrConflict
				}
				if err := f.step(stage); !errors.Is(err, want) {
					t.Fatalf("invalid grant: got %v, want %v", err, want)
				}
				dMySQLUnchanged(t, db, before)
			})
		}
	}
	for _, tc := range []struct{ stage, table string }{{"pending", "system_backup_v2_evidence_chunks"}, {"result", "system_backup_producer_result_receipts"}} {
		t.Run(tc.stage+"_sql_failure", func(t *testing.T) {
			db, _ := dProducerMySQLDB(t)
			f := newDIntegrationFixtureWithDB(t, db)
			for _, s := range []string{"pending", "claim", "finish", "result"} {
				if s == tc.stage {
					break
				}
				f.advance(s)
			}
			_, err := db.Exec("CREATE TRIGGER fail_insert BEFORE INSERT ON " + tc.table + " FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='injected SQL failure'")
			mustSQL(t, err)
			before := dMySQLSnapshot(t, db)
			if err = f.step(tc.stage); err == nil {
				t.Fatal("SQL failure accepted")
			}
			dMySQLUnchanged(t, db, before)
		})
	}
	for _, stage := range []string{"pending", "claim", "finish", "result"} {
		for _, failure := range []string{"audit", "guard"} {
			t.Run(stage+"_rollback_"+failure, func(t *testing.T) {
				db, _ := dProducerMySQLDB(t)
				f := newDIntegrationFixtureWithDB(t, db)
				for _, s := range []string{"pending", "claim", "finish", "result"} {
					if s == stage {
						break
					}
					f.advance(s)
				}
				before := dMySQLSnapshot(t, db)
				f.fail = stage + "_" + failure
				if err := f.step(stage); err == nil {
					t.Fatal("failure accepted")
				}
				dMySQLUnchanged(t, db, before)
				if stage == "claim" && f.claim != nil {
					t.Fatal("failed claim minted authority")
				}
			})
		}
	}
	t.Run("competing_claims", func(t *testing.T) {
		db, _ := dProducerMySQLDB(t)
		f := newDIntegrationFixtureWithDB(t, db)
		f.advance("pending")
		gate := make(chan struct{})
		results := make(chan error, 2)
		for i := 0; i < 2; i++ {
			go func() {
				<-gate
				_, err := f.publication.ClaimPublication(ctx, f.handle, f.claimRequest)
				results <- err
			}()
		}
		close(gate)
		successes := 0
		for i := 0; i < 2; i++ {
			if <-results == nil {
				successes++
			}
		}
		if successes != 1 {
			t.Fatalf("claim winners=%d", successes)
		}
		claim, err := f.publication.ReadPublicationClaim(ctx, f.handle, f.claimRequest)
		mustSQL(t, err)
		f.claim = claim
		f.advance("finish", "result")
		dMySQLReceipt(t, f)
	})
	t.Run("commit_ack_lost", func(t *testing.T) {
		db, lost := dProducerMySQLDB(t)
		f := newDIntegrationFixtureWithDB(t, db)
		f.advance("pending", "claim", "finish")
		lost.Store(true)
		out, err := f.results.CommitResult(ctx, f.handle, f.resultRequest)
		if !errors.Is(err, pd.ErrCommitUnknown) || !reflect.DeepEqual(out, pd.CommittedResult{}) {
			t.Fatal("ambiguous result", err)
		}
		receipt := dMySQLReceipt(t, f)
		before := dMySQLSnapshot(t, db)
		out, err = f.results.CommitResult(ctx, f.handle, f.resultRequest)
		mustSQL(t, err)
		if !out.Replayed || !reflect.DeepEqual(out.Receipt, receipt) {
			t.Fatal("receipt recovery")
		}
		dMySQLUnchanged(t, db, before)
		dMySQLInvalidateGrant(t, f, "expired")
		before = dMySQLSnapshot(t, db)
		out, err = f.results.CommitResult(ctx, f.handle, f.resultRequest)
		mustSQL(t, err)
		if !out.Replayed || !reflect.DeepEqual(out.Receipt, receipt) {
			t.Fatal("historical exact replay")
		}
		dMySQLUnchanged(t, db, before)
	})
	t.Run("competing_result_commits", func(t *testing.T) {
		db, _ := dProducerMySQLDB(t)
		f := newDIntegrationFixtureWithDB(t, db)
		f.advance("pending", "claim", "finish")
		type response struct {
			out pd.CommittedResult
			err error
		}
		gate, replies := make(chan struct{}), make(chan response, 2)
		for i := 0; i < 2; i++ {
			go func() {
				<-gate
				out, err := f.results.CommitResult(ctx, f.handle, f.resultRequest)
				replies <- response{out, err}
			}()
		}
		close(gate)
		first, second := <-replies, <-replies
		mustSQL(t, first.err)
		mustSQL(t, second.err)
		if first.out.Replayed == second.out.Replayed || !reflect.DeepEqual(first.out.Receipt, second.out.Receipt) {
			t.Fatal("concurrent commit did not converge to one exact receipt")
		}
		dMySQLReceipt(t, f)
	})
}
