//go:build systembackup_mysql

package systembackupevidence

// Entry fence SQL scope only. Original A writes and D DomainOpener are real;
// deployment/resource admission and state-variant fixtures remain synthetic.
import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
	"github.com/go-sql-driver/mysql"
)

var bootstrapEntryCases = []string{"schema_absent_first", "schema_partial_first", "schema_full_no_domain_first", "schema_full_unconfigured_first", "hidden_c1_a_only", "history_schema_absent", "history_full_no_domain", "history_configured_open", "history_configured_closed", "history_configured_revoked", "history_wrong_hash", "history_wrong_version", "history_unconfigured_open", "history_unconfigured_closed", "history_unconfigured_revoked", "history_admin_revoked", "history_authority_revoked", "late_domain_mutation", "scope_gap_lock", "wrong_context", "wrong_transaction", "commit_lost"}

type bootstrapEntryAdmission struct {
	grant               sec.OfflineBootstrapGrant
	config              sec.BootstrapConfig
	authCalls, reserves int
	denied              bool
	reserveMarker       bool
	late                func(context.Context, *sql.Tx) error
	barrier             func(context.Context, *sql.Tx) error
}

func (a *bootstrapEntryAdmission) Authorize(ctx context.Context, tx *sql.Tx, g sec.OfflineBootstrapGrant, c sec.BootstrapConfig, _ time.Time) error {
	if a == nil || ctx.Err() != nil || tx == nil || a.denied || g != a.grant || !bytes.Equal(c.CanonicalJSON(), a.config.CanonicalJSON()) {
		return sec.ErrRegistrationPermission
	}
	a.authCalls++
	if a.authCalls == 1 && a.barrier != nil {
		return a.barrier(ctx, tx)
	}
	if a.authCalls == 2 && a.late != nil {
		return a.late(ctx, tx)
	}
	return nil
}
func (a *bootstrapEntryAdmission) ValidateAndReserve(ctx context.Context, tx *sql.Tx, g sec.OfflineBootstrapGrant, c sec.BootstrapConfig, _ time.Time) error {
	if ctx.Err() != nil || tx == nil || g != a.grant || !bytes.Equal(c.CanonicalJSON(), a.config.CanonicalJSON()) {
		return sec.ErrRegistrationUnavailable
	}
	a.reserves++
	if !a.reserveMarker {
		return nil
	}
	_, err := tx.ExecContext(ctx, "INSERT INTO synthetic_guard_marker(n) VALUES(771)")
	return err
}

type bootstrapEntryFixture struct {
	db        *sql.DB
	lost      *atomic.Bool
	grant     sec.OfflineBootstrapGrant
	config    sec.BootstrapConfig
	scope     pd.Scope
	admission *bootstrapEntryAdmission
	service   sec.ConfigBootstrapService
	first     sec.ConfigBootstrapResult
}

func bootstrapEntryFirstDDL(t *testing.T, ddl string) string {
	t.Helper()
	first := strings.Index(ddl, "CREATE TABLE ")
	if first < 0 {
		t.Fatal("missing original C1 DDL")
	}
	next := strings.Index(ddl[first+1:], "CREATE TABLE ")
	if next < 0 {
		t.Fatal("incomplete original C1 DDL")
	}
	return ddl[:first+1+next]
}
func bootstrapEntryNew(t *testing.T, schema string, history bool) *bootstrapEntryFixture {
	t.Helper()
	capsule := bootstrapMySQLInput(t)
	input, err := os.ReadFile(os.Getenv("D_PROVIDER_REGISTRATION_DDL"))
	mustSQL(t, err)
	if !bytes.Equal(input, bootstrapConsumerMySQLInputs) || hash(input) != os.Getenv("D_PROVIDER_REGISTRATION_DDL_SHA256") {
		t.Fatal("entry compiled input mismatch")
	}
	ddl := capsule.DDL
	wantTables := 8
	switch schema {
	case "absent":
		ddl = "SELECT 1"
		wantTables = 0
	case "partial":
		ddl = bootstrapEntryFirstDDL(t, ddl)
		wantTables = 1
	case "full":
	default:
		t.Fatal("unknown closed schema mode")
	}
	owned := filepath.Join(t.TempDir(), "entry-original-c1.sql")
	mustSQL(t, os.WriteFile(owned, []byte(ddl), 0600))
	t.Setenv("D_PROVIDER_REGISTRATION_DDL", owned)
	t.Setenv("D_PROVIDER_REGISTRATION_DDL_SHA256", hash([]byte(ddl)))
	f := &bootstrapEntryFixture{config: bootstrapMySQLProfile(t, capsule)}
	f.db, f.lost = dProducerMySQLDB(t, func(db *sql.DB) {
		bootstrapMySQLCanonicalA(t, db, capsule)
		var server, database string
		mustSQL(t, db.QueryRow("SELECT @@server_uuid,DATABASE()").Scan(&server, &database))
		f.scope = pd.Scope{ServerUUID: pd.ServerUUID(server), Database: pd.Database(database), Installation: "installation_bootstrap_entry_fixture"}
		f.grant = sec.OfflineBootstrapGrant{InstallationID: string(f.scope.Installation), ServerUUID: server, Database: database, Username: "bootstrap-probe", UserID: 42, MatrixKey: "k8s-cluster", ConfigSHA256: f.config.SHA256(), IdempotencyKey: "bootstrap-entry-fixed-key-0001", ChangeReason: "synthetic isolated legacy entry fence probe"}
		f.admission = &bootstrapEntryAdmission{grant: f.grant, config: f.config}
		if history {
			var present int
			mustSQL(t, db.QueryRow("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND LEFT(TABLE_NAME,23)='system_backup_producer_'").Scan(&present))
			if present != 0 {
				t.Fatal("history seed must precede original C1 schema")
			}
			f.first, err = (sec.ConfigBootstrapService{DB: db, Admission: f.admission}).Bootstrap(context.Background(), f.grant, f.config.CanonicalJSON())
			mustSQL(t, err)
			if f.first.Replayed || f.first.Version != 1 {
				t.Fatal("history not originally committed")
			}
		}
	})
	f.service = sec.ConfigBootstrapService{DB: f.db, Admission: f.admission}
	f.admission.authCalls, f.admission.reserves = 0, 0
	f.admission.reserveMarker = true
	var present, checks int
	mustSQL(t, f.db.QueryRow("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND LEFT(TABLE_NAME,23)='system_backup_producer_'").Scan(&present))
	mustSQL(t, f.db.QueryRow("SELECT @@session.foreign_key_checks").Scan(&checks))
	if present != wantTables || checks != 1 {
		t.Fatal("entry schema fixture differs", present, checks)
	}
	t.Logf("ENTRY_FIXTURE migrations=96 canonical_A=8 c1=%d foreign_key_checks=1 history_pre_C1=%t authority=synthetic", present, history)
	return f
}
func bootstrapEntryAdmissionValue(t *testing.T, c sec.BootstrapConfig, configured bool) pd.Admission {
	t.Helper()
	name := "unconfigured_artifact"
	if configured {
		name = "disabled_artifact"
	}
	r, err := pd.DecodeResult(dIntegrationVector(t, "positive", name))
	mustSQL(t, err)
	if configured {
		r.Admission.Configured.ConfigHash = pd.Hash(c.SHA256())
		r.Admission.Configured.ConfigVersion = "1"
	}
	return r.Admission
}
func bootstrapEntryOpenDomain(t *testing.T, f *bootstrapEntryFixture, configured bool) pd.DomainRecord {
	t.Helper()
	a := &dMySQLDomainOpenAuthority{db: f.db, issuer: pd.Hash(strings.Repeat("e", 64)), admission: bootstrapEntryAdmissionValue(t, f.config, configured)}
	opener, err := pd.NewDomainOpener(f.db, f.scope, a)
	mustSQL(t, err)
	d, err := opener.OpenDomain(context.Background(), pd.DomainOpenRequest{Scope: f.scope, Operation: "provision", ExpectedEpoch: "0", ExpectedRowVersion: "0", DeploymentHash: pd.Hash(strings.Repeat("a", 64))})
	mustSQL(t, err)
	t.Logf("ENTRY_DOMAIN provision=real_DomainOpener configured=%t management_authority=synthetic", configured)
	return d
}

type bootstrapEntrySQLWriter interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func bootstrapEntryStoreDomain(ctx context.Context, db bootstrapEntrySQLWriter, d pd.DomainRecord) error {
	row, err := pd.EncodeStoredRecord(&d)
	if err != nil {
		return err
	}
	var sets []string
	var args []any
	for k, v := range row.Columns {
		sets = append(sets, k+"=?")
		args = append(args, v)
	}
	args = append(args, row.Columns["scope_key"])
	r, err := db.ExecContext(ctx, "UPDATE "+row.Table+" SET "+strings.Join(sets, ",")+" WHERE scope_key=?", args...)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil || n != 1 {
		return pd.ErrGuardRequired
	}
	return nil
}
func bootstrapEntryLowIdentity(t *testing.T, f *bootstrapEntryFixture) *sql.DB {
	t.Helper()
	var entropy [24]byte
	_, err := rand.Read(entropy[:])
	mustSQL(t, err)
	user := "dentry_" + hex.EncodeToString(entropy[:8])
	password := hex.EncodeToString(entropy[8:])
	_, err = f.db.Exec("CREATE USER '" + user + "'@'127.0.0.1' IDENTIFIED BY '" + password + "'")
	mustSQL(t, err)
	t.Cleanup(func() {
		if _, e := f.db.Exec("DROP USER '" + user + "'@'127.0.0.1'"); e != nil {
			t.Error("CLEANUP_PENDING entry mysql account")
			return
		}
		t.Log("CLEANED entry run-owned mysql account")
	})
	for _, table := range []string{"users", "audit_logs", "system_backup_v2_evidence", "system_backup_v2_evidence_chunks", "system_backup_v2_configs", "system_backup_v2_installation_state", "system_backup_v2_operations", "system_backup_v2_metadata_reservations"} {
		_, err = f.db.Exec("GRANT SELECT,INSERT,UPDATE,DELETE ON " + string(f.scope.Database) + "." + table + " TO '" + user + "'@'127.0.0.1'")
		mustSQL(t, err)
	}
	cfg := mysql.NewConfig()
	cfg.User = user
	cfg.Passwd = password
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort("127.0.0.1", "3306")
	cfg.DBName = string(f.scope.Database)
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = 5*time.Second, 15*time.Second, 15*time.Second
	cfg.Params = map[string]string{"time_zone": "'+00:00'", "innodb_lock_wait_timeout": "5"}
	db, err := sql.Open("mysql", cfg.FormatDSN())
	mustSQL(t, err)
	t.Cleanup(func() { db.Close() })
	var visible int
	mustSQL(t, db.QueryRow("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND LEFT(TABLE_NAME,23)='system_backup_producer_'").Scan(&visible))
	rows, e := db.Query("SELECT 1 FROM system_backup_producer_domains LIMIT 0")
	if rows != nil {
		rows.Close()
	}
	var denied *mysql.MySQLError
	if visible != 0 || !errors.As(e, &denied) || denied.Number != 1142 {
		t.Fatal("actual hidden C1/typed permission fixture not established")
	}
	// Establish that this identity can acquire the A prefix, then prove the
	// actual exported fence rejects invisible C1 instead of treating it absent.
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	mustSQL(t, err)
	defer tx.Rollback()
	for _, query := range []string{
		"SELECT origin_installation_id FROM system_backup_v2_installation_state ORDER BY origin_installation_id FOR UPDATE",
		"SELECT id,origin_installation_id,version,config_sha256,enabled,nonce_hmac_ref_version,nonce_hmac_identity_hash FROM system_backup_v2_configs FORCE INDEX(uk_sb_config_version) ORDER BY origin_installation_id,version FOR UPDATE",
	} {
		rows, err := tx.QueryContext(ctx, query)
		mustSQL(t, err)
		for rows.Next() {
		}
		mustSQL(t, rows.Err())
		mustSQL(t, rows.Close())
	}
	fence, err := pd.LockBootstrapInlineDomain(ctx, tx, f.scope)
	if fence != nil || !errors.Is(err, pd.ErrUnavailable) {
		t.Fatal("real invisible C1 fence did not reject permission failure")
	}
	mustSQL(t, tx.Rollback())
	t.Log("ENTRY_VISIBILITY real_tables=8 metadata_visible=0 direct_error=1142 identity=A_tables_only A_prefix_access=verified helper_denied=yes")
	return db
}
func TestDBootstrapEntryMySQLSeed(t *testing.T) {
	capsule := bootstrapMySQLInput(t)
	c := bootstrapMySQLProfile(t, capsule)
	first := bootstrapEntryFirstDDL(t, capsule.DDL)
	if len(bootstrapEntryCases) != 22 || strings.Count(first, "CREATE TABLE ") != 1 || !strings.Contains(first, "system_backup_producer_domains") {
		t.Fatal("entry closed fixture catalog differs")
	}
	for _, configured := range []bool{false, true} {
		a := bootstrapEntryAdmissionValue(t, c, configured)
		if configured != (a.Configured != nil) {
			t.Fatal("entry admission shape")
		}
	}
	t.Log("PASS bootstrap-entry-seed cases=22 original_pre_C1_writer=yes domain_open=real_API hidden_C1_requires_typed1142=yes actual_mysql=not_run production=no")
}

func TestDBootstrapEntryMySQL(t *testing.T) {
	for _, mode := range bootstrapEntryCases {
		t.Run(mode, func(t *testing.T) {
			schema := "full"
			history := strings.HasPrefix(mode, "history_") || mode == "late_domain_mutation"
			if mode == "schema_absent_first" || mode == "history_schema_absent" || mode == "commit_lost" {
				schema = "absent"
			}
			if mode == "schema_partial_first" {
				schema = "partial"
			}
			f := bootstrapEntryNew(t, schema, history)
			var domain *pd.DomainRecord
			configured := strings.HasPrefix(mode, "history_configured_") || mode == "history_wrong_hash" || mode == "history_wrong_version" || mode == "late_domain_mutation"
			if configured || strings.HasPrefix(mode, "history_unconfigured_") || mode == "schema_full_unconfigured_first" {
				d := bootstrapEntryOpenDomain(t, f, configured)
				domain = &d
				if strings.HasSuffix(mode, "_closed") {
					d.State = "closed"
				}
				if strings.HasSuffix(mode, "_revoked") {
					d.State = "revoked"
				}
				if mode == "history_wrong_hash" {
					d.Admission.Configured.ConfigHash = pd.Hash(strings.Repeat("f", 64))
				}
				if mode == "history_wrong_version" {
					d.Admission.Configured.ConfigVersion = "2"
				}
				if d.State != "open" || mode == "history_wrong_hash" || mode == "history_wrong_version" {
					mustSQL(t, bootstrapEntryStoreDomain(context.Background(), f.db, d))
					t.Log("ENTRY_DOMAIN_VARIANT canonical_codec=yes controlled_fixture_only=yes")
				}
				domain = &d
			}
			if mode == "hidden_c1_a_only" {
				f.service.DB = bootstrapEntryLowIdentity(t, f)
			}
			if mode == "history_admin_revoked" {
				_, e := f.db.Exec("UPDATE users SET is_active=FALSE WHERE id=42")
				mustSQL(t, e)
			}
			if mode == "history_authority_revoked" {
				f.admission.denied = true
			}
			if mode == "late_domain_mutation" {
				f.admission.late = func(ctx context.Context, tx *sql.Tx) error {
					d := *domain
					d.Epoch = "2"
					d.RowVersion = "2"
					if e := bootstrapEntryStoreDomain(ctx, tx, d); e != nil {
						return e
					}
					t.Log("ENTRY_LATE_DOMAIN mutation_rows=1 original_tx=yes stage=final_authorize")
					return nil
				}
			}
			before := dMySQLSnapshot(t, f.db)
			if mode == "scope_gap_lock" {
				bootstrapEntryGap(t, f, before)
				return
			}
			if mode == "wrong_context" || mode == "wrong_transaction" {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				tx, e := f.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
				mustSQL(t, e)
				defer tx.Rollback()
				fence, e := pd.LockBootstrapInlineDomain(ctx, tx, f.scope)
				mustSQL(t, e)
				if mode == "wrong_context" {
					other, done := context.WithCancel(context.Background())
					defer done()
					e = fence.Recheck(other, tx)
				} else {
					other, x := f.db.BeginTx(context.Background(), nil)
					mustSQL(t, x)
					defer other.Rollback()
					e = fence.Recheck(ctx, other)
				}
				if e == nil {
					t.Fatal("fence binding bypassed")
				}
				mustSQL(t, tx.Rollback())
				dMySQLUnchanged(t, f.db, before)
				t.Logf("ENTRY_RESULT case=%s result=denied A_D_rows=unchanged", mode)
				return
			}
			if mode == "commit_lost" {
				f.lost.Store(true)
			}
			r, e := f.service.Bootstrap(context.Background(), f.grant, f.config.CanonicalJSON())
			allowed := mode == "schema_absent_first" || mode == "history_schema_absent" || mode == "history_full_no_domain" || strings.HasPrefix(mode, "history_configured_")
			if mode == "commit_lost" {
				if !errors.Is(e, sec.ErrRegistrationCommitUnknown) || r != (sec.ConfigBootstrapResult{}) {
					t.Fatal("entry commit acknowledgement not uncertain")
				}
				committed := dMySQLSnapshot(t, f.db)
				f.admission.authCalls = 0
				r, e = f.service.Bootstrap(context.Background(), f.grant, f.config.CanonicalJSON())
				mustSQL(t, e)
				if !r.Replayed || f.admission.reserves != 1 {
					t.Fatal("entry lost commit did not recover exact history")
				}
				dMySQLUnchanged(t, f.db, committed)
				t.Log("ENTRY_RESULT case=commit_lost result=commit_unknown_then_history capacity_callbacks=1 A_D_rows=unchanged_on_retry")
				return
			}
			if !allowed {
				if e == nil || r != (sec.ConfigBootstrapResult{}) {
					t.Fatal("entry fallback admitted", mode)
				}
				dMySQLUnchanged(t, f.db, before)
				if f.admission.reserves != 0 {
					t.Fatal("denied entry reserved capacity")
				}
				t.Logf("ENTRY_RESULT case=%s result=denied A_D_rows=unchanged", mode)
				return
			}
			mustSQL(t, e)
			if history {
				if !r.Replayed || r.OperationPublicID != f.first.OperationPublicID || f.admission.reserves != 0 {
					t.Fatal("entry exact history not read only")
				}
				dMySQLUnchanged(t, f.db, before)
				t.Logf("ENTRY_RESULT case=%s result=history capacity_callbacks=0 A_D_rows=unchanged", mode)
			} else {
				if r.Replayed || r.Version != 1 || f.admission.reserves != 1 {
					t.Fatal("old schema original writer failed")
				}
				var configs int
				mustSQL(t, f.db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=1 AND enabled=FALSE", f.grant.InstallationID).Scan(&configs))
				if configs != 1 {
					t.Fatal("entry atomic disabled config missing")
				}
				t.Logf("ENTRY_RESULT case=%s result=created capacity_callbacks=1 disabled_v1=yes", mode)
			}
		})
	}
}

func bootstrapEntryGap(t *testing.T, f *bootstrapEntryFixture, before map[string][][]any) {
	t.Helper()
	entered := make(chan uint64, 1)
	release := make(chan struct{})
	var once sync.Once
	ctx, cancel := context.WithCancel(context.Background())
	writerCtx, stopWriter := context.WithTimeout(context.Background(), 8*time.Second)
	var workers sync.WaitGroup
	var writer *sql.Tx
	defer func() {
		cancel()
		once.Do(func() { close(release) })
		stopWriter()
		if writer != nil {
			_ = writer.Rollback()
		}
		done := make(chan struct{})
		go func() { workers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("CLEANUP_PENDING entry gap workers")
		}
	}()
	f.admission.barrier = func(ctx context.Context, tx *sql.Tx) error {
		var id uint64
		if e := tx.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&id); e != nil {
			return e
		}
		entered <- id
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	serviceDone := make(chan error, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		r, e := f.service.Bootstrap(ctx, f.grant, f.config.CanonicalJSON())
		if r != (sec.ConfigBootstrapResult{}) {
			e = errors.New("unexpected legacy success")
		}
		serviceDone <- e
	}()
	var blocker uint64
	select {
	case blocker = <-entered:
	case e := <-serviceDone:
		t.Fatal("entry did not hold domain absence", e)
	case <-time.After(3 * time.Second):
		t.Fatal("entry barrier timeout")
	}
	tx, e := f.db.BeginTx(writerCtx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	mustSQL(t, e)
	writer = tx
	var requester uint64
	mustSQL(t, tx.QueryRowContext(writerCtx, "SELECT CONNECTION_ID()").Scan(&requester))
	// Use the original complete domain codec for a direct insert adversary. It
	// deliberately omits installation locks to isolate the domain PK gap proof.
	var d pd.DomainRecord
	mustSQL(t, pd.DecodeRecord(dIntegrationVector(t, "records", "DomainRecord"), &d))
	d.Scope = f.scope
	var now time.Time
	mustSQL(t, f.db.QueryRowContext(writerCtx, "SELECT UTC_TIMESTAMP(6)").Scan(&now))
	d.CreatedAt = systemExecutionStamp(now)
	d.UpdatedAt = d.CreatedAt
	d.AdmissionExpiresAt = systemExecutionStamp(now.Add(time.Minute))
	d.Admission = bootstrapEntryAdmissionValue(t, f.config, false)
	row, e := pd.EncodeStoredRecord(&d)
	mustSQL(t, e)
	var names, marks []string
	var args []any
	for k, v := range row.Columns {
		names = append(names, k)
		marks = append(marks, "?")
		args = append(args, v)
	}
	writerDone := make(chan error, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		r, e := tx.ExecContext(writerCtx, "INSERT INTO "+row.Table+"("+strings.Join(names, ",")+") VALUES("+strings.Join(marks, ",")+")", args...)
		if e == nil {
			n, x := r.RowsAffected()
			if x != nil || n != 1 {
				e = pd.ErrGuardRequired
			}
		}
		if e == nil {
			e = tx.Commit()
		}
		writerDone <- e
	}()
	deadline := time.Now().Add(1500 * time.Millisecond)
	observed := false
	for time.Now().Before(deadline) {
		select {
		case e := <-writerDone:
			t.Fatal("direct domain insert escaped gap", e)
		default:
		}
		var count int
		mustSQL(t, f.db.QueryRowContext(writerCtx, `SELECT COUNT(*) FROM performance_schema.data_lock_waits w JOIN performance_schema.data_locks l ON l.ENGINE=w.ENGINE AND l.ENGINE_LOCK_ID=w.REQUESTING_ENGINE_LOCK_ID JOIN performance_schema.threads r ON r.THREAD_ID=w.REQUESTING_THREAD_ID JOIN performance_schema.threads b ON b.THREAD_ID=w.BLOCKING_THREAD_ID WHERE r.PROCESSLIST_ID=? AND b.PROCESSLIST_ID=? AND l.OBJECT_SCHEMA=DATABASE() AND l.OBJECT_NAME='system_backup_producer_domains' AND l.INDEX_NAME='PRIMARY' AND l.LOCK_TYPE='RECORD' AND l.LOCK_MODE LIKE '%INSERT_INTENTION%'`, requester, blocker).Scan(&count))
		if count == 1 {
			observed = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !observed {
		t.Fatal("actual domain absence gap wait missing")
	}
	t.Log("ENTRY_GAP index=PRIMARY insertion_intention=yes actual_wait_graph=yes direct_installation_lock=no")
	cancel()
	once.Do(func() { close(release) })
	select {
	case e = <-serviceDone:
		if e == nil {
			t.Fatal("cancelled entry succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("entry cancellation did not return")
	}
	select {
	case e = <-writerDone:
		mustSQL(t, e)
	case <-time.After(3 * time.Second):
		t.Fatal("direct writer not released")
	}
	after := dMySQLSnapshot(t, f.db)
	delete(before, "system_backup_producer_domains")
	domainRows := after["system_backup_producer_domains"]
	delete(after, "system_backup_producer_domains")
	if len(domainRows) != 1 || !reflect.DeepEqual(before, after) {
		t.Fatal("gap rollback changed unrelated rows")
	}
	t.Log("ENTRY_RESULT case=scope_gap_lock result=gap_observed_then_released A_rows=unchanged direct_domain_rows=1")
}
