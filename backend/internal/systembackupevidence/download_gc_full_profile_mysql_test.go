//go:build systembackup_mysql

package systembackupevidence

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	metadata "clawreef/internal/systembackupgcmetadata"
	sec "clawreef/internal/systembackupsecurity"
	"github.com/go-sql-driver/mysql"
)

// Full-PROFILE protocol probe, not public Collect or a full group fixture.
// Actual SQL/grants/observer/freeze/owner run against UID-owned disposable
// schemas. Protocol authority is explicitly synthetic and cannot authorize a
// business group: Early and Lock always deny. Production remains unapproved.
var dGCFullProfileControls = []string{"commit_canary", "rollback_canary", "missing_backup_grant", "extra_privilege", "observer_revoked", "wrong_program_pin", "missing_reservation_insert", "capacity_reservation"}

func TestDDownloadGCFullProfileMySQLSeed(t *testing.T) {
	if _, err := decodeADownloadMFAInputs(aDownloadMFASeed); err != nil {
		t.Fatal("full-profile capsule unavailable")
	}
	seen := map[string]bool{}
	for _, tc := range dGCFreezeDDLs {
		if seen[tc.name] || tc.statement == "" {
			t.Fatal("invalid DDL catalog")
		}
		seen[tc.name] = true
	}
	for _, name := range dGCFullProfileControls {
		if seen[name] {
			t.Fatal("duplicate full-profile control")
		}
		seen[name] = true
	}
	if len(seen) != 33 {
		t.Fatal("full-profile case catalog changed")
	}
	grants := aGCRoleGrants("full_profile_seed", "full_profile_seed")
	grants = append(grants, "GRANT INSERT ON `full_profile_seed`.`system_backup_v2_metadata_reservations` TO 'full_profile_seed'@'%'")
	for _, body := range []string{"BACKUP_ADMIN ON *.*", "SELECT ON `performance_schema`.`metadata_locks`", "SELECT ON `performance_schema`.`threads`"} {
		grants = append(grants, "GRANT "+body+" TO 'full_profile_seed'@'%'")
	}
	sort.Strings(grants)
	runtime := &downloadGCFullFreeze{worker: &SQLDownloadGCEarlyReferences{c: DownloadGCEarlyReferenceConfig{Account: "full_profile_seed@%", GrantsSHA256: hash(canonical(grants)), Database: sec.DatabaseIdentity{Database: "full_profile_seed"}, MaintenanceReceipts: "absent"}}}
	if runtime.grants(grants) != nil || runtime.worker.grants(grants) == nil {
		t.Fatal("full and historical profiles were conflated")
	}
	var authority DownloadGCFullFreezeAuthority = (*dGCFullProfileAuthority)(nil)
	if !nilSystemAdapter(authority) {
		t.Fatal("nil authority accepted")
	}
	t.Log("PASS full_profile_seed cases=33 actual_mysql=not_run public_collect=no full_group=no production_approval=no")
}

type dGCFullProfileFixture struct {
	role           *aGCRoleFixture
	ddl            *dGCFreezeFixture
	observer       *sql.DB
	observerConfig metadata.Config
	observerUser   string
	version        string
}

type dGCFullProfileAuthority struct {
	f        *dGCFullProfileFixture
	t        *testing.T
	holder   int64
	prepare  func(context.Context) error
	finalize func(context.Context, *sql.Tx) error
}

func (*dGCFullProfileAuthority) Early(context.Context, *sql.Tx, DownloadGCEarlyScope, time.Time) (DownloadRetentionGCGuard, error) {
	return nil, ErrDenied
}
func (*dGCFullProfileAuthority) Lock(context.Context, *sql.Tx, DownloadRetentionGCScope, time.Time) (DownloadRetentionGCGuard, error) {
	return nil, ErrDenied
}
func (a *dGCFullProfileAuthority) AdmitFreezeSession(ctx context.Context, _ *sql.Conn, s DownloadGCFreezeScope) error {
	f := a.f
	if s.ServerUUID != f.ddl.server || s.Database != f.role.c.Database.Database || s.WorkerAccount != f.role.c.Account || s.ObserverAccount != f.observerUser+"@%" || s.MySQLVersion != f.version || s.Installation != f.role.c.Installation || s.SessionID <= 0 {
		return ErrDenied
	}
	var run, uid, server string
	if f.ddl.admin.QueryRowContext(ctx, "SELECT run_namespace,namespace_uid,server_uuid FROM d_invariant_run_marker WHERE id=1").Scan(&run, &uid, &server) != nil || run != os.Getenv("D_INVARIANT_RUN") || uid != f.ddl.uid || server != f.ddl.server {
		return ErrDenied
	}
	if a.holder != 0 && a.holder != s.SessionID {
		return ErrDenied
	}
	a.holder = s.SessionID
	f.ddl.pinThread(a.t, s.SessionID)
	if s.BackupLockHeld {
		f.ddl.held(a.t, s.SessionID)
	} else {
		f.ddl.released(a.t, s.SessionID)
	}
	return nil // UID-scoped synthetic protocol approval only, never production.
}

func newDGCFullProfileFixture(t *testing.T, input aDownloadMFAInputs) *dGCFullProfileFixture {
	t.Helper()
	f := &dGCFullProfileFixture{role: newAGCRoleFixture(t, input), ddl: newDGCFreezeFixture(t)}
	if f.role.c.Database.ServerUUID != f.ddl.server {
		t.Fatal("full-profile fixtures use different servers")
	}
	f.observerUser = f.role.user + "_o"
	if !regexp.MustCompile(`^a_gc_[a-f0-9]{20}_o$`).MatchString(f.observerUser) {
		t.Fatal("unsafe observer account")
	}
	_, err := f.role.root.ExecContext(f.ddl.ctx, "CREATE USER '"+f.observerUser+"'@'%' IDENTIFIED BY '"+f.role.cfg.Passwd+"'")
	dGCFreezeOK(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		var server string
		if f.role.root.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&server) != nil || server != f.ddl.server {
			t.Error("CLEANUP_PENDING full-profile observer identity")
			return
		}
		if _, err := f.role.root.ExecContext(ctx, "DROP USER '"+f.observerUser+"'@'%'"); err != nil {
			t.Error("CLEANUP_PENDING full-profile observer account")
			return
		}
		var n int
		if f.role.root.QueryRowContext(ctx, "SELECT COUNT(*) FROM mysql.user WHERE User=? AND Host='%'", f.observerUser).Scan(&n) != nil || n != 0 {
			t.Error("CLEANUP_PENDING full-profile observer absence")
		}
	})
	for _, body := range []string{"BACKUP_ADMIN ON *.*", "SELECT ON `performance_schema`.`metadata_locks`", "SELECT ON `performance_schema`.`threads`"} {
		_, err = f.role.root.ExecContext(f.ddl.ctx, "GRANT "+body+" TO '"+f.role.user+"'@'%'")
		dGCFreezeOK(t, err)
	}
	_, err = f.role.root.ExecContext(f.ddl.ctx, "GRANT INSERT ON `"+f.role.c.Database.Database+"`.`system_backup_v2_metadata_reservations` TO '"+f.role.user+"'@'%'")
	dGCFreezeOK(t, err)
	for _, body := range []string{"SELECT, SHOW VIEW, TRIGGER, EVENT ON *.*", "SHOW_ROUTINE ON *.*"} {
		_, err = f.role.root.ExecContext(f.ddl.ctx, "GRANT "+body+" TO '"+f.observerUser+"'@'%'")
		dGCFreezeOK(t, err)
	}
	cfg := f.role.cfg.Clone()
	cfg.User = f.observerUser
	f.observer, err = sql.Open("mysql", cfg.FormatDSN())
	dGCFreezeOK(t, err)
	t.Cleanup(func() { dGCFreezeOK(t, f.observer.Close()) })
	dGCFreezeOK(t, f.role.root.QueryRowContext(f.ddl.ctx, "SELECT @@version").Scan(&f.version))
	f.observerConfig = metadata.Config{DB: f.observer, ServerUUID: f.ddl.server, Database: f.role.c.Database.Database, Account: f.observerUser + "@%", Version: f.version, GrantsSHA256: dGCFullObserverGrants(t, f)}
	return f
}

func dGCFullObserverGrants(t *testing.T, f *dGCFullProfileFixture) string {
	t.Helper()
	rows, err := f.role.root.QueryContext(f.ddl.ctx, "SHOW GRANTS FOR '"+f.observerUser+"'@'%'")
	dGCFreezeOK(t, err)
	var grants []string
	for rows.Next() {
		var g string
		dGCFreezeOK(t, rows.Scan(&g))
		grants = append(grants, g)
	}
	dGCFreezeOK(t, rows.Err())
	dGCFreezeOK(t, rows.Close())
	pin, err := metadata.GrantsDigest(grants)
	dGCFreezeOK(t, err)
	return pin
}

func (f *dGCFullProfileFixture) runtime(t *testing.T) (*downloadGCFullFreeze, *dGCFullProfileAuthority) {
	t.Helper()
	worker := f.role.c
	worker.GrantsSHA256 = aGCRoleGrantPin(t, f.ddl.ctx, f.role.root, f.role.user)
	worker.Metadata = aGCRoleMetadata(t, f.ddl.ctx, f.role.root)
	source, err := metadata.New(f.observerConfig)
	dGCFreezeOK(t, err)
	o, err := source.Read(f.ddl.ctx)
	dGCFreezeOK(t, err)
	connector, err := mysql.NewConnector(f.role.cfg.Clone())
	dGCFreezeOK(t, err)
	references, err := NewSQLDownloadGCDirectReferences(DownloadGCDirectReferencesConfig{Database: worker.Database, Installation: worker.Installation, MaintenanceReceipts: worker.MaintenanceReceipts})
	dGCFreezeOK(t, err)
	a := &dGCFullProfileAuthority{f: f, t: t}
	c := DownloadRetentionGCConfig{Registry: SQLRegistry{DB: f.role.root, ServerUUID: worker.Database.ServerUUID, Database: worker.Database.Database, Installation: worker.Installation}, References: references, Policy: a, OperationID: "sop_11111111-2222-4333-8444-555555555555", ConfigVersion: 1, OperationRowVersion: 1, ConfigSHA256: strings.Repeat("a", 64), CertificateSHA256: strings.Repeat("b", 64), ExpiresAt: time.Now().Add(time.Minute)}
	runtime, err := newDownloadGCFullFreeze(DownloadGCFullFreezeConfig{Connector: connector, WaitSeconds: 2, Worker: worker, Observer: f.observerConfig, ProgramsSHA256: o.Digests().Combined}, c)
	dGCFreezeOK(t, err)
	return runtime, a
}

func (f *dGCFullProfileFixture) run(t *testing.T, r *downloadGCFullFreeze, a *dGCFullProfileAuthority, work func(context.Context, *sql.Tx) error) (downloadGCFreezeOutcome, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.ddl.ctx, 10*time.Second)
	defer cancel()
	if a.prepare != nil {
		if err := a.prepare(ctx); err != nil {
			return downloadGCFreezeOutcome{}, err
		}
	}
	admissions := 0
	out, err := runDownloadGCFreezeProtocol(ctx, downloadGCFreezeConfig{Connector: r.connector, WaitSeconds: r.wait, Server: r.scope.ServerUUID, Database: r.scope.Database, Account: r.scope.WorkerAccount,
		Admit: func(ctx context.Context, c *sql.Conn) error {
			held := admissions > 0
			admissions++
			return r.admitSession(ctx, c, held)
		}, Observe: r.observe}, func(ctx context.Context, tx *sql.Tx) error {
		if r.worker.metadata(ctx, tx) != nil {
			return ErrDenied
		}
		return work(ctx, tx)
	}, func(ctx context.Context, tx *sql.Tx) error {
		var n int
		if r.admit(ctx, tx) != nil || tx.QueryRowContext(ctx, downloadGCFreezeHeldSQL).Scan(&n) != nil || n != 1 || r.worker.metadata(ctx, tx) != nil {
			return ErrDenied
		}
		if a.finalize != nil {
			return a.finalize(ctx, tx)
		}
		return nil
	})
	if a.holder > 0 {
		f.ddl.released(t, a.holder)
	}
	return out, err
}

func TestDDownloadGCFullProfileMySQL(t *testing.T) {
	raw, err := os.ReadFile(os.Getenv("D_PROVIDER_REGISTRATION_DDL"))
	dGCFreezeOK(t, err)
	if hash(raw) != os.Getenv("D_PROVIDER_REGISTRATION_DDL_SHA256") || hash(raw) != hash(aDownloadMFASeed) {
		t.Fatal("full-profile input capsule mismatch")
	}
	input, err := decodeADownloadMFAInputs(raw)
	dGCFreezeOK(t, err)
	f := newDGCFullProfileFixture(t, input)
	for _, tc := range dGCFreezeDDLs {
		t.Run(tc.name, func(t *testing.T) { f.ddlCase(t, tc) })
	}
	for _, name := range dGCFullProfileControls {
		t.Run(name, func(t *testing.T) {
			r, a := f.runtime(t)
			if name == "capacity_reservation" {
				f.capacityReservation(t, r, a, input)
				return
			}
			query := "INSERT INTO audit_logs(user_id,action,resource_type,details) VALUES(42,'synthetic.gc.full.canary','system_backup','{}')"
			insert, e := f.role.root.ExecContext(f.ddl.ctx, query)
			dGCFreezeOK(t, e)
			id, e := insert.LastInsertId()
			dGCFreezeOK(t, e)
			t.Cleanup(func() {
				_, e := f.role.root.ExecContext(f.ddl.ctx, "DELETE FROM audit_logs WHERE id=?", id)
				dGCFreezeOK(t, e)
			})
			if name == "wrong_program_pin" {
				r.programs = strings.Repeat("0", 64)
			}
			revoke, restore := "", ""
			switch name {
			case "missing_backup_grant":
				revoke = "REVOKE BACKUP_ADMIN ON *.* FROM '" + f.role.user + "'@'%'"
				restore = "GRANT BACKUP_ADMIN ON *.* TO '" + f.role.user + "'@'%'"
			case "extra_privilege":
				revoke = "GRANT SYSTEM_USER ON *.* TO '" + f.role.user + "'@'%'"
				restore = "REVOKE SYSTEM_USER ON *.* FROM '" + f.role.user + "'@'%'"
			case "observer_revoked":
				revoke = "REVOKE SHOW_ROUTINE ON *.* FROM '" + f.observerUser + "'@'%'"
				restore = "GRANT SHOW_ROUTINE ON *.* TO '" + f.observerUser + "'@'%'"
			case "missing_reservation_insert":
				revoke = "REVOKE INSERT ON `" + f.role.c.Database.Database + "`.`system_backup_v2_metadata_reservations` FROM '" + f.role.user + "'@'%'"
				restore = "GRANT INSERT ON `" + f.role.c.Database.Database + "`.`system_backup_v2_metadata_reservations` TO '" + f.role.user + "'@'%'"
			}
			if revoke != "" {
				_, e = f.role.root.ExecContext(f.ddl.ctx, revoke)
				dGCFreezeOK(t, e)
				defer func() { _, e := f.role.root.ExecContext(f.ddl.ctx, restore); dGCFreezeOK(t, e) }()
			}
			if name == "missing_reservation_insert" {
				_, e = f.role.root.ExecContext(f.ddl.ctx, "INSERT IGNORE INTO system_backup_v2_metadata_reservations(id,sample_at,reserved_bytes) VALUES(1,UTC_TIMESTAMP(6),0)")
				dGCFreezeOK(t, e)
				_, e = f.role.db.ExecContext(f.ddl.ctx, "INSERT IGNORE INTO system_backup_v2_metadata_reservations(id,sample_at,reserved_bytes) VALUES(1,UTC_TIMESTAMP(6),0)")
				var denied *mysql.MySQLError
				if !errors.As(e, &denied) || denied.Number != 1142 {
					t.Fatal("existing row did not still require native INSERT privilege")
				}
				defer func() {
					_, e := f.role.root.ExecContext(f.ddl.ctx, "DELETE FROM system_backup_v2_metadata_reservations WHERE id=1")
					dGCFreezeOK(t, e)
				}()
			}
			entered := false
			out, e := f.run(t, r, a, func(ctx context.Context, tx *sql.Tx) error {
				entered = true
				result, e := tx.ExecContext(ctx, "DELETE FROM audit_logs WHERE id=?", id)
				if e != nil {
					return e
				}
				n, e := result.RowsAffected()
				if e != nil || n != 1 {
					return ErrAudit
				}
				if name == "rollback_canary" {
					return ErrDenied
				}
				return nil
			})
			commit := name == "commit_canary"
			if commit {
				if e != nil || !entered || out.Transaction != "committed" || out.Unlock != "confirmed" || !out.DiscardRequested {
					t.Fatal("full-profile commit owner failed")
				}
			} else if e == nil || out.Transaction == "committed" {
				t.Fatal("full-profile rejection committed")
			}
			if name == "rollback_canary" && (!entered || out.Transaction != "rolled_back" || out.Unlock != "confirmed") {
				t.Fatal("full-profile rollback not observed")
			}
			if !commit && name != "rollback_canary" && entered {
				t.Fatal("untrusted full profile reached work")
			}
			var n int
			dGCFreezeOK(t, f.role.root.QueryRowContext(f.ddl.ctx, "SELECT COUNT(*) FROM audit_logs WHERE id=?", id).Scan(&n))
			if (n == 0) != commit {
				t.Fatal("canary atomic outcome differs")
			}
		})
	}
	t.Log("PASS full_profile_protocol cases=33 worker_profile=full observer=independent actual_mysql=yes capacity_report=synthetic public_collect=no full_group=no role_approval=no production_approval=no")
}

func (f *dGCFullProfileFixture) capacityReservation(t *testing.T, r *downloadGCFullFreeze, a *dGCFullProfileAuthority, input aDownloadMFAInputs) {
	t.Helper()
	p := aDownloadMFAPinnedFixture(t, input)
	file := filepath.Join(t.TempDir(), "synthetic-physical-capacity.json")
	capacity, err := sec.NewConfigMutationCapacity(f.role.c.Database, file, 1)
	dGCFreezeOK(t, err)
	_, err = f.role.root.ExecContext(f.ddl.ctx, "DELETE FROM system_backup_v2_metadata_reservations WHERE id=1")
	dGCFreezeOK(t, err)
	t.Cleanup(func() {
		_, e := f.role.root.ExecContext(f.ddl.ctx, "DELETE FROM system_backup_v2_metadata_reservations WHERE id=1")
		dGCFreezeOK(t, e)
	})
	var reservation sec.ConfigMutationCapacityReservation
	var prepared *sec.PreparedConfigMutationCapacity
	a.prepare = func(ctx context.Context) error {
		var now time.Time
		if err := f.role.root.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil {
			return err
		}
		report := sec.CapacityReport{ServerUUID: f.ddl.server, Database: f.role.c.Database.Database, ObservedAt: now, AllocatedBytes: 1048576, AvailableBytes: 1099511627776}
		raw, err := json.Marshal(report)
		if err != nil {
			return err
		}
		if err = os.WriteFile(file, raw, 0600); err != nil {
			return err
		}
		prepared, err = capacity.PreparePinned(ctx, 65536)
		return err
	}
	a.finalize = func(ctx context.Context, tx *sql.Tx) error {
		var now time.Time
		if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || reservation == nil {
			return ErrDenied
		}
		return reservation.Recheck(ctx, tx, now)
	}
	out, err := f.run(t, r, a, func(ctx context.Context, tx *sql.Tx) error {
		var now time.Time
		if err := tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil {
			return err
		}
		var e error
		reservation, e = prepared.Reserve(ctx, tx, capacity, p.db.config, p.db.config, now)
		return e
	})
	if err != nil || out.Transaction != "committed" || out.Unlock != "confirmed" || reservation == nil {
		t.Fatal("actual Reserve insert/update/final recheck failed under Full grants")
	}
	var bytes int64
	dGCFreezeOK(t, f.role.root.QueryRowContext(f.ddl.ctx, "SELECT reserved_bytes FROM system_backup_v2_metadata_reservations WHERE id=1").Scan(&bytes))
	if bytes != 65536 {
		t.Fatal("actual reservation ledger did not commit exact cost")
	}
	t.Log("FULL_RESERVE actual_sql=yes physical_report=synthetic production_capacity_approval=no")
}

func (f *dGCFullProfileFixture) ddlCase(t *testing.T, tc dGCFreezeDDL) {
	t.Helper()
	d, _ := dGCFreezeIdentifier(f.ddl.db)
	p, _ := dGCFreezeIdentifier(f.ddl.peer)
	user := "'" + f.ddl.target + "'@'%'"
	if tc.name == "account_create" {
		user = "'" + f.ddl.user + "_c'@'%'"
		f.ddl.createdUsers[f.ddl.user+"_c"] = true
	}
	replace := strings.NewReplacer("@d@", d, "@p@", p, "@u@", user)
	if tc.prepare != "" {
		f.ddl.exec(t, replace.Replace(tc.prepare))
	}
	if strings.HasPrefix(tc.name, "account_") && tc.name != "account_create" {
		f.ddl.exec(t, "DROP USER IF EXISTS "+user)
		f.ddl.exec(t, "CREATE USER "+user+" ACCOUNT LOCK")
		if tc.name == "account_revoke" {
			f.ddl.exec(t, "GRANT SELECT ON "+d+".* TO "+user)
		}
	}
	r, a := f.runtime(t)
	waiter, err := f.ddl.admin.Conn(f.ddl.ctx)
	dGCFreezeOK(t, err)
	defer waiter.Close()
	_, err = waiter.ExecContext(f.ddl.ctx, "SET SESSION lock_wait_timeout=5")
	dGCFreezeOK(t, err)
	var wid int64
	dGCFreezeOK(t, waiter.QueryRowContext(f.ddl.ctx, "SELECT CONNECTION_ID()").Scan(&wid))
	f.ddl.pinThread(t, wid)
	ctx, cancel := context.WithTimeout(f.ddl.ctx, 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	started, completed := false, false
	defer func() {
		cancel()
		if started && !completed {
			<-done
		}
	}()
	out, err := f.run(t, r, a, func(context.Context, *sql.Tx) error {
		started = true
		go func() { _, e := waiter.ExecContext(ctx, replace.Replace(tc.statement)); done <- e }()
		limit := time.NewTimer(2 * time.Second)
		defer limit.Stop()
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for !dGCFreezeWitness(f.ddl.tickets(t, wid), false) {
			select {
			case e := <-done:
				completed = true
				if e != nil {
					return e
				}
				return errors.New("DDL did not wait for full-profile holder")
			case <-limit.C:
				return errors.New("no bounded full-profile waiter witness")
			case <-tick.C:
			}
		}
		f.ddl.held(t, a.holder)
		t.Logf("FULL_PROFILE_WAIT case=%s holder=%d waiter=%d holder_thread=%d waiter_thread=%d", tc.name, a.holder, wid, f.ddl.threads[a.holder], f.ddl.threads[wid])
		return nil
	})
	if err != nil || out.Transaction != "committed" || out.Unlock != "confirmed" || !out.DiscardRequested {
		t.Fatal("full-profile DDL owner failed")
	}
	err = <-done
	completed = true
	dGCFreezeOK(t, err)
	f.ddl.released(t, wid)
	if tc.check != "" {
		var n int
		dGCFreezeOK(t, f.ddl.admin.QueryRowContext(f.ddl.ctx, tc.check, f.ddl.db).Scan(&n))
		if n != 1 {
			t.Fatal("released full-profile DDL effect differs")
		}
	}
	if strings.HasPrefix(tc.name, "account_") {
		var n int
		user := f.ddl.target
		if tc.name == "account_create" {
			user = f.ddl.user + "_c"
		}
		query := "SELECT COUNT(*) FROM mysql.user WHERE User=? AND Host='%'"
		expected := 1
		switch tc.name {
		case "account_drop":
			expected = 0
		case "account_alter":
			query += " AND account_locked='N'"
		case "account_grant", "account_revoke":
			query = "SELECT COUNT(*) FROM information_schema.SCHEMA_PRIVILEGES WHERE GRANTEE=CONCAT(CHAR(39),?,CHAR(39),'@',CHAR(39),'%',CHAR(39)) AND TABLE_SCHEMA='" + f.ddl.db + "' AND PRIVILEGE_TYPE='SELECT'"
			if tc.name == "account_revoke" {
				expected = 0
			}
		}
		dGCFreezeOK(t, f.ddl.admin.QueryRowContext(f.ddl.ctx, query, user).Scan(&n))
		if n != expected {
			t.Fatal("account DDL effect differs")
		}
	}
}
