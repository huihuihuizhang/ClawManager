package systembackupevidence

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	metadata "clawreef/internal/systembackupgcmetadata"
	pd "clawreef/internal/systembackupproducer"
)

// Real adapter/observer/collector SQL with synthetic transport. No real grant,
// MySQL lock compatibility, physical capacity or deployment approval is proved.
type fullGCConn struct {
	*gcFrozenWorkConn
	grants      []string
	mode        string
	finalTicket bool
	onFinal     func()
}

func (c *fullGCConn) QueryContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	if q == "SELECT @@version" {
		return admissionTxRow("8.4.8"), nil
	}
	if q == downloadGCEarlyAccountSQL {
		return admissionTxRow(c.identity.ServerUUID, c.identity.Database, c.early.account, "NONE"), nil
	}
	if q == downloadGCFreezeSessionSQL {
		return admissionTxRow(c.identity.ServerUUID, c.identity.Database, c.early.account, "NONE", "+00:00", int64(41)), nil
	}
	if q == downloadGCEarlyGrantsSQL {
		var rows [][]driver.Value
		for _, g := range c.grants {
			rows = append(rows, []driver.Value{g})
		}
		return &admissionTxRows{width: 1, data: rows}, nil
	}
	if q == downloadGCFreezeHeldSQL && !c.finalTicket && len(c.queries) > 1 && len(c.writes) == 7 && c.queries[len(c.queries)-1] == downloadIntentClockSQL && c.queries[len(c.queries)-2] == "SELECT id FROM audit_logs WHERE id=?" {
		c.finalTicket = true
		if c.onFinal != nil {
			c.onFinal()
		}
		switch c.mode {
		case "late_grant":
			c.grants = c.grants[1:]
		case "late_worker":
			c.worker[6] = "other"
		case "late_hold":
			c.taskEligibility.tasks[c.taskEligibility.backup][19] = true
		case "late_config":
			c.activeConfig = 2
		case "late_clock":
			c.now = c.now.Add(-time.Microsecond)
		case "late_reference":
			r := c.direct.initial[0]
			c.direct.refs[gcTaskRangeKey(r.query, r.args...)] = [][]driver.Value{{int64(9900)}}
		}
	}
	return c.gcFrozenWorkConn.QueryContext(ctx, q, a)
}

func (c *fullGCConn) ExecContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Result, error) {
	if q == "UNLOCK INSTANCE" && c.mode == "unlock_unknown" {
		return nil, errors.New("PRIVATE release lost")
	}
	return c.gcFrozenWorkConn.ExecContext(ctx, q, a)
}

type fullGCConnector struct{ c *fullGCConn }

func (c fullGCConnector) Driver() driver.Driver { return c.c.Driver() }
func (c fullGCConnector) Connect(context.Context) (driver.Conn, error) {
	c.c.connections++
	return c.c, nil
}

type fullGCObserver struct {
	worker *fullGCConn
	setup  bool
	reads  int
	grants []string
}

func (o *fullGCObserver) Driver() driver.Driver { return o.worker.Driver() }
func (o *fullGCObserver) Connect(context.Context) (driver.Conn, error) {
	return &fullGCObserverConn{o}, nil
}

type fullGCObserverConn struct{ o *fullGCObserver }

func (*fullGCObserverConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected observer prepare")
}
func (*fullGCObserverConn) Close() error { return nil }
func (*fullGCObserverConn) Begin() (driver.Tx, error) {
	return nil, errors.New("observer must not begin")
}
func (c *fullGCObserverConn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	o := c.o
	if !o.setup && (!o.worker.held || o.worker.active) {
		return nil, errors.New("observer outside held pretransaction boundary")
	}
	if q == "SHOW GRANTS" {
		var rows [][]driver.Value
		for _, g := range o.grants {
			rows = append(rows, []driver.Value{g})
		}
		return &admissionTxRows{width: 1, data: rows}, nil
	}
	if strings.HasPrefix(q, "SELECT @@server_uuid") {
		o.reads++
		return admissionTxRow(o.worker.identity.ServerUUID, o.worker.identity.Database, "gc_observer@localhost", "NONE", int64(42), o.worker.now, int64(0), "8.4.8", "utf8mb4", "utf8mb4", "utf8mb4"), nil
	}
	if strings.Contains(q, " FROM INFORMATION_SCHEMA.") {
		return &admissionTxRows{width: 1}, nil
	}
	return nil, errors.New("unexpected observer SQL")
}

// Domain fake covers original owner/range checks only. The adapter performs
// its own real full-profile admission; the old Early profile stays untouched.
type fullGCDomain struct{ *retentionGCPolicy }

func (p fullGCDomain) AdmitFreezeSession(ctx context.Context, conn *sql.Conn, s DownloadGCFreezeScope) error {
	if p.d.fail == "full_protocol_unverified" || p.d.fail == "full_protocol_revoked" && s.BackupLockHeld {
		return ErrDenied
	}
	if ctx.Err() != nil || conn == nil || s.WorkerOperation != "sop_99999999-9999-4999-8999-999999999999" || s.ServerUUID != p.d.identity.ServerUUID || s.Database != p.d.identity.Database || s.WorkerAccount != p.d.early.account || s.ObserverAccount != "gc_observer@localhost" || s.MySQLVersion != "8.4.8" || s.SessionID != 41 || s.ConfigVersion != 1 || s.WorkerRowVersion != 7 || !digestPattern.MatchString(s.PeerCertificateSHA256) || s.ConfigSHA256 != hash(p.d.config.CanonicalJSON()) || s.AuthorityExpiresAt.IsZero() {
		return ErrDenied
	}
	return nil // Synthetic protocol approval, never a production authority.
}

func (p fullGCDomain) Early(ctx context.Context, tx *sql.Tx, h DownloadGCEarlyScope, _ time.Time) (DownloadRetentionGCGuard, error) {
	g := &DownloadGCEarlyReferenceGuard{source: p.d.early.service, tx: tx, hint: h, state: &downloadGCEarlyReferenceState{}}
	if g.references(ctx, tx) != nil {
		return nil, ErrDenied
	}
	return fullGCDomainEarly{g}, nil
}

type fullGCDomainEarly struct {
	g *DownloadGCEarlyReferenceGuard
}

func (g fullGCDomainEarly) Recheck(ctx context.Context, tx *sql.Tx, _ DownloadRetentionGCScope, _ time.Time) error {
	return g.g.references(ctx, tx)
}

func configureFullGC(t *testing.T, f *retentionGCFixture) (*fullGCConn, *fullGCObserver, DownloadGCFullFreezeConfig) {
	t.Helper()
	i := f.d.record.Manifest.Identity
	f.s.c.Policy = fullGCDomain{f.policy}
	if i.OwnerType != "system" {
		f.d.taskEligibility = newGCTaskEligibilityModel(t, f.d.identity, i.Installation, i.OwnerType, i.OwnerID, f.d.now)
	} else {
		// Include the actual published producer tables in the structural/read
		// fixture as well as the independently exercised producer SQL model.
		for _, table := range taskDownloadSystemProducerTables {
			f.d.early.catalog[downloadGCEarlyTablesSQL] = append(f.d.early.catalog[downloadGCEarlyTablesSQL], []driver.Value{table, "BASE TABLE", "InnoDB", "utf8mb4_unicode_ci"})
			f.d.early.grants = append(f.d.early.grants, "GRANT SELECT ON `"+f.d.identity.Database+"`.`"+table+"` TO 'download_gc'@'localhost'")
		}
		f.d.early.service.c.Metadata = f.d.early.pins()
	}
	c := &fullGCConn{gcFrozenWorkConn: &gcFrozenWorkConn{retentionGCModel: f.d}}
	c.grants = append([]string(nil), f.d.early.grants...)
	c.grants = append(c.grants, "GRANT INSERT ON `"+f.d.identity.Database+"`.`system_backup_v2_metadata_reservations` TO 'download_gc'@'localhost'")
	for _, body := range []string{"BACKUP_ADMIN ON *.*", "SELECT ON `performance_schema`.`metadata_locks`", "SELECT ON `performance_schema`.`threads`"} {
		c.grants = append(c.grants, "GRANT "+body+" TO 'download_gc'@'localhost'")
	}
	worker := f.d.early.service.c
	worker.GrantsSHA256 = fullGCGrantsPin(c.grants)
	o := &fullGCObserver{worker: c, setup: true, grants: []string{"GRANT SELECT, SHOW VIEW, TRIGGER, EVENT ON *.* TO 'gc_observer'@'localhost'", "GRANT SHOW_ROUTINE ON *.* TO 'gc_observer'@'localhost'"}}
	db := sql.OpenDB(o)
	t.Cleanup(func() { db.Close() })
	pin, err := metadata.GrantsDigest(o.grants)
	if err != nil {
		t.Fatal(err)
	}
	config := DownloadGCFullFreezeConfig{Connector: fullGCConnector{c}, WaitSeconds: 1, Worker: worker, Observer: metadata.Config{DB: db, ServerUUID: f.d.identity.ServerUUID, Database: f.d.identity.Database, Account: "gc_observer@localhost", Version: "8.4.8", GrantsSHA256: pin}}
	source, err := metadata.New(config.Observer)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := source.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	config.ProgramsSHA256 = observation.Digests().Combined
	o.setup = false
	o.reads = 0
	return c, o, config
}
func fullGCGrantsPin(ss []string) string {
	c := append([]string(nil), ss...)
	sort.Strings(c)
	return hash(canonical(c))
}

func installFullGC(t *testing.T, f *retentionGCFixture, c DownloadGCFullFreezeConfig) {
	t.Helper()
	peer := newTaskFixture(t, false)
	config := f.s.c
	config.ClientCAPEM = peer.c.ClientCAPEM
	config.ClientCASHA256 = peer.c.ClientCASHA256
	config.CertificateSHA256 = peer.c.CertificateSHA256
	config.ExpiresAt = peer.c.ExpiresAt
	config.Policy = fullGCDomain{f.policy}
	config.Freeze = &c
	missing := config
	missing.Freeze = nil
	if _, err := NewSQLDownloadRetentionGC(missing); err == nil {
		t.Fatal("full authority silently downgraded to legacy owner")
	}
	var err error
	f.s, err = NewSQLDownloadRetentionGC(config)
	if err != nil {
		t.Fatal(err)
	}
	f.ctx, err = f.s.AuthenticateRequest(peer.request)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDownloadGCFullCollectOwnerAndLateFailures(t *testing.T) {
	for _, mode := range []string{"commit", "late_grant", "late_worker", "late_hold", "late_config", "late_clock", "late_reference", "program_pin", "observer_grant", "unlock_unknown", "commit_unknown", "full_protocol_unverified", "full_protocol_revoked"} {
		t.Run(mode, func(t *testing.T) {
			f := newRetentionGCFixture(t)
			c, o, config := configureFullGC(t, f)
			installFullGC(t, f, config)
			c.mode = mode
			if strings.HasPrefix(mode, "full_protocol_") {
				f.d.fail = mode
			}
			if mode == "program_pin" {
				f.s.freeze.programs = strings.Repeat("0", 64)
			}
			if mode == "observer_grant" {
				o.grants = o.grants[:1]
			}
			if mode == "commit_unknown" {
				f.d.commitUnknown = true
			}
			before := gcConnectionGroupSnapshot(f.d)
			err := f.s.Collect(f.ctx, f.operation)
			if c.connections != 1 || f.d.active {
				t.Fatal("wrong session/transaction ownership", err)
			}
			if strings.HasPrefix(mode, "full_protocol_") {
				wantReleases := 0
				if mode == "full_protocol_revoked" {
					wantReleases = 1
				}
				if err == nil || c.begins != 0 || len(c.writes) != 0 || c.releases != wantReleases || o.reads != 0 {
					t.Fatal("unapproved/revoked protocol reached observation/work", err)
				}
				return
			}
			if mode == "program_pin" || mode == "observer_grant" {
				if err == nil || c.begins != 0 || len(c.writes) != 0 || c.releases != 1 {
					t.Fatal("untrusted observation reached work", err)
				}
				return
			}
			if !c.finalTicket || c.begins != 1 || o.reads != 2 {
				t.Fatal("protected owner/finalizer boundary missed", err, c.finalTicket, c.begins, o.reads)
			}
			committed := mode == "commit" || mode == "unlock_unknown" || mode == "commit_unknown"
			if committed {
				if f.d.commits != f.commits+1 || f.d.rollbacks != f.rollbacks || len(f.d.m.op) != 0 || len(f.d.stone) != 23 {
					t.Fatal("wrong commit/rollback", err)
				}
				if mode == "commit" && err != nil {
					t.Fatal(err)
				}
				if mode != "commit" && !errors.Is(err, ErrDownloadRetentionGCReleaseUnknown) {
					t.Fatal("release uncertainty lost", err)
				}
				if mode == "commit_unknown" && !errors.Is(err, ErrDownloadRetentionGCCommitUnknown) {
					t.Fatal("commit uncertainty lost", err)
				}
			} else if err == nil || f.d.commits != f.commits || f.d.rollbacks != f.rollbacks+1 || !reflect.DeepEqual(gcConnectionGroupSnapshot(f.d), before) {
				t.Fatal("late denial escaped atomic rollback", err)
			}
			if strings.Contains(fmt.Sprint(err), "PRIVATE") {
				t.Fatal("private error escaped")
			}
		})
	}
}

func TestDownloadGCFullPinsCapacityBeforeFreeze(t *testing.T) {
	for _, mode := range []string{"removed_after_lock", "replaced_after_lock", "missing_before_connect"} {
		t.Run(mode, func(t *testing.T) {
			f := newRetentionGCFixture(t)
			c, _, config := configureFullGC(t, f)
			installFullGC(t, f, config)
			changed := false
			change := func() {
				changed = true
				if mode == "replaced_after_lock" {
					f.p.report.AvailableBytes = 0
					f.p.writeReport(t)
				} else if err := os.Remove(f.p.reportPath); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "missing_before_connect" {
				change()
			} else {
				c.beforeQuery = func(q string) {
					if !changed && c.held && q == downloadGCFreezeHeldSQL {
						change()
					}
				}
			}
			err := f.s.Collect(f.ctx, f.operation)
			if mode == "missing_before_connect" {
				if err == nil || c.connections != 0 || c.begins != 0 {
					t.Fatal("missing report acquired SQL ownership", err)
				}
			} else if err != nil || !changed || !c.finalTicket || f.d.commits != f.commits+1 {
				t.Fatal("Full reread report under SQL ownership", err)
			}
		})
	}
}

func TestDownloadGCFullRejectsClockBetweenCapacityAndOwnerSamples(t *testing.T) {
	f := newRetentionGCFixture(t)
	c, _, config := configureFullGC(t, f)
	installFullGC(t, f, config)
	advanced, regressed := false, false
	initialReservation := f.d.reserved
	c.beforeQuery = func(q string) {
		if !advanced && q == "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))" && f.d.reserved > initialReservation && len(f.d.queries) > 0 && f.d.queries[len(f.d.queries)-1] == "SELECT sample_at,reserved_bytes FROM system_backup_v2_metadata_reservations WHERE id=1 FOR UPDATE" {
			f.d.now = f.d.now.Add(2 * time.Microsecond)
			advanced = true
		}
		if q == downloadIntentClockSQL && advanced && !regressed {
			f.d.now = f.d.now.Add(-time.Microsecond)
			regressed = true
		}
	}
	before := gcConnectionGroupSnapshot(f.d)
	err := f.s.Collect(f.ctx, f.operation)
	if err == nil || !regressed || f.d.commits != f.commits || f.d.rollbacks != f.rollbacks+1 || !reflect.DeepEqual(gcConnectionGroupSnapshot(f.d), before) {
		t.Fatal("capacity callback SQL floor lost at fixed owner", err)
	}
}

func TestDownloadGCFullGrantsSeparateProfile(t *testing.T) {
	f := newRetentionGCFixture(t)
	c, _, config := configureFullGC(t, f)
	runtime, err := newDownloadGCFullFreeze(config, f.s.c)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.grants(c.grants) != nil || f.d.early.service.grants(c.grants) == nil {
		t.Fatal("new grants widened old profile")
	}
	for _, mode := range []string{"missing_backup", "extra", "grant_option", "role", "duplicate", "wrong_account", "repinned_extra", "mixed_backup", "escaped_recipient", "cross_database", "repinned_extra_table", "global_select", "schema_wildcard"} {
		t.Run(mode, func(t *testing.T) {
			ss := append([]string(nil), c.grants...)
			switch mode {
			case "missing_backup":
				ss = append(ss[:len(ss)-3], ss[len(ss)-2:]...)
			case "extra", "repinned_extra":
				ss = append(ss, "GRANT SYSTEM_USER ON *.* TO 'download_gc'@'localhost'")
			case "grant_option":
				ss[0] += " WITH GRANT OPTION"
			case "role":
				ss = append(ss, "GRANT 'admin'@'%' TO 'download_gc'@'localhost'")
			case "duplicate":
				ss = append(ss, ss[0])
			case "wrong_account":
				ss[0] = strings.ReplaceAll(ss[0], "'download_gc'", "'other'")
			case "mixed_backup":
				ss[len(ss)-3] = "GRANT BACKUP_ADMIN, SYSTEM_USER ON *.* TO 'download_gc'@'localhost'"
			case "escaped_recipient":
				ss[0] = "GRANT REFERENCES ON *.* TO 'download_gc\\'@\\'localhost'"
			case "cross_database":
				ss = append(ss, "GRANT SELECT ON `other`.`system_backup_v2_operations` TO 'download_gc'@'localhost'")
			case "repinned_extra_table":
				ss = append(ss, "GRANT SELECT ON `"+f.d.identity.Database+"`.`system_unreviewed_catalog` TO 'download_gc'@'localhost'")
			case "global_select":
				ss = append(ss, "GRANT SELECT ON *.* TO 'download_gc'@'localhost'")
			case "schema_wildcard":
				ss = append(ss, "GRANT SELECT ON `"+f.d.identity.Database+"`.* TO 'download_gc'@'localhost'")
			}
			copy := *runtime
			worker := *copy.worker
			copy.worker = &worker
			if mode == "repinned_extra" || mode == "repinned_extra_table" || mode == "cross_database" || mode == "mixed_backup" {
				copy.worker.c.GrantsSHA256 = fullGCGrantsPin(ss)
			}
			if copy.grants(ss) == nil {
				t.Fatal("unsafe full worker grants accepted")
			}
		})
	}
}

func TestDownloadGCFullSystemProducerCollect(t *testing.T) {
	for _, mode := range []string{"commit", "late_authority", "late_hold"} {
		t.Run(mode, func(t *testing.T) {
			f, producer := newGCProducerCollectorFixture(t)
			c, o, config := configureFullGC(t, f)
			installFullGC(t, f, config)
			before := gcConnectionGroupSnapshot(f.d)
			originalProducer := cloneGCProducerRows(producer.rows)
			c.onFinal = func() {
				if mode == "late_authority" {
					producer.run.RowVersion = "6"
					producer.store(t, &producer.run)
				}
				if mode == "late_hold" {
					r := pd.ReferenceRecord{Scope: producer.history.Scope, EvidenceID: producer.history.Evidence.EvidenceID, ReferenceKind: "hold", ReferenceKeyHash: pd.Hash(strings.Repeat("f", 64)), CreatedAt: producer.history.CreatedAt, ProtectedUntil: systemExecutionStamp(f.d.now.Add(time.Hour))}
					producer.store(t, &r)
				}
			}
			err := f.s.Collect(f.ctx, f.operation)
			if !c.finalTicket || c.connections != 1 || c.begins != 1 || c.releases != 1 || o.reads != 2 || f.policy.producerGuard == nil || f.d.active {
				t.Fatal("public system group missed concrete protected producer path", err)
			}
			if !reflect.DeepEqual(producer.rows, originalProducer) {
				t.Fatal("retained producer rows changed or rollback incomplete")
			}
			if mode == "commit" {
				if err != nil || f.d.commits != f.commits+1 || f.d.rollbacks != f.rollbacks || len(f.d.m.op) != 0 || len(f.d.stone) != 23 {
					t.Fatal("public full system group did not commit once", err)
				}
			} else if err == nil || f.d.commits != f.commits || f.d.rollbacks != f.rollbacks+1 || !reflect.DeepEqual(gcConnectionGroupSnapshot(f.d), before) {
				t.Fatal("late producer authority/hold escaped shared rollback", err)
			}
		})
	}
}

func TestDownloadGCFullReservationInsertPrivilege(t *testing.T) {
	f := newRetentionGCFixture(t)
	c, _, config := configureFullGC(t, f)
	runtime, err := newDownloadGCFullFreeze(config, f.s.c)
	if err != nil {
		t.Fatal(err)
	}
	object := "`" + f.d.identity.Database + "`.`system_backup_v2_metadata_reservations`"
	to := " TO 'download_gc'@'localhost'"
	for _, mode := range []string{"separate", "merged", "missing", "duplicate", "other_table", "other_database", "column_insert", "grant_option", "combined_extra", "wrong_complete_hash"} {
		t.Run(mode, func(t *testing.T) {
			var statements []string
			for _, g := range c.grants {
				if strings.Contains(g, " ON "+object+" TO ") {
					continue
				}
				statements = append(statements, g)
			}
			statement := "GRANT SELECT, INSERT, UPDATE ON " + object + to
			switch mode {
			case "separate":
				statements = append(statements, "GRANT SELECT, UPDATE ON "+object+to, "GRANT INSERT ON "+object+to)
				statement = ""
			case "missing":
				statement = "GRANT SELECT, UPDATE ON " + object + to
			case "duplicate":
				statements = append(statements, "GRANT INSERT ON "+object+to)
			case "other_table":
				statement = "GRANT SELECT, UPDATE ON " + object + to
				statements = append(statements, "GRANT INSERT ON `"+f.d.identity.Database+"`.`system_backup_v2_operations`"+to)
			case "other_database":
				statement = "GRANT SELECT, UPDATE ON " + object + to
				statements = append(statements, "GRANT INSERT ON `other`.`system_backup_v2_metadata_reservations`"+to)
			case "column_insert":
				statement = "GRANT SELECT, UPDATE, INSERT (`id`) ON " + object + to
			case "grant_option":
				statement += " WITH GRANT OPTION"
			case "combined_extra":
				statement = "GRANT SELECT, INSERT, UPDATE, DELETE ON " + object + to
			}
			if statement != "" {
				statements = append(statements, statement)
			}
			copy := *runtime
			worker := *runtime.worker
			copy.worker = &worker
			copy.worker.c.GrantsSHA256 = fullGCGrantsPin(statements)
			if mode == "wrong_complete_hash" {
				copy.worker.c.GrantsSHA256 = strings.Repeat("0", 64)
			}
			accepted := copy.grants(statements) == nil
			if accepted != (mode == "separate" || mode == "merged") {
				t.Fatal("incorrect full reservation INSERT profile", mode)
			}
			if (mode == "separate" || mode == "merged") && runtime.worker.grants(statements) == nil {
				t.Fatal("old Early profile widened")
			}
		})
	}
}

func TestDownloadGCFullConfigAndBatchBoundaries(t *testing.T) {
	f := newRetentionGCFixture(t)
	_, _, config := configureFullGC(t, f)
	legacy := f.s.c
	legacy.Policy = f.policy
	if _, err := newDownloadGCFullFreeze(config, legacy); err == nil {
		t.Fatal("legacy policy enabled unreviewed freeze protocol")
	}
	for _, mode := range []string{"connector", "typed_nil", "wait", "worker_scope", "observer_scope", "same_account", "missing_program", "maintenance"} {
		c := config
		switch mode {
		case "connector":
			c.Connector = nil
		case "typed_nil":
			c.Connector = aFreezeNilMap(nil)
		case "wait":
			c.WaitSeconds = 6
		case "worker_scope":
			c.Worker.Installation = "another"
		case "observer_scope":
			c.Observer.Database = "another"
		case "same_account":
			c.Observer.Account = c.Worker.Account
		case "missing_program":
			c.ProgramsSHA256 = ""
		case "maintenance":
			c.Worker.MaintenanceReceipts = "absent"
		}
		if _, err := newDownloadGCFullFreeze(c, f.s.c); err == nil {
			t.Fatal("unsafe config accepted", mode)
		}
	}
	if _, err := json.Marshal(config); err == nil {
		t.Fatal("freeze config serialized")
	}
	for _, failure := range []error{ErrDownloadRetentionGCReleaseUnknown, errors.Join(ErrDownloadRetentionGCCommitUnknown, ErrDownloadRetentionGCReleaseUnknown), errors.Join(ErrDownloadRetentionGCRollbackUnknown, ErrDownloadRetentionGCReleaseUnknown)} {
		calls := 0
		result, err := runDownloadGCBatch(context.Background(), DownloadRetentionGCBatchResult{Cursor: DownloadRetentionGCBatchCursor{ThroughID: 3}}, []downloadGCBatchCandidate{{1, "known"}, {2, "uncertain"}, {3, "must_not_run"}}, false, func(context.Context, string) error {
			calls++
			if calls == 2 {
				return failure
			}
			return nil
		})
		if err == nil || calls != 2 || result.Cursor.AfterID != 1 || result.Examined != 2 || result.Collected != 1 || result.Rejected != 0 || result.EndOfRange || !result.ReleaseUnknown || result.CommitUnknown != errors.Is(failure, ErrDownloadRetentionGCCommitUnknown) || result.RollbackUnknown != errors.Is(failure, ErrDownloadRetentionGCRollbackUnknown) {
			t.Fatal("uncertain release advanced/retried batch", result, err)
		}
	}
}
