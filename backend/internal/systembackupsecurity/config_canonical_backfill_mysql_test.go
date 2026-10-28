//go:build systembackup_mysql

package systembackupsecurity

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// Local SQL/synthetic admission only. These callbacks deliberately do NOT
// implement a runtime issuer/grant/source authentication or physical capacity.
type backfillMySQLAuthority struct {
	f                                                      *maintenanceMySQLFixture
	denyWrite, denyObservation                             atomic.Bool
	writeCalls, observationCalls, reserveCalls, finalCalls atomic.Int64
	capacityTTL                                            time.Duration
	onFinal, onCapacity                                    func(context.Context, *sql.Tx) error
}

func (a *backfillMySQLAuthority) bind(ctx context.Context, tx *sql.Tx, scope configMaintenanceScope, source []byte) error {
	if !scope.valid() || scope.database != a.f.identity || scope.identity != a.f.scope.identity || scope.key != a.f.scope.key || scope.hash != a.f.scope.hash || !bytes.Equal(source, a.f.original) {
		return ErrRegistrationPermission
	}
	return a.f.identity.check(ctx, tx)
}

type backfillMySQLAdmission struct {
	a           *backfillMySQLAuthority
	tx          *sql.Tx
	until       time.Time
	observation bool
}

func (r *backfillMySQLAdmission) ValidUntil() time.Time { return r.until }
func (r *backfillMySQLAdmission) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if tx != r.tx || !now.Before(r.until) || r.observation && r.a.denyObservation.Load() || !r.observation && r.a.denyWrite.Load() {
		return ErrRegistrationPermission
	}
	r.a.finalCalls.Add(1)
	if r.a.onFinal != nil {
		if err := r.a.onFinal(ctx, tx); err != nil {
			return err
		}
	}
	return r.a.f.identity.check(ctx, tx)
}
func (a *backfillMySQLAuthority) AuthorizeWrite(ctx context.Context, tx *sql.Tx, scope configMaintenanceScope, source []byte, now time.Time) (configMaintenanceAdmission, error) {
	a.writeCalls.Add(1)
	if a.denyWrite.Load() {
		return nil, ErrRegistrationPermission
	}
	if err := a.bind(ctx, tx, scope, source); err != nil {
		return nil, err
	}
	return &backfillMySQLAdmission{a: a, tx: tx, until: now.Add(time.Minute)}, nil
}
func (a *backfillMySQLAuthority) AuthorizeObservation(ctx context.Context, tx *sql.Tx, scope configMaintenanceScope, source []byte, now time.Time) (configMaintenanceAdmission, error) {
	a.observationCalls.Add(1)
	if a.denyObservation.Load() {
		return nil, ErrRegistrationPermission
	}
	if err := a.bind(ctx, tx, scope, source); err != nil {
		return nil, err
	}
	return &backfillMySQLAdmission{a: a, tx: tx, until: now.Add(time.Minute), observation: true}, nil
}

type backfillMySQLCapacity struct {
	a     *backfillMySQLAuthority
	tx    *sql.Tx
	until time.Time
}

func (r *backfillMySQLCapacity) ValidUntil() time.Time { return r.until }
func (r *backfillMySQLCapacity) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if tx != r.tx || !now.Before(r.until) {
		return ErrRegistrationUnavailable
	}
	if r.a.onCapacity != nil {
		if err := r.a.onCapacity(ctx, tx); err != nil {
			return err
		}
	}
	return r.a.f.identity.check(ctx, tx)
}
func (a *backfillMySQLAuthority) Reserve(ctx context.Context, tx *sql.Tx, scope configMaintenanceScope, b configMaintenanceBudget, now time.Time) (ConfigMutationCapacityReservation, error) {
	a.reserveCalls.Add(1)
	if err := a.bind(ctx, tx, scope, a.f.original); err != nil {
		return nil, err
	}
	if b.canonicalWriteBytes != 0 && b.canonicalWriteBytes != len(a.f.original) || b.receiptMaxBytes < 2 || b.receiptMaxBytes > maxConfigMaintenanceReceiptBytes || b.intentBytes < 2 || b.resultBytes < 2 {
		return nil, ErrRegistrationUnavailable
	}
	ttl := a.capacityTTL
	if ttl == 0 {
		ttl = time.Minute
	}
	return &backfillMySQLCapacity{a, tx, now.Add(ttl)}, nil
}
func backfillMySQLService(t *testing.T, f *maintenanceMySQLFixture, db *sql.DB, a *backfillMySQLAuthority) *configCanonicalBackfillService {
	t.Helper()
	svc, err := newConfigCanonicalBackfillService(db, f.identity, f.installation, f.scope.identity.Actor, a)
	mysqlMust(t, err)
	return svc
}
func backfillMySQLEmpty(t *testing.T, result configMaintenanceResult, err error) {
	t.Helper()
	if err == nil || result.canonical != nil || result.replayed {
		t.Fatal("failed actual service released result")
	}
}

func backfillMySQLInstallationSnapshot(t *testing.T, ctx context.Context, f *maintenanceMySQLFixture) []byte {
	t.Helper()
	rows, err := f.db.QueryContext(ctx, "SELECT * FROM system_backup_v2_installation_state WHERE origin_installation_id=?", f.installation)
	mysqlMust(t, err)
	defer rows.Close()
	columns, err := rows.Columns()
	mysqlMust(t, err)
	columns = append([]string(nil), columns...)
	if !rows.Next() {
		t.Fatal("owned installation state missing")
	}
	values := make([]any, len(columns))
	dest := make([]any, len(columns))
	for i := range values {
		dest[i] = &values[i]
	}
	mysqlMust(t, rows.Scan(dest...))
	if rows.Next() {
		t.Fatal("duplicate installation state")
	}
	mysqlMust(t, rows.Err())
	mysqlMust(t, rows.Close())
	raw, err := json.Marshal(struct {
		Columns []string
		Values  []any
	}{columns, values})
	mysqlMust(t, err)
	return raw
}

func backfillMySQLSeedInstallation(t *testing.T, ctx context.Context, f *maintenanceMySQLFixture) []byte {
	t.Helper()
	_, err := f.db.ExecContext(ctx, configProofInstallationStateInsert, f.installation, configProofDBNow(t, ctx, f.db))
	mysqlMust(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		tx, e := f.db.BeginTx(cleanup, nil)
		if e != nil {
			t.Error("CLEANUP_PENDING backfill installation state")
			return
		}
		defer tx.Rollback()
		if f.identity.check(cleanup, tx) != nil {
			t.Error("CLEANUP_PENDING backfill installation identity")
			return
		}
		if _, e = tx.ExecContext(cleanup, "DELETE FROM system_backup_v2_installation_state WHERE origin_installation_id=?", f.installation); e != nil {
			t.Error("CLEANUP_PENDING backfill installation delete")
			return
		}
		if tx.Commit() != nil {
			t.Error("CLEANUP_PENDING backfill installation cleanup commit")
			return
		}
		var n int
		if f.db.QueryRowContext(cleanup, "SELECT COUNT(*) FROM system_backup_v2_installation_state WHERE origin_installation_id=?", f.installation).Scan(&n) != nil || n != 0 {
			t.Error("CLEANUP_PENDING backfill installation absence")
			return
		}
		t.Log("CLEANED backfill service owned installation state")
	})
	return backfillMySQLInstallationSnapshot(t, ctx, f)
}
func backfillMySQLUncommitted(ctx context.Context, tx *sql.Tx, installation string) error {
	var receipts, audits, filled int
	if tx.QueryRowContext(ctx, "SELECT (SELECT COUNT(*) FROM system_backup_v2_config_maintenance_receipts WHERE origin_installation_id=?),(SELECT COUNT(*) FROM audit_logs WHERE JSON_UNQUOTE(JSON_EXTRACT(details,'$.origin_installation_id'))=?),(SELECT COUNT(*) FROM system_backup_v2_configs WHERE origin_installation_id=? AND canonical_config_json IS NOT NULL)", installation, installation, installation).Scan(&receipts, &audits, &filled) != nil || receipts != 1 || audits != 2 || filled != 1 {
		return errors.New("required uncommitted effects not reached")
	}
	return nil
}
func backfillMySQLTrigger(t *testing.T, ctx context.Context, f *maintenanceMySQLFixture, phase string) string {
	t.Helper()
	id, err := maintenanceProbeUUID()
	mysqlMust(t, err)
	name := "dbs_" + strings.ReplaceAll(id, "-", "")
	table, predicate := "system_backup_v2_config_maintenance_receipts", "NEW.origin_installation_id='"+f.installation+"'"
	if phase == "result" {
		table = "audit_logs"
		predicate = "NEW.action='system_backup.config_canonical_backfill.result' AND JSON_UNQUOTE(JSON_EXTRACT(NEW.details,'$.origin_installation_id'))='" + f.installation + "'"
	}
	_, err = f.db.ExecContext(ctx, "CREATE TRIGGER "+name+" BEFORE INSERT ON "+table+" FOR EACH ROW BEGIN IF "+predicate+" THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic backfill service rejection'; END IF; END")
	mysqlMust(t, err)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, err := f.db.ExecContext(cleanup, "DROP TRIGGER IF EXISTS "+name); err != nil {
			t.Error("CLEANUP_PENDING backfill service trigger")
		}
	})
	return name
}

type backfillMySQLWorker struct {
	id      int64
	errors  <-chan error
	results <-chan configMaintenanceResult
}

func startBackfillMySQLWorker(t *testing.T, ctx context.Context, f *maintenanceMySQLFixture, a *backfillMySQLAuthority, cfg *mysql.Config) backfillMySQLWorker {
	t.Helper()
	db, err := sql.Open("mysql", cfg.FormatDSN())
	mysqlMust(t, err)
	db.SetMaxOpenConns(1)
	var id int64
	mysqlMust(t, db.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&id))
	svc := backfillMySQLService(t, f, db, a)
	work, cancel := context.WithTimeout(ctx, 20*time.Second)
	result, fail, done := make(chan configMaintenanceResult, 1), make(chan error, 1), make(chan struct{})
	go func() {
		defer close(done)
		r, e := svc.apply(work, f.scope.key, f.scope.canonical, f.original)
		result <- r
		fail <- e
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("backfill service worker did not drain")
		}
		_ = db.Close()
	})
	return backfillMySQLWorker{id, fail, result}
}

func TestDConfigCanonicalBackfillMySQL(t *testing.T) {
	ctx, db, cfg, identity := maintenanceProbeDatabase(t)
	for _, name := range []string{"service_apply_replay_nochange", "service_audit_failure_rollback", "service_receipt_failure_rollback", "service_final_revoke_rollback", "service_capacity_expiry_after_callback", "service_lost_commit_observe_only", "service_observed_lock_single_apply"} {
		if !t.Run(name, func(t *testing.T) {
			f := newMaintenanceMySQLFixture(t, ctx, db, identity)
			beforeState := backfillMySQLSeedInstallation(t, ctx, f)
			defer func() {
				if !bytes.Equal(beforeState, backfillMySQLInstallationSnapshot(t, ctx, f)) {
					t.Error("backfill changed active/deployment/monitoring installation state")
				}
			}()
			a := &backfillMySQLAuthority{f: f}
			svc := backfillMySQLService(t, f, db, a)
			switch name {
			case "service_apply_replay_nochange":
				r, err := svc.apply(ctx, f.scope.key, f.scope.canonical, f.original)
				mysqlMust(t, err)
				if r.replayed {
					t.Fatal("new fill returned replay")
				}
				f.assert(t, ctx, 1, 2, true)
				replay, err := svc.apply(ctx, f.scope.key, f.scope.canonical, f.original)
				mysqlMust(t, err)
				if !replay.replayed || !bytes.Equal(replay.bytes(), r.bytes()) {
					t.Fatal("service replay changed response")
				}
				f.assert(t, ctx, 1, 2, true)
				a.denyWrite.Store(true)
				observed, err := svc.observe(ctx, f.scope.key, f.scope.canonical, f.original)
				mysqlMust(t, err)
				if !bytes.Equal(observed.bytes(), r.bytes()) {
					t.Fatal("observation changed original")
				}
				denied, e := svc.apply(ctx, f.scope.key, f.scope.canonical, f.original)
				backfillMySQLEmpty(t, denied, e)
				if !errors.Is(e, ErrRegistrationPermission) {
					t.Fatal("write denial fell back to observation")
				}
				a.denyObservation.Store(true)
				denied, e = svc.observe(ctx, f.scope.key, f.scope.canonical, f.original)
				backfillMySQLEmpty(t, denied, e)
				a.denyWrite.Store(false)
				a.denyObservation.Store(false)
				f.scope, e = newConfigMaintenanceScope(identity, f.installation, f.scope.identity.Actor, "backfill_service_nochange_key", f.scope.canonical)
				mysqlMust(t, e)
				nochange, e := svc.apply(ctx, f.scope.key, f.scope.canonical, f.original)
				mysqlMust(t, e)
				var body struct {
					Wrote bool `json:"wrote"`
				}
				mysqlMust(t, json.Unmarshal(nochange.bytes(), &body))
				if body.Wrote {
					t.Fatal("same-byte service changed config")
				}
				f.assert(t, ctx, 2, 4, true)
				if a.reserveCalls.Load() != 2 {
					t.Fatal("replay/observation reserved write capacity")
				}
			case "service_audit_failure_rollback", "service_receipt_failure_rollback":
				phase := "receipt"
				if name == "service_audit_failure_rollback" {
					phase = "result"
				}
				trigger := backfillMySQLTrigger(t, ctx, f, phase)
				r, err := svc.apply(ctx, f.scope.key, f.scope.canonical, f.original)
				backfillMySQLEmpty(t, r, err)
				if !errors.Is(err, ErrProviderEvidenceStorage) || a.reserveCalls.Load() != 1 {
					t.Fatal("intended service insertion failure not reached")
				}
				f.assert(t, ctx, 0, 0, false)
				_, err = db.ExecContext(ctx, "DROP TRIGGER "+trigger)
				mysqlMust(t, err)
				_, err = svc.apply(ctx, f.scope.key, f.scope.canonical, f.original)
				mysqlMust(t, err)
				f.assert(t, ctx, 1, 2, true)
			case "service_final_revoke_rollback":
				var reached atomic.Bool
				a.onFinal = func(call context.Context, tx *sql.Tx) error {
					if err := backfillMySQLUncommitted(call, tx, f.installation); err != nil {
						return err
					}
					reached.Store(true)
					return ErrRegistrationPermission
				}
				r, err := svc.apply(ctx, f.scope.key, f.scope.canonical, f.original)
				backfillMySQLEmpty(t, r, err)
				if !errors.Is(err, ErrRegistrationPermission) || !reached.Load() {
					t.Fatal("final revocation did not follow actual staged effects")
				}
				f.assert(t, ctx, 0, 0, false)
			case "service_capacity_expiry_after_callback":
				a.capacityTTL = 2 * time.Second
				var reached atomic.Bool
				a.onCapacity = func(call context.Context, tx *sql.Tx) error {
					if err := backfillMySQLUncommitted(call, tx, f.installation); err != nil {
						return err
					}
					reached.Store(true)
					var result int
					return tx.QueryRowContext(call, "SELECT SLEEP(2.05)").Scan(&result)
				}
				r, err := svc.apply(ctx, f.scope.key, f.scope.canonical, f.original)
				backfillMySQLEmpty(t, r, err)
				if !errors.Is(err, ErrRegistrationUnavailable) || !reached.Load() {
					t.Fatal("expiry did not cross actual capacity callback")
				}
				f.assert(t, ctx, 0, 0, false)
			case "service_lost_commit_observe_only":
				connector, err := mysql.NewConnector(cfg)
				mysqlMust(t, err)
				lost := &configProofLostCommitConnector{base: connector}
				faultDB := sql.OpenDB(lost)
				defer faultDB.Close()
				fault := backfillMySQLService(t, f, faultDB, a)
				r, e := fault.apply(ctx, f.scope.key, f.scope.canonical, f.original)
				backfillMySQLEmpty(t, r, e)
				if !errors.Is(e, errConfigMaintenanceCommitUnknown) || !lost.lost.Load() {
					t.Fatal("service did not withhold ambiguous commit")
				}
				f.assert(t, ctx, 1, 2, true)
				a.denyWrite.Store(true)
				observed, e := svc.observe(ctx, f.scope.key, f.scope.canonical, f.original)
				mysqlMust(t, e)
				var original []byte
				mysqlMust(t, db.QueryRowContext(ctx, "SELECT redacted_response_canonical_json FROM system_backup_v2_config_maintenance_receipts WHERE origin_installation_id=?", f.installation).Scan(&original))
				if !observed.replayed || !bytes.Equal(observed.bytes(), original) || a.writeCalls.Load() != 1 || a.reserveCalls.Load() != 1 {
					t.Fatal("independent service observation retried mutation")
				}
				f.assert(t, ctx, 1, 2, true)
			case "service_observed_lock_single_apply":
				blocker, err := db.BeginTx(ctx, nil)
				mysqlMust(t, err)
				defer blocker.Rollback()
				_, err = f.read(ctx, blocker)
				mysqlMust(t, err)
				workers := []backfillMySQLWorker{}
				for i := 0; i < 2; i++ {
					w := startBackfillMySQLWorker(t, ctx, f, a, cfg)
					workers = append(workers, w)
					(sessionMySQLProbe{db: db, identity: identity}).waiting(t, ctx, sessionProbeWorker{id: w.id, result: w.errors}, "system_backup_v2_configs")
				}
				mysqlMust(t, blocker.Rollback())
				var original []byte
				replays := 0
				for _, w := range workers {
					mysqlMust(t, sessionWorkerResult(t, ctx, sessionProbeWorker{result: w.errors}))
					r := <-w.results
					if r.replayed {
						replays++
					}
					if original == nil {
						original = r.bytes()
					} else if !bytes.Equal(original, r.bytes()) {
						t.Fatal("concurrent service changed original response")
					}
				}
				if replays != 1 || a.reserveCalls.Load() != 1 {
					t.Fatal("concurrent service did not perform exactly one mutation")
				}
				f.assert(t, ctx, 1, 2, true)
			}
		}) {
			return
		}
	}
	t.Log("PASS actual private canonical backfill service MySQL: apply/replay/nochange, separate observation, audit/receipt/final rollback, callback expiry, lost commit withholding and observed two-worker once; synthetic_authority=yes synthetic_capacity=yes production_approval=no")
}
