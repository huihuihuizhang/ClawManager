//go:build systembackup_mysql

package systembackupevidence

// Separate actual-SQL scope for the global config/nonce L1 prefix. A trace or
// a delayed goroutine is not proof: every adversary must appear in InnoDB's
// data_lock_waits against the bootstrap connection's config index lock.
import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

const bootstrapRangeForeign = "installation_000_range_existing"
const bootstrapRangeNewOrigin = "installation_001_range_new"
const bootstrapRangeLowerAnchor = "installation_002_range_anchor"
const bootstrapRangeUpperAnchor = "installation_zzz_range_anchor"

func bootstrapRangeFixtureOrder(target string) bool {
	return bootstrapRangeForeign < bootstrapRangeNewOrigin && bootstrapRangeNewOrigin < bootstrapRangeLowerAnchor && bootstrapRangeLowerAnchor < target && target < bootstrapRangeUpperAnchor
}

// Only creates the unrelated existing-config fixture through the original A
// atomic disabled-bootstrap writer. This named synthetic authority does not
// authenticate a deployment or approve any resource/provider/physical report.
type bootstrapRangeSeedAdmission struct {
	grant  sec.OfflineBootstrapGrant
	config sec.BootstrapConfig
}

func (a bootstrapRangeSeedAdmission) Authorize(ctx context.Context, tx *sql.Tx, g sec.OfflineBootstrapGrant, c sec.BootstrapConfig, _ time.Time) error {
	if ctx.Err() != nil || tx == nil || g != a.grant || !bytes.Equal(c.CanonicalJSON(), a.config.CanonicalJSON()) {
		return sec.ErrRegistrationUnavailable
	}
	return nil
}
func (a bootstrapRangeSeedAdmission) ValidateAndReserve(ctx context.Context, tx *sql.Tx, g sec.OfflineBootstrapGrant, c sec.BootstrapConfig, now time.Time) error {
	return a.Authorize(ctx, tx, g, c, now)
}

func bootstrapRangeSeedBeforeC1(t *testing.T, db *sql.DB, c sec.BootstrapConfig) {
	t.Helper()
	var installed int
	mustSQL(t, db.QueryRow("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND LEFT(TABLE_NAME,23)='system_backup_producer_'").Scan(&installed))
	if installed != 0 {
		t.Fatal("legacy anchors must precede every C1 control table")
	}
	var server, database string
	mustSQL(t, db.QueryRow("SELECT @@server_uuid,DATABASE()").Scan(&server, &database))
	for _, origin := range []string{bootstrapRangeForeign, bootstrapRangeLowerAnchor, bootstrapRangeUpperAnchor} {
		g := sec.OfflineBootstrapGrant{InstallationID: origin, ServerUUID: server, Database: database, Username: "bootstrap-probe", UserID: 42, MatrixKey: "k8s-cluster", ConfigSHA256: c.SHA256(), IdempotencyKey: "range-existing-fixture-key-0001", ChangeReason: "synthetic isolated pre-C1 range anchors"}
		seed := sec.ConfigBootstrapService{DB: db, Admission: bootstrapRangeSeedAdmission{g, c}}
		if _, err := seed.Bootstrap(context.Background(), g, c.CanonicalJSON()); err != nil {
			t.Fatal("pre-C1 original foreign config writer", err)
		}
	}
	t.Log("CONFIG_RANGE_ANCHORS writer=original_legacy stage=before_C1_schema producer_tables_before=0 anchors=3")
}

type bootstrapRangeAuthority struct {
	sec.BootstrapCandidateAuthority
	entered chan uint64
	release <-chan struct{}
}
type bootstrapRangeSession struct {
	sec.BootstrapCandidateAuthoritySession
	entered chan uint64
	release <-chan struct{}
}

func (a bootstrapRangeAuthority) PrepareBootstrapCandidates(ctx context.Context, g sec.OfflineBootstrapGrant, c sec.BootstrapConfig, r pd.BootstrapConsumptionRequest) (sec.PreparedBootstrapCandidateAuthority, error) {
	p, err := a.BootstrapCandidateAuthority.PrepareBootstrapCandidates(ctx, g, c, r)
	if err != nil {
		return p, err
	}
	p.Session = &bootstrapRangeSession{p.Session, a.entered, a.release}
	return p, nil
}
func (a *bootstrapRangeSession) Authorize(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, d pd.DomainRecord, now time.Time) (pd.BootstrapConsumptionAdmission, error) {
	admission, err := a.BootstrapCandidateAuthoritySession.Authorize(ctx, tx, r, d, now)
	if err != nil {
		return admission, err
	}
	var connection uint64
	if err = tx.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&connection); err != nil {
		return admission, err
	}
	select {
	case a.entered <- connection:
	case <-ctx.Done():
		return pd.BootstrapConsumptionAdmission{}, pd.ErrGuardRequired
	}
	select {
	case <-a.release:
		return admission, nil
	case <-ctx.Done():
		return pd.BootstrapConsumptionAdmission{}, pd.ErrGuardRequired
	}
}

// Full canonical columns come from a real SELECT in the owned database. Skip
// only the generated auto ID. Preserve all other bytes, overriding only the
// adversarial new key; no handwritten abbreviated config schema is used.
func bootstrapRangeInsertSQL(columns []string) (string, error) {
	var names, values []string
	seen := map[string]bool{}
	for _, name := range columns {
		if !regexp.MustCompile(`^[a-z][a-z0-9_]*$`).MatchString(name) || seen[name] {
			return "", errors.New("invalid canonical column")
		}
		seen[name] = true
		if name == "id" {
			continue
		}
		names = append(names, "`"+name+"`")
		values = append(values, "?")
	}
	if !seen["id"] || !seen["origin_installation_id"] || !seen["version"] || !seen["nonce_hmac_identity_hash"] || !seen["nonce_hmac_ref_version"] {
		return "", errors.New("incomplete canonical config")
	}
	return "INSERT INTO system_backup_v2_configs (" + strings.Join(names, ",") + ") VALUES (" + strings.Join(values, ",") + ")", nil
}

func TestDBootstrapConsumerRangesMySQLSeed(t *testing.T) {
	if !bootstrapRangeFixtureOrder("installation_synthetic") || bootstrapRangeFixtureOrder(bootstrapRangeNewOrigin) {
		t.Fatal("range fixture must isolate the adversary gap from the target absence gap")
	}
	columns := []string{"id", "origin_installation_id", "version", "nonce_hmac_identity_hash", "nonce_hmac_ref_version", "enabled"}
	q, err := bootstrapRangeInsertSQL(columns)
	if err != nil || strings.Contains(q, "(`id`") || strings.Count(q, "?") != len(columns)-1 || strings.Contains(q, "SELECT") {
		t.Fatal("direct insert plan differs", q, err)
	}
	for _, bad := range [][]string{columns[:3], append(append([]string{}, columns...), "version"), append(append([]string{}, columns...), "x;DROP TABLE users")} {
		if _, err := bootstrapRangeInsertSQL(bad); err == nil {
			t.Fatal("unsafe/incomplete column plan accepted")
		}
	}
	t.Log("PASS bootstrap-config-ranges-seed separated_gaps=yes actual_mysql=not_run direct_writer_installation_lock=no lock_wait_graph_required=yes")
}

type bootstrapRangeWriteResult struct {
	rows int64
	err  error
}
type bootstrapRangeServiceResult struct {
	result sec.ConfigBootstrapResult
	err    error
}

// Observe an actual requesting/blocking connection pair and its specific config
// record/index lock. Fail if the direct write completes before a wait exists.
func bootstrapRangeWait(t *testing.T, db *sql.DB, requester, blocker uint64, mode string, done <-chan bootstrapRangeWriteResult) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case result := <-done:
			t.Fatalf("direct writer escaped config prefix before graph observation rows=%d err=%v", result.rows, result.err)
		default:
		}
		rows, err := db.QueryContext(ctx, `SELECT l.INDEX_NAME,l.LOCK_TYPE,l.LOCK_MODE
FROM performance_schema.data_lock_waits w
JOIN performance_schema.data_locks l ON l.ENGINE=w.ENGINE AND l.ENGINE_LOCK_ID=w.REQUESTING_ENGINE_LOCK_ID
JOIN performance_schema.threads r ON r.THREAD_ID=w.REQUESTING_THREAD_ID
JOIN performance_schema.threads b ON b.THREAD_ID=w.BLOCKING_THREAD_ID
WHERE r.PROCESSLIST_ID=? AND b.PROCESSLIST_ID=? AND l.OBJECT_SCHEMA=DATABASE() AND l.OBJECT_NAME='system_backup_v2_configs'`, requester, blocker)
		if err != nil {
			t.Fatal("actual lock graph unavailable", err)
		}
		var observed bool
		var index, kind, lockMode string
		for rows.Next() {
			mustSQL(t, rows.Scan(&index, &kind, &lockMode))
			if kind == "RECORD" && (index == "uk_sb_config_version" || mode == "existing_nonce_metadata" && index == "PRIMARY") && (mode == "existing_nonce_metadata" || strings.Contains(lockMode, "INSERT_INTENTION")) {
				observed = true
				break
			}
		}
		mustSQL(t, rows.Err())
		mustSQL(t, rows.Close())
		if observed {
			t.Logf("CONFIG_RANGE_WAIT case=%s index=%s lock_type=%s lock_mode=%s requester=%d blocker=%d direct_writer_installation_lock=no", mode, index, kind, lockMode, requester, blocker)
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("config index wait not observed before bounded deadline")
		case <-tick.C:
		}
	}
}

func TestDBootstrapConsumerRangesMySQL(t *testing.T) {
	for _, mode := range []string{"existing_nonce_metadata", "empty_new_origin", "existing_origin_new_version"} {
		t.Run(mode, func(t *testing.T) {
			_, a, _ := bootstrapMySQLFixture(t, func(db *sql.DB, c sec.BootstrapConfig) { bootstrapRangeSeedBeforeC1(t, db, c) })
			db := a.f.db
			if !bootstrapRangeFixtureOrder(a.g.InstallationID) {
				t.Fatal("fixture target is outside the separated index gaps")
			}
			// Three anchors put the direct insert BEFORE the lower anchor while
			// target-only absence locking covers the DISTINCT lower..upper gap.
			// Otherwise an old target-only lookup might coincidentally block the
			// same supremum gap and falsely look like a global range proof.
			var installed int
			mustSQL(t, db.QueryRow("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND LEFT(TABLE_NAME,23)='system_backup_producer_'").Scan(&installed))
			if installed != 8 {
				t.Fatal("complete original C1 schema must be installed after legacy anchors", installed)
			}
			t.Logf("CONFIG_RANGE_LAYOUT case=%s anchors=3 direct_gap=000..002 target_gap=002..zzz source_values=before_begin", mode)
			// Capture INSERT values BEFORE the guarded transaction begins. An
			// INSERT..SELECT would wait on its source row and falsely look like
			// an insertion-gap test. The direct writer below has no source read.
			template, err := db.Query("SELECT * FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=1", bootstrapRangeForeign)
			mustSQL(t, err)
			columns, err := template.Columns()
			mustSQL(t, err)
			values, dest := make([]any, len(columns)), make([]any, len(columns))
			for i := range dest {
				dest[i] = &values[i]
			}
			if !template.Next() {
				t.Fatal("missing full config template")
			}
			mustSQL(t, template.Scan(dest...))
			for i, value := range values {
				if b, ok := value.([]byte); ok {
					values[i] = append([]byte(nil), b...)
				}
			}
			if template.Next() {
				t.Fatal("duplicate config template")
			}
			mustSQL(t, template.Err())
			mustSQL(t, template.Close())
			var originalNonce string
			mustSQL(t, db.QueryRow("SELECT nonce_hmac_identity_hash FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=1", bootstrapRangeForeign).Scan(&originalNonce))
			before := dMySQLSnapshot(t, db)
			entered, release := make(chan uint64, 1), make(chan struct{})
			var releaseOnce sync.Once
			open := func() { releaseOnce.Do(func() { close(release) }) }
			plan, err := sec.NewConfigBootstrapCandidates(db, a.g, a.c.CanonicalJSON(), a.selection, bootstrapRangeAuthority{a, entered, release})
			mustSQL(t, err)
			svc := sec.ConfigBootstrapService{DB: db, Candidates: plan}
			bootstrapCtx, cancelBootstrap := context.WithCancel(context.Background())
			writerCtx, cancelWriter := context.WithTimeout(context.Background(), 8*time.Second)
			var workers sync.WaitGroup
			var writer *sql.Tx
			defer func() {
				cancelBootstrap()
				open()
				cancelWriter()
				if writer != nil {
					_ = writer.Rollback()
				}
				drained := make(chan struct{})
				go func() { workers.Wait(); close(drained) }()
				select {
				case <-drained:
				case <-time.After(3 * time.Second):
					t.Error("CLEANUP_PENDING config range workers")
				}
			}()
			serviceDone := make(chan bootstrapRangeServiceResult, 1)
			workers.Add(1)
			go func() {
				defer workers.Done()
				result, e := svc.Bootstrap(bootstrapCtx, a.g, a.c.CanonicalJSON())
				serviceDone <- bootstrapRangeServiceResult{result, e}
			}()
			var blocker uint64
			select {
			case blocker = <-entered:
			case e := <-serviceDone:
				t.Fatal("bootstrap did not reach locked authorization", e.err)
			case <-time.After(3 * time.Second):
				t.Fatal("bootstrap did not reach controlled prefix")
			}
			writer, err = db.BeginTx(writerCtx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			mustSQL(t, err)
			var requester uint64
			mustSQL(t, writer.QueryRowContext(writerCtx, "SELECT CONNECTION_ID()").Scan(&requester))
			q := "UPDATE system_backup_v2_configs SET nonce_hmac_identity_hash=? WHERE origin_installation_id=? AND version=1"
			expectedNonce := strings.Repeat("f", 64)
			if expectedNonce == originalNonce {
				expectedNonce = strings.Repeat("e", 64)
			}
			args := []any{expectedNonce, bootstrapRangeForeign}
			target, version := bootstrapRangeForeign, int64(1)
			if mode != "existing_nonce_metadata" {
				var e error
				q, e = bootstrapRangeInsertSQL(columns)
				mustSQL(t, e)
				if mode == "empty_new_origin" {
					target = bootstrapRangeNewOrigin
				} else {
					version = 2
				}
				args = nil
				for i, column := range columns {
					switch column {
					case "id":
						continue
					case "origin_installation_id":
						args = append(args, target)
					case "version":
						args = append(args, version)
					default:
						args = append(args, values[i])
					}
				}
			}
			writeDone := make(chan bootstrapRangeWriteResult, 1)
			workers.Add(1)
			go func() {
				defer workers.Done()
				out, e := writer.ExecContext(writerCtx, q, args...)
				var n int64
				if e == nil {
					n, e = out.RowsAffected()
				}
				if e == nil {
					e = writer.Commit()
				}
				writeDone <- bootstrapRangeWriteResult{n, e}
			}()
			bootstrapRangeWait(t, db, requester, blocker, mode, writeDone)
			cancelBootstrap()
			open()
			select {
			case out := <-serviceDone:
				if out.err == nil || out.result != (sec.ConfigBootstrapResult{}) {
					t.Fatal("canceled bootstrap exposed success", out.result, out.err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("bootstrap rollback not completed")
			}
			var written bootstrapRangeWriteResult
			select {
			case written = <-writeDone:
			case <-time.After(3 * time.Second):
				t.Fatal("direct write did not complete after rollback release")
			}
			mustSQL(t, written.err)
			if written.rows != 1 {
				t.Fatal("direct writer did not affect one row", written.rows)
			}
			var got string
			mustSQL(t, db.QueryRow("SELECT nonce_hmac_identity_hash FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=?", target, version).Scan(&got))
			if mode == "existing_nonce_metadata" && got != expectedNonce {
				t.Fatal("direct nonce mutation not persisted")
			}
			var targetConfigs, totalConfigs int
			mustSQL(t, db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_configs WHERE origin_installation_id=?", a.g.InstallationID).Scan(&targetConfigs))
			mustSQL(t, db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_configs").Scan(&totalConfigs))
			expectedTotal := 4
			if mode == "existing_nonce_metadata" {
				expectedTotal = 3
			}
			if targetConfigs != 0 || totalConfigs != expectedTotal {
				t.Fatal("canceled bootstrap/config insertion state differs", targetConfigs, totalConfigs)
			}
			// The only allowed committed change belongs to the direct writer.
			after := dMySQLSnapshot(t, db)
			delete(before, "system_backup_v2_configs")
			delete(after, "system_backup_v2_configs")
			if !reflect.DeepEqual(before, after) {
				t.Fatal("canceled bootstrap changed non-config state")
			}
			t.Logf("CONFIG_RANGE_RELEASE case=%s bootstrap_rolled_back=yes direct_writer_committed=yes rows=1", mode)
		})
	}
}
