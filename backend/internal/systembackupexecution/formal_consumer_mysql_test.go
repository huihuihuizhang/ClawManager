package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
	api "clawreef/internal/systembackupdeployment"
	d "clawreef/internal/systembackupdispatch"
	security "clawreef/internal/systembackupsecurity"
	w "clawreef/internal/systembackupwire"
	"github.com/go-sql-driver/mysql"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

type consumerFrozenProfile struct{ x b.Discovery }

func (p consumerFrozenProfile) Discover(context.Context, d.Input) (b.Discovery, error) {
	return p.x, nil
}
func (p consumerFrozenProfile) BindWriters(context.Context, d.Input, b.Discovery) ([]flow.Writer, error) {
	return nil, nil
}
func (p consumerFrozenProfile) CheckSource(context.Context, d.Input, b.Discovery) error { return nil }

type consumerCurrentKeyUse struct {
	*scopedKeyUseFixture
	gate      c.SQLCaptureGate
	authority d.Authority
	after     func()
}

func (u *consumerCurrentKeyUse) Recheck(ctx context.Context, scope FormalCandidateReadScope) error {
	if err := u.scopedKeyUseFixture.Recheck(ctx, scope); err != nil {
		return err
	}
	return u.gate.Check(ctx, u.authority)
}
func (u *consumerCurrentKeyUse) Unwrap(ctx context.Context, r w.KeyRequest, wrapped w.WrappedKey, use w.WithDEK) error {
	err := u.scopedKeyUseFixture.Unwrap(ctx, r, wrapped, use)
	if err == nil && u.after != nil {
		u.after()
	}
	return err
}

// Local fixture uses a dedicated table-scoped SQL account, the ACTUAL pinned
// record identity and production deploymentAuthorization wrapper. Kubernetes
// metadata and independent KMS unwrap are local fixtures; no production claim.
func TestFormalCandidateMySQLActualEvidenceConsumer(t *testing.T) {
	if os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS") == "" {
		t.Skip("requires disposable local MySQL")
	}
	for _, fault := range []string{"", "wrong-attempt", "newer-attempt", "job-revoked", "wrapper-revoked", "claim-changed-during-unwrap", "expired-during-unwrap", "ciphertext", "envelope"} {
		t.Run(fault, func(t *testing.T) {
			owner, service, admin, db, a, j, candidate, keys, refresh := newConsumerMySQLFixture(t)
			if _, ok := owner.Gate.Authority.Authorization.(deploymentAuthorization); !ok {
				t.Fatal("production wrapper was bypassed")
			}
			if owner.Gate.Records.Keys != service.Forward {
				t.Fatal("record encryption identity replaced by verifier grant")
			}
			stage, err := owner.Staging.OpenRoot(a.TaskPublicID)
			if err != nil {
				t.Fatal(err)
			}
			defer stage.Close()
			if fault == "newer-attempt" {
				if _, err = admin.Exec("INSERT INTO system_backup_v2_attempts VALUES('backup',?,?,'capture','running',1)", a.TaskPublicID, a.AttemptNo+1); err != nil {
					t.Fatal(err)
				}
			}
			if fault == "job-revoked" {
				if _, err = admin.Exec("UPDATE system_backup_v2_runtime_resources SET revoked=TRUE WHERE observed_uid=?", j.UID); err != nil {
					t.Fatal(err)
				}
			}
			if fault == "wrapper-revoked" {
				if _, err = admin.Exec("UPDATE system_backup_v2_installation_state SET last_effective_enabled=FALSE"); err != nil {
					t.Fatal(err)
				}
			}
			if fault == "claim-changed-during-unwrap" {
				keys.after = func() {
					if _, err := admin.Exec("UPDATE system_backup_v2_backups SET row_version=row_version+1 WHERE public_id=?", a.TaskPublicID); err != nil {
						t.Error(err)
					}
				}
			}
			if fault == "expired-during-unwrap" {
				keys.until = time.Now().Add(300 * time.Millisecond)
				keys.after = func() { <-time.After(time.Until(keys.until) + time.Millisecond) }
			}
			if fault == "ciphertext" || fault == "envelope" {
				receipt := candidate.Ciphertext
				if fault == "envelope" {
					receipt = candidate.Envelope
				}
				if err = stage.Chmod(receipt.Name, 0600); err != nil {
					t.Fatal(err)
				}
				if err = stage.WriteFile(receipt.Name, []byte("changed original candidate"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			refresh()
			if fault == "wrong-attempt" {
				a.AttemptNo++
			}
			ref, err := owner.Evidence(context.Background(), a, j)
			if fault != "" {
				if err == nil || ref != nil {
					t.Fatal("invalid original SQL consumer produced evidence", fault, err)
				}
				var count int
				if db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE result_sha256 IS NOT NULL").Scan(&count) != nil || count != 0 {
					t.Fatal("failed consumer committed ModuleResult")
				}
				if db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_evidence").Scan(&count) != nil || count != 0 {
					t.Fatal("failed consumer registered evidence")
				}
				return
			}
			if err != nil || ref == nil {
				t.Fatal("actual original SQL Evidence consumer failed", err)
			}
			// Simulate losing the successful transaction ACK: repeat the original
			// Evidence call, preserving result/evidence bytes and a single unwrap.
			again, err := owner.Evidence(context.Background(), a, j)
			if err != nil || again == nil || *again != *ref || keys.inner.calls != 1 {
				t.Fatal("unknown ACK regenerated result/key", err, keys.inner.calls)
			}
			var retries sync.WaitGroup
			for range 2 {
				retries.Go(func() {
					x, e := owner.Evidence(context.Background(), a, j)
					if e != nil || x == nil || *x != *ref {
						t.Error("concurrent original ACK replay changed evidence", e)
					}
				})
			}
			retries.Wait()
			if _, err = db.Exec("UPDATE system_backup_v2_evidence SET observed_health='healthy' WHERE public_id=?", ref.PublicID); err == nil {
				t.Fatal("consumer unexpectedly has evidence UPDATE privilege")
			}
			if _, err = db.Exec("DELETE FROM system_backup_v2_evidence WHERE public_id=?", ref.PublicID); err == nil {
				t.Fatal("consumer unexpectedly has evidence DELETE privilege")
			}
			for _, receipt := range []staging.Receipt{candidate.Ciphertext, candidate.Envelope} {
				if err = stage.Remove(receipt.Name); err != nil {
					t.Fatal(err)
				}
			}
			raw, err := owner.ReadResult(context.Background(), a, j, *ref)
			if err != nil {
				t.Fatal("original SQL ReadResult failed without worker files", err)
			}
			var result d.ModuleResult
			if json.Unmarshal(raw, &result) != nil || result.Status != "completed" || result.Part != "workspace" || result.Statistics["sealed_bytes"] != uint64(candidate.Ciphertext.Size) {
				t.Fatal("wrong original ModuleResult")
			}
			var count int
			if db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_evidence").Scan(&count) != nil || count != 1 {
				t.Fatal("duplicate evidence after retry")
			}
			var sealed []byte
			var digest string
			if db.QueryRow("SELECT result_cipher,result_sha256 FROM system_backup_v2_runtime_resources WHERE observed_uid=?", j.UID).Scan(&sealed, &digest) != nil {
				t.Fatal("result custody unavailable")
			}
			_, key, err := service.Forward.Resolve(context.Background(), a, "")
			if err != nil {
				t.Fatal(err)
			}
			defer clear(key)
			var plain bytes.Buffer
			if staging.Open(context.Background(), bytes.NewReader(sealed), &plain, key, workerResultBinding(a, j, digest), 1<<20) != nil || !bytes.Equal(plain.Bytes(), raw) {
				t.Fatal("result ciphertext did not bind actual attempt")
			}
			changed := a
			changed.AttemptNo++
			if staging.Open(context.Background(), bytes.NewReader(sealed), io.Discard, key, workerResultBinding(changed, j, digest), 1<<20) == nil {
				t.Fatal("result ciphertext admitted another attempt")
			}
		})
	}
}

// This narrower real SQL test exercises the two simultaneous saveResult
// transactions directly. The end-to-end test above separately authenticates
// actual candidate/plan contents before this persistence boundary.
func TestFormalCandidateMySQLConcurrentResultPublication(t *testing.T) {
	if os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS") == "" {
		t.Skip("requires disposable local MySQL")
	}
	owner, _, _, db, a, j, _, _, refresh := newConsumerMySQLFixture(t)
	// Authenticate the real original candidate and build exactly the same
	// plan-validated ModuleResult as the consumer, before racing persistence.
	record, err := owner.ReadFormalCandidate(context.Background(), a, j, false)
	if err != nil {
		t.Fatal(err)
	}
	in, plan, desc, err := owner.input(context.Background(), a, false)
	if err != nil {
		t.Fatal(err)
	}
	part, err := partFor(desc, j.JobUnitKey)
	var invocation worker.Invocation
	if err != nil || json.Unmarshal(part.InvocationJSON, &invocation) != nil {
		t.Fatal("original invocation unavailable", err)
	}
	keys, err := openFormalCandidateKeys(context.Background(), owner.FormalKeys, FormalCandidateReadScope{Authority: a, Job: j, Invocation: invocation, Candidate: record.Candidate, CapturePod: record.Pod, CaptureGrantSHA256: record.ExecutionGrantSHA256})
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Close()
	custody, err := staging.OpenSealCustody(owner.Staging)
	if err != nil {
		t.Fatal(err)
	}
	defer custody.Close()
	source, err := owner.Staging.OpenRoot(a.TaskPublicID)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	observed, err := observeOriginalFormalCandidate(context.Background(), source, custody, staging.CustodyPolicy{Installation: a.InstallationID, MaxBytes: owner.SealCustodyMaxBytes}, workerSealScope(a, j, invocation), invocation, record.Candidate, keys)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := d.UnwrapTaskPlan(in, plan, b.PlanVersion)
	if err != nil {
		t.Fatal(err)
	}
	result, err := b.BuildFormalPartResult(in, inner, j.JobUnitKey, j, record.Candidate, b.SealedPart{Reference: observed.Reference(), ContentSHA256: observed.Ciphertext().SHA256, EvidenceIDs: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(result)
	if err != nil || b.ValidatePartResult(in, inner, j, raw) != nil {
		t.Fatal("original result failed frozen plan validation", err)
	}
	var before int64
	if err := db.QueryRow("SELECT reserved_bytes FROM system_backup_v2_metadata_reservations WHERE id=1").Scan(&before); err != nil {
		t.Fatal(err)
	}
	refresh()
	start := make(chan struct{})
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			errs <- owner.saveResult(context.Background(), a, j, raw)
		}()
	}
	close(start)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal("concurrent original result persistence failed", err)
		}
	}
	var sealed []byte
	var after int64
	var count int
	if db.QueryRow("SELECT result_cipher FROM system_backup_v2_runtime_resources WHERE observed_uid=?", j.UID).Scan(&sealed) != nil || db.QueryRow("SELECT reserved_bytes FROM system_backup_v2_metadata_reservations WHERE id=1").Scan(&after) != nil || db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_evidence").Scan(&count) != nil || count != 1 || after-before != int64(len(raw))+65536 {
		t.Fatal("concurrent publication duplicated original evidence/capacity")
	}
	if err := owner.saveResult(context.Background(), a, j, raw); err != nil {
		t.Fatal("lost commit ACK replay failed", err)
	}
	var replay []byte
	var reserved int64
	if db.QueryRow("SELECT result_cipher FROM system_backup_v2_runtime_resources WHERE observed_uid=?", j.UID).Scan(&replay) != nil || !bytes.Equal(replay, sealed) || db.QueryRow("SELECT reserved_bytes FROM system_backup_v2_metadata_reservations WHERE id=1").Scan(&reserved) != nil || reserved != after {
		t.Fatal("ACK replay replaced ciphertext or reserved capacity again")
	}
}

// The surrounding control tables are a focused current-column fixture. The
// resource/capture/key-use/candidate DDL is executed byte-for-byte from repo
// migrations above; this is not a full installation upgrade certification.
func consumerDDL() []string {
	return []string{
		`CREATE TABLE system_backup_v2_backups(public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,schema_version VARCHAR(64) NOT NULL,task_type VARCHAR(32) NOT NULL,request_id VARCHAR(128) NOT NULL,status VARCHAR(32) NOT NULL,controller_owner VARCHAR(128) NOT NULL,row_version BIGINT UNSIGNED NOT NULL,controller_lease_expires_at DATETIME(6) NOT NULL,deadline_at DATETIME(6) NOT NULL,config_version BIGINT UNSIGNED NOT NULL,config_snapshot_json MEDIUMBLOB NOT NULL,config_snapshot_size_bytes BIGINT UNSIGNED NOT NULL,config_snapshot_sha256 CHAR(64) NOT NULL,maintenance_lock_owner VARCHAR(128),maintenance_fencing_token BIGINT UNSIGNED,source_orchestrator VARCHAR(32),source_profile VARCHAR(32),matrix_key VARCHAR(64),datasource_topology VARCHAR(32),runner VARCHAR(32),task_purpose VARCHAR(32),requested_parts VARCHAR(128),UNIQUE KEY(origin_installation_id,public_id)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_attempts(target_type ENUM('backup') NOT NULL,target_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,attempt_no INT UNSIGNED NOT NULL,phase ENUM('capture') NOT NULL,status VARCHAR(32) NOT NULL,row_version BIGINT UNSIGNED NOT NULL,PRIMARY KEY(target_type,target_public_id,attempt_no,phase)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_configs(origin_installation_id VARCHAR(128) NOT NULL,version BIGINT UNSIGNED NOT NULL,schema_version VARCHAR(64) NOT NULL,enabled BOOLEAN NOT NULL,canonical_config_json MEDIUMBLOB NOT NULL,config_sha256 CHAR(64) NOT NULL,config_size_bytes BIGINT UNSIGNED NOT NULL,control_metadata_capacity_bytes BIGINT NOT NULL,evidence_retention_seconds BIGINT NOT NULL,PRIMARY KEY(origin_installation_id,version)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_installation_state(origin_installation_id VARCHAR(128) PRIMARY KEY,schema_version VARCHAR(64) NOT NULL,row_version BIGINT UNSIGNED NOT NULL,active_config_version BIGINT UNSIGNED NOT NULL,last_effective_enabled BOOLEAN NOT NULL) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_maintenance_locks(origin_installation_id VARCHAR(128),scope VARCHAR(128),lock_name VARCHAR(128),gate_state VARCHAR(32),lock_owner VARCHAR(128),fencing_token BIGINT UNSIGNED,row_version BIGINT UNSIGNED,lease_expires_at DATETIME(6),absolute_hold_deadline_at DATETIME(6),PRIMARY KEY(origin_installation_id,scope,lock_name)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_engine_bindings(scope VARCHAR(128) PRIMARY KEY,engine VARCHAR(32)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_gate(scope VARCHAR(128) PRIMARY KEY,phase VARCHAR(32),owner VARCHAR(128),fencing_token BIGINT UNSIGNED,generation BIGINT UNSIGNED) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_execution_inputs(origin_installation_id VARCHAR(128),task_public_id CHAR(40),task_type VARCHAR(32),profile_json MEDIUMBLOB,profile_sha256 CHAR(64),PRIMARY KEY(origin_installation_id,task_public_id,task_type)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_execution_records(origin_installation_id VARCHAR(128),task_public_id CHAR(40),attempt_no INT UNSIGNED,phase VARCHAR(32),record_kind VARCHAR(32),payload_sha256 CHAR(64),key_ref VARCHAR(256),sealed_payload MEDIUMBLOB,PRIMARY KEY(origin_installation_id,task_public_id,attempt_no,phase,record_kind)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_operations(origin_installation_id VARCHAR(128),target_type VARCHAR(32),target_public_id CHAR(40),operation_type VARCHAR(32),status VARCHAR(32)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_evidence(public_id VARCHAR(128) PRIMARY KEY,schema_version VARCHAR(64) DEFAULT 'system-backup-evidence.v1',owner_target_type VARCHAR(32),owner_target_public_id CHAR(40),evidence_type VARCHAR(32),storage_state VARCHAR(32),inline_payload MEDIUMBLOB,content_checksum CHAR(64),content_size_bytes BIGINT,media_type VARCHAR(64),encryption VARCHAR(32),redaction_classification VARCHAR(32),evidence_failure_code VARCHAR(32) DEFAULT 'none',observed_health VARCHAR(32),expires_at DATETIME(6),protected_until DATETIME(6),created_at DATETIME(6)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_job_observations(origin_installation_id VARCHAR(128),target_type VARCHAR(32),target_public_id CHAR(40),attempt_no BIGINT UNSIGNED,phase VARCHAR(32),job_unit_key VARCHAR(64),job_uid VARCHAR(256),job_generation BIGINT UNSIGNED,relay_identity_ref VARCHAR(256),relay_identity_version VARCHAR(128),relay_identity_bound_at DATETIME(6),relay_identity_expires_at DATETIME(6),last_accepted_sequence BIGINT UNSIGNED,last_accepted_body_sha256 CHAR(64),last_observed_status VARCHAR(32),last_observed_at DATETIME(6),progress_sequence BIGINT UNSIGNED,progress_digest_sha256 CHAR(64),last_business_progress_at DATETIME(6),created_at DATETIME(6),row_version BIGINT UNSIGNED DEFAULT 1,PRIMARY KEY(origin_installation_id,target_type,target_public_id,attempt_no,phase,job_unit_key)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_metadata_reservations(id BIGINT PRIMARY KEY,sample_at DATETIME(6) NOT NULL,reserved_bytes BIGINT NOT NULL) ENGINE=InnoDB`,
	}
}

func seedConsumerRows(t *testing.T, db *sql.DB, a d.Authority, config, profile []byte, now time.Time, j d.JobBinding) {
	t.Helper()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal("original SQL consumer fixture seed failed", err)
		}
	}
	exec(`INSERT INTO system_backup_v2_backups(public_id,origin_installation_id,schema_version,task_type,request_id,status,controller_owner,row_version,controller_lease_expires_at,deadline_at,config_version,config_snapshot_json,config_snapshot_size_bytes,config_snapshot_sha256,maintenance_lock_owner,maintenance_fencing_token,source_orchestrator,source_profile,matrix_key,datasource_topology,runner,task_purpose,requested_parts) VALUES(?,?,'system-backup-task.v1','backup',?,'capturing',?,?,?, ?,1,?,?,?, ?,?,'kubernetes','cluster','k8s-cluster','in_cluster','k8s','functional_test','workspace')`, a.TaskPublicID, a.InstallationID, a.RequestID, a.ClaimOwner, a.ClaimRowVersion, a.DeadlineAt, a.DeadlineAt, config, len(config), a.ConfigSHA256, a.MaintenanceOwner, a.MaintenanceFencingToken)
	exec(`INSERT INTO system_backup_v2_attempts VALUES('backup',?,?,'capture','running',1)`, a.TaskPublicID, a.AttemptNo)
	exec(`INSERT INTO system_backup_v2_configs VALUES(?,1,'system-backup-config.v1',TRUE,?,?,?,1073741824,86400)`, a.InstallationID, config, a.ConfigSHA256, len(config))
	exec(`INSERT INTO system_backup_v2_installation_state VALUES(?,'system-backup-installation-state.v1',1,1,TRUE)`, a.InstallationID)
	exec(`INSERT INTO system_backup_v2_maintenance_locks VALUES(?,?,'system_backup_capture_gate','held',?,?,1,?,?)`, a.InstallationID, c.CaptureGateScope, a.MaintenanceOwner, a.MaintenanceFencingToken, a.DeadlineAt, a.DeadlineAt)
	exec(`INSERT INTO system_backup_v2_engine_bindings VALUES('installation','v2')`)
	exec(`INSERT INTO system_backup_gate(scope,phase,owner,fencing_token,generation) VALUES('original-app','held',?,10,?)`, a.TaskPublicID, a.MaintenanceFencingToken)
	exec(`INSERT INTO system_backup_v2_execution_inputs VALUES(?,?,'backup',?,?)`, a.InstallationID, a.TaskPublicID, profile, hash(profile))
	exec(`INSERT INTO system_backup_v2_runtime_captures(task_public_id,application_scope,gate_generation,acquire_token,held_token,registry_sha256,writers_json,acquire_until,hold_until) VALUES(?,'original-app',?,9,10,?,'[]',?,?)`, a.TaskPublicID, a.MaintenanceFencingToken, strings.Repeat("a", 64), a.DeadlineAt, a.DeadlineAt)
}

func newConsumerMySQLFixture(t *testing.T, configure ...func(*worker.Invocation)) (*PublicJobOwner, *DeploymentService, *sql.DB, *sql.DB, d.Authority, d.JobBinding, worker.FormalCaptureResult, *consumerCurrentKeyUse, func()) {
	return newConsumerMySQLFixtureOptions(t, &consumerFixtureOptions{}, configure...)
}

type consumerFixtureOptions struct {
	PartName, Category                    string
	RequestedParts                        []string
	ConfigureWorkload                     func(*kube.JobRequest)
	OwnedCredentialsFile, OwnedServerUUID string
	DeploymentCore                        func(c.ExecutionGrant, ed25519.PublicKey, string) DeploymentConfig
	JobDeadlineSeconds                    int64
	ConfigureGrant                        func(*c.ExecutionGrant)
	PrepareSource                         func(*os.Root, *worker.Invocation)
	RewriteCandidate                      func(*os.Root, worker.Invocation, worker.FormalCaptureResult, *candidateContentUnwrapper) (*os.Root, worker.FormalCaptureResult)

	FormalMaterials *kube.FormalJobMaterials
	Configure       func(*worker.Invocation, *sql.DB, *sql.DB, d.Authority)
}

func newConsumerMySQLFixtureOptions(t *testing.T, options *consumerFixtureOptions, configure ...func(*worker.Invocation)) (*PublicJobOwner, *DeploymentService, *sql.DB, *sql.DB, d.Authority, d.JobBinding, worker.FormalCaptureResult, *consumerCurrentKeyUse, func()) {
	t.Helper()
	ctx := context.Background()
	var cred struct {
		Host           string
		Port           int
		User, Password string
	}
	credentialsFile := os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS")
	if options.OwnedCredentialsFile != "" {
		credentialsFile = options.OwnedCredentialsFile
		if options.OwnedServerUUID == "" {
			t.Fatal("owned fixture requires independent server UUID")
		}
	}
	raw, err := os.ReadFile(credentialsFile)
	if err != nil || json.Unmarshal(raw, &cred) != nil || cred.Host != "127.0.0.1" {
		t.Fatal("local consumer fixture credentials unavailable")
	}
	clear(raw)
	cfg := mysql.NewConfig()
	cfg.Net = "tcp"
	cfg.Addr = cred.Host + ":" + fmtPort(cred.Port)
	cfg.User = cred.User
	cfg.Passwd = cred.Password
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.Params = map[string]string{"time_zone": "'+00:00'"}
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 10 * time.Second
	root, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal("local MySQL open failed")
	}
	t.Cleanup(func() { root.Close() })
	if options.OwnedCredentialsFile != "" {
		var server string
		if root.QueryRow("SELECT @@server_uuid").Scan(&server) != nil || server != options.OwnedServerUUID {
			t.Fatal("owned fixture server UUID mismatch")
		}
	}
	var nonce [8]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	run := hex.EncodeToString(nonce[:])
	database, user := "ad_d_consumer_"+run, "ad_d_read_"+run
	if options.OwnedCredentialsFile != "" {
		database, user = "ad_a_publisher_"+run, "ad_a_pub_"+run
	}
	if _, err = root.Exec("CREATE DATABASE `" + database + "`"); err != nil {
		t.Fatal("local schema creation failed")
	}
	cfg.DBName = database
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal("local schema open failed")
	}
	t.Cleanup(func() { admin.Close() })
	createdUser := false
	t.Cleanup(func() {
		if options.OwnedCredentialsFile != "" {
			var server, marker string
			if root.QueryRow("SELECT @@server_uuid").Scan(&server) != nil || server != options.OwnedServerUUID || admin.QueryRow("SELECT run_id FROM _ad_a_publisher_marker").Scan(&marker) != nil || marker != run {
				t.Error("owned publisher cleanup UUID/marker mismatch; retained")
				return
			}
		}
		if createdUser {
			if _, err := root.Exec("DROP USER '" + user + "'@'127.0.0.1'"); err != nil {
				t.Error("local consumer user cleanup failed")
			}
		}
		if _, err := root.Exec("DROP DATABASE `" + database + "`"); err != nil {
			t.Error("local consumer schema cleanup failed")
		}
	})
	if options.OwnedCredentialsFile != "" {
		if _, err = admin.Exec("CREATE TABLE _ad_a_publisher_marker(run_id VARCHAR(64) PRIMARY KEY)"); err != nil {
			t.Fatal(err)
		}
		if _, err = admin.Exec("INSERT INTO _ad_a_publisher_marker VALUES (?)", run); err != nil {
			t.Fatal(err)
		}
	}
	for _, ddl := range consumerDDL() {
		if _, err = admin.Exec(ddl); err != nil {
			t.Fatal("consumer schema DDL failed", err)
		}
	}
	base, err := os.ReadFile(filepath.Join("..", "db", "migrations", "123_backup_v2_runtime_execution_journal.sql"))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(string(base), "CREATE TABLE IF NOT EXISTS system_backup_v2_runtime_captures")
	resourceDDL := parts[0]
	capturesDDL := "CREATE TABLE IF NOT EXISTS system_backup_v2_runtime_captures" + strings.Split(parts[1], "CREATE TABLE IF NOT EXISTS system_backup_v2_runtime_writers")[0]
	for _, ddl := range []string{resourceDDL, capturesDDL} {
		if _, err = admin.Exec(ddl); err != nil {
			t.Fatal("actual runtime DDL failed", err)
		}
	}
	for _, name := range []string{"125_backup_v2_job_key_use.sql", "131_backup_v2_formal_job_candidates.sql"} {
		ddl, err := os.ReadFile(filepath.Join("..", "db", "migrations", name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = admin.Exec(string(ddl)); err != nil {
			t.Fatal("actual candidate migration failed", err)
		}
	}
	var pass [24]byte
	rand.Read(pass[:])
	password := hex.EncodeToString(pass[:])
	clear(pass[:])
	if _, err = root.Exec("CREATE USER '" + user + "'@'127.0.0.1' IDENTIFIED BY '" + password + "'"); err != nil {
		t.Fatal("local consumer account failed")
	}
	createdUser = true
	for table, verbs := range map[string]string{"backups": "SELECT,UPDATE", "attempts": "SELECT,UPDATE", "maintenance_locks": "SELECT,UPDATE", "installation_state": "SELECT,UPDATE", "configs": "SELECT", "execution_inputs": "SELECT", "execution_records": "SELECT,INSERT", "runtime_resources": "SELECT,UPDATE", "runtime_captures": "SELECT", "operations": "SELECT", "evidence": "SELECT,INSERT", "job_observations": "SELECT,INSERT,UPDATE", "metadata_reservations": "SELECT,INSERT,UPDATE"} {
		if _, err = root.Exec("GRANT " + verbs + " ON `" + database + "`.`system_backup_v2_" + table + "` TO '" + user + "'@'127.0.0.1'"); err != nil {
			t.Fatal("local table-scoped consumer grant failed")
		}
	}
	if _, err = root.Exec("GRANT SELECT ON `" + database + "`.`system_backup_gate` TO '" + user + "'@'127.0.0.1'"); err != nil {
		t.Fatal(err)
	}
	if _, err = root.Exec("GRANT SELECT ON `" + database + "`.`system_backup_v2_engine_bindings` TO '" + user + "'@'127.0.0.1'"); err != nil {
		t.Fatal(err)
	}
	cfg.User, cfg.Passwd = user, password
	password = ""
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal("local consumer connection failed")
	}
	db.SetMaxOpenConns(8)
	t.Cleanup(func() { db.Close() })
	var preparation []func(*os.Root, *worker.Invocation)
	if options.PrepareSource != nil {
		preparation = append(preparation, options.PrepareSource)
	}
	source, _, _, inv, candidate, contentKeys := formalObserverFixture(t, preparation...)
	a, j, _ := resultEvidenceFixture()
	a.ConfigVersion = 1
	if options.PartName != "" {
		j.JobUnitKey = options.PartName
	}
	a.ClaimOwner = "controller"
	a.ClaimRowVersion = 19
	a.RequestID = "request-original"
	a.MaintenanceOwner = a.TaskPublicID
	a.MaintenanceFencingToken = 7
	var now time.Time
	var server string
	if admin.QueryRow("SELECT UTC_TIMESTAMP(6),@@server_uuid").Scan(&now, &server) != nil {
		t.Fatal("local server identity unavailable")
	}
	a.DeadlineAt = now.UTC().Add(4 * time.Minute)
	inv.Request.Deadline = a.DeadlineAt
	for _, f := range configure {
		f(&inv)
	}
	config := []byte(`{"source":"original-fixture"}`)
	a.ConfigSHA256 = hash(config)
	if options.Configure != nil {
		options.Configure(&inv, db, admin, a)
	}
	if options.RewriteCandidate != nil {
		source, candidate = options.RewriteCandidate(source, inv, candidate, contentKeys)
	}
	invHash, _ := inv.Hash()
	candidate.InvocationSHA256 = invHash
	profileID := "original-linux"
	profile, _ := json.Marshal(map[string]string{"installation_id": a.InstallationID, "source_profile": profileID, "revision": "original-r1"})
	if options.DeploymentCore != nil {
		p := api.ExecutionProfile{InstallationID: a.InstallationID, Revision: "original-r1", Orchestrator: "kubernetes", Profile: "cluster", TargetClass: "dr-ready-external", TargetRisks: []string{}, FailureDomain: "local-test", RestoreTargetRef: "isolated-target", RestoreTargetHash: strings.Repeat("f", 64)}
		profile, _, err = p.CanonicalIdentity()
		if err != nil {
			t.Fatal(err)
		}
		profileID = p.Profile
	}
	dir := t.TempDir()
	key := make([]byte, 32)
	rand.Read(key)
	defer clear(key)
	if err = os.WriteFile(filepath.Join(dir, "record-v1"), key, 0600); err != nil {
		t.Fatal(err)
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	grant := c.ExecutionGrant{Version: "system-backup-execution-grant.v1", InstallationID: a.InstallationID, ControllerOwner: a.ClaimOwner, DatabaseAccount: user + "@127.0.0.1", ServerUUID: server, Database: database, ConfigVersion: 1, ConfigSHA256: a.ConfigSHA256, ProfileSHA256: hash(profile), NotBefore: now.Add(-time.Minute), ExpiresAt: a.DeadlineAt, Actions: []string{"capture"}, RecordKeys: []c.ExecutionRecordKey{{Ref: "record-v1", SHA256: hash(key)}}}
	if options.ConfigureGrant != nil {
		options.ConfigureGrant(&grant)
	}
	var fullCore *DeploymentConfig
	coreRaw := []byte(`{"fixture":"pinned-deployment"}`)
	if options.DeploymentCore != nil {
		configured := options.DeploymentCore(grant, pub, dir)
		if configured.Validate() != nil {
			t.Fatal("owned full deployment config")
		}
		fullCore = &configured
		coreRaw, _ = json.Marshal(configured)
		grant.DeploymentConfigSHA256 = hash(coreRaw)
		grant.Actions = []string{"prepare", "capture", "issue_worker"}
		grant.WorkerIssuerSHA256 = strings.Repeat("f", 64)
		if os.WriteFile(configured.ProfileFile, profile, 0600) != nil {
			t.Fatal("owned full profile")
		}
	}
	body, _ := json.Marshal(grant)
	envelope, _ := json.Marshal(map[string]string{"payload_base64": base64.StdEncoding.EncodeToString(body), "signature_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(private, body))})
	grantFile := filepath.Join(dir, "grant.json")
	os.WriteFile(grantFile, envelope, 0600)
	identity, err := c.NewPinnedExecutionIdentity(grantFile, hash(envelope), dir, pub)
	if err != nil {
		t.Fatal("fixture signed record identity failed", err)
	}
	pinnedConfig := filepath.Join(dir, "deployment.json")
	recoveryIdentity := identity
	if fullCore != nil {
		recovery := grant
		recovery.Actions = []string{"recover"}
		recovery.WorkerIssuerSHA256 = ""
		body, _ := json.Marshal(recovery)
		raw, _ := json.Marshal(map[string]string{"payload_base64": base64.StdEncoding.EncodeToString(body), "signature_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(private, body))})
		if os.WriteFile(fullCore.RecoveryGrant.Path, raw, 0600) != nil {
			t.Fatal("owned recovery identity")
		}
		recoveryIdentity, err = c.NewPinnedExecutionIdentity(fullCore.RecoveryGrant.Path, hash(raw), dir, pub)
		if err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(pinnedConfig, coreRaw, 0600)
	stagePath := t.TempDir()
	stage, err := os.OpenRoot(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stage.Close() })
	if err = stage.Mkdir(a.TaskPublicID, 0700); err != nil {
		t.Fatal(err)
	}
	taskStage, err := stage.OpenRoot(a.TaskPublicID)
	if err != nil {
		t.Fatal(err)
	}
	defer taskStage.Close()
	for _, receipt := range []staging.Receipt{candidate.Ciphertext, candidate.Envelope} {
		reader, err := staging.OpenFile(ctx, source, receipt)
		if err != nil {
			t.Fatal(err)
		}
		_, err = staging.WriteUnpublishedFile(ctx, taskStage, receipt.Name, func(dst io.Writer) error { _, err := io.Copy(dst, reader); return err })
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	serviceConfig := DeploymentConfig{InstallationID: a.InstallationID, ApplicationScope: "original-app", AcquireSeconds: 60, HoldSeconds: 240, CapacityFile: filepath.Join(dir, "capacity.json")}
	if fullCore != nil {
		serviceConfig = *fullCore
	}
	service := &DeploymentService{ForwardEnabled: true, Forward: identity, Recovery: recoveryIdentity, ConfigPath: pinnedConfig, ConfigDigest: hash(coreRaw), Config: serviceConfig}
	gate := service.captureGate(db)
	if _, ok := gate.Records.Authority.Authorization.(deploymentAuthorization); !ok {
		t.Fatal("record authority lost production wrapper")
	}
	client := kubefake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: j.Namespace, UID: types.UID("ns-original")}})
	owner := &PublicJobOwner{Gate: gate, Identity: identity, Client: client, Dynamic: fake.NewSimpleDynamicClient(runtime.NewScheme()), Namespace: j.Namespace, NamespaceUID: "ns-original", TrustDomain: "fixture.invalid", Security: kube.WorkerSecurity{ServiceAccountName: "capture", ServiceAccountUID: "capture-sa"}, Staging: stage, SealCustodyMaxBytes: 16 << 20, AllowKubeletStopWitness: true}
	refresh := func() {
		var current time.Time
		if admin.QueryRow("SELECT UTC_TIMESTAMP(6)").Scan(&current) != nil {
			t.Fatal("capacity clock failed")
		}
		report := security.CapacityReport{ServerUUID: server, Database: database, ObservedAt: current.UTC(), AvailableBytes: 4 << 30}
		raw, _ := json.Marshal(report)
		if err = os.WriteFile(service.Config.CapacityFile, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	seedConsumerRows(t, admin, a, config, profile, now, j)
	refresh()
	requestedParts := []string{"workspace"}
	if options.RequestedParts != nil {
		requestedParts = append([]string{}, options.RequestedParts...)
		if _, err := admin.Exec("UPDATE system_backup_v2_backups SET requested_parts=? WHERE public_id=?", strings.Join(requestedParts, ","), a.TaskPublicID); err != nil {
			t.Fatal(err)
		}
	}
	in := d.Input{Authority: a, ConfigSnapshot: config, ProfileID: profileID, ProfileRevision: "original-r1", Backup: &d.BackupSpec{SourceOrchestrator: "kubernetes", SourceProfile: "cluster", MatrixKey: "k8s-cluster", DatasourceTopology: "in_cluster", Runner: "k8s", TaskPurpose: "functional_test", RequestedParts: requestedParts}}
	jobDeadlineSeconds := int64(200)
	if options.JobDeadlineSeconds != 0 {
		jobDeadlineSeconds = options.JobDeadlineSeconds
	}
	partName, category := "workspace", "workspace"
	if options.PartName != "" {
		partName = options.PartName
	}
	if options.Category != "" {
		category = options.Category
	}
	workload := kube.JobRequest{Identity: kube.Identity{Namespace: j.Namespace, Name: j.Name, Owner: a.TaskPublicID}, Image: "fixture/worker@sha256:" + strings.Repeat("a", 64), ServiceAccount: "capture", Source: corev1.Volume{Name: "source", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "fixture-source"}}}, StagingClaim: "fixture-staging", DeadlineSeconds: jobDeadlineSeconds, FormalMaterials: options.FormalMaterials, WorkerControl: &kube.WorkerControl{URL: "https://control.fixture.invalid", InvocationConfigMap: "original-invocation", IdentitySecret: "original-identity", BoundPodIdentity: true}}
	if options.ConfigureWorkload != nil {
		options.ConfigureWorkload(&workload)
	}
	part, err := b.BuildCapturePart(in, a.DeadlineAt, b.CapturePartRequest{Part: partName, Category: category, JobUnitKey: j.JobUnitKey, Generation: j.Generation, Invocation: inv, Workload: workload})
	if err != nil {
		t.Fatal("original formal part assembly failed", err)
	}
	sourceInventory, _ := json.Marshal(b.SourceInventory{Database: "source", ServerUUID: "source-original", Users: []int{1}, Instances: []b.InstanceIdentity{}})
	discovery := b.Discovery{Source: sourceInventory, SourceSHA256: hash(sourceInventory), Parts: []b.JobPart{part}, Writers: []b.FrozenWriter{}, HoldUntil: a.DeadlineAt}
	runner, err := b.NewPublicRunner(b.Dependencies{Profiles: map[b.ProfileKey]b.Profile{{ID: in.ProfileID, Revision: in.ProfileRevision}: consumerFrozenProfile{discovery}}, Results: PublicResults{owner}, Recovery: owner, Admission: func(ctx context.Context, in d.Input) error { return gate.Check(ctx, in.Authority) }, ValidateInventory: func(_ context.Context, _ d.Input, x b.Discovery) error {
		if len(x.Parts) != 1 {
			return d.ErrNotReady
		}
		return nil
	}, RecoveryTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	bound, err := d.BindTaskRunner(runner, b.PlanVersion)
	if err != nil {
		t.Fatal(err)
	}
	ports, err := c.NewExecutionJobPorts(gate, owner)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := bound.Prepare(ctx, in, ports)
	if err != nil {
		t.Fatal("original public plan prepare failed", err)
	}
	if err = gate.Records.SavePlan(ctx, in, plan); err != nil {
		t.Fatal("original SQL plan save failed", err)
	}
	j.RelayBoundAt = now.UTC()
	j.RelayExpiresAt = a.DeadlineAt
	j.RelayIdentityRef = "original-relay"
	j.RelayIdentityVersion = "v1"
	var job batchv1.Job
	if json.Unmarshal(part.Intent.SpecJSON, &job) != nil {
		t.Fatal("original job manifest unavailable")
	}
	intent, err := kube.Intent("Job", &job)
	if err != nil {
		t.Fatal(err)
	}
	bindingRaw, _ := json.Marshal(j)
	if _, err = admin.Exec(`INSERT INTO system_backup_v2_runtime_resources(task_public_id,resource_kind,namespace_name,resource_name,resource_owner,request_sha256,request_json,row_version,create_dispatched,observed_uid,resource_version,lifecycle,attempt_no,phase,binding_json) VALUES(?,'Job',?,?,?,?,?,1,TRUE,?,'1','ready',?,'capture',?)`, a.TaskPublicID, j.Namespace, j.Name, a.TaskPublicID, intent.RequestSHA256, intent.RequestJSON, j.UID, a.AttemptNo, bindingRaw); err != nil {
		t.Fatal("original Job SQL insert failed", err)
	}
	record := FormalCandidateRecord{Version: "public-formal-candidate-record.v1", Authority: a, Job: j, Pod: BoundPod{Namespace: j.Namespace, Name: "capture-pod", UID: "capture-pod-uid", ServiceAccountUID: "capture-sa"}, InvocationSHA256: invHash, KeyUseNonce: strings.Repeat("e", 32), ExecutionGrantSHA256: identity.GrantSHA256(), Candidate: candidate}
	recordRaw, _ := json.Marshal(record)
	digest := hash(recordRaw)
	var sealed bytes.Buffer
	if err = staging.Seal(ctx, &sealed, key, formalCandidateBinding(a, j, digest), func(dst io.Writer) error { _, err := dst.Write(recordRaw); return err }); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = owner.saveFormalCandidateTx(ctx, tx, a, j, "record-v1", digest, sealed.Bytes()); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	keyUse := &consumerCurrentKeyUse{gate: gate, authority: a, scopedKeyUseFixture: &scopedKeyUseFixture{inner: contentKeys, until: a.DeadlineAt, identity: FormalVerifierIdentity{Namespace: "control", PodName: "controller-pod", PodUID: "controller-pod-uid", ServiceAccountName: "controller", ServiceAccountUID: "controller-sa", OwnerKind: "Deployment", OwnerUID: "controller-deployment-uid", GrantSHA256: strings.Repeat("f", 64)}}}
	owner.FormalKeys = func(ctx context.Context, s FormalCandidateReadScope) (FormalCandidateKeyUse, error) {
		raw, _ := json.Marshal(s)
		keyUse.original = raw
		return keyUse, nil
	}
	return owner, service, admin, db, a, j, candidate, keyUse, refresh
}
