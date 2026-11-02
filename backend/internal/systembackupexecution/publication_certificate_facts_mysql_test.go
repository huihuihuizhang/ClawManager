package systembackupexecution

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	appdb "clawreef/internal/db"
	security "clawreef/internal/systembackupsecurity"
	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
)

type publicationCertificateFactsFixture struct {
	admin, reader *sql.DB
	service       *DeploymentService
	installation  string
	config        []byte
}

// Full production 175 schema, but named historical DATA for the reader's SQL
// properties. These records are not an actual capture/verification/signing
// success and cannot pass prepareOriginalCaptureCertificate's complete C gate.
// No capture Authority, source grant or private artifact signer is constructed.
func newPublicationCertificateFactsFixture(t *testing.T) *publicationCertificateFactsFixture {
	t.Helper()
	file, expected := os.Getenv("A_SIGNING_MYSQL_CREDENTIALS_FILE"), os.Getenv("A_SIGNING_MYSQL_SERVER_UUID")
	if file == "" || expected == "" {
		t.Skip("requires owned UUID-pinned local MySQL")
	}
	var credential struct {
		Host, User, Password string
		Port                 int
	}
	raw, err := os.ReadFile(file)
	if err != nil || json.Unmarshal(raw, &credential) != nil || credential.Host != "127.0.0.1" {
		t.Fatal("owned local certificate SQL fixture unavailable")
	}
	clear(raw)
	config := mysql.NewConfig()
	config.Net, config.Addr = "tcp", credential.Host+":"+strconv.Itoa(credential.Port)
	config.User, config.Passwd, config.ParseTime, config.Loc = credential.User, credential.Password, true, time.UTC
	config.Params = map[string]string{"time_zone": "'+00:00'"}
	config.Timeout, config.ReadTimeout = 5*time.Second, 30*time.Second
	root, err := sql.Open("mysql", config.FormatDSN())
	if err != nil {
		t.Fatal("owned SQL connection unavailable")
	}
	t.Cleanup(func() { root.Close() })
	var server string
	if root.QueryRow(`SELECT @@server_uuid`).Scan(&server) != nil || server != expected {
		t.Fatal("owned certificate SQL server identity mismatch")
	}
	run := strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	database, user := "a_cert_facts_"+run, "a_cert_read_"+run
	if _, err = root.Exec("CREATE DATABASE `" + database + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"); err != nil {
		t.Fatal(err)
	}
	config.DBName = database
	admin, err := sql.Open("mysql", config.FormatDSN())
	if err != nil {
		t.Fatal("owned database unavailable")
	}
	t.Cleanup(func() { admin.Close() })
	if _, err = admin.Exec(`CREATE TABLE _a_certificate_facts_owner(nonce VARCHAR(64) PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if _, err = admin.Exec(`INSERT INTO _a_certificate_facts_owner VALUES(?)`, run); err != nil {
		t.Fatal(err)
	}
	createdUser := false
	t.Cleanup(func() {
		var actual, marker string
		if root.QueryRow(`SELECT @@server_uuid`).Scan(&actual) != nil || actual != expected || admin.QueryRow(`SELECT nonce FROM _a_certificate_facts_owner`).Scan(&marker) != nil || marker != run {
			t.Error("certificate SQL cleanup identity/owner mismatch; retained")
			return
		}
		if createdUser {
			if _, err := root.Exec("DROP USER '" + user + "'@'127.0.0.1'"); err != nil {
				t.Error(err)
			}
		}
		if _, err := root.Exec("DROP DATABASE `" + database + "`"); err != nil {
			t.Error(err)
		}
	})
	catalog, err := appdb.EmbeddedMigrationCatalog()
	if err != nil || len(catalog.Filenames) != 175 || catalog.Hash != "5bb2b0320880d4259826510f3cee10ce6ca2fbd817ec9a6f5f6c450c5b16d292" {
		t.Fatal("reviewed 175 migration catalog changed", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err = appdb.ApplyPinnedMigrations(ctx, admin, appdb.MigrationTarget{ServerUUID: expected, Database: database, CatalogSHA256: catalog.Hash}); err != nil {
		t.Fatal("actual complete migration runner", err)
	}
	var count, fk int
	if admin.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&count) != nil || count != 175 || admin.QueryRow(`SELECT @@foreign_key_checks`).Scan(&fk) != nil || fk != 1 {
		t.Fatal("complete original migration/FK evidence unavailable", count, fk)
	}
	password := uuid.NewString() + uuid.NewString()
	if _, err = root.Exec("CREATE USER '" + user + "'@'127.0.0.1' IDENTIFIED BY '" + password + "'"); err != nil {
		t.Fatal(err)
	}
	createdUser = true
	for _, table := range []string{"system_backup_v2_configs", "system_backup_v2_backups", "system_backup_v2_attempts", "system_backup_v2_staging_resources"} {
		if _, err = root.Exec("GRANT SELECT ON `" + database + "`.`" + table + "` TO '" + user + "'@'127.0.0.1'"); err != nil {
			t.Fatal(err)
		}
	}
	config.User, config.Passwd = user, password
	reader, err := sql.Open("mysql", config.FormatDSN())
	config.Passwd, password = "", ""
	if err != nil {
		t.Fatal("exact read-only certificate connection unavailable")
	}
	t.Cleanup(func() { reader.Close() })
	if _, err = reader.Exec(`UPDATE system_backup_v2_staging_resources SET row_version=row_version+1`); err == nil {
		t.Fatal("certificate fact reader has mutation privileges")
	}
	stage, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stage.Close() })
	f := &publicationCertificateFactsFixture{admin: admin, reader: reader, installation: "installation_certificate_" + run, service: &DeploymentService{PublisherOwner: "public:certificate-reader", Runtime: &PublicCapture{Owner: &PublicJobOwner{Staging: stage}}}}
	document, err := os.ReadFile("../../../contracts/system-backup/v12/admin-control-redacted-examples.json")
	if err != nil {
		t.Fatal(err)
	}
	var examples struct {
		Request struct {
			Config json.RawMessage `json:"config"`
		} `json:"config_update_request"`
	}
	var values struct {
		Enabled                          bool        `json:"enabled"`
		Alert                            string      `json:"alert_profile"`
		Minimum                          json.Number `json:"minimum_recovery_points"`
		Durations, Capacity, Concurrency map[string]json.Number
		Preflight                        map[string]json.Number `json:"preflight_limits"`
		Registries                       []security.BootstrapRegistryRef
		References                       []security.BootstrapSecretRef
	}
	if json.Unmarshal(document, &examples) != nil || json.Unmarshal(examples.Request.Config, &values) != nil {
		t.Fatal("complete named config DATA")
	}
	f.config = examples.Request.Config
	columns := []string{"origin_installation_id", "version", "config_sha256", "config_size_bytes", "enabled", "alert_profile", "minimum_recovery_points", "created_by"}
	arguments := []any{f.installation, 1, hash(f.config), len(f.config), values.Enabled, values.Alert, values.Minimum.String(), "system:controller"}
	for group, members := range map[string]map[string]json.Number{"durations": values.Durations, "capacity": values.Capacity, "concurrency": values.Concurrency, "preflight_limits": values.Preflight} {
		for name, value := range members {
			if group == "preflight_limits" {
				name = "preflight_" + name
			}
			columns, arguments = append(columns, name), append(arguments, value.String())
		}
	}
	for _, ref := range values.Registries {
		columns = append(columns, ref.Kind+"_registry_version", ref.Kind+"_registry_sha256")
		arguments = append(arguments, ref.Version, ref.SHA256)
	}
	for _, ref := range values.References {
		columns = append(columns, ref.Purpose+"_identity_hash", ref.Purpose+"_ref_version")
		arguments = append(arguments, ref.IdentityHash, ref.Version)
	}
	if _, err = admin.Exec("INSERT INTO system_backup_v2_configs("+strings.Join(columns, ",")+") VALUES("+strings.TrimSuffix(strings.Repeat("?,", len(arguments)), ",")+")", arguments...); err != nil {
		t.Fatal("actual config constraints rejected fixture DATA", err)
	}
	return f
}

func (f *publicationCertificateFactsFixture) seed(t *testing.T) (security.PublisherCaptureFacts, publicationVerifiedCapture, string) {
	t.Helper()
	backup := "sbk_" + uuid.NewString()
	var now time.Time
	if f.admin.QueryRow(`SELECT UTC_TIMESTAMP(6)`).Scan(&now) != nil {
		t.Fatal("actual SQL clock")
	}
	lease, deadline := now.Add(time.Minute), now.Add(15*time.Minute)
	_, err := f.admin.Exec(`INSERT INTO system_backup_v2_backups(public_id,origin_installation_id,actor_type,actor_id,endpoint,idempotency_key,request_hash,request_id,status,config_version,config_snapshot_json,config_snapshot_size_bytes,config_snapshot_sha256,controller_owner,controller_lease_expires_at,deadline_at,started_at,created_at,source_orchestrator,source_profile,matrix_key,runner,task_purpose,requested_parts,artifact_read_identity_hash,artifact_read_ref_version,artifact_ca_identity_hash,artifact_ca_ref_version,target_class,target_risks,target_failure_domain_id) VALUES(?,?,'system','system:controller','CertificateFactsFixture',?,?,'certificate-facts-request','validating',1,?,?,?,?,?,?,?,?,'kubernetes','cluster','k8s-cluster','k8s','functional_test','workspace',?,'fixture-v1',?,'fixture-v1','same-cluster-copy','','local')`, backup, f.installation, uuid.NewString(), hash([]byte("named historical request DATA")), f.config, len(f.config), hash(f.config), f.service.PublisherOwner, lease, deadline, now.Add(-4*time.Second), now.Add(-5*time.Second), hash([]byte("named read identity DATA")), hash([]byte("named CA identity DATA")))
	if err != nil {
		t.Fatal("actual task constraints rejected historical DATA", err)
	}
	if _, err = f.admin.Exec(`INSERT INTO system_backup_v2_attempts(target_type,target_public_id,attempt_no,phase,status,started_at,finished_at,created_at) VALUES('backup',?,1,'capture','sealed',?,?,?)`, backup, now.Add(-3*time.Second), now.Add(-time.Second), now.Add(-4*time.Second)); err != nil {
		t.Fatal(err)
	}
	var capture publicationVerifiedCapture
	capture.Input.ConfigVersion, capture.Input.CaptureAttemptNo, capture.Input.CaptureEpoch = 1, 1, 17
	capture.Input.ConfigSHA256 = hash(f.config)
	capture.CaptureResultSHA256 = hash([]byte("named historical result DATA"))
	capture.Control.Generated = now.Add(-2 * time.Second)
	facts := security.PublisherCaptureFacts{InstallationID: f.installation, BackupPublicID: backup, Status: "validating", ConfigVersion: 1, ConfigSHA256: hash(f.config), CaptureAttemptNo: 1, CaptureEpoch: 17, CaptureResultSHA256: capture.CaptureResultSHA256, ClaimLeaseUntil: lease, TaskDeadline: deadline, SourceResumedAt: now.Add(-2 * time.Second)}
	owner := originalStageOwner{Schema: "system-backup-original-stage-owner.v1", Installation: f.installation, Task: backup, Phase: "capture", Attempt: 1, ConfigVersion: 1, ConfigSHA256: hash(f.config), Location: filepath.Join(f.service.Runtime.Owner.Staging.Name(), backup)}
	raw, _ := json.Marshal(owner)
	owner.PhaseUID = "capture-" + hash(raw)
	owner.Resource, owner.KeyVersion = "sbs_"+uuid.NewString(), uuid.NewString()
	_, err = f.admin.Exec(`INSERT INTO system_backup_v2_staging_resources(public_id,origin_installation_id,backup_public_id,attempt_no,phase,phase_uid,resource_type,planned_locator,location_sha256,owner_marker_hmac,owner_marker_key_version,observed_name,observed_uid,lifecycle) VALUES(?,?,?,1,'capture',?,'hostpath',?,?,?,?,?,?,'ready')`, owner.Resource, f.installation, backup, owner.PhaseUID, owner.Location, hash([]byte(owner.Location)), hash([]byte("named marker DATA")), owner.KeyVersion, backup, owner.Resource)
	if err != nil {
		t.Fatal("actual original 104 rejected historical DATA", err)
	}
	return facts, capture, owner.Resource
}

func TestPublicationCertificateCurrentComplete104RowsFull175MySQL(t *testing.T) {
	f := newPublicationCertificateFactsFixture(t)
	for _, mode := range []string{"current", "extra-resource", "replaced-uid", "expired-lease", "expired-task", "stage-row-version", "task-row-version", "finished-at", "marker", "marker-key-version", "lifecycle", "missing-resource"} {
		t.Run(mode, func(t *testing.T) {
			facts, capture, id := f.seed(t)
			read := func(expected *publicationCertificateSQLFacts) (publicationCertificateSQLFacts, error) {
				t.Helper()
				tx, err := f.reader.BeginTx(context.Background(), nil)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				return f.service.readPublicationCertificateFactsTx(context.Background(), tx, facts, capture, expected)
			}
			original, err := read(nil)
			if err != nil {
				t.Fatal("healthy current full-175 locked row read", err)
			}
			var result sql.Result
			switch mode {
			case "extra-resource":
				result, err = f.admin.Exec(`INSERT INTO system_backup_v2_staging_resources(public_id,origin_installation_id,backup_public_id,attempt_no,phase,phase_uid,resource_type,planned_locator,location_sha256,owner_marker_hmac,owner_marker_key_version,observed_name,observed_uid,lifecycle) SELECT ?,origin_installation_id,backup_public_id,attempt_no,phase,phase_uid,resource_type,CONCAT(planned_locator,'-extra'),?,owner_marker_hmac,owner_marker_key_version,observed_name,?,lifecycle FROM system_backup_v2_staging_resources WHERE public_id=?`, "sbs_"+uuid.NewString(), hash([]byte("extra "+id)), "sbs_"+uuid.NewString(), id)
			case "replaced-uid":
				result, err = f.admin.Exec(`UPDATE system_backup_v2_staging_resources SET observed_uid=? WHERE public_id=?`, "sbs_"+uuid.NewString(), id)
			case "expired-lease":
				result, err = f.admin.Exec(`UPDATE system_backup_v2_backups SET controller_lease_expires_at=TIMESTAMPADD(SECOND,-1,UTC_TIMESTAMP(6)) WHERE public_id=?`, facts.BackupPublicID)
			case "expired-task":
				result, err = f.admin.Exec(`UPDATE system_backup_v2_backups SET deadline_at=TIMESTAMPADD(SECOND,-1,UTC_TIMESTAMP(6)) WHERE public_id=?`, facts.BackupPublicID)
			case "stage-row-version":
				result, err = f.admin.Exec(`UPDATE system_backup_v2_staging_resources SET row_version=row_version+1 WHERE public_id=?`, id)
			case "task-row-version":
				result, err = f.admin.Exec(`UPDATE system_backup_v2_backups SET row_version=row_version+1 WHERE public_id=?`, facts.BackupPublicID)
			case "finished-at":
				result, err = f.admin.Exec(`UPDATE system_backup_v2_attempts SET finished_at=TIMESTAMPADD(MICROSECOND,1,finished_at) WHERE target_type='backup' AND target_public_id=? AND attempt_no=1 AND phase='capture'`, facts.BackupPublicID)
			case "marker":
				result, err = f.admin.Exec(`UPDATE system_backup_v2_staging_resources SET owner_marker_hmac=? WHERE public_id=?`, hash([]byte("different marker DATA")), id)
			case "marker-key-version":
				result, err = f.admin.Exec(`UPDATE system_backup_v2_staging_resources SET owner_marker_key_version=? WHERE public_id=?`, uuid.NewString(), id)
			case "lifecycle":
				result, err = f.admin.Exec(`UPDATE system_backup_v2_staging_resources SET lifecycle='deleting',cleanup_result='running' WHERE public_id=?`, id)
			case "missing-resource":
				result, err = f.admin.Exec(`DELETE FROM system_backup_v2_staging_resources WHERE public_id=?`, id)
			}
			if err != nil {
				t.Fatal("independent SQL fault actor", err)
			}
			if result != nil {
				if count, err := result.RowsAffected(); err != nil || count != 1 {
					t.Fatal("independent SQL fault did not affect its exact row", count, err)
				}
			}
			// Read the committed fault independently through the administrative
			// actor before asking the production reader to reject it. This keeps
			// a test setup failure distinct from an authority/snapshot refusal.
			query, args := "", []any{}
			switch mode {
			case "extra-resource":
				query, args = `SELECT COUNT(*)=2 FROM system_backup_v2_staging_resources WHERE backup_public_id=?`, []any{facts.BackupPublicID}
			case "replaced-uid":
				query, args = `SELECT observed_uid<>public_id FROM system_backup_v2_staging_resources WHERE public_id=?`, []any{id}
			case "expired-lease":
				query, args = `SELECT controller_lease_expires_at<UTC_TIMESTAMP(6) FROM system_backup_v2_backups WHERE public_id=?`, []any{facts.BackupPublicID}
			case "expired-task":
				query, args = `SELECT deadline_at<UTC_TIMESTAMP(6) FROM system_backup_v2_backups WHERE public_id=?`, []any{facts.BackupPublicID}
			case "stage-row-version":
				query, args = `SELECT row_version=? FROM system_backup_v2_staging_resources WHERE public_id=?`, []any{original.stage.version + 1, id}
			case "task-row-version":
				query, args = `SELECT row_version=? FROM system_backup_v2_backups WHERE public_id=?`, []any{original.taskVersion + 1, facts.BackupPublicID}
			case "finished-at":
				query, args = `SELECT finished_at=? FROM system_backup_v2_attempts WHERE target_type='backup' AND target_public_id=? AND attempt_no=1 AND phase='capture'`, []any{original.completed.Add(time.Microsecond), facts.BackupPublicID}
			case "marker":
				query, args = `SELECT owner_marker_hmac=? FROM system_backup_v2_staging_resources WHERE public_id=?`, []any{hash([]byte("different marker DATA")), id}
			case "marker-key-version":
				query, args = `SELECT owner_marker_key_version<>? FROM system_backup_v2_staging_resources WHERE public_id=?`, []any{original.stage.owner.KeyVersion, id}
			case "lifecycle":
				query, args = `SELECT lifecycle='deleting' AND cleanup_result='running' FROM system_backup_v2_staging_resources WHERE public_id=?`, []any{id}
			case "missing-resource":
				query, args = `SELECT COUNT(*)=0 FROM system_backup_v2_staging_resources WHERE public_id=?`, []any{id}
			}
			if query != "" {
				var observed bool
				if err := f.admin.QueryRow(query, args...).Scan(&observed); err != nil || !observed {
					t.Fatal("independent committed SQL fault readback", mode, err)
				}
			}
			again, err := read(&original)
			if mode == "current" {
				if err != nil || again != original {
					t.Fatal("unchanged original facts refused", err)
				}
			} else if err == nil {
				t.Fatal("changed current rows were silently omitted/adopted", mode)
			}
		})
	}
}
