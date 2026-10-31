package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	appdb "clawreef/internal/db"
	root "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/control"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/worker"
	api "clawreef/internal/systembackupapi"
	c "clawreef/internal/systembackupcontroller"
	deployment "clawreef/internal/systembackupdeployment"
	d "clawreef/internal/systembackupdispatch"
	read "clawreef/internal/systembackupread"
	security "clawreef/internal/systembackupsecurity"
	"github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

// One task-owned full original schema and one authenticated HTTP acceptance
// request. The readiness/capacity observations below are explicit LOCAL input
// fixtures, not PublishReadiness or physical volume certification. This fixture
// is extended by the same-task source/worker tests; it never substitutes a
// synthetic Prepare runner or a second task for an uncompleted capture.
type dOriginalSixPartTask struct {
	db, control                             *sql.DB
	service                                 *DeploymentService
	queue                                   c.SQLExecutionQueue
	claimed                                 c.ClaimedBackup
	publicID, database, server              string
	config                                  []byte
	profile                                 deployment.ExecutionProfile
	directory                               string
	sourceSpec                              worker.DatabaseSpec
	sourceMount                             worker.FormalSourceMount
	owner                                   *PublicJobOwner
	input                                   d.Input
	sourceInventory                         b.SourceInventory
	frozenWriters                           []b.FrozenWriter
	metadataSigner                          ed25519.PrivateKey
	objectBodies                            map[string][]byte
	workspaceDirectories                    map[string]string
	packageContentMD5, unpackagedContentMD5 string
	unpackagedBytes                         int
	provider                                *dOriginalProvider
	resourceSources                         map[string]worker.ResourceSourceMount
	workers                                 *dOriginalWorkers
}

func newDOriginalSixPartTask(t *testing.T) *dOriginalSixPartTask {
	t.Helper()
	path := os.Getenv("TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS")
	if path == "" {
		t.Skip("requires the separate task-owned SAN/TLS MySQL instance")
	}
	var credential struct {
		Host, User, Password, CAFile, TLSServerName, ServerUUID string
		Port                                                    int
	}
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &credential) != nil || credential.Host != "127.0.0.1" || credential.ServerUUID == "" {
		t.Fatal("owned TLS MySQL fixture credentials unavailable")
	}
	clear(raw)
	ca, err := os.ReadFile(credential.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("owned source CA")
	}
	var nonce [8]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	run := hex.EncodeToString(nonce[:])
	tlsName := "d-sixpart-" + run
	if err = mysql.RegisterTLSConfig(tlsName, &tls.Config{RootCAs: roots, ServerName: credential.TLSServerName, MinVersion: tls.VersionTLS13}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mysql.DeregisterTLSConfig(tlsName) })
	connection := mysql.NewConfig()
	connection.User, connection.Passwd, connection.Net, connection.Addr = credential.User, credential.Password, "tcp", net.JoinHostPort(credential.Host, strconv.Itoa(credential.Port))
	connection.ParseTime, connection.Loc, connection.TLSConfig = true, time.UTC, tlsName
	connection.Params = map[string]string{"time_zone": "'+00:00'"}
	connection.Timeout, connection.ReadTimeout, connection.WriteTimeout = 5*time.Second, 30*time.Second, 30*time.Second
	credential.Password = ""
	admin, err := sql.Open("mysql", connection.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })
	f := &dOriginalSixPartTask{database: "ad_d_six_" + run, directory: t.TempDir()}
	f.createOriginalPayloads(t)
	ctx := context.Background()
	if _, err = admin.ExecContext(ctx, "CREATE DATABASE `"+f.database+"` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"); err != nil {
		t.Fatal("owned original task schema", err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec("DROP DATABASE `" + f.database + "`"); err != nil {
			t.Error(err)
		}
	})
	connection.DBName = f.database
	f.db, err = sql.Open("mysql", connection.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Close() })
	if f.db.QueryRow("SELECT @@server_uuid").Scan(&f.server) != nil || f.server != credential.ServerUUID {
		t.Fatal("owned TLS MySQL original identity mismatch")
	}
	var cipher string
	if f.db.QueryRow("SELECT VARIABLE_VALUE FROM performance_schema.session_status WHERE VARIABLE_NAME='Ssl_cipher'").Scan(&cipher) != nil || cipher == "" {
		t.Fatal("actual SQL session has no TLS cipher")
	}
	catalog, err := appdb.EmbeddedMigrationCatalog()
	if err != nil {
		t.Fatal(err)
	}
	migrate, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err = appdb.ApplyPinnedMigrations(migrate, f.db, appdb.MigrationTarget{ServerUUID: f.server, Database: f.database, CatalogSHA256: catalog.Hash}); err != nil {
		t.Fatal("original full migration runner", err)
	}
	installation := "installation_d_six_" + run
	f.profile = deployment.ExecutionProfile{InstallationID: installation, Revision: "d-original-six-r1", Orchestrator: "kubernetes", Profile: "cluster", TargetClass: "dr-ready-external", TargetRisks: []string{}, FailureDomain: "local-protocol-fixture", RestoreTargetRef: "isolated-original-target", RestoreTargetHash: strings.Repeat("f", 64)}
	profileRaw, profileSHA, err := f.profile.CanonicalIdentity()
	if err != nil {
		t.Fatal(err)
	}
	rbac, _ := json.Marshal(map[string]any{"schema_version": "system-backup-registration-rbac.draft.v1", "version": "d-six-rbac-v1", "installation_id": installation, "bindings": []any{map[string]any{"actor_id": "42", "subject": "user:42", "role": "operator"}}})
	example, err := os.ReadFile("../../../contracts/system-backup/v12/admin-control-redacted-examples.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Request struct {
			Config map[string]any `json:"config"`
		} `json:"config_update_request"`
	}
	decoder := json.NewDecoder(bytes.NewReader(example))
	decoder.UseNumber()
	if decoder.Decode(&document) != nil {
		t.Fatal("original config example")
	}
	values := document.Request.Config
	values["enabled"] = true
	values["capacity"].(map[string]any)["control_metadata_capacity_bytes"] = json.Number("1073741824")
	for _, entry := range values["registries"].([]any) {
		registry := entry.(map[string]any)
		if registry["registry_kind"] == "rbac_bindings" {
			registry["version"], registry["sha256"] = "d-six-rbac-v1", hash(rbac)
		}
	}
	f.config, _ = json.Marshal(values)
	flat := map[string]any{"origin_installation_id": installation, "version": 1, "config_sha256": hash(f.config), "config_size_bytes": len(f.config), "canonical_config_json": f.config, "created_by": "1", "change_reason": "named local original six-part task fixture"}
	for _, name := range []string{"enabled", "alert_profile", "minimum_recovery_points"} {
		flat[name] = values[name]
	}
	for _, group := range []string{"durations", "capacity", "concurrency", "preflight_limits"} {
		for name, value := range values[group].(map[string]any) {
			if group == "preflight_limits" {
				name = "preflight_" + name
			}
			flat[name] = value
		}
	}
	for _, entry := range values["registries"].([]any) {
		registry := entry.(map[string]any)
		kind := registry["registry_kind"].(string)
		flat[kind+"_registry_version"], flat[kind+"_registry_sha256"] = registry["version"], registry["sha256"]
	}
	for _, entry := range values["references"].([]any) {
		reference := entry.(map[string]any)
		kind := reference["purpose"].(string)
		flat[kind+"_identity_hash"], flat[kind+"_ref_version"] = reference["identity_hash"], reference["version"]
	}
	columns := make([]string, 0, len(flat))
	for name := range flat {
		columns = append(columns, name)
	}
	sort.Strings(columns)
	arguments := make([]any, 0, len(columns))
	for _, name := range columns {
		value := flat[name]
		if number, ok := value.(json.Number); ok {
			value = number.String()
		}
		arguments = append(arguments, value)
	}
	if _, err = f.db.Exec("INSERT INTO system_backup_v2_configs("+strings.Join(columns, ",")+") VALUES("+strings.TrimSuffix(strings.Repeat("?,", len(columns)), ",")+")", arguments...); err != nil {
		t.Fatal("original task config", err)
	}
	if _, err = f.db.Exec("INSERT INTO system_backup_v2_installation_state(origin_installation_id,active_config_version,last_effective_enabled,last_effective_enabled_transition_at,matrix_key) VALUES(?,1,TRUE,UTC_TIMESTAMP(6),'k8s-cluster')", installation); err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.Exec("INSERT INTO system_backup_v2_engine_bindings(scope,engine) VALUES('installation','v2')"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.Exec("INSERT INTO users(id,username,email,password_hash,role,is_active) VALUES(42,'d-six-operator','d-six@example.invalid','named-test-session-credential','admin',TRUE)"); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"INSERT INTO instances(id,user_id,name,type,instance_mode,runtime_type,runtime_variant,os_type,os_version,cpu_cores,memory_gb,disk_gb,status,runtime_generation,pod_name,pod_namespace,workspace_path,image_registry,image_tag) VALUES(7,42,'original-running','openclaw','pro','desktop','linux','linux','original',2,4,10,'running',3,'d-original-7','backup','/workspaces/42/7','original/openclaw@sha256:" + strings.Repeat("a", 64) + "',NULL),(9,42,'original-stopped','hermes','pro','desktop','linux','linux','original',2,4,10,'stopped',4,NULL,'backup','/workspaces/42/9','original/hermes@sha256:" + strings.Repeat("b", 64) + "',NULL)",
		"INSERT INTO teams(id,user_id,name,status,communication_mode,redis_events_last_id,shared_pvc_name,shared_pvc_namespace,shared_mount_path,resource_scope) VALUES(20,42,'original-six-team','running','redis','0-0','d-team-20','backup','/team','cm')",
		"INSERT INTO team_members(id,team_id,instance_id,user_id,member_key,display_name,role,runtime_type,instance_mode,status,progress,availability) VALUES(21,20,7,42,'original-member','Original member','worker','openclaw','pro','running',0,'available')",
		"INSERT INTO skills(id,user_id,skill_key,name) VALUES(11,42,'original-six-skill','Original six-part skill')",
		fmt.Sprintf("INSERT INTO skill_blobs(id,content_hash,archive_hash,object_key,file_name,size_bytes) VALUES(12,'%s','%s','original.zip','original.zip',%d),(18,'%s','','','local',%d)", f.packageContentMD5, hash(f.objectBodies["original.zip"]), len(f.objectBodies["original.zip"]), f.unpackagedContentMD5, f.unpackagedBytes),
		"INSERT INTO skill_versions(id,skill_id,blob_id,version_no,manifest_json) VALUES(13,11,12,1,'{\"named_original_manifest\":true}'),(19,11,18,2,'{\"named_workspace_manifest\":true}')",
		"UPDATE skills SET current_version_id=13 WHERE id=11",
		"INSERT INTO instance_skills(id,instance_id,skill_id,skill_version_id,workspace_dir,observed_hash) VALUES(14,7,11,19,'demo','" + f.unpackagedContentMD5 + "')",
		"INSERT INTO skill_scan_results(id,blob_id,engine,findings_json) VALUES(15,12,'original-scan','{\"named_original_findings\":true}')",
		"INSERT INTO skill_hub_tags(id,tag_key,name) VALUES(16,'original-six','Original six-part tag')",
		"INSERT INTO skill_hub_tag_assignments(id,skill_id,tag_id) VALUES(17,11,16)",
		"INSERT INTO skill_package_materialize_jobs(id,instance_id,skill_id,blob_id,workspace_dir,content_hash,idempotency_key) VALUES(20,7,11,18,'previous','" + f.unpackagedContentMD5 + "','original-six-materialize')",
	} {
		if _, err = f.db.Exec(statement); err != nil {
			t.Fatal("nonempty original Teams/Skills/runtime source fixture", err)
		}
	}
	capacityFile := filepath.Join(f.directory, "capacity.json")
	var observed time.Time
	if f.db.QueryRow("SELECT UTC_TIMESTAMP(6)").Scan(&observed) != nil {
		t.Fatal("SQL fixture clock")
	}
	capacity, _ := json.Marshal(security.CapacityReport{ServerUUID: f.server, Database: f.database, ObservedAt: observed, AllocatedBytes: 1 << 20, AvailableBytes: 4 << 30})
	if os.WriteFile(capacityFile, capacity, 0600) != nil {
		t.Fatal("named capacity input fixture")
	}
	if _, err = f.db.Exec("INSERT INTO system_backup_v2_execution_readiness(origin_installation_id,task_type,config_version,profile_sha256,owner,generation,ready,checked_at,expires_at,execution_protocol,supported_parts,acceptance_ready) VALUES(?,'backup',1,?,'named-local-readiness-input',1,TRUE,UTC_TIMESTAMP(6),TIMESTAMPADD(SECOND,60,UTC_TIMESTAMP(6)),'public-v1','mysql,redis,object_storage,workspace,deployment_resources,secret_bundle',TRUE)", installation, profileSHA); err != nil {
		t.Fatal(err)
	}
	registryFile := filepath.Join(f.directory, "registries", "rbac_bindings", "d-six-rbac-v1", hash(rbac)+".json")
	if os.MkdirAll(filepath.Dir(registryFile), 0700) != nil || os.WriteFile(registryFile, rbac, 0600) != nil {
		t.Fatal("RBAC fixture files")
	}
	pins, _ := json.Marshal(security.SystemBackupReadPins{InstallationID: installation, ConfigVersion: 1, RBACVersion: "d-six-rbac-v1", RBACSHA256: hash(rbac), RegistryDirectory: filepath.Join(f.directory, "registries")})
	pinFile := filepath.Join(f.directory, "read-pins.json")
	if os.WriteFile(pinFile, pins, 0600) != nil {
		t.Fatal("read pins")
	}
	key := make([]byte, 48)
	if _, err = rand.Read(key); err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	sessions, err := security.NewSQLLoginSessions(f.db, security.DatabaseIdentity{ServerUUID: f.server, Database: f.database}, installation, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sessions.Close)
	now := time.Now().UTC().Add(-time.Second)
	signToken := func(kind string) string {
		expires := now.Add(time.Hour)
		if kind == "refresh" {
			expires = now.Add(2 * time.Hour)
		}
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"user_id": 42, "token_type": kind, "jti": "d-six-" + kind + "-" + run, "iat": now.Unix(), "exp": expires.Unix()}).SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	access, refresh := signToken("access"), signToken("refresh")
	if err = sessions.RecordPair(ctx, security.LoginSessionPair{UserID: 42, CredentialSHA256: hash([]byte("named-test-session-credential")), AccessToken: access, RefreshToken: refresh}); err != nil {
		t.Fatal("original signed login session registration", err)
	}
	actions, err := security.LoadSystemBackupActionAuthorizer(sessions, pinFile, hash(pins))
	if err != nil {
		t.Fatal(err)
	}
	reads, err := security.LoadSystemBackupReadAuthorizer(sessions, pinFile, hash(pins))
	if err != nil {
		t.Fatal(err)
	}
	writer, err := api.NewAdmittedTaskWriter(api.ExecutionProfile(f.profile), capacityFile, true)
	if err != nil {
		t.Fatal(err)
	}
	application, err := api.NewSQLApplication(f.db, actions, reads, writer, api.SQLTaskDetails{DB: f.db}, 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://localhost/api/v1/admin/system-backups", strings.NewReader(`{"task_purpose":"acceptance","requested_parts":["mysql","redis","object_storage","workspace","deployment_resources","secret_bundle"]}`))
	request.TLS = &tls.ConnectionState{}
	request.Header.Set("Authorization", "Bearer "+access)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "d-six-original-task-"+run)
	response := httptest.NewRecorder()
	api.NewHandler(application).Create(response, request, read.BackupTask, "d-six-original-request-"+run)
	if response.Code != http.StatusAccepted {
		t.Fatal("original HTTP/RBAC six-part admission", response.Code, response.Body.String())
	}
	f.publicID = strings.TrimPrefix(response.Header().Get("Location"), "/api/v1/admin/system-backups/")
	if len(f.publicID) != 40 {
		t.Fatal("original HTTP task location")
	}
	// Only the controller gets the original finite controller table/verb role.
	user := "ad_d_six_ctl_" + run
	password := make([]byte, 24)
	rand.Read(password)
	pass := hex.EncodeToString(password)
	clear(password)
	if _, err = admin.Exec("CREATE USER '" + user + "'@'127.0.0.1' IDENTIFIED BY '" + pass + "'"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec("DROP USER '" + user + "'@'127.0.0.1'"); err != nil {
			t.Error(err)
		}
	})
	grants, err := c.ControlEvidenceGrantSQL(f.database, user, "127.0.0.1", false, true, true, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, grant := range grants {
		if _, err = admin.Exec(grant); err != nil {
			t.Fatal("original finite controller grants", err)
		}
	}
	connection.User, connection.Passwd = user, pass
	f.control, err = sql.Open("mysql", connection.FormatDSN())
	connection.Passwd = ""
	pass = ""
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.control.Close() })
	if err = (c.SQLControlEvidenceGrantProbe{DB: f.control, Schema: f.database, User: user, Runtime: true, ProviderPermits: true}).Check(ctx); err != nil {
		t.Fatal("original controller direct grants", err)
	}
	sourceUser := "ad_d_six_src_" + run
	secret := make([]byte, 24)
	rand.Read(secret)
	sourcePassword := hex.EncodeToString(secret)
	clear(secret)
	if _, err = admin.Exec("CREATE USER '" + sourceUser + "'@'127.0.0.1' IDENTIFIED BY '" + sourcePassword + "'"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec("DROP USER '" + sourceUser + "'@'127.0.0.1'"); err != nil {
			t.Error(err)
		}
	})
	for _, table := range domain.BusinessCaptureTables() {
		var present int
		if f.db.QueryRow("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?", table).Scan(&present) != nil {
			t.Fatal("original source metadata")
		}
		if present == 1 {
			if _, err = admin.Exec("GRANT SELECT ON `" + f.database + "`.`" + table + "` TO '" + sourceUser + "'@'127.0.0.1'"); err != nil {
				t.Fatal(err)
			}
		}
	}
	definer, _, _, census, _ := installLockedSourceCensusFixture(t, f.db, f.database, sourceUser, nonce)
	t.Cleanup(func() {
		if _, err := admin.Exec("DROP USER '" + definer + "'@'127.0.0.1'"); err != nil {
			t.Error(err)
		}
	})
	f.sourceSpec = worker.DatabaseSpec{Address: connection.Addr, Name: f.database, ServerUUID: f.server, TLSServerName: credential.TLSServerName, RootCA: ca, MaxRows: 100000, MaxMemoryBytes: 32 << 20, SourceScope: domain.BusinessTableSourceScope, SchemaCensus: &census}
	credentialRaw, _ := json.Marshal(metadataSourceCredential{Username: sourceUser, Password: []byte(sourcePassword)})
	f.sourceMount.CredentialFile = filepath.Join(f.directory, "original-sql-source-credential.json")
	f.sourceMount.CredentialSHA256 = hash(credentialRaw)
	if os.WriteFile(f.sourceMount.CredentialFile, credentialRaw, 0600) != nil {
		t.Fatal("private original source credential")
	}
	clear(credentialRaw)
	sourceCredential := worker.DatabaseCredential{Username: sourceUser, Password: []byte(sourcePassword)}
	workerSource, err := worker.OpenDatabase(&f.sourceSpec, &sourceCredential)
	clear(sourceCredential.Password)
	sourcePassword = ""
	if err != nil {
		t.Fatal("actual original SQL worker TLS opener", err)
	}
	t.Cleanup(func() { workerSource.Close() })
	var sourceAccount, sourceRole, sourceDatabase, sourceUUID string
	if workerSource.QueryRow("SELECT CURRENT_USER(),CURRENT_ROLE(),DATABASE(),@@server_uuid").Scan(&sourceAccount, &sourceRole, &sourceDatabase, &sourceUUID) != nil || sourceAccount != sourceUser+"@127.0.0.1" || sourceRole != "NONE" || sourceDatabase != f.database || sourceUUID != f.server {
		t.Fatal("original SQL worker TLS identity")
	}
	if _, err = workerSource.Query("SELECT * FROM system_backup_v2_configs"); err == nil {
		t.Fatal("source collector could read control metadata")
	}
	observedSchema, err := domain.ObserveBusinessCaptureSchema(ctx, workerSource, census)
	if err != nil {
		t.Fatal("original complete source metadata", err)
	}
	f.sourceSpec.CaptureSchema = &observedSchema
	if err = (root.Gate{DB: f.db}).EnsureScope(ctx, "installation"); err != nil {
		t.Fatal(err)
	}
	if err = (c.SQLGateInitializer{DB: f.db}).Ensure(ctx, installation, c.GatePolicy{LockTTL: 900 * time.Second, AcquisitionTimeout: 60 * time.Second, MaxHold: 600 * time.Second}); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	recordKey := make([]byte, 32)
	rand.Read(recordKey)
	defer clear(recordKey)
	if os.WriteFile(filepath.Join(f.directory, "record-v1"), recordKey, 0600) != nil {
		t.Fatal("record key")
	}
	core := runtimeDeploymentFixture(t)
	core.CaptureScope = "six-part"
	// Declare the full ten-part bound BEFORE core signing/Prepare. No frozen
	// hold or old key lease is extended when a shorter run fails closed.
	core.HoldSeconds = 300
	core.InstallationID, core.ControllerOwner, core.ApplicationScope = installation, "d-six-controller-"+run, "installation"
	core.SourceDatabase, core.SourceServerUUID = f.database, f.server
	core.SourceUser = sourceUser
	core.Workspace.MaxFiles, core.Workspace.MaxFileBytes, core.Workspace.MaxArchiveBytes, core.Workspace.MaxCompressedBytes = 100, 4<<20, 16<<20, 16<<20
	// Pin the original observed PVC/PV content before the core is signed.
	core.Security.Volumes[0].Volume, core.Security.Volumes[1].Volume = "workspace", "staging"
	core.Security.Volumes[0].SHA256 = kube.ContentHash(corev1.PersistentVolumeSpec{ClaimRef: &corev1.ObjectReference{Name: "source", Namespace: core.Namespace, UID: "source-uid"}})
	core.Security.Volumes[1].SHA256 = kube.ContentHash(corev1.PersistentVolumeSpec{ClaimRef: &corev1.ObjectReference{Name: "staging", Namespace: core.Namespace, UID: "stage-uid"}})
	core.CapacityFile = capacityFile
	core.RuntimeSources.Supported = append(core.RuntimeSources.Supported, b.AgentKind{Type: "hermes", Mode: "pro", Variant: "linux", OS: "linux"})
	core.StagingDirectory = filepath.Join(f.directory, "staging")
	if os.MkdirAll(core.StagingDirectory, 0700) != nil {
		t.Fatal("private task staging")
	}
	core.CaptureModules = &ProductionCaptureReference{Protocol: productionCaptureMaterialsVersion, Path: filepath.Join(f.directory, "capture-materials.json")}
	core.FormalVerifier = &FormalVerifierReference{Protocol: formalVerifierMaterialsVersion, Path: filepath.Join(f.directory, "formal-verifier.json")}
	core.ProfileFile, core.KeyDirectory = filepath.Join(f.directory, "profile.json"), f.directory
	core.ForwardGrant = GrantReference{Path: filepath.Join(f.directory, "forward.json"), PublicKey: base64.StdEncoding.EncodeToString(public)}
	core.RecoveryGrant = GrantReference{Path: filepath.Join(f.directory, "recovery.json"), PublicKey: base64.StdEncoding.EncodeToString(public)}
	issuerPublic, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(issuerPrivate) })
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "D original same-task worker issuer"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, issuerPublic, issuerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	issuerPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER})
	issuerPKCS8, err := x509.MarshalPKCS8PrivateKey(issuerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(issuerPKCS8)
	serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(serverPrivate) })
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "D original control endpoint"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, issuer, serverPublic, issuerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	serverPKCS8, err := x509.MarshalPKCS8PrivateKey(serverPrivate)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(serverPKCS8)
	core.IssuerCertificate, core.IssuerKey, core.IssuerSHA256 = filepath.Join(f.directory, "worker-issuer.pem"), filepath.Join(f.directory, "worker-issuer-key.pem"), hash(issuerDER)
	core.ServerCertificate, core.ServerKey = filepath.Join(f.directory, "control-server.pem"), filepath.Join(f.directory, "control-server-key.pem")
	for path, raw := range map[string][]byte{core.IssuerCertificate: issuerPEM, core.IssuerKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: issuerPKCS8}), core.ServerCertificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), core.ServerKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverPKCS8})} {
		if os.WriteFile(path, raw, 0600) != nil {
			t.Fatal("original local control PKI")
		}
		clear(raw)
	}
	// Keep the issuer public bytes for the original worker issuer, independently
	// of the temporary serialized buffers cleared above.
	issuerRoots := x509.NewCertPool()
	issuerRoots.AddCert(issuer)
	controlServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.service == nil || f.service.Runtime == nil || f.service.Runtime.Control == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		f.service.controlHandler().ServeHTTP(w, r)
	}))
	controlServer.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{serverDER}, PrivateKey: serverPrivate}}, MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: issuerRoots}
	controlServer.StartTLS()
	t.Cleanup(controlServer.Close)
	core.ControlURL = controlServer.URL
	if os.WriteFile(core.ProfileFile, profileRaw, 0600) != nil {
		t.Fatal("profile")
	}
	coreRaw, _ := json.Marshal(core)
	corePath := filepath.Join(f.directory, "core.json")
	if os.WriteFile(corePath, coreRaw, 0600) != nil {
		t.Fatal("core")
	}
	grant := c.ExecutionGrant{Version: "system-backup-execution-grant.v1", InstallationID: installation, ControllerOwner: core.ControllerOwner, DatabaseAccount: user + "@127.0.0.1", ServerUUID: f.server, Database: f.database, ConfigVersion: 1, ConfigSHA256: hash(f.config), ProfileSHA256: profileSHA, DeploymentConfigSHA256: hash(coreRaw), WorkerIssuerSHA256: hash(issuerDER), NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Actions: []string{"prepare", "capture", "issue_worker"}, RecordKeys: []c.ExecutionRecordKey{{Ref: "record-v1", SHA256: hash(recordKey)}}}
	makeIdentity := func(record c.ExecutionGrant, path string) *c.PinnedExecutionIdentity {
		body, _ := json.Marshal(record)
		envelope, _ := json.Marshal(map[string]string{"payload_base64": base64.StdEncoding.EncodeToString(body), "signature_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(private, body))})
		if os.WriteFile(path, envelope, 0600) != nil {
			t.Fatal("identity")
		}
		identity, err := c.NewPinnedExecutionIdentity(path, hash(envelope), f.directory, public)
		if err != nil {
			t.Fatal(err)
		}
		return identity
	}
	forward := makeIdentity(grant, core.ForwardGrant.Path)
	grant.Actions, grant.WorkerIssuerSHA256 = []string{"recover"}, ""
	recovery := makeIdentity(grant, core.RecoveryGrant.Path)
	f.service = &DeploymentService{ForwardEnabled: true, Config: core, ConfigPath: corePath, ConfigDigest: hash(coreRaw), Forward: forward, Recovery: recovery, profile: f.profile, profileHash: profileSHA, Source: workerSource, captureMaterials: &productionCaptureMaterials{Operations: map[string]productionCaptureOperation{"capture-database": {Request: worker.Request{Database: &f.sourceSpec}}}}}
	if err = f.service.checkSource(ctx); err != nil {
		t.Fatal("original service finite source/census admission", err)
	}
	gate := f.service.captureGate(f.control)
	f.queue = c.SQLExecutionQueue{DB: f.control, InstallationID: installation, Owner: core.ControllerOwner, Policy: c.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second}, Authorization: gate.Authority.Authorization, ApplicationScope: core.ApplicationScope, Recovery: &gate.Recovery}
	f.claimed, err = f.queue.TakeBackup(ctx)
	if err != nil || f.claimed.Claim.Target.PublicID != f.publicID || f.claimed.RecoveryRequired || f.claimed.Status != "preparing" {
		t.Fatal("same original admitted task queue acquisition", err)
	}
	tx, err := f.control.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.input, err = f.claimed.ExecutionInputForAttempt(ctx, tx, 1)
	tx.Rollback()
	if err != nil {
		t.Fatal("same original queue input", err)
	}
	ctx, stopPreparation := context.WithDeadline(ctx, f.input.Authority.DeadlineAt)
	defer stopPreparation()
	stage, err := os.OpenRoot(core.StagingDirectory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stage.Close() })
	one := int32(1)
	controller := true
	labels := map[string]string{"app": "d-original-platform"}
	client := kubefake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: core.Namespace, UID: "ns-uid"}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node", UID: "node-uid", Labels: map[string]string{corev1.LabelOSStable: "linux"}}},
		&corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "source", Namespace: core.Namespace, UID: "source-uid"}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "source-pv"}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}},
		&corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "source-pv", UID: "source-pv-uid"}, Spec: corev1.PersistentVolumeSpec{ClaimRef: &corev1.ObjectReference{Name: "source", Namespace: core.Namespace, UID: "source-uid"}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "d-original-7", Namespace: core.Namespace, UID: "d-original-7-uid", ResourceVersion: "1"}, Spec: corev1.PodSpec{NodeName: "node", Volumes: []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "source"}}}}, Containers: []corev1.Container{{Name: "desktop", Image: "original/openclaw@sha256:" + strings.Repeat("a", 64), VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/workspaces"}}}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: "desktop", ContainerID: "containerd://d-original-7", Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.Now()}}}}}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "source", Namespace: core.Namespace, UID: "dep-uid", Generation: 1, ResourceVersion: "1"}, Spec: appsv1.DeploymentSpec{Replicas: &one, Selector: &metav1.LabelSelector{MatchLabels: labels}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "platform", Image: core.WorkerImage}}}}}, Status: appsv1.DeploymentStatus{ObservedGeneration: 1, Replicas: 1, ReadyReplicas: 1}},
		&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "d-platform-rs", Namespace: core.Namespace, UID: "d-platform-rs-uid", Labels: labels, OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "source", UID: "dep-uid", Controller: &controller}}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "d-platform-pod", Namespace: core.Namespace, UID: "d-platform-pod-uid", ResourceVersion: "1", Labels: labels, OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "d-platform-rs", UID: "d-platform-rs-uid", Controller: &controller}}}, Spec: corev1.PodSpec{NodeName: "node", Containers: []corev1.Container{{Name: "platform", Image: core.WorkerImage}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: "platform", ContainerID: "containerd://d-platform", Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.Now()}}}}}},
	)
	f.owner = &PublicJobOwner{Gate: gate, Identity: forward, Client: client, Dynamic: fake.NewSimpleDynamicClient(runtime.NewScheme()), Namespace: core.Namespace, NamespaceUID: core.NamespaceUID, TrustDomain: core.TrustDomain, Security: core.Security, Staging: stage, AllowKubeletStopWitness: true}
	f.owner.Issuer = control.IdentityIssuer{Certificate: issuer, Signer: issuerPrivate, ServerRoots: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER}), TrustDomain: core.TrustDomain}
	f.owner.SealCustodyMaxBytes = core.SealCustodyMaxBytes
	f.service.tlsConfig = controlServer.TLS.Clone()
	// The original platform guard resolves its client through this same owner.
	// This component-only owner link is not NewPublicCapture composition or an
	// execution/readiness success declaration.
	f.service.Runtime = &PublicCapture{Owner: f.owner}
	if err = (root.Gate{DB: f.db}).RegisterParticipant(ctx, core.ApplicationScope, "application-mutations"); err != nil {
		t.Fatal("original application mutation participant registration", err)
	}
	profile, err := f.service.platformProfile(f.owner)
	if err != nil {
		t.Fatal(err)
	}
	profile, err = f.service.attachRuntimeSources(f.owner, profile)
	if err != nil {
		t.Fatal("original Runtime composition", err)
	}
	profile = b.WithSkillCaptureInventory(b.WithTeamsSourceFacts(profile))
	var instances []b.InstanceIdentity
	var users []int
	tx, err = workerSource.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	userRows, err := tx.QueryContext(ctx, "SELECT id FROM users ORDER BY id")
	if err != nil {
		tx.Rollback()
		t.Fatal("original source users", err)
	}
	for userRows.Next() {
		var id int
		if userRows.Scan(&id) != nil || len(users) >= 10000 {
			userRows.Close()
			tx.Rollback()
			t.Fatal("original source user projection")
		}
		users = append(users, id)
	}
	err = userRows.Err()
	userRows.Close()
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	instances, err = domain.ReadSourceInstances(ctx, tx)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	inventory := b.SourceInventory{Database: f.database, ServerUUID: f.server, Users: users, Instances: instances}
	inventory.TeamFacts, err = profile.ReadTeamFacts(ctx, tx, inventory)
	if err == nil {
		inventory.Skills, err = profile.ReadSkills(ctx, tx, inventory)
	}
	tx.Rollback()
	if err != nil || inventory.TeamFacts == nil || inventory.Skills == nil {
		t.Fatal("same original RR Teams/Skills source readers", err)
	}
	f.sourceInventory = inventory
	if err = f.service.validateRuntimeInventory(inventory); err != nil {
		t.Fatal("original runtime inventory binding", err)
	}
	if err = f.service.checkRuntimeWorkspace(ctx, client, instances); err != nil {
		t.Fatal("original runtime workspace aliases", err)
	}
	if err = f.service.RuntimeControl.Ready(ctx); err != nil {
		t.Fatal("original runtime SQL schema readiness", err)
	}
	return f
}

func TestProductionSameTaskOriginalAdmissionAndQueueMySQL(t *testing.T) {
	runDOriginalSixPartCapture(t, false, false)
}

func TestProductionSameTaskOriginalProviderDeniedStopsBeforeResumeMySQL(t *testing.T) {
	runDOriginalSixPartCapture(t, true, true)
}

func runDOriginalSixPartCapture(t *testing.T, denyGenerate, completeCapture bool) {
	t.Helper()
	f := newDOriginalSixPartTask(t)
	ctx, cancel := context.WithDeadline(context.Background(), f.input.Authority.DeadlineAt)
	defer cancel()
	stopCapacity := f.startLocalCapacityInput(ctx, t)
	defer stopCapacity()
	store := c.SQLExecutionWorkStore{Queue: f.queue}
	if err := store.RunWithExecutionHeartbeat(ctx, f.input.Authority, func(active context.Context) error {
		f.checkOriginalMetadataSources(active, t)
		return nil
	}); err != nil {
		t.Fatal("original same-epoch source preparation heartbeat", err)
	}
	plan, err := f.service.Runtime.Loop.Dispatch.Prepare(ctx, f.input)
	if err != nil {
		t.Fatal("same-task original leased public runner Prepare", err)
	}
	inner, err := d.UnwrapTaskPlan(f.input, plan, b.PlanVersion)
	if err != nil {
		t.Fatal("original task plan wrapper", err)
	}
	discovery, err := b.DescribePlan(f.input, inner)
	clear(inner.CanonicalJSON)
	if err != nil {
		t.Fatal("original Prepare frozen plan", err)
	}
	f.checkOriginalFrozenDiscovery(ctx, t, discovery)
	checkOriginalPublicationSourceFacts(t, discovery)
	if err := f.service.Runtime.Loop.Store.Record(ctx, c.ExecutionWork{Step: c.ExecutionPrepare, Input: f.input}, c.ExecutionOutcome{Plan: plan}); err != nil {
		t.Fatal("same-task original DurableExecutionStore SavePlan/outcome", err)
	}
	var status, storedSHA string
	var encrypted []byte
	if f.control.QueryRowContext(ctx, "SELECT b.status,r.payload_sha256,r.sealed_payload FROM system_backup_v2_backups b JOIN system_backup_v2_execution_records r ON r.task_public_id=b.public_id AND r.record_kind='plan' AND r.attempt_no=1 AND r.phase='capture' WHERE b.public_id=?", f.publicID).Scan(&status, &storedSHA, &encrypted) != nil || status != "ready_for_capture" || storedSHA != plan.SHA256 || len(encrypted) == 0 || bytes.Equal(encrypted, plan.CanonicalJSON) {
		t.Fatal("original encrypted same-task plan/outcome not persisted")
	}
	var attempts int
	if f.db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_attempts WHERE target_type='backup' AND target_public_id=? AND attempt_no=1 AND phase IN ('capture','secret_capture') AND status='preparing'", f.publicID).Scan(&attempts) != nil || attempts != 2 {
		t.Fatal("original same-task capture/secret phase attempts")
	}
	var tasks int
	if f.db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_backups").Scan(&tasks) != nil || tasks != 1 {
		t.Fatal("original admission created another task")
	}
	if len(f.claimed.Request) == 0 || f.claimed.ConfigSHA256 != hash(f.config) {
		t.Fatal("queue lost admitted original request/config")
	}
	// The real scheduler's original ready_for_capture reconciliation is one
	// second later. Re-take the SAME task; never substitute another acceptance.
	timer := time.NewTimer(time.Second + 100*time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-timer.C:
	}
	capture, err := f.service.Runtime.Loop.Store.Next(ctx)
	if err != nil || capture == nil || capture.Step != c.ExecutionCapture || capture.Input.Authority.TaskPublicID != f.publicID || capture.Input.Authority.AttemptNo != 1 || capture.Plan.SHA256 != plan.SHA256 || !bytes.Equal(capture.Plan.CanonicalJSON, plan.CanonicalJSON) || capture.Input.Authority.ClaimRowVersion <= f.input.Authority.ClaimRowVersion || capture.Input.Authority.MaintenanceOwner != f.publicID || capture.Input.Authority.MaintenanceFencingToken == 0 {
		t.Fatal("original same-task reTake/acquiring epoch/frozen plan", err)
	}
	var phase, gateOwner string
	var generation uint64
	if f.control.QueryRowContext(ctx, "SELECT phase,owner,generation FROM system_backup_gate WHERE scope=?", f.service.Config.ApplicationScope).Scan(&phase, &gateOwner, &generation) != nil || phase != "acquiring" || gateOwner != f.publicID || generation != capture.Input.Authority.MaintenanceFencingToken {
		t.Fatal("original acquiring gate not bound to same task/fence")
	}
	var jobs int
	if f.control.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job'", f.publicID).Scan(&jobs) != nil || jobs != 0 {
		t.Fatal("reTake dispatched collectors before actual writer pause")
	}
	if !completeCapture {
		return
	}
	f.installOriginalWorkers(ctx, t)
	if denyGenerate {
		f.provider.mu.Lock()
		f.provider.refuseGenerate = true
		f.provider.mu.Unlock()
	}
	results, err := f.service.Runtime.Loop.Dispatch.Capture(ctx, capture.Input, capture.Plan)
	if denyGenerate {
		f.checkOriginalProviderDeniedOutcome(ctx, t, *capture, discovery, results, err)
		return
	}
	if err != nil {
		f.workers.cancel()
		f.workers.active.Wait()
		rows, queryErr := f.control.QueryContext(context.Background(), "SELECT writer_id,paused,resumed FROM system_backup_v2_runtime_writers WHERE task_public_id=? ORDER BY writer_id", f.publicID)
		if queryErr == nil {
			for rows.Next() {
				var id string
				var paused, resumed bool
				if rows.Scan(&id, &paused, &resumed) == nil {
					t.Log("original writer state", id, paused, resumed)
				}
			}
			rows.Close()
		}
		client := f.owner.Client.(*kubefake.Clientset)
		actions := client.Actions()
		start := len(actions) - 22
		if start < 0 {
			start = 0
		}
		for _, action := range actions[start:] {
			t.Log("original API action", action.GetVerb(), action.GetResource().Resource, action.GetNamespace())
		}
		f.workers.mu.Lock()
		for name, workerErr := range f.workers.errors {
			if workerErr != nil {
				t.Log("original worker", name, workerErr)
			}
		}
		f.workers.mu.Unlock()
		t.Fatal("same-task original Pause/worker/Evidence/Stop/Resume Capture", err)
	}
	if len(results) != 10 {
		t.Fatalf("original same-task captured %d parts, expected 10", len(results))
	}
	if err = f.service.Runtime.Loop.Store.Record(ctx, *capture, c.ExecutionOutcome{Results: results}); err != nil {
		t.Fatal("same-task original encrypted capture-result/validating outcome", err)
	}
}
