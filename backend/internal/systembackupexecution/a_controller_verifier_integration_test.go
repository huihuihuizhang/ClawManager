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
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	k "clawreef/internal/systembackupkms"
	w "clawreef/internal/systembackupwire"
	mysql "github.com/go-sql-driver/mysql"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

// A-owned integration seam: actual deploymentAuthorization and original
// Forward record custody, independent original verifier grant, real local
// InnoDB/SQL authority and TLS provider. Kubernetes reads use client-go fake;
// this is not an actual cluster/Runtime or complete six-domain page acceptance.
func TestAControllerVerifierOriginalDeploymentSQLAndTLS(t *testing.T) {
	aControllerVerifierOriginalSQLAndTLS(t, false)
}

func TestAControllerVerifierOriginalUnwrapOnlyRevocation(t *testing.T) {
	aControllerVerifierOriginalSQLAndTLS(t, true)
}

func aControllerVerifierOriginalSQLAndTLS(t *testing.T, unwrapOnly bool, exercises ...func(aOriginalIssuerFixture)) {
	file := os.Getenv("A_SIGNING_MYSQL_CREDENTIALS_FILE")
	expectedUUID := os.Getenv("A_SIGNING_MYSQL_SERVER_UUID")
	if file == "" {
		t.Skip("opt-in pinned disposable local MySQL required")
	}
	if expectedUUID == "" {
		t.Fatal("independent local server UUID pin required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var credentials struct {
		Host, User, Password string
		Port                 int
	}
	private, err := os.ReadFile(file)
	if err != nil || len(private) > 4096 || json.Unmarshal(private, &credentials) != nil || credentials.Host != "127.0.0.1" {
		clear(private)
		t.Fatal("local credentials unavailable")
	}
	clear(private)
	cfg := mysql.NewConfig()
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(credentials.Host, strconv.Itoa(credentials.Port))
	cfg.User = credentials.User
	cfg.Passwd = credentials.Password
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.MultiStatements = true
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 15 * time.Second
	cfg.WriteTimeout = 15 * time.Second
	cfg.Params = map[string]string{"time_zone": "'+00:00'"}
	root, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal("local root fixture unavailable")
	}
	t.Cleanup(func() { root.Close() })
	var uuid string
	if root.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&uuid) != nil || uuid != expectedUUID {
		t.Fatal("local MySQL UUID mismatch")
	}
	var entropy [12]byte
	rand.Read(entropy[:])
	run := hex.EncodeToString(entropy[:])
	database, user := "ad_a_controller_"+run, "ad_a_ctl_"+run[:16]
	if _, err = root.ExecContext(ctx, "CREATE DATABASE `"+database+"`"); err != nil {
		t.Fatal(err)
	}
	cfg.DBName = database
	owner, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Close() })
	if _, err = owner.ExecContext(ctx, "CREATE TABLE _ad_a_controller_marker(run_id VARCHAR(64) PRIMARY KEY);INSERT INTO _ad_a_controller_marker VALUES ('"+run+"')"); err != nil {
		t.Fatal(err)
	}
	createdUser := false
	t.Cleanup(func() {
		clean, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var gotUUID, marker string
		if root.QueryRowContext(clean, "SELECT @@server_uuid").Scan(&gotUUID) != nil || gotUUID != expectedUUID || owner.QueryRowContext(clean, "SELECT run_id FROM _ad_a_controller_marker").Scan(&marker) != nil || marker != run {
			t.Error("controller fixture cleanup owner mismatch; retained")
			return
		}
		if createdUser {
			if _, e := root.ExecContext(clean, "DROP USER '"+user+"'@'127.0.0.1'"); e != nil {
				t.Error("owned controller user cleanup failed")
			}
		}
		if _, e := root.ExecContext(clean, "DROP DATABASE `"+database+"`"); e != nil {
			t.Error("owned controller schema cleanup failed")
		}
	})
	for _, ddl := range []string{
		`CREATE TABLE system_backup_v2_engine_bindings(scope VARCHAR(128) PRIMARY KEY,engine VARCHAR(32)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_gate(scope VARCHAR(128) PRIMARY KEY,phase VARCHAR(32),owner VARCHAR(128),fencing_token BIGINT UNSIGNED,generation BIGINT UNSIGNED) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_runtime_captures(task_public_id VARCHAR(128) PRIMARY KEY,application_scope VARCHAR(128),gate_generation BIGINT UNSIGNED,acquire_token BIGINT UNSIGNED,held_token BIGINT UNSIGNED,collectors_stopped_at DATETIME(6),source_resumed_at DATETIME(6),acquire_until DATETIME(6),hold_until DATETIME(6)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_maintenance_locks(origin_installation_id VARCHAR(128),scope VARCHAR(128),lock_name VARCHAR(128),gate_state VARCHAR(32),lock_owner VARCHAR(128),fencing_token BIGINT UNSIGNED,row_version BIGINT UNSIGNED,lease_expires_at DATETIME(6),absolute_hold_deadline_at DATETIME(6),PRIMARY KEY(origin_installation_id,scope,lock_name)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_installation_state(origin_installation_id VARCHAR(128) PRIMARY KEY,schema_version VARCHAR(64),row_version BIGINT UNSIGNED,active_config_version BIGINT UNSIGNED,last_effective_enabled BOOLEAN) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_configs(origin_installation_id VARCHAR(128),version BIGINT UNSIGNED,schema_version VARCHAR(64),enabled BOOLEAN,canonical_config_json MEDIUMBLOB,config_sha256 CHAR(64),config_size_bytes INT UNSIGNED,PRIMARY KEY(origin_installation_id,version)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_backups(origin_installation_id VARCHAR(128),public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,schema_version VARCHAR(64),task_type VARCHAR(32),request_id VARCHAR(128),status VARCHAR(32),controller_owner VARCHAR(128),row_version BIGINT UNSIGNED,controller_lease_expires_at DATETIME(6),deadline_at DATETIME(6),config_version BIGINT UNSIGNED,config_snapshot_json MEDIUMBLOB,config_snapshot_size_bytes INT UNSIGNED,config_snapshot_sha256 CHAR(64),maintenance_lock_owner VARCHAR(128),maintenance_fencing_token BIGINT UNSIGNED,PRIMARY KEY(origin_installation_id,public_id),UNIQUE KEY original_backup_public(public_id)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_attempts(target_type ENUM('backup') NOT NULL,target_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,phase ENUM('capture') NOT NULL,attempt_no INT UNSIGNED NOT NULL,status VARCHAR(32),row_version BIGINT UNSIGNED,PRIMARY KEY(target_type,target_public_id,attempt_no,phase)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
		`CREATE TABLE system_backup_v2_operations(origin_installation_id VARCHAR(128),target_type VARCHAR(32),target_public_id VARCHAR(128),operation_type VARCHAR(32),status VARCHAR(32)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_execution_inputs(origin_installation_id VARCHAR(128),task_public_id VARCHAR(128),task_type VARCHAR(32),profile_json MEDIUMBLOB,profile_sha256 CHAR(64),PRIMARY KEY(origin_installation_id,task_public_id,task_type)) ENGINE=InnoDB`,
		`CREATE TABLE system_backup_v2_execution_records(origin_installation_id VARCHAR(128),task_public_id VARCHAR(128),attempt_no INT UNSIGNED,phase VARCHAR(32),record_kind VARCHAR(32),payload_sha256 CHAR(64),key_ref VARCHAR(128),sealed_payload MEDIUMBLOB,PRIMARY KEY(origin_installation_id,task_public_id,attempt_no,phase,record_kind)) ENGINE=InnoDB`,
	} {
		if _, err = owner.ExecContext(ctx, ddl); err != nil {
			t.Fatal(err)
		}
	}
	runtimeDDL, e := os.ReadFile("../db/migrations/123_backup_v2_runtime_execution_journal.sql")
	if e != nil {
		t.Fatal(e)
	}
	runtimeParts := strings.SplitN(string(runtimeDDL), "CREATE TABLE IF NOT EXISTS system_backup_v2_runtime_captures", 2)
	if len(runtimeParts) != 2 {
		t.Fatal("runtime migration split changed")
	}
	if _, e = owner.ExecContext(ctx, runtimeParts[0]); e != nil {
		t.Fatal("actual runtime resource DDL failed", e)
	}
	coreDDL, e := os.ReadFile("../db/migrations/096_backup_v2_add_system_backup_control_metadata_core.sql")
	if e != nil {
		t.Fatal(e)
	}
	evidenceParts := strings.SplitN(string(coreDDL), "CREATE TABLE IF NOT EXISTS system_backup_v2_evidence (", 2)
	if len(evidenceParts) != 2 {
		t.Fatal("evidence migration start changed")
	}
	evidenceParts = strings.SplitN(evidenceParts[1], "CREATE TABLE IF NOT EXISTS system_backup_v2_evidence_chunks", 2)
	if len(evidenceParts) != 2 {
		t.Fatal("evidence migration end changed")
	}
	if _, e = owner.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS system_backup_v2_evidence ("+evidenceParts[0]); e != nil {
		t.Fatal("actual original evidence DDL failed", e)
	}
	for _, name := range []string{"125_backup_v2_job_key_use.sql", "131_backup_v2_formal_job_candidates.sql"} {
		ddl, e := os.ReadFile("../db/migrations/" + name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = owner.ExecContext(ctx, string(ddl)); e != nil {
			t.Fatal("actual key-use/candidate migration failed", e)
		}
	}
	for _, name := range []string{"127_backup_v2_kek_registry.sql", "128_backup_installation_kek_authority.sql"} {
		ddl, e := os.ReadFile("../db/migrations/" + name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = owner.ExecContext(ctx, string(ddl)); e != nil {
			t.Fatal(e)
		}
	}
	rand.Read(entropy[:])
	password := hex.EncodeToString(entropy[:])
	clear(entropy[:])
	if _, err = root.ExecContext(ctx, "CREATE USER '"+user+"'@'127.0.0.1' IDENTIFIED BY '"+password+"'"); err != nil {
		t.Fatal("controller fixture user creation failed")
	}
	createdUser = true
	if _, err = root.ExecContext(ctx, "GRANT SELECT,INSERT,UPDATE ON `"+database+"`.* TO '"+user+"'@'127.0.0.1'"); err != nil {
		t.Fatal(err)
	}
	jobCfg := cfg.Clone()
	jobCfg.User = user
	jobCfg.Passwd = password
	password = ""
	jobCfg.MultiStatements = false
	db, err := sql.Open("mysql", jobCfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	var account string
	var now time.Time
	if db.QueryRowContext(ctx, "SELECT CURRENT_USER(),UTC_TIMESTAMP(6)").Scan(&account, &now) != nil {
		t.Fatal("controller SQL identity unavailable")
	}
	now = now.UTC().Truncate(time.Microsecond)
	var logins, decrypts int
	var loginTTL atomic.Int64
	loginTTL.Store(10)
	dek := bytes.Repeat([]byte{9}, 32)
	defer clear(dek)
	var workload a.ControllerVerifierWorkload
	var expectedGenerateContext string
	var captureLoginMu sync.Mutex
	var captureLoginHook func() error
	var generationCalls atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(wr http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/capture-jwt/login":
			logins++
			var req map[string]string
			if json.NewDecoder(r.Body).Decode(&req) != nil || req["role"] != "capture-generate-role" || req["jwt"] != "local-capture-projected-jwt-only" {
				t.Error("wrong independently issued capture login")
				wr.WriteHeader(403)
				return
			}
			captureLoginMu.Lock()
			hook := captureLoginHook
			captureLoginMu.Unlock()
			if hook != nil {
				if err := hook(); err != nil {
					t.Error("original owner login hook failed", err)
					wr.WriteHeader(403)
					return
				}
			}
			json.NewEncoder(wr).Encode(map[string]any{"auth": map[string]any{"client_token": "local-capture-generate-token-only", "token_type": "batch", "renewable": false, "lease_duration": 10, "policies": []string{"capture-generate-policy"}, "metadata": map[string]string{"role": "capture-generate-role", "namespace": "backup", "pod_uid": "capture-pod-uid", "service_account_uid": "capture-sa-uid"}}})
		case "/v1/transit/datakey/plaintext/original-key":
			generationCalls.Add(1)
			var originalReference string
			if db.QueryRowContext(r.Context(), `SELECT reference_state FROM system_backup_v2_kek_references WHERE installation_id=?`, "installation_test").Scan(&originalReference) != nil || originalReference != "unknown" {
				t.Error("provider called before committed original unknown reference")
				wr.WriteHeader(403)
				return
			}
			var req map[string]string
			if r.Header.Get("X-Vault-Token") != "local-capture-generate-token-only" || json.NewDecoder(r.Body).Decode(&req) != nil || req["context"] != expectedGenerateContext || req["key_version"] != "1" || req["bits"] != "256" {
				t.Error("wrong original Generate operation")
				wr.WriteHeader(403)
				return
			}
			json.NewEncoder(wr).Encode(map[string]any{"data": map[string]any{"plaintext": base64.StdEncoding.EncodeToString(dek), "ciphertext": "vault:v1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 60)), "key_version": 1}})
		case "/v1/auth/controller-jwt/login":
			logins++
			var req map[string]string
			if json.NewDecoder(r.Body).Decode(&req) != nil || req["role"] != "controller-unwrap-role" || req["jwt"] != "local-controller-projected-jwt-only" {
				t.Error("wrong controller login")
				wr.WriteHeader(403)
				return
			}
			json.NewEncoder(wr).Encode(map[string]any{"auth": map[string]any{"client_token": "local-controller-unwrap-token-only", "token_type": "batch", "renewable": false, "lease_duration": loginTTL.Load(), "policies": []string{"controller-unwrap-policy"}, "metadata": map[string]string{"role": "controller-unwrap-role", "namespace": workload.Namespace, "pod_uid": workload.PodUID, "service_account_uid": workload.ServiceAccountUID}}})
		case "/v1/transit/decrypt/original-key":
			decrypts++
			if r.Header.Get("X-Vault-Token") != "local-controller-unwrap-token-only" {
				t.Error("wrong controller credential")
				wr.WriteHeader(403)
				return
			}
			json.NewEncoder(wr).Encode(map[string]any{"data": map[string]any{"plaintext": base64.StdEncoding.EncodeToString(dek)}})
		default:
			t.Error("verifier attempted non-unwrap provider operation")
			wr.WriteHeader(403)
		}
	}))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	caHash := hash(ca)
	in := d.Input{Authority: d.Authority{InstallationID: "installation_test", TaskPublicID: "sbk_11111111-1111-4111-8111-111111111111", TaskType: "backup", RequestID: "original-request", ConfigVersion: 1, AttemptNo: 3, Phase: "capture", ClaimOwner: "original-controller", ClaimRowVersion: 11, MaintenanceFencingToken: 17, DeadlineAt: now.Add(2 * time.Minute)}, ConfigSnapshot: json.RawMessage(`{"local_source_fixture":true}`), ProfileID: "local-profile", ProfileRevision: strings.Repeat("a", 64), Backup: &d.BackupSpec{SourceOrchestrator: "kubernetes", SourceProfile: "cluster", MatrixKey: "k8s-cluster", DatasourceTopology: "in_cluster", Runner: "k8s", TaskPurpose: "functional_test", RequestedParts: []string{"workspace"}}}
	in.Authority.ConfigSHA256 = hash(in.ConfigSnapshot)
	in.Authority.MaintenanceOwner = in.Authority.TaskPublicID
	j := d.JobBinding{JobUnitKey: "workspace", Namespace: "backup", Name: "capture-workspace", UID: "22222222-2222-4222-8222-222222222222", Generation: 7, RelayIdentityRef: "original-relay", RelayIdentityVersion: "v1", RelayBoundAt: now, RelayExpiresAt: in.Authority.DeadlineAt}
	request := w.KeyRequest{Key: w.KeyBinding{Provider: "external-kms", IdentityHash: strings.Repeat("d", 64), RegistryVersion: "original-r1", ProviderKeyID: "original-key", ProviderVersion: "1"}, Context: w.KeyContext{InstallationID: in.Authority.InstallationID, BackupPublicID: in.Authority.TaskPublicID, AttemptNo: "3", Phase: "capture", Part: "workspace", PartIndex: "0", EnvelopeID: "original-envelope", CaptureContextHash: strings.Repeat("b", 64)}}
	expectedGenerateContext, _ = k.TransitContext(request)
	i := worker.Invocation{Request: worker.Request{Version: worker.Version, Operation: "capture-workspace", Binding: staging.Binding{BackupID: request.Context.BackupPublicID, Attempt: request.Context.AttemptNo, Path: "workspace", EnvelopeID: request.Context.EnvelopeID, CaptureContextHash: request.Context.CaptureContextHash}, Deadline: in.Authority.DeadlineAt, ArtifactName: "workspace.enc", MaxFiles: 100, MaxFileBytes: 2 << 20, MaxArchiveBytes: 4 << 20, MaxCompressedBytes: 2 << 20}, WorkspacePath: "/workspace", StagingPath: "/staging", ProviderKey: &k.Access{Request: request, Operation: k.Generate, Endpoint: server.URL, KeyName: "original-key"}, FormalCapture: &worker.FormalCaptureSpec{Version: worker.FormalCaptureVersion, ConfigSHA256: strings.Repeat("c", 64), EnvelopeName: "envelope.json", MaxFrames: 8}}
	if !worker.ValidateRecordedInvocation(i) {
		t.Fatal("invalid original invocation fixture")
	}
	seconds := int64(60)
	job := batchv1.Job{TypeMeta: metav1.TypeMeta{APIVersion: "batch/v1", Kind: "Job"}, ObjectMeta: metav1.ObjectMeta{Name: j.Name, Namespace: j.Namespace, Labels: map[string]string{kube.OwnerLabel: in.Authority.TaskPublicID}}, Spec: batchv1.JobSpec{ActiveDeadlineSeconds: &seconds, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{kube.OwnerLabel: in.Authority.TaskPublicID}}, Spec: corev1.PodSpec{ServiceAccountName: "capture-worker", RestartPolicy: corev1.RestartPolicyNever, Containers: []corev1.Container{{Name: "capture", Image: "test@sha256:" + strings.Repeat("b", 64)}}, Volumes: []corev1.Volume{{Name: "invocation", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "original-invocation"}}}}}}}}}
	jobRaw, _ := json.Marshal(job)
	jobIntent, err := kube.Intent("Job", &job)
	if err != nil || jobIntent.RequestSHA256 == hash(jobRaw) {
		t.Fatal("fixture must use actual normalized kube.Intent, with distinct SpecSHA/RequestSHA", err)
	}
	invRaw, _ := json.Marshal(i)
	profile := []byte(`{"local_profile":"original"}`)
	part := b.JobPart{Part: "workspace", Category: "workspace", InvocationSHA256: hash(invRaw), InvocationJSON: invRaw, InvocationConfigMap: "original-invocation", Intent: d.JobIntent{JobUnitKey: j.JobUnitKey, Namespace: j.Namespace, Name: j.Name, Generation: j.Generation, SpecJSON: jobRaw, SpecSHA256: hash(jobRaw)}}
	plan := aVerifierTaskPlan(t, in, part)
	keys := t.TempDir()
	recordKey := bytes.Repeat([]byte{7}, 32)
	defer clear(recordKey)
	os.WriteFile(filepath.Join(keys, "original-record"), recordKey, 0600)
	deployFile := filepath.Join(t.TempDir(), "deployment.json")
	deployBytes := []byte(`{"local_deployment_fixture":true}`)
	os.WriteFile(deployFile, deployBytes, 0600)
	forwardGrant := c.ExecutionGrant{Version: "system-backup-execution-grant.v1", InstallationID: in.Authority.InstallationID, ControllerOwner: in.Authority.ClaimOwner, DatabaseAccount: account, ServerUUID: uuid, Database: database, ConfigVersion: 1, ConfigSHA256: in.Authority.ConfigSHA256, ProfileSHA256: hash(profile), NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(5 * time.Minute), Actions: []string{"prepare", "capture", "issue_worker"}, RecordKeys: []c.ExecutionRecordKey{{Ref: "original-record", SHA256: hash(recordKey)}}, DeploymentConfigSHA256: hash(deployBytes), WorkerIssuerSHA256: strings.Repeat("a", 64)}
	public, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	payload, _ := json.Marshal(forwardGrant)
	envelope, _ := json.Marshal(map[string]string{"payload_base64": base64.StdEncoding.EncodeToString(payload), "signature_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))})
	clear(privateKey)
	forwardFile := filepath.Join(t.TempDir(), "forward.json")
	os.WriteFile(forwardFile, envelope, 0600)
	forward, err := c.NewPinnedExecutionIdentity(forwardFile, hash(envelope), keys, public)
	if err != nil {
		t.Fatal(err)
	}
	service := &DeploymentService{ForwardEnabled: true, Forward: forward, ConfigPath: deployFile, ConfigDigest: hash(deployBytes)}
	service.Config.InstallationID = in.Authority.InstallationID
	service.Config.ApplicationScope = "local-application"
	gate := service.captureGate(db)
	authority, records := gate.Authority, gate.Records
	workload = a.ControllerVerifierWorkload{Namespace: "controller", PodName: "controller-pod", PodUID: "verifier-pod-uid", ServiceAccountName: "controller-sa", ServiceAccountUID: "verifier-sa-uid", OwnerKind: "Deployment", OwnerUID: "controller-deployment-uid", ControllerOwner: in.Authority.ClaimOwner, ConfigVersion: 1, ConfigSHA256: in.Authority.ConfigSHA256}
	verifierGrant := a.ControllerVerifierGrant{Version: "system-backup-controller-verifier-grant.v1", InstallationID: in.Authority.InstallationID, Database: reg.DatabaseIdentity{ServerUUID: uuid, Database: database}, DatabaseAccount: account, Workload: workload, CaptureGrantSHA256: forward.GrantSHA256(), NotBefore: now.Add(-time.Minute), Until: now.Add(40 * time.Second)}
	verifierIssuer, verifierPrivate, _ := ed25519.GenerateKey(rand.Reader)
	grantRaw, _ := json.Marshal(verifierGrant)
	verifierEnvelope, _ := json.Marshal(a.SignedControllerVerifierGrant{Record: grantRaw, Signature: ed25519.Sign(verifierPrivate, append([]byte(a.ControllerVerifierGrantDomain), grantRaw...))})
	t.Cleanup(func() { clear(verifierPrivate) })
	verifierFile := filepath.Join(t.TempDir(), "independent-verifier.json")
	os.WriteFile(verifierFile, verifierEnvelope, 0600)
	workload.GrantSHA256 = hash(verifierEnvelope)
	ctrl := true
	kubeClient := fake.NewSimpleClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: workload.PodName, Namespace: workload.Namespace, UID: types.UID(workload.PodUID), OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "controller-rs", UID: "controller-rs-uid", Controller: &ctrl}}}, Spec: corev1.PodSpec{ServiceAccountName: workload.ServiceAccountName}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: workload.ServiceAccountName, Namespace: workload.Namespace, UID: types.UID(workload.ServiceAccountUID)}}, &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "controller-rs", Namespace: workload.Namespace, UID: "controller-rs-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "controller-deployment", UID: types.UID(workload.OwnerUID), Controller: &ctrl}}}}, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "controller-deployment", Namespace: workload.Namespace, UID: types.UID(workload.OwnerUID)}})
	ref := func(purpose, capability, identity string) reg.TypedReference {
		raw, _ := json.Marshal(map[string]string{"ref_kind": "external_kms_key", "purpose": purpose, "identity_hash": identity, "identity_version": "operation-r1", "description_redacted": "local original permission fixture", "kms_capability": capability, "provider_identity_hash": strings.Repeat("e", 64), "scope_hash": strings.Repeat("f", 64)})
		return reg.TypedReference{RawJSON: raw, SHA256: hash(raw)}
	}
	binding := reg.Binding{InstallationID: in.Authority.InstallationID, ConfigRef: reg.ReferencePin{IdentityHash: request.Key.IdentityHash, Version: request.Key.RegistryVersion}, Key: request.Key, Provider: reg.ProviderBinding{Endpoint: server.URL, KeyName: "original-key", ProviderIdentityHash: strings.Repeat("e", 64), ScopeHash: strings.Repeat("f", 64), CAPEMSHA256: caHash, CASource: reg.SourceRecord{SourceID: "original-ca", RecordID: "ca", RecordVersion: "v1", ContentSHA256: caHash}}, GenerateRef: ref("data_key_generation", "generate_data_key", strings.Repeat("1", 64)), UnwrapRef: ref("kek_unwrap", "unwrap_data_key", strings.Repeat("2", 64))}
	installationIssuer, installationKey, _ := ed25519.GenerateKey(rand.Reader)
	t.Cleanup(func() { clear(installationKey) })
	bindingBytes, _ := json.Marshal(binding)
	originalMapping := a.OriginalRecord{Binding: binding, Source: reg.SourceRecord{SourceID: "original-installation-owner", RecordID: "original-kek", RecordVersion: "v1", ContentSHA256: hash(bindingBytes)}, Revision: "owner-r1", NotBefore: now.Add(-time.Minute), Until: now.Add(5 * time.Minute)}
	originalWriter, err := a.NewInstallationAuthorityWriter(owner, binding.InstallationID, verifierGrant.Database, installationIssuer)
	if err != nil {
		t.Fatal(err)
	}
	putOriginal := func(record a.OriginalRecord, expected uint64) {
		t.Helper()
		raw, _ := json.Marshal(record)
		if version, err := originalWriter.Put(ctx, raw, ed25519.Sign(installationKey, append([]byte("system-backup-original-kek.v1\x00"), raw...)), expected); err != nil || version != expected+1 {
			t.Fatal("original installation owner write failed", err)
		}
	}
	putOriginal(originalMapping, 0)
	capRecord := a.ProviderCapabilityRecord{Facts: a.ProviderCapabilityFacts{Binding: binding, Operation: k.Unwrap, Permission: a.ProviderCapabilityPermission{Path: "transit/decrypt/original-key", ProviderVersion: "1", AuthMount: "controller-jwt", Role: "controller-unwrap-role", Policy: "controller-unwrap-policy", PolicySHA256: strings.Repeat("a", 64), RoleSHA256: strings.Repeat("b", 64), JWTTrustSHA256: strings.Repeat("c", 64), Reference: binding.UnwrapRef, ControllerVerifier: &workload}}, Source: reg.SourceRecord{SourceID: "original-provider-observer", RecordID: "sev_controller_unwrap", RecordVersion: "v1"}, Revision: "r1", NotBefore: now.Add(-time.Minute), Until: now.Add(time.Minute)}
	factsRaw, _ := json.Marshal(capRecord.Facts)
	capRecord.Source.ContentSHA256 = hash(factsRaw)
	capIssuer, capPrivate, _ := ed25519.GenerateKey(rand.Reader)
	capRaw, _ := json.Marshal(capRecord)
	capEnvelope, _ := json.Marshal(a.SignedProviderCapabilityRecord{Record: capRaw, Signature: ed25519.Sign(capPrivate, append([]byte(a.ProviderCapabilityDomain), capRaw...))})
	t.Cleanup(func() { clear(capPrivate) })
	capPin := a.ProviderCapabilityPin{Source: capRecord.Source, Issuer: capIssuer}
	dummyGenerate := capPin
	dummyGenerate.Source.RecordID = "sev_unused_generate"
	capabilities, err := a.NewSQLProviderCapabilityPreparation(db, verifierGrant.Database, binding.InstallationID, dummyGenerate, capPin)
	if err != nil {
		t.Fatal(err)
	}
	jwtFile := filepath.Join(t.TempDir(), "controller.jwt")
	os.WriteFile(jwtFile, []byte("local-controller-projected-jwt-only"), 0600)
	vcfg := a.ControllerVerifierConfig{Capabilities: capabilities, Binding: binding, CAPEM: ca, JWTFile: jwtFile, Workload: workload, Kubernetes: kubeClient, Authority: authority, Records: records, GrantMount: a.ControllerVerifierGrantMount{File: verifierFile, SHA256: workload.GrantSHA256, Issuer: verifierIssuer}, CaptureGrantSHA256: forward.GrantSHA256(), InstallationIssuer: installationIssuer}
	factory, err := a.NewControllerVerifierFactory(vcfg)
	if err != nil {
		t.Fatal("actual deploymentAuthorization + original Forward record keys + independent grant rejected", err)
	}
	bad := vcfg
	bad.Authority.Authorization = forward
	bad.Records.Authority = bad.Authority
	if _, err = a.NewControllerVerifierFactory(bad); err == nil {
		t.Fatal("bare forward identity bypassed deployment wrapper")
	}
	bad = vcfg
	bad.Workload.GrantSHA256 = forward.GrantSHA256()
	if _, err = a.NewControllerVerifierFactory(bad); err == nil {
		t.Fatal("capture grant reused as independent verifier grant")
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := owner.ExecContext(ctx, q, args...); e != nil {
			t.Fatal("original controller SQL fixture insert failed", e)
		}
	}
	exec(`INSERT INTO system_backup_v2_engine_bindings VALUES ('installation','v2')`)
	exec(`INSERT INTO system_backup_gate VALUES (?,'held',?,19,17)`, authority.ApplicationScope, in.Authority.TaskPublicID)
	exec(`INSERT INTO system_backup_v2_runtime_captures VALUES (?,?,17,18,19,NULL,NULL,?,?)`, in.Authority.TaskPublicID, authority.ApplicationScope, in.Authority.DeadlineAt, in.Authority.DeadlineAt)
	exec(`INSERT INTO system_backup_v2_maintenance_locks VALUES (?,?,'system_backup_capture_gate','held',?,17,1,?,?)`, in.Authority.InstallationID, c.CaptureGateScope, in.Authority.TaskPublicID, in.Authority.DeadlineAt, in.Authority.DeadlineAt)
	exec(`INSERT INTO system_backup_v2_installation_state VALUES (?,'system-backup-installation-state.v1',1,1,TRUE)`, in.Authority.InstallationID)
	exec(`INSERT INTO system_backup_v2_configs VALUES (?,1,'system-backup-config.v1',TRUE,?,?,?)`, in.Authority.InstallationID, []byte(in.ConfigSnapshot), in.Authority.ConfigSHA256, len(in.ConfigSnapshot))
	exec(`INSERT INTO system_backup_v2_backups VALUES (?,?,'system-backup-task.v1','backup',?,'capturing',?,11,?,?,1,?,?,?, ?,17)`, in.Authority.InstallationID, in.Authority.TaskPublicID, in.Authority.RequestID, in.Authority.ClaimOwner, in.Authority.DeadlineAt, in.Authority.DeadlineAt, []byte(in.ConfigSnapshot), len(in.ConfigSnapshot), in.Authority.ConfigSHA256, in.Authority.TaskPublicID)
	exec(`INSERT INTO system_backup_v2_attempts VALUES ('backup',?,'capture',3,'running',1)`, in.Authority.TaskPublicID)
	exec(`INSERT INTO system_backup_v2_execution_inputs VALUES (?,?,'backup',?,?)`, in.Authority.InstallationID, in.Authority.TaskPublicID, profile, hash(profile))
	var sealed bytes.Buffer
	if err = staging.Seal(ctx, &sealed, recordKey, staging.Binding{BackupID: in.Authority.TaskPublicID, Attempt: "3", Path: in.Authority.InstallationID + "/capture/plan", CaptureContextHash: in.Authority.ConfigSHA256, EnvelopeID: plan.SHA256}, func(dst io.Writer) error { _, e := dst.Write(plan.CanonicalJSON); return e }); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO system_backup_v2_execution_records VALUES (?,?,3,'capture','plan',?,'original-record',?)`, in.Authority.InstallationID, in.Authority.TaskPublicID, plan.SHA256, sealed.Bytes())
	candidateHash := strings.Repeat("d", 64)
	exec(`INSERT INTO system_backup_v2_runtime_resources(task_public_id,resource_kind,namespace_name,resource_name,resource_owner,request_sha256,request_json,row_version,create_dispatched,observed_uid,resource_version,lifecycle,attempt_no,phase,candidate_cipher,candidate_key_ref,candidate_sha256) VALUES (?,'Job',?,?,?,?,?,1,TRUE,?,'1','ready',3,'capture',?,'original-record',?)`, in.Authority.TaskPublicID, j.Namespace, j.Name, in.Authority.TaskPublicID, jobIntent.RequestSHA256, jobIntent.RequestJSON, j.UID, []byte("local-original-candidate-component-fixture"), candidateHash)
	core, _ := json.Marshal(binding)
	semantic := binding
	for _, r := range []*reg.TypedReference{&semantic.GenerateRef, &semantic.UnwrapRef} {
		var value map[string]json.RawMessage
		json.Unmarshal(r.RawJSON, &value)
		delete(value, "description_redacted")
		r.RawJSON, _ = json.Marshal(value)
		r.SHA256 = ""
	}
	semanticRaw, _ := json.Marshal(semantic)
	fingerprint, _ := reg.BindingFingerprint(binding)
	exec(`INSERT INTO system_backup_v2_kek_bindings(installation_id,identity_hash,registry_version,binding_sha256,core_sha256,core_json) VALUES (?,?,?,?,?,?)`, in.Authority.InstallationID, binding.Key.IdentityHash, binding.Key.RegistryVersion, fingerprint, hash(semanticRaw), core)
	exec(`INSERT INTO system_backup_v2_evidence(public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,inline_payload,content_checksum,content_size_bytes,media_type,encryption,redaction_classification,observed_health,expires_at) VALUES (?,'system',?,'capability_snapshot','inline',?,?,?,'application/json','none','internal','healthy',?)`, capRecord.Source.RecordID, in.Authority.InstallationID, capEnvelope, hash(capEnvelope), len(capEnvelope), capRecord.Until)
	if len(exercises) > 0 {
		for _, exercise := range exercises {
			exercise(aOriginalIssuerFixture{ctx: ctx, db: db, owner: owner, cfg: vcfg, in: in, job: j, invocation: i, unwrapPin: capPin, original: originalMapping, putOriginal: putOriginal, dek: dek, generationCalls: generationCalls.Load, onCaptureLogin: func(hook func() error) { captureLoginMu.Lock(); captureLoginHook = hook; captureLoginMu.Unlock() }, updateOriginal: func(record a.OriginalRecord, expected uint64) error {
				raw, _ := json.Marshal(record)
				_, err := originalWriter.Put(ctx, raw, ed25519.Sign(installationKey, append([]byte("system-backup-original-kek.v1\x00"), raw...)), expected)
				return err
			}})
		}
		return
	}
	scope := a.ControllerVerifierCandidate{Input: in, Job: j, Invocation: i, CandidateSHA256: candidateHash, CaptureGrantSHA256: forward.GrantSHA256()}
	verifier, err := factory.ForCandidate(ctx, scope)
	if err != nil {
		t.Fatal("automatic original controller candidate scope rejected", err)
	}
	defer verifier.Close()
	wrongIssuer := vcfg
	wrongIssuer.InstallationIssuer, _, _ = ed25519.GenerateKey(rand.Reader)
	wrongFactory, err := a.NewControllerVerifierFactory(wrongIssuer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = wrongFactory.ForCandidate(ctx, scope); err == nil || logins != 0 {
		t.Fatal("substituted installation issuer admitted")
	}
	if !verifier.ValidUntil().Equal(verifierGrant.Until) {
		t.Fatal("independent original grant did not bound complete verification")
	}
	wrapped := w.WrappedKey{Request: request, Algorithm: "provider-native", Ciphertext: []byte("vault:v1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 60)))}
	called := 0
	if err = verifier.Unwrap(ctx, request, wrapped, func(key []byte) error {
		called++
		if !bytes.Equal(key, dek) {
			t.Fatal("wrong DEK")
		}
		derived, stop := context.WithCancel(ctx)
		defer stop()
		return verifier.Recheck(derived)
	}); err != nil {
		t.Fatal("actual deployment wrapper/SQL/source/independent JWT unwrap failed", err)
	}
	if called != 1 || logins != 1 || decrypts != 1 || verifier.Workload().GrantSHA256 == forward.GrantSHA256() {
		t.Fatal("wrong original verifier use", called, logins, decrypts)
	}
	service.ForwardEnabled = false
	if err = verifier.Unwrap(ctx, request, wrapped, func([]byte) error { called++; return nil }); err == nil || logins != 1 {
		t.Fatal("disabled deployment wrapper bypassed by independent grant")
	}
	service.ForwardEnabled = true
	exec(`UPDATE system_backup_v2_runtime_resources SET request_sha256=?`, hash(jobRaw))
	beforeWrongRequest := logins
	if err = verifier.Recheck(ctx); err == nil {
		t.Fatal("plan SpecSHA substituted for normalized runtime RequestSHA")
	}
	if _, err = factory.ForCandidate(ctx, scope); err == nil || logins != beforeWrongRequest {
		t.Fatal("new verifier accepted substituted runtime RequestSHA")
	}
	exec(`UPDATE system_backup_v2_runtime_resources SET request_sha256=?`, jobIntent.RequestSHA256)
	exec(`UPDATE system_backup_v2_runtime_resources SET candidate_sha256=?`, strings.Repeat("e", 64))
	if err = verifier.Recheck(ctx); err == nil {
		t.Fatal("replaced original candidate accepted")
	}
	exec(`UPDATE system_backup_v2_runtime_resources SET candidate_sha256=?`, candidateHash)
	wrong := scope
	wrong.Input.Authority.AttemptNo++
	if _, err = factory.ForCandidate(ctx, wrong); err == nil {
		t.Fatal("cross-attempt candidate scope accepted")
	}
	exec(`INSERT INTO system_backup_v2_operations VALUES (?,'backup',?,'cancel','pending')`, in.Authority.InstallationID, in.Authority.TaskPublicID)
	if err = verifier.Unwrap(ctx, request, wrapped, func([]byte) error { called++; return nil }); err == nil || logins != 1 {
		t.Fatal("canceled original task reached provider")
	}
	if called != 1 {
		t.Fatal("failed scope exposed DEK")
	}
	exec(`DELETE FROM system_backup_v2_operations`)
	if !unwrapOnly {
		t.Run("independent_grant_expires_during_use", func(t *testing.T) {
			// Reissue both independent ORIGINAL owners' signed fixture records;
			// never mutate a grant hash in place or substitute an ACL for authority.
			shortGrant := verifierGrant
			shortGrant.Until = time.Now().UTC().Add(3500 * time.Millisecond)
			grantRaw, _ := json.Marshal(shortGrant)
			grantEnvelope, _ := json.Marshal(a.SignedControllerVerifierGrant{Record: grantRaw, Signature: ed25519.Sign(verifierPrivate, append([]byte(a.ControllerVerifierGrantDomain), grantRaw...))})
			grantFile := filepath.Join(t.TempDir(), "short-original-verifier.json")
			if err := os.WriteFile(grantFile, grantEnvelope, 0600); err != nil {
				t.Fatal(err)
			}
			shortWorkload := workload
			shortWorkload.GrantSHA256 = hash(grantEnvelope)
			shortCap := capRecord
			shortCap.Facts.Permission.ControllerVerifier = &shortWorkload
			facts, _ := json.Marshal(shortCap.Facts)
			shortCap.Source.ContentSHA256 = hash(facts)
			raw, _ := json.Marshal(shortCap)
			capEnvelope, _ := json.Marshal(a.SignedProviderCapabilityRecord{Record: raw, Signature: ed25519.Sign(capPrivate, append([]byte(a.ProviderCapabilityDomain), raw...))})
			exec(`UPDATE system_backup_v2_evidence SET inline_payload=?,content_checksum=?,content_size_bytes=? WHERE public_id=?`, capEnvelope, hash(capEnvelope), len(capEnvelope), shortCap.Source.RecordID)
			shortCaps, err := a.NewSQLProviderCapabilityPreparation(db, shortGrant.Database, binding.InstallationID, dummyGenerate, a.ProviderCapabilityPin{Source: shortCap.Source, Issuer: capIssuer})
			if err != nil {
				t.Fatal(err)
			}
			shortCfg := vcfg
			shortCfg.Capabilities, shortCfg.Workload = shortCaps, shortWorkload
			shortCfg.GrantMount = a.ControllerVerifierGrantMount{File: grantFile, SHA256: shortWorkload.GrantSHA256, Issuer: verifierIssuer}
			shortFactory, err := a.NewControllerVerifierFactory(shortCfg)
			if err != nil {
				t.Fatal(err)
			}
			shortVerifier, err := shortFactory.ForCandidate(ctx, scope)
			if err != nil {
				t.Fatal(err)
			}
			defer shortVerifier.Close()
			loginTTL.Store(1)
			defer loginTTL.Store(10)
			g, err := shortVerifier.Resolve(ctx, shortVerifier.ExpectedAccess())
			if err != nil {
				t.Fatal("short independent grant still admits bounded login", err)
			}
			clear(g.Secret)
			if !g.ExpiresAt.Equal(shortGrant.Until) || g.CredentialExpiresAt.After(shortGrant.Until) || g.NotBefore.Before(shortGrant.NotBefore) || !shortVerifier.ValidUntil().Equal(shortGrant.Until) {
				t.Fatal("provider credential or DEK grant escaped independent authorization window")
			}
			// The production D adapter must use this context for candidate streams
			// and private custody I/O, so a blocked read ends BEFORE callback return.
			streamCtx, stop := context.WithDeadline(ctx, shortVerifier.ValidUntil())
			defer stop()
			entered, canceledInside := false, false
			err = shortVerifier.Unwrap(streamCtx, request, wrapped, func(key []byte) error {
				entered = true
				if !bytes.Equal(key, dek) {
					t.Fatal("wrong bounded DEK")
				}
				<-streamCtx.Done()
				canceledInside = streamCtx.Err() == context.DeadlineExceeded
				if shortVerifier.Recheck(streamCtx) == nil {
					t.Fatal("expired scope rechecked during callback")
				}
				return streamCtx.Err()
			})
			if err == nil || !entered || !canceledInside {
				t.Fatal("independent deadline failed to cancel active read", err, entered, canceledInside)
			}
			beforeLogin := logins
			if err = shortVerifier.Unwrap(ctx, request, wrapped, func([]byte) error { t.Fatal("expired callback"); return nil }); err == nil || logins != beforeLogin {
				t.Fatal("expired original verifier grant reached login")
			}
		})
	}
	// Restore the original capability after the short-grant fixture. The real
	// owner writer advances the SAME KEK fence without touching registry flags.
	exec(`UPDATE system_backup_v2_evidence SET inline_payload=?,content_checksum=?,content_size_bytes=? WHERE public_id=?`, capEnvelope, hash(capEnvelope), len(capEnvelope), capRecord.Source.RecordID)
	nextVersion := uint64(1)
	if !unwrapOnly {
		originalMapping.GenerateRevoked = true
		originalMapping.Revision = "owner-r2"
		putOriginal(originalMapping, 1)
		nextVersion = 2
		beforeGenerateOnly := logins
		if err = verifier.Unwrap(ctx, request, wrapped, func(key []byte) error {
			if !bytes.Equal(key, dek) {
				t.Fatal("wrong retained DEK")
			}
			return nil
		}); err != nil || logins != beforeGenerateOnly+1 {
			t.Fatal("Generate-only revocation wrongly disabled retained Unwrap", err)
		}
		newVerifier, err := factory.ForCandidate(ctx, scope)
		if err != nil {
			t.Fatal("new Unwrap scope after Generate-only revocation", err)
		}
		newVerifier.Close()
	}
	originalMapping.UnwrapRevoked = true
	originalMapping.Revision = "owner-r3"
	putOriginal(originalMapping, nextVersion)
	var registryUnwrapRevoked bool
	if db.QueryRowContext(ctx, `SELECT unwrap_revocation_json IS NOT NULL FROM system_backup_v2_kek_bindings WHERE installation_id=? AND identity_hash=? AND registry_version=?`, binding.InstallationID, binding.Key.IdentityHash, binding.Key.RegistryVersion).Scan(&registryUnwrapRevoked) != nil || registryUnwrapRevoked {
		t.Fatal("fixture must keep registry revocation empty to verify original owner enforcement")
	}
	beforeUnwrapRevocation := logins
	if err = verifier.Unwrap(ctx, request, wrapped, func([]byte) error { t.Fatal("revoked Unwrap exposed DEK"); return nil }); err == nil || logins != beforeUnwrapRevocation {
		t.Fatal("existing verifier ignored original owner Unwrap revocation")
	}
	if _, err = factory.ForCandidate(ctx, scope); err == nil || logins != beforeUnwrapRevocation {
		t.Fatal("new verifier ignored original owner Unwrap revocation")
	}
}

func aVerifierTaskPlan(t *testing.T, in d.Input, part b.JobPart) d.Plan {
	t.Helper()
	au := in.Authority
	source := json.RawMessage(`{"local_original_inventory":true}`)
	type binding struct {
		Installation, Task, Kind, Request, ConfigSHA, Phase, Profile, Revision string
		ConfigVersion, Attempt                                                 uint64
		Deadline                                                               time.Time
	}
	inner := struct {
		Version             string
		Binding             binding
		LocalFlowGeneration int64
		Discovery           b.Discovery
	}{b.PlanVersion, binding{au.InstallationID, au.TaskPublicID, au.TaskType, au.RequestID, au.ConfigSHA256, au.Phase, in.ProfileID, in.ProfileRevision, au.ConfigVersion, au.AttemptNo, au.DeadlineAt}, 1, b.Discovery{Writers: []b.FrozenWriter{}, Parts: []b.JobPart{part}, Source: source, SourceSHA256: hash(source), HoldUntil: au.DeadlineAt}}
	innerRaw, _ := json.Marshal(inner)
	if _, err := b.DescribePlan(in, d.Plan{SchemaVersion: b.PlanVersion, CanonicalJSON: innerRaw, SHA256: hash(innerRaw)}); err != nil {
		t.Fatal("original B plan fixture rejected", err)
	}
	backup, _ := json.Marshal(in.Backup)
	type taskBinding struct {
		InstallationID   string    `json:"installation_id"`
		PublicID         string    `json:"task_public_id"`
		Kind             string    `json:"task_type"`
		RequestID        string    `json:"request_id"`
		ConfigVersion    uint64    `json:"config_version"`
		ConfigSHA256     string    `json:"config_sha256"`
		AttemptNo        uint64    `json:"attempt_no"`
		Phase            string    `json:"phase"`
		ProfileID        string    `json:"profile_id"`
		ProfileRevision  string    `json:"profile_revision"`
		Deadline         time.Time `json:"deadline_at"`
		BackupSpecSHA256 string    `json:"backup_spec_sha256"`
	}
	outer := struct {
		Version      string      `json:"schema_version"`
		Binding      taskBinding `json:"binding"`
		InnerVersion string      `json:"runner_plan_version"`
		InnerSHA256  string      `json:"runner_plan_sha256"`
		InnerBytes   []byte      `json:"runner_plan_bytes"`
	}{d.TaskPlanVersion, taskBinding{au.InstallationID, au.TaskPublicID, au.TaskType, au.RequestID, au.ConfigVersion, au.ConfigSHA256, au.AttemptNo, au.Phase, in.ProfileID, in.ProfileRevision, au.DeadlineAt, hash(backup)}, b.PlanVersion, hash(innerRaw), innerRaw}
	raw, _ := json.Marshal(outer)
	plan := d.Plan{SchemaVersion: d.TaskPlanVersion, CanonicalJSON: raw, SHA256: hash(raw)}
	if _, err := d.UnwrapTaskPlan(in, plan, b.PlanVersion); err != nil {
		t.Fatal(err)
	}
	return plan
}
