package systembackupapi

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	backup "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/control"
	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/quiesce"
	"clawreef/internal/systembackup/scope"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	execution "clawreef/internal/systembackupexecution"
	read "clawreef/internal/systembackupread"
	security "clawreef/internal/systembackupsecurity"
	"github.com/go-sql-driver/mysql"
	appsv1 "k8s.io/api/apps/v1"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

type nativeLostCreate struct {
	Base             http.RoundTripper
	Enabled          bool
	Dropped, Created atomic.Int64
}

func (t *nativeLostCreate) RoundTrip(r *http.Request) (*http.Response, error) {
	response, e := t.Base.RoundTrip(r)
	if e == nil && response.StatusCode == 201 && r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/jobs") {
		t.Created.Add(1)
		if t.Enabled && t.Dropped.CompareAndSwap(0, 1) {
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			return nil, errors.New("synthetic lost original Job create acknowledgement")
		}
	}
	return response, e
}

type nativeProofInspector struct {
	Client         kubernetes.Interface
	Config         *rest.Config
	Namespace, Pod string
	Calls          atomic.Int64
}

func (i *nativeProofInspector) Inspect(ctx context.Context, id string) ([]byte, error) {
	i.Calls.Add(1)
	req := i.Client.CoreV1().RESTClient().Post().Resource("pods").Name(i.Pod).Namespace(i.Namespace).SubResource("exec").VersionedParams(&corev1.PodExecOptions{Container: "proof", Command: []string{"/crictl", "--runtime-endpoint", "unix:///runtime/containerd.sock", "inspect", "--output", "json", id}, Stdout: true, Stderr: true}, scheme.ParameterCodec)
	exec, e := remotecommand.NewSPDYExecutor(i.Config, http.MethodPost, req.URL())
	if e != nil {
		return nil, e
	}
	var out, stderr bytes.Buffer
	e = exec.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: &out, Stderr: &stderr})
	if e != nil {
		return nil, e
	}
	return out.Bytes(), nil
}

type nativeGateProbe struct{ CheckFn func(context.Context) error }

type nativeTraceRunner struct {
	d.Runner
	T *testing.T
}

type nativeTraceAuthorizer struct {
	Owner *execution.PublicJobOwner
	T     *testing.T
}

type nativeTracePorts struct {
	d.Ports
	T *testing.T
}

type nativeTraceSource struct {
	flow.Writer
	T *testing.T
}

func (w nativeTraceSource) Resume(ctx context.Context, s flow.State) error {
	e := w.Writer.Resume(ctx, s)
	w.T.Log("physical source resume", e)
	return e
}

func (p nativeTracePorts) BeforeResume(ctx context.Context, a d.Authority) error {
	e := p.Ports.(d.ResumeBarrier).BeforeResume(ctx, a)
	p.T.Log("resume barrier", e)
	return e
}
func (p nativeTracePorts) StopJob(ctx context.Context, a d.Authority, binding d.JobBinding) error {
	e := p.Ports.StopJob(ctx, a, binding)
	p.T.Log("collector stop", e)
	return e
}
func (p nativeTracePorts) Resumed(ctx context.Context, a d.Authority, id string) error {
	e := p.Ports.Resumed(ctx, a, id)
	p.T.Log("source resumed receipt", e)
	return e
}

func (a nativeTraceAuthorizer) Authorize(ctx context.Context, peer string, req worker.ControlRequest) (worker.Lease, error) {
	v, e := a.Owner.Authorize(ctx, peer, req)
	a.T.Log("worker control", req.Action, req.Point, "outcome", e)
	return v, e
}

func (r nativeTraceRunner) Capture(ctx context.Context, in d.Input, p d.Plan, ports d.Ports) ([]d.ModuleResult, error) {
	v, e := r.Runner.Capture(ctx, in, p, ports)
	r.T.Log("B Capture outcome", e, "parts", len(v))
	return v, e
}
func (r nativeTraceRunner) Recover(ctx context.Context, in d.Input, p d.Plan, ports d.Ports) (d.RecoveryResult, error) {
	v, e := r.Runner.Recover(ctx, in, p, ports)
	r.T.Log("B Recover outcome", e, "stopped", v.CollectorsStopped, "resumed", v.WritersResumed)
	return v, e
}

func (p nativeGateProbe) Check(ctx context.Context) error { return p.CheckFn(ctx) }

type nativeFaultProof struct {
	Real    execution.StopProof
	Unknown atomic.Bool
}

func (p *nativeFaultProof) Confirm(ctx context.Context, pods []quiesce.PodIdentity) error {
	if e := p.Real.Confirm(ctx, pods); e != nil {
		return e
	}
	if p.Unknown.Load() {
		return flow.ErrQuiesce
	}
	return nil
}

// This runs INSIDE the task-owned kind test Pod with real MySQL, containerd,
// Kubernetes, mTLS and the compiled backup-worker. The source is a controlled
// continuous file writer, not an OpenClaw/model semantics acceptance fixture.
func TestPublicCaptureNativeMySQLKubernetes(t *testing.T) {
	if os.Getenv("TEST_PUBLIC_CAPTURE_NATIVE") != "m0m2-20261028" {
		t.Skip("requires explicitly provisioned task-owned native cluster")
	}
	for _, scenario := range []string{"capture", "lost-create-response", "unknown-stop-recovery", "prepare-revoked", "release-atomic", "legacy-release-gap", "binding-write-outage", "production-entry", "production-recovery-only", "production-delayed-exit", "prepare-cancel", "capture-cancel", "acquire-atomic"} {
		t.Run(scenario, func(t *testing.T) { testPublicNativeScenario(t, scenario) })
	}
}

func testPublicNativeScenario(t *testing.T, scenario string) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	cfg, e := rest.InClusterConfig()
	if e != nil {
		t.Fatal(e)
	}
	cfg.Timeout = 10 * time.Second
	cfg.QPS = 50
	cfg.Burst = 100
	client, e := kubernetes.NewForConfig(cfg)
	if e != nil {
		t.Fatal(e)
	}
	lost := &nativeLostCreate{Enabled: scenario == "lost-create-response"}
	dynamicCfg := rest.CopyConfig(cfg)
	dynamicCfg.WrapTransport = func(rt http.RoundTripper) http.RoundTripper { lost.Base = rt; return lost }
	dyn, e := dynamic.NewForConfig(dynamicCfg)
	if e != nil {
		t.Fatal(e)
	}
	nsName := os.Getenv("NATIVE_BACKUP_NAMESPACE")
	image := os.Getenv("NATIVE_BACKUP_IMAGE")
	workerImage := os.Getenv("NATIVE_BACKUP_WORKER_IMAGE")
	if workerImage == "" {
		workerImage = image
	}
	podIP := os.Getenv("POD_IP")
	nodeName := os.Getenv("NODE_NAME")
	if nsName != "cm-backup-m0m2-native" || !strings.Contains(image, "@sha256:") || !strings.Contains(workerImage, "@sha256:") || net.ParseIP(podIP) == nil || nodeName == "" {
		t.Fatal("native fixture identity missing")
	}
	ns, e := client.CoreV1().Namespaces().Get(ctx, nsName, metav1.GetOptions{})
	if e != nil {
		t.Fatal(e)
	}
	node, e := client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if e != nil {
		t.Fatal(e)
	}
	sa, e := client.CoreV1().ServiceAccounts(nsName).Get(ctx, "capture-worker", metav1.GetOptions{})
	if e != nil {
		t.Fatal(e)
	}
	db, legacy := submissionMySQL(t)
	stopCapacity := nativeSyntheticCapacity(t, db, legacy.capacityFile)
	defer stopCapacity()
	if _, e = db.Exec("UPDATE system_backup_v2_execution_readiness SET execution_protocol='public-v1',supported_parts='workspace',acceptance_ready=FALSE,expires_at=TIMESTAMPADD(SECOND,60,checked_at)"); e != nil {
		t.Fatal(e)
	}
	taskWriter, e := NewAdmittedTaskWriter(testExecutionProfile(), legacy.capacityFile, true)
	if e != nil {
		t.Fatal(e)
	}
	handler, operator, _ := liveAdmissionHTTP(t, db, taskWriter)
	handler.application = handler.application.(*SQLApplication).WithCancellationCapacityReport(legacy.capacityFile)
	request := httptest.NewRequest(http.MethodPost, "https://example.invalid/api/v1/admin/system-backups", strings.NewReader(`{"requested_parts":["workspace"],"task_purpose":"functional_test"}`))
	request.TLS = &tls.ConnectionState{}
	request.Header.Set("Authorization", "Bearer "+operator)
	request.Header.Set("Idempotency-Key", "native-m2-functional-0001")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.Create(response, request, read.BackupTask, "m2-native-request")
	if response.Code != 202 {
		t.Fatal(response.Code, response.Body.String())
	}
	var task, server, database, configHash string
	if e = db.QueryRow("SELECT public_id,config_snapshot_sha256 FROM system_backup_v2_backups").Scan(&task, &configHash); e != nil {
		t.Fatal(e)
	}
	if e = db.QueryRow("SELECT @@server_uuid,DATABASE()").Scan(&server, &database); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		var status, phase string
		var n int
		db.QueryRow("SELECT status FROM system_backup_v2_backups WHERE public_id=?", task).Scan(&status)
		db.QueryRow("SELECT phase FROM system_backup_gate WHERE scope='installation'").Scan(&phase)
		db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE task_public_id=?", task).Scan(&n)
		t.Log("final native facts", status, phase, "resource rows", n)
		rows, z := db.Query("SELECT writer_id,paused,resumed FROM system_backup_v2_runtime_writers WHERE task_public_id=?", task)
		if z == nil {
			defer rows.Close()
			for rows.Next() {
				var id string
				var paused, resumed bool
				rows.Scan(&id, &paused, &resumed)
				t.Log("writer", id, "paused", paused, "resumed", resumed)
			}
		}
	})
	account := "m2_" + strings.ReplaceAll(task[4:16], "-", "")
	sourceUser := account + "s"
	for _, user := range []string{account, sourceUser} {
		if _, e = db.Exec("CREATE USER '" + user + "'@'%' IDENTIFIED BY 'synthetic-native-only'"); e != nil {
			t.Fatal(e)
		}
		u := user
		t.Cleanup(func() { db.Exec("DROP USER '" + u + "'@'%'") })
	}
	if strings.HasPrefix(scenario, "production-") {
		grants, z := c.PublicCaptureGrantSQL(database, account, "%", true)
		if z != nil {
			t.Fatal(z)
		}
		for _, statement := range grants {
			if _, z = db.Exec(statement); z != nil {
				t.Fatal("install exact public control grants", z)
			}
		}
	} else if _, e = db.Exec("GRANT ALL PRIVILEGES ON `" + database + "`.* TO '" + account + "'@'%'"); e != nil {
		t.Fatal(e)
	}
	for _, table := range []string{"users", "instances"} {
		if _, e = db.Exec("GRANT SELECT ON `" + database + "`." + table + " TO '" + sourceUser + "'@'%'"); e != nil {
			t.Fatal(e)
		}
	}
	var projectionFault atomic.Bool
	projectionFault.Store(scenario == "release-atomic" || scenario == "acquire-atomic")
	open := func(user string) *sql.DB {
		q := mysql.Config{User: user, Passwd: "synthetic-native-only", Net: "tcp", Addr: net.JoinHostPort(os.Getenv("TEST_SYSTEM_BACKUP_MYSQL_HOST"), os.Getenv("TEST_SYSTEM_BACKUP_MYSQL_PORT")), DBName: database, ParseTime: true, AllowNativePasswords: true}
		q.Loc = time.UTC
		connector, z := mysql.NewConnector(&q)
		if z != nil {
			t.Fatal(z)
		}
		var conn *sql.DB
		if user == account {
			conn = sql.OpenDB(nativeProjectionConnector{Connector: connector, Fail: &projectionFault, BlockBinding: scenario == "binding-write-outage", BlockAcquire: scenario == "acquire-atomic"})
		} else {
			conn = sql.OpenDB(connector)
		}
		t.Cleanup(func() { conn.Close() })
		return conn
	}
	controlDB, sourceDB := open(account), open(sourceUser)
	if strings.HasPrefix(scenario, "production-") {
		if e = (c.SQLPublicCaptureGrantProbe{DB: controlDB, Schema: database, User: account}).Check(ctx); e != nil {
			t.Fatal("exact public control grants rejected", e)
		}
		for _, statement := range []string{"UPDATE users SET id=id WHERE FALSE", "UPDATE system_backup_v2_configs SET enabled=enabled WHERE FALSE", "DELETE FROM system_backup_v2_execution_records WHERE FALSE", "CREATE TABLE public_controller_must_not_create(id INT)"} {
			if _, z := controlDB.Exec(statement); z == nil {
				t.Fatal("public controller acquired forbidden business/config/delete/DDL capability")
			}
		}
	}
	if e = (backup.Gate{DB: db}).EnsureScope(ctx, "installation"); e != nil {
		t.Fatal(e)
	}
	if e = (c.SQLGateInitializer{DB: db}).Ensure(ctx, "installation_admission", c.GatePolicy{LockTTL: 900 * time.Second, AcquisitionTimeout: 60 * time.Second, MaxHold: 600 * time.Second}); e != nil {
		t.Fatal(e)
	}
	issuer, serverCert, caPEM := nativeTLS(t, net.ParseIP(podIP))
	dir := t.TempDir()
	recordKey, captureKey := make([]byte, 32), make([]byte, 32)
	rand.Read(recordKey)
	rand.Read(captureKey)
	for ref, key := range map[string][]byte{"record-v1": recordKey, "capture-v1": captureKey} {
		if e = os.WriteFile(filepath.Join(dir, ref), key, 0600); e != nil {
			t.Fatal(e)
		}
	}
	pub, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	controllerOwner := "m2-controller-" + account
	grant := c.ExecutionGrant{Version: "system-backup-execution-grant.v1", InstallationID: "installation_admission", ControllerOwner: controllerOwner, DatabaseAccount: account + "@%", ServerUUID: server, Database: database, ConfigVersion: 1, ConfigSHA256: configHash, ProfileSHA256: legacy.hash, NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Actions: []string{"prepare", "capture", "issue_worker"}, RecordKeys: []c.ExecutionRecordKey{{Ref: "record-v1", SHA256: digestJSON(recordKey)}}, CaptureKeys: []c.ExecutionRecordKey{{Ref: "capture-v1", SHA256: digestJSON(captureKey)}}, WorkerIssuerSHA256: digestJSON(issuer.Certificate.Raw)}
	sign := func(name string, g c.ExecutionGrant) *c.PinnedExecutionIdentity {
		body, _ := json.Marshal(g)
		envelope, _ := json.Marshal(map[string]string{"payload_base64": base64.StdEncoding.EncodeToString(body), "signature_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(private, body))})
		path := filepath.Join(dir, name)
		if z := os.WriteFile(path, envelope, 0600); z != nil {
			t.Fatal(z)
		}
		identity, z := c.NewPinnedExecutionIdentity(path, digestJSON(envelope), dir, pub)
		if z != nil {
			t.Fatal(z)
		}
		return identity
	}
	if strings.HasPrefix(scenario, "production-") {
		raw, z := x509.MarshalPKCS8PrivateKey(issuer.Signer)
		if z != nil {
			t.Fatal(z)
		}
		if z = os.WriteFile(filepath.Join(dir, "native-issuer-raw.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}), 0600); z != nil {
			t.Fatal(z)
		}
		clear(raw)
	}
	forward := sign("forward.json", grant)
	recoveryGrant := grant
	recoveryGrant.Actions = []string{"recover"}
	recoveryGrant.CaptureKeys = nil
	recoveryGrant.WorkerIssuerSHA256 = ""
	recovery := sign("recovery.json", recoveryGrant)
	authority := c.SQLExecutionAuthority{DB: controlDB, InstallationID: "installation_admission", ApplicationScope: "installation", Authorization: forward, DeploymentEnabled: true}
	recoveryAuthority := c.SQLRecoveryAuthority{DB: controlDB, InstallationID: authority.InstallationID, ApplicationScope: authority.ApplicationScope, Identity: recovery}
	records := c.SQLExecutionRecords{Authority: authority, Keys: forward, CapacityReportFile: legacy.capacityFile}
	gate := c.SQLCaptureGate{Authority: authority, Recovery: recoveryAuthority, Records: records, AcquisitionTimeout: 60 * time.Second, HoldTimeout: 300 * time.Second}
	stagingRoot, e := os.OpenRoot("/staging")
	if e != nil {
		t.Fatal(e)
	}
	defer stagingRoot.Close()
	root, e := os.OpenRoot("/source")
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	if e = os.Mkdir("/source/"+account, 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile("/source/"+account+"/data.txt", []byte("native-capture-preserves-source\n"), 0600); e != nil {
		t.Fatal(e)
	}
	slug := strings.ReplaceAll(account, "_", "-")
	deploymentName := "native-writer-" + slug
	replicas := int32(1)
	graces := int64(1)
	var sourceLifecycle *corev1.Lifecycle
	if scenario == "production-delayed-exit" {
		graces = 20
		sourceLifecycle = &corev1.Lifecycle{PreStop: &corev1.LifecycleHandler{Exec: &corev1.ExecAction{Command: []string{"/bin/sleep", "13"}}}}
	}
	dep, e := client.AppsV1().Deployments(nsName).Create(ctx, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: deploymentName, Namespace: nsName}, Spec: appsv1.DeploymentSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"native-source": account}}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"native-source": account}}, Spec: corev1.PodSpec{TerminationGracePeriodSeconds: &graces, Containers: []corev1.Container{{Name: "writer", Image: image, Lifecycle: sourceLifecycle, Command: []string{"/bin/sh", "-c", "while true; do date +%s%N > /source/counter.txt; sleep 1; done"}, VolumeMounts: []corev1.VolumeMount{{Name: "source", MountPath: "/source", SubPath: account}}}}, Volumes: []corev1.Volume{{Name: "source", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "native-source"}}}}}}}}, metav1.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		client.AppsV1().Deployments(nsName).Delete(context.Background(), deploymentName, metav1.DeleteOptions{})
	})
	waitNative(t, ctx, func() bool {
		v, z := client.AppsV1().Deployments(nsName).Get(ctx, deploymentName, metav1.GetOptions{})
		return z == nil && v.Status.ReadyReplicas == 1 && v.Status.ObservedGeneration == v.Generation
	})
	inspector := &nativeProofInspector{Client: client, Config: cfg, Namespace: nsName, Pod: "native-node-proof"}
	proof := quiesce.CRIProver{Node: nodeName, Inspector: inspector}
	faultProof := &nativeFaultProof{Real: proof}
	faultProof.Unknown.Store(scenario == "unknown-stop-recovery")
	owner := &execution.PublicJobOwner{Gate: gate, Client: client, Dynamic: dyn, Namespace: nsName, NamespaceUID: string(ns.UID), TrustDomain: "native-backup.invalid", Security: kube.WorkerSecurity{NodeUIDs: map[string]string{nodeName: string(node.UID)}, ServiceAccountName: sa.Name, ServiceAccountUID: string(sa.UID)}, Identity: forward, Issuer: issuer, Staging: stagingRoot, Proof: faultProof, AllowKubeletStopWitness: scenario != "unknown-stop-recovery"}
	for _, entry := range []struct{ Volume, Claim string }{{"workspace", "native-source"}, {"staging", "native-staging"}} {
		claim, z := client.CoreV1().PersistentVolumeClaims(nsName).Get(ctx, entry.Claim, metav1.GetOptions{})
		if z != nil {
			t.Fatal(z)
		}
		pv, z := client.CoreV1().PersistentVolumes().Get(ctx, claim.Spec.VolumeName, metav1.GetOptions{})
		if z != nil {
			t.Fatal(z)
		}
		owner.Security.Volumes = append(owner.Security.Volumes, kube.MountIdentity{Volume: entry.Volume, Kind: "PersistentVolumeClaim", Name: claim.Name, UID: string(claim.UID), PVName: pv.Name, PVUID: string(pv.UID), SHA256: kube.ContentHash(pv.Spec)})
	}
	listener, e := net.Listen("tcp", "0.0.0.0:0")
	if e != nil {
		t.Fatal(e)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	endpoint := fmt.Sprintf("https://%s:%d/worker/v1", podIP, port)
	if strings.HasPrefix(scenario, "production-") {
		listener.Close()
		entryCfg := execution.DeploymentConfig{Version: "system-backup-public-deployment.v1", CaptureScope: "platform-workspace", InstallationID: authority.InstallationID, ControllerOwner: controllerOwner, ApplicationScope: authority.ApplicationScope, Namespace: nsName, NamespaceUID: string(ns.UID), TrustDomain: owner.TrustDomain, ForwardGrant: execution.GrantReference{Path: filepath.Join(dir, "forward.json"), PublicKey: base64.StdEncoding.EncodeToString(pub)}, RecoveryGrant: execution.GrantReference{Path: filepath.Join(dir, "recovery.json"), PublicKey: base64.StdEncoding.EncodeToString(pub)}, KeyDirectory: dir, ProfileFile: filepath.Join(dir, "profile.json"), CapacityFile: legacy.capacityFile, SourceDSNFile: filepath.Join(dir, "source.dsn"), SourceUser: sourceUser, SourceDatabase: database, SourceServerUUID: server, StagingDirectory: "/staging", StagingClaim: "native-staging", WorkerImage: workerImage, Security: owner.Security, ControlURL: endpoint, Listen: listener.Addr().String(), ServerCertificate: filepath.Join(dir, "server.pem"), ServerKey: filepath.Join(dir, "server.key"), IssuerCertificate: filepath.Join(dir, "issuer.pem"), IssuerKey: filepath.Join(dir, "issuer.key"), Writers: []execution.PlatformDeployment{{Namespace: nsName, Name: dep.Name, UID: string(dep.UID)}}, Workspace: execution.WorkspaceCapture{Claim: "native-source", SubPath: account, Node: nodeName, MaxFiles: 50, MaxFileBytes: 1 << 20, MaxArchiveBytes: 4 << 20, MaxCompressedBytes: 4 << 20}, AcquireSeconds: 60, HoldSeconds: 120}
		if os.Getenv("NATIVE_BACKUP_PHYSICAL_CAPACITY") == "true" {
			stopCapacity()
			if e = os.Remove(legacy.capacityFile); e != nil {
				t.Fatal(e)
			}
			raw, _ := json.Marshal(map[string]string{"database": database, "server_uuid": server, "report_file": legacy.capacityFile})
			fmt.Fprintln(os.Stdout, "NATIVE_CAPACITY_REQUEST "+string(raw))
			probe, done := context.WithTimeout(ctx, 30*time.Second)
			waitNative(t, probe, func() bool {
				raw, z := os.ReadFile(legacy.capacityFile)
				if z != nil {
					return false
				}
				r, z := security.ParseCapacityReport(raw)
				return z == nil && r.Database == database && r.ServerUUID == server
			})
			done()
		}
		entryCfg.IssuerSHA256 = digestJSON(issuer.Certificate.Raw)
		if os.Getenv("NATIVE_BACKUP_MINIMUM_KUBERNETES") == "true" {
			restoreAccess := nativeMinimumKubernetes(t, ctx, client, entryCfg)
			defer restoreAccess()
		}
		testNativeProductionEntry(t, ctx, db, client, handler, operator, task, entryCfg, grant, private, serverCert, caPEM, scenario == "production-recovery-only")
		return
	}
	writerID := "deployment/" + nsName + "/" + deploymentName
	sourceCfg := b.LinuxProfileConfig{Source: sourceDB, Database: database, ServerUUID: server, Supported: map[b.AgentKind]bool{{Type: "openclaw", Mode: "pro", Variant: "linux", OS: "linux"}: true}, HoldLimit: 300 * time.Second}
	sourceCfg.BuildWriters = func(ctx context.Context, in d.Input, inventory b.SourceInventory, frozen []b.FrozenWriter) ([]flow.Writer, error) {
		if len(inventory.Instances) != 0 {
			return nil, d.ErrNotReady
		}
		w := &quiesce.DeploymentWriter{Client: client, Namespace: nsName, Name: dep.Name, UID: string(dep.UID), FenceID: in.Authority.TaskPublicID + "/attempt/1", Runtime: scope.Runtime{Type: "openclaw", Mode: "pro", Variant: "linux", OS: "linux"}, PollInterval: 100 * time.Millisecond}
		w.Guard = func(ctx context.Context, point string, s flow.State) error {
			var e error
			switch point {
			case "before-resume", "recovery-check-stopped", "check-resumed":
				e = gate.CheckRecovery(ctx, in.Authority, writerID, d.WriterState{UID: s.UID, Generation: s.Generation, Running: s.Running, Checkpoint: s.Checkpoint})
			default:
				e = gate.Check(ctx, in.Authority)
			}
			if e != nil {
				t.Log("source guard rejected", point, e)
			}
			return e
		}
		w.PrepareStop = func(ctx context.Context, _ flow.State, pods []quiesce.PodIdentity) error {
			return owner.StopWitness(in.Authority).Arm(ctx, pods)
		}
		w.ConfirmStopped = func(ctx context.Context, _ flow.State, pods []quiesce.PodIdentity) error {
			if owner.StopWitness(in.Authority).Confirm(ctx, pods) == nil {
				return nil
			}
			if proof.Confirm(ctx, pods) == nil {
				return nil
			}
			return quiesce.ErrStopProofPending
		}
		w.ConfirmResumed = func(ctx context.Context, _ flow.State) error {
			current, z := client.AppsV1().Deployments(nsName).Get(ctx, dep.Name, metav1.GetOptions{})
			if z != nil || current.UID != dep.UID || current.Status.ReadyReplicas != 1 {
				return flow.ErrResume
			}
			return nil
		}
		return []flow.Writer{nativeTraceSource{Writer: w, T: t}}, nil
	}
	var capturedInv worker.Invocation
	var preparedAuthority d.Authority
	sourceCfg.BuildParts = func(in d.Input, _ b.SourceInventory, until time.Time) ([]b.JobPart, error) {
		invocation := worker.Invocation{Request: worker.Request{Version: worker.Version, Operation: "capture-workspace", Binding: staging.Binding{BackupID: in.Authority.TaskPublicID, Attempt: "1", Path: "workspace", PartIndex: 1, CaptureContextHash: in.Authority.ConfigSHA256, EnvelopeID: "functional-native"}, Deadline: until, ArtifactName: "workspace.enc", MaxFiles: 50, MaxFileBytes: 1 << 20, MaxArchiveBytes: 4 << 20, MaxCompressedBytes: 4 << 20}, WorkspacePath: "/workspace", StagingPath: "/staging"}
		p, z := b.BuildCapturePart(in, until, b.CapturePartRequest{Part: "workspace", Category: "workspace", JobUnitKey: "workspace", Generation: 1, Invocation: invocation, Workload: kube.JobRequest{Identity: kube.Identity{Namespace: nsName, Name: "capture-" + slug, Owner: in.Authority.TaskPublicID}, Image: workerImage, ServiceAccount: sa.Name, Source: corev1.Volume{Name: "source", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "native-source"}}}, StagingClaim: "native-staging", SourceSubPath: account, NodeName: nodeName, DeadlineSeconds: 120, WorkerControl: &kube.WorkerControl{URL: endpoint, InvocationConfigMap: "request-" + slug, IdentitySecret: "identity-" + slug, BoundPodIdentity: true}}})
		if z != nil {
			return nil, z
		}
		capturedInv = invocation
		preparedAuthority = in.Authority
		return []b.JobPart{p}, nil
	}
	queue := c.SQLExecutionQueue{DB: controlDB, InstallationID: authority.InstallationID, Owner: controllerOwner, ApplicationScope: authority.ApplicationScope, Policy: c.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second}, Authorization: forward, Recovery: &recoveryAuthority}
	runtime, z := execution.NewPublicCapture(execution.PublicCaptureConfig{Owner: owner, Queue: queue, Source: sourceCfg, Profile: b.ProfileKey{ID: testExecutionProfile().Profile, Revision: testExecutionProfile().Revision}, Guard: nativeGateProbe{CheckFn: func(ctx context.Context) error { return controlDB.PingContext(ctx) }}, Admission: func(_ context.Context, in d.Input) error {
		if in.Backup == nil || in.Backup.TaskPurpose != "functional_test" || len(in.Backup.RequestedParts) != 1 || in.Backup.RequestedParts[0] != "workspace" {
			return d.ErrNotReady
		}
		return nil
	}, Inventory: func(_ context.Context, _ d.Input, x b.Discovery) error {
		if len(x.Writers) != 1 || x.Writers[0].ID != writerID || x.Writers[0].Original.UID != string(dep.UID) || len(x.Parts) != 1 || x.Parts[0].Part != "workspace" {
			return d.ErrNotReady
		}
		return nil
	}, RecoveryTimeout: 2 * time.Minute})
	if z != nil {
		t.Fatal(z)
	}
	runtime.Loop.Dispatch.Runner = nativeTraceRunner{Runner: runtime.Loop.Dispatch.Runner, T: t}
	runtime.Loop.Dispatch.Ports = nativeTracePorts{Ports: runtime.Loop.Dispatch.Ports, T: t}
	runtime.Control = execution.WorkloadIdentity{Client: client, Namespace: nsName, ServiceAccount: sa.Name, ServiceAccountUID: string(sa.UID), Next: worker.ControlHandler{Authorizer: nativeTraceAuthorizer{Owner: owner, T: t}}}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	serverHTTP := &http.Server{Handler: runtime.Control, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}, ReadHeaderTimeout: 5 * time.Second}
	serverDone := make(chan error, 1)
	go func() { serverDone <- serverHTTP.Serve(tls.NewListener(listener, serverHTTP.TLSConfig)) }()
	defer func() { serverHTTP.Close(); <-serverDone }()
	if e = runtime.Loop.RunOnce(ctx); e != nil {
		t.Fatal("prepare", e)
	}
	if _, e = db.Exec("UPDATE system_backup_v2_backups SET next_reconcile_at=UTC_TIMESTAMP(6) WHERE public_id=?", task); e != nil {
		t.Fatal(e)
	}
	if scenario == "prepare-revoked" {
		if e = os.Remove(filepath.Join(dir, "forward.json")); e != nil {
			t.Fatal(e)
		}
		if e = runtime.Loop.RunOnce(ctx); e != nil {
			t.Fatal("revoked preparation cleanup", e)
		}
		var state string
		var resources int
		if db.QueryRow("SELECT status FROM system_backup_v2_backups WHERE public_id=?", task).Scan(&state) != nil || state != "failed" {
			t.Fatal("revoked preparation stuck", state)
		}
		if db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE task_public_id=?", task).Scan(&resources) != nil || resources != 0 {
			t.Fatal("revoked preparation performed source actions")
		}
		t.Log("revoked preparation closed with no source effects")
		return
	}
	if scenario == "prepare-cancel" {
		nativeRequestCancel(t, handler, operator, task)
		if e = runtime.Loop.RunOnce(ctx); e != nil {
			t.Fatal("cancel untouched preparation", e)
		}
		var state, operation string
		if db.QueryRow("SELECT status FROM system_backup_v2_backups WHERE public_id=?", task).Scan(&state) != nil || state != "canceled" {
			t.Fatal("preparation not canceled", state)
		}
		if db.QueryRow("SELECT status FROM system_backup_v2_operations WHERE target_public_id=? AND operation_type='cancel'", task).Scan(&operation) != nil || operation != "succeeded" {
			t.Fatal("cancellation not settled", operation)
		}
		t.Log("real authorized pending cancel -> untouched source proved -> root and operation canceled atomically")
		return
	}
	bindRaw, _ := json.Marshal(capturedInv.Request.Binding)
	captureDEK, e := forward.DeriveCaptureKey(ctx, preparedAuthority, bindRaw)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(captureDEK)
	stopLog := nativeWorkerFailureLog(t, ctx, client, nsName, "capture-"+slug)
	defer stopLog()
	if scenario == "acquire-atomic" {
		if e = runtime.Loop.RunOnce(ctx); e == nil {
			t.Fatal("acquisition journal outage hidden")
		}
		var phase string
		var count int
		if db.QueryRow("SELECT phase FROM system_backup_gate WHERE scope='installation'").Scan(&phase) != nil || phase != "idle" {
			t.Fatal("physical acquisition committed without public journal", phase)
		}
		if db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_runtime_captures WHERE task_public_id=?", task).Scan(&count) != nil || count != 0 {
			t.Fatal("partial acquisition journal")
		}
		projectionFault.Store(false)
		nativeRequestCancel(t, handler, operator, task)
		// Real lease expiry, no manual reset of controller/task state.
		waitNative(t, ctx, func() bool {
			runtime.Loop.RunOnce(ctx)
			var state string
			return db.QueryRow("SELECT status FROM system_backup_v2_backups WHERE public_id=?", task).Scan(&state) == nil && state == "canceled"
		})
		if db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE task_public_id=?", task).Scan(&count) != nil || count != 0 {
			t.Fatal("canceled acquisition dispatched source work")
		}
		var closed bool
		if db.QueryRow("SELECT owner IS NULL AND close_until IS NULL FROM system_backup_gate_admissions WHERE scope='installation'").Scan(&closed) != nil || !closed {
			t.Fatal("request admission left closed")
		}
		t.Log("actual acquisition journal SQL outage rolls back physical transition; real lease expiry and authorized cancellation clear only original admission without source IO")
		return
	}
	if scenario == "capture-cancel" {
		passDone := make(chan error, 1)
		go func() { passDone <- runtime.Loop.RunOnce(ctx) }()
		waitNative(t, ctx, func() bool {
			var n int
			return db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND create_dispatched=TRUE", task).Scan(&n) == nil && n == 1
		})
		nativeRequestCancel(t, handler, operator, task)
		select {
		case <-passDone:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		waitNative(t, ctx, func() bool {
			var state string
			if db.QueryRow("SELECT status FROM system_backup_v2_backups WHERE public_id=?", task).Scan(&state) != nil {
				return false
			}
			if state == "canceled" {
				return true
			}
			runtime.Loop.RunOnce(ctx)
			return false
		})
		var stops, resumes sql.NullTime
		var operation string
		if db.QueryRow("SELECT collectors_stopped_at,source_resumed_at FROM system_backup_v2_runtime_captures WHERE task_public_id=?", task).Scan(&stops, &resumes) != nil || !stops.Valid || !resumes.Valid {
			t.Fatal("cancel acknowledged without actual exit and resume")
		}
		if db.QueryRow("SELECT status FROM system_backup_v2_operations WHERE target_public_id=? AND operation_type='cancel'", task).Scan(&operation) != nil || operation != "succeeded" {
			t.Fatal("cancel operation not settled", operation)
		}
		t.Log("real running Job -> authorized durable cancellation -> original exit proof + source resume -> canceled, no replacement Job")
		return
	}
	e = runtime.Loop.RunOnce(ctx)
	expectedStatus := "validating"
	if scenario == "unknown-stop-recovery" {
		if !errors.Is(e, c.ErrExecutionRecoveryRequired) {
			t.Fatal("unknown stop was not fenced", e)
		}
		blocked, z := client.AppsV1().Deployments(nsName).Get(ctx, dep.Name, metav1.GetOptions{})
		if z != nil || *blocked.Spec.Replicas != 0 {
			t.Fatal("source resumed without stop proof", z)
		}
		var blockedNotes int
		if db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_events WHERE target_public_id=? AND event_type='diagnostic.d.recovery_blocked'", task).Scan(&blockedNotes) != nil || blockedNotes != 1 {
			t.Fatal("missing durable original recovery diagnostic", blockedNotes)
		}
		var original d.Authority
		original.InstallationID, original.TaskType, original.TaskPublicID, original.AttemptNo, original.Phase = "installation_admission", "backup", task, 1, "capture"
		if db.QueryRow("SELECT request_id,config_version,config_snapshot_sha256,controller_owner,row_version,deadline_at,maintenance_lock_owner,maintenance_fencing_token FROM system_backup_v2_backups WHERE public_id=?", task).Scan(&original.RequestID, &original.ConfigVersion, &original.ConfigSHA256, &original.ClaimOwner, &original.ClaimRowVersion, &original.DeadlineAt, &original.MaintenanceOwner, &original.MaintenanceFencingToken) != nil {
			t.Fatal("original blocked claim missing")
		}
		blockedWork := c.ExecutionWork{Step: c.ExecutionRecover, Input: d.Input{Authority: original}}
		if z = runtime.Scheduler.ReportExecutionBlocked(ctx, blockedWork); z != nil {
			t.Fatal("duplicate diagnostic lookup", z)
		}
		blockedWork.Input.Authority.ClaimRowVersion++
		if z = runtime.Scheduler.ReportExecutionBlocked(ctx, blockedWork); !errors.Is(z, c.ErrClaimLost) {
			t.Fatal("stale diagnostic claim accepted", z)
		}
		if db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_events WHERE target_public_id=? AND event_type='diagnostic.d.recovery_blocked'", task).Scan(&blockedNotes) != nil || blockedNotes != 1 {
			t.Fatal("recovery diagnostic duplicated", blockedNotes)
		}
		// Fault only the disposable control journal after a real physical pause.
		// Recovery must reconstruct the original intent from its independent
		// witness and really resume this source, never merely mark it untouched.
		var witness int
		if db.QueryRow("SELECT COUNT(*) FROM system_backup_participants WHERE scope='installation' AND checkpoint_hash IS NOT NULL").Scan(&witness) != nil || witness != 1 {
			t.Fatal("physical pause witness absent", witness)
		}
		if _, z = db.Exec("DELETE FROM system_backup_v2_runtime_writers WHERE task_public_id=?", task); z != nil {
			t.Fatal(z)
		}
		if z = os.Remove(filepath.Join(dir, "forward.json")); z != nil {
			t.Fatal(z)
		}
		faultProof.Unknown.Store(false)
		owner.AllowKubeletStopWitness = true
		waitNative(t, ctx, func() bool {
			var expired bool
			return db.QueryRow("SELECT controller_lease_expires_at<=UTC_TIMESTAMP(6) FROM system_backup_v2_backups WHERE public_id=?", task).Scan(&expired) == nil && expired
		})
		if e = runtime.Loop.RunOnce(ctx); e != nil {
			t.Fatal("restart recovery after forward revocation", e)
		}
		if db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_events WHERE target_public_id=? AND event_type='diagnostic.d.recovery_intent_repaired'", task).Scan(&witness) != nil || witness != 1 {
			t.Fatal("original intent repair missing", witness)
		}
		expectedStatus = "failed"
	} else if scenario == "release-atomic" {
		if e == nil {
			t.Fatal("injected projection outage was hidden")
		}
		var phase string
		var resumed sql.NullTime
		if z := db.QueryRow("SELECT phase FROM system_backup_gate WHERE scope='installation'").Scan(&phase); z != nil || phase != "releasing" {
			t.Fatal("physical release committed without projection", phase, z)
		}
		if z := db.QueryRow("SELECT source_resumed_at FROM system_backup_v2_runtime_captures WHERE task_public_id=?", task).Scan(&resumed); z != nil || resumed.Valid {
			t.Fatal("projection invented", z)
		}
		projectionFault.Store(false)
		if z := os.Remove(filepath.Join(dir, "forward.json")); z != nil {
			t.Fatal(z)
		}
		if _, z := db.Exec("UPDATE system_backup_v2_backups SET controller_lease_expires_at=TIMESTAMPADD(SECOND,-1,UTC_TIMESTAMP(6)),next_reconcile_at=UTC_TIMESTAMP(6) WHERE public_id=?", task); z != nil {
			t.Fatal(z)
		}
		if e = runtime.Loop.RunOnce(ctx); e != nil {
			t.Fatal("atomic release recovery", e)
		}
		expectedStatus = "failed"
	} else if scenario == "binding-write-outage" {
		if e == nil {
			t.Fatal("unknown original dispatch hidden")
		}
		if z := os.Remove(filepath.Join(dir, "forward.json")); z != nil {
			t.Fatal(z)
		}
		if _, z := db.Exec("UPDATE system_backup_v2_backups SET controller_lease_expires_at=TIMESTAMPADD(SECOND,-1,UTC_TIMESTAMP(6)),next_reconcile_at=UTC_TIMESTAMP(6) WHERE public_id=?", task); z != nil {
			t.Fatal(z)
		}
		if e = runtime.Loop.RunOnce(ctx); e != nil {
			t.Fatal("binding outage recovery failed", e)
		}
		expectedStatus = "failed"
		if lost.Created.Load() != 1 {
			t.Fatal("orphan binding caused duplicate Job", lost.Created.Load())
		}
	} else if e != nil {
		t.Fatal("capture", e)
	}
	if scenario == "lost-create-response" && (lost.Dropped.Load() != 1 || lost.Created.Load() != 1) {
		t.Fatal("create replay duplicated source Job", lost.Dropped.Load(), lost.Created.Load())
	}
	var status string
	var stopped, resumed sql.NullTime
	var resources, attempts int
	if e = db.QueryRow("SELECT status FROM system_backup_v2_backups WHERE public_id=?", task).Scan(&status); e != nil || status != expectedStatus {
		t.Fatal("capture is not publish success", status, e)
	}
	if e = db.QueryRow("SELECT collectors_stopped_at,source_resumed_at FROM system_backup_v2_runtime_captures WHERE task_public_id=?", task).Scan(&stopped, &resumed); e != nil || !stopped.Valid || !resumed.Valid {
		t.Fatal("missing physical recovery proof", e)
	}
	if e = db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job'", task).Scan(&resources); e != nil || resources != 1 {
		t.Fatal("duplicate job", resources, e)
	}
	if e = db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_attempts WHERE target_public_id=?", task).Scan(&attempts); e != nil || attempts != 1 {
		t.Fatal("duplicate attempt", attempts, e)
	}
	var stopProofs int
	if e = db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_runtime_stop_proofs WHERE task_public_id=?", task).Scan(&stopProofs); e != nil || stopProofs != 2 {
		t.Fatal("explicit runtime termination proofs", stopProofs, e)
	}
	before, e := os.ReadFile("/source/" + account + "/counter.txt")
	if e != nil {
		t.Fatal(e)
	}
	waitNative(t, ctx, func() bool {
		after, z := os.ReadFile("/source/" + account + "/counter.txt")
		return z == nil && !bytes.Equal(before, after)
	})
	// The authenticated worker result is encrypted in SQL; decrypt the original
	// capture plan and sealed file with its task-bound key, then inspect tar bytes.
	var sealed []byte
	if e = db.QueryRow("SELECT sealed_payload FROM system_backup_v2_execution_records WHERE task_public_id=? AND record_kind='plan'", task).Scan(&sealed); e != nil || bytes.Contains(sealed, []byte("data.txt")) {
		t.Fatal("plan custody", e)
	}
	if scenario == "binding-write-outage" {
		var revokedStopped int
		if e = db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND revoked=TRUE AND process_json IS NOT NULL AND stopped_at IS NOT NULL", task).Scan(&revokedStopped); e != nil || revokedStopped != 1 {
			t.Fatal("orphan stop proof missing", e)
		}
		if e = db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND result_cipher IS NOT NULL", task).Scan(&revokedStopped); e != nil || revokedStopped != 0 {
			t.Fatal("orphan invented worker result", e)
		}
		t.Log("original orphan job revoked, bound, physically stopped; source recovered without issuing a new read grant")
		return
	}
	rootTask, e := stagingRoot.OpenRoot(task)
	if e != nil {
		t.Fatal(e)
	}
	defer rootTask.Close()
	raw, e := rootTask.ReadFile("workspace.enc")
	if e != nil || bytes.Contains(raw, []byte("native-capture-preserves-source")) {
		t.Fatal("native ciphertext", e)
	}
	t.Logf("native public capture: task=%s Jobs=%d attempts=%d CRI_inspections=%d status=%s source_resumed=true", task, resources, attempts, inspector.Calls.Load(), status)
	if scenario == "legacy-release-gap" {
		// Seed only the historical pre-fix journal gap. Physical source, exit,
		// original writer and participant proofs above all came from real work.
		if _, e = db.Exec("UPDATE system_backup_v2_backups SET status='capturing',controller_owner=?,controller_lease_expires_at=TIMESTAMPADD(SECOND,60,UTC_TIMESTAMP(6)),row_version=row_version+1 WHERE public_id=?", controllerOwner, task); e != nil {
			t.Fatal(e)
		}
		if _, e = db.Exec("UPDATE system_backup_v2_runtime_captures SET source_resumed_at=NULL WHERE task_public_id=?", task); e != nil {
			t.Fatal(e)
		}
		a := preparedAuthority
		if e = db.QueryRow("SELECT row_version,maintenance_fencing_token FROM system_backup_v2_backups WHERE public_id=?", task).Scan(&a.ClaimRowVersion, &a.MaintenanceFencingToken); e != nil {
			t.Fatal(e)
		}
		a.MaintenanceOwner = task
		// A conflicting epoch is rejected without repairing the journal.
		bad := a
		bad.MaintenanceFencingToken++
		if ok, z := owner.Gate.ReconcileReleasedCapture(ctx, bad); z == nil || ok {
			t.Fatal("foreign generation repaired")
		}
		if _, e = db.Exec("UPDATE system_backup_v2_runtime_writers SET resumed=FALSE WHERE task_public_id=?", task); e != nil {
			t.Fatal(e)
		}
		if ok, z := owner.Gate.ReconcileReleasedCapture(ctx, a); z == nil || ok {
			t.Fatal("missing writer proof repaired")
		}
		if _, e = db.Exec("UPDATE system_backup_v2_runtime_writers SET resumed=TRUE WHERE task_public_id=?", task); e != nil {
			t.Fatal(e)
		}
		// Losing a whole row must not pass a loop which checks only present
		// receipts. Preserve and restore the exact disposable fixture row.
		func() {
			var id, digest string
			var original []byte
			var paused, resumed bool
			var version uint64
			var created, updated time.Time
			if z := db.QueryRow("SELECT writer_id,original_json,original_sha256,paused,resumed,row_version,created_at,updated_at FROM system_backup_v2_runtime_writers WHERE task_public_id=?", task).Scan(&id, &original, &digest, &paused, &resumed, &version, &created, &updated); z != nil {
				t.Fatal(z)
			}
			if _, z := db.Exec("DELETE FROM system_backup_v2_runtime_writers WHERE task_public_id=? AND writer_id=?", task, id); z != nil {
				t.Fatal(z)
			}
			defer func() {
				if _, z := db.Exec("INSERT INTO system_backup_v2_runtime_writers(task_public_id,writer_id,original_json,original_sha256,paused,resumed,row_version,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)", task, id, original, digest, paused, resumed, version, created, updated); z != nil {
					t.Error("restore original fault fixture", z)
				}
			}()
			if ok, z := owner.Gate.ReconcileReleasedCapture(ctx, a); z == nil || ok {
				t.Fatal("entire missing writer receipt was accepted as recovered")
			}
		}()
		if ok, z := owner.Gate.ReconcileReleasedCapture(ctx, a); z != nil || !ok {
			t.Fatal("historical release projection not recovered", z)
		}
		if ok, z := owner.Gate.ReconcileReleasedCapture(ctx, a); z != nil || !ok {
			t.Fatal("release reconciliation not idempotent", z)
		}
		if e = os.Remove(filepath.Join(dir, "forward.json")); e != nil {
			t.Fatal(e)
		}
		if _, e = db.Exec("UPDATE system_backup_v2_backups SET controller_lease_expires_at=TIMESTAMPADD(SECOND,-1,UTC_TIMESTAMP(6)),next_reconcile_at=UTC_TIMESTAMP(6) WHERE public_id=?", task); e != nil {
			t.Fatal(e)
		}
		if e = runtime.Loop.RunOnce(ctx); e != nil {
			t.Fatal("close recovered legacy task", e)
		}
		if e = db.QueryRow("SELECT status FROM system_backup_v2_backups WHERE public_id=?", task).Scan(&status); e != nil || status != "failed" {
			t.Fatal("legacy task left running", status, e)
		}
		t.Log("historical projection recovered without source reread or resume")
	}

	found := false
	if e = staging.ConsumeCompressed(ctx, bytes.NewReader(raw), captureDEK, capturedInv.Request.Binding, capturedInv.Request.MaxCompressedBytes, capturedInv.Request.MaxArchiveBytes, func(plain io.Reader) error {
		reader := tar.NewReader(plain)
		for {
			entry, z := reader.Next()
			if z == io.EOF {
				return nil
			}
			if z != nil {
				return z
			}
			if entry.Name == "data.txt" {
				body, z := io.ReadAll(io.LimitReader(reader, 1024))
				if z != nil {
					return z
				}
				if string(body) != "native-capture-preserves-source\n" {
					return fmt.Errorf("capture content differs")
				}
				found = true
			}
		}
	}); e != nil || !found {
		t.Fatal("authenticated native archive content", e, found)
	}
}

func nativeRequestCancel(t *testing.T, handler *Handler, token, task string) {
	t.Helper()
	call := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "https://example.invalid/api/v1/admin/system-backups/"+task+"/cancel", strings.NewReader(`{}`))
		r.TLS = &tls.ConnectionState{}
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Idempotency-Key", "native-cancel-original-0001")
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.Cancel(w, r, read.BackupTask, task, "native-cancel-request")
		return w
	}
	first := call()
	if first.Code != http.StatusAccepted {
		t.Fatal("active cancel admission", first.Code, first.Body.String())
	}
	var op read.OperationDTO
	if json.Unmarshal(first.Body.Bytes(), &op) != nil || op.Status != "pending" {
		t.Fatal("active cancel falsely acknowledged complete")
	}
	second := call()
	if second.Code != http.StatusAccepted || second.Header().Get("Location") != first.Header().Get("Location") {
		t.Fatal("cancel replay created another operation")
	}
}

func waitNative(t *testing.T, ctx context.Context, ready func() bool) {
	t.Helper()
	for {
		if ready() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// Admission capacity is an explicit fixture input, not physical-capacity or
// production deployment acceptance. Refresh it like the trusted mounted feed;
// never extend the production five-second freshness rule to suit this test.
func nativeSyntheticCapacity(t *testing.T, db *sql.DB, path string) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			var now time.Time
			var server, database string
			if db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6),@@server_uuid,DATABASE()").Scan(&now, &server, &database) == nil {
				raw, _ := json.Marshal(map[string]any{"server_uuid": server, "database": database, "observed_at": now, "allocated_bytes": int64(1 << 20), "available_bytes": int64(1 << 42)})
				if os.WriteFile(path+".next", raw, 0600) == nil {
					os.Rename(path+".next", path)
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}()
	return func() { cancel(); <-done }
}

func nativeWorkerFailureLog(t *testing.T, ctx context.Context, client kubernetes.Interface, namespace, job string) func() {
	tracking, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	stream, e := client.CoreV1().Pods(namespace).Watch(tracking, metav1.ListOptions{LabelSelector: "batch.kubernetes.io/job-name=" + job})
	if e != nil {
		cancel()
		close(done)
		return func() {}
	}
	go func() {
		defer close(done)
		defer stream.Stop()
		for {
			select {
			case <-tracking.Done():
				return
			case event, ok := <-stream.ResultChan():
				if !ok {
					return
				}
				pod, ok := event.Object.(*corev1.Pod)
				if !ok || pod.Status.Phase != corev1.PodFailed {
					continue
				}
				raw, e := client.CoreV1().Pods(namespace).GetLogs(pod.Name, &corev1.PodLogOptions{Container: "worker"}).DoRaw(tracking)
				if e == nil {
					for _, line := range strings.Split(string(raw), "\n") {
						if strings.HasPrefix(line, "backup worker failed; category=") && len(line) < 100 {
							t.Log("native worker", line)
						}
					}
				}
				return
			}
		}
	}()
	return func() { cancel(); <-done }
}
func nativeTLS(t *testing.T, ip net.IP) (control.IdentityIssuer, tls.Certificate, []byte) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "task-owned-native-ca"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(3 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	serverKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	server := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "native-control"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour), IPAddresses: []net.IP{ip}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverDER, e := x509.CreateCertificate(rand.Reader, server, parsed, &serverKey.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	serverPrivate, e := x509.MarshalPKCS8PrivateKey(serverKey)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverPrivate}))
	if e != nil {
		t.Fatal(e)
	}
	return control.IdentityIssuer{Certificate: parsed, Signer: key, ServerRoots: caPEM, TrustDomain: "native-backup.invalid"}, cert, caPEM
}

// Native MySQL remains authoritative; only the projection statement is withheld.
type nativeProjectionConnector struct {
	driver.Connector
	Fail         *atomic.Bool
	BlockBinding bool
	BlockAcquire bool
}

func (c nativeProjectionConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, e := c.Connector.Connect(ctx)
	if e != nil {
		return nil, e
	}
	return nativeProjectionConn{Conn: conn, Fail: c.Fail, BlockBinding: c.BlockBinding, BlockAcquire: c.BlockAcquire}, nil
}

type nativeProjectionConn struct {
	driver.Conn
	Fail         *atomic.Bool
	BlockBinding bool
	BlockAcquire bool
}

func (c nativeProjectionConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if c.BlockAcquire && c.Fail.Load() && strings.HasPrefix(q, "INSERT INTO system_backup_v2_runtime_captures") {
		return nil, errors.New("injected original acquisition journal unavailable")
	}
	if c.BlockBinding && strings.HasPrefix(q, "UPDATE system_backup_v2_runtime_resources SET binding_json=? WHERE") {
		return nil, errors.New("injected original binding write unavailable")
	}
	if c.Fail.Load() && strings.HasPrefix(q, "UPDATE system_backup_v2_runtime_captures SET source_resumed_at") {
		return nil, errors.New("injected projection write unavailable")
	}
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
}
func (c nativeProjectionConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
}
func (c nativeProjectionConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, o)
}
func (c nativeProjectionConn) Ping(ctx context.Context) error {
	return c.Conn.(driver.Pinger).Ping(ctx)
}
func (c nativeProjectionConn) ResetSession(ctx context.Context) error {
	return c.Conn.(driver.SessionResetter).ResetSession(ctx)
}
func (c nativeProjectionConn) IsValid() bool { return c.Conn.(driver.Validator).IsValid() }

// This fixture starts the actual production command; it does not replace its
// execution owner or readiness with a test callback. Capacity remains explicit
// synthetic input here and is not production capacity/grants acceptance.
func testNativeProductionEntry(t *testing.T, ctx context.Context, db *sql.DB, client kubernetes.Interface, handler *Handler, operator, bootstrapTask string, cfg execution.DeploymentConfig, grant c.ExecutionGrant, signing ed25519.PrivateKey, serverCert tls.Certificate, caPEM []byte, recoveryRestart bool) {
	t.Helper()
	write := func(path string, raw []byte) {
		t.Helper()
		if e := os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	privateRaw, e := x509.MarshalPKCS8PrivateKey(serverCert.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	write(cfg.ServerCertificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Certificate[0]}))
	write(cfg.ServerKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateRaw}))
	clear(privateRaw)
	write(cfg.IssuerCertificate, caPEM)
	// Native fixture CA key belongs only to this disposable test. It is passed in
	// via the parent-generated issuer, never read from a deployment or a server.
	// Native server certificate and issuer use the same root signing key below.
	issuerKeyPath := filepath.Join(filepath.Dir(cfg.IssuerKey), "native-issuer-raw.key")
	raw, e := os.ReadFile(issuerKeyPath)
	if e != nil {
		t.Fatal("fixture issuer key unavailable")
	}
	write(cfg.IssuerKey, raw)
	clear(raw)
	profileRaw, _ := json.Marshal(testExecutionProfile())
	write(cfg.ProfileFile, profileRaw)
	source := mysql.Config{User: cfg.SourceUser, Passwd: "synthetic-native-only", Net: "tcp", Addr: net.JoinHostPort(os.Getenv("TEST_SYSTEM_BACKUP_MYSQL_HOST"), os.Getenv("TEST_SYSTEM_BACKUP_MYSQL_PORT")), DBName: cfg.SourceDatabase, ParseTime: true, AllowNativePasswords: true}
	write(cfg.SourceDSNFile, []byte(source.FormatDSN()))
	cfgRaw, _ := json.Marshal(cfg)
	configFile := filepath.Join(filepath.Dir(cfg.ProfileFile), "deployment.json")
	write(configFile, cfgRaw)
	grant.DeploymentConfigSHA256 = digestJSON(cfgRaw)
	sign := func(path string, g c.ExecutionGrant) string {
		body, _ := json.Marshal(g)
		envelope, _ := json.Marshal(map[string]string{"payload_base64": base64.StdEncoding.EncodeToString(body), "signature_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(signing, body))})
		write(path, envelope)
		return digestJSON(envelope)
	}
	forwardHash := sign(cfg.ForwardGrant.Path, grant)
	recoverGrant := grant
	recoverGrant.Actions = []string{"recover"}
	recoverGrant.CaptureKeys = nil
	recoverGrant.WorkerIssuerSHA256 = ""
	recoveryHash := sign(cfg.RecoveryGrant.Path, recoverGrant)
	// Close the setup-only task, then remove its synthetic readiness. The actual
	// task below must be admitted using the production publisher's fresh receipt.
	if _, e = db.Exec("UPDATE system_backup_v2_backups SET status='failed',failure_category='runner_failed',started_at=COALESCE(started_at,UTC_TIMESTAMP(6)),finished_at=UTC_TIMESTAMP(6),can_cancel=FALSE WHERE public_id=?", bootstrapTask); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec("UPDATE system_backup_v2_execution_readiness SET ready=FALSE,expires_at=UTC_TIMESTAMP(6)"); e != nil {
		t.Fatal(e)
	}
	command := exec.CommandContext(ctx, "/tmp/public-controller")
	command.Env = append(os.Environ(), "DB_HOST="+os.Getenv("TEST_SYSTEM_BACKUP_MYSQL_HOST"), "DB_PORT="+os.Getenv("TEST_SYSTEM_BACKUP_MYSQL_PORT"), "DB_USER="+strings.Split(grant.DatabaseAccount, "@")[0], "DB_PASSWORD=synthetic-native-only", "DB_NAME="+cfg.SourceDatabase, "SYSTEM_BACKUP_V2_CONTROL_PLANE_ENABLED=true", "SYSTEM_BACKUP_CONTROLLER_ENABLED=true", "SYSTEM_BACKUP_EXECUTION_PROTOCOL=public-v1", "SYSTEM_BACKUP_SQL_GATE_SCOPE=installation", "SYSTEM_BACKUP_ENABLED=true", "SYSTEM_BACKUP_PUBLIC_CONFIG_FILE="+configFile, "SYSTEM_BACKUP_PUBLIC_CONFIG_SHA256="+digestJSON(cfgRaw), "SYSTEM_BACKUP_FORWARD_GRANT_SHA256="+forwardHash, "SYSTEM_BACKUP_RECOVERY_GRANT_SHA256="+recoveryHash, "POD_NAME="+os.Getenv("HOSTNAME"), "POD_NAMESPACE="+cfg.Namespace, "CLAWMANAGER_LEADER_ELECTION=true")
	logFile, e := os.OpenFile(filepath.Join(filepath.Dir(configFile), "production.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer logFile.Close()
	command.Stdout = logFile
	command.Stderr = logFile
	if e = command.Start(); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait(); close(done) }()
	t.Cleanup(func() {
		command.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			command.Process.Kill()
			<-done
		}
	})
	waitNative(t, ctx, func() bool {
		select {
		case <-done:
			raw, _ := os.ReadFile(filepath.Join(filepath.Dir(configFile), "production.log"))
			for _, line := range strings.Split(string(raw), "\n") {
				if strings.Contains(line, "[system-backup-public]") || strings.Contains(line, "[system-backup-controller]") {
					t.Log(line)
				}
			}
			t.Fatal("production command exited before readiness")
		default:
		}
		var ready bool
		return db.QueryRow("SELECT ready AND execution_protocol='public-v1' AND supported_parts='workspace' AND expires_at>UTC_TIMESTAMP(6) FROM system_backup_v2_execution_readiness WHERE task_type='backup'").Scan(&ready) == nil && ready
	})
	apiServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.Create(w, r, read.BackupTask, "m3-production-http")
	}))
	defer apiServer.Close()
	request, e := http.NewRequestWithContext(ctx, http.MethodPost, apiServer.URL+"/api/v1/admin/system-backups", strings.NewReader(`{"requested_parts":["workspace"],"task_purpose":"functional_test"}`))
	if e != nil {
		t.Fatal(e)
	}
	request.Header.Set("Authorization", "Bearer "+operator)
	request.Header.Set("Idempotency-Key", "native-production-functional-0001")
	request.Header.Set("Content-Type", "application/json")
	response, e := apiServer.Client().Do(request)
	if e != nil {
		t.Fatal(e)
	}
	responseBody, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		var rejection struct {
			Code string `json:"code"`
		}
		json.Unmarshal(responseBody, &rejection)
		t.Fatal("production HTTP create", response.StatusCode, rejection.Code)
	}
	var task string
	if e = db.QueryRow("SELECT public_id FROM system_backup_v2_backups WHERE public_id<>?", bootstrapTask).Scan(&task); e != nil {
		t.Fatal(e)
	}
	if recoveryRestart {
		waitNative(t, ctx, func() bool {
			// This case recovers an actual original Job. The durable send bit
			// precedes the API call: stopping at that bit can instead exercise
			// an unresolved send with no observed object, which must stay fenced.
			var name string
			if db.QueryRow("SELECT resource_name FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND create_dispatched=TRUE", task).Scan(&name) != nil {
				return false
			}
			job, err := client.BatchV1().Jobs(cfg.Namespace).Get(ctx, name, metav1.GetOptions{})
			return err == nil && job.UID != "" && job.Labels[kube.OwnerLabel] == task
		})
		recoveryBytes, z := os.ReadFile(cfg.RecoveryGrant.Path)
		if z != nil {
			t.Fatal(z)
		}
		if z = os.Remove(cfg.RecoveryGrant.Path); z != nil {
			t.Fatal(z)
		}
		command.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Fatal("original production owner did not stop")
		}
		var originalPhase string
		if db.QueryRow("SELECT phase FROM system_backup_gate WHERE scope=?", cfg.ApplicationScope).Scan(&originalPhase) != nil || originalPhase == "idle" {
			t.Fatal("restart fixture did not retain a protected original capture")
		}
		for _, path := range []string{cfg.ForwardGrant.Path, cfg.SourceDSNFile, cfg.IssuerKey, cfg.ServerKey} {
			if z = os.Remove(path); z != nil {
				t.Fatal("withdraw forward-only material", z)
			}
		}
		write(cfg.RecoveryGrant.Path, recoveryBytes)
		clear(recoveryBytes)
		if os.Getenv("NATIVE_BACKUP_MINIMUM_KUBERNETES") == "true" {
			ack := filepath.Join(filepath.Dir(cfg.ProfileFile), "kubernetes-recovery-only")
			raw, _ := json.Marshal(map[string]string{"ack_file": ack})
			fmt.Println("NATIVE_KUBERNETES_RECOVERY_ONLY " + string(raw))
			bounded, cancel := context.WithTimeout(ctx, 40*time.Second)
			waitNative(t, bounded, func() bool { b, e := os.ReadFile(ack); return e == nil && string(b) == "confirmed\n" })
			cancel()
		}
		env := append([]string(nil), command.Env...)
		command = exec.CommandContext(ctx, "/tmp/public-controller")
		command.Env = env
		command.Stdout = logFile
		command.Stderr = logFile
		if z = command.Start(); z != nil {
			t.Fatal(z)
		}
		done = make(chan error, 1)
		go func(cmd *exec.Cmd, ch chan error) { ch <- cmd.Wait(); close(ch) }(command, done)
		waitNative(t, ctx, func() bool {
			select {
			case <-done:
				t.Fatal("recovery-only production process exited")
			default:
			}
			var state string
			if db.QueryRow("SELECT status FROM system_backup_v2_backups WHERE public_id=?", task).Scan(&state) != nil {
				return false
			}
			return state == "failed"
		})
		var stopped, resumed sql.NullTime
		if db.QueryRow("SELECT collectors_stopped_at,source_resumed_at FROM system_backup_v2_runtime_captures WHERE task_public_id=?", task).Scan(&stopped, &resumed) != nil || !stopped.Valid || !resumed.Valid {
			t.Fatal("recovery-only process lacks actual exit/resume proof")
		}
		var jobs, attempts, readiness int
		if db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job'", task).Scan(&jobs) != nil || jobs != 1 {
			t.Fatal("recovery-only created a replacement Job")
		}
		if db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_attempts WHERE target_public_id=?", task).Scan(&attempts) != nil || attempts != 1 {
			t.Fatal("recovery-only created another attempt")
		}
		if db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_execution_readiness WHERE ready=TRUE AND expires_at>UTC_TIMESTAMP(6)").Scan(&readiness) != nil || readiness != 0 {
			t.Fatal("recovery grant advertised forward readiness")
		}
		counter := filepath.Join("/source", cfg.Workspace.SubPath, "counter.txt")
		before, z := os.ReadFile(counter)
		if z != nil {
			t.Fatal(z)
		}
		waitNative(t, ctx, func() bool { after, z := os.ReadFile(counter); return z == nil && !bytes.Equal(before, after) })
		t.Log("actual public controller restart: missing forward grant/source DSN/issuer and server private keys; independent recovery grant closes original Job, restores original source and ends failed/idle without new execution capability")
		return
	}
	waitNative(t, ctx, func() bool {
		select {
		case <-done:
			raw, _ := os.ReadFile(filepath.Join(filepath.Dir(configFile), "production.log"))
			for _, line := range strings.Split(string(raw), "\n") {
				if strings.Contains(line, "[system-backup-public]") {
					t.Log(line)
				}
			}
			t.Fatal("production controller stopped with active task")
		default:
		}
		var state string
		if db.QueryRow("SELECT status FROM system_backup_v2_backups WHERE public_id=?", task).Scan(&state) != nil {
			return false
		}
		if state == "failed" || state == "canceled" {
			t.Fatal("production task failed")
		}
		var blocked int
		if db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_events WHERE target_public_id=? AND event_type='diagnostic.d.recovery_blocked'", task).Scan(&blocked) == nil && blocked != 0 {
			t.Fatal("normal production capture entered protected recovery; inspect the retained closed controller diagnostics")
		}
		return state == "validating"
	})
	var stopped, resumed sql.NullTime
	var jobs, attempts int
	if db.QueryRow("SELECT collectors_stopped_at,source_resumed_at FROM system_backup_v2_runtime_captures WHERE task_public_id=?", task).Scan(&stopped, &resumed) != nil || !stopped.Valid || !resumed.Valid {
		t.Fatal("production physical recovery missing")
	}
	if db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job'", task).Scan(&jobs) != nil || jobs != 1 {
		t.Fatal("production duplicate job")
	}
	if db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_attempts WHERE target_public_id=?", task).Scan(&attempts) != nil || attempts != 1 {
		t.Fatal("production duplicate attempt")
	}
	var visibleJobs int
	if db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_job_observations j JOIN system_backup_v2_runtime_resources r ON r.task_public_id=j.target_public_id AND r.observed_uid=j.job_uid AND r.resource_kind='Job' WHERE j.target_public_id=? AND j.last_observed_status='sealed' AND j.progress_sequence=j.last_accepted_sequence AND j.progress_sequence>0 AND j.progress_digest_sha256=r.result_sha256 AND j.last_business_progress_at IS NOT NULL", task).Scan(&visibleJobs) != nil || visibleJobs != 1 {
		t.Fatal("authenticated sealed Job progress missing from user-visible projection")
	}
	identity, e := c.NewPinnedExecutionIdentity(cfg.ForwardGrant.Path, forwardHash, cfg.KeyDirectory, signing.Public().(ed25519.PublicKey))
	if e != nil {
		t.Fatal(e)
	}
	binding := staging.Binding{BackupID: task, Attempt: "1", Path: "workspace", PartIndex: 1, CaptureContextHash: grant.ConfigSHA256, EnvelopeID: "functional-workspace"}
	bindRaw, _ := json.Marshal(binding)
	key, e := identity.DeriveCaptureKey(ctx, d.Authority{InstallationID: grant.InstallationID, TaskPublicID: task, ClaimOwner: grant.ControllerOwner, ConfigVersion: grant.ConfigVersion, ConfigSHA256: grant.ConfigSHA256}, bindRaw)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(key)
	sealed, e := os.ReadFile(filepath.Join(cfg.StagingDirectory, task, "workspace.enc"))
	if e != nil {
		t.Fatal("production sealed output unavailable")
	}
	found := false
	if e = staging.ConsumeCompressed(ctx, bytes.NewReader(sealed), key, binding, cfg.Workspace.MaxCompressedBytes, cfg.Workspace.MaxArchiveBytes, func(plain io.Reader) error {
		r := tar.NewReader(plain)
		for {
			h, z := r.Next()
			if z == io.EOF {
				return nil
			}
			if z != nil {
				return z
			}
			if h.Name == "data.txt" {
				content, z := io.ReadAll(io.LimitReader(r, 1024))
				if z != nil {
					return z
				}
				if string(content) != "native-capture-preserves-source\n" {
					return errors.New("production content differs")
				}
				found = true
			}
		}
	}); e != nil || !found {
		t.Fatal("production authenticated content mismatch", e)
	}
	counter := filepath.Join("/source", cfg.Workspace.SubPath, "counter.txt")
	before, e := os.ReadFile(counter)
	if e != nil {
		t.Fatal(e)
	}
	waitNative(t, ctx, func() bool { after, z := os.ReadFile(counter); return z == nil && !bytes.Equal(before, after) })
	nativeReadCaptureDetail(t, handler, operator, task, "validating")
	// Admission is exercised against real original capture/exit/resume facts.
	// Temporarily damage only the disposable fixture's receipt, then restore
	// the exact original value; this is a fault test, not a recovery procedure.
	for _, fault := range []struct{ clear, restore string }{
		{"UPDATE system_backup_v2_runtime_captures SET source_resumed_at=NULL WHERE task_public_id=?", "UPDATE system_backup_v2_runtime_captures SET source_resumed_at=? WHERE task_public_id=?"},
		{"UPDATE system_backup_v2_runtime_writers SET resumed=FALSE WHERE task_public_id=?", "UPDATE system_backup_v2_runtime_writers SET resumed=TRUE WHERE task_public_id=?"},
	} {
		if _, z := db.Exec(fault.clear, task); z != nil {
			t.Fatal(z)
		}
		r := nativeCancelCall(handler, operator, task)
		if r.Code != http.StatusConflict {
			t.Fatal("released cancel accepted missing original recovery proof", r.Code, r.Body.String())
		}
		args := []any{task}
		if strings.Contains(fault.restore, "source_resumed_at=?") {
			args = []any{resumed.Time, task}
		}
		if _, z := db.Exec(fault.restore, args...); z != nil {
			t.Fatal(z)
		}
	}
	first := nativeCancelCall(handler, operator, task)
	var canceled read.OperationDTO
	if first.Code != http.StatusAccepted || json.Unmarshal(first.Body.Bytes(), &canceled) != nil || canceled.Status != "succeeded" {
		t.Fatal("released cancel did not close original task", first.Code, first.Body.String())
	}
	second := nativeCancelCall(handler, operator, task)
	if second.Code != http.StatusAccepted || second.Header().Get("Location") != first.Header().Get("Location") {
		t.Fatal("released cancel replay created another operation")
	}
	var canceledState, attemptState string
	if db.QueryRow("SELECT status FROM system_backup_v2_backups WHERE public_id=?", task).Scan(&canceledState) != nil || canceledState != "canceled" {
		t.Fatal("released task not canceled")
	}
	if db.QueryRow("SELECT status FROM system_backup_v2_attempts WHERE target_public_id=?", task).Scan(&attemptState) != nil || attemptState != "sealed" {
		t.Fatal("released cancellation rewrote physical capture history")
	}
	retained, z := os.ReadFile(filepath.Join(cfg.StagingDirectory, task, "workspace.enc"))
	if z != nil || !bytes.Equal(retained, sealed) {
		t.Fatal("released cancellation discarded original sealed data")
	}
	nativeReadCaptureDetail(t, handler, operator, task, "canceled")
	capacityEvidence := "synthetic capacity"
	if os.Getenv("NATIVE_BACKUP_PHYSICAL_CAPACITY") == "true" {
		capacityEvidence = "actual MySQL data-volume capacity under exact SELECT-only collector"
	}
	t.Log("actual production binary: leader + signed mounted config + fresh capability -> real TLS HTTP create -> actual worker -> source recovered -> validating -> authorized pre-publication cancellation, sealed data retained; missing recovery proofs rejected; " + capacityEvidence)
}

func nativeMinimumKubernetes(t *testing.T, ctx context.Context, client kubernetes.Interface, cfg execution.DeploymentConfig) func() {
	t.Helper()
	objects, err := execution.CaptureKubernetesGrants(cfg, "native-controller")
	if err != nil {
		t.Fatal(err)
	}
	ack := filepath.Join(filepath.Dir(cfg.ProfileFile), "kubernetes-installed")
	raw, _ := json.Marshal(map[string]any{"objects": objects, "ack_file": ack})
	fmt.Println("NATIVE_KUBERNETES_ACCESS " + string(raw))
	installed, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	waitNative(t, installed, func() bool { b, e := os.ReadFile(ack); return e == nil && string(b) == "confirmed\n" })
	restore := func() {
		ack := filepath.Join(filepath.Dir(cfg.ProfileFile), "kubernetes-restored")
		raw, _ := json.Marshal(map[string]string{"ack_file": ack})
		fmt.Println("NATIVE_KUBERNETES_RESTORE " + string(raw))
		bounded, done := context.WithTimeout(context.Background(), 40*time.Second)
		defer done()
		waitNative(t, bounded, func() bool { b, e := os.ReadFile(ack); return e == nil && string(b) == "confirmed\n" })
	}
	checks := []authv1.ResourceAttributes{
		{Namespace: cfg.Namespace, Verb: "create", Resource: "pods", Subresource: "exec", Name: "native-controller"},
		{Namespace: cfg.Namespace, Verb: "list", Resource: "secrets"},
		{Namespace: cfg.Namespace, Verb: "create", Group: "apps", Resource: "deployments"},
		{Namespace: cfg.Namespace, Verb: "update", Group: "apps", Resource: "deployments", Name: "unrelated-source"},
		{Namespace: cfg.Writers[0].Namespace, Verb: "update", Group: "apps", Resource: "deployments", Name: cfg.Writers[0].Name},
		{Namespace: cfg.Writers[0].Namespace, Verb: "patch", Group: "apps", Resource: "deployments", Name: "unrelated-source"},
		{Verb: "get", Resource: "nodes", Name: "unrelated-node"},
	}
	for _, check := range checks {
		r, e := client.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authv1.SelfSubjectAccessReview{Spec: authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &check}}, metav1.CreateOptions{})
		if e != nil || r.Status.Allowed || r.Status.EvaluationError != "" {
			restore()
			t.Fatal("minimum Kubernetes role allowed unrelated operation")
		}
	}
	t.Log("actual API server denies exec, Secret listing, source creation/unrelated mutation and unrelated node read under the temporary minimum role")
	return restore
}

func nativeReadCaptureDetail(t *testing.T, handler *Handler, token, task, status string) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "https://example.invalid/api/v1/admin/system-backups/"+task, nil)
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.Detail(w, r, read.BackupTask, task, "native-capture-detail")
	var detail map[string]any
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &detail) != nil {
		t.Fatal("actual captured task detail unavailable", status, w.Code, w.Body.String())
	}
	header, ok := detail["task"].(map[string]any)
	if !ok || header["status"] != status || detail["artifact_usable"] != false || detail["acceptance_ready"] != false {
		t.Fatal("captured detail misreported publication/readiness")
	}
	execution, ok := detail["execution"].(map[string]any)
	if !ok || execution["last_business_progress_at"] == nil || execution["job_generation"] != float64(1) {
		t.Fatal("actual HTTP detail omitted authenticated Job progress")
	}
}

func nativeCancelCall(handler *Handler, token, task string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "https://example.invalid/api/v1/admin/system-backups/"+task+"/cancel", strings.NewReader(`{}`))
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Idempotency-Key", "native-cancel-original-0001")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.Cancel(w, r, read.BackupTask, task, "native-released-cancel")
	return w
}
