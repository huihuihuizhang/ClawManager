package systembackupapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	backup "clawreef/internal/systembackup"
	b "clawreef/internal/systembackup/publicadapter"
	controller "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	read "clawreef/internal/systembackupread"
	"github.com/go-sql-driver/mysql"
)

// SQL, HTTP/RBAC, signed workload authorization, and encrypted records are real.
// The tiny Prepare runner below isolates custody from source/Kubernetes work;
// M2 separately verifies actual capture. No fixture is production composition.
type custodyPrepareRunner struct {
	d.Runner
	calls int
	cut   *atomic.Bool
}

func (r *custodyPrepareRunner) Prepare(context.Context, d.Input, d.Ports) (d.Plan, error) {
	r.calls++
	if r.cut != nil {
		r.cut.Store(true)
	}
	raw := []byte("{\n  \"custody_test\": true\n}")
	return d.Plan{SchemaVersion: b.PlanVersion, CanonicalJSON: raw, SHA256: digestJSON(raw)}, nil
}

type custodyPorts struct {
	d.Ports
	authority controller.SQLExecutionAuthority
}

func (p custodyPorts) Check(ctx context.Context, a d.Authority) error {
	return p.authority.Check(ctx, a)
}

type custodyReady struct{}

func (custodyReady) Check(context.Context) error { return nil }

// Drop an actual MySQL COMMIT acknowledgement after the server returned it.
// This is a native SQL commit, not an injected Store return value.
type lostCommitConn struct {
	net.Conn
	arm  *atomic.Bool
	cut  bool
	cuts *atomic.Int64
}

func (c *lostCommitConn) Write(p []byte) (int, error) {
	if len(p) > 5 && p[4] == 3 && string(p[5:]) == "COMMIT" && c.arm.Swap(false) {
		c.cut = true
	}
	return c.Conn.Write(p)
}
func (c *lostCommitConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if c.cut && n > 0 {
		c.cut = false
		c.cuts.Add(1)
		c.Conn.Close()
		return 0, io.ErrUnexpectedEOF
	}
	return n, err
}

func TestPublicExecutionRealSQLHTTPPlanCustodyAndRevocation(t *testing.T) {
	db, legacy := submissionMySQL(t)
	if _, err := db.Exec("UPDATE system_backup_v2_execution_readiness SET execution_protocol='public-v1',supported_parts='workspace',acceptance_ready=FALSE"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	writer, err := NewAdmittedTaskWriter(testExecutionProfile(), legacy.capacityFile, true)
	if err != nil {
		t.Fatal(err)
	}
	h, operator, viewer := liveAdmissionHTTP(t, db, writer)
	send := func(token, key string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "https://example.invalid/api/v1/admin/system-backups", strings.NewReader(`{"requested_parts":["workspace"],"task_purpose":"functional_test"}`))
		r.TLS = &tls.ConnectionState{}
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Idempotency-Key", key)
		r.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		h.Create(res, r, read.BackupTask, "m1-http-request")
		return res
	}
	if res := send(viewer, "public-viewer-key-0001"); res.Code != 403 {
		t.Fatalf("viewer status %d", res.Code)
	}
	res := send(operator, "public-operator-key-0001")
	if res.Code != 202 {
		t.Fatalf("create %d %s", res.Code, res.Body.String())
	}
	if replay := send(operator, "public-operator-key-0001"); replay.Code != 202 || replay.Header().Get("Location") != res.Header().Get("Location") {
		t.Fatal("replay changed task", replay.Code, replay.Body.String())
	}
	var id, server, database, configHash string
	if err = db.QueryRow("SELECT public_id,config_snapshot_sha256 FROM system_backup_v2_backups").Scan(&id, &configHash); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow("SELECT @@server_uuid,DATABASE()").Scan(&server, &database); err != nil {
		t.Fatal(err)
	}
	// Dedicated SQL workload; these broad test-schema grants are not production
	// grant acceptance. The production probe still requires its exact matrix.
	user := "m1_" + strings.ReplaceAll(id[4:16], "-", "")
	if _, err = db.Exec("CREATE USER '" + user + "'@'%' IDENTIFIED BY 'synthetic-m1-only'"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Exec("DROP USER '" + user + "'@'%'") })
	if _, err = db.Exec("GRANT ALL PRIVILEGES ON `" + database + "`.* TO '" + user + "'@'%'"); err != nil {
		t.Fatal(err)
	}
	cfg := mysql.Config{User: user, Passwd: "synthetic-m1-only", Net: "tcp", Addr: "127.0.0.1:" + os.Getenv("TEST_SYSTEM_BACKUP_MYSQL_PORT"), DBName: database, ParseTime: true, AllowNativePasswords: true}
	var cutCommit atomic.Bool
	var cuts atomic.Int64
	dialName := "lost-commit-" + user
	mysql.RegisterDialContext(dialName, func(ctx context.Context, addr string) (net.Conn, error) {
		conn, e := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		if e != nil {
			return nil, e
		}
		return &lostCommitConn{Conn: conn, arm: &cutCommit, cuts: &cuts}, nil
	})
	defer mysql.DeregisterDialContext(dialName)
	cfg.Net = dialName
	control, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	gate := backup.Gate{DB: db}
	if err = gate.EnsureScope(ctx, "installation"); err != nil {
		t.Fatal(err)
	}
	if err = (controller.SQLGateInitializer{DB: db}).Ensure(ctx, "installation_admission", controller.GatePolicy{LockTTL: 900 * time.Second, AcquisitionTimeout: 60 * time.Second, MaxHold: 600 * time.Second}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	key := make([]byte, 32)
	rand.Read(key)
	if err = os.WriteFile(filepath.Join(dir, "record-v1"), key, 0600); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	owner := "m1-controller-" + user
	grant := controller.ExecutionGrant{Version: "system-backup-execution-grant.v1", InstallationID: "installation_admission", ControllerOwner: owner, DatabaseAccount: user + "@%", ServerUUID: server, Database: database, ConfigVersion: 1, ConfigSHA256: configHash, ProfileSHA256: legacy.hash, NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Actions: []string{"prepare", "capture"}, RecordKeys: []controller.ExecutionRecordKey{{Ref: "record-v1", SHA256: digestJSON(key)}}}
	payload, _ := json.Marshal(grant)
	envelope, _ := json.Marshal(map[string]string{"payload_base64": base64.StdEncoding.EncodeToString(payload), "signature_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))})
	grantPath := filepath.Join(dir, "execution-grant.json")
	if err = os.WriteFile(grantPath, envelope, 0600); err != nil {
		t.Fatal(err)
	}
	identity, err := controller.NewPinnedExecutionIdentity(grantPath, digestJSON(envelope), dir, pub)
	if err != nil {
		t.Fatal(err)
	}
	authority := controller.SQLExecutionAuthority{DB: control, InstallationID: "installation_admission", Authorization: identity, DeploymentEnabled: true, ApplicationScope: "installation"}
	records := controller.SQLExecutionRecords{Authority: authority, Keys: identity, CapacityReportFile: legacy.capacityFile}
	queue := controller.SQLExecutionQueue{DB: control, InstallationID: "installation_admission", Owner: owner, Policy: controller.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 10 * time.Second, ReconcileInterval: time.Second}, Authorization: identity, ApplicationScope: "installation"}
	scheduler := &controller.SQLExecutionWorkStore{Queue: queue, Authority: authority, Records: records, PrepareCapture: func(context.Context, controller.ClaimedBackup) (*controller.ExecutionWork, error) {
		return nil, errors.New("capture intentionally outside M1 test")
	}}
	durable := controller.DurableExecutionStore{Scheduler: scheduler, Records: records}
	runner := &custodyPrepareRunner{cut: &cutCommit}
	bound, err := d.BindTaskRunner(runner, b.PlanVersion)
	if err != nil {
		t.Fatal(err)
	}
	loop := controller.TaskExecutionLoop{Guard: custodyReady{}, Store: durable, Dispatch: d.Dispatcher{Runner: bound, Ports: custodyPorts{authority: authority}}, Interval: time.Second}
	if err = loop.RunOnce(ctx); !errors.Is(err, controller.ErrExecutionCommitUnknown) || cuts.Load() != 1 {
		t.Fatal("lost commit was not observed", err, cuts.Load())
	}
	if _, err = db.Exec("UPDATE system_backup_v2_backups SET controller_lease_expires_at=TIMESTAMPADD(SECOND,-1,UTC_TIMESTAMP(6)),next_reconcile_at=UTC_TIMESTAMP(6) WHERE public_id=?", id); err != nil {
		t.Fatal(err)
	}
	// Restart replays custody into the scheduler without invoking Prepare again.
	if err = loop.RunOnce(ctx); err != nil {
		t.Fatal("restart after unknown commit", err)
	}
	var status string
	var sealed []byte
	var count int
	if err = db.QueryRow("SELECT status FROM system_backup_v2_backups WHERE public_id=?", id).Scan(&status); err != nil || status != "ready_for_capture" {
		t.Fatal(status, err)
	}
	if err = db.QueryRow("SELECT sealed_payload FROM system_backup_v2_execution_records WHERE task_public_id=? AND record_kind='plan'", id).Scan(&sealed); err != nil || bytes.Contains(sealed, []byte("custody_test")) {
		t.Fatal("plaintext or no plan", err)
	}
	if err = db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_events WHERE target_public_id=? AND event_type=?", id, controller.TaskClaimAcquiredEvent).Scan(&count); err != nil || count != 2 || runner.calls != 1 {
		t.Fatal("claim receipt or duplicate prepare", count, runner.calls, err)
	}
	// A fresh scheduler reads the original encrypted plan under a newly acquired
	// claim. No in-memory Prepare result or old lease grants that read.
	if _, err = db.Exec("UPDATE system_backup_v2_backups SET next_reconcile_at=UTC_TIMESTAMP(6) WHERE public_id=?", id); err != nil {
		t.Fatal(err)
	}
	claimed, err := queue.TakeBackup(ctx)
	if err != nil {
		t.Fatal("restart claim", err)
	}
	tx, err := control.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	input, err := claimed.ExecutionInput(ctx, tx)
	tx.Rollback()
	if err != nil {
		t.Fatal(err)
	}
	originalPlan, err := records.LoadPlan(ctx, input)
	innerPlan, unwrapErr := d.UnwrapTaskPlan(input, originalPlan, b.PlanVersion)
	if err != nil || unwrapErr != nil || !bytes.Equal(innerPlan.CanonicalJSON, []byte("{\n  \"custody_test\": true\n}")) || runner.calls != 1 {
		t.Fatal("original plan lost or rediscovered", err)
	}
	corrupt := append([]byte(nil), sealed...)
	corrupt[len(corrupt)-1] ^= 1
	if _, err = db.Exec("UPDATE system_backup_v2_execution_records SET sealed_payload=? WHERE task_public_id=?", corrupt, id); err != nil {
		t.Fatal(err)
	}
	if _, err = records.LoadPlan(ctx, input); err == nil {
		t.Fatal("corrupt custody accepted")
	}
	if _, err = db.Exec("UPDATE system_backup_v2_execution_records SET sealed_payload=? WHERE task_public_id=?", sealed, id); err != nil {
		t.Fatal(err)
	}
	if _, err = records.LoadPlan(ctx, input); err != nil {
		t.Fatal("restored original unreadable", err)
	}
	// A separately pinned envelope with a changed payload must still fail its
	// independent issuer signature; digest pinning alone is not authentication.
	badEnvelope := append([]byte(nil), envelope...)
	var bad map[string]string
	json.Unmarshal(badEnvelope, &bad)
	bad["payload_base64"] = base64.StdEncoding.EncodeToString(bytes.Replace(payload, []byte("m1-controller"), []byte("xx-controller"), 1))
	badEnvelope, _ = json.Marshal(bad)
	badPath := filepath.Join(dir, "bad-grant.json")
	os.WriteFile(badPath, badEnvelope, 0600)
	if _, err = controller.NewPinnedExecutionIdentity(badPath, digestJSON(badEnvelope), dir, pub); err == nil {
		t.Fatal("forged signed grant accepted")
	}
	if _, err = (controller.ClaimCoordinator{Executor: control, InstallationID: queue.InstallationID}).Release(ctx, claimed.Claim, time.Second); err != nil {
		t.Fatal(err)
	}
	// Revocation happens outside the model/SQL authority and must block claim
	// atomically. Deleting the grant cannot be bypassed by an existing pointer.
	if err = os.Remove(grantPath); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("UPDATE system_backup_v2_backups SET next_reconcile_at=UTC_TIMESTAMP(6) WHERE public_id=?", id); err != nil {
		t.Fatal(err)
	}
	if _, err = queue.TakeBackup(ctx); !errors.Is(err, controller.ErrExecutionAuthority) {
		t.Fatal("revocation ignored", err)
	}
	var stillClaimed bool
	if err = db.QueryRow("SELECT controller_owner IS NOT NULL FROM system_backup_v2_backups WHERE public_id=?", id).Scan(&stillClaimed); err != nil || stillClaimed {
		t.Fatal("revoked claim leaked", stillClaimed, err)
	}
}
