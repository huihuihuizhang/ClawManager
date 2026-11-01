package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"clawreef/internal/systembackup/control"
	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Actual PublicJobOwner.Bind and native SQL, with explicitly local modeled
// Kubernetes objects and a real locally signed worker TLS identity. This is
// existing-binding recovery only, not new first-binding or cross-process proof.
func TestOriginalPublicBindExistingIdentityReadbackMySQL(t *testing.T) {
	if os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS") == "" {
		t.Skip("requires isolated local MySQL")
	}
	var lost atomic.Bool
	options := &consumerFixtureOptions{WrapControlConnector: func(conn driver.Connector) driver.Connector {
		return dBindReadbackACKConnector{Connector: conn, lose: &lost}
	}}
	owner, _, admin, db, authority, original, _, _, _ := newConsumerMySQLFixtureOptions(t, options)
	ctx := context.Background()
	if _, err := admin.ExecContext(ctx, `ALTER TABLE system_backup_v2_backups ADD COLUMN heartbeat_at DATETIME(6) NULL`); err != nil {
		t.Fatal(err)
	}
	_, _, desc, err := owner.input(ctx, authority, false)
	if err != nil {
		t.Fatal(err)
	}
	part, err := partFor(desc, original.JobUnitKey)
	if err != nil {
		t.Fatal(err)
	}
	var job batchv1.Job
	if json.Unmarshal(part.Intent.SpecJSON, &job) != nil {
		t.Fatal("original frozen Job unavailable")
	}
	var secretName string
	for _, volume := range job.Spec.Template.Spec.Volumes {
		if volume.Name == "worker-identity" && volume.Secret != nil {
			secretName = volume.Secret.SecretName
		}
	}
	if secretName == "" {
		t.Fatal("original identity Secret declaration missing")
	}
	var issuer control.IdentityIssuer
	originalMTLSControlServer(t, http.NotFoundHandler(), func(value control.IdentityIssuer) { issuer = value })
	identity, err := issuer.IssueWorker(authority.TaskPublicID, authority.DeadlineAt, part.InvocationSHA256)
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Clear()
	plain, err := json.Marshal(identity.Data)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	ref, key, err := owner.Identity.Resolve(ctx, authority, "")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	envelope := identityEnvelope{KeyRef: ref, PlainSHA256: hash(plain), InvocationSHA256: part.InvocationSHA256}
	var sealed bytes.Buffer
	if err := staging.Seal(ctx, &sealed, key, identityBinding(authority, secretName, envelope.PlainSHA256), func(w io.Writer) error { _, err := w.Write(plain); return err }); err != nil {
		t.Fatal(err)
	}
	envelope.Cipher = sealed.Bytes()
	rawEnvelope, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	immutable := true
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: original.Namespace, Name: secretName, UID: types.UID("original-bind-readback-identity")}, Immutable: &immutable, Data: identity.Data}
	if _, err := owner.Client.CoreV1().Secrets(original.Namespace).Create(ctx, secret, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, `INSERT INTO system_backup_v2_runtime_resources(task_public_id,resource_kind,namespace_name,resource_name,resource_owner,request_sha256,request_json,row_version,create_dispatched,observed_uid,resource_version,lifecycle,attempt_no,phase) VALUES(?,'IdentitySecret',?,?,?,?,?,1,TRUE,?,'1','ready',?,'capture')`, authority.TaskPublicID, original.Namespace, secretName, authority.TaskPublicID, hash(rawEnvelope), rawEnvelope, string(secret.UID), authority.AttemptNo); err != nil {
		t.Fatal(err)
	}
	certificate, err := originalWorkerIdentityCertificate(secret, string(secret.UID), hash(rawEnvelope), rawEnvelope, owner.TrustDomain, authority.TaskPublicID, part.InvocationSHA256)
	if err != nil {
		t.Fatal(err)
	}
	binding := original
	binding.RelayIdentityRef = string(secret.UID)
	binding.RelayIdentityVersion = hash(certificate.Raw)
	binding.RelayBoundAt = time.Now().UTC().Truncate(time.Microsecond)
	binding.RelayExpiresAt = certificate.NotAfter
	if authority.DeadlineAt.Before(binding.RelayExpiresAt) {
		binding.RelayExpiresAt = authority.DeadlineAt
	}
	var invocation worker.Invocation
	if err := json.Unmarshal(part.InvocationJSON, &invocation); err != nil {
		t.Fatal(err)
	}
	if invocation.Request.Deadline.Before(binding.RelayExpiresAt) {
		binding.RelayExpiresAt = invocation.Request.Deadline
	}
	binding.RelayExpiresAt = binding.RelayExpiresAt.UTC().Truncate(time.Microsecond)
	encoded, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, `UPDATE system_backup_v2_runtime_resources SET binding_json=? WHERE resource_kind='Job' AND observed_uid=?`, encoded, original.UID); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, `UPDATE system_backup_v2_backups SET controller_lease_expires_at=TIMESTAMPADD(SECOND,20,UTC_TIMESTAMP(6)) WHERE public_id=?`, authority.TaskPublicID); err != nil {
		t.Fatal(err)
	}
	var raw, keyUse []byte
	var revision int64
	var dispatched bool
	var resourceVersion string
	if err := admin.QueryRowContext(ctx, `SELECT request_json,row_version,create_dispatched,resource_version,key_use_json FROM system_backup_v2_runtime_resources WHERE resource_kind='Job' AND observed_uid=?`, original.UID).Scan(&raw, &revision, &dispatched, &resourceVersion, &keyUse); err != nil {
		t.Fatal(err)
	}
	record := kube.ResourceRecord{Intent: kube.ResourceIntent{Kind: "Job", Identity: kube.Identity{Namespace: original.Namespace, Name: original.Name, Owner: authority.TaskPublicID}, RequestJSON: raw}, Revision: revision, CreateDispatched: dispatched, UID: original.UID, ResourceVersion: resourceVersion}
	if err := admin.QueryRowContext(ctx, `SELECT request_sha256 FROM system_backup_v2_runtime_resources WHERE resource_kind='Job' AND observed_uid=?`, original.UID).Scan(&record.Intent.RequestSHA256); err != nil {
		t.Fatal(err)
	}
	var lease time.Time
	var epoch uint64
	if err := admin.QueryRowContext(ctx, `SELECT controller_lease_expires_at,row_version FROM system_backup_v2_backups WHERE public_id=?`, authority.TaskPublicID).Scan(&lease, &epoch); err != nil {
		t.Fatal(err)
	}
	store := c.SQLExecutionWorkStore{Queue: c.SQLExecutionQueue{DB: db, InstallationID: authority.InstallationID, Owner: authority.ClaimOwner, ApplicationScope: owner.Gate.Authority.ApplicationScope, Policy: c.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second}}, Authority: owner.Gate.Authority, Records: owner.Gate.Records}
	err = store.RunWithExecutionHeartbeat(ctx, authority, func(active context.Context) error {
		for attempt := 0; attempt < 3; attempt++ {
			if attempt == 1 {
				lost.Store(true)
			}
			got, err := owner.Bind(active, authority, part.Intent, record)
			if attempt == 1 {
				if !errors.Is(err, c.ErrExecutionCommitUnknown) {
					t.Fatalf("actual existing Bind did not expose lost commit ACK: %v", err)
				}
				continue
			}
			if err != nil || got != binding {
				t.Fatalf("actual existing Bind readback changed: %+v %v", got, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if lost.Load() {
		t.Fatal("actual Commit did not consume the lost-ACK fault")
	}
	// A separately opened controller scope must also recover the same original
	// identity. This is a fresh in-process run, not a cross-process restart.
	err = store.RunWithExecutionHeartbeat(ctx, authority, func(active context.Context) error {
		got, err := owner.Bind(active, authority, part.Intent, record)
		if err != nil || got != binding {
			t.Fatalf("fresh controller scope changed existing Bind: %+v %v", got, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var afterBinding, afterKey []byte
	var afterLease time.Time
	var afterEpoch uint64
	if err := admin.QueryRowContext(ctx, `SELECT binding_json,key_use_json FROM system_backup_v2_runtime_resources WHERE resource_kind='Job' AND observed_uid=?`, original.UID).Scan(&afterBinding, &afterKey); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRowContext(ctx, `SELECT controller_lease_expires_at,row_version FROM system_backup_v2_backups WHERE public_id=?`, authority.TaskPublicID).Scan(&afterLease, &afterEpoch); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, afterBinding) || !bytes.Equal(keyUse, afterKey) || !lease.Equal(afterLease) || epoch != afterEpoch {
		t.Fatal("existing Bind/unknown readback renewed claim or replaced original binding/key-use")
	}
}

// Lose only the ACK of the real transaction that reads the original Job
// binding. Preliminary authority/plan reads and the ordinary heartbeat cannot
// consume the fault, even if a slow native test crosses a heartbeat interval.
type dBindReadbackACKConnector struct {
	driver.Connector
	lose *atomic.Bool
}

func (c dBindReadbackACKConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &dBindReadbackACKConn{Conn: conn, lose: c.lose}, nil
}

type dBindReadbackACKConn struct {
	driver.Conn
	lose    *atomic.Bool
	binding atomic.Bool
}

func (c *dBindReadbackACKConn) Begin() (driver.Tx, error) {
	c.binding.Store(false)
	tx, err := c.Conn.Begin()
	if err != nil {
		return nil, err
	}
	return dBindReadbackACKTx{Tx: tx, conn: c}, nil
}

func (c *dBindReadbackACKConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	c.binding.Store(false)
	tx, err := c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return dBindReadbackACKTx{Tx: tx, conn: c}, nil
}

func (c *dBindReadbackACKConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	// MySQL may return driver.ErrSkip so database/sql executes this exact
	// query through Prepare instead. Mark its owning transaction before that
	// transparent fallback; any failed read still prevents the real Commit.
	if strings.HasPrefix(query, "SELECT binding_json FROM system_backup_v2_runtime_resources WHERE ") && strings.HasSuffix(query, " FOR UPDATE") {
		c.binding.Store(true)
	}
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
}

func (c *dBindReadbackACKConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, query, args)
}

type dBindReadbackACKTx struct {
	driver.Tx
	conn *dBindReadbackACKConn
}

func (t dBindReadbackACKTx) Commit() error {
	if err := t.Tx.Commit(); err != nil {
		return err
	}
	if t.conn.binding.Load() && t.conn.lose.Swap(false) {
		return errAPublicationACKLost
	}
	return nil
}
