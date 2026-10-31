package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	k "clawreef/internal/systembackupkms"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type aOriginalIssuerFixture struct {
	ctx             context.Context
	db, owner       *sql.DB
	cfg             a.ControllerVerifierConfig
	in              d.Input
	job             d.JobBinding
	invocation      worker.Invocation
	unwrapPin       a.ProviderCapabilityPin
	original        a.OriginalRecord
	putOriginal     func(a.OriginalRecord, uint64)
	dek             []byte
	onCaptureLogin  func(func() error)
	generationCalls func() int64
	updateOriginal  func(a.OriginalRecord, uint64) error
}

// Real local SQL transactions/current deploymentAuthorization and TLS provider;
// K8s is a fake API. This exercises actual original keyUseTx + issuer Stage +
// readback + worker kms consumer, not a real cluster/mTLS/6-part acceptance.
func TestAProviderPermitIssuerOriginalSQLAndTLS(t *testing.T) {
	aProviderPermitIssuerOriginalSQLAndTLS(t, false)
}

func TestAProviderPermitIssuerRevokedAfterLogin(t *testing.T) {
	aProviderPermitIssuerOriginalSQLAndTLS(t, true)
}

func TestAProviderPermitIssuerNanosecondAuthorizationDeadline(t *testing.T) {
	aProviderPermitIssuerOriginalSQLAndTLS(t, false, true)
}

func aProviderPermitIssuerOriginalSQLAndTLS(t *testing.T, revokedAfterLogin bool, nanos ...bool) {
	aControllerVerifierOriginalSQLAndTLS(t, false, func(f aOriginalIssuerFixture) {
		ctx, db := f.ctx, f.db
		exec := func(query string, args ...any) {
			t.Helper()
			if _, err := f.owner.ExecContext(ctx, query, args...); err != nil {
				t.Fatal(err)
			}
		}
		permission := a.ProviderCapabilityPermission{Path: "transit/datakey/plaintext/original-key", ProviderVersion: "1", AuthMount: "capture-jwt", Role: "capture-generate-role", Policy: "capture-generate-policy", PolicySHA256: strings.Repeat("a", 64), RoleSHA256: strings.Repeat("b", 64), JWTTrustSHA256: strings.Repeat("c", 64), Reference: f.cfg.Binding.GenerateRef}
		now := time.Now().UTC()
		capRecord := a.ProviderCapabilityRecord{Facts: a.ProviderCapabilityFacts{Binding: f.cfg.Binding, Operation: k.Generate, Permission: permission}, Source: reg.SourceRecord{SourceID: "original-provider-permission-owner", RecordID: "sev_original_capture_generate", RecordVersion: "v1"}, Revision: "r1", NotBefore: now.Add(-time.Minute), Until: now.Add(time.Minute)}
		factsRaw, _ := json.Marshal(capRecord.Facts)
		capRecord.Source.ContentSHA256 = hash(factsRaw)
		capPublic, capKey, _ := ed25519.GenerateKey(rand.Reader)
		defer clear(capKey)
		capRaw, _ := json.Marshal(capRecord)
		capEnvelope, _ := json.Marshal(a.SignedProviderCapabilityRecord{Record: capRaw, Signature: ed25519.Sign(capKey, append([]byte(a.ProviderCapabilityDomain), capRaw...))})
		exec(`INSERT INTO system_backup_v2_evidence(public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,observed_health,encryption,inline_payload,content_checksum,content_size_bytes,expires_at,media_type,redaction_classification) VALUES (?,'system',?,'capability_snapshot','inline','healthy','none',?,?,?,?,'application/json','internal')`, capRecord.Source.RecordID, f.in.Authority.InstallationID, capEnvelope, hash(capEnvelope), len(capEnvelope), capRecord.Until)
		capabilities, err := a.NewSQLProviderCapabilityPreparation(db, f.originalDatabase(), f.in.Authority.InstallationID, a.ProviderCapabilityPin{Source: capRecord.Source, Issuer: capPublic}, f.unwrapPin)
		if err != nil {
			t.Fatal(err)
		}
		rootPublic, rootKey, _ := ed25519.GenerateKey(rand.Reader)
		defer clear(rootKey)
		issuerPublic, issuerKey, _ := ed25519.GenerateKey(rand.Reader)
		defer clear(issuerKey)
		workload := f.cfg.Workload
		workload.GrantSHA256 = ""
		jwtFile := filepath.Join(t.TempDir(), "job.jwt")
		if err = os.WriteFile(jwtFile, []byte("local-capture-projected-jwt-only"), 0600); err != nil {
			t.Fatal(err)
		}
		var account string
		if db.QueryRowContext(ctx, "SELECT CURRENT_USER()").Scan(&account) != nil {
			t.Fatal("original issuer SQL account unavailable")
		}
		grant := a.ProviderPermitIssuerGrant{Version: "system-backup-provider-permit-issuer-grant.v1", Binding: f.cfg.Binding, Database: f.originalDatabase(), DatabaseAccount: account, Workload: workload, SigningPublicKey: issuerPublic, GeneratePermission: permission, WorkerNamespace: f.job.Namespace, WorkerServiceAccountName: "capture-worker", WorkerServiceAccountUID: "capture-sa-uid", WorkerJWTIdentityFile: jwtFile, NotBefore: now.Add(-time.Minute), Until: now.Add(time.Minute)}
		nanosecondMinimum := len(nanos) > 0 && nanos[0]
		if nanosecondMinimum {
			grant.Until = now.Truncate(time.Second).Add(35*time.Second + 123456789*time.Nanosecond)
		}
		grantRaw, _ := json.Marshal(grant)
		// The delegation has no Forward/capture grant/profile/deployment digest.
		// Its independent pin can be frozen into materials BEFORE those parents.
		if bytes.Contains(grantRaw, []byte(f.cfg.CaptureGrantSHA256)) {
			t.Fatal("parent Forward hash reintroduced into issuer delegation")
		}
		grantEnvelope, _ := json.Marshal(a.SignedProviderPermitIssuerGrant{Record: grantRaw, Signature: ed25519.Sign(rootKey, append([]byte(a.ProviderPermitIssuerGrantDomain), grantRaw...))})
		grantFile := filepath.Join(t.TempDir(), "issuer-grant.json")
		keyFile := filepath.Join(t.TempDir(), "permit-signing-key")
		if os.WriteFile(grantFile, grantEnvelope, 0600) != nil || os.WriteFile(keyFile, issuerKey, 0600) != nil {
			t.Fatal("local issuer mounts unavailable")
		}
		workload.GrantSHA256 = hash(grantEnvelope)
		issuerConfig := a.ProviderPermitIssuerConfig{Capabilities: capabilities, Binding: f.cfg.Binding, InstallationIssuer: f.cfg.InstallationIssuer, Authority: f.cfg.Authority, Records: f.cfg.Records, Kubernetes: f.cfg.Kubernetes, Workload: workload, CaptureGrantSHA256: f.cfg.CaptureGrantSHA256, GrantMount: a.ProviderPermitIssuerGrantMount{File: grantFile, SHA256: hash(grantEnvelope), Issuer: rootPublic}, SigningKeyFile: keyFile}
		issuer, err := a.NewProviderPermitIssuer(issuerConfig)
		if err != nil {
			t.Fatal("independent original Generate delegation rejected", err)
		}
		var requestRaw []byte
		if db.QueryRowContext(ctx, `SELECT request_json FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job'`, f.in.Authority.TaskPublicID).Scan(&requestRaw) != nil {
			t.Fatal("original normalized Job unavailable")
		}
		var job batchv1.Job
		if json.Unmarshal(requestRaw, &job) != nil {
			t.Fatal("invalid original Job")
		}
		job.UID = types.UID(f.job.UID)
		job.ResourceVersion = "1"
		if _, err = f.cfg.Kubernetes.BatchV1().Jobs(f.job.Namespace).Create(ctx, &job, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err = f.cfg.Kubernetes.CoreV1().ServiceAccounts(f.job.Namespace).Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "capture-worker", Namespace: f.job.Namespace, UID: "capture-sa-uid"}}, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		controller := true
		if _, err = f.cfg.Kubernetes.CoreV1().Pods(f.job.Namespace).Create(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "capture-pod", Namespace: f.job.Namespace, UID: "capture-pod-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: f.job.Name, UID: types.UID(f.job.UID), Controller: &controller}}}, Spec: corev1.PodSpec{ServiceAccountName: "capture-worker"}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		invocationHash, _ := f.invocation.Hash()
		scope := a.ProviderPermitIssueScope{Input: f.in, Job: f.job, Invocation: f.invocation, WorkerIdentity: k.JobIdentity{Namespace: f.job.Namespace, PodUID: "capture-pod-uid", ServiceAccountUID: "capture-sa-uid", JobUID: f.job.UID, InvocationSHA256: invocationHash, ExecutionGrantSHA256: f.cfg.CaptureGrantSHA256}, WorkerPodName: "capture-pod"}
		original := &aSQLPermitOriginal{fixture: f, issuer: issuer, scope: scope, nonce: strings.Repeat("d", 32), until: now.Add(40 * time.Second), owner: &PublicJobOwner{Gate: c.SQLCaptureGate{Authority: f.cfg.Authority, Records: f.cfg.Records}, Identity: f.cfg.Records.Keys.(*c.PinnedExecutionIdentity)}}
		// Rollback does not publish a permit or a planned reference.
		if _, err = original.control(ctx, "key-reserve", false); !errors.Is(err, aExpectedPermitRollback) {
			t.Fatal("actual Stage must succeed then rollback deny committed readback", err)
		}
		var members int
		if db.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_kek_references`).Scan(&members) != nil || members != 0 {
			t.Fatal("rolled back reserve retained an index member")
		}
		delivery, err := original.control(ctx, "key-reserve", true)
		if err != nil {
			t.Fatal("original provider permit reserve failed", err)
		}
		var body k.DeliveredPermitPayload
		if json.Unmarshal(delivery.Payload, &body) != nil {
			t.Fatal("issued payload unavailable")
		}
		var sqlExpires time.Time
		if db.QueryRowContext(ctx, `SELECT expires_at FROM system_backup_v2_evidence WHERE evidence_type='diagnostic' AND owner_target_type='backup'`).Scan(&sqlExpires) != nil || !body.Permit.ExpiresAt.Equal(original.lease.Until) || !sqlExpires.Equal(original.lease.Until) || !original.until.Equal(original.until.UTC().Truncate(time.Microsecond)) {
			t.Fatal("original lease, signature and DATETIME(6) precision diverged")
		}
		if nanosecondMinimum {
			want := grant.Until.UTC().Truncate(time.Microsecond)
			if grant.Until.Equal(want) || !original.until.Equal(want) || !original.until.Before(grant.Until) {
				t.Fatal("nanosecond independent owner minimum was rounded/extended", original.until, grant.Until)
			}
		}
		var state string
		if db.QueryRowContext(ctx, `SELECT reference_state FROM system_backup_v2_kek_references`).Scan(&state) != nil || state != "planned" {
			t.Fatal("reserve did not atomically retain planned original reference")
		}
		// Replay requires no private signing key and returns original bytes.
		if err = os.WriteFile(keyFile, bytes.Repeat([]byte{1}, 64), 0600); err != nil {
			t.Fatal(err)
		}
		prepared, err := issuer.Prepare(ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
		if err != nil {
			t.Fatal(err)
		}
		if err = prepared.Stage(ctx, tx, original.lease, "key-reserve"); err != nil {
			tx.Rollback()
			t.Fatal("original permit replay tried to re-sign", err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
		replayed, err := prepared.ReadCommitted(ctx)
		if err != nil || !bytes.Equal(replayed.Payload, delivery.Payload) || !bytes.Equal(replayed.Signature, delivery.Signature) {
			t.Fatal("unknown ACK replay changed original signed bytes", err)
		}
		if err = os.WriteFile(keyFile, issuerKey, 0600); err != nil {
			t.Fatal(err)
		}
		pin := k.PermitDeliveryPin{Version: k.PermitDeliveryVersion, Issuer: issuerPublic, IssuerGrantSHA256: hash(grantEnvelope)}
		config := k.Config{Endpoint: f.cfg.Binding.Provider.Endpoint, InstallationID: f.in.Authority.InstallationID, KeyName: f.cfg.Binding.Provider.KeyName, Key: f.cfg.Binding.Key, CAPEM: f.cfg.CAPEM, CASHA256: f.cfg.Binding.Provider.CAPEMSHA256, NotBefore: now.Add(-time.Minute), NotAfter: original.until}
		capture, err := k.NewDeliveredCaptureJob(ctx, config, pin, delivery, original, f.invocation.ProviderKey.Request)
		if err != nil {
			t.Fatal("real original SQL permit consumer rejected", err)
		}
		defer capture.Close()
		// Constructor's authenticated key-check conservatively marks unknown
		// BEFORE JWT/provider RPC, since generation precedes DEK WithUse.
		if db.QueryRowContext(ctx, `SELECT reference_state FROM system_backup_v2_kek_references`).Scan(&state) != nil || state != "unknown" {
			t.Fatal("possible provider write not retained before provider I/O")
		}
		used := false
		var borrowed []byte
		var loginRevoked atomic.Bool
		if revokedAfterLogin {
			revoked := f.original
			revoked.GenerateRevoked = true
			revoked.Revision = "provider-owner-login-r2"
			f.onCaptureLogin(func() error {
				if err := f.updateOriginal(revoked, 1); err != nil {
					return err
				}
				loginRevoked.Store(true)
				return nil
			})
		}
		wrapped, err := capture.WithDEK(ctx, func(key []byte) error {
			used = true
			borrowed = key
			if !bytes.Equal(key, f.dek) {
				t.Fatal("wrong dynamically authorized DEK")
			}
			return nil
		})
		if revokedAfterLogin {
			if err == nil || used || !loginRevoked.Load() || f.generationCalls() != 0 {
				t.Fatal("current original Generate revoke after login failed to block provider", err, loginRevoked.Load(), f.generationCalls())
			}
			if db.QueryRowContext(ctx, `SELECT reference_state FROM system_backup_v2_kek_references`).Scan(&state) != nil || state != "unknown" {
				t.Fatal("post-login revoke released possible write")
			}
			return
		}
		if err != nil || !used || len(wrapped.Ciphertext) == 0 {
			t.Fatal("actual SQL→issuer→JWT→TLS Generate→original key-use failed", err)
		}
		if f.generationCalls() != 1 {
			t.Fatal("unexpected provider call count", f.generationCalls())
		}
		if !bytes.Equal(borrowed, make([]byte, 32)) {
			t.Fatal("borrowed DEK survived callback")
		}
		if _, err = capture.WithDEK(ctx, func([]byte) error { t.Fatal("repeated Generate callback"); return nil }); err == nil {
			t.Fatal("same original envelope generated twice")
		}
		if db.QueryRowContext(ctx, `SELECT reference_state FROM system_backup_v2_kek_references`).Scan(&state) != nil || state != "unknown" {
			t.Fatal("key-end incorrectly released or proved retention")
		}
		var stored int
		if db.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_evidence WHERE evidence_type='diagnostic' AND owner_target_type='backup'`).Scan(&stored) != nil || stored != 1 {
			t.Fatal("retries minted duplicate permits")
		}
		f.original.GenerateRevoked = true
		f.original.Revision = "provider-owner-r2"
		f.putOriginal(f.original, 1)
		if _, err = issuer.Prepare(ctx, scope); err == nil {
			t.Fatal("new permit ignored original owner Generate revocation")
		}
		if _, err = prepared.ReadCommitted(ctx); err == nil {
			t.Fatal("stored permit ignored current original owner Generate revocation")
		}
		if db.QueryRowContext(ctx, `SELECT reference_state FROM system_backup_v2_kek_references`).Scan(&state) != nil || state != "unknown" {
			t.Fatal("revocation lost possible external write")
		}
	})
}

func (f aOriginalIssuerFixture) originalDatabase() reg.DatabaseIdentity {
	var d reg.DatabaseIdentity
	if f.db.QueryRowContext(f.ctx, "SELECT @@server_uuid,DATABASE()").Scan(&d.ServerUUID, &d.Database) != nil {
		return reg.DatabaseIdentity{}
	}
	return d
}

// This test bridge runs the actual original keyUseTx and issuer on every
// protocol action. It does not simulate mTLS/TokenReview or replace D's handler.
type aSQLPermitOriginal struct {
	fixture aOriginalIssuerFixture
	issuer  *a.ProviderPermitIssuer
	scope   a.ProviderPermitIssueScope
	owner   *PublicJobOwner
	lease   worker.KeyUseLease
	nonce   string
	until   time.Time
	used    bool
}

var aExpectedPermitRollback = errors.New("test original Stage succeeded; rollback denied readback")

func (o *aSQLPermitOriginal) Identity() k.JobIdentity { return o.scope.WorkerIdentity }
func (o *aSQLPermitOriginal) PermitNonce() string     { return o.nonce }
func (o *aSQLPermitOriginal) ValidUntil() time.Time   { return o.until }
func (o *aSQLPermitOriginal) Recheck(ctx context.Context, access k.Access) error {
	if access != *o.scope.Invocation.ProviderKey {
		return k.ErrPermission
	}
	_, err := o.control(ctx, "key-check", true)
	return err
}
func (o *aSQLPermitOriginal) WithUse(ctx context.Context, access k.Access, use func() error) error {
	if o.used || access != *o.scope.Invocation.ProviderKey {
		return k.ErrPermission
	}
	o.used = true
	if _, err := o.control(ctx, "key-begin", true); err != nil {
		return err
	}
	if err := use(); err != nil {
		return err
	}
	_, err := o.control(ctx, "key-end", true)
	return err
}
func (o *aSQLPermitOriginal) control(ctx context.Context, action string, commit bool) (k.DeliveredProviderPermit, error) {
	p, err := o.issuer.Prepare(ctx, o.scope)
	if err != nil {
		return k.DeliveredProviderPermit{}, err
	}
	tx, err := o.fixture.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return k.DeliveredProviderPermit{}, err
	}
	defer tx.Rollback()
	guard, err := o.fixture.cfg.Authority.Bind(ctx, tx, o.scope.Input.Authority)
	if err != nil {
		return k.DeliveredProviderPermit{}, err
	}
	req := worker.ControlRequest{Invocation: o.scope.Invocation, InvocationSHA256: o.scope.WorkerIdentity.InvocationSHA256, Action: action, Point: o.nonce}
	pod := BoundPod{Namespace: o.scope.WorkerIdentity.Namespace, Name: o.scope.WorkerPodName, UID: o.scope.WorkerIdentity.PodUID, ServiceAccountUID: o.scope.WorkerIdentity.ServiceAccountUID}
	until := o.until
	if p.ValidUntil().Before(until) {
		until = p.ValidUntil()
	}
	if guard.ValidUntil().Before(until) {
		until = guard.ValidUntil()
	}
	lease, err := o.owner.keyUseTx(ctx, tx, o.scope.Input.Authority, o.scope.Job, pod, req, until)
	if err != nil {
		return k.DeliveredProviderPermit{}, err
	}
	if err = p.Stage(ctx, tx, *lease, action); err != nil {
		return k.DeliveredProviderPermit{}, err
	}
	if err = guard.Recheck(ctx, tx); err != nil {
		return k.DeliveredProviderPermit{}, err
	}
	if commit {
		err = tx.Commit()
	} else {
		err = tx.Rollback()
	}
	if err != nil {
		return k.DeliveredProviderPermit{}, err
	}
	delivery, err := p.ReadCommitted(ctx)
	if !commit {
		if err == nil {
			return k.DeliveredProviderPermit{}, errors.New("rollback wrongly published delivery")
		}
		return k.DeliveredProviderPermit{}, aExpectedPermitRollback
	}
	if err != nil {
		return k.DeliveredProviderPermit{}, err
	}
	o.lease = *lease
	o.until = lease.Until
	return delivery, nil
}
