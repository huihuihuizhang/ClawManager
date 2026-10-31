package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	k "clawreef/internal/systembackupkms"
	s "clawreef/internal/systembackupsecurity"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

type publisherHistoryFixture struct {
	owner     *PublicJobOwner
	service   *DeploymentService
	admin, db *sql.DB
	original  d.Authority
	job       d.JobBinding
	token     c.ClaimToken
	cfg       s.PublisherCaptureAuthorityConfig
	scope     s.PublisherCaptureScope
	access    *s.SQLPublisherCaptureAuthority
	candidate worker.FormalCaptureResult
}

// Real original record-key custody, original encrypted plan/report/result and
// production authorization wrapper; actual AcquireWithReceipt and A's concrete
// independent grant. Stop/resume facts and Kubernetes remain named local
// fixtures here, not a certification of Linux/CSI/physical business recovery.
func newPublisherHistoryFixture(t *testing.T) *publisherHistoryFixture {
	t.Helper()
	if os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS") == "" {
		t.Skip("requires disposable local MySQL")
	}
	ctx := context.Background()
	options := &consumerFixtureOptions{ConfigureGrant: func(g *c.ExecutionGrant) { g.DeploymentConfigSHA256 = hash([]byte(`{"fixture":"pinned-deployment"}`)) }}
	owner, service, admin, db, a, job, candidate, _, refresh := newConsumerMySQLFixtureOptions(t, options)
	service.Config.ControllerOwner = a.ClaimOwner
	refresh()
	ref, err := owner.Evidence(ctx, a, job)
	if err != nil || ref == nil {
		t.Fatal("original actual Evidence before release", err)
	}
	raw, err := owner.ReadResult(ctx, a, job, *ref)
	if err != nil {
		t.Fatal(err)
	}
	var result d.ModuleResult
	if json.Unmarshal(raw, &result) != nil {
		t.Fatal("original result")
	}
	input, plan, _, err := owner.input(ctx, a, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.Gate.Records.RecordCapture(ctx, c.ExecutionWork{Step: c.ExecutionCapture, Input: input, Plan: plan}, c.ExecutionOutcome{Results: []d.ModuleResult{result}}); err != nil {
		t.Fatal("actual original RecordCapture", err)
	}
	originalAuthority, _ := json.Marshal(a)
	nonce := strings.Repeat("e", 32)
	record, err := owner.ReadFormalCandidate(ctx, a, job, false)
	if err != nil {
		t.Fatal(err)
	}
	var invocation worker.Invocation
	if json.Unmarshal(findHistoryInvocation(t, owner, a, job), &invocation) != nil {
		t.Fatal("original invocation")
	}
	use := worker.KeyUseLease{Identity: k.JobIdentity{Namespace: job.Namespace, PodUID: record.Pod.UID, ServiceAccountUID: record.Pod.ServiceAccountUID, JobUID: job.UID, InvocationSHA256: candidate.InvocationSHA256, ExecutionGrantSHA256: owner.Identity.GrantSHA256()}, Access: *invocation.ProviderKey, AuthoritySHA256: hash(originalAuthority), Nonce: nonce, Until: a.DeadlineAt, State: "finished"}
	keyUseRaw, _ := json.Marshal(use)
	for _, q := range []string{
		"ALTER TABLE system_backup_v2_backups MODIFY controller_owner VARCHAR(128) NULL,MODIFY controller_lease_expires_at DATETIME(6) NULL,ADD COLUMN heartbeat_at DATETIME(6) NULL,ADD COLUMN next_reconcile_at DATETIME(6) NULL",
		"CREATE TABLE system_backup_v2_events(id BIGINT AUTO_INCREMENT PRIMARY KEY,public_id VARCHAR(128),origin_installation_id VARCHAR(128),target_type VARCHAR(32),target_public_id VARCHAR(128),event_type VARCHAR(128),level VARCHAR(32),task_status VARCHAR(32),message VARCHAR(255),details_present BOOLEAN NOT NULL DEFAULT FALSE,request_id VARCHAR(128),details_json JSON,created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6)) ENGINE=InnoDB",
	} {
		if _, err := admin.Exec(q); err != nil {
			t.Fatal("owned history fixture metadata", err)
		}
	}
	grant := owner.Identity.DeploymentBinding()
	account := strings.Split(grant.DatabaseAccount, "@")[0]
	if _, err := admin.Exec("GRANT SELECT,INSERT ON `" + grant.Database + "`.`system_backup_v2_events` TO '" + account + "'@'127.0.0.1'"); err != nil {
		t.Fatal("owned receipt role", err)
	}
	// These are explicit local stop/resume observations. No old capture claim
	// is minted from them; the public read authority separately verifies them.
	if _, err := admin.Exec("UPDATE system_backup_v2_runtime_resources SET key_use_json=?,revoked=TRUE,stopped_at=UTC_TIMESTAMP(6) WHERE observed_uid=?", keyUseRaw, job.UID); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec("UPDATE system_backup_v2_runtime_captures SET collectors_stopped_at=UTC_TIMESTAMP(6),source_resumed_at=UTC_TIMESTAMP(6) WHERE task_public_id=?", a.TaskPublicID); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec("UPDATE system_backup_v2_attempts SET status='sealed' WHERE target_public_id=?", a.TaskPublicID); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec("UPDATE system_backup_v2_backups SET status='validating',controller_owner=NULL,controller_lease_expires_at=NULL,row_version=row_version+1 WHERE public_id=?", a.TaskPublicID); err != nil {
		t.Fatal(err)
	}
	var version uint64
	if admin.QueryRow("SELECT row_version FROM system_backup_v2_backups WHERE public_id=?", a.TaskPublicID).Scan(&version) != nil {
		t.Fatal("released original version")
	}
	service.PublisherOwner = "public:history-publisher-pod"
	policy := c.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second}
	token, err := (c.SQLTaskClaimStore{DB: db, InstallationID: a.InstallationID}).AcquireWithReceipt(ctx, c.Target{Kind: c.TargetBackup, PublicID: a.TaskPublicID}, service.PublisherOwner, version, policy)
	if err != nil {
		t.Fatal("actual new publisher AcquireWithReceipt", err)
	}
	client := owner.Client
	for _, object := range []kruntime.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "publisher-control", UID: types.UID("publisher-namespace")}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "publisher-control", Name: "publisher-reader", UID: types.UID("publisher-sa")}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "publisher-control", Name: "publisher", UID: types.UID("history-publisher-pod")}, Spec: corev1.PodSpec{ServiceAccountName: "publisher-reader"}, Status: corev1.PodStatus{Phase: corev1.PodRunning}},
	} {
		switch v := object.(type) {
		case *corev1.Namespace:
			_, err = client.CoreV1().Namespaces().Create(ctx, v, metav1.CreateOptions{})
		case *corev1.ServiceAccount:
			_, err = client.CoreV1().ServiceAccounts(v.Namespace).Create(ctx, v, metav1.CreateOptions{})
		case *corev1.Pod:
			_, err = client.CoreV1().Pods(v.Namespace).Create(ctx, v, metav1.CreateOptions{})
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	fixture := &publisherHistoryFixture{owner: owner, service: service, admin: admin, db: db, original: a, job: job, token: token, candidate: candidate}
	fixture.cfg = s.PublisherCaptureAuthorityConfig{DB: db, Kubernetes: client, Deployment: s.PublisherCaptureDeployment{InstallationID: grant.InstallationID, Database: grant.Database, DatabaseAccount: grant.DatabaseAccount, ServerUUID: grant.ServerUUID, ControllerOwner: grant.ControllerOwner, ConfigVersion: grant.ConfigVersion, ConfigSHA256: grant.ConfigSHA256, ProfileSHA256: grant.ProfileSHA256, DeploymentConfigSHA256: grant.DeploymentConfigSHA256, CaptureGrantSHA256: owner.Identity.GrantSHA256(), NotBefore: grant.NotBefore, Until: grant.ExpiresAt}, Workload: s.PublisherCaptureWorkload{Namespace: "publisher-control", NamespaceUID: "publisher-namespace", PodName: "publisher", PodUID: "history-publisher-pod", ServiceAccountName: "publisher-reader", ServiceAccountUID: "publisher-sa", PublisherOwner: service.PublisherOwner}}
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	defer clear(private)
	issued := s.PublisherCaptureGrant{Version: s.PublisherCaptureGrantVersion, Deployment: fixture.cfg.Deployment, Workload: fixture.cfg.Workload, NotBefore: time.Now().Add(-time.Minute), Until: time.Now().Add(time.Minute)}
	payload, _ := json.Marshal(issued)
	signed, _ := json.Marshal(s.SignedPublisherCaptureGrant{Record: payload, Signature: ed25519.Sign(private, append([]byte(s.PublisherCaptureGrantDomain), payload...))})
	file := filepath.Join(t.TempDir(), "publisher-history-grant.json")
	if os.WriteFile(file, signed, 0600) != nil {
		t.Fatal("independent history grant")
	}
	fixture.cfg.GrantMount = s.PublisherCaptureGrantMount{File: file, SHA256: hash(signed), Issuer: pub}
	fixture.cfg.Workload.GrantSHA256 = hash(signed)
	fixture.scope = s.PublisherCaptureScope{BackupPublicID: a.TaskPublicID, Claim: s.SQLSigningClaim{ControllerOwner: token.Owner, RowVersion: token.RowVersion}, CaptureAttemptNo: a.AttemptNo, Part: "workspace"}
	// Kube calls must happen with NO original SQL read transaction held.
	owner.Client.(*kubefake.Clientset).PrependReactor("*", "*", func(ktesting.Action) (bool, kruntime.Object, error) {
		if db.Stats().InUse != 0 {
			t.Error("Kubernetes I/O while original metadata SQL transaction held")
		}
		return false, nil, nil
	})
	fixture.access, err = s.NewSQLPublisherCaptureAuthority(ctx, fixture.cfg, fixture.scope)
	if err != nil {
		t.Fatal("concrete original publisher authority", err)
	}
	return fixture
}

func findHistoryInvocation(t *testing.T, owner *PublicJobOwner, a d.Authority, j d.JobBinding) []byte {
	t.Helper()
	_, _, desc, err := owner.input(context.Background(), a, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range desc.Parts {
		if part.Intent.JobUnitKey == j.JobUnitKey {
			return part.InvocationJSON
		}
	}
	t.Fatal("missing original invocation")
	return nil
}

func TestPublisherCaptureRecordsUsesNewConcreteClaimAndOriginalCiphertextMySQL(t *testing.T) {
	for _, mode := range []string{"valid", "publishing", "finalization_unknown", "grant-replaced", "stale-claim", "candidate-cipher", "foreign-key-ref", "finished-use-missing", "wrong-wrapper", "missing-part", "last-get-renewal", "last-get-grant-replaced", "last-get-original-grant-replaced", "last-get-candidate-changed"} {
		t.Run(mode, func(t *testing.T) {
			f := newPublisherHistoryFixture(t)
			ctx := context.Background()
			switch mode {
			case "publishing", "finalization_unknown":
				if _, err := f.admin.Exec("UPDATE system_backup_v2_backups SET status=? WHERE public_id=?", mode, f.original.TaskPublicID); err != nil {
					t.Fatal(err)
				}
				var err error
				f.access, err = s.NewSQLPublisherCaptureAuthority(ctx, f.cfg, f.scope)
				if err != nil {
					t.Fatal(err)
				}
			case "grant-replaced":
				os.WriteFile(f.cfg.GrantMount.File, []byte("replaced"), 0600)
			case "stale-claim":
				_, err := c.RenewClaimInInstallation(ctx, f.db, f.original.InstallationID, f.token, c.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second})
				if err != nil {
					t.Fatal(err)
				}
			case "candidate-cipher":
				if _, err := f.admin.Exec("UPDATE system_backup_v2_runtime_resources SET candidate_cipher=CONCAT(candidate_cipher,'x') WHERE observed_uid=?", f.job.UID); err != nil {
					t.Fatal(err)
				}
			case "foreign-key-ref":
				if _, err := f.admin.Exec("UPDATE system_backup_v2_runtime_resources SET candidate_key_ref='foreign-key' WHERE observed_uid=?", f.job.UID); err != nil {
					t.Fatal(err)
				}
			case "finished-use-missing":
				if _, err := f.admin.Exec("UPDATE system_backup_v2_runtime_resources SET key_use_json=NULL WHERE observed_uid=?", f.job.UID); err != nil {
					t.Fatal(err)
				}
			case "wrong-wrapper":
				f.owner.Gate.Records.Authority.Authorization = f.owner.Identity
			case "missing-part":
				f.scope.Part = "foreign-part"
				var err error
				f.access, err = s.NewSQLPublisherCaptureAuthority(ctx, f.cfg, f.scope)
				if err != nil {
					t.Fatal(err)
				}
			}
			lastGETs, hookFired := 0, false
			if strings.HasPrefix(mode, "last-get-") {
				f.owner.Client.(*kubefake.Clientset).PrependReactor("get", "serviceaccounts", func(action ktesting.Action) (bool, kruntime.Object, error) {
					if action.GetNamespace() != f.cfg.Workload.Namespace {
						return false, nil, nil
					}
					lastGETs++
					if lastGETs != 6 {
						return false, nil, nil
					}
					hookFired = true
					var err error
					switch mode {
					case "last-get-renewal":
						_, err = c.RenewClaimInInstallation(ctx, f.db, f.original.InstallationID, f.token, c.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second})
					case "last-get-grant-replaced":
						err = os.WriteFile(f.cfg.GrantMount.File, []byte("replaced during final GET"), 0600)
					case "last-get-original-grant-replaced":
						err = os.WriteFile(filepath.Join(filepath.Dir(f.service.ConfigPath), "grant.json"), []byte("replaced during final GET"), 0600)
					case "last-get-candidate-changed":
						_, err = f.admin.Exec("UPDATE system_backup_v2_runtime_resources SET candidate_cipher=CONCAT(candidate_cipher,'x') WHERE observed_uid=?", f.job.UID)
					}
					if err != nil {
						t.Error("last workload GET mutation", err)
					}
					return false, nil, nil
				})
			}
			record, err := f.owner.Gate.Records.LoadPublisherCapture(ctx, f.access)
			if strings.HasPrefix(mode, "last-get-") && !hookFired {
				t.Fatalf("final workload GET hook did not run (observed %d)", lastGETs)
			}
			if mode != "valid" && mode != "publishing" && mode != "finalization_unknown" {
				if err == nil || record.Input.TaskPublicID != "" || len(record.CandidateJSON) != 0 {
					t.Fatal("invalid historical scope yielded original part", mode, err)
				}
				return
			}
			if err != nil || record.Input.TaskPublicID != f.original.TaskPublicID || record.Input.CaptureAttemptNo != 3 || record.Job != f.job || record.Invocation.Request.Binding.Attempt != "3" || record.KeyUse.State != "finished" || record.PartResult.Part != "workspace" || !record.ValidUntil.Equal(f.access.ValidUntil()) {
				t.Fatal("new publisher did not authenticate original history", err)
			}
			var original FormalCandidateRecord
			if json.Unmarshal(record.CandidateJSON, &original) != nil || original.Authority.ClaimOwner != f.original.ClaimOwner || original.Authority.ClaimRowVersion != f.original.ClaimRowVersion || original.Authority.ClaimOwner == f.token.Owner || !bytes.Equal(record.CandidateJSON, mustHistoryCandidateJSON(t, f)) {
				t.Fatal("new publisher synthesized/replaced old capture authority")
			}
			if _, err := f.owner.ReadFormalCandidate(ctx, f.original, f.job, false); err == nil {
				t.Fatal("old capture gate was resurrected")
			}
			if _, err := f.db.Exec("DELETE FROM system_backup_v2_evidence"); err == nil {
				t.Fatal("history added forbidden evidence DELETE")
			}
		})
	}
}

func mustHistoryCandidateJSON(t *testing.T, f *publisherHistoryFixture) []byte {
	t.Helper()
	record := FormalCandidateRecord{Version: "public-formal-candidate-record.v1", Authority: f.original, Job: f.job, Pod: BoundPod{Namespace: f.job.Namespace, Name: "capture-pod", UID: "capture-pod-uid", ServiceAccountUID: "capture-sa"}, InvocationSHA256: f.candidate.InvocationSHA256, KeyUseNonce: strings.Repeat("e", 32), ExecutionGrantSHA256: f.owner.Identity.GrantSHA256(), Candidate: f.candidate}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
