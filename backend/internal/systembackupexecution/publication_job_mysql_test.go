package systembackupexecution

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	kt "k8s.io/client-go/testing"
)

type aPublicationJobBoundaryConnector struct {
	driver.Connector
	boundary *aStageCommitBoundary
}
type aPublicationJobBoundaryConn struct{ *aStageBoundaryConn }

func (c aPublicationJobBoundaryConnector) Connect(ctx context.Context) (driver.Conn, error) {
	connection, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &aPublicationJobBoundaryConn{&aStageBoundaryConn{Conn: connection, boundary: c.boundary}}, nil
}
func (c *aPublicationJobBoundaryConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	result, err := c.aStageBoundaryConn.ExecContext(ctx, query, args)
	if err == nil || errors.Is(err, driver.ErrSkip) {
		if strings.HasPrefix(query, "UPDATE system_backup_v2_job_send_intents SET send_state='sending'") {
			c.kind = "publication-sending"
		}
		if strings.HasPrefix(query, "UPDATE system_backup_v2_job_send_intents SET send_state='bound'") {
			c.kind = "publication-bound"
		}
	}
	return result, err
}

// Keep the authenticated original records byte-for-byte. The narrow fixture's
// parent tables are replaced with production DDL, never placeholder plan data.
func aUseActualPublicationJobDDL(t *testing.T, x *aPublisherVerifierFixture) {
	t.Helper()
	h := x.history
	conn, err := h.admin.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := conn.ExecContext(context.Background(), q, args...); e != nil {
			t.Fatal("original publication Job DDL", e)
		}
	}
	exec("SET FOREIGN_KEY_CHECKS=0")
	exec("CREATE TEMPORARY TABLE a_original_attempts AS SELECT * FROM system_backup_v2_attempts")
	exec("DROP TABLE system_backup_v2_attempts")
	exec(aPublicationActualTable(t, "098_backup_v2_add_system_backup_task_execution_core.sql", "system_backup_v2_attempts"))
	exec(`INSERT INTO system_backup_v2_attempts(target_type,target_public_id,attempt_no,phase,status,row_version,created_at,started_at,finished_at) SELECT target_type,target_public_id,attempt_no,phase,status,row_version,TIMESTAMPADD(SECOND,-2,UTC_TIMESTAMP(6)),TIMESTAMPADD(SECOND,-1,UTC_TIMESTAMP(6)),UTC_TIMESTAMP(6) FROM a_original_attempts`)
	exec("DROP TEMPORARY TABLE a_original_attempts")
	exec("CREATE TEMPORARY TABLE a_original_records AS SELECT * FROM system_backup_v2_execution_records")
	exec("DROP TABLE system_backup_v2_execution_records")
	exec(aPublicationActualTable(t, "122_backup_v2_execution_records.sql", "system_backup_v2_execution_records"))
	exec(`INSERT INTO system_backup_v2_execution_records(origin_installation_id,task_public_id,attempt_no,phase,record_kind,payload_sha256,key_ref,sealed_payload) SELECT origin_installation_id,task_public_id,attempt_no,phase,record_kind,payload_sha256,key_ref,sealed_payload FROM a_original_records`)
	var changed int
	if conn.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM a_original_records old LEFT JOIN system_backup_v2_execution_records current ON current.origin_installation_id=old.origin_installation_id AND current.task_public_id=old.task_public_id AND current.attempt_no=old.attempt_no AND current.phase=old.phase AND current.record_kind=old.record_kind WHERE current.task_public_id IS NULL OR current.payload_sha256<>old.payload_sha256 OR current.key_ref<>old.key_ref OR OCTET_LENGTH(current.sealed_payload)<>OCTET_LENGTH(old.sealed_payload) OR SHA2(current.sealed_payload,256)<>SHA2(old.sealed_payload,256)`).Scan(&changed) != nil || changed != 0 {
		t.Fatal("authenticated original plan/result bytes changed", changed)
	}
	exec("DROP TEMPORARY TABLE a_original_records")
	// The original fixture's input has the same immutable rows but predates
	// the production parent's ASCII key types and two-column unique identity.
	exec("ALTER TABLE system_backup_v2_execution_inputs MODIFY origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL, MODIFY task_public_id CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL, ADD UNIQUE KEY a_original_input_identity(origin_installation_id,task_public_id)")
	exec(aPublicationActualTable(t, "120_backup_v2_execution_plans.sql", "system_backup_v2_execution_plans"))
	exec("SET FOREIGN_KEY_CHECKS=1")
	for _, query := range []string{
		`SELECT COUNT(*) FROM system_backup_v2_execution_records r LEFT JOIN system_backup_v2_backups b ON b.origin_installation_id=r.origin_installation_id AND b.public_id=r.task_public_id WHERE b.public_id IS NULL`,
		`SELECT COUNT(*) FROM system_backup_v2_staging_resources r LEFT JOIN system_backup_v2_backups b ON b.origin_installation_id=r.origin_installation_id AND b.public_id=r.backup_public_id LEFT JOIN system_backup_v2_attempts a ON a.target_type='backup' AND a.target_public_id=r.backup_public_id AND a.attempt_no=r.attempt_no AND a.phase=r.phase WHERE b.public_id IS NULL OR a.target_public_id IS NULL`,
	} {
		var orphans int
		if conn.QueryRowContext(context.Background(), query).Scan(&orphans) != nil || orphans != 0 {
			t.Fatal("original parent chain orphan after fixture DDL", orphans)
		}
	}
	exec(aPublicationActualTable(t, "121_backup_v2_job_send_intents.sql", "system_backup_v2_job_send_intents"))
	raw, err := os.ReadFile(filepath.Join("..", "db", "migrations", "133_backup_v2_publish_original_plan_parent.sql"))
	if err != nil {
		t.Fatal(err)
	}
	exec(string(raw))
	g := h.owner.Identity.DeploymentBinding()
	grants, err := c.PublicationGrantSQL(g.Database, strings.Split(g.DatabaseAccount, "@")[0], "127.0.0.1", false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, grant := range grants {
		if strings.Contains(grant, "`.`system_backup_v2_job_send_intents`") {
			exec(grant)
		}
	}
}

// This is a suspended native Job transport test with one original workspace
// capture, NOT full six-domain preparation, result delivery or acceptance.
func TestPublicationJobOriginal121SingleSendSuspendedMySQL(t *testing.T) {
	if os.Getenv("A_SIGNING_MYSQL_CREDENTIALS_FILE") == "" {
		t.Skip("requires owned local MySQL")
	}
	for _, mode := range []string{"current", "sending-commit-ack-lost", "bound-commit-ack-lost", "create-ack-lost", "sending-absent", "release-during-create", "source-hash-drift", "upload-sa-drift", "upload-sa-forbidden", "bound-row-drift-during-get"} {
		t.Run(mode, func(t *testing.T) {
			store, provider := newANativePublicationStore(t, time.Minute)
			defer store.Close()
			store.config.RemoteStagingRoot = "remote-staging/installation_test/"
			worker := &PublicationWorkerReference{Protocol: publicationPresignedUploadVersion, ServiceAccountName: "publish-upload", ServiceAccountUID: "publish-upload-sa"}
			boundary := &aStageCommitBoundary{}
			x := newAPublisherVerifierFixtureOptions(t, aPublisherVerifierFixtureOptions{FullService: true, PublicationTarget: &store.config, AttemptNo: 1, PublicationWorker: worker, WrapControlConnector: func(inner driver.Connector) driver.Connector {
				return aPublicationJobBoundaryConnector{inner, boundary}
			}})
			aStartPublisherVerifierSamePod(t, x)
			aUseActualPublicationDDL(t, x, store.config)
			aUseActualPublicationJobDDL(t, x)
			h, ctx := x.history, context.Background()
			h.service.Runtime = &PublicCapture{Owner: h.owner}
			h.service.staging = h.owner.Staging
			client := h.owner.Client.(*fake.Clientset)
			cfg := h.service.Config
			for _, object := range []runtime.Object{
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: cfg.Namespace, Name: worker.ServiceAccountName, UID: types.UID(worker.ServiceAccountUID)}},
				&corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Namespace: cfg.Namespace, Name: cfg.StagingClaim, UID: "staging-uid"}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "staging-pv"}},
				&corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "staging-pv", UID: "staging-pv-uid"}, Spec: corev1.PersistentVolumeSpec{ClaimRef: &corev1.ObjectReference{Namespace: cfg.Namespace, Name: cfg.StagingClaim, UID: "staging-uid"}}},
			} {
				if err := client.Tracker().Add(object); err != nil {
					t.Fatal(err)
				}
			}
			verifier, err := h.service.PublisherVerifierForPart(ctx, h.token, 1, "workspace")
			if err != nil {
				t.Fatal(err)
			}
			record, err := verifier.CapturedRecord(ctx)
			verifier.Close()
			if err != nil {
				t.Fatal(err)
			}
			var original FormalCandidateRecord
			if json.Unmarshal(record.CandidateJSON, &original) != nil {
				t.Fatal("original candidate")
			}
			invSHA, _ := record.Invocation.Hash()
			cipher, envelope := publicationPartPaths("workspace", record.Invocation.Request.Binding.PartIndex, invSHA)
			index := []byte("suspended Job index DATA")
			request := PublicationUploadRequest{Version: publicationPresignedUploadVersion, Installation: h.original.InstallationID, Backup: h.original.TaskPublicID, Attempt: 1, Endpoint: store.config.Endpoint, Region: store.config.Region, Bucket: store.config.Bucket, ArtifactRoot: store.config.Root, RemoteStagingRoot: store.config.RemoteStagingRoot, CAHash: store.config.CASHA256, Deadline: h.original.DeadlineAt.Add(-time.Second), IndexBytes: index, Objects: []PublicationUploadInput{{Path: cipher, SHA256: original.Candidate.Ciphertext.SHA256, Bytes: original.Candidate.Ciphertext.Size}, {Path: envelope, SHA256: original.Candidate.Envelope.SHA256, Bytes: original.Candidate.Envelope.Size}, {Path: "artifact-index.json", SHA256: hash(index), Bytes: int64(len(index))}}}
			request.ManifestInput = []byte(`{"schema_version":"system-backup.v1","origin_installation_id":"` + request.Installation + `","backup_public_id":"` + request.Backup + `","attempt_no":1,"artifact_index":{"path":"artifact-index.json","checksum":"` + hash(index) + `"}}`)
			aRefreshPublicationPayloadCapacity(t, x)
			candidate, err := h.service.beginPublicationCandidate(ctx, h.token, 1, store.config, request)
			if err != nil {
				t.Fatal(err)
			}
			request.CandidateOwnerHMAC = candidate.MAC
			delegated, err := h.service.issuePublicationPutGrants(ctx, h.token, 1, store.config, request)
			if err != nil {
				t.Fatal(err)
			}
			request.CredentialHash = hash(delegated)
			clear(delegated)
			if mode == "source-hash-drift" {
				request.Objects[0].SHA256 = hash([]byte("changed original C"))
			}
			if mode == "upload-sa-drift" {
				sa, _ := client.CoreV1().ServiceAccounts(cfg.Namespace).Get(ctx, worker.ServiceAccountName, metav1.GetOptions{})
				sa.UID = "replaced-sa"
				client.CoreV1().ServiceAccounts(cfg.Namespace).Update(ctx, sa, metav1.UpdateOptions{})
			}
			if mode == "upload-sa-forbidden" {
				client.PrependReactor("get", "serviceaccounts", func(action kt.Action) (bool, runtime.Object, error) {
					if action.(kt.GetAction).GetName() == worker.ServiceAccountName {
						return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "serviceaccounts"}, worker.ServiceAccountName, errors.New("actual named local API denied"))
					}
					return false, nil, nil
				})
			}
			if mode == "sending-commit-ack-lost" || mode == "bound-commit-ack-lost" {
				kind, expected := "publication-sending", "sending"
				if mode == "bound-commit-ack-lost" {
					kind, expected = "publication-bound", "bound"
				}
				boundary.arm(kind, func() error {
					var state string
					if h.admin.QueryRow(`SELECT send_state FROM system_backup_v2_job_send_intents WHERE task_public_id=? AND phase='publish'`, request.Backup).Scan(&state) != nil || state != expected {
						t.Fatal("SQL ACK lost before actual commit", state)
					}
					return errAPublicationACKLost
				})
			}
			creates := 0
			client.PrependReactor("create", "jobs", func(action kt.Action) (bool, runtime.Object, error) {
				creates++
				var state string
				if err := h.admin.QueryRow(`SELECT send_state FROM system_backup_v2_job_send_intents WHERE task_public_id=? AND phase='publish'`, request.Backup).Scan(&state); err != nil || state != "sending" {
					t.Fatal("original 121 not committed before native Create", state, err)
				}
				job := action.(kt.CreateAction).GetObject().(*batchv1.Job).DeepCopy()
				if job.Spec.Suspend == nil || !*job.Spec.Suspend {
					t.Fatal("publication Job ran before resources/107 binding")
				}
				job.UID, job.Generation = "12345678-1234-4123-8123-123456789abc", 1
				if mode != "sending-absent" {
					if err := client.Tracker().Create(batchv1.SchemeGroupVersion.WithResource("jobs"), job, job.Namespace); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "release-during-create" {
					fault, cancel := context.WithTimeout(ctx, 2*time.Second)
					defer cancel()
					if _, err := (c.ClaimCoordinator{Executor: h.admin, InstallationID: request.Installation}).Release(fault, h.token, time.Second); err != nil {
						t.Fatal("SQL lock held across native Create", err)
					}
					var owner sql.NullString
					var version uint64
					if h.admin.QueryRowContext(fault, `SELECT controller_owner,row_version FROM system_backup_v2_backups WHERE public_id=?`, request.Backup).Scan(&owner, &version) != nil || owner.Valid || version <= h.token.RowVersion {
						t.Fatal("actual Release effect absent")
					}
				}
				if mode == "create-ack-lost" || mode == "sending-absent" {
					return true, nil, errors.New("actual local native ACK lost")
				}
				return true, job, nil
			})
			job, err := h.service.ensureSuspendedPublicationJob(ctx, h.token, 1, store.config, request)
			if mode == "source-hash-drift" || mode == "upload-sa-drift" || mode == "upload-sa-forbidden" {
				if err == nil || creates != 0 {
					t.Fatal("changed input/SA reached native Create", err)
				}
				if provider.puts != 0 || provider.gets != 0 || provider.heads != 0 || x.logins.Load() != 0 || x.decrypts.Load() != 0 {
					t.Fatal("denied publication Job reached source/KMS/provider")
				}
				return
			}
			if mode == "release-during-create" {
				if err == nil || job != nil || creates != 1 {
					t.Fatal("withdrawn authority bound original Job", err)
				}
				return
			}
			if mode == "sending-commit-ack-lost" || mode == "bound-commit-ack-lost" {
				if !errors.Is(err, c.ErrExecutionCommitUnknown) {
					t.Fatal("actual SQL ACK loss did not remain unknown", err)
				}
				boundary.arm("", nil)
			} else if mode != "current" && mode != "bound-row-drift-during-get" && !errors.Is(err, ErrJobUncertain) {
				t.Fatal("lost native ACK accepted", err)
			}
			if (mode == "current" || mode == "bound-row-drift-during-get") && (err != nil || job == nil) {
				t.Fatal("initial native Create", err)
			}
			if mode == "bound-row-drift-during-get" {
				originalName := job.Name
				applied := false
				client.PrependReactor("get", "jobs", func(action kt.Action) (bool, runtime.Object, error) {
					if action.(kt.GetAction).GetName() == originalName {
						changed, err := h.admin.Exec(`UPDATE system_backup_v2_job_send_intents SET job_uid='22222222-2222-4222-8222-222222222222' WHERE task_public_id=? AND phase='publish' AND send_state='bound'`, request.Backup)
						if err != nil {
							t.Fatal(err)
						}
						if rows, err := changed.RowsAffected(); err != nil || rows != 1 {
							t.Fatal("actual bound row drift absent", rows, err)
						}
						applied = true
					}
					return false, nil, nil
				})
				if result, err := h.service.ensureSuspendedPublicationJob(ctx, h.token, 1, store.config, request); err == nil || result != nil || !applied || creates != 1 {
					t.Fatal("stale pre-GET bound row accepted", creates, applied, err)
				}
				return
			}
			job, err = h.service.ensureSuspendedPublicationJob(ctx, h.token, 1, store.config, request)
			if mode == "sending-absent" || mode == "sending-commit-ack-lost" {
				expected := 1
				if mode == "sending-commit-ack-lost" {
					expected = 0
				}
				if !errors.Is(err, ErrJobUncertain) || creates != expected {
					t.Fatal("absent sent Job resent", creates, err)
				}
				return
			}
			if err != nil || job == nil || creates != 1 {
				t.Fatal("query-only native bind/retry", creates, err)
			}
			var count int
			var state, uid string
			if h.admin.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_execution_plans`).Scan(&count) != nil || count != 0 {
				t.Fatal("placeholder/second frozen plan was introduced")
			}
			if h.admin.QueryRow(`SELECT send_state,job_uid FROM system_backup_v2_job_send_intents WHERE task_public_id=? AND phase='publish'`, request.Backup).Scan(&state, &uid) != nil || state != "bound" || uid != string(job.UID) {
				t.Fatal("actual original 121 UID bind", state, uid)
			}
			t.Log("original attempt", strconv.FormatUint(h.original.AttemptNo, 10), "single native suspended Job, original 122 plan parent")
		})
	}
}
