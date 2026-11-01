package systembackupexecution

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
	"github.com/google/uuid"
	batchv1 "k8s.io/api/batch/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	kt "k8s.io/client-go/testing"
)

type aPublicationReceiveConnector struct {
	driver.Connector
	boundary *aStageCommitBoundary
}
type aPublicationReceiveConn struct{ *aStageBoundaryConn }

func (c aPublicationReceiveConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &aPublicationReceiveConn{&aStageBoundaryConn{Conn: conn, boundary: c.boundary}}, nil
}
func (c *aPublicationReceiveConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	result, err := c.aStageBoundaryConn.ExecContext(ctx, query, args)
	if err == nil || errors.Is(err, driver.ErrSkip) {
		if strings.HasPrefix(query, "INSERT INTO system_backup_v2_job_observations(") {
			c.kind = "publication-activation"
		}
		if strings.HasPrefix(query, "UPDATE system_backup_v2_job_observations SET last_accepted_sequence=") {
			c.kind = "publication-result"
		}
	}
	return result, err
}

func aPublicationActualObservationDDL(t *testing.T, f *aPublicationMaterialFixture) {
	t.Helper()
	var rows int
	if f.x.history.admin.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_job_observations`).Scan(&rows) != nil || rows != 1 {
		t.Fatal("original capture observation unavailable")
	}
	if _, err := f.x.history.admin.Exec(`RENAME TABLE system_backup_v2_job_observations TO a_original_capture_observations`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.x.history.admin.Exec(aPublicationActualTable(t, "107_backup_v2_add_system_backup_job_observations.sql", "system_backup_v2_job_observations")); err != nil {
		t.Fatal("actual original 107 FK/CHECK", err)
	}
	// Preserve every existing capture field, including its actual UID, generation,
	// original timestamps and cursor. Only new production columns take defaults.
	columns := []string{"origin_installation_id", "target_type", "target_public_id", "attempt_no", "phase", "job_unit_key", "job_uid", "job_generation", "relay_identity_ref", "relay_identity_version", "relay_identity_bound_at", "relay_identity_expires_at", "last_accepted_sequence", "last_accepted_body_sha256", "last_observed_status", "last_observed_at", "progress_sequence", "progress_digest_sha256", "last_business_progress_at", "created_at", "row_version"}
	names := strings.Join(columns, ",")
	if _, err := f.x.history.admin.Exec("INSERT INTO system_backup_v2_job_observations(" + names + ",updated_at) SELECT " + names + ",created_at FROM a_original_capture_observations"); err != nil {
		t.Fatal("original capture observation did not satisfy unchanged production 107", err)
	}
	comparisons := make([]string, 0, len(columns))
	for _, column := range columns {
		comparisons = append(comparisons, "NOT(CAST(current."+column+" AS BINARY)<=>CAST(original."+column+" AS BINARY))")
	}
	var changed, count int
	if err := f.x.history.admin.QueryRow("SELECT COUNT(*) FROM a_original_capture_observations original LEFT JOIN system_backup_v2_job_observations current ON CAST(current.job_uid AS BINARY)=CAST(original.job_uid AS BINARY) WHERE current.job_uid IS NULL OR " + strings.Join(comparisons, " OR ")).Scan(&changed); err != nil {
		t.Fatal("original capture field comparison query", err)
	}
	if err := f.x.history.admin.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_job_observations`).Scan(&count); err != nil {
		t.Fatal("original capture field comparison count", err)
	}
	if changed != 0 || count != rows {
		t.Fatal("capture observation fields changed during fixture DDL", changed, count)
	}
}

func aPublicationNativeJobAPI(t *testing.T, f *aPublicationMaterialFixture, mode string) *int {
	t.Helper()
	h := f.x.history
	patches := new(int)
	f.client.PrependReactor("create", "jobs", func(action kt.Action) (bool, runtime.Object, error) {
		f.jobCreates++
		job := action.(kt.CreateAction).GetObject().(*batchv1.Job).DeepCopy()
		job.UID, job.Generation, job.ResourceVersion = types.UID(uuid.NewString()), 1, "1"
		if job.Spec.Suspend == nil || !*job.Spec.Suspend {
			t.Fatal("native Create was already active")
		}
		if err := f.client.Tracker().Create(batchv1.SchemeGroupVersion.WithResource("jobs"), job, job.Namespace); err != nil {
			t.Fatal(err)
		}
		return true, job, nil
	})
	f.client.PrependReactor("patch", "jobs", func(action kt.Action) (bool, runtime.Object, error) {
		*patches++
		patch := action.(kt.PatchAction)
		if patch.GetPatchType() != types.JSONPatchType {
			t.Fatal("unsuspend is not conditional JSON patch")
		}
		current, err := f.client.Tracker().Get(batchv1.SchemeGroupVersion.WithResource("jobs"), patch.GetNamespace(), patch.GetName())
		if err != nil {
			t.Fatal(err)
		}
		job := current.(*batchv1.Job).DeepCopy()
		var operations []struct {
			Op, Path string
			Value    json.RawMessage
		}
		if json.Unmarshal(patch.GetPatch(), &operations) != nil || len(operations) != 5 {
			t.Fatal("unsuspend patch is not closed")
		}
		for i, value := range []any{string(job.UID), job.ResourceVersion, job.Generation, true, false} {
			want, _ := json.Marshal(value)
			paths := []string{"/metadata/uid", "/metadata/resourceVersion", "/metadata/generation", "/spec/suspend", "/spec/suspend"}
			if string(operations[i].Value) != string(want) || operations[i].Path != paths[i] || (i < 4 && operations[i].Op != "test") || (i == 4 && operations[i].Op != "replace") {
				t.Fatal("unsuspend lost original UID/RV/generation test")
			}
		}
		// Independent original SQL connection proves 121/107/activation were
		// committed, and no controller SQL lock spans the native patch.
		var uid, state, ref string
		var generation int64
		if h.admin.QueryRow(`SELECT job_uid,send_state FROM system_backup_v2_job_send_intents WHERE task_public_id=? AND phase='publish'`, h.original.TaskPublicID).Scan(&uid, &state) != nil || state != "bound" || uid != string(job.UID) {
			t.Fatal("native start preceded original 121 binding")
		}
		if h.admin.QueryRow(`SELECT job_uid,job_generation,relay_identity_ref FROM system_backup_v2_job_observations WHERE target_public_id=? AND phase='publish'`, h.original.TaskPublicID).Scan(&uid, &generation, &ref) != nil || uid != string(job.UID) || generation != 2 || !strings.HasPrefix(ref, "k8s-secret://") {
			t.Fatal("native start preceded actual original 107 identity binding")
		}
		var attemptState string
		var started sql.NullTime
		if h.admin.QueryRow(`SELECT status,started_at FROM system_backup_v2_attempts WHERE target_public_id=? AND phase='publish'`, h.original.TaskPublicID).Scan(&attemptState, &started) != nil || attemptState != "running" || !started.Valid {
			t.Fatal("native start preceded original running publish attempt")
		}
		var intents int
		if h.admin.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_evidence WHERE public_id=?`, publicationMaterialID(h.original.InstallationID, h.original.TaskPublicID, 1)+"_activation").Scan(&intents) != nil || intents != 1 {
			t.Fatal("native start preceded original activation intent")
		}
		if mode == "release-during-patch" {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if _, err = (c.ClaimCoordinator{Executor: h.admin, InstallationID: h.original.InstallationID}).Release(ctx, h.token, time.Second); err != nil {
				t.Fatal("SQL lock held across native start", err)
			}
			var owner sql.NullString
			var rv uint64
			if h.admin.QueryRowContext(ctx, `SELECT controller_owner,row_version FROM system_backup_v2_backups WHERE public_id=?`, h.original.TaskPublicID).Scan(&owner, &rv) != nil || owner.Valid || rv <= h.token.RowVersion {
				t.Fatal("actual Release effect absent")
			}
		}
		if mode == "patch-absent" {
			return true, nil, errors.New("native patch failed before effect with unknown ACK")
		}
		if mode == "patch-forbidden" {
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "batch", Resource: "jobs"}, job.Name, errors.New("current native patch denied"))
		}
		no := false
		job.Spec.Suspend, job.Generation, job.ResourceVersion = &no, 2, "2"
		if mode == "wrong-generation" {
			job.Generation = 3
		}
		if mode == "replaced-uid" {
			job.UID = types.UID(uuid.NewString())
		}
		if err = f.client.Tracker().Update(batchv1.SchemeGroupVersion.WithResource("jobs"), job, job.Namespace); err != nil {
			t.Fatal(err)
		}
		if mode == "patch-ack-lost" {
			return true, nil, errors.New("native start succeeded with lost ACK")
		}
		return true, job, nil
	})
	return patches
}

// Partial workspace transport DATA only. Original 107/121/098/122 FKs and
// CHECKs stay enabled; this is not complete six-domain publication admission.
func TestPublicationOriginal107BeforeNativeStartAndUnknownReopenMySQL(t *testing.T) {
	if os.Getenv("A_SIGNING_MYSQL_CREDENTIALS_FILE") == "" {
		t.Skip("requires owned local MySQL")
	}
	for _, mode := range []string{"current", "activation-commit-ack-lost", "patch-ack-lost", "patch-absent", "patch-forbidden", "release-during-patch", "wrong-generation", "replaced-uid", "121-namespace-drift-during-get", "publish-attempt-failed"} {
		t.Run(mode, func(t *testing.T) {
			boundary := &aStageCommitBoundary{}
			f := newAPublicationMaterialFixtureControl(t, true, func(conn driver.Connector) driver.Connector { return aPublicationReceiveConnector{conn, boundary} })
			aPublicationActualObservationDDL(t, f)
			patches := aPublicationNativeJobAPI(t, f, mode)
			h, ctx := f.x.history, context.Background()
			if mode == "activation-commit-ack-lost" {
				boundary.arm("publication-activation", func() error {
					var count int
					if h.admin.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_job_observations WHERE target_public_id=? AND phase='publish'`, h.original.TaskPublicID).Scan(&count) != nil || count != 1 {
						t.Fatal("activation SQL ACK lost before actual commit")
					}
					return errAPublicationACKLost
				})
			}
			job, err := h.service.ensureStartedPublicationJob(ctx, h.token, 1, f.store.config, f.request)
			if mode == "current" || mode == "121-namespace-drift-during-get" || mode == "publish-attempt-failed" {
				if err != nil || job.Spec.Suspend == nil || *job.Spec.Suspend || job.Generation != 2 {
					t.Fatal("actual original native start", err)
				}
			} else if err == nil {
				t.Fatal("unknown/drift/released native start became known", mode)
			}
			wantPatches := 1
			if mode == "activation-commit-ack-lost" {
				wantPatches = 0
			}
			if *patches != wantPatches || f.jobCreates != 1 || f.secretCreates != 1 || f.secretUpdates != 1 {
				t.Fatal("start did not preserve original one-send boundaries")
			}
			var ownerRaw []byte
			if h.admin.QueryRow(`SELECT inline_payload FROM system_backup_v2_evidence WHERE public_id=?`, publicationMaterialID(h.original.InstallationID, h.original.TaskPublicID, 1)+"_job_owner").Scan(&ownerRaw) != nil {
				t.Fatal("original owner intent unavailable")
			}
			var owner publicationMaterialJobOwner
			if json.Unmarshal(ownerRaw, &owner) != nil || owner.Generation != 1 {
				t.Fatal("start rewrote original suspended owner generation")
			}
			if mode == "publish-attempt-failed" {
				aPublicationFailRunningAttempt(t, f)
			}
			if mode == "121-namespace-drift-during-get" {
				fired := false
				f.client.PrependReactor("get", "jobs", func(action kt.Action) (bool, runtime.Object, error) {
					if fired {
						return false, nil, nil
					}
					fired = true
					get := action.(kt.GetAction)
					original, err := f.client.Tracker().Get(batchv1.SchemeGroupVersion.WithResource("jobs"), get.GetNamespace(), get.GetName())
					if err != nil {
						t.Fatal(err)
					}
					result, err := h.admin.Exec(`UPDATE system_backup_v2_job_send_intents SET namespace_uid='independent-replaced-namespace' WHERE phase='publish'`)
					if err != nil {
						t.Fatal(err)
					}
					var observed string
					if count, err := result.RowsAffected(); err != nil || count != 1 || h.admin.QueryRow(`SELECT namespace_uid FROM system_backup_v2_job_send_intents WHERE phase='publish'`).Scan(&observed) != nil || observed != "independent-replaced-namespace" {
						t.Fatal("actual original 121 drift absent during native GET")
					}
					return true, original, nil
				})
			}
			// No signer is available during recovery. A second native patch or
			// credential/Job generation would violate these independent counters.
			h.owner.Issuer.Signer = nil
			got, err := h.service.ensureStartedPublicationJob(ctx, h.token, 1, f.store.config, PublicationUploadRequest{})
			positive := mode == "current" || mode == "patch-ack-lost"
			if (err == nil) != positive || (positive && (got.Generation != 2 || string(got.UID) != owner.JobUID)) {
				t.Fatal("query-only original activation recovery", mode, err)
			}
			if *patches != wantPatches || f.jobCreates != 1 || f.secretCreates != 1 || f.secretUpdates != 1 || f.provider.puts != 0 || f.provider.gets != 0 || f.provider.heads != 0 || f.x.logins.Load() != 0 || f.x.decrypts.Load() != 0 {
				t.Fatal("start/reopen resent or reached source/KMS/provider")
			}
		})
	}
}

func aPublicationFailRunningAttempt(t *testing.T, f *aPublicationMaterialFixture) {
	t.Helper()
	h := f.x.history
	var prior uint64
	if h.admin.QueryRow(`SELECT row_version FROM system_backup_v2_attempts WHERE target_public_id=? AND phase='publish' AND status='running'`, h.original.TaskPublicID).Scan(&prior) != nil {
		t.Fatal("original running publish attempt missing")
	}
	result, err := h.admin.Exec(`UPDATE system_backup_v2_attempts SET status='failed',failure_category='runner_failed',finished_at=UTC_TIMESTAMP(6),row_version=row_version+1 WHERE target_public_id=? AND phase='publish' AND status='running'`, h.original.TaskPublicID)
	if err != nil {
		t.Fatal(err)
	}
	var status string
	var version uint64
	if count, err := result.RowsAffected(); err != nil || count != 1 || h.admin.QueryRow(`SELECT status,row_version FROM system_backup_v2_attempts WHERE target_public_id=? AND phase='publish'`, h.original.TaskPublicID).Scan(&status, &version) != nil || status != "failed" || version <= prior {
		t.Fatal("independent failed publish attempt was not observed")
	}
}

func TestPublicationStartedJobActualProcessReopenMySQL(t *testing.T) {
	if os.Getenv("A_SIGNING_MYSQL_CREDENTIALS_FILE") == "" {
		t.Skip("requires owned local MySQL")
	}
	f := newAPublicationMaterialFixture(t, true)
	aPublicationActualObservationDDL(t, f)
	patches := aPublicationNativeJobAPI(t, f, "current")
	h, ctx := f.x.history, context.Background()
	job, err := h.service.ensureStartedPublicationJob(ctx, h.token, 1, f.store.config, f.request)
	if err != nil {
		t.Fatal(err)
	}
	m, err := h.service.preparePublicationJobMaterials(ctx, h.token, 1, f.store.config, PublicationUploadRequest{})
	if err != nil {
		t.Fatal(err)
	}
	expected := aPublicationReopenProof{RequestSHA256: m.intent.RequestSHA256, CredentialSHA256: m.intent.CredentialSHA256, MaterialBodySHA256: m.intent.BodySHA256, SecretUID: string(m.secret.UID), JobUID: string(job.UID), Deadline: m.intent.Deadline, JobOwner: true, JobGeneration: 2}
	m.Close()
	bridge, writes := aPublicationReadOnlyKubernetesBridge(t, f.client)
	dir := t.TempDir()
	proofPath := filepath.Join(dir, "started-proof.json")
	input := aPublicationReopenContext{ConfigPath: h.service.ConfigPath, ConfigSHA256: h.service.ConfigDigest, ForwardSHA256: h.service.Forward.GrantSHA256(), RecoverySHA256: h.service.Recovery.GrantSHA256(), ControlDSN: f.controlDSN, StagingPath: h.owner.Staging.Name(), KubernetesURL: bridge.URL, KubernetesCA: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: bridge.Certificate().Raw}), Inputs: f.inputs, Claim: h.token, Target: f.store.config, ProofFile: proofPath}
	raw, _ := json.Marshal(input)
	path := filepath.Join(dir, "private-context.json")
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("private child context")
	}
	clear(raw)
	clear(f.request.ManifestInput)
	clear(f.request.IndexBytes)
	f.request = PublicationUploadRequest{}
	f.controlDSN, input.ControlDSN = "", ""
	h.service.publisherVerifierFactory, h.service.Runtime, h.service = nil, nil, nil
	process := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPublicationMaterialReopenProcessChild$", "-test.v")
	process.Env = append(os.Environ(), "A_PUBLICATION_REOPEN_CONTEXT="+path)
	if output, err := process.CombinedOutput(); err != nil {
		t.Fatalf("started Job child failed: %v\n%s", err, output)
	}
	proofRaw, err := os.ReadFile(proofPath)
	var proof aPublicationReopenProof
	if err != nil || json.Unmarshal(proofRaw, &proof) != nil || proof != expected || writes.Load() != 0 || *patches != 1 || f.jobCreates != 1 || f.secretCreates != 1 {
		t.Fatal("started Job reopened another material/native operation", err)
	}
}
