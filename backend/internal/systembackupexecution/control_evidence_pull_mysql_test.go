package systembackupexecution

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	app "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/control"
	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	k "clawreef/internal/systembackupkms"
	security "clawreef/internal/systembackupsecurity"
	w "clawreef/internal/systembackupwire"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktest "k8s.io/client-go/testing"
)

// Transparent hook around the real original controller's SQL connection. It
// changes only an independently owned LOCAL source grant file during the final
// original SQL snapshot. No synthetic rows, clocks or authorizer are returned.
type aControlPullConnector struct {
	driver.Connector
	query func(string)
}

// Transparent named latency injection within each independently acquired real
// controller DEK callback. Identity, fixed deadline, rechecks and close remain
// those of the original verifier; no permission/DEK is renewed or substituted.
type aOwnedReadLatency struct {
	FormalCandidateKeyUse
	delay        func(context.Context) error
	readBoundary bool
	reading      atomic.Bool
	boundaries   atomic.Int64
	applied      atomic.Bool
}

func (x *aOwnedReadLatency) Recheck(ctx context.Context, scope FormalCandidateReadScope) error {
	// A plaintext pipe reader and ciphertext reader may run concurrently. The
	// third boundary is after the first actual original C header read; a fault
	// must execute exactly once, not merely before entering the stream callback.
	if x.readBoundary && x.reading.Load() && x.boundaries.Add(1) >= 3 && x.applied.CompareAndSwap(false, true) {
		if err := x.delay(ctx); err != nil {
			return err
		}
	}
	return x.FormalCandidateKeyUse.Recheck(ctx, scope)
}

func (x *aOwnedReadLatency) Unwrap(ctx context.Context, request w.KeyRequest, wrapped w.WrappedKey, use w.WithDEK) error {
	return x.FormalCandidateKeyUse.Unwrap(ctx, request, wrapped, func(key []byte) error {
		if x.readBoundary {
			x.reading.Store(true)
			defer x.reading.Store(false)
			return use(key)
		}
		if err := x.delay(ctx); err != nil {
			return err
		}
		return use(key)
	})
}

func aSlowOriginalOwnedCipherRead(ctx context.Context, owner *PublicJobOwner, scope FormalCandidateReadScope) error {
	custody, err := staging.OpenSealCustody(owner.Staging)
	if err != nil {
		return err
	}
	defer custody.Close()
	files, _, err := staging.OpenFormalObserved(ctx, custody, workerSealScope(scope.Authority, scope.Job, scope.Invocation), scope.Candidate.Ciphertext, scope.Candidate.Envelope)
	if err != nil {
		return err
	}
	defer files.Close()
	timer := time.NewTimer(8 * time.Second)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		return ctx.Err()
	}
	digest := sha256.New()
	n, err := io.Copy(digest, files.Ciphertext)
	if err != nil || n != scope.Candidate.Ciphertext.Size || fmt.Sprintf("%x", digest.Sum(nil)) != scope.Candidate.Ciphertext.SHA256 {
		return errors.New("owned slow C read did not match original receipt")
	}
	return ctx.Err()
}

func (x aControlPullConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := x.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &aControlPullConn{Conn: conn, query: x.query}, nil
}

type aControlPullConn struct {
	driver.Conn
	query func(string)
}

func (x *aControlPullConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	return x.Conn.(driver.ConnBeginTx).BeginTx(ctx, o)
}
func (x *aControlPullConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	x.query(q)
	return x.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
}
func (x *aControlPullConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	return x.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
}

func aRefreshControlSourceCapacity(t *testing.T, f *aControlEvidenceSourceFixture) {
	t.Helper()
	g := f.x.history.service.Forward.DeploymentBinding()
	var now time.Time
	if f.x.history.db.QueryRow("SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil {
		t.Fatal("actual capacity clock")
	}
	raw, _ := json.Marshal(security.CapacityReport{ServerUUID: g.ServerUUID, Database: g.Database, ObservedAt: now, AvailableBytes: 4 << 30})
	if os.WriteFile(f.x.history.service.Config.CapacityFile, raw, 0600) != nil {
		t.Fatal("owned capacity report")
	}
}

type aControlCaptureFixture struct {
	source       *aControlEvidenceSourceFixture
	input        d.Input
	parts        []b.JobPart
	config       k.Config
	pin          k.PermitDeliveryPin
	materialFile string
}

// Uses actual original Prepare/SavePlan/Record/TakeBackup/PrepareCapture and
// held-gate SQL. Its single physical writer and Kubernetes API are explicitly
// local named fixtures, not a six-domain Runtime/CSI certification.
func newAControlCaptureFixture(t *testing.T, f *aControlEvidenceSourceFixture, withBusiness ...bool) *aControlCaptureFixture {
	t.Helper()
	business := len(withBusiness) > 0 && withBusiness[0]
	businessCount := 1
	if len(withBusiness) > 1 && withBusiness[1] {
		businessCount = 2
	}
	expectedParts := 2
	if business {
		expectedParts += businessCount
	}
	h, ctx := f.x.history, context.Background()
	s, o := h.service, h.owner
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := h.admin.ExecContext(ctx, q, args...); err != nil {
			t.Fatal("owned CE capture setup", err)
		}
	}
	// Upgrade the original consumer's narrow gate fixtures to the actual DDL,
	// preserving constraints and using a NEW task with no prior effects.
	exec("RENAME TABLE system_backup_gate TO system_backup_gate_a_prior_fixture")
	exec("RENAME TABLE system_backup_v2_engine_bindings TO system_backup_v2_engine_bindings_a_prior_fixture")
	exec(aPublicationActualTable(t, "111_backup_engine_selection.sql", "system_backup_v2_engine_bindings"))
	exec("INSERT INTO system_backup_v2_engine_bindings(scope,engine) VALUES('installation','v2')")
	for _, table := range []string{"system_backup_gate", "system_backup_participants", "system_backup_mutation_leases"} {
		exec(aPublicationActualTable(t, "079_add_system_backup_control.sql", table))
	}
	exec(aPublicationActualTable(t, "089_add_backup_gate_admission.sql", "system_backup_gate_admissions"))
	exec("RENAME TABLE system_backup_v2_maintenance_locks TO system_backup_v2_maintenance_locks_a_prior_fixture")
	exec(aPublicationActualTable(t, "099_backup_v2_add_system_backup_coordination_observability.sql", "system_backup_v2_maintenance_locks"))
	exec(`INSERT INTO system_backup_v2_maintenance_locks(origin_installation_id,scope,lock_ttl_seconds) VALUES(?,?,600)`, f.in.Authority.InstallationID, c.CaptureGateScope)
	exec(`INSERT INTO system_backup_v2_attempts(target_type,target_public_id,attempt_no,phase,status,row_version,started_at,finished_at) SELECT target_type,target_public_id,attempt_no,phase,status,row_version,CASE WHEN status='preparing' THEN NULL ELSE UTC_TIMESTAMP(6) END,CASE WHEN status IN ('sealed','succeeded','failed','canceled') THEN UTC_TIMESTAMP(6) ELSE NULL END FROM system_backup_v2_attempts_a_prior_fixture`)
	// Earlier publication fixtures renamed their parent backup table. Rebuild
	// these original 123 tables against the actual 098 parent, preserving their
	// prior rows. No FK is disabled or left pointing at the narrow fixture.
	for _, table := range []string{"system_backup_v2_runtime_resources", "system_backup_v2_runtime_captures"} {
		copyName := table + "_a_parent_copy"
		exec("CREATE TABLE " + copyName + " AS SELECT * FROM " + table)
		exec("DROP TABLE " + table)
		exec(aPublicationActualTable(t, "123_backup_v2_runtime_execution_journal.sql", table))
		if table == "system_backup_v2_runtime_resources" {
			for _, name := range []string{"125_backup_v2_job_key_use.sql", "131_backup_v2_formal_job_candidates.sql"} {
				raw, err := os.ReadFile(filepath.Join("..", "db", "migrations", name))
				if err != nil {
					t.Fatal(err)
				}
				exec(string(raw))
			}
		}
		exec("INSERT INTO " + table + " SELECT * FROM " + copyName)
	}
	exec(aPublicationActualTable(t, "123_backup_v2_runtime_execution_journal.sql", "system_backup_v2_runtime_writers"))
	exec("RENAME TABLE system_backup_v2_execution_inputs TO system_backup_v2_execution_inputs_a_prior_fixture")
	exec(aPublicationActualTable(t, "119_backup_v2_execution_admission.sql", "system_backup_v2_execution_inputs"))
	requestRaw := []byte(`{"requested_parts":["mysql"],"task_purpose":"functional_test"}`)
	if business {
		requestRaw = []byte(`{"requested_parts":["mysql","workspace"],"task_purpose":"functional_test"}`)
	}
	exec(`INSERT INTO system_backup_v2_execution_inputs(origin_installation_id,task_public_id,task_type,profile_json,profile_sha256,request_json) SELECT origin_installation_id,task_public_id,task_type,profile_json,profile_sha256,? FROM system_backup_v2_execution_inputs_a_prior_fixture`, requestRaw)
	exec("UPDATE system_backup_v2_backups SET request_hash=? WHERE public_id=?", hash(requestRaw), f.in.Authority.TaskPublicID)
	sourceWaitDDL, err := os.ReadFile(filepath.Join("..", "db", "migrations", "129_backup_v2_source_gate_wait.sql"))
	if err != nil {
		t.Fatal(err)
	}
	exec(string(sourceWaitDDL))
	if err := (app.Gate{DB: h.admin}).EnsureScope(ctx, s.Config.ApplicationScope); err != nil {
		t.Fatal("actual idle gate initialization", err)
	}
	g := s.Forward.DeploymentBinding()
	grants, err := c.ControlEvidenceGrantSQL(g.Database, strings.Split(g.DatabaseAccount, "@")[0], "127.0.0.1", false, false, true, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range grants {
		_, rest, ok := strings.Cut(q, "`.`")
		if !ok {
			t.Fatal("official table grant")
		}
		table, _, ok := strings.Cut(rest, "`")
		if !ok {
			t.Fatal("official table grant")
		}
		var exists int
		if h.admin.QueryRow("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?", table).Scan(&exists) != nil {
			t.Fatal("actual table inventory")
		}
		if exists == 1 {
			exec(q)
		}
	}
	config, pin := aEnableControlGenerateIssuer(t, f)
	mount := *f.materials.ControlEvidenceSource
	scope, err := worker.ControlEvidenceSourceScopeSHA256(f.expected, mount.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	grant := worker.ControlEvidenceSourceGrant{Version: worker.ControlEvidenceSourceGrantVersion, InstallationID: f.expected.Installation, ConfigSHA256: f.expected.ConfigSHA256, WorkerNamespace: o.Namespace, WorkerServiceAccountUID: o.Security.ServiceAccountUID, Operation: ce.Operation, ScopeSHA256: scope, NotBefore: time.Now().Add(-time.Minute), Until: f.in.Authority.DeadlineAt}
	grantRaw, _ := json.Marshal(grant)
	signed, _ := json.Marshal(worker.SignedControlEvidenceSourceGrant{Record: grantRaw, Signature: ed25519.Sign(f.sourceKey, append([]byte(worker.ControlEvidenceSourceGrantDomain), grantRaw...))})
	mount.GrantSHA256 = hash(signed)
	if os.WriteFile(mount.GrantFile, signed, 0600) != nil || os.WriteFile(mount.ControllerGrantFile, signed, 0600) != nil {
		t.Fatal("independent worker/controller source projections")
	}
	materials := worker.FormalCaptureMaterials{Version: worker.FormalCaptureVersion, KMS: config, PermitDelivery: &pin, ControlEvidence: &mount}
	materialRaw, _ := json.Marshal(materials)
	materialFile := filepath.Join(filepath.Dir(s.ConfigPath), "actual-worker-materials.json")
	if os.WriteFile(materialFile, materialRaw, 0600) != nil {
		t.Fatal("original worker material projection")
	}
	in := f.in
	var profile struct {
		Installation string `json:"installation_id"`
		ID           string `json:"source_profile"`
		Revision     string `json:"revision"`
	}
	var profileRaw []byte
	if h.db.QueryRow("SELECT profile_json FROM system_backup_v2_execution_inputs WHERE task_public_id=?", in.Authority.TaskPublicID).Scan(&profileRaw) != nil || json.Unmarshal(profileRaw, &profile) != nil {
		t.Fatal("original profile input")
	}
	in.ProfileID, in.ProfileRevision = profile.ID, profile.Revision
	exec("UPDATE system_backup_v2_backups SET datasource_topology='in_cluster' WHERE public_id=?", in.Authority.TaskPublicID)
	in.Backup = &d.BackupSpec{SourceOrchestrator: "kubernetes", SourceProfile: "cluster", MatrixKey: "k8s-cluster", DatasourceTopology: "in_cluster", Runner: "k8s", TaskPurpose: "functional_test", RequestedParts: []string{"mysql"}}
	if business {
		in.Backup.RequestedParts = append(in.Backup.RequestedParts, "workspace")
	}
	source := b.SourceInventory{Database: s.Config.SourceDatabase, ServerUUID: s.Config.SourceServerUUID, Users: []int{}, Instances: []b.InstanceIdentity{}}
	sourceRaw, _ := json.Marshal(source)
	sourceSHA := hash(sourceRaw)
	hold := time.Now().UTC().Add(90 * time.Second).Truncate(time.Microsecond)
	point := b.ModuleCaptureContext{InstallationID: in.Authority.InstallationID, TaskPublicID: in.Authority.TaskPublicID, ConfigVersion: in.Authority.ConfigVersion, AttemptNo: in.Authority.AttemptNo, Phase: "capture", ConfigSHA256: in.Authority.ConfigSHA256, ProfileID: in.ProfileID, ProfileRevision: in.ProfileRevision, InventorySHA256: sourceSHA, CatalogSHA256: hash([]byte("original CE module fixture catalog")), CaptureContextSHA256: hash([]byte("original CE pair fixture context")), HoldUntil: hold}
	requests := make([]b.CapturePartRequest, 2)
	for index, part := range []string{ce.Part, ce.ProofPart} {
		name := "control-" + strconv.Itoa(index) + "-" + strings.TrimPrefix(in.Authority.TaskPublicID, "sbk_")
		limit, logical := int64(ce.MaxBytes), ce.LogicalCipherName
		if index == 1 {
			limit, logical = ce.MaxProofBytes, ce.LogicalProofCipherName
		}
		binding := staging.Binding{BackupID: in.Authority.TaskPublicID, Attempt: "1", Path: part, PartIndex: uint32(index), EnvelopeID: name + "-envelope", CaptureContextHash: point.CaptureContextSHA256}
		inv := worker.Invocation{StagingPath: "/staging", Request: worker.Request{Version: worker.Version, Operation: ce.Operation, Binding: binding, Deadline: hold, ArtifactName: logical, MaxArchiveBytes: limit, MaxCompressedBytes: limit, ControlEvidence: &f.locator}, ProviderKey: &k.Access{Operation: k.Generate, Endpoint: config.Endpoint, KeyName: config.KeyName, Request: w.KeyRequest{Key: config.Key, Context: w.KeyContext{InstallationID: in.Authority.InstallationID, BackupPublicID: in.Authority.TaskPublicID, AttemptNo: "1", Phase: "capture", Part: part, PartIndex: strconv.Itoa(index), EnvelopeID: binding.EnvelopeID, CaptureContextHash: binding.CaptureContextHash}}}, FormalCapture: &worker.FormalCaptureSpec{Version: worker.FormalCaptureVersion, ConfigSHA256: hash(materialRaw), SourceConfigSHA256: in.Authority.ConfigSHA256, EnvelopeName: part + ".envelope", MaxFrames: 64, PermitDelivery: &pin}}
		workload := kube.JobRequest{Identity: kube.Identity{Namespace: o.Namespace, Name: name, Owner: in.Authority.TaskPublicID}, Image: s.Config.WorkerImage, ServiceAccount: o.Security.ServiceAccountName, StagingClaim: s.Config.StagingClaim, DeadlineSeconds: 60, FormalMaterials: &kube.FormalJobMaterials{ConfigMap: name + "-formal", Inputs: []kube.FormalInputMount{{Volume: "formal-control-source", Kind: "ConfigMap", Name: name + "-source", Directory: "/run/backup/materials/source", Items: []corev1.KeyToPath{{Key: "grant.json", Path: "grant.json"}}}}}, WorkerControl: &kube.WorkerControl{URL: s.Config.ControlURL, InvocationConfigMap: name + "-inv", IdentitySecret: name + "-identity", BoundPodIdentity: true}}
		requests[index] = b.CapturePartRequest{Part: part, Category: ce.Part, JobUnitKey: part, Generation: 1, Workload: workload, Invocation: inv}
	}
	registrations := []b.CaptureModuleRegistration{}
	if business {
		businessRequests := []b.CapturePartRequest{}
		businessParts := []b.CaptureModulePart{}
		policyParts := []ce.FinalizationPart{}
		for ordinal := 0; ordinal < businessCount; ordinal++ {
			part := "z_business_workspace"
			name := "business-" + strings.TrimPrefix(in.Authority.TaskPublicID, "sbk_")
			if ordinal > 0 {
				part += "_" + strconv.Itoa(ordinal)
				name += "-" + strconv.Itoa(ordinal)
			}
			partIndex := 2 + ordinal
			inv := requests[0].Invocation
			inv.WorkspacePath = "/workspace"
			inv.Request = worker.Request{Version: worker.Version, Operation: "capture-workspace", Binding: staging.Binding{BackupID: in.Authority.TaskPublicID, Attempt: strconv.FormatUint(in.Authority.AttemptNo, 10), PartIndex: uint32(partIndex), Path: part, EnvelopeID: name + "-envelope", CaptureContextHash: point.CaptureContextSHA256}, Deadline: hold, ArtifactName: part + ".enc", MaxFiles: 100, MaxFileBytes: 1 << 20, MaxArchiveBytes: 2 << 20, MaxCompressedBytes: 2 << 20}
			formal := *inv.FormalCapture
			formal.EnvelopeName = part + ".envelope"
			formal.SourceConfigSHA256 = ""
			inv.FormalCapture = &formal
			provider := *inv.ProviderKey
			provider.Request.Context.Part = part
			provider.Request.Context.PartIndex = strconv.Itoa(partIndex)
			provider.Request.Context.EnvelopeID = inv.Request.Binding.EnvelopeID
			inv.ProviderKey = &provider
			workload := requests[0].Workload
			workload.Identity.Name = name
			workload.Source = corev1.Volume{Name: "source", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "owned-business-source"}}}
			workload.WorkerControl = &kube.WorkerControl{URL: s.Config.ControlURL, InvocationConfigMap: name + "-inv", IdentitySecret: name + "-identity", BoundPodIdentity: true}
			workload.FormalMaterials = &kube.FormalJobMaterials{ConfigMap: name + "-formal", Inputs: []kube.FormalInputMount{{Volume: "formal-control-source", Kind: "ConfigMap", Name: name + "-source", Directory: "/run/backup/materials/source", Items: []corev1.KeyToPath{{Key: "grant.json", Path: "grant.json"}}}}}
			request := b.CapturePartRequest{Part: part, Category: "instances", JobUnitKey: part, Generation: 1, Workload: workload, Invocation: inv}
			if !worker.ValidateRecordedInvocation(inv) {
				t.Fatal("named original business invocation invalid")
			}
			if _, buildErr := b.BuildCapturePart(in, hold, request); buildErr != nil {
				t.Fatal("named original business part construction", buildErr)
			}
			invSHA, err := inv.Hash()
			if err != nil {
				t.Fatal(err)
			}
			policyParts = append(policyParts, ce.FinalizationPart{Part: part, Operation: inv.Request.Operation, InvocationSHA256: invSHA})
			businessRequests = append(businessRequests, request)
			businessParts = append(businessParts, b.CaptureModulePart{Part: part, Category: "instances", RequestedPart: "workspace", Operation: "capture-workspace"})
		}
		seed, err := ce.RequireOwnedFinalization(f.locator, ce.FinalizationPolicy{Version: ce.FinalizationPolicyVersion, ChecksVersion: ce.OwnedChecksVersion, CaptureContextSHA256: point.CaptureContextSHA256, Parts: policyParts})
		if err != nil {
			t.Fatal(err)
		}
		for index := range requests {
			requests[index].Invocation.Request.ControlEvidence = &seed
		}
		registrations = append(registrations, b.CaptureModuleRegistration{Descriptor: b.CaptureModuleDescriptor{ID: "zz_named_business", Owner: "B", Revision: "named-portable-source-r1", Required: true, Parts: businessParts}, Build: func(input b.CaptureModuleInput) ([]b.CapturePartRequest, error) {
			if len(input.Parts) != len(businessRequests) || input.Parts[0].PartIndex != 2 {
				return nil, d.ErrNotReady
			}
			return businessRequests, nil
		}})
	}
	registration, err := b.NewControlEvidenceModule(b.ControlEvidenceModuleConfig{Revision: "original-control-pair-r1", Sidecar: requests[0], Proofs: requests[1]})
	if err != nil {
		t.Fatal("actual paired module", err)
	}
	registrations = append(registrations, registration)
	modules, err := b.NewCaptureModules(registrations, func(_ d.Input, _ b.SourceInventory, _ time.Time, catalog string) (b.ModuleCaptureContext, error) {
		point.CatalogSHA256 = catalog
		return point, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	parts, err := modules.BuildParts(in, source, hold)
	if err != nil || len(parts) != expectedParts {
		t.Fatal("actual paired Job assembly", err)
	}
	writer := b.FrozenWriter{ID: "controlled-metadata-writer", Original: flow.State{UID: "controlled-metadata-writer-uid", Generation: 1, Running: true}}
	discovery := b.Discovery{Source: sourceRaw, SourceSHA256: sourceSHA, Parts: parts, Writers: []b.FrozenWriter{writer}, HoldUntil: hold}
	runner, err := b.NewPublicRunner(b.Dependencies{Profiles: map[b.ProfileKey]b.Profile{{ID: in.ProfileID, Revision: in.ProfileRevision}: consumerFrozenProfile{discovery}}, Results: PublicResults{o}, Recovery: o, Admission: func(ctx context.Context, in d.Input) error { return o.Gate.Check(ctx, in.Authority) }, ValidateInventory: func(_ context.Context, _ d.Input, got b.Discovery) error {
		if len(got.Parts) != expectedParts {
			return d.ErrNotReady
		}
		return nil
	}, RecoveryTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	bound, err := d.BindTaskRunner(runner, b.PlanVersion)
	if err != nil {
		t.Fatal(err)
	}
	ports, err := c.NewExecutionJobPorts(o.Gate, o)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := bound.Prepare(ctx, in, ports)
	if err != nil {
		t.Fatal("actual original CE Prepare", err)
	}
	aRefreshControlSourceCapacity(t, f)
	if err = o.Gate.Records.SavePlan(ctx, in, plan); err != nil {
		t.Fatal("actual original CE SavePlan", err)
	}
	queue := c.SQLExecutionQueue{DB: h.db, InstallationID: in.Authority.InstallationID, Owner: in.Authority.ClaimOwner, Policy: c.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second}, Authorization: o.Gate.Authority.Authorization, ApplicationScope: s.Config.ApplicationScope, Recovery: &o.Gate.Recovery}
	workStore := c.SQLExecutionWorkStore{Queue: queue, Authority: o.Gate.Authority, Records: o.Gate.Records, PrepareCapture: o.Gate.PrepareCapture, FinishCapture: o.Gate.FinishCapture}
	if err = workStore.Record(ctx, c.ExecutionWork{Step: c.ExecutionPrepare, Input: in}, c.ExecutionOutcome{Plan: plan}); err != nil {
		t.Fatal("actual original CE preparation Record", err)
	}
	time.Sleep(1100 * time.Millisecond)
	claimed, err := queue.TakeBackup(ctx)
	if err != nil {
		t.Fatal("actual original CE TakeBackup", err)
	}
	work, err := o.Gate.PrepareCapture(ctx, claimed)
	if err != nil || work == nil {
		t.Fatal("actual original CE PrepareCapture", err)
	}
	in = work.Input
	if err = o.Gate.PauseIntent(ctx, in.Authority, writer.ID, d.WriterState{UID: writer.Original.UID, Generation: 1, Running: true}); err != nil {
		t.Fatal("actual original pause intent", err)
	}
	if err = o.Gate.Paused(ctx, in.Authority, writer.ID, d.WriterACK{UID: writer.Original.UID, Generation: 1, Stopped: true}); err != nil {
		t.Fatal("named physical pause ACK / real held projection", err)
	}
	if err = o.Gate.ValidateCollectors(ctx, in.Authority); err != nil {
		t.Fatal("actual original held collector guard", err)
	}
	// The bundle carries the original source-owner mount independently of the
	// worker mapping. Neither side can grant itself the other's issuer.
	f.materials.ControlEvidenceSource = &mount
	op := f.materials.Operations[ce.Operation]
	op.Formal = *requests[0].Invocation.FormalCapture
	f.materials.Operations[ce.Operation] = op
	materialBundle, _ := json.Marshal(f.materials)
	if os.WriteFile(s.Config.CaptureModules.Path, materialBundle, 0600) != nil {
		t.Fatal("original capture bundle")
	}
	if err = s.loadProductionCapture([]ProductionCaptureInput{{File: s.Config.CaptureModules.Path, SHA256: hash(materialBundle)}}); err != nil {
		t.Fatal("original CE source material binding", err)
	}
	return &aControlCaptureFixture{source: f, input: in, parts: parts, config: config, pin: pin, materialFile: materialFile}
}

// A separate local installation/provider owner signs the real Generate
// capability and delegation. Current original SQL/Job remains mandatory.
func aEnableControlGenerateIssuer(t *testing.T, f *aControlEvidenceSourceFixture) (k.Config, k.PermitDeliveryPin) {
	t.Helper()
	h := f.x.history
	s := h.service
	g := s.Forward.DeploymentBinding()
	binding := f.x.cfg.Binding
	now := time.Now().UTC()
	permission := a.ProviderCapabilityPermission{Path: "transit/datakey/plaintext/original-key", ProviderVersion: "1", AuthMount: "capture-jwt", Role: "capture-generate-role", Policy: "capture-generate-policy", PolicySHA256: strings.Repeat("a", 64), RoleSHA256: strings.Repeat("b", 64), JWTTrustSHA256: strings.Repeat("c", 64), Reference: binding.GenerateRef}
	capPub, capKey, _ := ed25519.GenerateKey(rand.Reader)
	defer clear(capKey)
	record := a.ProviderCapabilityRecord{Facts: a.ProviderCapabilityFacts{Binding: binding, Operation: k.Generate, Permission: permission}, Source: reg.SourceRecord{SourceID: "original-control-generate-owner", RecordID: "sev_original_control_generate", RecordVersion: "v1"}, Revision: "r1", NotBefore: now.Add(-time.Minute), Until: f.in.Authority.DeadlineAt}
	facts, _ := json.Marshal(record.Facts)
	record.Source.ContentSHA256 = hash(facts)
	raw, _ := json.Marshal(record)
	envelope, _ := json.Marshal(a.SignedProviderCapabilityRecord{Record: raw, Signature: ed25519.Sign(capKey, append([]byte(a.ProviderCapabilityDomain), raw...))})
	if _, err := h.admin.Exec(`INSERT INTO system_backup_v2_evidence(public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,observed_health,encryption,inline_payload,content_checksum,content_size_bytes,media_type,redaction_classification,expires_at) VALUES(?,'system',?,'capability_snapshot','inline','healthy','none',?,?,?,'application/json','internal',?)`, record.Source.RecordID, g.InstallationID, envelope, hash(envelope), len(envelope), record.Until); err != nil {
		t.Fatal("actual signed Generate capability", err)
	}
	workload := a.ControllerVerifierWorkload{Namespace: "controller", PodName: "controller-pod", PodUID: "controller-pod-uid", ServiceAccountName: "controller", ServiceAccountUID: "controller-sa", OwnerKind: "Deployment", OwnerUID: "controller-deployment-uid", ControllerOwner: g.ControllerOwner, ConfigVersion: g.ConfigVersion, ConfigSHA256: g.ConfigSHA256}
	rootPub, rootKey, _ := ed25519.GenerateKey(rand.Reader)
	defer clear(rootKey)
	issuerPub, issuerKey, _ := ed25519.GenerateKey(rand.Reader)
	defer clear(issuerKey)
	dir := filepath.Dir(s.ConfigPath)
	jwtFile, keyFile, grantFile := filepath.Join(dir, "control-job.jwt"), filepath.Join(dir, "control-permit.key"), filepath.Join(dir, "control-permit.json")
	if os.WriteFile(jwtFile, []byte("local-capture-projected-jwt-only"), 0600) != nil || os.WriteFile(keyFile, issuerKey, 0600) != nil {
		t.Fatal("owned independent issuer files")
	}
	grant := a.ProviderPermitIssuerGrant{Version: "system-backup-provider-permit-issuer-grant.v1", Binding: binding, Database: reg.DatabaseIdentity{ServerUUID: g.ServerUUID, Database: g.Database}, DatabaseAccount: g.DatabaseAccount, Workload: workload, SigningPublicKey: issuerPub, GeneratePermission: permission, WorkerNamespace: s.Config.Namespace, WorkerServiceAccountName: s.Config.Security.ServiceAccountName, WorkerServiceAccountUID: s.Config.Security.ServiceAccountUID, WorkerJWTIdentityFile: jwtFile, NotBefore: now.Add(-time.Minute), Until: f.in.Authority.DeadlineAt}
	raw, _ = json.Marshal(grant)
	envelope, _ = json.Marshal(a.SignedProviderPermitIssuerGrant{Record: raw, Signature: ed25519.Sign(rootKey, append([]byte(a.ProviderPermitIssuerGrantDomain), raw...))})
	if os.WriteFile(grantFile, envelope, 0600) != nil {
		t.Fatal("original permit delegation")
	}
	workload.GrantSHA256 = hash(envelope)
	pin := k.PermitDeliveryPin{Version: k.PermitDeliveryVersion, Issuer: issuerPub, IssuerGrantSHA256: workload.GrantSHA256}
	s.formalVerifier = &FormalVerifierDeploymentConfig{Database: grant.Database, Binding: binding, InstallationIssuer: f.x.cfg.InstallationIssuer, GenerateCapability: a.ProviderCapabilityPin{Source: record.Source, Issuer: capPub}, UnwrapCapability: f.x.materials.UnwrapCapability, ProviderPermits: &ProviderPermitDeploymentConfig{Workload: workload, Grant: a.ProviderPermitIssuerGrantMount{File: grantFile, SHA256: workload.GrantSHA256, Issuer: rootPub}, SigningKeyFile: keyFile, DeliveryPin: pin}}
	aEnableControlOriginalVerifier(t, f)
	return k.Config{Endpoint: binding.Provider.Endpoint, InstallationID: g.InstallationID, KeyName: binding.Provider.KeyName, Key: binding.Key, CAPEM: f.x.cfg.CAPEM, CASHA256: binding.Provider.CAPEMSHA256, NotBefore: now.Add(-time.Minute), NotAfter: f.in.Authority.DeadlineAt}, pin
}

// The source and Generate issuer never supply this independent original
// verification permission. The actual service loads its separately signed
// controller grant/capability before attaching the original SQL consumer.
func aEnableControlOriginalVerifier(t *testing.T, f *aControlEvidenceSourceFixture) {
	t.Helper()
	h, s := f.x.history, f.x.history.service
	v := s.formalVerifier
	workload := v.ProviderPermits.Workload
	workload.GrantSHA256 = ""
	now := time.Now().UTC()
	grant := a.ControllerVerifierGrant{Version: "system-backup-controller-verifier-grant.v1", InstallationID: f.expected.Installation, Database: v.Database, DatabaseAccount: s.Forward.DeploymentBinding().DatabaseAccount, Workload: workload, CaptureGrantSHA256: s.Forward.GrantSHA256(), NotBefore: now.Add(-time.Minute), Until: f.in.Authority.DeadlineAt}
	issuer, private, _ := ed25519.GenerateKey(rand.Reader)
	defer clear(private)
	raw, _ := json.Marshal(grant)
	envelope, _ := json.Marshal(a.SignedControllerVerifierGrant{Record: raw, Signature: ed25519.Sign(private, append([]byte(a.ControllerVerifierGrantDomain), raw...))})
	workload.GrantSHA256 = hash(envelope)
	dir := filepath.Dir(s.ConfigPath)
	grantFile, jwtFile := filepath.Join(dir, "control-verifier-grant.json"), filepath.Join(dir, "control-verifier.jwt")
	if os.WriteFile(grantFile, envelope, 0600) != nil || os.WriteFile(jwtFile, []byte("local-controller-projected-jwt-only"), 0600) != nil {
		t.Fatal("independent original verifier mounts")
	}
	capability := a.ProviderCapabilityRecord{Facts: a.ProviderCapabilityFacts{Binding: v.Binding, Operation: k.Unwrap, Permission: a.ProviderCapabilityPermission{Path: "transit/decrypt/original-key", ProviderVersion: "1", AuthMount: "controller-jwt", Role: "controller-unwrap-role", Policy: "controller-unwrap-policy", PolicySHA256: strings.Repeat("a", 64), RoleSHA256: strings.Repeat("b", 64), JWTTrustSHA256: strings.Repeat("c", 64), Reference: v.Binding.UnwrapRef, ControllerVerifier: &workload}}, Source: reg.SourceRecord{SourceID: "original-controller-observer", RecordID: "sev_control_original_unwrap", RecordVersion: "v1"}, Revision: "r1", NotBefore: now.Add(-time.Minute), Until: grant.Until}
	facts, _ := json.Marshal(capability.Facts)
	capability.Source.ContentSHA256 = hash(facts)
	capPub, capKey, _ := ed25519.GenerateKey(rand.Reader)
	defer clear(capKey)
	raw, _ = json.Marshal(capability)
	envelope, _ = json.Marshal(a.SignedProviderCapabilityRecord{Record: raw, Signature: ed25519.Sign(capKey, append([]byte(a.ProviderCapabilityDomain), raw...))})
	if _, err := h.admin.Exec(`INSERT INTO system_backup_v2_evidence(public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,observed_health,encryption,inline_payload,content_checksum,content_size_bytes,media_type,redaction_classification,expires_at) VALUES(?,'system',?,'capability_snapshot','inline','healthy','none',?,?,?,'application/json','internal',?)`, capability.Source.RecordID, f.expected.Installation, envelope, hash(envelope), len(envelope), capability.Until); err != nil {
		t.Fatal("actual original Unwrap capability", err)
	}
	v.Version, v.Workload, v.CAFile, v.JWTFile = formalVerifierMaterialsVersion, workload, f.x.materials.CAFile, jwtFile
	v.Grant = a.ControllerVerifierGrantMount{File: grantFile, SHA256: workload.GrantSHA256, Issuer: issuer}
	v.UnwrapCapability = a.ProviderCapabilityPin{Source: capability.Source, Issuer: capPub}
	raw, _ = json.Marshal(v)
	if os.WriteFile(s.Config.FormalVerifier.Path, raw, 0600) != nil {
		t.Fatal("original verifier bundle")
	}
	if err := s.loadFormalVerifier([]FormalVerifierInput{{File: s.Config.FormalVerifier.Path, SHA256: hash(raw)}}); err != nil {
		t.Fatal("independent original verifier startup", err)
	}
}

func TestAControlEvidenceOriginalCaptureComposition(t *testing.T) {
	for _, mode := range []string{"pair", "controller-grant-replaced-during-final-sql", "job-stopped-before-final-sql", "owned-finalization", "owned-long-batch", "owned-long-use", "owned-malformed-business", "owned-source-withdrawn", "owned-context-canceled", "owned-claim-released", "owned-claim-taken-over", "owned-provider-revoked", "owned-issuer-revoked", "owned-fixed-dek-expired", "owned-missing-business-result"} {
		t.Run(mode, func(t *testing.T) { testAControlEvidenceOriginalCapture(t, mode) })
	}
}

func testAControlEvidenceOriginalCapture(t *testing.T, mode string) {
	business := strings.HasPrefix(mode, "owned-")
	malformed := mode == "owned-malformed-business"
	longUse := mode == "owned-long-use"
	longBatch := mode == "owned-long-batch" || longUse
	withdrawSource := mode == "owned-source-withdrawn"
	missingResult := mode == "owned-missing-business-result"
	cancelRead := mode == "owned-context-canceled"
	releaseClaim, takeoverClaim := mode == "owned-claim-released", mode == "owned-claim-taken-over"
	revokeProvider, revokeIssuer := mode == "owned-provider-revoked", mode == "owned-issuer-revoked"
	expireDEK := mode == "owned-fixed-dek-expired"
	ownedFault := withdrawSource || cancelRead || releaseClaim || takeoverClaim || revokeProvider || revokeIssuer || expireDEK || missingResult
	var ownedReadEntered atomic.Bool
	replaceGrant, stopJob := mode == "controller-grant-replaced-during-final-sql", mode == "job-stopped-before-final-sql"
	fault := replaceGrant || stopJob
	var s *DeploymentService
	var armed, replaced atomic.Bool
	var evidenceReads atomic.Int64
	var sourceReads atomic.Int64
	var source *aControlEvidenceSourceFixture
	var currentJob string
	var workerIssuer control.IdentityIssuer
	endpoint, makeClient := originalMTLSControlServer(t, http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
		if s == nil {
			out.WriteHeader(503)
			return
		}
		if fault && r.URL.Path == ControlEvidencePullPath {
			evidenceReads.Store(0)
			sourceReads.Store(0)
			armed.Store(true)
			defer armed.Store(false)
		}
		s.controlHandler().ServeHTTP(out, r)
	}), func(issuer control.IdentityIssuer) { workerIssuer = issuer })
	f := newAControlEvidenceSourceFixture(t, func(o *aPublisherVerifierFixtureOptions) {
		if business {
			o.WorkerIssuer = &workerIssuer
		}
		o.ControlURL = endpoint + "/worker/v1"
		o.ControlRequestedParts = []string{"mysql"}
		if business {
			o.ControlRequestedParts = append(o.ControlRequestedParts, "workspace")
		}
		if fault {
			o.WrapControlConnector = func(inner driver.Connector) driver.Connector {
				return aControlPullConnector{Connector: inner, query: func(q string) {
					if !armed.Load() || source == nil || replaced.Load() {
						return
					}
					if strings.HasPrefix(q, "SELECT public_id,owner_target_type,owner_target_public_id,evidence_type,inline_payload") {
						evidenceReads.Add(1)
					}
					if stopJob && strings.HasPrefix(q, "SELECT key_use_json FROM system_backup_v2_runtime_resources WHERE target_type=?") && sourceReads.Add(1) == 2 {
						if _, err := source.x.history.admin.Exec(`UPDATE system_backup_v2_runtime_resources SET stopped_at=UTC_TIMESTAMP(6) WHERE target_type='backup' AND task_public_id=? AND resource_kind='Job' AND observed_uid=?`, source.expected.Backup, currentJob); err != nil {
							t.Error("owned final SQL Job state change", err)
						}
						replaced.Store(true)
					}
					// Both complete registered-body snapshots have been read. The
					// following clock query still executes against real original SQL.
					if replaceGrant && q == "SELECT UTC_TIMESTAMP(6)" && evidenceReads.Load() == int64(2*len(source.locator.Evidence)) {
						if os.WriteFile(source.materials.ControlEvidenceSource.ControllerGrantFile, []byte("independent source owner revoked this projection"), 0600) != nil {
							t.Error("owned controller projection replacement failed")
						}
						replaced.Store(true)
					}
				}}
			}
		}
	})
	source = f
	s = f.x.history.service
	x := newAControlCaptureFixture(t, f, business, longBatch)
	expectedResults, expectedDecrypts := 2, int64(2)
	if business {
		expectedResults, expectedDecrypts = 3, 4
	}
	if longBatch {
		expectedResults, expectedDecrypts = 4, 6
	}
	if len(x.parts) != expectedResults || x.input.Authority.MaintenanceFencingToken == 0 {
		t.Fatal("missing original pair/held epoch")
	}
	h, ctx := f.x.history, context.Background()
	o := h.owner
	if business {
		o.Issuer = workerIssuer
	}
	if business {
		heartbeatCtx, cancelHeartbeat := context.WithCancel(ctx)
		started := make(chan context.Context, 1)
		done := make(chan error, 1)
		store := c.SQLExecutionWorkStore{Queue: c.SQLExecutionQueue{DB: h.db, InstallationID: x.input.Authority.InstallationID, Owner: x.input.Authority.ClaimOwner, Policy: c.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second}}}
		go func() {
			done <- store.RunWithExecutionHeartbeat(heartbeatCtx, x.input.Authority, func(runCtx context.Context) error { started <- runCtx; <-runCtx.Done(); return nil })
		}()
		ctx = <-started
		defer func() {
			cancelHeartbeat()
			if err := <-done; err != nil && !((releaseClaim || takeoverClaim) && errors.Is(err, c.ErrClaimLost)) {
				t.Error("actual original capture heartbeat", err)
			}
		}()
	}
	if err := o.Staging.Mkdir(x.input.Authority.TaskPublicID, 0700); err != nil {
		t.Fatal(err)
	}
	taskStage, err := o.Staging.OpenRoot(x.input.Authority.TaskPublicID)
	if err != nil {
		t.Fatal(err)
	}
	defer taskStage.Close()
	plain := map[string][]byte{}
	captureParts := append([]b.JobPart{}, x.parts...)
	if business {
		captureParts = append(append([]b.JobPart{}, x.parts[2:]...), x.parts[:2]...)
	} // execution dependency only; original global indices/plan stay frozen
	for index, part := range captureParts {
		phaseStarted := time.Now()
		var inv worker.Invocation
		var object batchv1.Job
		if json.Unmarshal(part.InvocationJSON, &inv) != nil || json.Unmarshal(part.Intent.SpecJSON, &object) != nil {
			t.Fatal("original frozen pair")
		}
		if seed := inv.Request.ControlEvidence; seed != nil && seed.Finalization != nil {
			aRefreshControlSourceCapacity(t, f)
			admissionCtx, cancelAdmission := context.WithCancel(ctx)
			originalKeys := o.FormalKeys
			firstCE := index == len(x.parts)-2
			var evidenceBefore, resourcesBefore int
			if firstCE && ownedFault {
				if h.db.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_evidence WHERE owner_target_type='backup' AND owner_target_public_id=?`, x.input.Authority.TaskPublicID).Scan(&evidenceBefore) != nil || h.db.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE task_public_id=?`, x.input.Authority.TaskPublicID).Scan(&resourcesBefore) != nil {
					t.Fatal("original pre-admission effect snapshot")
				}
			}
			if firstCE && missingResult {
				if _, err := h.admin.Exec(`UPDATE system_backup_v2_runtime_resources SET result_sha256=NULL WHERE task_public_id=? AND resource_kind='Job'`, x.input.Authority.TaskPublicID); err != nil {
					t.Fatal(err)
				}
			}
			if firstCE && (longBatch || ownedFault && !missingResult) {
				if longBatch {
					for _, selected := range seed.Finalization.Parts {
						for _, frozen := range x.parts {
							if selected.Part == frozen.Part && selected.InvocationSHA256 != frozen.InvocationSHA256 {
								t.Fatal("frozen business invocation changed during module assembly", selected.Part)
							}
						}
					}
				}
				o.FormalKeys = func(readCtx context.Context, scope FormalCandidateReadScope) (FormalCandidateKeyUse, error) {
					if longBatch && !longUse {
						// Model slow ciphertext storage BEFORE acquiring the next DEK.
						// This reads the actual original private C and verifies its full
						// receipt; it creates no fallback/result or permission.
						if err := aSlowOriginalOwnedCipherRead(readCtx, o, scope); err != nil {
							return nil, err
						}
					}
					actual, err := originalKeys(readCtx, scope)
					if err != nil {
						return nil, err
					}
					return &aOwnedReadLatency{FormalCandidateKeyUse: actual, readBoundary: ownedFault && !cancelRead && !expireDEK && !missingResult, delay: func(useCtx context.Context) error {
						ownedReadEntered.Store(true)
						if expireDEK {
							<-useCtx.Done()
							return useCtx.Err()
						}
						if releaseClaim || takeoverClaim {
							token := c.ClaimToken{Target: c.Target{Kind: c.TargetBackup, PublicID: x.input.Authority.TaskPublicID}, Owner: x.input.Authority.ClaimOwner, RowVersion: x.input.Authority.ClaimRowVersion}
							version, err := (c.ClaimCoordinator{Executor: h.db, InstallationID: x.input.Authority.InstallationID}).Release(useCtx, token, time.Microsecond)
							if err != nil {
								return err
							}
							if takeoverClaim {
								_, err = c.AcquireClaimInInstallation(useCtx, h.db, x.input.Authority.InstallationID, token.Target, token.Owner+"-takeover", version, c.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second})
								if err != nil {
									return err
								}
							}
						}
						if revokeProvider {
							record := f.x.original
							record.UnwrapRevoked = true
							record.Revision = "owner-revoked-during-owned-C-read"
							f.x.putOriginal(record, 1)
						}
						if revokeIssuer && os.WriteFile(s.formalVerifier.Grant.File, []byte("independent verifier issuer withdrew during original C read"), 0600) != nil {
							return errors.New("owned verifier issuer withdrawal failed")
						}
						if cancelRead {
							cancelAdmission()
							return admissionCtx.Err()
						}
						if longBatch {
							latency := 8 * time.Second
							if longUse {
								latency = 16 * time.Second
							}
							timer := time.NewTimer(latency)
							defer timer.Stop()
							select {
							case <-timer.C:
							case <-useCtx.Done():
								return useCtx.Err()
							}
							// This is a named capacity-source boundary sample on Windows;
							// the real collector is Linux-only and is not certified here.
							aRefreshControlSourceCapacity(t, f)
						}
						if withdrawSource && os.WriteFile(f.materials.ControlEvidenceSource.ControllerGrantFile, []byte("independent source owner withdrew during original C read"), 0600) != nil {
							return errors.New("owned source fault injection failed")
						}
						return nil
					}}, nil
				}
			}
			// Exercise the production admission entry point before any CE Job
			// row or Generate exists, including its real encrypted identity journal.
			client := o.Client.(*fake.Clientset)
			client.PrependReactor("create", "secrets", func(action ktest.Action) (bool, runtime.Object, error) {
				secret := action.(ktest.CreateAction).GetObject().(*corev1.Secret).DeepCopy()
				secret.UID, secret.ResourceVersion = types.UID(secret.Name+"-uid"), "1"
				if err := client.Tracker().Create(corev1.SchemeGroupVersion.WithResource("secrets"), secret, secret.Namespace); err != nil {
					return true, nil, err
				}
				return true, secret, nil
			})
			_, _, _, prepareErr := o.Admit(admissionCtx, x.input.Authority, part.Intent)
			cancelAdmission()
			o.FormalKeys = originalKeys
			if firstCE && ownedFault {
				id, _ := ce.FinalizedSourceEvidenceID(*seed)
				var seals, jobs int
				if prepareErr == nil || !missingResult && !ownedReadEntered.Load() || f.x.generates.Load() != 1 || h.db.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_evidence WHERE public_id=?`, id).Scan(&seals) != nil || seals != 0 || h.db.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND resource_name=?`, x.input.Authority.TaskPublicID, part.Intent.Name).Scan(&jobs) != nil || jobs != 0 {
					t.Fatal("failed original owned admission left seal/CE Job/Generate", prepareErr)
				}
				var evidenceAfter, resourcesAfter int
				if h.db.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_evidence WHERE owner_target_type='backup' AND owner_target_public_id=?`, x.input.Authority.TaskPublicID).Scan(&evidenceAfter) != nil || h.db.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE task_public_id=?`, x.input.Authority.TaskPublicID).Scan(&resourcesAfter) != nil || evidenceAfter != evidenceBefore || resourcesAfter != resourcesBefore {
					t.Fatal("failed admission left partial owner report/identity registration")
				}
				return
			}
			if malformed && index == 1 {
				id, _ := ce.FinalizedSourceEvidenceID(*seed)
				var seals, jobs int
				if prepareErr == nil || f.x.generates.Load() != 1 || h.db.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_evidence WHERE public_id=?`, id).Scan(&seals) != nil || seals != 0 || h.db.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND resource_name=?`, x.input.Authority.TaskPublicID, part.Intent.Name).Scan(&jobs) != nil || jobs != 0 {
					t.Fatal("unsafe original business payload produced seal or early CE dispatch", prepareErr)
				}
				return
			}
			if prepareErr != nil {
				t.Fatal("actual pre-dispatch owned reader/source seal", prepareErr)
			}
			if firstCE && longBatch {
				var revision uint64
				var until time.Time
				if time.Since(phaseStarted) <= 30*time.Second || h.db.QueryRow(`SELECT row_version,controller_lease_expires_at FROM system_backup_v2_backups WHERE public_id=?`, x.input.Authority.TaskPublicID).Scan(&revision, &until) != nil || revision != x.input.Authority.ClaimRowVersion || !until.After(time.Now()) {
					t.Fatal("long original batch did not preserve live same-epoch heartbeat authority")
				}
				t.Logf("actual Admit batch=%s, original heartbeat kept row version=%d", time.Since(phaseStarted), revision)
			}
		}
		intent, err := kube.Intent("Job", &object)
		if err != nil {
			t.Fatal(err)
		}
		j := d.JobBinding{JobUnitKey: part.Intent.JobUnitKey, Namespace: part.Intent.Namespace, Name: part.Intent.Name, UID: "22222222-2222-4222-8222-22222222222" + strconv.Itoa(index), Generation: part.Intent.Generation, RelayBoundAt: time.Now().UTC().Truncate(time.Microsecond), RelayExpiresAt: inv.Request.Deadline, RelayIdentityRef: "original-control-identity-" + strconv.Itoa(index), RelayIdentityVersion: "v1"}
		currentJob = j.UID
		fixedRemaining := func() time.Duration {
			var raw []byte
			var use worker.KeyUseLease
			if h.db.QueryRow(`SELECT key_use_json FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND observed_uid=?`, x.input.Authority.TaskPublicID, j.UID).Scan(&raw) != nil || json.Unmarshal(raw, &use) != nil {
				t.Fatal("original fixed key-use deadline unavailable")
			}
			return time.Until(use.Until)
		}
		bindingRaw, _ := json.Marshal(j)
		if _, err = h.admin.Exec(`INSERT INTO system_backup_v2_runtime_resources(task_public_id,resource_kind,namespace_name,resource_name,resource_owner,request_sha256,request_json,row_version,create_dispatched,observed_uid,resource_version,lifecycle,attempt_no,phase,binding_json) VALUES(?,'Job',?,?,?,?,?,1,TRUE,?,'1','ready',?,'capture',?)`, x.input.Authority.TaskPublicID, j.Namespace, j.Name, x.input.Authority.TaskPublicID, intent.RequestSHA256, intent.RequestJSON, j.UID, x.input.Authority.AttemptNo, bindingRaw); err != nil {
			t.Fatal("actual original Job row", err)
		}
		if index == 0 {
			// Original 123 permits ONLY target_type='backup'. Prove that a
			// wrong-target row cannot be installed without changing the original
			// DDL/FK; the final read independently includes that same predicate.
			if _, wrongTargetErr := h.admin.Exec(`UPDATE system_backup_v2_runtime_resources SET target_type='drill' WHERE task_public_id=? AND observed_uid=?`, x.input.Authority.TaskPublicID, j.UID); wrongTargetErr == nil {
				t.Fatal("original DDL admitted a wrong-target Job")
			}
		}
		materialRaw, _ := os.ReadFile(x.materialFile)
		sourceRaw, _ := os.ReadFile(f.materials.ControlEvidenceSource.GrantFile)
		mapped := map[string]map[string]string{}
		for _, v := range object.Spec.Template.Spec.Volumes {
			if v.ConfigMap != nil {
				switch v.Name {
				case "formal-mapping":
					mapped[v.ConfigMap.Name] = map[string]string{"materials.json": string(materialRaw)}
				case "formal-control-source":
					mapped[v.ConfigMap.Name] = map[string]string{"grant.json": string(sourceRaw)}
				}
			}
		}
		installOriginalWorkerAPIFixture(t, o, h.admin, x.input.Authority, j, inv, mapped)
		caps, err := a.NewSQLProviderCapabilityPreparation(h.db, s.formalVerifier.Database, x.input.Authority.InstallationID, s.formalVerifier.GenerateCapability, s.formalVerifier.UnwrapCapability)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.attachProviderPermits(o, caps); err != nil {
			t.Fatal("actual original Generate issuer attach", err)
		}
		if err = s.attachFormalVerifier(o); err != nil {
			t.Fatal("actual original controller Unwrap attach", err)
		}
		s.Runtime = &PublicCapture{Owner: o, Control: WorkloadIdentity{Client: o.Client, Namespace: o.Namespace, ServiceAccount: o.Security.ServiceAccountName, ServiceAccountUID: o.Security.ServiceAccountUID, Next: worker.ControlHandler{Authorizer: o}}}
		client := makeClient(o, x.input.Authority, inv, s.Config.ControlURL)
		f.x.controlGenerateRequest = &inv.ProviderKey.Request
		aRefreshControlSourceCapacity(t, f)
		readyStarted := time.Now()
		if err = client.Ready(ctx, inv); err != nil {
			if malformed && index == 1 {
				if !errors.Is(err, worker.ErrNotReady) || f.x.generates.Load() != 1 {
					t.Fatal("invalid business C reached CE Generate", err)
				}
				id, idErr := ce.FinalizedSourceEvidenceID(*inv.Request.ControlEvidence)
				var count int
				if idErr != nil || h.db.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_evidence WHERE public_id=?`, id).Scan(&count) != nil || count != 0 {
					t.Fatal("invalid actual domain produced final owner seal")
				}
				return
			}
			t.Fatal("actual original CE Ready", err)
		}
		if malformed && index == 1 {
			t.Fatal("valid AEAD unsafe business archive passed original owned reader")
		}
		t.Logf("part=%d Ready RPC=%s", index, time.Since(readyStarted))
		job, err := worker.NewDeliveredCaptureKeyJob(ctx, client, inv, x.config, x.pin)
		if err != nil {
			t.Fatal("actual original CE reserve", err)
		}
		t.Logf("part=%d reserved=%s fixed_remaining=%s", index, time.Since(phaseStarted), fixedRemaining())
		var sources *worker.ControlEvidenceCaptureSources
		environment := worker.FormalCaptureEnvironment{Staging: taskStage}
		if inv.Request.ControlEvidence != nil {
			sources, err = worker.OpenControlEvidenceCaptureSources(ctx, inv, job, f.materials.ControlEvidenceSource)
			if err != nil {
				job.Close()
				t.Fatal("actual original CE source open", err)
			}
			environment.ControlEvidence = sources
			environment.SourceAuthorize = sources.Authorize
			environment.SourceValidUntil = sources.ValidUntil()
		} else {
			root, openErr := os.OpenRoot(t.TempDir())
			if openErr != nil {
				t.Fatal(openErr)
			}
			defer root.Close()
			if root.WriteFile("history.json", []byte(`{"history":"named owned portable workspace"}`), 0600) != nil {
				t.Fatal("owned business workspace fixture")
			}
			environment.Workspace = root
		}
		result, err := worker.RunFormalCapture(ctx, inv, job, environment)
		if fault {
			sources.Close()
			job.Close()
			if !replaced.Load() || err == nil || f.x.generates.Load() != 1 {
				t.Fatal("final SQL source revocation was not rejected after one original Generate", err)
			}
			dir, readErr := taskStage.Open(".")
			if readErr != nil {
				t.Fatal(readErr)
			}
			entries, readErr := dir.ReadDir(-1)
			dir.Close()
			if readErr != nil || len(entries) != 0 {
				t.Fatal("rejected source retained an output candidate")
			}
			var candidate []byte
			if h.db.QueryRow(`SELECT candidate_cipher FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND observed_uid=?`, x.input.Authority.TaskPublicID, j.UID).Scan(&candidate) != nil || len(candidate) != 0 {
				t.Fatal("rejected source journaled a candidate")
			}
			return
		}
		if err != nil {
			sources.Close()
			job.Close()
			t.Fatal("actual original CE Generate/pull/C stream", err)
		}
		if malformed && index == 0 {
			result = forgeOwnedBusinessArchive(t, taskStage, inv, result)
		}
		t.Logf("part=%d C-written=%s fixed_remaining=%s", index, time.Since(phaseStarted), fixedRemaining())
		if index == 0 {
			aRefreshControlSourceCapacity(t, f)
			raw, _ := os.ReadFile(s.Config.CapacityFile)
			var stale security.CapacityReport
			if json.Unmarshal(raw, &stale) != nil {
				t.Fatal("owned capacity sample")
			}
			stale.ObservedAt = stale.ObservedAt.Add(-6 * time.Second)
			raw, _ = json.Marshal(stale)
			if os.WriteFile(s.Config.CapacityFile, raw, 0600) != nil {
				t.Fatal("owned stale capacity sample")
			}
			retryCtx, cancel := context.WithTimeout(ctx, time.Second)
			err = job.ReportCandidate(retryCtx, inv, result)
			cancel()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("stale capacity was accepted", err)
			}
			var count int
			if h.db.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND observed_uid=? AND candidate_cipher IS NOT NULL`, x.input.Authority.TaskPublicID, j.UID).Scan(&count) != nil || count != 0 || f.x.generates.Load() != 1 {
				t.Fatal("stale capacity admitted or regenerated candidate")
			}
		}
		// Capacity is an independently sampled source with its own five-second
		// freshness rule; this cannot extend the original claim/key-use window.
		aRefreshControlSourceCapacity(t, f)
		if err = job.ReportCandidate(ctx, inv, result); err != nil {
			sources.Close()
			job.Close()
			t.Fatal("actual original CE candidate ACK", err)
		}
		t.Logf("part=%d candidate-ACK=%s fixed_remaining=%s", index, time.Since(phaseStarted), fixedRemaining())
		sources.Close()
		job.Close()
		aRefreshControlSourceCapacity(t, f)
		ref, err := o.Evidence(ctx, x.input.Authority, j)
		if malformed && index == 0 && err != nil {
			var seedInv worker.Invocation
			if json.Unmarshal(x.parts[0].InvocationJSON, &seedInv) != nil {
				t.Fatal("missing frozen finalization seed")
			}
			id, _ := ce.FinalizedSourceEvidenceID(*seedInv.Request.ControlEvidence)
			var seals, ceJobs int
			if f.x.generates.Load() != 1 || h.db.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_evidence WHERE public_id=?`, id).Scan(&seals) != nil || seals != 0 || h.db.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND resource_name<>?`, x.input.Authority.TaskPublicID, j.Name).Scan(&ceJobs) != nil || ceJobs != 0 {
				t.Fatal("rejected original business reader left CE effects")
			}
			return
		}
		if err != nil || ref == nil {
			t.Fatal("actual original CE independent Unwrap/Evidence consumer", err)
		}
		t.Logf("part=%d original-consumer=%s", index, time.Since(phaseStarted))
		frames, _ := taskStage.ReadFile(result.Ciphertext.Name)
		envelope, _ := taskStage.ReadFile(result.Envelope.Name)
		var decoded bytes.Buffer
		spec := w.StreamSpec{Request: inv.ProviderKey.Request, Path: inv.Request.ArtifactName, MaxPlaintextBytes: inv.Request.MaxCompressedBytes, MaxFrames: inv.FormalCapture.MaxFrames}
		// Named fixture DEK is only the independent C format reader. Actual
		// original Generate permission/state and mTLS source delivery ran above.
		keys := &candidateContentUnwrapper{expected: inv.ProviderKey.Request, key: bytes.Repeat([]byte{9}, 32)}
		if _, err = w.InspectWrappedStream(ctx, spec, envelope, bytes.NewReader(frames), keys, func(r io.Reader) error { _, err := io.Copy(&decoded, r); return err }); err != nil {
			t.Fatal("complete independent C readback", err)
		}
		plain[part.Part] = bytes.Clone(decoded.Bytes())
	}
	if f.x.generates.Load() != int64(expectedResults) {
		t.Fatal("pair did not consume two distinct original Generate uses")
	}
	var results int
	if f.x.decrypts.Load() != expectedDecrypts || h.db.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='Job' AND result_sha256 IS NOT NULL`, x.input.Authority.TaskPublicID).Scan(&results) != nil || results != expectedResults {
		t.Fatal("pair omitted original independent Unwrap/result registration")
	}
	verified, err := ce.Verify(ctx, plain[ce.Part], plain[ce.ProofPart], f.expected)
	if err != nil || verified.Groups["event"].Count < 121 {
		t.Fatal("complete actual service pair readback", err)
	}
	if business {
		for _, owner := range []string{"A", "B", "C", "D"} {
			if verified.Owners[owner].Status != "complete" {
				t.Fatal("actual owned reader/registration was skipped", owner)
			}
		}
		var seed ce.CaptureLocator
		var invocation worker.Invocation
		if json.Unmarshal(x.parts[0].InvocationJSON, &invocation) != nil || invocation.Request.ControlEvidence == nil {
			t.Fatal("original v2 source seed")
		}
		seed = *invocation.Request.ControlEvidence
		prepared, verifyErr := ce.VerifyFinalizedBytes(ctx, seed, plain[ce.Part], plain[ce.ProofPart])
		clear(prepared.SidecarJSON)
		clear(prepared.ProofsJSON)
		if verifyErr != nil {
			t.Fatal("self-contained final owned proof readback", verifyErr)
		}
	}
}

// Explicit malicious-worker fixture: one actual original Generate completed,
// then unpublished bytes are replaced by a valid C stream/envelope containing
// an unsafe tar path. Crypto-only observation is insufficient for owner B.
func forgeOwnedBusinessArchive(t *testing.T, stage *os.Root, inv worker.Invocation, result worker.FormalCaptureResult) worker.FormalCaptureResult {
	t.Helper()
	spec := w.StreamSpec{Request: inv.ProviderKey.Request, Path: inv.Request.ArtifactName, MaxPlaintextBytes: inv.Request.MaxCompressedBytes, MaxFrames: inv.FormalCapture.MaxFrames}
	var ciphertext bytes.Buffer
	seal, err := w.EncryptStream(context.Background(), spec, bytes.Repeat([]byte{9}, 32), &ciphertext, func(dst io.Writer) error {
		return staging.Compress(dst, func(z io.Writer) error {
			tw := tar.NewWriter(z)
			if err := tw.WriteHeader(&tar.Header{Name: "../../outside", Typeflag: tar.TypeReg, Mode: 0600, Size: 3}); err != nil {
				return err
			}
			if _, err := tw.Write([]byte("bad")); err != nil {
				return err
			}
			return tw.Close()
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := seal.EnvelopeJSON(w.WrappedKey{Request: spec.Request, Algorithm: "provider-native", Ciphertext: bytes.Repeat([]byte{7}, 60)})
	if err != nil {
		t.Fatal(err)
	}
	// Only the named fixture worker's unpublished files are made mutable for
	// this malicious-worker negative; controller-private custody is untouched.
	if stage.Chmod(result.Ciphertext.Name, 0600) != nil || stage.Chmod(result.Envelope.Name, 0600) != nil {
		t.Fatal("owned forged-worker file mode")
	}
	if stage.WriteFile(result.Ciphertext.Name, ciphertext.Bytes(), 0600) != nil || stage.WriteFile(result.Envelope.Name, envelope, 0600) != nil {
		t.Fatal("owned unpublished forged-worker bytes")
	}
	result.Ciphertext.Size = int64(ciphertext.Len())
	result.Ciphertext.SHA256 = hash(ciphertext.Bytes())
	result.Envelope.Size = int64(len(envelope))
	result.Envelope.SHA256 = hash(envelope)
	result.Files = 1
	result.Bytes = 3
	if !worker.ValidateFormalCaptureResult(inv, &result) {
		t.Fatal("forgery did not preserve original candidate binding")
	}
	return result
}
