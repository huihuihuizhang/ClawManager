package systembackupcontroller

import (
	"bytes"
	"clawreef/internal/services"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/flow"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/quiesce"
	"clawreef/internal/systembackup/staging"
	d "clawreef/internal/systembackupdispatch"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"strconv"
	"time"
)

type RuntimeStopProof interface {
	Confirm(context.Context, []quiesce.PodIdentity) error
}
type RuntimeArmedStopProof interface {
	RuntimeStopProof
	Arm(context.Context, []quiesce.PodIdentity) error
}

// RuntimeControlConfig is deployment-owned. GatewayOriginal is the existing
// service's secret-bearing create request, at the ORIGINAL generation. D seals
// it before returning a writer spec. It must never be populated from HTTP input.
// Each non-runtime registered participant requires its actual drain/health probe.
type RuntimeControlConfig struct {
	Namespace              string // pinned installation namespace; no discovery expansion
	Gate                   SQLCaptureGate
	Keys                   ExecutionRecordKeys
	Client                 kubernetes.Interface
	Agent                  services.BackupGatewayAgent
	StoppedProObserver     *quiesce.StoppedProNodeObservationClient
	StoppedProBaseline     func(context.Context, d.Authority, b.InstanceIdentity) (quiesce.StoppedProBaseline, error)
	StopProof              RuntimeStopProof
	GatewayOriginal        func(context.Context, b.InstanceIdentity) (services.RuntimeAgentCreateGatewayRequest, error)
	GatewayOriginalForTask func(context.Context, d.Authority, b.InstanceIdentity) (services.RuntimeAgentCreateGatewayRequest, error)
	StopProofForTask       func(d.Authority, string) RuntimeArmedStopProof
	AdditionalWriterIDs    []string
	ParticipantChecks      map[string]ReadinessProbe
	// Reconciler/HPA fencing proofs keyed by namespace/deployment name.
	DeploymentChecks map[string]ReadinessProbe
	PollInterval     time.Duration
}
type SQLRuntimeControl struct{ cfg RuntimeControlConfig }

func NewSQLRuntimeControl(c RuntimeControlConfig) (*SQLRuntimeControl, error) {
	if c.Namespace == "" || !c.Gate.ready() || absentExecutionDependency(c.Keys) || absentExecutionDependency(c.Client) || (absentExecutionDependency(c.StopProof) && c.StopProofForTask == nil) || len(c.ParticipantChecks) == 0 || c.PollInterval <= 0 || c.PollInterval > time.Second {
		return nil, d.ErrNotReady
	}
	probes := map[string]ReadinessProbe{}
	for id, p := range c.ParticipantChecks {
		if id == "" || absentExecutionDependency(p) {
			return nil, d.ErrNotReady
		}
		probes[id] = p
	}
	c.ParticipantChecks = probes
	deployments := map[string]ReadinessProbe{}
	for id, p := range c.DeploymentChecks {
		if id == "" || absentExecutionDependency(p) {
			return nil, d.ErrNotReady
		}
		deployments[id] = p
	}
	c.DeploymentChecks = deployments
	c.AdditionalWriterIDs = append([]string(nil), c.AdditionalWriterIDs...)
	return &SQLRuntimeControl{c}, nil
}
func runtimeWriterID(s b.RuntimeWriterSpec) string {
	switch s.Kind {
	case "gateway":
		return fmt.Sprintf("gateway/%s/%d", s.UID, s.Source.ID)
	case "pod", "deployment":
		return s.Kind + "/" + s.Source.Namespace + "/" + s.Name
	case "stopped":
		return "stopped/" + strconv.Itoa(s.Source.ID)
	}
	return ""
}
func sourceRow(ctx context.Context, tx *sql.Tx, id int) (b.InstanceIdentity, error) {
	var s b.InstanceIdentity
	e := tx.QueryRowContext(ctx, `SELECT id,user_id,instance_mode,type,runtime_type,COALESCE(runtime_variant,''),os_type,status,runtime_generation,COALESCE(pod_name,''),COALESCE(pod_namespace,''),COALESCE(workspace_path,'') FROM instances WHERE id=? FOR UPDATE`, id).Scan(&s.ID, &s.UserID, &s.Mode, &s.Type, &s.Backend, &s.Variant, &s.OS, &s.Status, &s.Generation, &s.Pod, &s.Namespace, &s.Workspace)
	return s, e
}

// Prepare reserves a generation in the same original authority transaction as
// source validation and encrypted custody. It never increments the source row
// before recovery, releases a runtime slot, or performs physical stop/start.
func (o *SQLRuntimeControl) Prepare(ctx context.Context, a d.Authority) ([]b.RuntimeWriterSpec, error) {
	if o == nil || o.cfg.Gate.Authority.Check(ctx, a) != nil {
		return nil, ErrExecutionAuthority
	}
	tx, e := o.cfg.Gate.Authority.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return nil, e
	}
	sources, e := domain.ReadSourceInstances(ctx, tx)
	tx.Rollback()
	if e != nil {
		return nil, e
	}
	specs := make([]b.RuntimeWriterSpec, 0, len(sources))
	for _, source := range sources {
		if source.Namespace != "" && source.Namespace != o.cfg.Namespace {
			return nil, ErrExecutionRecord
		}
		spec := b.RuntimeWriterSpec{Source: source, Name: source.Pod, RestartRef: a.TaskPublicID + "/" + strconv.FormatUint(a.AttemptNo, 10) + "/" + strconv.Itoa(source.ID)}
		var material []byte
		switch {
		case source.Status == "stopped":
			if source.Mode != "pro" || o.cfg.StoppedProObserver == nil || o.cfg.StoppedProBaseline == nil {
				return nil, d.ErrNotReady
			}
			baseline, err := o.cfg.StoppedProBaseline(ctx, a, source)
			if err != nil || baseline.InstanceID != uint64(source.ID) || baseline.UserID != uint64(source.UserID) || baseline.InstanceGeneration != uint64(source.Generation) || baseline.SourceKey != fmt.Sprintf("stopped/%d", source.ID) {
				return nil, ErrExecutionRecord
			}
			material, err = json.Marshal(baseline)
			if err != nil {
				return nil, err
			}
			spec.Kind, spec.StoppedProBaseline = "stopped", string(material)
			spec.Stopped = flow.State{UID: baseline.SourceKey, Generation: int64(source.Generation), Checkpoint: quiesce.StoppedProBaselineSHA256(baseline)}
		case source.Status == "running" && source.Mode == "lite":
			if (o.cfg.GatewayOriginal == nil && o.cfg.GatewayOriginalForTask == nil) || absentExecutionDependency(o.cfg.Agent) || source.Generation >= 2147483647 {
				return nil, d.ErrNotReady
			}
			mapped, err := o.ResolveGatewaySource(ctx, source)
			if err != nil {
				return nil, err
			}
			mapped.RestartRef = spec.RestartRef
			spec = mapped
			spec.ResumeGeneration = source.Generation + 1
			var original services.RuntimeAgentCreateGatewayRequest
			if o.cfg.GatewayOriginalForTask != nil {
				original, e = o.cfg.GatewayOriginalForTask(ctx, a, source)
			} else {
				original, e = o.cfg.GatewayOriginal(ctx, source)
			}
			if e != nil || original.InstanceID != source.ID || original.UserID != source.UserID || original.Generation != source.Generation || original.WorkspacePath != source.Workspace || original.GatewayPort != spec.Port || original.UpgradeID != "" || original.PodUID != spec.UID || original.PortRange.Start != spec.Port || original.PortRange.End < spec.Port || original.PortRange.End > 65535 || original.UID <= 0 || original.GID <= 0 {
				return nil, ErrExecutionRecord
			}
			spec.UIDNumber, spec.GIDNumber = original.UID, original.GID
			original.Generation = spec.ResumeGeneration
			restartDigest, digestErr := services.RuntimeBackupRestartDigest(original)
			if digestErr != nil {
				return nil, digestErr
			}
			spec.Backup = b.RuntimeGatewayBackup{Protocol: services.RuntimeBackupProtocol, OperationID: gatewayOperationID(a, runtimeWriterID(spec)), RestartSHA256: restartDigest}
			material, e = json.Marshal(original)
			if e != nil {
				return nil, e
			}
		case source.Status == "running" && source.Mode == "pro":
			pod, e := o.cfg.Client.CoreV1().Pods(source.Namespace).Get(ctx, source.Pod, metav1.GetOptions{})
			if e != nil || pod.UID == "" || pod.DeletionTimestamp != nil {
				return nil, ErrExecutionRecord
			}
			spec.Kind = "pod"
			spec.UID = string(pod.UID)
			if len(pod.OwnerReferences) != 0 {
				dep, e := o.deploymentForPod(ctx, pod)
				if e != nil {
					return nil, e
				}
				probe := o.cfg.DeploymentChecks[source.Namespace+"/"+dep.Name]
				if absentExecutionDependency(probe) || probe.Check(ctx) != nil || dep.Spec.Replicas == nil || *dep.Spec.Replicas != 1 {
					return nil, d.ErrNotReady
				}
				spec.Kind = "deployment"
				spec.Name = dep.Name
				spec.UID = string(dep.UID)
				material, e = json.Marshal(dep)
				if e != nil {
					return nil, e
				}
				break
			}
			original := pod.DeepCopy()
			original.UID = ""
			original.ResourceVersion = ""
			original.CreationTimestamp = metav1.Time{}
			original.ManagedFields = nil
			original.Status = corev1.PodStatus{}
			material, e = json.Marshal(original)
			if e != nil {
				return nil, e
			}
		default:
			return nil, d.ErrNotReady
		}
		if e = o.save(ctx, a, spec, material); e != nil {
			clear(material)
			return nil, e
		}
		clear(material)
		specs = append(specs, spec)
	}
	return specs, nil
}
func (o *SQLRuntimeControl) save(ctx context.Context, a d.Authority, s b.RuntimeWriterSpec, plain []byte) error {
	id := runtimeWriterID(s)
	if id == "" || len(id) > 128 || len(plain) > 7<<20 {
		return ErrExecutionRecord
	}
	ref, key, e := o.cfg.Keys.Resolve(ctx, a, "")
	defer clear(key)
	if e != nil || len(key) != 32 || ref == "" {
		return ErrExecutionAuthority
	}
	digest := recordHash(plain)
	var sealed bytes.Buffer
	if e = staging.Seal(ctx, &sealed, key, recordBinding(a, "runtime/"+id, digest), func(w io.Writer) error { _, e := w.Write(plain); return e }); e != nil {
		return e
	}
	raw, _ := json.Marshal(s)
	tx, e := o.cfg.Gate.Authority.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return e
	}
	defer tx.Rollback()
	guard, e := o.cfg.Gate.Authority.Bind(ctx, tx, a)
	if e != nil {
		return e
	}
	current, e := sourceRow(ctx, tx, s.Source.ID)
	if e != nil || current != s.Source {
		return ErrExecutionRecord
	}
	if s.Kind == "gateway" {
		if e = o.gatewayBinding(ctx, tx, s, false); e != nil {
			return e
		}
	}
	var old []byte
	var oldHash string
	e = tx.QueryRowContext(ctx, `SELECT spec_json,material_sha256 FROM system_backup_v2_runtime_controls WHERE task_public_id=? AND attempt_no=? AND writer_id=? FOR UPDATE`, a.TaskPublicID, a.AttemptNo, id).Scan(&old, &oldHash)
	if e == nil {
		if !bytes.Equal(old, raw) || oldHash != digest {
			return ErrExecutionRecord
		}
	} else if errors.Is(e, sql.ErrNoRows) {
		// An untouched terminal preparation owns no physical writer. Retire its
		// reservation under the new task's locked authority before reusing it.
		_, e = tx.ExecContext(ctx, `UPDATE system_backup_v2_runtime_controls c JOIN system_backup_v2_backups b ON b.public_id=c.task_public_id SET c.restart_completed=TRUE,c.resumed_json='{"unstarted":true}',c.row_version=c.row_version+1 WHERE c.instance_id=? AND c.restart_claimed=FALSE AND c.restart_completed=FALSE AND b.origin_installation_id=? AND b.status IN ('failed','canceled') AND NOT EXISTS(SELECT 1 FROM system_backup_v2_runtime_writers w WHERE w.task_public_id=c.task_public_id) AND NOT EXISTS(SELECT 1 FROM system_backup_v2_runtime_captures g WHERE g.task_public_id=c.task_public_id)`, s.Source.ID, a.InstallationID)
		if e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO system_backup_v2_runtime_controls (task_public_id,attempt_no,writer_id,instance_id,spec_json,material_sha256,key_ref,sealed_material) VALUES (?,?,?,?,?,?,?,?)`, a.TaskPublicID, a.AttemptNo, id, s.Source.ID, raw, digest, ref, sealed.Bytes())
		if e != nil {
			return e
		}
	} else {
		return e
	}
	if e = guard.Recheck(ctx, tx); e != nil {
		return e
	}
	if tx.Commit() != nil {
		return ErrExecutionCommitUnknown
	}
	return nil
}
func (o *SQLRuntimeControl) gatewayBinding(ctx context.Context, tx *sql.Tx, s b.RuntimeWriterSpec, resumed bool) error {
	if s.Runtime.Version != "" {
		r, e := readGatewayBinding(ctx, tx, s.Source.ID, true)
		want := s.Source
		if resumed {
			want.Generation = s.ResumeGeneration
		}
		if e != nil || s.Runtime.Version != "runtime-locator.v2" || !bindingMatchesSource(r, want, o.cfg.Namespace) || r.ID != s.Runtime.RuntimePodID || r.UID != s.Runtime.RegisteredPodUID || r.Namespace != s.Runtime.Namespace || r.Pod != s.Runtime.Pod || r.Deployment != s.Runtime.Deployment || r.Endpoint != s.Endpoint || r.Port != s.Port || (!resumed && r.PID != s.Runtime.GatewayPID) {
			return ErrExecutionRecord
		}
		return o.checkGatewayPod(ctx, s)
	}
	var uid, endpoint, workspace, state, gateway string
	var generation, port int
	if tx.QueryRowContext(ctx, `SELECT p.pod_uid,p.agent_endpoint,b.workspace_path,b.generation,b.gateway_port,b.state,b.gateway_id FROM instance_runtime_bindings b JOIN runtime_pods p ON p.id=b.runtime_pod_id WHERE b.instance_id=? AND p.namespace=? AND p.pod_name=? AND p.state='ready' AND p.draining=FALSE FOR UPDATE`, s.Source.ID, s.Source.Namespace, s.Source.Pod).Scan(&uid, &endpoint, &workspace, &generation, &port, &state, &gateway) != nil {
		return ErrExecutionRecord
	}
	want := s.Source.Generation
	if resumed {
		want = s.ResumeGeneration
	}
	if uid != s.UID || endpoint != s.Endpoint || workspace != s.Source.Workspace || generation != want || port != s.Port || state != "running" || gateway != fmt.Sprintf("gw-%d-%d", s.Source.ID, want) {
		return ErrExecutionRecord
	}
	return nil
}

type runtimeControlRow struct {
	Spec               b.RuntimeWriterSpec
	Digest, Key        string
	Sealed             []byte
	Claimed, Completed bool
	Resumed            []byte
	Stopped            sql.NullString
	Version            uint64
}

func readRuntimeControl(ctx context.Context, tx *sql.Tx, a d.Authority, id string) (runtimeControlRow, error) {
	var r runtimeControlRow
	var raw []byte
	e := tx.QueryRowContext(ctx, `SELECT spec_json,material_sha256,key_ref,sealed_material,restart_claimed,restart_completed,resumed_json,stopped_sha256,row_version FROM system_backup_v2_runtime_controls WHERE task_public_id=? AND attempt_no=? AND writer_id=? FOR UPDATE`, a.TaskPublicID, a.AttemptNo, id).Scan(&raw, &r.Digest, &r.Key, &r.Sealed, &r.Claimed, &r.Completed, &r.Resumed, &r.Stopped, &r.Version)
	if e != nil {
		return r, e
	}
	if json.Unmarshal(raw, &r.Spec) != nil || runtimeWriterID(r.Spec) != id || !executionHash.MatchString(r.Digest) || len(r.Sealed) > 8<<20 {
		return r, ErrExecutionRecord
	}
	return r, nil
}
func runtimeRecoveryPoint(point string) (bool, error) {
	switch point {
	case "observe", "observed", "before-stop", "check-stopped":
		return false, nil
	case "before-resume", "recovery-check-stopped", "recovery-stop-old", "before-restart-dispatch", "restart-dispatched", "check-resumed", "commit-resumed", "claim-restart", "complete-restart", "release-restart":
		return true, nil
	}
	return false, ErrExecutionAuthority
}
func (o *SQLRuntimeControl) transaction(ctx context.Context, a d.Authority, recovery bool, fn func(*sql.Tx) error) error {
	if o == nil || ctx == nil || ctx.Err() != nil {
		return ErrExecutionAuthority
	}
	tx, e := o.cfg.Gate.Authority.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var recheck func() error
	if recovery {
		if e = o.cfg.Gate.Recovery.CheckTx(ctx, tx, a); e != nil {
			return e
		}
		recheck = func() error { return o.cfg.Gate.Recovery.CheckTx(ctx, tx, a) }
	} else {
		g, e := o.cfg.Gate.Authority.Bind(ctx, tx, a)
		if e != nil {
			return e
		}
		recheck = func() error { return g.Recheck(ctx, tx) }
	}
	if e = fn(tx); e != nil {
		return e
	}
	if e = recheck(); e != nil {
		return e
	}
	if tx.Commit() != nil {
		return ErrExecutionCommitUnknown
	}
	return nil
}
func originalRuntimeState(ctx context.Context, tx *sql.Tx, a d.Authority, id string, s flow.State) error {
	var raw []byte
	var digest string
	if tx.QueryRowContext(ctx, `SELECT original_json,original_sha256 FROM system_backup_v2_runtime_writers WHERE task_public_id=? AND writer_id=? FOR UPDATE`, a.TaskPublicID, id).Scan(&raw, &digest) != nil {
		return ErrExecutionRecord
	}
	var original flow.State
	if json.Unmarshal(raw, &original) != nil || original != s || recordHash(raw) != digest {
		return ErrExecutionRecord
	}
	return nil
}
func (o *SQLRuntimeControl) Guard(ctx context.Context, a d.Authority, id, point string, s flow.State) error {
	recovery, e := runtimeRecoveryPoint(point)
	if e != nil {
		return e
	}
	if o.cfg.StopProofForTask != nil && (point == "before-stop" || point == "before-resume") {
		var namespace string
		var pods []quiesce.PodIdentity
		e = o.transaction(ctx, a, recovery, func(tx *sql.Tx) error {
			if _, participant := o.cfg.ParticipantChecks[id]; participant {
				return nil
			}
			r, e := readRuntimeControl(ctx, tx, a, id)
			if e != nil {
				return e
			}
			if r.Spec.Kind != "pod" && r.Spec.Kind != "deployment" {
				return nil
			}
			if e = originalRuntimeState(ctx, tx, a, id, s); e != nil {
				return e
			}
			var cp struct {
				Namespace string
				Process   quiesce.PodIdentity
				Pods      []quiesce.PodIdentity
			}
			if json.Unmarshal([]byte(s.Checkpoint), &cp) != nil || cp.Namespace != r.Spec.Source.Namespace {
				return ErrExecutionRecord
			}
			namespace = cp.Namespace
			pods = cp.Pods
			if cp.Process.UID != "" {
				pods = []quiesce.PodIdentity{cp.Process}
			}
			return nil
		})
		if e != nil {
			return e
		}
		if namespace != "" {
			proof := o.cfg.StopProofForTask(a, namespace)
			if absentExecutionDependency(proof) {
				return ErrExecutionRecord
			}
			if e = proof.Arm(ctx, pods); e != nil {
				return e
			}
		}
	}
	if probe, ok := o.cfg.ParticipantChecks[id]; ok {
		if point != "observe" && point != "observed" {
			if e = probe.Check(ctx); e != nil {
				return e
			}
		}
		return o.transaction(ctx, a, recovery, func(tx *sql.Tx) error {
			var n int
			if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_participants WHERE scope=? AND participant_id=?`, o.cfg.Gate.Authority.ApplicationScope, id).Scan(&n) != nil || n != 1 {
				return ErrExecutionRecord
			}
			if point == "before-stop" || point == "check-stopped" {
				if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_mutation_leases WHERE scope=? AND released_at IS NULL`, o.cfg.Gate.Authority.ApplicationScope).Scan(&n) != nil || n != 0 {
					return ErrExecutionRecord
				}
			}
			if recovery {
				return originalRuntimeState(ctx, tx, a, id, s)
			}
			return nil
		})
	}
	return o.transaction(ctx, a, recovery, func(tx *sql.Tx) error {
		r, e := readRuntimeControl(ctx, tx, a, id)
		if e != nil {
			return e
		}
		current, e := sourceRow(ctx, tx, r.Spec.Source.ID)
		if e != nil {
			return e
		}
		want := r.Spec.Source
		if r.Completed && r.Spec.Kind == "gateway" {
			want.Generation = r.Spec.ResumeGeneration
		}
		if r.Completed && r.Spec.Kind == "deployment" {
			var ob deploymentResume
			if json.Unmarshal(r.Resumed, &ob) != nil {
				return ErrExecutionRecord
			}
			want.Pod = ob.PodName
		}
		if current != want {
			return ErrExecutionRecord
		}
		if r.Spec.Kind == "gateway" {
			if e = o.gatewayBinding(ctx, tx, r.Spec, r.Completed); e != nil {
				return e
			}
			if e := o.checkGatewayPod(ctx, r.Spec); e != nil {
				return e
			}
		}
		if r.Spec.Kind == "deployment" {
			probe := o.cfg.DeploymentChecks[r.Spec.Source.Namespace+"/"+r.Spec.Name]
			if absentExecutionDependency(probe) || probe.Check(ctx) != nil {
				return ErrExecutionRecord
			}
		}
		if !runtimeStateMatches(r.Spec, s, point) {
			return ErrExecutionRecord
		}
		if recovery {
			if e = originalRuntimeState(ctx, tx, a, id, s); e != nil {
				return e
			}
		}
		if point == "restart-dispatched" && !r.Claimed {
			return ErrExecutionRecord
		}
		// Originally stopped completion is written ONLY by the concrete P7
		// recovered-stopped consumer after an authenticated native observation.
		return nil
	})
}
func (o *SQLRuntimeControl) load(ctx context.Context, a d.Authority, id, ref string) ([]byte, error) {
	var row runtimeControlRow
	read := func(tx *sql.Tx) error {
		var e error
		row, e = readRuntimeControl(ctx, tx, a, id)
		if e == nil && row.Spec.RestartRef != ref {
			return ErrExecutionRecord
		}
		return e
	}
	// Both paths require a real grant. A failed forward grant never creates
	// recovery permission; the independent recovery checker must authorize it.
	e := o.transaction(ctx, a, false, read)
	if e != nil {
		e = o.transaction(ctx, a, true, read)
	}
	if e != nil {
		return nil, e
	}
	actual, key, e := o.cfg.Keys.Resolve(ctx, a, row.Key)
	defer clear(key)
	if e != nil || actual != row.Key || len(key) != 32 {
		return nil, ErrExecutionAuthority
	}
	var plain bytes.Buffer
	defer func() { clear(plain.Bytes()) }()
	if staging.Open(ctx, bytes.NewReader(row.Sealed), &plain, key, recordBinding(a, "runtime/"+id, row.Digest), 7<<20) != nil || recordHash(plain.Bytes()) != row.Digest {
		return nil, ErrExecutionRecord
	}
	original := row
	e = o.transaction(ctx, a, false, read)
	if e != nil {
		e = o.transaction(ctx, a, true, read)
	}
	if e != nil {
		return nil, e
	}
	if row.Spec != original.Spec || row.Digest != original.Digest || row.Key != original.Key || !bytes.Equal(row.Sealed, original.Sealed) {
		return nil, ErrExecutionRecord
	}
	return bytes.Clone(plain.Bytes()), nil
}
func (o *SQLRuntimeControl) ClaimRestart(ctx context.Context, a d.Authority, id string, s flow.State) (bool, error) {
	claimed := false
	e := o.transaction(ctx, a, true, func(tx *sql.Tx) error {
		if e := originalRuntimeState(ctx, tx, a, id, s); e != nil {
			return e
		}
		r, e := readRuntimeControl(ctx, tx, a, id)
		if e != nil {
			return e
		}
		if r.Claimed || r.Completed {
			return nil
		}
		if r.Spec.Kind != "pod" && r.Spec.Kind != "gateway" {
			return ErrExecutionRecord
		}
		current, e := sourceRow(ctx, tx, r.Spec.Source.ID)
		if e != nil || current != r.Spec.Source {
			return ErrExecutionRecord
		}
		if r.Spec.Kind == "gateway" {
			if e = o.gatewayBinding(ctx, tx, r.Spec, false); e != nil {
				return e
			}
			req, err := gatewayBackupRequest(a, r.Spec)
			if err != nil {
				return err
			}
			proof, err := readGatewayProof(ctx, tx, a, id, req, "stopped")
			if err != nil || !r.Stopped.Valid || recordHash(proof.Raw) != r.Stopped.String {
				return ErrExecutionRecoveryRequired
			}
			agent, ok := o.cfg.Agent.(services.RuntimeAgentBackupClient)
			if !ok {
				return ErrExecutionRecoveryRequired
			}
			live, err := agent.BackupControl(ctx, r.Spec.Endpoint, "state", req, nil)
			if err != nil || live.Pending || live.Receipt.State != "stopped" || !bytes.Equal(live.Raw, proof.Raw) {
				return ErrExecutionRecoveryRequired
			}
		}
		var stopped sql.NullTime
		if tx.QueryRowContext(ctx, `SELECT collectors_stopped_at FROM system_backup_v2_runtime_captures WHERE task_public_id=? FOR UPDATE`, a.TaskPublicID).Scan(&stopped) != nil || !stopped.Valid {
			return ErrExecutionRecoveryRequired
		}
		if r.Spec.Kind == "pod" && !r.Stopped.Valid {
			return ErrExecutionRecoveryRequired
		}
		result, e := tx.ExecContext(ctx, `UPDATE system_backup_v2_runtime_controls SET restart_claimed=TRUE,row_version=row_version+1 WHERE task_public_id=? AND attempt_no=? AND writer_id=? AND row_version=? AND restart_claimed=FALSE AND restart_completed=FALSE`, a.TaskPublicID, a.AttemptNo, id, r.Version)
		if e != nil {
			return e
		}
		ok, e := exactlyOneRow(result)
		if e != nil || !ok {
			return ErrExecutionRecord
		}
		claimed = true
		return nil
	})
	if e != nil {
		return false, e
	}
	return claimed, nil
}
func (o *SQLRuntimeControl) ConfirmStopped(ctx context.Context, a d.Authority, id string, s flow.State, pods []quiesce.PodIdentity) error {
	// Bind the complete process set to B's already-journaled checkpoint, not a
	// caller-selected subset. API absence alone cannot produce a stop proof.
	var cp struct {
		Process quiesce.PodIdentity
		Pods    []quiesce.PodIdentity
	}
	if json.Unmarshal([]byte(s.Checkpoint), &cp) != nil {
		return ErrExecutionRecord
	}
	expected := cp.Pods
	if cp.Process.UID != "" {
		expected = []quiesce.PodIdentity{cp.Process}
	}
	raw, _ := json.Marshal(pods)
	want, _ := json.Marshal(expected)
	if len(pods) == 0 || !bytes.Equal(raw, want) {
		return ErrExecutionRecord
	}
	proof := o.cfg.StopProof
	if o.cfg.StopProofForTask != nil {
		var cp struct{ Namespace string }
		if json.Unmarshal([]byte(s.Checkpoint), &cp) != nil || cp.Namespace == "" {
			return ErrExecutionRecord
		}
		proof = o.cfg.StopProofForTask(a, cp.Namespace)
	}
	if absentExecutionDependency(proof) {
		return ErrExecutionRecord
	}
	if e := proof.Confirm(ctx, pods); e != nil {
		return quiesce.ErrStopProofPending
	}
	write := func(tx *sql.Tx) error {
		if e := originalRuntimeState(ctx, tx, a, id, s); e != nil {
			return e
		}
		r, e := readRuntimeControl(ctx, tx, a, id)
		if e != nil {
			return e
		}
		digest := recordHash(raw)
		if r.Stopped.Valid && r.Stopped.String != digest {
			return ErrExecutionRecord
		}
		result, e := tx.ExecContext(ctx, `UPDATE system_backup_v2_runtime_controls SET stopped_sha256=?,row_version=row_version+1 WHERE task_public_id=? AND attempt_no=? AND writer_id=? AND row_version=?`, digest, a.TaskPublicID, a.AttemptNo, id, r.Version)
		if e != nil {
			return e
		}
		ok, e := exactlyOneRow(result)
		if e != nil || !ok {
			return ErrExecutionRecord
		}
		return nil
	}
	if e := o.transaction(ctx, a, false, write); e == nil {
		return nil
	}
	return o.transaction(ctx, a, true, write)
}
func (o *SQLRuntimeControl) ConfirmResumed(ctx context.Context, a d.Authority, id string, s flow.State) error {
	return o.transaction(ctx, a, true, func(tx *sql.Tx) error {
		if e := originalRuntimeState(ctx, tx, a, id, s); e != nil {
			return e
		}
		r, e := readRuntimeControl(ctx, tx, a, id)
		if e != nil {
			return e
		}
		if r.Spec.Kind == "deployment" {
			return o.confirmDeployment(ctx, tx, a, id, r)
		}
		// B verifies live readiness/spec; D requires original UID or a durable
		// claimed dispatch. A copied annotation alone cannot acquire ownership.
		if r.Spec.Kind != "pod" {
			return ErrExecutionRecord
		}
		pod, e := o.cfg.Client.CoreV1().Pods(r.Spec.Source.Namespace).Get(ctx, r.Spec.Name, metav1.GetOptions{})
		if e != nil || pod.UID == "" || pod.DeletionTimestamp != nil {
			return ErrExecutionRecord
		}
		if string(pod.UID) != r.Spec.UID && !r.Claimed {
			return ErrExecutionRecord
		}
		return nil
	})
}
func (o *SQLRuntimeControl) CompleteRestart(ctx context.Context, a d.Authority, id string, s flow.State, ob b.RestartObservation) error {
	return o.transaction(ctx, a, true, func(tx *sql.Tx) error {
		if e := originalRuntimeState(ctx, tx, a, id, s); e != nil {
			return e
		}
		r, e := readRuntimeControl(ctx, tx, a, id)
		if e != nil {
			return e
		}
		spec := r.Spec
		var gatewayResume services.RuntimeBackupObservation
		if spec.Kind == "gateway" {
			req, err := gatewayBackupRequest(a, spec)
			if err != nil || !r.Claimed {
				return ErrExecutionRecoveryRequired
			}
			gatewayResume, err = readGatewayProof(ctx, tx, a, id, req, "resumed")
			if err != nil {
				return err
			}
			agent, ok := o.cfg.Agent.(services.RuntimeAgentBackupClient)
			if !ok {
				return ErrExecutionRecoveryRequired
			}
			live, err := agent.BackupControl(ctx, spec.Endpoint, "state", req, nil)
			if err != nil || live.Pending || !bytes.Equal(live.Raw, gatewayResume.Raw) {
				return ErrExecutionRecoveryRequired
			}
		}
		raw, _ := json.Marshal(ob)
		if r.Completed {
			if !bytes.Equal(r.Resumed, raw) {
				return ErrExecutionRecord
			}
			want := spec.Source
			if spec.Kind == "gateway" {
				want.Generation = spec.ResumeGeneration
			}
			current, e := sourceRow(ctx, tx, spec.Source.ID)
			if e != nil || current != want {
				return ErrExecutionRecord
			}
			if spec.Kind == "gateway" {
				if e = o.gatewayBinding(ctx, tx, spec, true); e != nil {
					return e
				}
				live, e := o.cfg.Agent.GatewayState(ctx, spec.Endpoint, ob.GatewayID)
				if e != nil || live == nil || live.GatewayID != ob.GatewayID || live.InstanceID != spec.Source.ID || live.Generation != spec.ResumeGeneration || live.State != "running" || live.UserID != spec.Source.UserID || live.Port != spec.Port || live.PID != gatewayResume.Receipt.PID {
					return ErrExecutionRecord
				}
				binding, e := readGatewayBinding(ctx, tx, spec.Source.ID, true)
				if e != nil || binding.PID != gatewayResume.Receipt.PID {
					return ErrExecutionRecord
				}
			}
			pod, e := o.cfg.Client.CoreV1().Pods(spec.RuntimeNamespace()).Get(ctx, spec.RuntimePod(), metav1.GetOptions{})
			if e != nil || string(pod.UID) != ob.PodUID || pod.DeletionTimestamp != nil {
				return ErrExecutionRecord
			}
			return nil
		}
		current, e := sourceRow(ctx, tx, spec.Source.ID)
		if e != nil || current != spec.Source {
			return ErrExecutionRecord
		}
		switch spec.Kind {
		case "gateway":
			if !r.Claimed || ob.PodUID != spec.UID || ob.GatewayID != fmt.Sprintf("gw-%d-%d", spec.Source.ID, spec.ResumeGeneration) || ob.Port != spec.Port {
				return ErrExecutionRecord
			}
			live, e := o.cfg.Agent.GatewayState(ctx, spec.Endpoint, ob.GatewayID)
			if e != nil || live == nil || live.GatewayID != ob.GatewayID || live.InstanceID != spec.Source.ID || live.Generation != spec.ResumeGeneration || live.State != "running" || live.UserID != spec.Source.UserID || live.Port != spec.Port || live.PID != gatewayResume.Receipt.PID {
				return ErrExecutionRecord
			}
			if e := o.checkGatewayPod(ctx, spec); e != nil {
				return e
			}
			if e = o.gatewayBinding(ctx, tx, spec, false); e != nil {
				return e
			}
			result, e := tx.ExecContext(ctx, `UPDATE instance_runtime_bindings SET generation=?,gateway_id=?,gateway_pid=?,state='running' WHERE instance_id=? AND generation=? AND gateway_port=? AND runtime_pod_id=? AND gateway_pid=?`, spec.ResumeGeneration, ob.GatewayID, gatewayResume.Receipt.PID, spec.Source.ID, spec.Source.Generation, spec.Port, spec.Runtime.RuntimePodID, spec.Runtime.GatewayPID)
			if e != nil {
				return e
			}
			ok, e := exactlyOneRow(result)
			if e != nil || !ok {
				return ErrExecutionRecord
			}
			result, e = tx.ExecContext(ctx, `UPDATE instances SET runtime_generation=? WHERE id=? AND runtime_generation=?`, spec.ResumeGeneration, spec.Source.ID, spec.Source.Generation)
			if e != nil {
				return e
			}
			ok, e = exactlyOneRow(result)
			if e != nil || !ok {
				return ErrExecutionRecord
			}
		case "pod":
			if ob.PodUID == "" || (ob.PodUID != spec.UID && !r.Claimed) || ob.GatewayID != "" || ob.Port != 0 {
				return ErrExecutionRecord
			}
			pod, e := o.cfg.Client.CoreV1().Pods(spec.Source.Namespace).Get(ctx, spec.Name, metav1.GetOptions{})
			if e != nil || string(pod.UID) != ob.PodUID || pod.DeletionTimestamp != nil {
				return ErrExecutionRecord
			}
		default:
			return ErrExecutionRecord
		}
		result, e := tx.ExecContext(ctx, `UPDATE system_backup_v2_runtime_controls SET restart_completed=TRUE,resumed_json=?,row_version=row_version+1 WHERE task_public_id=? AND attempt_no=? AND writer_id=? AND row_version=? AND restart_completed=FALSE`, raw, a.TaskPublicID, a.AttemptNo, id, r.Version)
		if e != nil {
			return e
		}
		ok, e := exactlyOneRow(result)
		if e != nil || !ok {
			return ErrExecutionRecord
		}
		return nil
	})
}
func (o *SQLRuntimeControl) Callbacks() b.WriterCallbacks {
	return b.WriterCallbacks{StoppedProControl: o.StoppedProControl, GatewayControl: o.GatewayControl, Guard: o.Guard, ClaimRestart: o.ClaimRestart, CompleteRestart: o.CompleteRestart, ConfirmStopped: o.ConfirmStopped, ConfirmResumed: o.ConfirmResumed,
		LoadGateway: func(ctx context.Context, a d.Authority, id, ref string) (services.RuntimeAgentCreateGatewayRequest, error) {
			var v services.RuntimeAgentCreateGatewayRequest
			raw, e := o.load(ctx, a, id, ref)
			defer clear(raw)
			if e != nil {
				return v, e
			}
			e = json.Unmarshal(raw, &v)
			return v, e
		},
		LoadPod: func(ctx context.Context, a d.Authority, id, ref string) (*corev1.Pod, error) {
			var v corev1.Pod
			raw, e := o.load(ctx, a, id, ref)
			defer clear(raw)
			if e != nil {
				return nil, e
			}
			if json.Unmarshal(raw, &v) != nil {
				return nil, ErrExecutionRecord
			}
			return &v, nil
		},
	}
}

// Dependencies returns the exact registered participant set, excluding runtime
// IDs already represented by specs. Unknown/missing participants fail closed.
func (o *SQLRuntimeControl) Dependencies(ctx context.Context, a d.Authority, specs []b.RuntimeWriterSpec) (b.RuntimeWriterDependencies, error) {
	if o == nil || a.ConfigVersion == 0 || a.ConfigVersion > uint64(1<<63-1) {
		return b.RuntimeWriterDependencies{}, ErrExecutionAuthority
	}
	out := b.RuntimeWriterDependencies{Ports: o.cfg.Gate, Client: o.cfg.Client, Agent: o.cfg.Agent, Callbacks: o.Callbacks(), PollInterval: o.cfg.PollInterval}
	physical := map[string]bool{}
	for _, id := range o.cfg.AdditionalWriterIDs {
		if id == "" || len(id) > 128 || physical[id] {
			return out, ErrExecutionRecord
		}
		physical[id] = true
	}
	for _, s := range specs {
		id := runtimeWriterID(s)
		if id == "" || len(id) > 128 || physical[id] {
			return out, ErrExecutionRecord
		}
		physical[id] = true
	}
	for id := range o.cfg.ParticipantChecks {
		if physical[id] {
			return out, ErrExecutionRecord
		}
	}
	rows, e := o.cfg.Gate.Authority.DB.QueryContext(ctx, `SELECT participant_id FROM system_backup_participants WHERE scope=? ORDER BY participant_id`, o.cfg.Gate.Authority.ApplicationScope)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil || seen[id] {
			return out, ErrExecutionRecord
		}
		seen[id] = true
		if physical[id] {
			continue
		}
		if _, ok := o.cfg.ParticipantChecks[id]; !ok {
			return out, ErrExecutionRecord
		}
		out.Participants = append(out.Participants, b.ParticipantSpec{ID: id, Original: flow.State{UID: o.cfg.Gate.Authority.ApplicationScope + "/" + id, Generation: int64(a.ConfigVersion), Checkpoint: recordHash([]byte(o.cfg.Gate.Authority.ApplicationScope + "/" + id + "/" + a.ConfigSHA256))}})
	}
	if e = rows.Err(); e != nil {
		return out, e
	}
	for id := range o.cfg.ParticipantChecks {
		if !seen[id] {
			return out, ErrExecutionRecord
		}
	}
	if len(out.Participants) == 0 {
		return out, ErrExecutionRecord
	}
	return out, nil
}
