package systembackupcontroller

import (
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/flow"
	b "clawreef/internal/systembackup/publicadapter"
	d "clawreef/internal/systembackupdispatch"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"reflect"
	"strconv"
)

func (o *SQLRuntimeControl) CheckGate(g SQLCaptureGate) error {
	if o == nil || o.cfg.Gate.Authority.DB != g.Authority.DB || o.cfg.Gate.Authority.InstallationID != g.Authority.InstallationID || o.cfg.Gate.Authority.ApplicationScope != g.Authority.ApplicationScope || o.cfg.Gate.Recovery.Identity != g.Recovery.Identity {
		return ErrExecutionAuthority
	}
	return nil
}

func (o *SQLRuntimeControl) Ready(ctx context.Context) error {
	if o == nil || o.cfg.Gate.Authority.DB == nil {
		return d.ErrNotReady
	}
	for _, query := range []string{
		"SELECT task_public_id,attempt_no,writer_id,instance_id,spec_json,material_sha256,key_ref,sealed_material,restart_claimed,restart_completed,resumed_json,stopped_sha256,row_version FROM system_backup_v2_runtime_controls WHERE 1=0",
		"SELECT origin_installation_id,task_public_id,attempt_no,phase,job_unit_key,sequence_no,body_sha256,body_json FROM system_backup_v2_relay_receipts WHERE 1=0",
		"SELECT task_public_id,attempt_no,writer_id,proof_kind,request_sha256,body_sha256,body_raw FROM system_backup_v2_gateway_proofs WHERE 1=0",
	} {
		rows, e := o.cfg.Gate.Authority.DB.QueryContext(ctx, query)
		if e != nil {
			return e
		}
		if e = rows.Close(); e != nil {
			return e
		}
	}
	return nil
}

func runtimeStateMatches(spec b.RuntimeWriterSpec, s flow.State, point string) bool {
	if spec.Kind == "stopped" {
		return s == spec.Stopped
	}
	uid := spec.UID
	if spec.Kind == "gateway" {
		uid += fmt.Sprintf("/gw-%d-%d", spec.Source.ID, spec.Source.Generation)
	}
	if s.UID != uid {
		return false
	}
	if spec.Kind != "deployment" && s.Generation != int64(spec.Source.Generation) {
		return false
	}
	if point == "observe" {
		return true
	}
	return s.Generation > 0 && s.Checkpoint != "" && s.Running
}

// BuildWriters plugs directly into LinuxProfileConfig.BuildWriters. Recovery
// loads custody only; it cannot rediscover sources or mint fresh reservations.
func (o *SQLRuntimeControl) BuildWriters(ctx context.Context, in d.Input, inv b.SourceInventory, frozen []b.FrozenWriter) ([]flow.Writer, error) {
	if o != nil {
		if o.cfg.RuntimeTestScope != nil && o.cfg.RuntimeTestScope.Version == domain.RunningOnlyRuntimeTestScopeVersion && (in.Backup == nil || in.Backup.TaskPurpose != "functional_test") {
			return nil, ErrExecutionRecord
		}
		if !reflect.DeepEqual(inv.RuntimeTestScope, o.cfg.RuntimeTestScope) {
			return nil, ErrExecutionRecord
		}
		var scopeErr error
		inv.Instances, scopeErr = o.cfg.RuntimeTestScope.RuntimeInstances(inv.Instances)
		if scopeErr != nil {
			return nil, ErrExecutionRecord
		}
		inv.RuntimeTestScope = nil
	}
	if o != nil && o.cfg.Shared != nil {
		return o.buildSharedTaskWriters(ctx, in, inv, frozen)
	}
	if o == nil {
		return nil, d.ErrNotReady
	}
	var specs []b.RuntimeWriterSpec
	read := func(tx *sql.Tx) error {
		specs = nil
		rows, e := tx.QueryContext(ctx, `SELECT spec_json FROM system_backup_v2_runtime_controls WHERE task_public_id=? AND attempt_no=? ORDER BY instance_id`, in.Authority.TaskPublicID, in.Authority.AttemptNo)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			var spec b.RuntimeWriterSpec
			if rows.Scan(&raw) != nil || json.Unmarshal(raw, &spec) != nil || len(specs) >= 9998 {
				return ErrExecutionRecord
			}
			specs = append(specs, spec)
		}
		return rows.Err()
	}
	e := o.transaction(ctx, in.Authority, false, read)
	if e != nil && frozen != nil {
		e = o.transaction(ctx, in.Authority, true, read)
	}
	if e != nil {
		return nil, e
	}
	if frozen == nil && len(specs) != len(inv.Instances) {
		specs, e = o.Prepare(ctx, in.Authority)
		if e != nil {
			return nil, e
		}
	}
	if len(specs) != len(inv.Instances) {
		return nil, ErrExecutionRecord
	}
	deps, e := o.Dependencies(ctx, in.Authority, specs)
	if e != nil {
		return nil, e
	}
	builder, e := b.NewRuntimeWriterBuilder(specs, deps)
	if e != nil {
		return nil, e
	}
	return builder(ctx, in, inv, frozen)
}

func (o *SQLRuntimeControl) deploymentForPod(ctx context.Context, pod *corev1.Pod) (*appsv1.Deployment, error) {
	owner := metav1.GetControllerOf(pod)
	if owner == nil || owner.Kind != "ReplicaSet" {
		return nil, ErrExecutionRecord
	}
	rs, e := o.cfg.Client.AppsV1().ReplicaSets(pod.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
	if e != nil || rs.UID != owner.UID {
		return nil, ErrExecutionRecord
	}
	parent := metav1.GetControllerOf(rs)
	if parent == nil || parent.Kind != "Deployment" {
		return nil, ErrExecutionRecord
	}
	dep, e := o.cfg.Client.AppsV1().Deployments(pod.Namespace).Get(ctx, parent.Name, metav1.GetOptions{})
	if e != nil || dep.UID != parent.UID || dep.DeletionTimestamp != nil {
		return nil, ErrExecutionRecord
	}
	return dep, nil
}

type deploymentResume struct{ PodName, PodUID string }

func (o *SQLRuntimeControl) confirmDeployment(ctx context.Context, tx *sql.Tx, a d.Authority, id string, r runtimeControlRow) error {
	spec := r.Spec
	if o.checkJournaledDeployment(ctx, a, spec, true) != nil {
		return ErrExecutionRecord
	}
	dep, e := o.cfg.Client.AppsV1().Deployments(spec.Source.Namespace).Get(ctx, spec.Name, metav1.GetOptions{})
	if e != nil || string(dep.UID) != spec.UID || dep.Spec.Replicas == nil || *dep.Spec.Replicas != 1 || dep.Status.ReadyReplicas != 1 || dep.Status.ObservedGeneration < dep.Generation || dep.Annotations["backup.clawmanager.io/source-resume-fence"] != a.TaskPublicID+"/attempt/"+strconv.FormatUint(a.AttemptNo, 10) {
		return ErrExecutionRecord
	}
	selector, e := metav1.LabelSelectorAsSelector(dep.Spec.Selector)
	if e != nil {
		return ErrExecutionRecord
	}
	pods, e := o.cfg.Client.CoreV1().Pods(spec.Source.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if e != nil {
		return e
	}
	var ob deploymentResume
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.DeletionTimestamp != nil {
			continue
		}
		owner, e := o.deploymentForPod(ctx, pod)
		if e != nil || owner.UID != dep.UID {
			return ErrExecutionRecord
		}
		ready := false
		for _, c := range pod.Status.Conditions {
			if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
				ready = true
			}
		}
		if !ready || ob.PodUID != "" {
			return ErrExecutionRecord
		}
		ob = deploymentResume{pod.Name, string(pod.UID)}
	}
	if ob.PodUID == "" {
		return ErrExecutionRecord
	}
	raw, _ := json.Marshal(ob)
	if r.Completed {
		if string(raw) != string(r.Resumed) {
			return ErrExecutionRecord
		}
		return nil
	}
	current, e := sourceRow(ctx, tx, spec.Source.ID)
	if e != nil || current != spec.Source {
		return ErrExecutionRecord
	}
	result, e := tx.ExecContext(ctx, `UPDATE instances SET pod_name=? WHERE id=? AND pod_name=? AND runtime_generation=?`, ob.PodName, spec.Source.ID, spec.Source.Pod, spec.Source.Generation)
	if e != nil {
		return e
	}
	// MySQL may report zero changed rows when the original Pod survived; its
	// identity was locked and verified above, so only a changed name needs CAS=1.
	if ob.PodName != spec.Source.Pod {
		if ok, z := exactlyOneRow(result); z != nil || !ok {
			return ErrExecutionRecord
		}
	}
	result, e = tx.ExecContext(ctx, `UPDATE system_backup_v2_runtime_controls SET restart_completed=TRUE,resumed_json=?,row_version=row_version+1 WHERE task_public_id=? AND attempt_no=? AND writer_id=? AND row_version=? AND restart_completed=FALSE`, raw, a.TaskPublicID, a.AttemptNo, id, r.Version)
	if e != nil {
		return e
	}
	if ok, z := exactlyOneRow(result); z != nil || !ok {
		return ErrExecutionRecord
	}
	return nil
}

// This opt-in role extends the functional-capture role explicitly. The original
// PublicCaptureGrantSQL stays read-only for business tables.
func runtimeControlTableGrants() map[string][]string {
	out := map[string][]string{}
	for table, verbs := range publicCaptureTableGrants {
		out[table] = append([]string(nil), verbs...)
	}
	out["instances"] = []string{"SELECT", "UPDATE"}
	out["instance_runtime_bindings"] = []string{"SELECT", "UPDATE"}
	out["runtime_pods"] = []string{"SELECT", "UPDATE"}
	out["system_backup_v2_runtime_controls"] = []string{"SELECT", "INSERT", "UPDATE"}
	out["system_backup_v2_gateway_proofs"] = []string{"SELECT", "INSERT"}
	out["system_backup_v2_relay_receipts"] = []string{"SELECT", "INSERT"}
	return out
}
func RuntimeControlGrantSQL(schema, user, host string, allowAnyHost bool) ([]string, error) {
	return controllerGrantSQL(schema, user, host, allowAnyHost, runtimeControlTableGrants())
}
func ValidateRuntimeControlGrants(schema string, statements []string) error {
	return validateControllerGrants(schema, statements, runtimeControlTableGrants())
}

type SQLRuntimeControlGrantProbe struct {
	DB           *sql.DB
	Schema, User string
}

func (p SQLRuntimeControlGrantProbe) Check(ctx context.Context) error {
	return (SQLControllerGrantProbe{DB: p.DB, Schema: p.Schema, User: p.User}).check(ctx, runtimeControlTableGrants())
}
