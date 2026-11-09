package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

const longhornKeeperPurpose = "original-task-longhorn-attachment-keeper.v1"

// The concrete storage owner implements this only after authenticating the
// handover into the existing Node owner and its original recovery journal.
type longhornKeeperHandover interface {
	BindKeeper(context.Context, d.Input, longhornKeeperPlan, kube.ResourceRecord, kube.WorkerProcess) error
}

// The immutable PLAN is an original resource-journal request, not a label or
// native hold proof. Recovery must compare it with the original frozen source
// and exact Job request before treating that Job as an attachment keeper.
type longhornKeeperPlan struct {
	Purpose, Task, Writer, SourceSHA256 string
	Attempt, Generation                 uint64
	Original                            d.WriterState
	Runtime                             b.RuntimeWriterSpec
	Source                              originalLonghornSource
	SourcePodUID, SourcePodSHA256       string
	ServiceAccountUID                   string
	Keeper                              kube.LonghornAttachmentKeeper
}

func longhornKeeperPlanName(plan longhornKeeperPlan) string {
	return "sbk-kplan-" + plan.Keeper.Identity.Name[len("sbk-keeper-"):]
}

func longhornKeeperPlanConfig(namespace string, plan longhornKeeperPlan) *corev1.ConfigMap {
	immutable := true
	raw, _ := json.Marshal(plan)
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: longhornKeeperPlanName(plan), Labels: map[string]string{kube.OwnerLabel: plan.Task}},
		Immutable: &immutable, Data: map[string]string{"keeper-plan.json": string(raw)}}
}

// Pure reconstruction from frozen task data and the signed source selection.
// The default tenant SA mounts no token and grants the keeper no API powers.
func (s *DeploymentService) frozenLonghornKeeperPlan(a d.Authority, discovery b.Discovery, id string, original d.WriterState, spec b.RuntimeWriterSpec, serviceAccountUID string) (*longhornKeeperPlan, error) {
	if !isRunningTenantPro(spec.Source) || spec.Source.Namespace == s.Config.Namespace {
		return nil, nil
	}
	pin := s.signedTenantProMount(spec.Source)
	if pin == nil || !pin.matchesWriter(spec) || !pin.valid() || serviceAccountUID == "" {
		return nil, kube.ErrOwnership
	}
	var inventory b.SourceInventory
	var metadata productionCaptureMetadata
	if hash(discovery.Source) != discovery.SourceSHA256 || json.Unmarshal(discovery.Source, &inventory) != nil ||
		decodeMetadataCanonical(inventory.CaptureMetadata, &metadata) != nil || metadata.Version != productionCaptureMetadataVersion {
		return nil, kube.ErrOwnership
	}
	matched := 0
	for _, instance := range inventory.Instances {
		if instance == spec.Source {
			matched++
		}
	}
	if matched != 1 {
		return nil, kube.ErrOwnership
	}
	var selected *originalLonghornSource
	for _, plan := range metadata.LonghornClones {
		if plan.Original.Source != pin.Identity || plan.Original.Namespace != spec.Source.Namespace {
			continue
		}
		if plan != plan.Original.plan(a, s.Config.Namespace, s.Config.NamespaceUID) || plan.Original.AccessMode != corev1.ReadWriteOnce || plan.Original.NamespaceUID != pin.NamespaceUID {
			return nil, kube.ErrOwnership
		}
		if selected != nil && *selected != plan.Original {
			return nil, kube.ErrOwnership
		}
		copy := plan.Original
		selected = &copy
	}
	if selected == nil {
		return nil, nil
	}
	signed := false
	for _, source := range s.captureMaterials.Discovery.LonghornSources {
		if source == *selected {
			signed = true
		}
	}
	if !signed {
		return nil, kube.ErrOwnership
	}
	node := ""
	for _, mount := range metadata.Mounts {
		if mount.InstanceID != spec.Source.ID || mount.Source.PersistentVolumeClaim == nil || mount.Source.PersistentVolumeClaim.ClaimName != pin.Identity.Name {
			continue
		}
		if mount.NodeName == "" || node != "" && node != mount.NodeName {
			return nil, kube.ErrOwnership
		}
		node = mount.NodeName
	}
	if node == "" || s.Config.Security.NodeUIDs[node] == "" {
		return nil, kube.ErrOwnership
	}
	nameRaw, _ := json.Marshal([]any{a.TaskPublicID, a.AttemptNo, a.MaintenanceFencingToken, id, discovery.SourceSHA256, selected})
	plan := &longhornKeeperPlan{Purpose: longhornKeeperPurpose, Task: a.TaskPublicID, Writer: id, SourceSHA256: discovery.SourceSHA256,
		Attempt: a.AttemptNo, Generation: a.MaintenanceFencingToken, Original: original, Runtime: spec, Source: *selected,
		SourcePodUID: pin.PodUID, SourcePodSHA256: pin.PodSpecSHA256, ServiceAccountUID: serviceAccountUID,
		Keeper: kube.LonghornAttachmentKeeper{Identity: kube.Identity{Namespace: selected.Namespace, Name: "sbk-keeper-" + hash(nameRaw)[:48], Owner: a.TaskPublicID},
			NamespaceUID: selected.NamespaceUID, Node: node, NodeUID: s.Config.Security.NodeUIDs[node], ServiceAccount: "default", Image: s.Config.WorkerImage,
			Executable: "/backup-shared-runtime-node-owner", Source: selected.Source}}
	return plan, nil
}

// BeforeSourceStop runs after the original pause intent committed, before the
// original writer's physical stop. It never admits a capture worker or hold.
func (o *PublicJobOwner) BeforeSourceStop(ctx context.Context, a d.Authority, id string, original d.WriterState) error {
	if o == nil {
		return d.ErrNotReady
	}
	if o.longhornExecutor == nil {
		return nil
	}
	s := o.longhornExecutor.service
	if s == nil || !s.ForwardEnabled || s.checkProductionCaptureMaterials() != nil {
		return kube.ErrOwnership
	}
	spec, err := o.Gate.PrepareSourceStop(ctx, a, id, original)
	if err != nil {
		return err
	}
	if spec == nil || !isRunningTenantPro(spec.Source) || spec.Source.Namespace == o.Namespace {
		return nil
	}
	in, _, discovery, err := o.input(ctx, a, false)
	if err != nil || in.Authority != a {
		return errors.Join(err, kube.ErrOwnership)
	}
	sa, err := o.Client.CoreV1().ServiceAccounts(spec.Source.Namespace).Get(ctx, "default", metav1.GetOptions{})
	if err != nil || sa.UID == "" || sa.DeletionTimestamp != nil {
		return errors.Join(err, kube.ErrOwnership)
	}
	plan, err := s.frozenLonghornKeeperPlan(a, discovery, id, original, *spec, string(sa.UID))
	if err != nil || plan == nil {
		return err
	}
	handover, ok := o.longhornCutOwner.(longhornKeeperHandover)
	if !ok {
		return d.ErrNotReady
	}
	pin := s.signedTenantProMount(spec.Source)
	if pin == nil || pin.check(ctx, o.Client, o.Namespace) != nil {
		return kube.ErrOwnership
	}
	rows, err := o.rows(a)
	if err != nil {
		return err
	}
	fence := func(ctx context.Context, tx *sql.Tx) error {
		current, err := o.Gate.CheckSourceStopTx(ctx, tx, a, id, original)
		if err != nil || current == nil || !reflect.DeepEqual(*current, *spec) {
			return errors.Join(err, kube.ErrOwnership)
		}
		return nil
	}
	check := func(ctx context.Context) error {
		current, err := o.Gate.PrepareSourceStop(ctx, a, id, original)
		if err != nil || current == nil || !reflect.DeepEqual(*current, *spec) || s.checkProductionCaptureMaterials() != nil {
			return errors.Join(err, kube.ErrOwnership)
		}
		if pin.check(ctx, o.Client, o.Namespace) != nil {
			return kube.ErrOwnership
		}
		return o.namespace(ctx)
	}
	runner := kube.Runner{Client: o.Dynamic, Journal: kube.SQLJournal{DB: o.Gate.Authority.DB, Rows: rows, Fence: fence}, CheckFence: check}
	if _, err := runner.Ensure(ctx, "ConfigMap", longhornKeeperPlanConfig(o.Namespace, *plan)); err != nil {
		return err
	}
	return wait.PollUntilContextCancel(ctx, 200*time.Millisecond, true, func(current context.Context) (bool, error) {
		record, err := kube.ReconcileLonghornAttachmentKeeper(current, o.Client, runner, plan.Keeper)
		if errors.Is(err, kube.ErrPending) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		process, err := o.observeLonghornKeeper(current, *plan, record)
		if err != nil {
			return false, err
		}
		if err := o.persistLonghornKeeperProcess(current, a, id, original, *plan, record, process); err != nil {
			return false, err
		}
		if err := handover.BindKeeper(current, in, *plan, record, process); err != nil {
			return false, err
		}
		return true, check(current)
	})
}

// loadLonghornKeeperRecord reads ONLY original resource custody. The caller
// must reconstruct plan from the authenticated frozen source, never a label.
// Unknown creates, missing/replaced UIDs and changed process receipts refuse.
func (o *PublicJobOwner) loadLonghornKeeperRecord(ctx context.Context, a d.Authority, plan longhornKeeperPlan, recovery bool) (kube.ResourceRecord, kube.WorkerProcess, error) {
	var process kube.WorkerProcess
	var zero kube.ResourceRecord
	if plan.Purpose != longhornKeeperPurpose || plan.Task != a.TaskPublicID || plan.Attempt != a.AttemptNo || plan.Generation != a.MaintenanceFencingToken ||
		plan.Keeper.Identity.Owner != a.TaskPublicID || plan.Keeper.Identity.Namespace != plan.Source.Namespace || plan.Keeper.Source != plan.Source.Source {
		return zero, process, kube.ErrOwnership
	}
	job, err := kube.LonghornAttachmentKeeperJob(plan.Keeper)
	if err != nil {
		return zero, process, err
	}
	jobIntent, err := kube.Intent(kube.LonghornKeeperResource, job)
	if err != nil {
		return zero, process, err
	}
	configIntent, err := kube.Intent("ConfigMap", longhornKeeperPlanConfig(o.Namespace, plan))
	if err != nil {
		return zero, process, err
	}
	tx, err := o.Gate.Authority.DB.BeginTx(ctx, nil)
	if err != nil {
		return zero, process, err
	}
	defer tx.Rollback()
	check := func() error {
		if recovery {
			return o.Gate.Recovery.CheckTx(ctx, tx, a)
		}
		_, err := o.Gate.CheckSourceStopTx(ctx, tx, a, plan.Writer, plan.Original)
		return err
	}
	if err := check(); err != nil {
		return zero, process, err
	}
	rows, err := o.rows(a)
	if err != nil {
		return zero, process, err
	}
	config, err := rows.Load(ctx, tx, configIntent)
	if err != nil || !sameLonghornExecutionIntent(config.Intent, configIntent) || config.UID == "" || config.Deleted || config.Deleting {
		return zero, process, errors.Join(err, kube.ErrOwnership)
	}
	record, err := rows.Load(ctx, tx, jobIntent)
	if err != nil || !sameLonghornExecutionIntent(record.Intent, jobIntent) || record.UID == "" || !record.CreateDispatched || record.Deleted || record.Deleting {
		return zero, process, errors.Join(err, kube.ErrOwnership)
	}
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT process_json FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND attempt_no=? AND phase=? AND resource_kind='AttachmentKeeper' AND namespace_name=? AND resource_name=? FOR SHARE`, a.TaskPublicID, a.AttemptNo, a.Phase, plan.Keeper.Identity.Namespace, plan.Keeper.Identity.Name).Scan(&raw)
	if err != nil || json.Unmarshal(raw, &process) != nil || process.Name == "" || process.UID == "" || process.Node != plan.Keeper.Node || len(process.Containers) != 1 {
		return zero, process, errors.Join(err, kube.ErrOwnership)
	}
	if err := check(); err != nil {
		return zero, process, err
	}
	return record, process, nil
}

// This readback is also usable by the original recovery owner. A container
// string from the plan or a successful Job create alone is never an identity.
func (o *PublicJobOwner) observeLonghornKeeper(ctx context.Context, plan longhornKeeperPlan, record kube.ResourceRecord) (kube.WorkerProcess, error) {
	job, err := kube.LonghornAttachmentKeeperJob(plan.Keeper)
	if err != nil {
		return kube.WorkerProcess{}, err
	}
	intent, err := kube.Intent(kube.LonghornKeeperResource, job)
	if err != nil || !sameLonghornExecutionIntent(record.Intent, intent) {
		return kube.WorkerProcess{}, kube.ErrOwnership
	}
	mount := plan.Keeper.Source
	mount.Volume = "source"
	process, err := (kube.WorkerObserver{Client: o.Client}).Observe(ctx, record, kube.WorkerSecurity{NodeUIDs: map[string]string{plan.Keeper.Node: plan.Keeper.NodeUID}, Volumes: []kube.MountIdentity{mount}})
	if err != nil || len(process.Containers) != 1 {
		return process, errors.Join(err, kube.ErrOwnership)
	}
	sa, err := o.Client.CoreV1().ServiceAccounts(plan.Keeper.Identity.Namespace).Get(ctx, plan.Keeper.ServiceAccount, metav1.GetOptions{})
	if err != nil || string(sa.UID) != plan.ServiceAccountUID || sa.DeletionTimestamp != nil {
		return process, errors.Join(err, kube.ErrOwnership)
	}
	return process, nil
}

func (o *PublicJobOwner) persistLonghornKeeperProcess(ctx context.Context, a d.Authority, id string, original d.WriterState, plan longhornKeeperPlan, record kube.ResourceRecord, process kube.WorkerProcess) error {
	tx, err := o.Gate.Authority.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := o.Gate.CheckSourceStopTx(ctx, tx, a, id, original); err != nil {
		return err
	}
	rows, err := o.rows(a)
	if err != nil {
		return err
	}
	current, err := rows.Load(ctx, tx, record.Intent)
	if err != nil || !sameLonghornExecutionIntent(current.Intent, record.Intent) || current.UID != record.UID || current.Deleting || current.Deleted {
		return errors.Join(err, kube.ErrOwnership)
	}
	var previous []byte
	err = tx.QueryRowContext(ctx, `SELECT process_json FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND attempt_no=? AND phase=? AND resource_kind='AttachmentKeeper' AND namespace_name=? AND resource_name=? FOR UPDATE`, a.TaskPublicID, a.AttemptNo, a.Phase, plan.Keeper.Identity.Namespace, plan.Keeper.Identity.Name).Scan(&previous)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(process)
	if len(previous) != 0 && !bytes.Equal(previous, raw) {
		return kube.ErrOwnership
	}
	if len(previous) == 0 {
		result, err := tx.ExecContext(ctx, `UPDATE system_backup_v2_runtime_resources SET process_json=?,row_version=row_version+1 WHERE task_public_id=? AND attempt_no=? AND phase=? AND resource_kind='AttachmentKeeper' AND namespace_name=? AND resource_name=? AND row_version=? AND request_sha256=? AND observed_uid=? AND lifecycle='ready' AND process_json IS NULL`, raw, a.TaskPublicID, a.AttemptNo, a.Phase, plan.Keeper.Identity.Namespace, plan.Keeper.Identity.Name, current.Revision, record.Intent.RequestSHA256, record.UID)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil || n != 1 {
			return kube.ErrOwnership
		}
	}
	if _, err := o.Gate.CheckSourceStopTx(ctx, tx, a, id, original); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return c.ErrExecutionCommitUnknown
	}
	return nil
}
