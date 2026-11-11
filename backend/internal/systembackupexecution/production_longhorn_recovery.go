package systembackupexecution

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	d "clawreef/internal/systembackupdispatch"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

// Called by the existing resume barrier after all collectors are proven
// stopped, including recovery of an interrupted native acquire before Jobs.
func (o *PublicJobOwner) BeforeSourceResume(ctx context.Context, a d.Authority) error {
	if o.productionSource == nil {
		return nil
	}
	in, _, discovery, err := o.input(ctx, a, true)
	if err != nil {
		return err
	}
	var source b.SourceInventory
	var metadata productionCaptureMetadata
	if json.Unmarshal(discovery.Source, &source) != nil || decodeMetadataCanonical(source.CaptureMetadata, &metadata) != nil {
		return d.ErrNotReady
	}
	if len(metadata.LonghornClones) == 0 {
		return nil
	}
	if o.longhornCutOwner == nil {
		return d.ErrNotReady
	}
	plans, err := o.orderedLonghornPlans(a, metadata.LonghornClones)
	if err != nil {
		return err
	}
	o.longhornCutMu.Lock()
	defer o.longhornCutMu.Unlock()
	return o.longhornCutOwner.Release(ctx, in, plans)
}

// Called only after the original writer's physical resume and readiness
// checks, before acknowledging resume in the maintenance gate.
func (o *PublicJobOwner) AfterSourceResume(ctx context.Context, a d.Authority, writer string) error {
	if o == nil || o.longhornCutOwner == nil {
		return nil
	}
	record, found, err := o.recoveredKeeper(ctx, a, writer)
	if err != nil || !found {
		return err
	}
	runner, err := o.runner(a, true)
	if err != nil {
		return err
	}
	return wait.PollUntilContextCancel(ctx, 200*time.Millisecond, true, func(ctx context.Context) (bool, error) {
		return runner.Cleanup(ctx, record)
	})
}

func (o *PublicJobOwner) recoveredKeeper(ctx context.Context, a d.Authority, writer string) (kube.ResourceRecord, bool, error) {
	var zero kube.ResourceRecord
	tx, err := o.Gate.Authority.DB.BeginTx(ctx, nil)
	if err != nil {
		return zero, false, err
	}
	defer tx.Rollback()
	if err := o.Gate.Recovery.CheckTx(ctx, tx, a); err != nil {
		return zero, false, err
	}
	plans, err := tx.QueryContext(ctx, `SELECT resource_name,request_sha256,request_json FROM system_backup_v2_runtime_resources
WHERE task_public_id=? AND target_type=? AND attempt_no=? AND phase=? AND resource_kind='ConfigMap' AND namespace_name=?
AND resource_name LIKE 'sbk-kplan-%' FOR SHARE`, a.TaskPublicID, a.TaskType, a.AttemptNo, a.Phase, o.Namespace)
	if err != nil {
		return zero, false, err
	}
	defer plans.Close()
	var selected *longhornKeeperPlan
	for plans.Next() {
		var name, digest string
		var raw []byte
		if err := plans.Scan(&name, &digest, &raw); err != nil {
			return zero, false, err
		}
		var config corev1.ConfigMap
		var plan longhornKeeperPlan
		if json.Unmarshal(raw, &config) != nil || json.Unmarshal([]byte(config.Data["keeper-plan.json"]), &plan) != nil ||
			plan.Purpose != longhornKeeperPurpose || plan.Task != a.TaskPublicID || plan.Attempt != a.AttemptNo || plan.Generation != a.MaintenanceFencingToken ||
			!strings.HasPrefix(plan.Keeper.Identity.Name, "sbk-keeper-") || name != longhornKeeperPlanName(plan) ||
			plan.Keeper.Identity.Owner != a.TaskPublicID || plan.Keeper.Identity.Namespace != plan.Source.Namespace || plan.Keeper.Source != plan.Source.Source {
			return zero, false, kube.ErrOwnership
		}
		intent, err := kube.Intent("ConfigMap", longhornKeeperPlanConfig(o.Namespace, plan))
		if err != nil || intent.RequestSHA256 != digest || string(intent.RequestJSON) != string(raw) {
			return zero, false, kube.ErrOwnership
		}
		if plan.Writer == writer {
			if selected != nil {
				return zero, false, kube.ErrOwnership
			}
			selected = &plan
		}
	}
	if err := plans.Err(); err != nil {
		return zero, false, err
	}
	if err := plans.Close(); err != nil || selected == nil {
		return zero, false, err
	}
	job, err := kube.LonghornAttachmentKeeperJob(selected.Keeper)
	if err != nil {
		return zero, false, err
	}
	intent, err := kube.Intent(kube.LonghornKeeperResource, job)
	if err != nil {
		return zero, false, err
	}
	rows, err := o.rows(a)
	if err != nil {
		return zero, false, err
	}
	record, err := rows.Load(ctx, tx, intent)
	if errors.Is(err, sql.ErrNoRows) {
		return zero, false, nil
	}
	if err != nil || !sameLonghornExecutionIntent(record.Intent, intent) {
		return zero, false, errors.Join(err, kube.ErrOwnership)
	}
	if err := tx.Rollback(); err != nil {
		return zero, false, err
	}
	// ConfirmResumed has proved the original workload and SQL source CAS. Before
	// deleting its attachment keeper, also re-read the original physical volume.
	if err := checkRecoveredLonghornVolume(ctx, o.Client, selected.Source); err != nil {
		return zero, false, err
	}
	return record, true, o.Gate.Recovery.Check(ctx, a)
}

// Uses the original task's saved physical source, never current discovery. A
// replacement claim/PV must not inherit the old keeper's recovery completion.
func checkRecoveredLonghornVolume(ctx context.Context, client kubernetes.Interface, source originalLonghornSource) error {
	if client == nil || source.Namespace == "" || source.NamespaceUID == "" || source.ProviderNamespace == "" || source.ProviderUID == "" || source.Source.UID == "" || source.Source.PVUID == "" || !formalCandidateDigest(source.Source.SHA256) || source.Handle == "" {
		return kube.ErrOwnership
	}
	ns, err := client.CoreV1().Namespaces().Get(ctx, source.Namespace, metav1.GetOptions{})
	if err != nil || ns.DeletionTimestamp != nil || string(ns.UID) != source.NamespaceUID {
		return kube.ErrOwnership
	}
	provider, err := client.CoreV1().Namespaces().Get(ctx, source.ProviderNamespace, metav1.GetOptions{})
	if err != nil || provider.DeletionTimestamp != nil || string(provider.UID) != source.ProviderUID {
		return kube.ErrOwnership
	}
	claim, err := client.CoreV1().PersistentVolumeClaims(source.Namespace).Get(ctx, source.Source.Name, metav1.GetOptions{})
	if err != nil || claim.DeletionTimestamp != nil || string(claim.UID) != source.Source.UID || claim.Status.Phase != corev1.ClaimBound || claim.Spec.VolumeName != source.Source.PVName || len(claim.Spec.AccessModes) != 1 || claim.Spec.AccessModes[0] != source.AccessMode {
		return kube.ErrOwnership
	}
	pv, err := client.CoreV1().PersistentVolumes().Get(ctx, source.Source.PVName, metav1.GetOptions{})
	if err != nil || pv.DeletionTimestamp != nil || string(pv.UID) != source.Source.PVUID || kube.ContentHash(pv.Spec) != source.Source.SHA256 || pv.Spec.CSI == nil || pv.Spec.CSI.Driver != "driver.longhorn.io" || pv.Spec.CSI.VolumeHandle != source.Handle || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.Namespace != source.Namespace || pv.Spec.ClaimRef.Name != claim.Name || pv.Spec.ClaimRef.UID != claim.UID {
		return kube.ErrOwnership
	}
	return ctx.Err()
}
