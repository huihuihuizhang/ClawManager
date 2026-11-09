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
	"k8s.io/apimachinery/pkg/util/wait"
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
	return record, true, o.Gate.Recovery.CheckTx(ctx, tx, a)
}
