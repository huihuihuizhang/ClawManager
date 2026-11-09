package systembackupexecution

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"clawreef/internal/systembackup/kube"
	q "clawreef/internal/systembackup/quiesce"
	d "clawreef/internal/systembackupdispatch"
)

type longhornKeeperRegistration struct {
	Request q.LonghornExt4Request
	JobUID  string
}

func keeperRegistrationName(a d.Authority, plan plannedLonghornClone) string {
	return longhornNativeName(a, "keeper/"+hash(mustLonghornJSON(plan)))
}

func (o *deploymentLonghornCutOwner) keeperRegistration(ctx context.Context, in d.Input, plan plannedLonghornClone, recovery bool) (longhornKeeperRegistration, bool, error) {
	var entry longhornKeeperRegistration
	a := in.Authority
	raw, found, err := o.originalNativeConfig(ctx, in, keeperRegistrationName(a, plan), recovery)
	if err != nil || !found {
		return entry, found, err
	}
	if json.Unmarshal(raw, &entry) != nil || entry.JobUID == "" {
		return entry, false, kube.ErrOwnership
	}
	r := entry.Request
	keeper := r.Keeper
	if r.Action != "register" || keeper == nil || keeper.OriginalPodUID == "" || keeper.PodName == "" || keeper.PodUID == "" || keeper.ContainerID == "" ||
		r.Binding.InstallationID != a.InstallationID || r.Binding.OperationID != a.TaskPublicID || r.Attempt != a.AttemptNo ||
		r.Binding.Generation != a.MaintenanceFencingToken || r.Claim.TaskPublicID != a.TaskPublicID || r.Claim.MaintenanceOwner != a.MaintenanceOwner ||
		r.Claim.EntryRowVersion > a.ClaimRowVersion || !recovery && (r.Claim.Owner != a.ClaimOwner || r.Claim.EntryRowVersion != a.ClaimRowVersion) ||
		r.Binding.Namespace != plan.Original.Namespace || r.Binding.NamespaceUID != plan.Original.NamespaceUID {
		return entry, false, kube.ErrOwnership
	}
	identity, err := q.LonghornExt4SourceIdentity(hash(mustLonghornJSON(plan.Original)), plan.Original.ProviderUID, r.Binding.NodeUID)
	if err != nil || identity != r.SourceIdentity {
		return entry, false, kube.ErrOwnership
	}
	return entry, true, nil
}

func (o *deploymentLonghornCutOwner) BindKeeper(ctx context.Context, in d.Input, plan longhornKeeperPlan, record kube.ResourceRecord, process kube.WorkerProcess) error {
	a := in.Authority
	fence := func(ctx context.Context, tx *sql.Tx) error {
		spec, err := o.owner.Gate.CheckSourceStopTx(ctx, tx, a, plan.Writer, plan.Original)
		if err != nil || spec == nil || !reflect.DeepEqual(*spec, plan.Runtime) {
			return errors.Join(err, kube.ErrOwnership)
		}
		return nil
	}
	check := func(ctx context.Context) error {
		tx, err := o.owner.Gate.Authority.DB.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if err := fence(ctx, tx); err != nil {
			return err
		}
		return o.owner.namespace(ctx)
	}
	if o.checkMaterials() != nil || record.UID == "" || process.Node != plan.Keeper.Node || len(process.Containers) != 1 {
		return kube.ErrOwnership
	}
	if err := check(ctx); err != nil {
		return err
	}
	clone := plan.Source.plan(a, o.owner.Namespace, o.owner.NamespaceUID)
	entry, found, err := o.keeperRegistration(ctx, in, clone, false)
	if err != nil {
		return err
	}
	keeper := q.LonghornExt4Keeper{OriginalPodUID: plan.SourcePodUID, PodName: process.Name, PodUID: process.UID, ContainerID: process.Containers[0]}
	rows, err := o.owner.rows(a)
	if err != nil {
		return err
	}
	runner := kube.Runner{Client: o.owner.Dynamic, Journal: kube.SQLJournal{DB: o.owner.Gate.Authority.DB, Rows: rows, Fence: fence}, CheckFence: check}
	name := keeperRegistrationName(a, clone)
	if !found {
		entry.Request, err = o.newKeeperRequest(ctx, in, clone, fence)
		if err != nil {
			return err
		}
		entry.Request.Keeper = &keeper
		entry.Request.RegistrationBoundarySHA256 = hash(mustLonghornJSON([]any{entry.Request, plan, record.UID, record.Intent.RequestSHA256, process}))
		entry.JobUID = record.UID
	}
	if entry.JobUID != record.UID || *entry.Request.Keeper != keeper ||
		entry.Request.Binding.Node != plan.Keeper.Node || entry.Request.Binding.NodeUID != plan.Keeper.NodeUID {
		return kube.ErrOwnership
	}
	if _, err := runner.Ensure(ctx, "ConfigMap", longhornNativeConfig(o.owner.Namespace, name, a.TaskPublicID, entry)); err != nil {
		return err
	}
	// Registration is idempotent for the original tuple. A lost reply never
	// permits a second request with a different keeper or lease.
	proof, reply, err := o.native.LonghornExt4Transition(ctx, entry.Request)
	if err != nil {
		return err
	}
	if out := proof.Response(); out.Phase != "prepared" || out.NativeState != "rw" {
		return d.ErrNotReady
	}
	_, err = runner.Ensure(ctx, "ConfigMap", longhornNativeConfig(o.owner.Namespace,
		longhornNativeName(a, name+"/reply/"+hash(reply)), a.TaskPublicID, json.RawMessage(reply)))
	return err
}

func (o *deploymentLonghornCutOwner) newKeeperRequest(ctx context.Context, in d.Input, plan plannedLonghornClone, fence func(context.Context, *sql.Tx) error) (q.LonghornExt4Request, error) {
	var zero q.LonghornExt4Request
	a := in.Authority
	tx, err := o.owner.Gate.Authority.DB.BeginTx(ctx, nil)
	if err != nil {
		return zero, err
	}
	defer tx.Rollback()
	if err := fence(ctx, tx); err != nil {
		return zero, err
	}
	var lease, now, hold time.Time
	var epoch uint64
	var registry string
	err = tx.QueryRowContext(ctx, `SELECT b.controller_lease_expires_at,UTC_TIMESTAMP(6),r.hold_until,r.acquire_token,r.registry_sha256
FROM system_backup_v2_backups b JOIN system_backup_v2_runtime_captures r ON r.task_public_id=b.public_id
WHERE b.origin_installation_id=? AND b.public_id=? FOR SHARE`, a.InstallationID, a.TaskPublicID).Scan(&lease, &now, &hold, &epoch, &registry)
	if err != nil || epoch == 0 || !now.Before(lease) || lease.Sub(now) > 300*time.Second || !now.Before(hold) {
		return zero, errors.Join(err, kube.ErrOwnership)
	}
	if err := tx.Rollback(); err != nil {
		return zero, err
	}
	claim := q.LonghornExt4Claim{TaskPublicID: a.TaskPublicID, Owner: a.ClaimOwner, MaintenanceOwner: a.MaintenanceOwner, EntryRowVersion: a.ClaimRowVersion, LeaseObservedAt: now, LeaseExpiresAt: lease}
	source, err := o.nativeSource(ctx, in, plan, claim, hold, epoch, registry)
	if err != nil {
		return zero, err
	}
	source.Provider.Action = "register"
	return source.Provider, nil
}
