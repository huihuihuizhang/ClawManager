package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"clawreef/internal/systembackup/kube"
	q "clawreef/internal/systembackup/quiesce"
	d "clawreef/internal/systembackupdispatch"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type longhornNativeSource struct {
	Plan     plannedLonghornClone
	Provider q.LonghornExt4Request
	Clients  []q.LonghornExt4Request
}

type longhornNativeGrant struct {
	Task                string
	Attempt, Generation uint64
	Sources             []longhornNativeSource
}

func longhornNativeName(a d.Authority, suffix string) string {
	raw, _ := json.Marshal([]any{a.TaskPublicID, a.AttemptNo, a.MaintenanceFencingToken, suffix})
	return "sbk-native-" + hash(raw)[:48]
}

func longhornNativeConfig(namespace, name, task string, value any) *corev1.ConfigMap {
	raw, _ := json.Marshal(value)
	immutable := true
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Labels: map[string]string{kube.OwnerLabel: task}}, Immutable: &immutable, Data: map[string]string{"native.json": string(raw)}}
}

// Reads the existing resource journal, including an uncertain create. It
// never substitutes a newly observed claim for the original native tuple.
func (o *deploymentLonghornCutOwner) originalNativeConfig(ctx context.Context, in d.Input, name string, recovery bool) ([]byte, bool, error) {
	a := in.Authority
	tx, err := o.owner.Gate.Authority.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	if recovery {
		err = o.owner.Gate.Recovery.CheckTx(ctx, tx, a)
	} else {
		guard, bindErr := o.owner.Gate.Authority.Bind(ctx, tx, a)
		err = bindErr
		if err == nil {
			err = guard.Recheck(ctx, tx)
		}
	}
	if err != nil {
		return nil, false, err
	}
	rows, err := o.owner.rows(a)
	if err != nil {
		return nil, false, err
	}
	record, err := rows.Load(ctx, tx, kube.ResourceIntent{Kind: "ConfigMap", Identity: kube.Identity{Namespace: o.owner.Namespace, Name: name}})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var config corev1.ConfigMap
	if json.Unmarshal(record.Intent.RequestJSON, &config) != nil || len(config.Data) != 1 || len(config.BinaryData) != 0 {
		return nil, false, kube.ErrOwnership
	}
	expected := longhornNativeConfig(o.owner.Namespace, name, a.TaskPublicID, json.RawMessage(config.Data["native.json"]))
	intent, err := kube.Intent("ConfigMap", expected)
	if err != nil || !bytes.Equal(intent.RequestJSON, record.Intent.RequestJSON) || intent.RequestSHA256 != record.Intent.RequestSHA256 {
		return nil, false, kube.ErrOwnership
	}
	return []byte(config.Data["native.json"]), true, nil
}

func (o *deploymentLonghornCutOwner) loadNativeGrant(ctx context.Context, in d.Input, plans []plannedLonghornClone, recovery bool) (longhornNativeGrant, bool, error) {
	var grant longhornNativeGrant
	raw, found, err := o.originalNativeConfig(ctx, in, longhornNativeName(in.Authority, "grant"), recovery)
	if err != nil || !found {
		return grant, found, err
	}
	a := in.Authority
	if json.Unmarshal(raw, &grant) != nil || grant.Task != a.TaskPublicID || grant.Attempt != a.AttemptNo || grant.Generation != a.MaintenanceFencingToken || len(grant.Sources) != len(plans) {
		return grant, false, kube.ErrOwnership
	}
	for i, source := range grant.Sources {
		r := source.Provider
		if source.Plan != plans[i] || r.Binding.InstallationID != a.InstallationID || r.Binding.OperationID != a.TaskPublicID || r.Attempt != a.AttemptNo || r.Binding.Generation != a.MaintenanceFencingToken || r.Claim.TaskPublicID != a.TaskPublicID || !recovery && r.Claim.Owner != a.ClaimOwner || r.Claim.MaintenanceOwner != a.MaintenanceOwner || r.Claim.EntryRowVersion > a.ClaimRowVersion {
			return grant, false, kube.ErrOwnership
		}
	}
	return grant, true, nil
}

func (o *deploymentLonghornCutOwner) prepareNativeGrant(ctx context.Context, in d.Input, plans []plannedLonghornClone) (longhornNativeGrant, error) {
	grant, found, err := o.loadNativeGrant(ctx, in, plans, false)
	if err != nil || found {
		return grant, err
	}
	a := in.Authority
	if err = o.owner.Gate.ValidateCollectors(ctx, a); err != nil {
		return grant, err
	}
	tx, err := o.owner.Gate.Authority.DB.BeginTx(ctx, nil)
	if err != nil {
		return grant, err
	}
	defer tx.Rollback()
	guard, err := o.owner.Gate.Authority.Bind(ctx, tx, a)
	if err != nil {
		return grant, err
	}
	var lease, now, hold time.Time
	var generation, epoch uint64
	var writers []byte
	var registry, scope, phase, gateOwner string
	err = tx.QueryRowContext(ctx, `SELECT b.controller_lease_expires_at,UTC_TIMESTAMP(6),r.hold_until,r.gate_generation,g.fencing_token,r.writers_json,r.registry_sha256,r.application_scope,g.phase,COALESCE(g.owner,'') FROM system_backup_v2_backups b JOIN system_backup_v2_runtime_captures r ON r.task_public_id=b.public_id JOIN system_backup_gate g ON g.scope=r.application_scope WHERE b.origin_installation_id=? AND b.public_id=? FOR SHARE`, a.InstallationID, a.TaskPublicID).Scan(&lease, &now, &hold, &generation, &epoch, &writers, &registry, &scope, &phase, &gateOwner)
	if err != nil || phase != "held" || gateOwner != a.TaskPublicID || scope != o.owner.Gate.Authority.ApplicationScope || generation != a.MaintenanceFencingToken || hash(writers) != registry || !now.Before(lease) || lease.Sub(now) > 300*time.Second || !now.Before(hold) || guard.Recheck(ctx, tx) != nil {
		return grant, kube.ErrOwnership
	}
	if err = tx.Rollback(); err != nil {
		return grant, err
	}
	claim := q.LonghornExt4Claim{TaskPublicID: a.TaskPublicID, Owner: a.ClaimOwner, MaintenanceOwner: a.MaintenanceOwner, EntryRowVersion: a.ClaimRowVersion, LeaseObservedAt: now, LeaseExpiresAt: lease}
	grant = longhornNativeGrant{Task: a.TaskPublicID, Attempt: a.AttemptNo, Generation: a.MaintenanceFencingToken}
	for _, plan := range plans {
		source, err := o.captureNativeSource(ctx, in, plan, claim, hold, epoch, registry)
		if err != nil {
			return grant, err
		}
		grant.Sources = append(grant.Sources, source)
	}
	runner, err := o.owner.runner(a, false)
	if err != nil {
		return grant, err
	}
	_, err = runner.Ensure(ctx, "ConfigMap", longhornNativeConfig(o.owner.Namespace, longhornNativeName(a, "grant"), a.TaskPublicID, grant))
	return grant, err
}

func (o *deploymentLonghornCutOwner) nativeTransition(ctx context.Context, in d.Input, request q.LonghornExt4Request, action string, recovery bool) (q.LonghornExt4Response, error) {
	var out q.LonghornExt4Response
	if recovery {
		if err := o.owner.Gate.Recovery.Check(ctx, in.Authority); err != nil {
			return out, err
		}
	} else if err := o.owner.Gate.ValidateCollectors(ctx, in.Authority); err != nil {
		return out, err
	}
	request.Action = action
	marker := longhornNativeActionName(in.Authority, request, action)
	raw, dispatched, err := o.originalNativeConfig(ctx, in, marker, recovery)
	if err != nil {
		return out, err
	}
	if dispatched {
		if !bytes.Equal(raw, mustLonghornJSON(request)) {
			return out, kube.ErrOwnership
		}
		if action != "release" {
			request.Action = "state"
			request.RecoveryBoundarySHA256 = ""
			request.DrainBoundarySHA256 = ""
		}
	} else {
		runner, err := o.owner.runner(in.Authority, recovery)
		if err != nil {
			return out, err
		}
		if _, err = runner.Ensure(ctx, "ConfigMap", longhornNativeConfig(o.owner.Namespace, marker, in.Authority.TaskPublicID, request)); err != nil {
			return out, err
		}
	}
	proof, reply, err := o.native.LonghornExt4Transition(ctx, request)
	if err != nil {
		return out, err
	}
	out = proof.Response()
	runner, err := o.owner.runner(in.Authority, recovery)
	if err != nil {
		return out, err
	}
	_, err = runner.Ensure(ctx, "ConfigMap", longhornNativeConfig(o.owner.Namespace, longhornNativeName(in.Authority, marker+"/reply/"+hash(reply)), in.Authority.TaskPublicID, json.RawMessage(reply)))
	if err != nil {
		return out, err
	}
	return out, nil
}

func longhornNativeActionName(a d.Authority, request q.LonghornExt4Request, action string) string {
	request.Action = action
	return longhornNativeName(a, "action/"+hash(mustLonghornJSON(request)))
}

func mustLonghornJSON(value any) []byte { raw, _ := json.Marshal(value); return raw }
