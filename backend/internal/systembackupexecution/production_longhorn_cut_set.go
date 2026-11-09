package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"time"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	d "clawreef/internal/systembackupdispatch"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

type heldLonghornCutsRecord struct {
	Task, SourceSHA256  string
	Attempt, Generation uint64
	Plans               []plannedLonghornClone
	Pins                []kube.LonghornSnapshotPin
}

func longhornCutSetName(a d.Authority, discovery b.Discovery) string {
	raw, _ := json.Marshal([]any{a.TaskPublicID, a.AttemptNo, a.MaintenanceFencingToken, discovery.SourceSHA256})
	return "sbk-cuts-" + hash(raw)[:48]
}

func longhornCutSetConfig(a d.Authority, discovery b.Discovery, plans []plannedLonghornClone, pins []kube.LonghornSnapshotPin, namespace string) *corev1.ConfigMap {
	raw, _ := json.Marshal(heldLonghornCutsRecord{a.TaskPublicID, discovery.SourceSHA256, a.AttemptNo, a.MaintenanceFencingToken, plans, pins})
	immutable := true
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: longhornCutSetName(a, discovery), Labels: map[string]string{kube.OwnerLabel: a.TaskPublicID}},
		Immutable: &immutable, Data: map[string]string{"cuts.json": string(raw)}}
}

func originalLonghornPinMatches(pin kube.LonghornSnapshotPin, plan plannedLonghornClone) bool {
	expected := plan.Original.pin()
	return pin.Source == expected.Source && pin.AccessMode == expected.AccessMode && pin.NamespaceUID == expected.NamespaceUID &&
		pin.SourceHandle == expected.SourceHandle && pin.ProviderNamespace == expected.ProviderNamespace && pin.ProviderNamespaceUID == expected.ProviderNamespaceUID &&
		pin.Class == expected.Class && pin.ClassUID == expected.ClassUID && pin.ClassSHA == expected.ClassSHA
}

func (o *PublicJobOwner) loadLonghornCutSet(ctx context.Context, in d.Input, discovery b.Discovery, plans []plannedLonghornClone, runner kube.Runner) ([]kube.LonghornSnapshotPin, bool, error) {
	a := in.Authority
	tx, err := o.Gate.Authority.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	rows, err := o.rows(a)
	if err != nil {
		return nil, false, err
	}
	record, err := rows.Load(ctx, tx, kube.ResourceIntent{Kind: "ConfigMap", Identity: kube.Identity{Namespace: o.Namespace, Name: longhornCutSetName(a, discovery)}})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil || record.Deleting || record.Deleted {
		return nil, false, kube.ErrOwnership
	}
	tx.Rollback()
	var config corev1.ConfigMap
	var saved heldLonghornCutsRecord
	if json.Unmarshal(record.Intent.RequestJSON, &config) != nil || json.Unmarshal([]byte(config.Data["cuts.json"]), &saved) != nil ||
		saved.Task != a.TaskPublicID || saved.Attempt != a.AttemptNo || saved.Generation != a.MaintenanceFencingToken ||
		saved.SourceSHA256 != discovery.SourceSHA256 || !reflect.DeepEqual(saved.Plans, plans) || len(saved.Pins) != len(plans) {
		return nil, false, kube.ErrOwnership
	}
	for index, pin := range saved.Pins {
		if !originalLonghornPinMatches(pin, plans[index]) || pin.ProviderSnapshotUID == "" || pin.BackendSnapshotHandle == "" ||
			pin.Snapshot.Intent.Identity != plans[index].Snapshot || pin.Snapshot.UID == "" || pin.CutStart.IsZero() || !pin.CutObservedAt.After(pin.CutStart) {
			return nil, false, kube.ErrOwnership
		}
	}
	expected := longhornCutSetConfig(a, discovery, plans, saved.Pins, o.Namespace)
	intent, err := kube.Intent("ConfigMap", expected)
	if err != nil || intent.Identity != record.Intent.Identity || !bytes.Equal(intent.RequestJSON, record.Intent.RequestJSON) {
		return nil, false, kube.ErrOwnership
	}
	// Reconcile an uncertain ConfigMap acknowledgement using its original
	// journaled request. An observed UID cannot be replaced by a new object.
	if _, err := runner.Ensure(ctx, "ConfigMap", expected); err != nil {
		return nil, false, err
	}
	return saved.Pins, true, nil
}

func (o *PublicJobOwner) releaseLonghornCutSet(ctx context.Context, in d.Input, plans []plannedLonghornClone) error {
	recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	return o.longhornCutOwner.Release(recovery, in, plans)
}

func (o *PublicJobOwner) captureLonghornCutSet(ctx context.Context, in d.Input, discovery b.Discovery, plans []plannedLonghornClone, runner kube.Runner) (pins []kube.LonghornSnapshotPin, resultErr error) {
	// Even a partially acquired cohort belongs to the original recovery owner.
	// It decides whether an uncertain native operation can be reversed.
	defer func() { resultErr = errors.Join(resultErr, o.releaseLonghornCutSet(ctx, in, plans)) }()
	cuts, err := o.longhornCutOwner.Hold(ctx, in, plans)
	if err != nil {
		return nil, err
	}
	if len(cuts) != len(plans) {
		return nil, kube.ErrOwnership
	}
	for index, cut := range cuts {
		if cut.Target != plans[index].Snapshot || !originalLonghornPinMatches(cut.Pin, plans[index]) {
			return nil, kube.ErrOwnership
		}
	}
	err = wait.PollUntilContextCancel(ctx, 500*time.Millisecond, true, func(attempt context.Context) (bool, error) {
		var err error
		cuts, err = kube.ReconcileLonghornCaptureCuts(attempt, o.Client, runner, cuts)
		if errors.Is(err, kube.ErrPending) {
			return false, nil
		}
		return err == nil, err
	})
	if err != nil {
		return nil, err
	}
	for _, cut := range cuts {
		pins = append(pins, cut.Pin)
	}
	_, err = runner.Ensure(ctx, "ConfigMap", longhornCutSetConfig(in.Authority, discovery, plans, pins, o.Namespace))
	return pins, err
}

func (o *PublicJobOwner) prepareLonghornCutSet(ctx context.Context, in d.Input, discovery b.Discovery, selected map[string]plannedLonghornClone) (map[string]kube.LonghornSnapshotPin, error) {
	o.longhornCutMu.Lock()
	defer o.longhornCutMu.Unlock()
	if ctx.Err() != nil || o.longhornCutOwner == nil || len(selected) == 0 || len(selected) > 9996 {
		return nil, kube.ErrOwnership
	}
	plans, err := o.orderedLonghornPlans(in.Authority, selected)
	if err != nil {
		return nil, err
	}
	runner, err := o.runner(in.Authority, false)
	if err != nil {
		return nil, err
	}
	pins, found, err := o.loadLonghornCutSet(ctx, in, discovery, plans, runner)
	if err != nil {
		return nil, err
	}
	if found {
		err = o.releaseLonghornCutSet(ctx, in, plans)
	} else {
		pins, err = o.captureLonghornCutSet(ctx, in, discovery, plans, runner)
	}
	if err != nil {
		return nil, err
	}
	out := make(map[string]kube.LonghornSnapshotPin, len(pins))
	for index, pin := range pins {
		out[plans[index].Snapshot.Namespace+"/"+plans[index].Snapshot.Name] = pin
	}
	return out, nil
}

func (o *PublicJobOwner) orderedLonghornPlans(a d.Authority, selected map[string]plannedLonghornClone) ([]plannedLonghornClone, error) {
	unique := map[string]plannedLonghornClone{}
	for _, plan := range selected {
		if plan != plan.Original.plan(a, o.Namespace, o.NamespaceUID) {
			return nil, kube.ErrOwnership
		}
		key := plan.Snapshot.Namespace + "/" + plan.Snapshot.Name
		if previous, exists := unique[key]; exists && previous != plan {
			return nil, kube.ErrOwnership
		}
		unique[key] = plan
	}
	plans := make([]plannedLonghornClone, 0, len(unique))
	for _, plan := range unique {
		plans = append(plans, plan)
	}
	sort.Slice(plans, func(i, j int) bool {
		return plans[i].Snapshot.Namespace+"/"+plans[i].Snapshot.Name < plans[j].Snapshot.Namespace+"/"+plans[j].Snapshot.Name
	})
	return plans, nil
}
