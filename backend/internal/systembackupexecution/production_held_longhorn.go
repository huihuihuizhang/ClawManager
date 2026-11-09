package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	d "clawreef/internal/systembackupdispatch"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

type plannedLonghornClone struct {
	Original originalLonghornSource
	Snapshot kube.Identity
	Target   kube.LonghornCaptureClone
}

// The owner holds all original sources before either cut. Release uses the
// original recovery authority and the owner's durable operation records.
type heldLonghornCutOwner interface {
	Hold(context.Context, d.Input, []plannedLonghornClone) ([]kube.LonghornCaptureCut, error)
	Release(context.Context, d.Input, []plannedLonghornClone) error
	ContentRunner(context.Context, d.Input, plannedLonghornClone, kube.LonghornSnapshotPin) (kube.Runner, error)
}

type heldLonghornMountRecord struct {
	Task, SourceSHA256, JobSHA256 string
	Attempt, Generation           uint64
	Binding                       kube.LonghornSnapshotBinding
}

func heldLonghornMountName(a d.Authority, part b.JobPart) string {
	raw, _ := json.Marshal([]any{a.TaskPublicID, a.AttemptNo, a.MaintenanceFencingToken, part.Intent.JobUnitKey})
	return "sbk-held-" + hash(raw)[:48]
}

func heldLonghornMountConfig(a d.Authority, discovery b.Discovery, part b.JobPart, binding kube.LonghornSnapshotBinding) *corev1.ConfigMap {
	raw, _ := json.Marshal(heldLonghornMountRecord{a.TaskPublicID, discovery.SourceSHA256, part.Intent.SpecSHA256, a.AttemptNo, a.MaintenanceFencingToken, binding})
	immutable := true
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: part.Intent.Namespace, Name: heldLonghornMountName(a, part), Labels: map[string]string{kube.OwnerLabel: a.TaskPublicID}},
		Immutable: &immutable, Data: map[string]string{"binding.json": string(raw)}}
}

func (o *PublicJobOwner) prepareHeldLonghornMount(ctx context.Context, in d.Input, discovery b.Discovery, part b.JobPart) error {
	if o.productionSource == nil || supportedPublicCapture(in) == nil {
		return nil
	}
	var source b.SourceInventory
	var metadata productionCaptureMetadata
	if json.Unmarshal(discovery.Source, &source) != nil || decodeMetadataCanonical(source.CaptureMetadata, &metadata) != nil {
		return d.ErrNotReady
	}
	selection, ok := metadata.LonghornClones[part.Part]
	if !ok {
		return nil
	}
	a := in.Authority
	if o.longhornCutOwner == nil || a.TaskType != "backup" || selection.Target.NamespaceUID != o.NamespaceUID || selection.Target.Claim.Namespace != o.Namespace || selection.Target.Claim.Owner != a.TaskPublicID ||
		selection != selection.Original.plan(a, o.Namespace, o.NamespaceUID) {
		return d.ErrNotReady
	}
	var job batchv1.Job
	if json.Unmarshal(part.Intent.SpecJSON, &job) != nil {
		return d.ErrNotReady
	}
	held, cancel := context.WithDeadline(ctx, discovery.HoldUntil)
	defer cancel()
	runner, err := o.runner(a, false)
	if err != nil {
		return err
	}
	pins, err := o.prepareLonghornCutSet(held, in, discovery, metadata.LonghornClones)
	if err != nil {
		return err
	}
	pin, exists := pins[selection.Snapshot.Namespace+"/"+selection.Snapshot.Name]
	if !exists {
		return kube.ErrOwnership
	}
	cluster, err := o.longhornCutOwner.ContentRunner(held, in, selection, pin)
	if err != nil {
		return err
	}
	return wait.PollUntilContextCancel(held, 500*time.Millisecond, true, func(attempt context.Context) (bool, error) {
		var binding kube.LonghornSnapshotBinding
		pin, binding, err = kube.ReconcileLonghornCaptureJob(attempt, o.Client, runner, cluster, pin, selection.Target, &job)
		if errors.Is(err, kube.ErrPending) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		_, err := runner.Ensure(attempt, "ConfigMap", heldLonghornMountConfig(a, discovery, part, binding))
		return err == nil, err
	})
}

func (o *PublicJobOwner) readHeldLonghornMount(ctx context.Context, a d.Authority, discovery b.Discovery, part b.JobPart, selection plannedLonghornClone) (kube.MountIdentity, error) {
	var mount kube.MountIdentity
	if ctx == nil || a.TaskType != "backup" || selection.Target.Claim.Owner != a.TaskPublicID || selection.Target.Claim.Namespace != part.Intent.Namespace || selection.Target.NamespaceUID != o.NamespaceUID {
		return mount, kube.ErrOwnership
	}
	name := heldLonghornMountName(a, part)
	tx, err := o.Gate.Authority.DB.BeginTx(ctx, nil)
	if err != nil {
		return mount, err
	}
	defer tx.Rollback()
	rows, err := o.rows(a)
	if err != nil {
		return mount, err
	}
	record, err := rows.Load(ctx, tx, kube.ResourceIntent{Kind: "ConfigMap", Identity: kube.Identity{Namespace: part.Intent.Namespace, Name: name}})
	if err != nil || !record.CreateDispatched || record.UID == "" || record.Deleting || record.Deleted {
		return mount, kube.ErrOwnership
	}
	tx.Rollback()
	var config corev1.ConfigMap
	var saved heldLonghornMountRecord
	if json.Unmarshal(record.Intent.RequestJSON, &config) != nil || json.Unmarshal([]byte(config.Data["binding.json"]), &saved) != nil {
		return mount, kube.ErrOwnership
	}
	binding := saved.Binding
	if binding.SnapshotUID == "" || binding.ContentUID == "" || !formalCandidateDigest(binding.ContentSHA256) || binding.ProviderCloneUID == "" || binding.ProviderSnapshotUID == "" || binding.CreatedAt.IsZero() || binding.Clone.Name != selection.Target.Claim.Name {
		return mount, kube.ErrOwnership
	}
	expected, err := kube.Intent("ConfigMap", heldLonghornMountConfig(a, discovery, part, binding))
	if err != nil || expected.Identity != record.Intent.Identity || expected.RequestSHA256 != record.Intent.RequestSHA256 || !bytes.Equal(expected.RequestJSON, record.Intent.RequestJSON) {
		return mount, kube.ErrOwnership
	}
	current, err := o.Client.CoreV1().ConfigMaps(part.Intent.Namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil || current.DeletionTimestamp != nil || string(current.UID) != record.UID || current.Immutable == nil || !*current.Immutable ||
		current.Labels[kube.OwnerLabel] != a.TaskPublicID || current.Annotations[kube.RequestHashAnnotation] != record.Intent.RequestSHA256 || len(current.Data) != 1 || len(current.BinaryData) != 0 || current.Data["binding.json"] != config.Data["binding.json"] {
		return mount, kube.ErrOwnership
	}
	return binding.Clone, nil
}
