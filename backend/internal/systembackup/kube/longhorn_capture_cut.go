package kube

import (
	"context"
	"errors"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
)

// LonghornCaptureHold is supplied by the authenticated provider owner for the
// exact task and source volume. Recheck samples the same active hold and must
// return the observation time in the provider's clock domain.
type LonghornCaptureHold struct {
	StartedAt time.Time
	Recheck   func(context.Context) (time.Time, error)
}

type LonghornCaptureCut struct {
	Pin    LonghornSnapshotPin
	Target Identity
	Hold   LonghornCaptureHold
	// The signed source scope supplies a runner for this exact frozen request,
	// using the same controller client and original task journal.
	SourceRunner *Runner
}

// All selected sources must still be held before creating either snapshot.
// Pending cuts retain their original journaled request and can be reconciled.
func ReconcileLonghornCaptureCuts(ctx context.Context, client kubernetes.Interface, runner Runner, cuts []LonghornCaptureCut) ([]LonghornCaptureCut, error) {
	if len(cuts) == 0 || len(cuts) > 9996 || runner.CheckFence == nil || runner.CheckFence(ctx) != nil {
		return cuts, ErrJournal
	}
	checkAll := func() error {
		seen := map[string]bool{}
		for _, cut := range cuts {
			key := cut.Pin.ProviderNamespaceUID + "/" + cut.Pin.SourceHandle
			if seen[key] || cut.Pin.SourceHandle == "" || cut.Hold.StartedAt.IsZero() || cut.Hold.Recheck == nil {
				return ErrOwnership
			}
			seen[key] = true
			if cut.SourceRunner != nil {
				if err := cut.SourceRunner.ready(ctx); err != nil {
					return err
				}
			}
			observed, err := cut.Hold.Recheck(ctx)
			if err != nil {
				return err
			}
			if observed.Before(cut.Hold.StartedAt) {
				return ErrOwnership
			}
		}
		return runner.CheckFence(ctx)
	}
	if err := checkAll(); err != nil {
		return cuts, err
	}
	pending := false
	for index := range cuts {
		cut := &cuts[index]
		sourceRunner := runner
		if cut.SourceRunner != nil {
			sourceRunner = *cut.SourceRunner
		}
		pin, err := ReconcileLonghornCaptureCut(ctx, client, sourceRunner, cut.Pin, cut.Target, cut.Hold)
		cut.Pin = pin
		if errors.Is(err, ErrPending) {
			pending = true
		} else if err != nil {
			return cuts, err
		}
	}
	if err := checkAll(); err != nil {
		return cuts, err
	}
	if pending {
		return cuts, ErrPending
	}
	return cuts, nil
}

// ReconcileLonghornCaptureCut dispatches only a journaled source snapshot.
// A ready CSI object alone is insufficient. The native snapshot and current
// provider hold must corroborate the same backend cut before clone admission.
func ReconcileLonghornCaptureCut(ctx context.Context, client kubernetes.Interface, runner Runner, pin LonghornSnapshotPin, target Identity, hold LonghornCaptureHold) (LonghornSnapshotPin, error) {
	if ctx == nil || !target.valid() || hold.StartedAt.IsZero() || hold.Recheck == nil || runner.CheckFence == nil ||
		(pin.Snapshot.Intent.Kind != "" && pin.Snapshot.Intent.Identity != target) ||
		(!pin.CutStart.IsZero() && !pin.CutStart.Equal(hold.StartedAt)) {
		return pin, ErrResource
	}
	fence := runner.CheckFence
	check := func(ctx context.Context) (time.Time, error) {
		if err := fence(ctx); err != nil {
			return time.Time{}, err
		}
		observed, err := hold.Recheck(ctx)
		if err != nil {
			return time.Time{}, err
		}
		if observed.Before(hold.StartedAt) || !pin.CutObservedAt.IsZero() && observed.Before(pin.CutObservedAt) {
			return time.Time{}, ErrOwnership
		}
		return observed, ctx.Err()
	}
	observed, err := check(ctx)
	if err != nil {
		return pin, err
	}
	// The engine can report a whole-second creation time. Wait for a clock tick
	// inside the hold before dispatching, so old cuts are never rounded in.
	if !observed.Truncate(time.Second).After(hold.StartedAt) {
		return pin, ErrPending
	}
	if _, _, err := verifyLonghornSnapshotSource(ctx, client, runner.Client, pin, target.Namespace); err != nil {
		return pin, err
	}
	runner.CheckFence = func(ctx context.Context) error { _, err := check(ctx); return err }
	request, err := Snapshot(target, pin.Source.Name, pin.Class, true)
	if err != nil {
		return pin, err
	}
	pin.Snapshot, err = runner.Ensure(ctx, "VolumeSnapshot", request)
	if err != nil {
		return pin, err
	}
	snapshot, err := runner.Client.Resource(longhornSnapshotResource("volumesnapshots")).Namespace(target.Namespace).Get(ctx, target.Name, metav1.GetOptions{})
	if err != nil || !owned(pin.Snapshot, snapshot) || snapshot.GetDeletionTimestamp() != nil {
		return pin, ErrOwnership
	}
	if _, exists, err := unstructured.NestedFieldNoCopy(snapshot.Object, "status", "error"); exists || err != nil {
		return pin, ErrOwnership
	}
	if !SnapshotReady(snapshot, target, pin.Snapshot.UID, pin.Source.Name) {
		return pin, ErrPending
	}
	contentName := longhornSnapshotString(snapshot, "status", "boundVolumeSnapshotContentName")
	content, err := runner.Client.Resource(longhornSnapshotResource("volumesnapshotcontents")).Get(ctx, contentName, metav1.GetOptions{})
	if err != nil {
		return pin, ErrOwnership
	}
	handle := longhornSnapshotString(content, "status", "snapshotHandle")
	if pin.BackendSnapshotHandle != "" && pin.BackendSnapshotHandle != handle {
		return pin, ErrOwnership
	}
	candidate := pin
	candidate.BackendSnapshotHandle, candidate.CutStart = handle, hold.StartedAt
	candidate.CutObservedAt, err = check(ctx)
	if err != nil {
		return pin, err
	}
	cut, err := verifyLonghornSourceCut(ctx, client, runner.Client, candidate)
	if err != nil {
		return pin, err
	}
	backendName, _ := strings.CutPrefix(handle, "snap://"+candidate.SourceHandle+"/")
	// The default sidecar naming contract ties the backend cut to this UID.
	if backendName != "snapshot-"+pin.Snapshot.UID {
		return pin, ErrOwnership
	}
	provider, err := client.CoreV1().Namespaces().Get(ctx, candidate.ProviderNamespace, metav1.GetOptions{})
	if err != nil || string(provider.UID) != candidate.ProviderNamespaceUID || candidate.ProviderNamespaceUID == "" || provider.DeletionTimestamp != nil {
		return pin, ErrOwnership
	}
	nativeSnapshots := schema.GroupVersionResource{Group: "longhorn.io", Version: "v1beta2", Resource: "snapshots"}
	native, err := runner.Client.Resource(nativeSnapshots).Namespace(candidate.ProviderNamespace).Get(ctx, backendName, metav1.GetOptions{})
	if err != nil || native.GetUID() == "" || native.GetDeletionTimestamp() != nil || longhornSnapshotString(native, "spec", "volume") != candidate.SourceHandle {
		return pin, ErrOwnership
	}
	ready, _, _ := unstructured.NestedBool(native.Object, "status", "readyToUse")
	removed, _, _ := unstructured.NestedBool(native.Object, "status", "markRemoved")
	created, err := time.Parse(time.RFC3339Nano, longhornSnapshotString(native, "status", "creationTime"))
	if err != nil || !ready || removed || !created.Equal(cut.createdAt) || longhornSnapshotString(native, "status", "error") != "" ||
		candidate.ProviderSnapshotUID != "" && candidate.ProviderSnapshotUID != string(native.GetUID()) {
		return pin, ErrOwnership
	}
	if _, err := check(ctx); err != nil {
		return pin, err
	}
	candidate.ProviderSnapshotUID = string(native.GetUID())
	return candidate, nil
}
