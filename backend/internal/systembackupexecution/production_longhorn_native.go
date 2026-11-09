package systembackupexecution

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"time"

	"clawreef/internal/systembackup/kube"
	q "clawreef/internal/systembackup/quiesce"
	d "clawreef/internal/systembackupdispatch"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (o *deploymentLonghornCutOwner) nativeSource(ctx context.Context, in d.Input, plan plannedLonghornClone, claim q.LonghornExt4Claim, hold time.Time, epoch uint64, registry string) (longhornNativeSource, error) {
	out := longhornNativeSource{Plan: plan}
	source := plan.Original
	digest := hash(mustLonghornJSON(source))
	var selected *q.LonghornExt4SourceCoordinates
	for _, material := range o.materials {
		for _, candidate := range material.Sources {
			if candidate.OriginalSourceSHA256 != digest {
				continue
			}
			if selected != nil || candidate.VolumeHandle != source.Handle || candidate.PVCUID != source.Source.UID || candidate.PVUID != source.Source.PVUID || candidate.ProviderNamespaceUID != source.ProviderUID || candidate.Binding.Namespace != source.Namespace || candidate.Binding.NamespaceUID != source.NamespaceUID {
				return out, kube.ErrOwnership
			}
			copy := candidate
			selected = &copy
		}
	}
	if selected == nil {
		return out, d.ErrNotReady
	}
	request := func(binding q.ObservationBinding, identity string) q.LonghornExt4Request {
		binding.OperationID = in.Authority.TaskPublicID
		binding.ReservationID = hash(mustLonghornJSON([]any{in.Authority.TaskPublicID, in.Authority.AttemptNo, claim, digest}))
		binding.InventorySHA256 = registry
		binding.Generation = in.Authority.MaintenanceFencingToken
		binding.FenceEpoch = epoch
		binding.ExpiresAt = hold
		boundary := hash(mustLonghornJSON([]any{binding, claim, plan}))
		return q.LonghornExt4Request{Version: q.LonghornExt4Protocol, Binding: binding, SourceIdentity: identity, Attempt: in.Authority.AttemptNo, Claim: claim, RegistrationBoundarySHA256: boundary}
	}
	identity, err := q.LonghornExt4SourceIdentity(digest, source.ProviderUID, selected.Binding.NodeUID)
	if err != nil || selected.Identity != "" && selected.Identity != identity || selected.Binding.InstallationID != in.Authority.InstallationID || selected.Binding.Kind != q.LonghornExt4Protocol {
		return out, kube.ErrOwnership
	}
	out.Provider = request(selected.Binding, identity)
	if source.AccessMode != corev1.ReadWriteMany {
		return out, nil
	}
	// Enumerate actual mounts without label filtering. A declared client with
	// no installed Node/mount grant cannot silently disappear from the drain.
	pods, err := o.owner.Client.CoreV1().Pods(source.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil || pods.Continue != "" {
		return out, d.ErrNotReady
	}
	for _, pod := range pods.Items {
		volumes := map[string]bool{}
		for _, v := range pod.Spec.Volumes {
			if v.PersistentVolumeClaim != nil && v.PersistentVolumeClaim.ClaimName == source.Source.Name {
				volumes[v.Name] = true
			}
		}
		if len(volumes) == 0 {
			continue
		}
		statuses := map[string]corev1.ContainerStatus{}
		for _, status := range append(append(append([]corev1.ContainerStatus{}, pod.Status.ContainerStatuses...), pod.Status.InitContainerStatuses...), pod.Status.EphemeralContainerStatuses...) {
			statuses[status.Name] = status
		}
		for _, container := range append(append(append([]corev1.Container{}, pod.Spec.Containers...), pod.Spec.InitContainers...), ephemeralLonghornContainers(pod.Spec.EphemeralContainers)...) {
			status := statuses[container.Name]
			if status.State.Running == nil {
				continue
			}
			for _, mount := range container.VolumeMounts {
				if !volumes[mount.Name] {
					continue
				}
				var found *q.LonghornRWXClientCoordinates
				for _, material := range o.materials {
					for _, candidate := range material.Clients {
						if candidate.OriginalSourceSHA256 == digest && candidate.Binding.Node == pod.Spec.NodeName && candidate.PodNamespace == pod.Namespace && candidate.MountPoint == mount.MountPath {
							if found != nil || candidate.VolumeHandle != source.Handle || candidate.PVCUID != source.Source.UID || candidate.PVUID != source.Source.PVUID || candidate.ProviderNamespaceUID != source.ProviderUID || candidate.Binding.NamespaceUID != source.NamespaceUID || candidate.Binding.InstallationID != in.Authority.InstallationID {
								return out, kube.ErrOwnership
							}
							copy := candidate
							found = &copy
						}
					}
				}
				if found == nil || status.ContainerID == "" || pod.UID == "" {
					return out, d.ErrNotReady
				}
				identity, err := q.LonghornExt4SourceIdentity(digest, source.ProviderUID, found.Binding.NodeUID)
				if err != nil {
					return out, err
				}
				client := request(found.Binding, identity)
				client.ClientPodUID = string(pod.UID)
				client.ClientPodName = pod.Name
				client.ClientContainerID = status.ContainerID
				out.Clients = append(out.Clients, client)
			}
		}
	}
	sort.Slice(out.Clients, func(i, j int) bool {
		return string(mustLonghornJSON(out.Clients[i])) < string(mustLonghornJSON(out.Clients[j]))
	})
	return out, nil
}

func ephemeralLonghornContainers(items []corev1.EphemeralContainer) []corev1.Container {
	var out []corev1.Container
	for _, item := range items {
		out = append(out, corev1.Container{Name: item.Name, VolumeMounts: item.VolumeMounts})
	}
	return out
}

func (o *deploymentLonghornCutOwner) Hold(ctx context.Context, in d.Input, plans []plannedLonghornClone) ([]kube.LonghornCaptureCut, error) {
	if o.owner.longhornExecutor == nil || o.checkMaterials() != nil {
		return nil, d.ErrNotReady
	}
	grant, err := o.prepareNativeGrant(ctx, in, plans)
	if err != nil {
		return nil, err
	}
	for _, source := range grant.Sources {
		current, err := o.captureNativeSource(ctx, in, source.Plan, source.Provider.Claim, source.Provider.Binding.ExpiresAt, source.Provider.Binding.FenceEpoch, source.Provider.Binding.InventorySHA256)
		if err != nil || !reflect.DeepEqual(current, source) {
			return nil, errors.Join(err, kube.ErrOwnership)
		}
	}
	// Client syncs must finish for the complete cohort before any superblock
	// becomes read-only. The existing original writer gate remains held.
	for _, source := range grant.Sources {
		for _, client := range source.Clients {
			for _, action := range []string{"register-client", "sync-client"} {
				if err = o.owner.Gate.ValidateCollectors(ctx, in.Authority); err != nil {
					return nil, err
				}
				client.Action = action
				if _, _, err = o.native.LonghornExt4Transition(ctx, client); err != nil {
					return nil, err
				}
			}
		}
	}
	var cuts []kube.LonghornCaptureCut
	for _, source := range grant.Sources {
		var registered q.LonghornExt4Response
		var err error
		if source.Provider.Keeper == nil {
			registered, err = o.nativeTransition(ctx, in, source.Provider, "register", false)
		} else {
			request := source.Provider
			request.Action = "state"
			proof, _, callErr := o.native.LonghornExt4Transition(ctx, request)
			registered, err = proof.Response(), callErr
			if err == nil && registered.Phase == "prepared" && registered.NativeState != "rw" {
				err = d.ErrNotReady
			}
		}
		if err != nil || registered.Phase != "prepared" && registered.Phase != "held" {
			return nil, errors.Join(err, d.ErrNotReady)
		}
		request := source.Provider
		request.DrainBoundarySHA256 = hash(mustLonghornJSON(source.Clients))
		if _, err = o.nativeTransition(ctx, in, request, "acquire", false); err != nil {
			return nil, err
		}
		proof, err := o.checkHeld(ctx, in, source.Provider)
		if err != nil {
			return nil, err
		}
		runner, err := o.owner.longhornExecutor.SourceRunner(ctx, in, source.Plan)
		if err != nil {
			return nil, err
		}
		original := source.Provider
		cuts = append(cuts, kube.LonghornCaptureCut{Pin: source.Plan.Original.pin(), Target: source.Plan.Snapshot, SourceRunner: &runner, Hold: kube.LonghornCaptureHold{StartedAt: proof.StartedAt, Recheck: func(check context.Context) (time.Time, error) {
			current, err := o.checkHeld(check, in, original)
			return current.HeldObservedAt, err
		}}})
	}
	return cuts, nil
}

func (o *deploymentLonghornCutOwner) captureNativeSource(ctx context.Context, in d.Input, plan plannedLonghornClone, claim q.LonghornExt4Claim, hold time.Time, epoch uint64, registry string) (longhornNativeSource, error) {
	if plan.Original.AccessMode == corev1.ReadWriteOnce && plan.Original.Namespace != o.owner.Namespace {
		entry, found, err := o.keeperRegistration(ctx, in, plan, false)
		if err != nil || !found {
			return longhornNativeSource{}, errors.Join(err, d.ErrNotReady)
		}
		if entry.Request.Binding.InventorySHA256 != registry || !entry.Request.Binding.ExpiresAt.Equal(hold) {
			return longhornNativeSource{}, kube.ErrOwnership
		}
		return longhornNativeSource{Plan: plan, Provider: entry.Request}, nil
	}
	return o.nativeSource(ctx, in, plan, claim, hold, epoch, registry)
}

func (o *deploymentLonghornCutOwner) checkHeld(ctx context.Context, in d.Input, request q.LonghornExt4Request) (q.LonghornExt4Response, error) {
	if err := o.owner.Gate.ValidateCollectors(ctx, in.Authority); err != nil {
		return q.LonghornExt4Response{}, err
	}
	request.Action = "check-held"
	request.RegistrationBoundarySHA256 = ""
	proof, _, err := o.native.LonghornExt4Transition(ctx, request)
	if err != nil {
		return q.LonghornExt4Response{}, err
	}
	return proof.Response(), nil
}

func (o *deploymentLonghornCutOwner) Release(ctx context.Context, in d.Input, plans []plannedLonghornClone) error {
	if err := o.owner.Gate.Recovery.Check(ctx, in.Authority); err != nil {
		return err
	}
	grant, found, err := o.loadNativeGrant(ctx, in, plans, true)
	if err != nil {
		return err
	}
	if !found {
		// The keeper may have been registered before the original writer
		// stopped. Recover that same request even without a cohort grant.
		for _, plan := range plans {
			entry, exists, err := o.keeperRegistration(ctx, in, plan, true)
			if err != nil {
				return err
			}
			if exists {
				grant.Sources = append(grant.Sources, longhornNativeSource{Plan: plan, Provider: entry.Request})
			}
		}
	}
	var failures []error
	for _, source := range grant.Sources {
		if source.Provider.Keeper == nil {
			_, dispatched, err := o.originalNativeConfig(ctx, in, longhornNativeActionName(in.Authority, source.Provider, "register"), true)
			if err != nil {
				failures = append(failures, err)
				continue
			}
			if !dispatched {
				continue
			}
		}
		request := source.Provider
		request.RecoveryBoundarySHA256 = hash(mustLonghornJSON(source))
		request.RegistrationBoundarySHA256 = ""
		out, err := o.nativeTransition(ctx, in, request, "release", true)
		if err == nil && (out.Phase != "released" || (out.NativeState != "rw" && out.NativeState != "thaw-acknowledged")) {
			err = d.ErrNotReady
		}
		if err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}
