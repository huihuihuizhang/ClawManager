package systembackupexecution

import (
	"context"
	"reflect"
	"strconv"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackupinstallationowner/install"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
)

// The operator selects storage by name. The original read authority obtains
// UIDs, fingerprints and volume handles before the existing signing step.
type OriginalLonghornStorageSelection struct {
	ProviderNamespace string
	SnapshotClass     string
	CloneClass        string
}

func observeOriginalLonghornSources(ctx context.Context, clients *productionMetadataClients, cfg DeploymentConfig, inventory b.SourceInventory, scope *productionPersistentMountScope, selection *OriginalLonghornStorageSelection) (map[string]originalLonghornSource, error) {
	if selection == nil {
		if scope != nil && len(scope.RunningTenantPro) != 0 {
			return nil, install.ErrInstall
		}
		return nil, nil
	}
	if scope == nil || clients.API == nil || clients.Dynamic == nil || inventory.TeamFacts == nil ||
		len(validation.IsDNS1123Label(selection.ProviderNamespace)) != 0 ||
		len(validation.IsDNS1123Subdomain(selection.SnapshotClass)) != 0 ||
		len(validation.IsDNS1123Subdomain(selection.CloneClass)) != 0 {
		return nil, install.ErrInstall
	}

	api := clients.API
	options := metav1.GetOptions{}
	provider, err := api.CoreV1().Namespaces().Get(ctx, selection.ProviderNamespace, options)
	if err != nil || provider.UID == "" || provider.DeletionTimestamp != nil {
		return nil, install.ErrInstall
	}
	snapshotClasses := schema.GroupVersionResource{Group: "snapshot.storage.k8s.io", Version: "v1", Resource: "volumesnapshotclasses"}
	snapshot, err := clients.Dynamic.Resource(snapshotClasses).Get(ctx, selection.SnapshotClass, options)
	if err != nil || snapshot.GetUID() == "" {
		return nil, install.ErrInstall
	}
	clone, err := api.StorageV1().StorageClasses().Get(ctx, selection.CloneClass, options)
	if err != nil || clone.UID == "" {
		return nil, install.ErrInstall
	}
	target := kube.LonghornCaptureClone{
		Claim:        kube.Identity{Namespace: cfg.Namespace, Name: cfg.StagingClaim, Owner: cfg.InstallationID},
		NamespaceUID: cfg.NamespaceUID,
		Class:        clone.Name,
		ClassUID:     string(clone.UID),
		ClassSHA256:  kube.ContentHash([]any{clone.Provisioner, clone.Parameters, clone.ReclaimPolicy, clone.VolumeBindingMode, clone.MountOptions, clone.AllowedTopologies}),
	}
	common := originalLonghornSource{
		ProviderNamespace: provider.Name, ProviderUID: string(provider.UID),
		SnapshotClass: snapshot.GetName(), SnapshotClassUID: string(snapshot.GetUID()),
		SnapshotClassSHA256: kube.ContentHash([]any{snapshot.Object["driver"], snapshot.Object["deletionPolicy"], snapshot.Object["parameters"]}),
		CloneClass:          target.Class, CloneClassUID: target.ClassUID, CloneClassSHA256: target.ClassSHA256,
	}

	out := map[string]originalLonghornSource{}
	byClaim := map[[2]string]originalLonghornSource{}
	add := func(part, namespace, name string, expected *kube.MountIdentity, required bool) error {
		key := [2]string{namespace, name}
		source, found := byClaim[key]
		if !found {
			claim, err := api.CoreV1().PersistentVolumeClaims(namespace).Get(ctx, name, options)
			if err != nil || claim.Spec.VolumeName == "" || claim.Status.Phase != corev1.ClaimBound {
				return install.ErrInstall
			}
			pv, err := api.CoreV1().PersistentVolumes().Get(ctx, claim.Spec.VolumeName, options)
			if err != nil || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID != claim.UID || pv.Spec.ClaimRef.Namespace != namespace || pv.Spec.ClaimRef.Name != name {
				return install.ErrInstall
			}
			if pv.Spec.CSI != nil && pv.Spec.CSI.Driver == "driver.longhorn.io" {
				ns, err := api.CoreV1().Namespaces().Get(ctx, namespace, options)
				if err != nil || len(claim.Spec.AccessModes) != 1 {
					return install.ErrInstall
				}
				source = common
				source.Namespace, source.NamespaceUID = namespace, string(ns.UID)
				source.Source = kube.MountIdentity{Volume: "workspace", Kind: "PersistentVolumeClaim", Name: name, UID: string(claim.UID), PVName: pv.Name, PVUID: string(pv.UID), SHA256: kube.ContentHash(pv.Spec)}
				source.Handle, source.AccessMode = pv.Spec.CSI.VolumeHandle, claim.Spec.AccessModes[0]
				if err := kube.VerifyLonghornCaptureSource(ctx, api, clients.Dynamic, source.pin(), namespace, target); err != nil {
					return err
				}
			}
			byClaim[key] = source
		}
		if source.Handle == "" {
			if required {
				return install.ErrInstall
			}
			return nil
		}
		if expected != nil && source.Source != *expected {
			return install.ErrInstall
		}
		if namespace == cfg.Namespace && name == cfg.Workspace.Claim {
			pinned := false
			for _, pin := range cfg.Security.Volumes {
				pin.Volume = "workspace"
				pinned = pinned || pin == source.Source
			}
			if !pinned {
				return install.ErrInstall
			}
		}
		if _, exists := out[part]; exists || len(out) >= 9996 {
			return install.ErrInstall
		}
		out[part] = source
		return nil
	}

	instances := make(map[int]b.InstanceIdentity, len(inventory.Instances))
	for _, instance := range inventory.Instances {
		instances[instance.ID] = instance
		if instance.Status != "running" || deferredRuntimeTestInstance(cfg, instance) {
			continue
		}
		part := "instance_" + strconv.Itoa(instance.ID) + "_workspace"
		if tenant := runningTenantProMountFor(scope, instance); tenant != nil {
			if err := add(part, instance.Namespace, tenant.Identity.Name, &tenant.Identity, true); err != nil {
				return nil, err
			}
			if out[part].NamespaceUID != tenant.NamespaceUID || out[part].AccessMode != corev1.ReadWriteOnce {
				return nil, install.ErrInstall
			}
		} else if cfg.Workspace.Claim != "" {
			if err := add(part, cfg.Namespace, cfg.Workspace.Claim, nil, false); err != nil {
				return nil, err
			}
		}
	}
	for _, mapping := range scope.Mounts {
		pod, err := api.CoreV1().Pods(mapping.Namespace).Get(ctx, mapping.Pod, options)
		if err != nil {
			return nil, install.ErrInstall
		}
		instance := instances[mapping.InstanceID]
		_, identity, err := resolvePersistentMount(ctx, api, cfg, instance, pod, mapping, productionInstanceMount{InstanceID: instance.ID})
		if err != nil {
			return nil, err
		}
		if identity != nil {
			part := "instance_" + strconv.Itoa(instance.ID) + "_" + mapping.MountID
			if err := add(part, mapping.Namespace, identity.Name, identity, false); err != nil {
				return nil, err
			}
		}
	}
	for _, team := range inventory.TeamFacts.Teams {
		if team.PVC == "" {
			continue
		}
		namespaceUID, err := observeTeamSourceNamespace(ctx, api, cfg, team)
		if err != nil {
			return nil, err
		}
		if err := add("team_"+strconv.Itoa(team.ID)+"_workspace", team.Namespace, team.PVC, nil, false); err != nil {
			return nil, err
		}
		if source, ok := out["team_"+strconv.Itoa(team.ID)+"_workspace"]; ok && source.NamespaceUID != namespaceUID {
			return nil, install.ErrInstall
		}
	}
	if len(out) == 0 {
		return nil, install.ErrInstall
	}
	return out, ctx.Err()
}

func (x *bootstrapSourceRegistryReader) checkOriginalLonghornSources(ctx context.Context, clients *productionMetadataClients, inventory b.SourceInventory) error {
	discovery := x.materials.Discovery
	var selection *OriginalLonghornStorageSelection
	for _, source := range discovery.LonghornSources {
		selection = &OriginalLonghornStorageSelection{ProviderNamespace: source.ProviderNamespace, SnapshotClass: source.SnapshotClass, CloneClass: source.CloneClass}
		break
	}
	current, err := observeOriginalLonghornSources(ctx, clients, x.config, inventory, discovery.PersistentMounts, selection)
	if err != nil || (len(current) != 0 || len(discovery.LonghornSources) != 0) && !reflect.DeepEqual(current, discovery.LonghornSources) {
		return install.ErrInstall
	}
	return nil
}
