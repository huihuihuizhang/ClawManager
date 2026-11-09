package install

import (
	"context"
	"encoding/json"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/quiesce"
	c "clawreef/internal/systembackupcontroller"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// References only: these are the existing V2 registry and independently pinned
// capture consumer, not a new authorization or signature protocol.
type OriginalObserverLonghornSourceRegistry struct {
	Registry                            BootstrapSourceRegistryFiles
	CaptureConsumer, CaptureConsumerPin BootstrapSourceFilePin
}

// Exact projection of the existing signed originalLonghornSource JSON. Keep
// field order for OriginalSourceSHA256, which hashes json.Marshal(source).
type originalObserverLonghornSource struct {
	Namespace, NamespaceUID         string
	Source                          kube.MountIdentity
	Handle                          string
	AccessMode                      corev1.PersistentVolumeAccessMode
	ProviderNamespace, ProviderUID  string
	SnapshotClass, SnapshotClassUID string
	SnapshotClassSHA256             string
	CloneClass, CloneClassUID       string
	CloneClassSHA256                string
}

type originalObserverTenantMount struct {
	Source                                   domain.SourceInstance
	NamespaceUID, PodUID, PodSpecSHA256      string
	ReplicaSetUID, Deployment, DeploymentUID string
	SubPath                                  string
	Identity                                 kube.MountIdentity
}

type originalObserverLonghornMaterial struct {
	Discovery *struct {
		PersistentMounts *struct {
			Version          string
			RunningTenantPro []originalObserverTenantMount
		}
		LonghornSources map[string]originalObserverLonghornSource
	}
}

// Constructed only by the already authenticated host material producer; the
// returned callback retains the actual original-maintenance capability and
// exact signed material bytes. An unassociated file cannot reach this branch.
func (i *Installer) originalObserverLonghornTenantCheck(ctx context.Context, password []byte, enrollment EnrollmentPin, refs *OriginalObserverLonghornSourceRegistry) (func(quiesce.LonghornExt4SourceCoordinates) error, error) {
	if refs == nil {
		return nil, nil
	}
	locatorRaw, err := readObserverHostFile(refs.CaptureConsumer, 262144)
	var locator CaptureConsumerFiles
	if err != nil || decodeExact(locatorRaw, &locator) != nil || locator.PlanSHA256 != i.planHash || locator.IssuerPublicSHA256 != i.plan.IssuerPublicKeySHA256 {
		return nil, ErrInstall
	}
	independent, err := readObserverHostFile(refs.CaptureConsumerPin, 64)
	if err != nil || string(independent) != refs.CaptureConsumer.SHA256 {
		return nil, ErrInstall
	}
	consumer := NewCaptureSigningConsumer(refs.CaptureConsumer.File, refs.CaptureConsumerPin.File)
	loaded, err := consumer.load(ctx)
	if err != nil {
		return nil, ErrInstall
	}
	defer loaded.request.observer.Close()
	raw, err := readBootstrapSourcePin(BootstrapSourceFilePin{refs.Registry.RecordFile, refs.Registry.RecordSHA256}, 262144)
	if err != nil {
		return nil, ErrInstall
	}
	signature, err := ReadPrivateFile(refs.Registry.SignatureFile, 64)
	if err != nil {
		return nil, ErrInstall
	}
	record, err := verifyBootstrapSourceV2(raw, signature, i.public)
	if err != nil || record.PlanSHA256 != i.planHash || record.Target != i.plan.Target || record.Enrollment != enrollment {
		return nil, ErrInstall
	}
	prepared, err := consumer.PrepareBootstrapSourceRegistriesV2(ctx, loaded.request.grant, loaded.request.config, record.Selection, refs.Registry)
	if err != nil {
		return nil, ErrInstall
	}
	materialRaw, err := prepared.ReadSelectedFile(ctx, record.Source.Materials)
	var material originalObserverLonghornMaterial
	if err != nil || json.Unmarshal(materialRaw, &material) != nil || material.Discovery == nil || material.Discovery.PersistentMounts == nil ||
		material.Discovery.PersistentMounts.Version != "original-instance-persistent-mounts.v1" || len(material.Discovery.PersistentMounts.RunningTenantPro) == 0 || len(material.Discovery.PersistentMounts.RunningTenantPro) > 9998 {
		return nil, ErrInstall
	}
	// This factory only reads and authenticates. It does not acquire the gate,
	// reserve an operation, stop a writer or mutate any source.
	maintenance, err := i.PrepareOriginalWriterMaintenance(ctx, password, enrollment, c.GatePolicy{
		LockTTL: c.DefaultMaintenanceLockTTL, AcquisitionTimeout: c.DefaultGateAcquisitionTime, MaxHold: c.DefaultQuiesceMaxHold})
	if err != nil {
		return nil, ErrInstall
	}
	return func(coordinate quiesce.LonghornExt4SourceCoordinates) error {
		// ReadSelectedFile rechecks the original V2 signed window and all pins;
		// the actual installer/admin/head/census checks remain independently live.
		currentRaw, err := prepared.ReadSelectedFile(ctx, record.Source.Materials)
		if err != nil || hash(currentRaw) != hash(materialRaw) {
			return ErrInstall
		}
		instances, err := maintenance.Instances(ctx)
		if err != nil {
			return ErrInstall
		}
		mount, source, err := matchOriginalObserverTenantSource(material, coordinate, instances)
		if err != nil || record.Actor.UserID != maintenance.operator.userID || originalInitialTenantNamespace(i.plan.Target.Namespace, source) != coordinate.Binding.Namespace || coordinate.ProviderNamespace != source.Namespace {
			return ErrInstall
		}
		actual, pod, deployment, claims, err := maintenance.readInitialTenantPro(ctx, source)
		if err != nil || pod == nil || deployment == nil || actual.NamespaceUID != mount.NamespaceUID || actual.PodUID != mount.PodUID ||
			actual.ReplicaSetUID != mount.ReplicaSetUID || actual.DeploymentUID != mount.DeploymentUID || deployment.Name != mount.Deployment ||
			originalObjectSHA(pod.Spec) != mount.PodSpecSHA256 || pod.Spec.NodeName != coordinate.Binding.Node {
			return ErrInstall
		}
		selected := false
		for _, claim := range claims {
			if claim.Name == coordinate.PVCName && string(claim.UID) == coordinate.PVCUID && claim.Spec.VolumeName == mount.Identity.PVName {
				selected = true
			}
		}
		if !selected || i.validateOriginalLonghornObserverClaimObjects(ctx, coordinate.Binding, coordinate.PVCName, coordinate.PVCUID, coordinate.PVUID, coordinate.VolumeHandle) != nil {
			return ErrInstall
		}
		pv, err := i.kube.CoreV1().PersistentVolumes().Get(ctx, mount.Identity.PVName, metav1.GetOptions{})
		if err != nil || kube.ContentHash(pv.Spec) != mount.Identity.SHA256 || maintenance.check(ctx) != nil || maintenance.checkInstances(ctx) != nil {
			return ErrInstall
		}
		// Slow SQL/API observations cannot outlive the original signed source
		// window, even while the independent maintenance identity remains valid.
		currentRaw, err = prepared.ReadSelectedFile(ctx, record.Source.Materials)
		if err != nil || hash(currentRaw) != hash(materialRaw) {
			return ErrInstall
		}
		return nil
	}, nil
}

func matchOriginalObserverTenantSource(material originalObserverLonghornMaterial, coordinate quiesce.LonghornExt4SourceCoordinates, instances []domain.SourceInstance) (originalObserverTenantMount, domain.SourceInstance, error) {
	var selected originalObserverTenantMount
	var instance domain.SourceInstance
	if material.Discovery == nil || material.Discovery.PersistentMounts == nil {
		return selected, instance, ErrInstall
	}
	count := 0
	for _, mount := range material.Discovery.PersistentMounts.RunningTenantPro {
		if mount.Source.Namespace != coordinate.Binding.Namespace || mount.NamespaceUID != coordinate.Binding.NamespaceUID ||
			mount.Identity.Name != coordinate.PVCName || mount.Identity.UID != coordinate.PVCUID || mount.Identity.PVUID != coordinate.PVUID {
			continue
		}
		for _, source := range material.Discovery.LonghornSources {
			if source.Namespace != mount.Source.Namespace || source.NamespaceUID != mount.NamespaceUID || source.Source != mount.Identity ||
				source.Handle != coordinate.VolumeHandle || source.ProviderNamespace != coordinate.LonghornNamespace || source.ProviderUID != coordinate.ProviderNamespaceUID ||
				source.AccessMode != corev1.ReadWriteOnce {
				continue
			}
			raw, err := json.Marshal(source)
			if err != nil || hash(raw) != coordinate.OriginalSourceSHA256 {
				continue
			}
			for _, original := range instances {
				if original == mount.Source && original.Mode == "pro" && original.OS == "linux" && original.Status == "running" {
					selected, instance = mount, original
					count++
				}
			}
		}
	}
	if count != 1 {
		return originalObserverTenantMount{}, domain.SourceInstance{}, ErrInstall
	}
	return selected, instance, nil
}
