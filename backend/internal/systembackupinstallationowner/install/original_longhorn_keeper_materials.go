package install

import (
	"context"
	"reflect"

	q "clawreef/internal/systembackup/quiesce"
)

func (s *PreparedOriginalWriterSet) prepareLonghornKeepers(ctx context.Context, password []byte, enrollment EnrollmentPin) error {
	if s.selection.LonghornHostDefinition == (BootstrapSourceFilePin{}) {
		if s.selection.LonghornKeeperImage != "" {
			return ErrInstall
		}
		return nil
	}
	raw, err := readObserverHostFile(s.selection.LonghornHostDefinition, 1<<20)
	var def OriginalObserverHostDefinition
	if err != nil || decodeExact(raw, &def) != nil || def.LonghornVolumes == (BootstrapSourceFilePin{}) || def.LonghornSourceRegistry == nil {
		return ErrInstall
	}
	raw, err = readObserverHostFile(def.PKIReceipt, 1<<20)
	var pki GeneratedOriginalObserverPKI
	if err != nil || decodeOriginalWriterMaterialData(raw, &pki) != nil || pki.PlanSHA256 != s.owner.operator.installer.planHash || pki.Enrollment != enrollment || pki.CA != s.selection.ObserverCA || pki.ClientCertificate != s.selection.ObserverCertificate || pki.ClientKey != s.selection.ObserverKey {
		return ErrInstall
	}
	config, err := originalObserverLonghornControllerConfig(def, pki)
	if err != nil || config == nil || !reflect.DeepEqual(config.Observer.Endpoints, s.selection.SharedRuntimeEndpoints) {
		return ErrInstall
	}
	i := s.owner.operator.installer
	tenant, err := i.originalObserverLonghornTenantCheck(ctx, password, enrollment, def.LonghornSourceRegistry)
	if err != nil || i.validateOriginalLonghornObserverVolumesWithTenant(ctx, def.LonghornVolumes, tenant) != nil {
		return ErrInstall
	}
	raw, err = readObserverHostFile(def.LonghornVolumes, 1<<20)
	var materials q.LonghornExt4Materials
	if err != nil || decodeExact(raw, &materials) != nil {
		return ErrInstall
	}
	clients, err := originalLonghornRWXClients(ctx, i.kube, materials)
	if err != nil {
		return err
	}
	s.longhornMaterials, s.longhornRWXClients = &materials, clients
	s.longhornClient, err = q.NewSharedRuntimeNodeClient(config.Observer.Endpoints, config.Observer.CAFile, config.Observer.CertificateFile, config.Observer.KeyFile)
	if err != nil {
		return ErrInstall
	}
	s.longhornSources = map[string]q.LonghornExt4SourceCoordinates{}
	for _, source := range materials.Sources {
		key := source.Binding.Namespace + "/" + source.PVCName
		if _, duplicate := s.longhornSources[key]; duplicate {
			return ErrInstall
		}
		s.longhornSources[key] = source
		cohort := []originalLonghornRWXClient{}
		for _, client := range clients {
			if client.Template.OriginalSourceSHA256 == source.OriginalSourceSHA256 && client.Template.PVCUID == source.PVCUID && client.Template.PVUID == source.PVUID {
				cohort = append(cohort, client)
			}
		}
		if len(cohort) > 0 {
			s.longhornRWX = append(s.longhornRWX, &originalLonghornRWXHold{set: s, source: source, clients: cohort})
		}
	}
	for _, writer := range s.deployments {
		installationMinIO := writer.namespace == s.initial.Namespace && writer.namespaceUID == s.initial.NamespaceUID && writer.selection.Name == "minio" && writer.minio == nil && writer.redis == nil
		if writer.namespace == s.initial.Namespace && !installationMinIO {
			continue
		}
		keeper, err := s.prepareLonghornKeeper(ctx, writer, s.selection.LonghornKeeperImage)
		if err != nil {
			return err
		}
		source, found := s.longhornSources[keeper.plan.Identity.Namespace+"/"+keeper.plan.Source.Name]
		if !found || source.PVCUID != keeper.plan.Source.UID || source.PVUID != keeper.plan.Source.PVUID || source.Binding.NodeUID != keeper.plan.NodeUID || source.ProviderPodUID != writer.pods[0].UID || (installationMinIO && (source.MountPoint != "/data" || source.Binding.Namespace != s.initial.Namespace || source.Binding.NamespaceUID != s.initial.NamespaceUID)) {
			return ErrInstall
		}
		s.longhornKeepers = append(s.longhornKeepers, keeper)
	}
	return nil
}
