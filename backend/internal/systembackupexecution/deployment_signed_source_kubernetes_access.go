package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"slices"
	"time"

	c "clawreef/internal/systembackupcontroller"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// Use the already selected final capture pin and its original metadata owner
// envelope. No caller-supplied namespace list or task is involved.
func loadSignedSourceAccess(cfg DeploymentConfig, configDigest, controllerSA string, inputs []ProductionCaptureInput) ([]CaptureAccess, error) {
	if len(inputs) == 0 {
		return nil, nil
	}
	if cfg.CaptureModules == nil || cfg.CaptureModules.validate() != nil || len(inputs) != 1 ||
		inputs[0].File != cfg.CaptureModules.Path || !formalCandidateDigest(configDigest) {
		return nil, c.ErrExecutionAuthority
	}
	raw, err := pinnedDeploymentFile(inputs[0].File, inputs[0].SHA256, 8<<20)
	var materials productionCaptureMaterials
	if err != nil || decodeMetadataCanonical(raw, &materials) != nil {
		return nil, c.ErrExecutionAuthority
	}
	return requiredSignedSourceAccess(cfg, configDigest, controllerSA, &materials)
}

func requiredSignedSourceAccess(cfg DeploymentConfig, configDigest, controllerSA string, materials *productionCaptureMaterials) ([]CaptureAccess, error) {
	if materials == nil || materials.Discovery == nil {
		return nil, nil
	}
	discovery := materials.Discovery
	scope := discovery.PersistentMounts
	if len(discovery.LonghornSources) == 0 && (scope == nil || len(scope.RunningTenantPro) == 0) {
		return nil, nil
	}
	if cfg.RuntimeSources == nil || materials.Version != productionCaptureMaterialsVersion || materials.InstallationID != cfg.InstallationID ||
		materials.ControllerOwner != cfg.ControllerOwner || materials.DeploymentConfigSHA256 != configDigest || !formalCandidateDigest(configDigest) ||
		!formalCandidateDigest(materials.CaptureGrantSHA256) || discovery.validate() != nil || discovery.ControllerServiceAccount != controllerSA {
		return nil, c.ErrExecutionAuthority
	}
	scopeSHA, err := sourceMetadataScope(*materials)
	if err != nil {
		return nil, c.ErrExecutionAuthority
	}
	raw, err := pinnedDeploymentFile(discovery.GrantFile, discovery.GrantSHA256, 65536)
	var signed signedSourceMetadataGrant
	var grant originalSourceMetadataGrant
	if err != nil || decodeMetadataCanonical(raw, &signed) != nil || decodeMetadataCanonical(signed.Record, &grant) != nil ||
		!ed25519.Verify(discovery.Issuer, append([]byte(sourceMetadataGrantDomain), signed.Record...), signed.Signature) {
		return nil, c.ErrExecutionAuthority
	}
	now := time.Now()
	if grant.Version != sourceMetadataGrantVersion || grant.InstallationID != cfg.InstallationID || grant.ControllerOwner != cfg.ControllerOwner ||
		grant.DeploymentConfigSHA256 != configDigest || grant.CaptureGrantSHA256 != materials.CaptureGrantSHA256 || grant.ScopeSHA256 != scopeSHA ||
		!formalCandidateDigest(grant.ConfigSHA256) ||
		grant.Namespace != cfg.Namespace || grant.NamespaceUID != cfg.NamespaceUID || grant.ControllerDeployment != discovery.ControllerDeployment ||
		grant.ControllerDeploymentUID != discovery.ControllerDeploymentUID || grant.ControllerServiceAccount != controllerSA ||
		grant.ControllerServiceAccountUID != discovery.ControllerServiceAccountUID || grant.Revoked || grant.NotBefore.IsZero() ||
		now.Before(grant.NotBefore) || !now.Before(grant.Until) || grant.Until.Sub(grant.NotBefore) > 24*time.Hour {
		return nil, c.ErrExecutionAuthority
	}

	var out []CaptureAccess
	add := func(ns, group string, resources, verbs, names []string) {
		for _, resource := range resources {
			out = append(out, CaptureAccess{ns, rbacv1.PolicyRule{APIGroups: []string{group}, Resources: []string{resource}, Verbs: verbs, ResourceNames: names}})
		}
	}
	deployments := map[string][]string{}
	var volumes []string
	if scope != nil {
		for _, mount := range scope.RunningTenantPro {
			ns := mount.Source.Namespace
			if !validTenantProNamespace(cfg.Namespace, mount.Source) || len(validation.IsDNS1123Label(ns)) != 0 ||
				slices.Contains(cfg.RuntimeSources.Namespaces, ns) || len(validation.IsDNS1123Subdomain(mount.Deployment)) != 0 {
				return nil, c.ErrExecutionAuthority
			}
			deployments[ns] = append(deployments[ns], mount.Deployment)
			if !slices.Contains(scope.TenantProCensusPVs[ns], mount.Identity.PVName) {
				return nil, c.ErrExecutionAuthority
			}
		}
		if len(scope.TenantProCensusPVs) != len(deployments) {
			return nil, c.ErrExecutionAuthority
		}
	}
	for _, ns := range sortedKeys(deployments) {
		for _, volume := range scope.TenantProCensusPVs[ns] {
			if len(validation.IsDNS1123Subdomain(volume)) != 0 {
				return nil, c.ErrExecutionAuthority
			}
			volumes = append(volumes, volume)
		}
		add(ns, "", []string{"pods", "persistentvolumeclaims"}, []string{"get", "list"}, nil)
		add(ns, "apps", []string{"replicasets"}, []string{"get", "list"}, nil)
		add(ns, "apps", []string{"deployments", "statefulsets", "daemonsets"}, []string{"list"}, nil)
		add(ns, "apps", []string{"deployments"}, []string{"get", "patch"}, sortedUnique(deployments[ns]))
		add(ns, "batch", []string{"jobs", "cronjobs"}, []string{"list"}, nil)
		add(ns, "autoscaling", []string{"horizontalpodautoscalers"}, []string{"list"}, nil)
	}
	if len(deployments) != 0 {
		add("", "", []string{"namespaces"}, []string{"get"}, sortedKeys(deployments))
		add("", "", []string{"persistentvolumes"}, []string{"get"}, sortedUnique(volumes))
	}
	if len(discovery.LonghornSources) != 0 {
		const snapshot = "snapshot.storage.k8s.io"
		var classes, storageClasses []string
		providers := map[string]bool{}
		sourceCuts := map[string]bool{}
		keepers := map[string]bool{}
		for _, source := range discovery.LonghornSources {
			if len(validation.IsDNS1123Label(source.ProviderNamespace)) != 0 || source.ProviderUID == "" ||
				len(validation.IsDNS1123Subdomain(source.SnapshotClass)) != 0 || len(validation.IsDNS1123Subdomain(source.CloneClass)) != 0 ||
				(source.Namespace != cfg.Namespace && len(deployments[source.Namespace]) == 0) {
				return nil, c.ErrExecutionAuthority
			}
			providers[source.ProviderNamespace] = true
			sourceCuts[source.Namespace] = true
			if source.Namespace != cfg.Namespace && source.AccessMode == "ReadWriteOnce" {
				keepers[source.Namespace] = true
			}
			classes = append(classes, source.SnapshotClass)
			storageClasses = append(storageClasses, source.CloneClass)
		}
		add(cfg.Namespace, "", []string{"persistentvolumeclaims"}, []string{"get", "create", "delete"}, nil)
		sourceCuts[cfg.Namespace] = true
		for _, ns := range sortedKeys(sourceCuts) {
			add(ns, snapshot, []string{"volumesnapshots"}, []string{"get", "create", "delete"}, nil)
		}
		for _, ns := range sortedKeys(keepers) {
			add(ns, "batch", []string{"jobs"}, []string{"get", "create", "delete"}, nil)
			add(ns, "", []string{"serviceaccounts"}, []string{"get"}, []string{"default"})
		}
		// Provisioned clone PV names are assigned after the task's PVC create.
		// The clone binding verifier checks the actual claimRef and UIDs.
		if len(cfg.ProviderDependencies) == 0 {
			add("", "", []string{"persistentvolumes"}, []string{"get"}, nil)
		}
		add("", "", []string{"namespaces"}, []string{"get"}, sortedKeys(providers))
		add("", snapshot, []string{"volumesnapshotclasses"}, []string{"get"}, sortedUnique(classes))
		add("", "storage.k8s.io", []string{"storageclasses"}, []string{"get"}, sortedUnique(storageClasses))
		add("", snapshot, []string{"volumesnapshotcontents"}, []string{"get", "create", "delete"}, nil)
		// The CSI sidecar chooses these names from the actual cut/clone UID.
		for _, ns := range sortedKeys(providers) {
			add(ns, "longhorn.io", []string{"snapshots", "volumes"}, []string{"get"}, nil)
		}
	}
	return out, nil
}

func (s *DeploymentService) checkDeploymentCaptureAccess(ctx context.Context) error {
	controller := s.controllerActor.ServiceAccountName
	access, err := RequiredDeploymentCaptureAccess(s.Config, controller, s.formalVerifier, s.publisherVerifier)
	if err != nil {
		return err
	}
	signed, err := requiredSignedSourceAccess(s.Config, s.ConfigDigest, controller, s.captureMaterials)
	if err != nil {
		return err
	}
	return checkCaptureKubernetesAccess(ctx, s.Runtime.Owner.Client, append(access, signed...))
}
