package install

import (
	"context"
	"path/filepath"
	"reflect"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type PreAdoptionVaultMaterialOptions struct {
	Deployment, Service, Claim, DataMountPath                        string
	Endpoint, ClusterID, TransitMount, KeyName, KeyVersion, JWTMount string
	CA, OwnerToken                                                   BootstrapSourceFilePin
}
type PreAdoptionVaultMaterialReceipt struct {
	Version, State                     string
	InstalledObserver, WriterSelection BootstrapSourceFilePin
	Scope                              VaultProviderScopeData
	Native                             owner.InstalledVaultDependencyData
}

// Safe stage diagnostics contain no provider/token/SQL input values.
type VaultDependencyMaterialFailure struct {
	stage string
	cause error
}

func (e *VaultDependencyMaterialFailure) Error() string {
	return "original Vault dependency material unconfirmed"
}
func (e *VaultDependencyMaterialFailure) Unwrap() error { return e.cause }
func (e *VaultDependencyMaterialFailure) Phase() string { return e.stage }

// ProducePreAdoptionVaultMaterials is an actual original installer action,
// before A1. It reads the original provider, real Kube/JWKS and existing key;
// it does not issue a key/token, register a future reference, create a role,
// activate configuration or acquire/claim a business-source hold.
func (i *Installer) ProducePreAdoptionVaultMaterials(ctx context.Context, password []byte, enrollment EnrollmentPin, selectionPin BootstrapSourceFilePin, options PreAdoptionVaultMaterialOptions, directory string) (_ PreAdoptionVaultMaterialReceipt, resultErr error) {
	stage := "inputs"
	defer func() {
		if resultErr != nil {
			resultErr = &VaultDependencyMaterialFailure{stage: stage, cause: resultErr}
		}
	}()
	var zero PreAdoptionVaultMaterialReceipt
	if i == nil || ctx == nil || ctx.Err() != nil || privateDirectory(directory) != nil {
		return zero, ErrInstall
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return zero, ErrInstall
	}
	stage = "installer_authority"
	s, e := i.authenticate(ctx, password)
	if e != nil || s.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	stage = "original_owner_head"
	before, _, e := originalAdoptionAuthoritySnapshot(ctx, s)
	if e != nil || before.cas != (HeadCAS{}) || len(before.recordRaw) != 0 {
		return zero, ErrInstall
	}
	stage = "writer_selection"
	raw, e := readBootstrapSourcePin(selectionPin, 262144)
	var selection OriginalWriterSetSelection
	if e != nil || decodeExact(raw, &selection) != nil || selection.Version != OriginalWriterSetSelectionVersion || len(selection.VaultProviderDependencies) != 0 || len(selection.PreAdoptionVaultDependencies) != 0 {
		return zero, ErrInstall
	}
	stage = "provider_objects"
	ns := i.plan.Target.Namespace
	deployment, e := i.kube.AppsV1().Deployments(ns).Get(ctx, options.Deployment, metav1.GetOptions{})
	if e != nil || deployment.UID == "" || deployment.DeletionTimestamp != nil {
		return zero, ErrInstall
	}
	service, e := i.kube.CoreV1().Services(ns).Get(ctx, options.Service, metav1.GetOptions{})
	if e != nil || service.UID == "" || service.DeletionTimestamp != nil {
		return zero, ErrInstall
	}
	claim, e := i.kube.CoreV1().PersistentVolumeClaims(ns).Get(ctx, options.Claim, metav1.GetOptions{})
	if e != nil || claim.UID == "" || claim.DeletionTimestamp != nil {
		return zero, ErrInstall
	}
	stage = "complete_platform_roster"
	actual, e := i.kube.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
	if e != nil || len(actual.Items) != len(selection.Deployments) {
		return zero, ErrInstall
	}
	selected := map[string]string{}
	for _, d := range selection.Deployments {
		if selected[d.Name] != "" {
			return zero, ErrInstall
		}
		selected[d.Name] = d.UID
	}
	for _, d := range actual.Items {
		if selected[d.Name] != string(d.UID) || d.DeletionTimestamp != nil {
			return zero, ErrInstall
		}
	}
	matched := false
	for n, d := range selection.Deployments {
		if d.Name != deployment.Name {
			continue
		}
		if matched || d.UID != string(deployment.UID) || d.Role != "writer" {
			return zero, ErrInstall
		}
		matched = true
		selection.Deployments[n].Role = "provider-dependency"
	}
	if !matched {
		return zero, ErrInstall
	}
	stage = "provider_ca"
	ca, e := readObserverHostFile(options.CA, 65536)
	if e != nil {
		return zero, ErrInstall
	}
	stage = "kubernetes_jwt_trust"
	trust, e := owner.ReadInstalledVaultKubernetesTrust(ctx, i.kube)
	if e != nil {
		return zero, ErrInstall
	}
	cfg := owner.InstalledVaultDependencyConfig{Version: "installed-vault-dependency-input.v1", Endpoint: options.Endpoint, CAPEM: ca, CASHA256: options.CA.SHA256, ClusterID: options.ClusterID, TransitMount: options.TransitMount, PinnedKeyName: options.KeyName, PinnedKeyVersion: options.KeyVersion, JWTMount: options.JWTMount, Trust: trust, TokenFile: options.OwnerToken.File, TokenSHA256: options.OwnerToken.SHA256, IdentityMode: "original-owner-readonly"}
	stage = "provider_observer_configuration"
	observer, e := owner.NewInstalledVaultDependencyObserver(cfg, i.kube, ns, i.plan.Target.NamespaceUID)
	if e != nil {
		return zero, ErrInstall
	}
	defer observer.Close()
	if len(deployment.Spec.Template.Spec.Containers) != 1 {
		return zero, ErrInstall
	}
	if options.DataMountPath == "" {
		volumeName := ""
		for _, volume := range deployment.Spec.Template.Spec.Volumes {
			if volume.PersistentVolumeClaim != nil && volume.PersistentVolumeClaim.ClaimName == claim.Name {
				if volumeName != "" {
					return zero, ErrInstall
				}
				volumeName = volume.Name
			}
		}
		for _, mount := range deployment.Spec.Template.Spec.Containers[0].VolumeMounts {
			if mount.Name == volumeName && !mount.ReadOnly {
				if options.DataMountPath != "" {
					return zero, ErrInstall
				}
				options.DataMountPath = mount.MountPath
			}
		}
	}
	stage = "provider_physical_scope"
	workload := VaultProviderWorkloadSelection{Deployment: deployment.Name, DeploymentUID: string(deployment.UID), Container: deployment.Spec.Template.Spec.Containers[0].Name, ImageID: originalProviderVaultImage, Service: service.Name, ServiceUID: string(service.UID), Claim: claim.Name, ClaimUID: string(claim.UID), DataMountPath: options.DataMountPath}
	scope, e := ObserveInstalledVaultProviderScope(ctx, i.db, i.kube, i.plan.Target, workload, cfg.Endpoint)
	if e != nil {
		return zero, ErrInstall
	}
	stage = "provider_native_metadata"
	proof, e := observer.Observe(ctx)
	if e != nil {
		return zero, ErrInstall
	}
	native, _, e := proof.Data(ctx)
	if e != nil {
		return zero, ErrInstall
	}
	check := func() error {
		raw, e := readBootstrapSourcePin(selectionPin, 262144)
		clear(raw)
		if e != nil || s.authority(ctx, enrollment) != nil {
			return ErrInstall
		}
		current, _, e := originalAdoptionAuthoritySnapshot(ctx, s)
		if e != nil || current.cas != (HeadCAS{}) || len(current.recordRaw) != 0 {
			return ErrInstall
		}
		caNow, e := readObserverHostFile(options.CA, 65536)
		clear(caNow)
		if e != nil {
			return ErrInstall
		}
		actual, e := ObserveInstalledVaultProviderScope(ctx, i.db, i.kube, i.plan.Target, workload, cfg.Endpoint)
		if e != nil || !reflect.DeepEqual(actual, scope) {
			return ErrInstall
		}
		fresh, e := observer.Observe(ctx)
		if e != nil {
			return ErrInstall
		}
		data, _, e := fresh.Data(ctx)
		if e != nil || !reflect.DeepEqual(data, native) {
			return ErrInstall
		}
		return nil
	}
	stage = "output_encoding"
	configRaw, e := canonical(cfg)
	if e != nil {
		return zero, ErrInstall
	}
	configPin := BootstrapSourceFilePin{File: filepath.Join(directory, "pre-adoption-vault-observer.private.json"), SHA256: hash(configRaw)}
	selection.PreAdoptionVaultDependencies = []PreAdoptionVaultDependencySelection{{Workload: workload, InstalledObserver: configPin}}
	selectionRaw, e := canonical(selection)
	if e != nil {
		return zero, ErrInstall
	}
	selectionOut := BootstrapSourceFilePin{File: filepath.Join(directory, "pre-adoption-vault-writer-selection.json"), SHA256: hash(selectionRaw)}
	receipt := PreAdoptionVaultMaterialReceipt{Version: "pre-adoption-vault-materials.v1", State: "actual_installed_dependency_inputs_only_no_adoption_or_task_authority", InstalledObserver: configPin, WriterSelection: selectionOut, Scope: scope, Native: native}
	receiptRaw, e := canonical(receipt)
	if e != nil {
		return zero, ErrInstall
	}
	for name, body := range map[string][]byte{"pre-adoption-vault-observer.private.json": configRaw, "pre-adoption-vault-writer-selection.json": selectionRaw, "pre-adoption-vault-materials.receipt.json": receiptRaw} {
		stage = "native_recheck_and_output_write"
		if check() != nil || writeNewFiles(directory, map[string][]byte{name: body}) != nil {
			return zero, ErrInstall
		}
		file := BootstrapSourceFilePin{File: filepath.Join(directory, name), SHA256: hash(body)}
		actual, e := readBootstrapSourcePin(file, 262144)
		clear(actual)
		if e != nil || check() != nil {
			return zero, ErrOriginalObserverPKIUnconfirmed
		}
	}
	stage = "owner_deadline"
	if !time.Now().Before(s.until) {
		return zero, ErrInstall
	}
	return receipt, nil
}
