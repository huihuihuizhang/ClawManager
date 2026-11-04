package install

import (
	"bytes"
	"context"
	"path/filepath"
	"reflect"

	owner "clawreef/internal/systembackupinstallationowner"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type InstalledVaultMetadataMaterials struct {
	Version  string
	Workload VaultProviderWorkloadSelection
	Observer BootstrapSourceFilePin
	Scope    VaultProviderScopeData
	Native   owner.InstalledVaultDependencyData
}

// ProduceInstalledVaultMetadataMaterials authenticates the real original
// local administrator/enrollment and pins the current authority before/after
// native issuance. It consumes the original full-roster selection, never a
// provider name filter, fake Installer or future task/config reference.
func (i *Installer) ProduceInstalledVaultMetadataMaterials(ctx context.Context, password []byte, enrollment EnrollmentPin, writerPin BootstrapSourceFilePin, outputDirectory string) (InstalledVaultMetadataMaterials, error) {
	var zero InstalledVaultMetadataMaterials
	if i == nil || ctx == nil || ctx.Err() != nil || privateDirectory(outputDirectory) != nil {
		return zero, ErrInstall
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return zero, ErrInstall
	}
	operator, e := i.authenticate(ctx, password)
	if e != nil || operator.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	head, _, e := originalAdoptionAuthoritySnapshot(ctx, operator)
	if e != nil {
		return zero, ErrInstall
	}
	raw, e := readBootstrapSourcePin(writerPin, 262144)
	var selected OriginalWriterSetSelection
	if e != nil || decodeExact(raw, &selected) != nil || selected.Version != OriginalWriterSetSelectionVersion || len(selected.PreAdoptionVaultDependencies) != 1 || len(selected.VaultProviderDependencies) != 0 {
		return zero, ErrInstall
	}
	input := selected.PreAdoptionVaultDependencies[0]
	count := 0
	for _, d := range selected.Deployments {
		if d.Name == input.Workload.Deployment && d.UID == input.Workload.DeploymentUID && d.Role == "provider-dependency" {
			count++
		}
	}
	if count != 1 {
		return zero, ErrInstall
	}
	roster := map[string]string{}
	for _, d := range selected.Deployments {
		if d.Name == "" || d.UID == "" || roster[d.Name] != "" {
			return zero, ErrInstall
		}
		roster[d.Name] = d.UID
	}
	actual, e := i.kube.AppsV1().Deployments(i.plan.Target.Namespace).List(ctx, metav1.ListOptions{})
	if e != nil || len(actual.Items) != len(roster) {
		return zero, ErrInstall
	}
	for _, d := range actual.Items {
		if roster[d.Name] != string(d.UID) || d.DeletionTimestamp != nil {
			return zero, ErrInstall
		}
	}
	observerRaw, e := readBootstrapSourcePin(input.InstalledObserver, 262144)
	var original owner.InstalledVaultDependencyConfig
	if e != nil || decodeExact(observerRaw, &original) != nil || original.IdentityMode != "original-owner-readonly" {
		return zero, ErrInstall
	}
	check := func() (VaultProviderScopeData, error) {
		if operator.authority(ctx, enrollment) != nil {
			return VaultProviderScopeData{}, ErrInstall
		}
		current, _, e := originalAdoptionAuthoritySnapshot(ctx, operator)
		if e != nil || current.cas != head.cas || !bytes.Equal(current.recordRaw, head.recordRaw) {
			return VaultProviderScopeData{}, ErrInstall
		}
		for _, pin := range []BootstrapSourceFilePin{writerPin, input.InstalledObserver} {
			now, e := readBootstrapSourcePin(pin, 262144)
			clear(now)
			if e != nil {
				return VaultProviderScopeData{}, ErrInstall
			}
		}
		currentRoster, e := i.kube.AppsV1().Deployments(i.plan.Target.Namespace).List(ctx, metav1.ListOptions{})
		if e != nil || len(currentRoster.Items) != len(roster) {
			return VaultProviderScopeData{}, ErrInstall
		}
		for _, d := range currentRoster.Items {
			if roster[d.Name] != string(d.UID) || d.DeletionTimestamp != nil {
				return VaultProviderScopeData{}, ErrInstall
			}
		}
		return ObserveInstalledVaultProviderScope(ctx, i.db, i.kube, i.plan.Target, input.Workload, original.Endpoint)
	}
	before, e := check()
	if e != nil {
		return zero, ErrInstall
	}
	metadata, e := owner.IssueInstalledVaultMetadataIdentity(ctx, original, i.kube, i.plan.Target.Namespace, i.plan.Target.NamespaceUID, filepath.Join(outputDirectory, "provider-metadata.token"))
	if e != nil {
		return zero, ErrInstall
	}
	observer, e := owner.NewInstalledVaultDependencyObserver(metadata, i.kube, i.plan.Target.Namespace, i.plan.Target.NamespaceUID)
	if e != nil {
		return zero, ErrInstall
	}
	defer observer.Close()
	proof, e := observer.Observe(ctx)
	if e != nil {
		return zero, ErrInstall
	}
	native, _, e := proof.Data(ctx)
	if e != nil {
		return zero, ErrInstall
	}
	after, e := check()
	if e != nil || !reflect.DeepEqual(before, after) {
		return zero, ErrInstall
	}
	body, e := canonical(metadata)
	if e != nil {
		return zero, ErrInstall
	}
	if writeNewFiles(outputDirectory, map[string][]byte{"provider-metadata-observer.private.json": body}) != nil {
		return zero, ErrInstall
	}
	pin := BootstrapSourceFilePin{File: filepath.Join(outputDirectory, "provider-metadata-observer.private.json"), SHA256: hash(body)}
	current, e := readBootstrapSourcePin(pin, 262144)
	if e != nil || !bytes.Equal(body, current) {
		return zero, ErrInstall
	}
	after, e = check()
	if e != nil || !reflect.DeepEqual(before, after) {
		return zero, ErrInstall
	}
	return InstalledVaultMetadataMaterials{Version: "installed-vault-metadata-materials.v1", Workload: input.Workload, Observer: pin, Scope: before, Native: native}, nil
}
