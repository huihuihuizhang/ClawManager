package systembackupexecution

import (
	"bytes"
	"context"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	ce "clawreef/internal/systembackupcontrolevidence"
	"clawreef/internal/systembackupinstallationowner/install"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const formalVaultDependencyMount = "/var/run/clawreef/system-backup/provider-dependency"

type FormalVaultMaterialsReceipt struct {
	Version                                        string
	Deployment, MaterialsTemplate, SourceSelection install.BootstrapSourceFilePin
	SecretManifest, DeploymentPatch                install.BootstrapSourceFilePin
	Workload                                       install.VaultProviderWorkloadSelection
}

// Actual pre-signing installer action: native token issuance, complete original
// roster correspondence, immutable Secret, guarded controller mount patch, and
// an updated config/material/source-selection hash chain. No ready flag, fake
// provider facts, policy supplied by a task, root mount or synthetic cold ack.
func ProduceFormalVaultDependencyMaterials(ctx context.Context, installer *install.Installer, password []byte, enrollment install.EnrollmentPin, selectionFile, selectionSHA, writerFile, writerSHA, container, outputDirectory string) (FormalVaultMaterialsReceipt, error) {
	var zero FormalVaultMaterialsReceipt
	if ctx == nil || installer == nil || ctx.Err() != nil || container == "" {
		return zero, install.ErrInstall
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return zero, install.ErrInstall
	}
	selected, e := readFormalObserverSelection(writerFile, writerSHA)
	if e != nil {
		return zero, install.ErrInstall
	}
	if len(selected.PreAdoptionVaultDependencies) != 1 || len(selected.VaultProviderDependencies) != 0 {
		return zero, install.ErrInstall
	}
	authority, e := installer.PrepareBootstrapSourceRegistryAuthoring(ctx, password, enrollment, selectionFile, selectionSHA)
	if e != nil {
		return zero, install.ErrInstall
	}
	defer authority.Close()
	x, e := newBootstrapSourceAuthoringReader(ctx, authority)
	if e != nil {
		return zero, install.ErrInstall
	}
	selection, _, e := authority.Selection(ctx)
	if e != nil || selected.ApplicationScope != selection.ApplicationScope || len(x.config.ProviderDependencies) != 0 {
		return zero, install.ErrInstall
	}
	clients, e := x.openMetadataClients()
	if e != nil {
		return zero, install.ErrInstall
	}
	defer clients.Close()
	ref := selection.Controller
	deployment, e := clients.API.AppsV1().Deployments(ref.Namespace).Get(x.physical, ref.Deployment, metav1.GetOptions{})
	if e != nil || string(deployment.UID) != ref.DeploymentUID || deployment.ResourceVersion == "" || deployment.DeletionTimestamp != nil || deployment.Spec.Template.Spec.ServiceAccountName != ref.ServiceAccount {
		return zero, install.ErrInstall
	}
	const volumeName = "provider-dependency"
	index := -1
	for n, c := range deployment.Spec.Template.Spec.Containers {
		if c.Name == container {
			index = n
		}
		for _, m := range c.VolumeMounts {
			if m.Name == volumeName || m.Name == volumeName+"-input" || m.MountPath == formalVaultDependencyMount || strings.HasPrefix(formalVaultDependencyMount, m.MountPath+"/") || strings.HasPrefix(m.MountPath, formalVaultDependencyMount+"/") {
				return zero, install.ErrInstall
			}
		}
	}
	if index < 0 {
		return zero, install.ErrInstall
	}
	for _, v := range deployment.Spec.Template.Spec.Volumes {
		if v.Name == volumeName || v.Name == volumeName+"-input" {
			return zero, install.ErrInstall
		}
	}
	for _, c := range deployment.Spec.Template.Spec.InitContainers {
		if c.Name == volumeName+"-install" {
			return zero, install.ErrInstall
		}
		for _, m := range c.VolumeMounts {
			if m.Name == volumeName || m.Name == volumeName+"-input" {
				return zero, install.ErrInstall
			}
		}
	}
	security := deployment.Spec.Template.Spec.Containers[index].SecurityContext.DeepCopy()
	if security == nil {
		security = &corev1.SecurityContext{}
	}
	podSecurity := deployment.Spec.Template.Spec.SecurityContext
	runAsUser := security.RunAsUser
	if runAsUser == nil && podSecurity != nil {
		runAsUser = podSecurity.RunAsUser
	}
	// The copy and runtime containers must have an explicit identical UID. The
	// init process reads group-private Secret projection and creates own 0600
	// regular files in EmptyDir; runtime never weakens its private-token checks.
	if runAsUser == nil || *runAsUser < 0 || *runAsUser != 0 && (podSecurity == nil || podSecurity.FSGroup == nil || *podSecurity.FSGroup <= 0) {
		return zero, install.ErrInstall
	}
	security.RunAsUser = runAsUser
	guard := func() error {
		now, e := readFormalObserverSelection(writerFile, writerSHA)
		if e != nil || !reflect.DeepEqual(now, selected) || authority.RecheckAuthority(ctx) != nil {
			return install.ErrInstall
		}
		current, e := clients.API.AppsV1().Deployments(ref.Namespace).Get(x.physical, ref.Deployment, metav1.GetOptions{})
		if e != nil || !reflect.DeepEqual(current, deployment) {
			return install.ErrInstall
		}
		return nil
	}
	outputs := []string{"provider-deployment-config.json", "provider-materials-template.json", "provider-source-selection.json", "provider-secret.private.json", "provider-deployment-mount.patch.json"}
	for _, name := range append(append([]string{}, outputs...), "provider-metadata.token", "provider-metadata-observer.private.json") {
		file := filepath.Join(outputDirectory, name)
		if file == selectionFile || file == writerFile || checkBootstrapSourceFactOutputs(file, filepath.Join(outputDirectory, "provider-output-reserved")) != nil {
			return zero, install.ErrInstall
		}
	}
	if guard() != nil {
		return zero, install.ErrInstall
	}
	materials, e := installer.ProduceInstalledVaultMetadataMaterials(ctx, password, enrollment, install.BootstrapSourceFilePin{File: writerFile, SHA256: writerSHA}, outputDirectory)
	if e != nil || !reflect.DeepEqual(materials.Workload, selected.PreAdoptionVaultDependencies[0].Workload) || guard() != nil {
		return zero, install.ErrInstall
	}
	observer, e := readFormalVaultObserver(materials.Observer)
	if e != nil {
		return zero, install.ErrInstall
	}
	token, e := install.ReadPrivateFile(observer.TokenFile, 16384)
	if e != nil || hash(token) != observer.TokenSHA256 {
		return zero, install.ErrInstall
	}
	defer clear(token)
	observer.TokenFile = path.Join(formalVaultDependencyMount, "token")
	observerRaw, e := ce.Canonical(observer)
	if e != nil {
		return zero, install.ErrInstall
	}
	secretName := "backup-provider-" + hash(observerRaw)[:24]
	immutable, mode := true, int32(0440)
	secret := corev1.Secret{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: ref.Namespace}, Immutable: &immutable, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"token": token, "observer.json": observerRaw}}
	input := corev1.Volume{Name: volumeName + "-input", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: secretName, DefaultMode: &mode}}}
	output := corev1.Volume{Name: volumeName, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory}}}
	image := deployment.Spec.Template.Spec.Containers[index].Image
	if !strings.Contains(image, "@sha256:") {
		return zero, install.ErrInstall
	}
	init := corev1.Container{Name: volumeName + "-install", Image: image, ImagePullPolicy: deployment.Spec.Template.Spec.Containers[index].ImagePullPolicy, Command: []string{"/usr/local/bin/system-backup-source-registries"}, Args: []string{"install-provider-files", "--observer-sha256", hash(observerRaw), "--token-sha256", observer.TokenSHA256}, SecurityContext: security, VolumeMounts: []corev1.VolumeMount{{Name: input.Name, MountPath: "/input", ReadOnly: true}, {Name: output.Name, MountPath: "/output"}}}
	patch := []formalObserverPatchOperation{{"test", "/metadata/uid", string(deployment.UID)}, {"test", "/metadata/resourceVersion", deployment.ResourceVersion}}
	if len(deployment.Spec.Template.Spec.Volumes) == 0 {
		patch = append(patch, formalObserverPatchOperation{"add", "/spec/template/spec/volumes", []corev1.Volume{input, output}})
	} else {
		patch = append(patch, formalObserverPatchOperation{"add", "/spec/template/spec/volumes/-", input}, formalObserverPatchOperation{"add", "/spec/template/spec/volumes/-", output})
	}
	if len(deployment.Spec.Template.Spec.InitContainers) == 0 {
		patch = append(patch, formalObserverPatchOperation{"add", "/spec/template/spec/initContainers", []corev1.Container{init}})
	} else {
		patch = append(patch, formalObserverPatchOperation{"add", "/spec/template/spec/initContainers/-", init})
	}
	position := "/spec/template/spec/containers/" + strconv.Itoa(index)
	patch = append(patch, formalObserverPatchOperation{"test", position + "/name", container})
	mount := corev1.VolumeMount{Name: volumeName, MountPath: formalVaultDependencyMount, SubPath: "private", ReadOnly: true}
	if len(deployment.Spec.Template.Spec.Containers[index].VolumeMounts) == 0 {
		patch = append(patch, formalObserverPatchOperation{"add", position + "/volumeMounts", []corev1.VolumeMount{mount}})
	} else {
		patch = append(patch, formalObserverPatchOperation{"add", position + "/volumeMounts/-", mount})
	}
	// Remove only the exact genuinely observed dependency, and prove that every
	// original non-provider Deployment remains in the signed business roster.
	roster := map[string]string{}
	roles := map[string]string{}
	expectedWriters := 0
	for _, d := range selected.Deployments {
		if roster[d.Name] != "" {
			return zero, install.ErrInstall
		}
		roster[d.Name] = d.UID
		roles[d.Name] = d.Role
		if d.Role == "writer" {
			expectedWriters++
		}
	}
	kept := make([]PlatformDeployment, 0, len(x.config.Writers))
	removed := 0
	for _, w := range x.config.Writers {
		if w.Namespace != x.config.Namespace || roster[w.Name] != w.UID {
			return zero, install.ErrInstall
		}
		if w.Name == materials.Workload.Deployment {
			if w.UID != materials.Workload.DeploymentUID {
				return zero, install.ErrInstall
			}
			removed++
			continue
		}
		if roles[w.Name] != "writer" {
			return zero, install.ErrInstall
		}
		kept = append(kept, w)
	}
	if removed != 1 || len(kept) != expectedWriters {
		return zero, install.ErrInstall
	}
	x.config.Writers = kept
	x.config.ProviderDependencies = []FormalVaultProviderDependency{{Version: "formal-vault-provider-dependency.v1", Workload: materials.Workload, Observer: install.BootstrapSourceFilePin{File: path.Join(formalVaultDependencyMount, "observer.json"), SHA256: hash(observerRaw)}}}
	if x.config.Validate() != nil {
		return zero, install.ErrInstall
	}
	configRaw, e := ce.Canonical(x.config)
	if e != nil {
		return zero, install.ErrInstall
	}
	selection.Deployment = install.BootstrapSourceFilePin{File: filepath.Join(outputDirectory, outputs[0]), SHA256: hash(configRaw)}
	x.materials.DeploymentConfigSHA256 = selection.Deployment.SHA256
	materialRaw, e := ce.Canonical(x.materials)
	if e != nil {
		return zero, install.ErrInstall
	}
	selection.MaterialsTemplate = install.BootstrapSourceFilePin{File: filepath.Join(outputDirectory, outputs[1]), SHA256: hash(materialRaw)}
	selectionRaw, e := ce.Canonical(selection)
	if e != nil {
		return zero, install.ErrInstall
	}
	secretRaw, e := ce.Canonical(secret)
	if e != nil {
		return zero, install.ErrInstall
	}
	defer clear(secretRaw)
	patchRaw, e := ce.Canonical(patch)
	if e != nil {
		return zero, install.ErrInstall
	}
	bodies := [][]byte{configRaw, materialRaw, selectionRaw, secretRaw, patchRaw}
	for n, name := range outputs {
		if guard() != nil {
			return zero, install.ErrInstall
		}
		file := filepath.Join(outputDirectory, name)
		if writeBootstrapSourceFactFile(file, bodies[n]) != nil {
			return zero, install.ErrInstall
		}
		actual, e := install.ReadSourceMaterialFile(file)
		matches := e == nil && bytes.Equal(actual, bodies[n])
		clear(actual)
		if !matches || guard() != nil {
			return zero, install.ErrInstall
		}
	}
	return FormalVaultMaterialsReceipt{Version: "formal-vault-dependency-materials.v1", Deployment: selection.Deployment, MaterialsTemplate: selection.MaterialsTemplate, SourceSelection: install.BootstrapSourceFilePin{File: filepath.Join(outputDirectory, outputs[2]), SHA256: hash(selectionRaw)}, SecretManifest: install.BootstrapSourceFilePin{File: filepath.Join(outputDirectory, outputs[3]), SHA256: hash(secretRaw)}, DeploymentPatch: install.BootstrapSourceFilePin{File: filepath.Join(outputDirectory, outputs[4]), SHA256: hash(patchRaw)}, Workload: materials.Workload}, nil
}
