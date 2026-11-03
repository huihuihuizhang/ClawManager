package systembackupexecution

import (
	"bytes"
	"context"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	q "clawreef/internal/systembackup/quiesce"
	ce "clawreef/internal/systembackupcontrolevidence"
	"clawreef/internal/systembackupinstallationowner/install"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const formalStoppedProObserverMount = "/var/run/clawreef/system-backup/stopped-pro-observer"

// This receipt contains only file coordinates and hashes. The private Secret
// manifest contains the EXISTING selected client key, never a newly issued key.
// None of these unsigned preparation outputs is a node observation or grant.
type FormalStoppedProMaterialsReceipt struct {
	Version, OriginalSelectionSHA256, WriterSelectionSHA256 string
	Deployment, MaterialsTemplate, SourceSelection          install.BootstrapSourceFilePin
	SecretManifest, DeploymentPatch                         install.BootstrapSourceFilePin
	NodeUIDs                                                map[string]string
}

type formalObserverPatchOperation struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}

func readFormalObserverSelection(file, digest string) (install.OriginalWriterSetSelection, error) {
	var out install.OriginalWriterSetSelection
	raw, err := install.ReadPrivateFile(file, 262144)
	if err != nil || hash(raw) != digest || strictBootstrapSourceJSON(raw, &out) != nil || out.Version != install.OriginalWriterSetSelectionVersion {
		return out, install.ErrInstall
	}
	return out, nil
}

// ProduceFormalStoppedProObserverMaterials is a real pre-signing Installer
// action. It authenticates the original operator/enrollment and complete SQL
// inventory, re-reads every stopped-Pro current volume/node binding, and emits
// a new config/material/selection chain plus a create-only immutable Secret
// manifest and guarded mount patch. It does not apply either Kubernetes object,
// issue credentials, reserve a source, or assert native observer availability.
// Run facts/signing only after deployment and a fresh controller selection.
func ProduceFormalStoppedProObserverMaterials(ctx context.Context, installer *install.Installer, password []byte, enrollment install.EnrollmentPin, selectionFile, selectionSHA, writerFile, writerSHA, container, outputDirectory string) (FormalStoppedProMaterialsReceipt, error) {
	var zero FormalStoppedProMaterialsReceipt
	if ctx == nil || ctx.Err() != nil || installer == nil || container == "" {
		return zero, install.ErrInstall
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return zero, install.ErrInstall
	}
	selected, err := readFormalObserverSelection(writerFile, writerSHA)
	if err != nil {
		return zero, err
	}
	authority, err := installer.PrepareBootstrapSourceRegistryAuthoring(ctx, password, enrollment, selectionFile, selectionSHA)
	if err != nil {
		return zero, install.ErrInstall
	}
	defer authority.Close()
	x, err := newBootstrapSourceAuthoringReader(ctx, authority)
	if err != nil {
		return zero, err
	}
	selection, _, err := authority.Selection(ctx)
	if err != nil || selected.ApplicationScope != selection.ApplicationScope || x.config.RuntimeSources.StoppedProObserver != nil {
		return zero, install.ErrInstall
	}

	// Read the existing actual client materials before and after native reads.
	// The source selection and all three pins must stay byte-for-byte unchanged.
	pins := []install.BootstrapSourceFilePin{selected.ObserverCA, selected.ObserverCertificate, selected.ObserverKey}
	secrets := make([][]byte, len(pins))
	defer func() {
		for _, raw := range secrets {
			clear(raw)
		}
	}()
	checkInputs := func() error {
		current, e := readFormalObserverSelection(writerFile, writerSHA)
		if e != nil || !reflect.DeepEqual(current, selected) || authority.RecheckAuthority(ctx) != nil {
			return install.ErrInstall
		}
		for n, pin := range pins {
			raw, e := install.ReadPrivateFile(pin.File, 262144)
			if e != nil || hash(raw) != pin.SHA256 || secrets[n] != nil && !bytes.Equal(raw, secrets[n]) {
				clear(raw)
				return install.ErrInstall
			}
			if secrets[n] == nil {
				secrets[n] = raw
			} else {
				clear(raw)
			}
		}
		return authority.RecheckAuthority(ctx)
	}
	if checkInputs() != nil {
		return zero, install.ErrInstall
	}
	firstSQL, err := x.readSourceSQL()
	if err != nil {
		return zero, err
	}
	clients, err := x.openMetadataClients()
	if err != nil {
		return zero, err
	}
	defer clients.Close()
	controller := selection.Controller
	deployment, err := clients.API.AppsV1().Deployments(controller.Namespace).Get(x.physical, controller.Deployment, metav1.GetOptions{})
	if err != nil || string(deployment.UID) != controller.DeploymentUID || deployment.ResourceVersion == "" || deployment.DeletionTimestamp != nil || deployment.Spec.Template.Spec.ServiceAccountName != controller.ServiceAccount {
		return zero, install.ErrInstall
	}
	containerIndex := -1
	for n, c := range deployment.Spec.Template.Spec.Containers {
		if c.Name == container {
			containerIndex = n
		}
		for _, m := range c.VolumeMounts {
			if m.Name == "stopped-pro-observer" || m.MountPath == formalStoppedProObserverMount || strings.HasPrefix(formalStoppedProObserverMount, m.MountPath+"/") || strings.HasPrefix(m.MountPath, formalStoppedProObserverMount+"/") {
				return zero, install.ErrInstall
			}
		}
	}
	if containerIndex < 0 {
		return zero, install.ErrInstall
	}
	for _, c := range deployment.Spec.Template.Spec.InitContainers {
		for _, m := range c.VolumeMounts {
			if m.Name == "stopped-pro-observer" {
				return zero, install.ErrInstall
			}
		}
	}
	for _, v := range deployment.Spec.Template.Spec.Volumes {
		if v.Name == "stopped-pro-observer" {
			return zero, install.ErrInstall
		}
	}

	nodes := map[string]string{}
	materials := map[int]CurrentStoppedProSourceMaterial{}
	for _, instance := range firstSQL.inventory.Instances {
		if !isCurrentStoppedPro(instance) {
			continue
		}
		m, e := observeCurrentStoppedPro(x.physical, clients.API, x.config, instance, firstSQL.metadata.CurrentStoppedProStorage[instance.ID])
		if e != nil {
			return zero, e
		}
		materials[instance.ID] = m
		for _, mount := range m.Mounts {
			if old := nodes[mount.Node]; old != "" && old != mount.NodeUID {
				return zero, install.ErrInstall
			}
			if x.config.Security.NodeUIDs[mount.Node] != mount.NodeUID {
				return zero, install.ErrInstall
			}
			nodes[mount.Node] = mount.NodeUID
		}
	}
	// No stopped-Pro branch is inferred from missing layouts or supplied data.
	if len(materials) == 0 || len(materials) != len(x.config.RuntimeSources.CurrentStoppedProLayouts) {
		return zero, install.ErrInstall
	}
	endpoints := map[string]q.ProofEndpoint{}
	for node := range nodes {
		ep, ok := selected.StoppedProEndpoints[node]
		if !ok {
			return zero, install.ErrInstall
		}
		endpoints[node] = ep
	}
	if _, err := q.NewStoppedProNodeObservationClient(endpoints, pins[0].File, pins[1].File, pins[2].File); err != nil || checkInputs() != nil {
		return zero, install.ErrInstall
	}
	transportRaw, err := ce.Canonical(struct {
		Pins      []install.BootstrapSourceFilePin
		Endpoints map[string]q.ProofEndpoint
		Nodes     map[string]string
	}{pins, endpoints, nodes})
	if err != nil {
		return zero, install.ErrInstall
	}
	secretName := "backup-stopped-pro-" + hash(transportRaw)[:24]
	// Do not relax private-key file mode or change existing workload IDs.
	// Non-root controllers need an already configured Secret-readable fsGroup.
	podSecurity := deployment.Spec.Template.Spec.SecurityContext
	var runAsUser *int64
	if podSecurity != nil {
		runAsUser = podSecurity.RunAsUser
	}
	if security := deployment.Spec.Template.Spec.Containers[containerIndex].SecurityContext; security != nil && security.RunAsUser != nil {
		runAsUser = security.RunAsUser
	}
	if (runAsUser == nil || *runAsUser != 0) && (podSecurity == nil || podSecurity.FSGroup == nil || *podSecurity.FSGroup <= 0) {
		return zero, install.ErrInstall
	}
	immutable, mode := true, int32(0440)
	secret := corev1.Secret{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: metav1.ObjectMeta{Namespace: controller.Namespace, Name: secretName, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: deployment.Name, UID: deployment.UID}}}, Immutable: &immutable, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"ca.pem": secrets[0], "client.pem": secrets[1], "client-key.pem": secrets[2]}}
	// Only the selected container receives this read-only volume. Its existing
	// UID/fsGroup must already allow private 0440 Secret projection reads.
	volume := corev1.Volume{Name: "stopped-pro-observer", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: secretName, DefaultMode: &mode}}}
	mount := corev1.VolumeMount{Name: volume.Name, MountPath: formalStoppedProObserverMount, ReadOnly: true}
	patch := []formalObserverPatchOperation{{"test", "/metadata/uid", string(deployment.UID)}, {"test", "/metadata/resourceVersion", deployment.ResourceVersion}}
	if len(deployment.Spec.Template.Spec.Volumes) == 0 {
		patch = append(patch, formalObserverPatchOperation{"add", "/spec/template/spec/volumes", []corev1.Volume{volume}})
	} else {
		patch = append(patch, formalObserverPatchOperation{"add", "/spec/template/spec/volumes/-", volume})
	}
	// A container-name test protects the positional JSON patch as well.
	index := strconv.Itoa(containerIndex)
	patch = append(patch, formalObserverPatchOperation{"test", "/spec/template/spec/containers/" + index + "/name", container})
	if len(deployment.Spec.Template.Spec.Containers[containerIndex].VolumeMounts) == 0 {
		patch = append(patch, formalObserverPatchOperation{"add", "/spec/template/spec/containers/" + index + "/volumeMounts", []corev1.VolumeMount{mount}})
	} else {
		patch = append(patch, formalObserverPatchOperation{"add", "/spec/template/spec/containers/" + index + "/volumeMounts/-", mount})
	}
	x.config.RuntimeSources.StoppedProObserver = &FormalStoppedProObserverConfig{CAFile: path.Join(formalStoppedProObserverMount, "ca.pem"), CASHA256: pins[0].SHA256, CertificateFile: path.Join(formalStoppedProObserverMount, "client.pem"), CertificateSHA256: pins[1].SHA256, KeyFile: path.Join(formalStoppedProObserverMount, "client-key.pem"), KeySHA256: pins[2].SHA256, Endpoints: endpoints, NodeUIDs: nodes}
	if x.config.Validate() != nil {
		return zero, install.ErrInstall
	}
	configRaw, err := ce.Canonical(x.config)
	if err != nil || len(configRaw) > 262144 {
		return zero, install.ErrInstall
	}
	selection.Deployment = install.BootstrapSourceFilePin{File: filepath.Join(outputDirectory, "observer-deployment-config.json"), SHA256: hash(configRaw)}
	x.materials.DeploymentConfigSHA256 = selection.Deployment.SHA256
	materialsRaw, err := ce.Canonical(x.materials)
	if err != nil || len(materialsRaw) > 8<<20 {
		return zero, install.ErrInstall
	}
	selection.MaterialsTemplate = install.BootstrapSourceFilePin{File: filepath.Join(outputDirectory, "observer-materials-template.json"), SHA256: hash(materialsRaw)}
	selectionRaw, err := ce.Canonical(selection)
	if err != nil || len(selectionRaw) > 262144 {
		return zero, install.ErrInstall
	}
	secretRaw, err := ce.Canonical(secret)
	if err != nil || len(secretRaw) > 1<<20 {
		return zero, install.ErrInstall
	}
	defer clear(secretRaw)
	patchRaw, err := ce.Canonical(patch)
	if err != nil {
		return zero, install.ErrInstall
	}
	outputs := []struct {
		file string
		raw  []byte
	}{{selection.Deployment.File, configRaw}, {selection.MaterialsTemplate.File, materialsRaw}, {filepath.Join(outputDirectory, "observer-source-selection.json"), selectionRaw}, {filepath.Join(outputDirectory, "observer-secret.private.json"), secretRaw}, {filepath.Join(outputDirectory, "observer-deployment-mount.patch.json"), patchRaw}}
	for _, output := range outputs {
		if output.file == selectionFile || output.file == writerFile || checkBootstrapSourceFactOutputs(output.file, filepath.Join(outputDirectory, "observer-output-reserved")) != nil {
			return zero, install.ErrInstall
		}
	}
	// Re-read the complete SQL source and native mappings before any output.
	lastSQL, err := x.readSourceSQL()
	if err != nil || !sameBootstrapSourceSQL(firstSQL, lastSQL) {
		return zero, install.ErrInstall
	}
	for _, instance := range lastSQL.inventory.Instances {
		if !isCurrentStoppedPro(instance) {
			continue
		}
		m, e := observeCurrentStoppedPro(x.physical, clients.API, x.config, instance, lastSQL.metadata.CurrentStoppedProStorage[instance.ID])
		if e != nil || !reflect.DeepEqual(m, materials[instance.ID]) {
			return zero, install.ErrInstall
		}
	}
	currentDeployment, err := clients.API.AppsV1().Deployments(controller.Namespace).Get(x.physical, controller.Deployment, metav1.GetOptions{})
	if err != nil || !reflect.DeepEqual(currentDeployment, deployment) || checkInputs() != nil {
		return zero, install.ErrInstall
	}
	for _, output := range outputs {
		if checkInputs() != nil || writeBootstrapSourceFactFile(output.file, output.raw) != nil {
			return zero, install.ErrInstall
		}
		actual, e := install.ReadSourceMaterialFile(output.file)
		matches := e == nil && bytes.Equal(actual, output.raw)
		clear(actual)
		if !matches || checkInputs() != nil {
			return zero, install.ErrInstall
		}
	}
	return FormalStoppedProMaterialsReceipt{Version: "formal-stopped-pro-observer-materials.v1", OriginalSelectionSHA256: selectionSHA, WriterSelectionSHA256: writerSHA, Deployment: selection.Deployment, MaterialsTemplate: selection.MaterialsTemplate, SourceSelection: install.BootstrapSourceFilePin{File: outputs[2].file, SHA256: hash(selectionRaw)}, SecretManifest: install.BootstrapSourceFilePin{File: outputs[3].file, SHA256: hash(secretRaw)}, DeploymentPatch: install.BootstrapSourceFilePin{File: outputs[4].file, SHA256: hash(patchRaw)}, NodeUIDs: nodes}, nil
}
