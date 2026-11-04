package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	ce "clawreef/internal/systembackupcontrolevidence"
	"clawreef/internal/systembackupinstallationowner/install"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const formalRedisMaterialMount = "/var/run/clawreef/system-backup/redis-read-service"

type FormalRedisMaterialsReceipt struct {
	Version                                                                         string
	Deployment, MaterialsTemplate, SourceSelection, SecretManifest, DeploymentPatch install.BootstrapSourceFilePin
}

// The genuine pre-signing source authoring action consumes the actual native
// installer output; it preserves the complete source roster and attaches the
// EXISTING original/formal Redis keeper factories through real config fields.
func ProduceFormalRedisReadMaterials(ctx context.Context, installer *install.Installer, password []byte, enrollment install.EnrollmentPin, selectionFile, selectionSHA, writerFile, writerSHA, container, directory string) (FormalRedisMaterialsReceipt, error) {
	var zero FormalRedisMaterialsReceipt
	selected, e := readFormalObserverSelection(writerFile, writerSHA)
	if e != nil || len(selected.RedisReadKeepers) != 1 {
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
	if e != nil || selection.ApplicationScope != selected.ApplicationScope || len(x.config.RedisReadKeepers) != 0 {
		return zero, install.ErrInstall
	}
	keeper := selected.RedisReadKeepers[0]
	if keeper.Native.Operation != "" || keeper.Native.InventorySHA256 != "" || keeper.Native.Policy.Validate() != nil {
		return zero, install.ErrInstall
	}
	matched := false
	for _, w := range x.config.Writers {
		if w.Namespace == keeper.Native.Namespace && w.Name == keeper.Deployment && w.UID == keeper.DeploymentUID {
			matched = true
		}
	}
	if !matched {
		return zero, install.ErrInstall
	}
	clients, e := x.openMetadataClients()
	if e != nil {
		return zero, install.ErrInstall
	}
	defer clients.Close()
	controller := selection.Controller
	deployment, e := clients.API.AppsV1().Deployments(controller.Namespace).Get(x.physical, controller.Deployment, metav1.GetOptions{})
	if e != nil || string(deployment.UID) != controller.DeploymentUID || deployment.DeletionTimestamp != nil {
		return zero, install.ErrInstall
	}
	const name = "redis-read-service"
	index := -1
	for n, c := range deployment.Spec.Template.Spec.Containers {
		if c.Name == container {
			index = n
		}
		for _, m := range c.VolumeMounts {
			if m.Name == name || m.Name == name+"-input" || m.MountPath == formalRedisMaterialMount || strings.HasPrefix(formalRedisMaterialMount, m.MountPath+"/") {
				return zero, install.ErrInstall
			}
		}
	}
	if index < 0 {
		return zero, install.ErrInstall
	}
	for _, v := range deployment.Spec.Template.Spec.Volumes {
		if v.Name == name || v.Name == name+"-input" {
			return zero, install.ErrInstall
		}
	}
	for _, c := range deployment.Spec.Template.Spec.InitContainers {
		if c.Name == name+"-install" {
			return zero, install.ErrInstall
		}
	}
	security := deployment.Spec.Template.Spec.Containers[index].SecurityContext.DeepCopy()
	if security == nil {
		security = &core.SecurityContext{}
	}
	podSecurity := deployment.Spec.Template.Spec.SecurityContext
	uid := security.RunAsUser
	if uid == nil && podSecurity != nil {
		uid = podSecurity.RunAsUser
	}
	if uid == nil || *uid < 0 || *uid != 0 && (podSecurity == nil || podSecurity.FSGroup == nil || *podSecurity.FSGroup <= 0) {
		return zero, install.ErrInstall
	}
	security.RunAsUser = uid
	image := deployment.Spec.Template.Spec.Containers[index].Image
	if !strings.Contains(image, "@sha256:") {
		return zero, install.ErrInstall
	}
	guard := func() error {
		if authority.RecheckAuthority(ctx) != nil {
			return install.ErrInstall
		}
		now, e := readFormalObserverSelection(writerFile, writerSHA)
		if e != nil || !reflect.DeepEqual(now, selected) {
			return install.ErrInstall
		}
		current, e := clients.API.AppsV1().Deployments(controller.Namespace).Get(x.physical, controller.Deployment, metav1.GetOptions{})
		if e != nil || !reflect.DeepEqual(current, deployment) {
			return install.ErrInstall
		}
		return nil
	}
	pins := []install.BootstrapSourceFilePin{keeper.CA, keeper.KeeperCredential, keeper.ReaderCredential, keeper.CustodyKey}
	names := []string{"ca.pem", "keeper.json", "reader.json", "custody.key"}
	data := map[string][]byte{}
	manifest := map[string]string{}
	defer func() {
		for _, raw := range data {
			clear(raw)
		}
	}()
	for n, pin := range pins {
		raw, e := install.ReadSourceMaterialFile(pin.File)
		if e != nil || hash(raw) != pin.SHA256 {
			return zero, install.ErrInstall
		}
		data[names[n]] = raw
		manifest[names[n]] = pin.SHA256
	}
	manifestRaw, e := ce.Canonical(manifest)
	if e != nil {
		return zero, install.ErrInstall
	}
	data["manifest.json"] = manifestRaw
	immutable, mode := true, int32(0440)
	secretName := "backup-redis-" + hash(manifestRaw)[:24]
	secret := core.Secret{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: controller.Namespace}, Immutable: &immutable, Type: core.SecretTypeOpaque, Data: data}
	input := core.Volume{Name: name + "-input", VolumeSource: core.VolumeSource{Secret: &core.SecretVolumeSource{SecretName: secretName, DefaultMode: &mode}}}
	output := core.Volume{Name: name, VolumeSource: core.VolumeSource{EmptyDir: &core.EmptyDirVolumeSource{Medium: core.StorageMediumMemory}}}
	init := core.Container{Name: name + "-install", Image: image, Command: []string{"/usr/local/bin/system-backup-source-registries"}, Args: []string{"install-redis-files", "--manifest-sha256", hash(manifestRaw)}, SecurityContext: security, VolumeMounts: []core.VolumeMount{{Name: input.Name, MountPath: "/input", ReadOnly: true}, {Name: output.Name, MountPath: "/output"}}}
	patch := []formalObserverPatchOperation{{"test", "/metadata/uid", string(deployment.UID)}, {"test", "/metadata/resourceVersion", deployment.ResourceVersion}}
	if len(deployment.Spec.Template.Spec.Volumes) == 0 {
		patch = append(patch, formalObserverPatchOperation{"add", "/spec/template/spec/volumes", []core.Volume{input, output}})
	} else {
		patch = append(patch, formalObserverPatchOperation{"add", "/spec/template/spec/volumes/-", input}, formalObserverPatchOperation{"add", "/spec/template/spec/volumes/-", output})
	}
	if len(deployment.Spec.Template.Spec.InitContainers) == 0 {
		patch = append(patch, formalObserverPatchOperation{"add", "/spec/template/spec/initContainers", []core.Container{init}})
	} else {
		patch = append(patch, formalObserverPatchOperation{"add", "/spec/template/spec/initContainers/-", init})
	}
	position := "/spec/template/spec/containers/" + strconv.Itoa(index)
	patch = append(patch, formalObserverPatchOperation{"test", position + "/name", container})
	mount := core.VolumeMount{Name: name, MountPath: formalRedisMaterialMount, SubPath: "private"}
	if len(deployment.Spec.Template.Spec.Containers[index].VolumeMounts) == 0 {
		patch = append(patch, formalObserverPatchOperation{"add", position + "/volumeMounts", []core.VolumeMount{mount}})
	} else {
		patch = append(patch, formalObserverPatchOperation{"add", position + "/volumeMounts/-", mount})
	}
	keeper.CA = install.BootstrapSourceFilePin{File: formalRedisMaterialMount + "/ca.pem", SHA256: manifest["ca.pem"]}
	keeper.KeeperCredential = install.BootstrapSourceFilePin{File: formalRedisMaterialMount + "/keeper.json", SHA256: manifest["keeper.json"]}
	keeper.ReaderCredential = install.BootstrapSourceFilePin{File: formalRedisMaterialMount + "/reader.json", SHA256: manifest["reader.json"]}
	keeper.CustodyKey = install.BootstrapSourceFilePin{File: formalRedisMaterialMount + "/custody.key", SHA256: manifest["custody.key"]}
	keeper.Native.CustodyDirectory = formalRedisMaterialMount + "/custody"
	x.config.RedisReadKeepers = []install.OriginalRedisReadKeeperSelection{keeper}
	x.materials.Redis.Redis.Address = net.JoinHostPort(keeper.ServerName, strconv.Itoa(keeper.Port))
	x.materials.Redis.Redis.ServerName = keeper.ServerName
	x.materials.Redis.Redis.CAFile = keeper.CA.File
	x.materials.Redis.Redis.CASHA256 = keeper.CA.SHA256
	x.materials.Redis.CredentialFile = keeper.ReaderCredential.File
	x.materials.Redis.CredentialSHA256 = keeper.ReaderCredential.SHA256
	x.materials.Discovery.Redis = keeper.Native.Policy
	selection.Connections[3].Endpoint = "rediss://" + x.materials.Redis.Redis.Address
	selection.Connections[3].Account = keeper.Native.ReaderAccount
	selection.Connections[3].CA = keeper.CA
	selection.Connections[3].Credential = keeper.ReaderCredential
	if x.config.Validate() != nil || guard() != nil {
		return zero, install.ErrInstall
	}
	configRaw, e := ce.Canonical(x.config)
	if e != nil {
		return zero, install.ErrInstall
	}
	selection.Deployment = install.BootstrapSourceFilePin{File: filepath.Join(directory, "redis-deployment-config.json"), SHA256: hash(configRaw)}
	x.materials.DeploymentConfigSHA256 = selection.Deployment.SHA256
	materialsRaw, e := ce.Canonical(x.materials)
	if e != nil {
		return zero, install.ErrInstall
	}
	selection.MaterialsTemplate = install.BootstrapSourceFilePin{File: filepath.Join(directory, "redis-materials-template.json"), SHA256: hash(materialsRaw)}
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
	files := []string{selection.Deployment.File, selection.MaterialsTemplate.File, filepath.Join(directory, "redis-source-selection.json"), filepath.Join(directory, "redis-secret.private.json"), filepath.Join(directory, "redis-controller-mount.patch.json")}
	bodies := [][]byte{configRaw, materialsRaw, selectionRaw, secretRaw, patchRaw}
	for n, file := range files {
		if checkBootstrapSourceFactOutputs(file, filepath.Join(directory, "redis-output-reserved")) != nil || guard() != nil || writeBootstrapSourceFactFile(file, bodies[n]) != nil {
			return zero, install.ErrInstall
		}
		actual, e := install.ReadSourceMaterialFile(file)
		same := e == nil && bytes.Equal(actual, bodies[n])
		clear(actual)
		if !same || guard() != nil {
			return zero, install.ErrInstall
		}
	}
	return FormalRedisMaterialsReceipt{Version: "formal-redis-read-service-materials.v1", Deployment: selection.Deployment, MaterialsTemplate: selection.MaterialsTemplate, SourceSelection: install.BootstrapSourceFilePin{File: files[2], SHA256: hash(selectionRaw)}, SecretManifest: install.BootstrapSourceFilePin{File: files[3], SHA256: hash(secretRaw)}, DeploymentPatch: install.BootstrapSourceFilePin{File: files[4], SHA256: hash(patchRaw)}}, nil
}

func InstallFormalRedisFiles(ctx context.Context, manifestSHA string) error {
	read := func(name, sha string) ([]byte, error) {
		f, e := os.Open("/input/" + name)
		if e != nil {
			return nil, install.ErrInstall
		}
		defer f.Close()
		st, e := f.Stat()
		if e != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > 262144 {
			return nil, install.ErrInstall
		}
		raw, e := io.ReadAll(io.LimitReader(f, 262145))
		if e != nil || hash(raw) != sha {
			clear(raw)
			return nil, install.ErrInstall
		}
		return raw, nil
	}
	if ctx == nil || ctx.Err() != nil || len(manifestSHA) != 64 {
		return install.ErrInstall
	}
	raw, e := read("manifest.json", manifestSHA)
	if e != nil {
		return install.ErrInstall
	}
	var manifest map[string]string
	if json.Unmarshal(raw, &manifest) != nil || len(manifest) != 4 {
		return install.ErrInstall
	}
	if os.Mkdir("/output/private", 0700) != nil || os.Mkdir("/output/private/custody", 0700) != nil {
		return install.ErrInstall
	}
	for _, name := range []string{"ca.pem", "keeper.json", "reader.json", "custody.key"} {
		raw, e := read(name, manifest[name])
		if e != nil {
			return install.ErrInstall
		}
		if name == "custody.key" && len(raw) != 32 {
			clear(raw)
			return install.ErrInstall
		}
		e = writeBootstrapSourceFactFile("/output/private/"+name, raw)
		clear(raw)
		if e != nil {
			return install.ErrInstall
		}
	}
	return ctx.Err()
}
