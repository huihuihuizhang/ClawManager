package install

import (
	"context"
	"encoding/json"
	"path"
	"reflect"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// Finite reviewed profile, not a caller-provided image policy. The exact OCI
// index/platform graph and original image's start.sh/ELF were read without
// executing the application. dbb86137 server exposes backup GET views only;
// it predates Store/Create/capture/publication. This does not classify a newer
// image, arbitrary command, historical independent tool, or whole installation.
const originalFix18ConsumerProfileVersion = "original-fix18-backup-read-view.v1"

const originalFix18Index = "sha256:c16f07c25c6dc8362aa09b7a1e81f5d1204f2812ae542bbcb21a3946975c6c9d"
const originalFix18PlatformManifest = "sha256:5a96a4c480da589168b0d98bf98297987236a4523ed54ede04ebad29ae198eaf"
const originalFix18ServerSHA = "770f0ea184203854bb7f2e5f914b0ed15626e38c2a59fa9d2f393db617c0a75a"
const originalFix18StartupSHA = "37def35b7cf831eaea99cca4e02607eca0a849072bfe2177c29b05965781f28d"
const originalFix18SourceRevision = "dbb86137b60737f29939746019e55f3bdd6ab0b9"

// Real source-consuming caller for D's finite producer. Caller already holds
// original set.mu -> prep.mu and has NOT entered final SQL. Read the original
// Kube Pod body retained by the genuine writer preflight, not a CLI Pod DTO or
// current Deployment template substituted for the original Pod. Original Pod
// deletion during a genuine held stop does not erase this original source.
// This covers one actual container; D must enumerate the complete original
// roster, classify other selected consumers/retired outputs and preserve this
// source's original historyMounted.until in the resolved minimum cap.
func readOriginalFix18BackupReadConsumerLocked(ctx context.Context, p *PreparedOriginalAdoptionSQLCut, h *OriginalWriterHold, podName, container string) (originalBackupHistoryConsumer, error) {
	var zero originalBackupHistoryConsumer
	if !originalEmptyHistoryOwner(ctx, p, h, false) || h.set.historyMounted == nil || h.recheckBeforeSQL(ctx) != nil || p.operator.authority(ctx, p.enrollment) != nil {
		return zero, ErrInstall
	}
	source := h.set.historyMounted
	if source.origin != source || !source.local(ctx) || source.installer != p.operator.installer {
		return zero, ErrInstall
	}
	namespace := p.operator.installer.plan.Target.Namespace
	key := "Pod/" + namespace + "/" + podName
	object := source.objects[key]
	if object == nil || object.kind != "Pod" || object.namespace != namespace || object.name != podName || object.uid == "" || object.resourceVersion == "" || hash(object.body) != object.digest {
		return zero, ErrInstall
	}
	var pod corev1.Pod
	if json.Unmarshal(object.body, &pod) != nil || string(pod.UID) != object.uid || pod.ResourceVersion != object.resourceVersion || pod.Namespace != namespace || pod.Name != podName {
		return zero, ErrInstall
	}
	classified, err := classifyOriginalFix18BackupReadContainer(&pod, container)
	if err != nil || h.recheckBeforeSQL(ctx) != nil || p.operator.authority(ctx, p.enrollment) != nil || !source.local(ctx) || h.set.historyMounted != source || source.objects[key] != object || hash(object.body) != object.digest {
		return zero, ErrInstall
	}
	return classified, nil
}

func originalFix18ImageIdentity(imageID string) bool {
	// A bare runtime image ID or full repo digest may represent either the
	// selected index or its verified amd64 manifest. Tags never establish it.
	for _, digest := range []string{originalFix18Index, originalFix18PlatformManifest} {
		if imageID == digest || strings.HasSuffix(imageID, "@"+digest) && !strings.ContainsAny(imageID, "\x00\r\n \t") {
			return true
		}
	}
	return false
}

// D's genuine reader calls this for EACH actual retained original Pod/container
// after authenticating its own source graph. This private function classifies
// one concrete launch profile only; its arguments and result ALONE are not
// NoS3/complete-universe evidence and cannot construct PreparedCoverage.
func classifyOriginalFix18BackupReadContainer(pod *corev1.Pod, name string) (originalBackupHistoryConsumer, error) {
	var zero originalBackupHistoryConsumer
	if pod == nil || pod.UID == "" || pod.Namespace == "" || pod.Name == "" || name == "" {
		return zero, ErrInstall
	}
	var selected *corev1.Container
	for n := range pod.Spec.Containers {
		if pod.Spec.Containers[n].Name == name {
			if selected != nil {
				return zero, ErrInstall
			}
			selected = &pod.Spec.Containers[n]
		}
	}
	if selected == nil || selected.Image == "" {
		return zero, ErrInstall
	}
	var status *corev1.ContainerStatus
	for n := range pod.Status.ContainerStatuses {
		if pod.Status.ContainerStatuses[n].Name == name {
			if status != nil {
				return zero, ErrInstall
			}
			status = &pod.Status.ContainerStatuses[n]
		}
	}
	if status == nil || status.ContainerID == "" || !originalFix18ImageIdentity(status.ImageID) {
		return zero, ErrInstall
	}
	// Both empty means the independently inspected exact image defaults:
	// Entrypoint=[dumb-init,--], Cmd=[/app/start.sh]. Explicit exact pair is
	// supported as well. No shell/eval, alternate binary or arbitrary flags.
	defaults := len(selected.Command) == 0 && len(selected.Args) == 0
	exact := reflect.DeepEqual(selected.Command, []string{"dumb-init", "--"}) && reflect.DeepEqual(selected.Args, []string{"/app/start.sh"})
	if !defaults && !exact || len(selected.EnvFrom) != 0 {
		return zero, ErrInstall
	}
	for _, env := range selected.Env {
		switch env.Name {
		case "PATH", "ENV", "BASH_ENV", "LD_PRELOAD", "LD_LIBRARY_PATH", "SHELLOPTS":
			// A concrete unresolved launch selector, not a requirement to read
			// arbitrary old business YAML/loaded memory. D may only add another
			// profile after authenticating that actual original startup source.
			return zero, ErrInstall
		}
	}
	controlPaths := []string{"/app/start.sh", "/usr/local/bin", "/usr/local/sbin", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/lib", "/usr/lib", "/etc/nginx", "/etc/ld.so.preload", "/etc/ld.so.conf", "/etc/ld.so.conf.d"}
	paths := make([]string, 0, len(selected.VolumeMounts)+len(selected.VolumeDevices))
	for _, mount := range selected.VolumeMounts {
		paths = append(paths, mount.MountPath)
	}
	for _, device := range selected.VolumeDevices {
		paths = append(paths, device.DevicePath)
	}
	for _, mounted := range paths {
		mp := path.Clean(mounted)
		if !path.IsAbs(mounted) || mp != mounted || strings.Contains(mounted, "\\") {
			return zero, ErrInstall
		}
		for _, controlled := range controlPaths {
			if mp == "/" || mp == controlled || strings.HasPrefix(controlled, mp+"/") || strings.HasPrefix(mp, controlled+"/") {
				return zero, ErrInstall
			}
		}
	}
	// Preserve the full selected actual PodSpec and container image/identity in
	// an explicit exported projection. D separately retains the original opaque
	// source and rereads its real provenance; this hash does not grant authority.
	source := originalObjectSHA(struct {
		Version, SourceRevision, ServerSHA256, StartupSHA256    string
		Namespace, Pod, PodUID, Container, ImageID, ContainerID string
		Spec                                                    corev1.PodSpec
	}{originalFix18ConsumerProfileVersion, originalFix18SourceRevision, originalFix18ServerSHA, originalFix18StartupSHA, pod.Namespace, pod.Name, string(pod.UID), name, status.ImageID, status.ContainerID, pod.Spec})
	return originalBackupHistoryConsumer{id: string(pod.UID) + "/" + name, kind: "original_non_backup_consumer", sourceVersion: originalFix18ConsumerProfileVersion, sourceSHA256: source}, nil
}
