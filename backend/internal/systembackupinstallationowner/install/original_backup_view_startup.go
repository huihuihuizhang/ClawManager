package install

import (
	"path"
	"reflect"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// Exact ABI consumed by D's real originalFiniteBackupConsumerSource. It is a
// pure classifier of the actual retained Pod/controller inputs already read by
// that source, not a new authorization boundary or alternate source factory.
// Original A2's actual Pod reader/profile remain frozen and unchanged.
func classifyOriginalBackupViewStartup(spec *corev1.PodSpec, c *corev1.Container, status *corev1.ContainerStatus, init bool) (originalBackupStartupDisposition, error) {
	var zero originalBackupStartupDisposition
	if spec == nil || c == nil || c.Name == "" || c.Image == "" {
		return zero, ErrInstall
	}
	const originalTag = "10.130.14.23:5000/clawmanager:backup-test-zh-fix18"
	family := originalFix18ImageIdentity(c.Image) || c.Image == originalTag
	if status != nil && originalFix18ImageIdentity(status.ImageID) {
		family = true
	}
	if !family {
		return zero, errOriginalBackupConsumerUnclassified
	}
	// A owns only this reviewed normal read-server launch. A recognized app
	// image with unsupported command/init/overlay must NOT fall through to C.
	if init {
		return zero, ErrInstall
	}
	count := 0
	for n := range spec.Containers {
		if spec.Containers[n].Name == c.Name {
			if !reflect.DeepEqual(spec.Containers[n], *c) {
				return zero, ErrInstall
			}
			count++
		}
	}
	if count != 1 {
		return zero, ErrInstall
	}
	if status == nil {
		// A genuine historical template has no runtime status. Only its actual
		// immutable known image digest is supported; never synthesize ImageID.
		if !originalFix18ImageIdentity(c.Image) {
			return zero, ErrInstall
		}
	} else if status.Name != c.Name || status.ContainerID == "" || !originalFix18ImageIdentity(status.ImageID) || c.Image != originalTag && !originalFix18ImageIdentity(c.Image) {
		return zero, ErrInstall
	}
	defaults := len(c.Command) == 0 && len(c.Args) == 0
	exact := reflect.DeepEqual(c.Command, []string{"dumb-init", "--"}) && reflect.DeepEqual(c.Args, []string{"/app/start.sh"})
	if !defaults && !exact || len(c.EnvFrom) != 0 {
		return zero, ErrInstall
	}
	for _, env := range c.Env {
		switch env.Name {
		case "PATH", "ENV", "BASH_ENV", "LD_PRELOAD", "LD_LIBRARY_PATH", "SHELLOPTS":
			return zero, ErrInstall
		}
	}
	controlPaths := []string{"/app/start.sh", "/usr/local/bin", "/usr/local/sbin", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/lib", "/usr/lib", "/etc/nginx", "/etc/ld.so.preload", "/etc/ld.so.conf", "/etc/ld.so.conf.d"}
	paths := make([]string, 0, len(c.VolumeMounts)+len(c.VolumeDevices))
	for _, m := range c.VolumeMounts {
		paths = append(paths, m.MountPath)
	}
	for _, d := range c.VolumeDevices {
		paths = append(paths, d.DevicePath)
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
	source := originalObjectSHA(struct {
		Version, SourceRevision, ServerSHA256, StartupSHA256 string
		Spec                                                 corev1.PodSpec
		Container                                            corev1.Container
		Status                                               *corev1.ContainerStatus
	}{originalFix18ConsumerProfileVersion, originalFix18SourceRevision, originalFix18ServerSHA, originalFix18StartupSHA, *spec, *c, status})
	return originalBackupStartupDisposition{kind: "original_non_backup_consumer", version: originalFix18ConsumerProfileVersion, sourceSHA256: source, requiresOriginalLegacyLayout: true}, nil
}
