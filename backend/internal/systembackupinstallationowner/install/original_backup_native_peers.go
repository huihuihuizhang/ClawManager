package install

import (
	"context"
	"path"
	"reflect"
	"strings"
	"time"

	q "clawreef/internal/systembackup/quiesce"
	corev1 "k8s.io/api/core/v1"
)

const originalPeerMinIOImage = "10.130.14.23:5000/minio@sha256:52dfd5c0bbd38d3219f2058c7af216d9f9a27a994b7b5baad09bbd38866015ff"
const originalPeerVaultImage = "10.130.14.23:5000/clawmanager-backup-vault@sha256:2194d86d9ddbb17a6d017c3b2e555e1d4431195f18c3cb2827e3f61320fb6855"

// Additional finite native service startups. A storage/server process is not
// automatically an independent backup producer. Conversely this classification
// never removes its logical retained backup objects, native roots or unknown
// selected entry scripts from the complete original history universe.
func classifyOriginalBackupNativePeer(ctx context.Context, p *PreparedOriginalAdoptionSQLCut, h *OriginalWriterHold, pod *corev1.Pod, spec *corev1.PodSpec, c *corev1.Container, status *corev1.ContainerStatus, until time.Time) (originalBackupStartupDisposition, error) {
	zero := originalBackupStartupDisposition{}
	if !originalEmptyHistoryOwner(ctx, p, h, false) || pod == nil || spec == nil || c == nil || status == nil || !originalPeerContainerMatches(pod, spec, c, status, false) {
		return zero, ErrInstall
	}
	profile := ""
	switch status.ImageID {
	case originalPeerMinIOImage:
		if !originalPeerMinIOEntry(spec, c) {
			return zero, errOriginalBackupConsumerUnclassified
		}
		profile = "original-held-native-minio-server-startup.v1"
	case originalPeerVaultImage:
		if !originalPeerVaultEntry(spec, c) {
			return zero, errOriginalBackupConsumerUnclassified
		}
		profile = "original-held-native-vault-server-startup.v1"
	default:
		return zero, errOriginalBackupConsumerUnclassified
	}
	if status.ImageID == originalPeerVaultImage {
		if kept, selected, err := originalBackupKeptVaultPeer(ctx, h, pod, spec, c, status, until); selected || err != nil {
			return kept, err
		}
	}
	binding, anchor, boot, cap, err := originalPeerWholeNativeActor(ctx, h, pod, status)
	if err != nil {
		return zero, err
	}
	if cap.Before(until) {
		until = cap
	}
	if !time.Now().Before(until) {
		return zero, ErrInstall
	}
	return originalBackupStartupDisposition{kind: "original_non_backup_consumer", version: profile, sourceSHA256: originalObjectSHA(struct {
		Profile, PodUID, ImageID, MountedRevision, Anchor, Boot string
		Container                                               corev1.Container
		Volumes                                                 []corev1.Volume
		Binding                                                 q.ObservationBinding
	}{profile, string(pod.UID), status.ImageID, h.set.historyMounted.revision, anchor, boot, *c, spec.Volumes, binding}), until: until}, nil
}

// Bind the actual immutable Pod+CRI container to D's original node request and
// B's genuine current stopped observation. Namespace labels/Role and a matching
// image alone cannot create this relation. This uses only genuine retained
// private objects; it does no native I/O under the final SQL lock prefix.
func originalPeerWholeNativeActor(ctx context.Context, h *OriginalWriterHold, pod *corev1.Pod, status *corev1.ContainerStatus) (binding q.ObservationBinding, anchor, boot string, until time.Time, err error) {
	if h == nil || h.origin != h || h.set == nil || h.set.actualHold != h || pod == nil || status == nil || status.ContainerID == "" {
		return binding, "", "", until, ErrInstall
	}
	found := false
	for _, n := range h.set.nodes {
		if n == nil || n.set != h.set || n.prepare == nil || n.current == nil || n.request.Binding.Node != pod.Spec.NodeName {
			continue
		}
		member := false
		for _, old := range n.request.Pods {
			if old.UID == string(pod.UID) && old.Name == pod.Name && old.Node == pod.Spec.NodeName {
				for _, id := range old.Containers {
					member = member || id == status.ContainerID
				}
			}
		}
		if !member {
			continue
		}
		response := n.current.Response()
		prepared := n.prepare.Response()
		if found || n.current.Recheck(ctx, n.request.Binding, "stopped", n.boot, time.Now().UTC()) != nil || response.Anchor == "" || response.Anchor != prepared.Anchor || response.BootID != prepared.BootID || !reflect.DeepEqual(prepared.Binding, n.request.Binding) {
			return binding, "", "", until, ErrInstall
		}
		found = true
		binding = n.request.Binding
		anchor = response.Anchor
		boot = response.BootID
		until = response.ValidUntil
	}
	if !found {
		return binding, "", "", until, errOriginalBackupConsumerUnclassified
	}
	return binding, anchor, boot, until, nil
}

func originalPeerNativeCommon(c *corev1.Container) bool {
	if c == nil || c.Lifecycle != nil || len(c.EnvFrom) != 0 || len(c.VolumeDevices) != 0 {
		return false
	}
	for _, e := range c.Env {
		switch e.Name {
		case "LD_PRELOAD", "LD_LIBRARY_PATH", "BASH_ENV", "ENV":
			return false
		}
	}
	for _, m := range c.VolumeMounts {
		for _, root := range []string{"/", "/bin", "/sbin", "/usr", "/app/start.sh", "/docker-entrypoint.sh"} {
			if m.MountPath == root || root != "/" && strings.HasPrefix(m.MountPath, root+"/") {
				return false
			}
		}
	}
	return true
}

func originalPeerMountedPath(spec *corev1.PodSpec, c *corev1.Container, file string, config bool) bool {
	if spec == nil || c == nil || !path.IsAbs(file) || path.Clean(file) != file || strings.ContainsAny(file, "\\\x00\r\n") {
		return false
	}
	for _, m := range c.VolumeMounts {
		if !path.IsAbs(m.MountPath) || path.Clean(m.MountPath) != m.MountPath || file != m.MountPath && !strings.HasPrefix(file, m.MountPath+"/") {
			continue
		}
		for _, v := range spec.Volumes {
			if v.Name == m.Name {
				if config {
					return m.ReadOnly && (v.ConfigMap != nil || v.Secret != nil || v.Projected != nil)
				}
				return !m.ReadOnly && (v.PersistentVolumeClaim != nil || v.HostPath != nil)
			}
		}
	}
	return false
}

func originalPeerMinIOEntry(spec *corev1.PodSpec, c *corev1.Container) bool {
	if !originalPeerNativeCommon(c) || spec == nil || len(c.Command) > 1 || len(c.Command) == 1 && c.Command[0] != "minio" && c.Command[0] != "/usr/bin/minio" && c.Command[0] != "/opt/bin/minio" {
		return false
	}
	if len(c.Args) < 2 || c.Args[0] != "server" {
		return false
	}
	roots := 0
	for n := 1; n < len(c.Args); n++ {
		a := c.Args[n]
		if strings.HasPrefix(a, "--") {
			parts := strings.SplitN(a, "=", 2)
			switch parts[0] {
			case "--address", "--console-address", "--certs-dir":
			default:
				return false
			}
			if len(parts) == 1 {
				n++
				if n >= len(c.Args) || strings.HasPrefix(c.Args[n], "--") {
					return false
				}
			}
			continue
		}
		if !originalPeerMountedPath(spec, c, a, false) {
			return false
		}
		roots++
	}
	return roots > 0
}

func originalPeerVaultEntry(spec *corev1.PodSpec, c *corev1.Container) bool {
	if !originalPeerNativeCommon(c) || spec == nil || len(c.Command) > 1 || len(c.Command) == 1 && c.Command[0] != "/bin/vault" {
		return false
	}
	args := c.Args
	// The inspected custom immutable OCI image's default CMD is exactly this
	// native server invocation; it does not inherit the official dev CMD.
	if len(c.Command) == 0 && len(args) == 0 {
		args = []string{"server", "-config=/vault/config/vault.hcl"}
	}
	if len(args) < 2 || args[0] != "server" {
		return false
	}
	config := ""
	if len(args) == 2 && strings.HasPrefix(args[1], "-config=") {
		config = strings.TrimPrefix(args[1], "-config=")
	}
	if len(args) == 3 && args[1] == "-config" {
		config = args[2]
	}
	return config != "" && originalPeerMountedPath(spec, c, config, true)
}
